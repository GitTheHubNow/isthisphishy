"""
Is This Phishy? — FastAPI application entry point.
Production-hardened: request IDs, structured logging, global exception handler,
configurable CORS, frontend serving.
"""
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import cfg
from app.api.routes import router
from app.services.database import init_db

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("%s v%s — ready (debug=%s)", cfg.APP_NAME, cfg.VERSION, cfg.DEBUG)
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=f"{cfg.APP_NAME} API",
    description="Free Australian scam detection engine",
    version=cfg.VERSION,
    lifespan=lifespan,
    # In production, suppress /docs and /redoc to reduce attack surface
    docs_url="/docs" if cfg.DEBUG else None,
    redoc_url=None,
)


# ── Request ID middleware ─────────────────────────────────────────────────────
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = uuid.uuid4().hex[:8]
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ── Global exception handler — never leak stack traces ───────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "unknown")
    # Log full detail server-side, return generic message to client
    logger.error(
        "Unhandled exception [rid=%s] %s: %s",
        rid, type(exc).__name__, exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "internal_error", "request_id": rid},
    )


# ── CORS — configurable, never wildcard in production ────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
)


# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api")


# ── Frontend serving ──────────────────────────────────────────────────────────
_THIS = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.path.join(_THIS, "..", "..", "frontend"),
    os.path.join(os.getcwd(), "frontend"),
    os.path.join(os.getcwd(), "..", "frontend"),
]
_FRONTEND = next((os.path.abspath(p) for p in _CANDIDATES if os.path.isdir(p)), None)

if _FRONTEND:
    logger.info("Frontend: %s", _FRONTEND)
    app.mount("/static", StaticFiles(directory=_FRONTEND), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(_FRONTEND, "index.html"))

    @app.get("/{full_path:path}")
    async def catch_all(full_path: str):
        # Only serve index.html for non-API, non-static paths
        if full_path.startswith("api/") or full_path.startswith("static/"):
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return FileResponse(os.path.join(_FRONTEND, "index.html"))

else:
    logger.warning("Frontend directory not found — API-only mode")

    @app.get("/")
    async def root():
        return {"name": cfg.APP_NAME, "version": cfg.VERSION, "docs": "/docs" if cfg.DEBUG else None}
