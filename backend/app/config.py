"""
Is This Phishy — Central Configuration
========================================
All configurable values live here. Every module imports from this file.
Override any value by setting the corresponding environment variable.
No external libraries required — os.getenv only.

Usage:
    from app.config import cfg
    print(cfg.RATE_LIMIT_ANALYZE)
"""
from __future__ import annotations
import os


def _bool(val: str | None, default: bool) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _int(val: str | None, default: int) -> int:
    try:
        return int(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def _float(val: str | None, default: float) -> float:
    try:
        return float(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def _list(val: str | None, default: list[str]) -> list[str]:
    """Comma-separated string → list of stripped non-empty strings."""
    if val is None:
        return default
    parts = [p.strip() for p in val.split(",") if p.strip()]
    return parts if parts else default


class Config:
    # ── App identity ──────────────────────────────────────────────────────────
    APP_NAME: str = "Is This Phishy?"
    VERSION:  str = "1.2.0"

    # ── Runtime ───────────────────────────────────────────────────────────────
    DEBUG:     bool = _bool(os.getenv("DEBUG"), False)
    LOG_LEVEL: str  = os.getenv(
        "LOG_LEVEL",
        "DEBUG" if _bool(os.getenv("DEBUG"), False) else "WARNING"
    )
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = _int(os.getenv("PORT"), 8000)   # PORT is what Railway sets
    PORT:     int = _int(os.getenv("PORT"), 8000)   # alias for start scripts

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Comma-separated allowed origins.
    # Local dev: ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
    # Production: ALLOWED_ORIGINS=https://phishy.com.au,https://isthisphishy.vercel.app
    ALLOWED_ORIGINS: list[str] = _list(
        os.getenv("ALLOWED_ORIGINS"),
        ["http://localhost:3000", "http://localhost:5173",
         "http://localhost:8000", "http://127.0.0.1:8000"],
    )

    # ── Rate limiting — per endpoint, per IP, per RATE_WINDOW seconds ────────
    # analyze:  10/min — CPU-intensive detection pipeline
    # upload:    2/min — file I/O + batch detection
    # feedback: 20/min — lightweight DB write
    # batch:    10/min — same weight as analyze
    RATE_WINDOW:         float = _float(os.getenv("RATE_WINDOW"),          60.0)
    RATE_LIMIT_ANALYZE:  int   = _int(os.getenv("RATE_LIMIT_ANALYZE"),     10)
    RATE_LIMIT_UPLOAD:   int   = _int(os.getenv("RATE_LIMIT_UPLOAD"),       2)
    RATE_LIMIT_FEEDBACK: int   = _int(os.getenv("RATE_LIMIT_FEEDBACK"),    20)
    RATE_LIMIT_BATCH:    int   = _int(os.getenv("RATE_LIMIT_BATCH"),       10)
    RATE_LIMIT:          int   = _int(os.getenv("RATE_LIMIT"),            100)  # legacy / general

    # ── Upload limits ─────────────────────────────────────────────────────────
    MAX_UPLOAD_BYTES:   int = _int(os.getenv("MAX_UPLOAD_BYTES"),   1_048_576)  # 1 MB
    MAX_LINES_PER_FILE: int = _int(os.getenv("MAX_LINES_PER_FILE"),       500)
    MAX_CHARS_PER_LINE: int = _int(os.getenv("MAX_CHARS_PER_LINE"),       500)

    # ── Batch analysis ────────────────────────────────────────────────────────
    MAX_BATCH_SIZE:    int = _int(os.getenv("MAX_BATCH_SIZE"),  100)

    # ── Message analysis ──────────────────────────────────────────────────────
    MAX_MESSAGE_CHARS: int = _int(os.getenv("MAX_MESSAGE_CHARS"), 5000)

    # ── Database ──────────────────────────────────────────────────────────────
    SQLITE_TIMEOUT:    float = _float(os.getenv("SQLITE_TIMEOUT"), 5.0)
    SQLITE_MAX_RETRIES: int  = _int(os.getenv("SQLITE_MAX_RETRIES"), 3)
    DATA_DIR: str = os.getenv(
        "PHISHY_DATA_DIR",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
    )

    # ── Admin ─────────────────────────────────────────────────────────────────
    ADMIN_TOKEN: str | None = os.getenv("ADMIN_TOKEN") or None

    # ── Split deployment ──────────────────────────────────────────────────────
    # Set to Railway backend URL when frontend is on Vercel:
    # API_BASE_URL=https://isthisphishy-production.up.railway.app
    API_BASE_URL: str | None = os.getenv("API_BASE_URL") or None

    def __repr__(self) -> str:
        return (
            f"Config(DEBUG={self.DEBUG}, LOG_LEVEL={self.LOG_LEVEL!r}, "
            f"RATE_LIMIT_ANALYZE={self.RATE_LIMIT_ANALYZE}, "
            f"RATE_LIMIT_UPLOAD={self.RATE_LIMIT_UPLOAD}, "
            f"ALLOWED_ORIGINS={self.ALLOWED_ORIGINS})"
        )


# Singleton — import this everywhere
cfg = Config()
