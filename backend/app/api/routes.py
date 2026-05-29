"""
Is This Phishy — API routes v1.2 (production-hardened)
All limits, rate window, and batch size pulled from config.
File uploads validated for size and MIME type before processing.
All responses follow consistent {success, data/error} envelope.
"""
import csv
import io
import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse

from app.config import cfg
from app.schemas import (
    AnalyzeRequest, AnalyzeResponse, BatchAnalyzeRequest,
    FeedbackRequest, FeedbackResponse, ReasonItem, PhoneTrustInfo,
)
from app.services.detection import run_pipeline
from app.services.phone_trust import classify_phones
from app.services import stats as mem_stats
from app.services import database as db

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Rate limiter ───────────────────────────────────────────────────────────────
_rate_lock = Lock()
_rate_buckets: dict[str, list[float]] = defaultdict(list)


# Separate bucket per (ip, endpoint_key) so each endpoint has its own limit
def _check_rate(ip: str, limit: int, key: str = "default") -> bool:
    bucket_key = f"{ip}:{key}"
    now = time.time()
    with _rate_lock:
        _rate_buckets[bucket_key] = [
            t for t in _rate_buckets[bucket_key] if now - t < cfg.RATE_WINDOW
        ]
        if len(_rate_buckets[bucket_key]) >= limit:
            return False
        _rate_buckets[bucket_key].append(now)
        return True


def _get_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _rate_exceeded():
    return JSONResponse(
        status_code=429,
        content={"success": False, "error": "rate_limit_exceeded",
                 "detail": "Too many requests. Please wait a moment."},
    )


# ── Pipeline helper ────────────────────────────────────────────────────────────
def _run_and_record(text: str) -> tuple:
    """Run pipeline + phone trust + DB record. Returns (result, phone_trust, analysis_id)."""
    result      = run_pipeline(text)
    phone_trust = classify_phones(text, result.features.brand_detected)
    analysis_id = db.record_analysis(result) or 0
    mem_stats.record(result)
    return result, phone_trust, analysis_id


def _build_response(result, phone_trust, analysis_id: int) -> AnalyzeResponse:
    return AnalyzeResponse(
        analysis_id=analysis_id,
        risk_score=result.risk_score,
        verdict=result.verdict,
        confidence=result.confidence,
        reasons=[ReasonItem(type=r.type, detail=r.detail) for r in result.reasons],
        scam_type=result.scam_type,
        scam_label=result.scam_label,
        scam_description=result.scam_description,
        scam_emoji=result.scam_emoji,
        phone_trust=PhoneTrustInfo(
            trust_level=phone_trust.trust_level,
            numbers_found=phone_trust.numbers_found,
            known_org=phone_trust.known_org,
            reason=phone_trust.reason,
        ) if phone_trust.numbers_found else None,
    )


# ── POST /analyze ──────────────────────────────────────────────────────────────
@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: Request, body: AnalyzeRequest):
    if not _check_rate(_get_ip(request), cfg.RATE_LIMIT_ANALYZE, "analyze"):
        return _rate_exceeded()
    try:
        result, phone_trust, analysis_id = _run_and_record(body.message_text)
    except Exception as e:
        logger.error("[rid=%s] Pipeline error: %s", _rid(request), type(e).__name__)
        raise HTTPException(status_code=500, detail="Detection pipeline failed")
    return _build_response(result, phone_trust, analysis_id)


# ── POST /analyze/batch ────────────────────────────────────────────────────────
@router.post("/analyze/batch")
async def analyze_batch(request: Request, body: BatchAnalyzeRequest):
    if not _check_rate(_get_ip(request), cfg.RATE_LIMIT_BATCH, "batch"):
        return _rate_exceeded()

    # Enforce per-request message cap from config
    messages = body.messages[:cfg.MAX_BATCH_SIZE]
    if len(body.messages) > cfg.MAX_BATCH_SIZE:
        logger.warning("[rid=%s] Batch truncated %d→%d", _rid(request),
                       len(body.messages), cfg.MAX_BATCH_SIZE)

    results = []
    errors  = 0
    for msg in messages:
        msg = msg.strip()
        if not msg or len(msg) > cfg.MAX_MESSAGE_CHARS:
            continue
        try:
            result, phone_trust, aid = _run_and_record(msg)
            results.append({
                "analysis_id":   aid,
                "message":       msg,
                "score":         result.risk_score,
                "verdict":       result.verdict,
                "scam_type":     result.scam_type,
                "scam_label":    result.scam_label,
                "scam_emoji":    result.scam_emoji,
                "top_reason":    result.reasons[0].detail if result.reasons else "",
                "phone_trust":   phone_trust.trust_level if phone_trust.numbers_found else None,
                "numbers_found": phone_trust.numbers_found,
                "reasons":       [r.detail for r in result.reasons],
            })
        except Exception as e:
            logger.warning("[rid=%s] Batch item error: %s", _rid(request), type(e).__name__)
            errors += 1

    results.sort(key=lambda x: x["score"], reverse=True)
    return {"success": True, "data": {"analyzed": len(results), "errors": errors, "results": results}}


# ── File upload helpers ────────────────────────────────────────────────────────
_ALLOWED_MIME = {"text/plain", "text/csv", "application/octet-stream"}


async def _validate_and_read(file: UploadFile, request: Request) -> list[str]:
    """Validate file size and MIME type, read lines. Raises HTTPException on failure."""
    # MIME type check
    if file.content_type and file.content_type.split(";")[0].strip() not in _ALLOWED_MIME:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type: {file.content_type}. Upload a plain .txt file."
        )

    # Filename extension check
    if not (file.filename or "").lower().endswith(".txt"):
        raise HTTPException(status_code=400, detail="Only .txt files are supported")

    # Read with size cap
    raw = await file.read(cfg.MAX_UPLOAD_BYTES + 1)
    if len(raw) > cfg.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {cfg.MAX_UPLOAD_BYTES // 1024} KB."
        )

    return raw.decode("utf-8", errors="replace").splitlines()


def _process_lines(lines: list[str]) -> tuple[list[dict], int, int]:
    """Process lines → results. Returns (results, skipped_long, skipped_limit)."""
    results       = []
    skipped_long  = 0
    skipped_limit = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if len(results) >= cfg.MAX_LINES_PER_FILE:
            skipped_limit += 1
            continue

        if len(line) > cfg.MAX_CHARS_PER_LINE:
            skipped_long += 1
            continue

        try:
            result, phone_trust, aid = _run_and_record(line)
            results.append({
                "analysis_id":   aid,
                "message":       line,
                "score":         result.risk_score,
                "verdict":       result.verdict,
                "scam_type":     result.scam_type,
                "scam_label":    result.scam_label,
                "scam_emoji":    result.scam_emoji,
                "top_reason":    result.reasons[0].detail if result.reasons else "",
                "phone_trust":   phone_trust.trust_level if phone_trust.numbers_found else "",
                "known_org":     phone_trust.known_org or "",
                "numbers_found": ", ".join(phone_trust.numbers_found),
                "has_url":       result.features.has_url,
                "has_phone":     result.features.has_phone,
                "reasons":       [r.detail for r in result.reasons],
            })
        except Exception as e:
            logger.warning("Pipeline error on line: %s", type(e).__name__)

    return results, skipped_long, skipped_limit


def _build_csv(results: list[dict]) -> str:
    output = io.StringIO()
    fields = [
        "score", "verdict", "scam_type", "scam_label",
        "phone_trust", "known_org", "numbers_found",
        "has_url", "has_phone", "top_reason", "message",
    ]
    writer = csv.DictWriter(output, fieldnames=fields,
                            extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for row in results:
        writer.writerow({
            **row,
            "has_url":   "Yes" if row.get("has_url")  else "No",
            "has_phone": "Yes" if row.get("has_phone") else "No",
        })
    return output.getvalue()


# ── POST /analyze/file (JSON) ─────────────────────────────────────────────────
@router.post("/analyze/file")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    if not _check_rate(_get_ip(request)):
        return _rate_exceeded()
    lines = await _validate_and_read(file, request)
    results, skipped_long, skipped_limit = _process_lines(lines)
    results.sort(key=lambda x: x["score"], reverse=True)
    return {
        "success": True,
        "data": {
            "analyzed":      len(results),
            "skipped_long":  skipped_long,
            "skipped_limit": skipped_limit,
            "results":       results,
        },
    }


# ── POST /analyze/file/csv (CSV download) ─────────────────────────────────────
@router.post("/analyze/file/csv")
async def analyze_file_csv(request: Request, file: UploadFile = File(...)):
    if not _check_rate(_get_ip(request), cfg.RATE_LIMIT_UPLOAD, "upload_csv"):
        return _rate_exceeded()
    lines = await _validate_and_read(file, request)
    results, _, _ = _process_lines(lines)
    results.sort(key=lambda x: x["score"], reverse=True)

    csv_content = _build_csv(results)
    safe_name   = (file.filename or "upload").replace(".txt", "") + "_phishy_results.csv"
    # Sanitise filename — no path traversal
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")[:80]

    return StreamingResponse(
        io.BytesIO(csv_content.encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


# ── POST /feedback ─────────────────────────────────────────────────────────────
@router.post("/feedback", response_model=FeedbackResponse)
async def feedback(request: Request, body: FeedbackRequest):
    if not _check_rate(_get_ip(request), cfg.RATE_LIMIT_FEEDBACK, "feedback"):
        return _rate_exceeded()
    engine_verdict = db.get_analysis_verdict(body.analysis_id)
    if engine_verdict is None:
        logger.info("Feedback for unknown analysis_id label=%s", body.user_label)
    else:
        db.record_feedback(
            analysis_id=body.analysis_id,
            engine_verdict=engine_verdict,
            user_label=body.user_label,
        )
    return FeedbackResponse(status="ok")


# ── GET /stats ─────────────────────────────────────────────────────────────────
@router.get("/stats")
async def get_stats():
    flat    = db.get_stats()
    live    = mem_stats.get_stats()
    summary = db.get_summary(days=30)
    return {
        "success": True,
        "data": {
            "total_analyses":  flat["total_analyses"],
            "high_risk":       flat["high_risk"],
            "medium_risk":     flat["medium_risk"],
            "low_risk":        flat["low_risk"],
            "feedback_count":  flat["feedback_count"],
            "agreement_rate":  flat["agreement_rate"],
            "total_analyzed":  flat["total_analyses"],
            "scam_percentage": summary["scam_percentage"],
            "top_scam_types": [
                {"type": t["type"], "label": t["type"].replace("_", " ").title(), "count": t["count"]}
                for t in summary["top_scam_types"]
            ],
            "recent_high":    live["recent_high"],
            "uptime_seconds": live["uptime_seconds"],
            "signals":        summary.get("signals", {}),
        },
    }


# ── GET /report ────────────────────────────────────────────────────────────────
@router.get("/report")
async def get_report(request: Request, days: int = 30):
    # Optional admin token protection
    if cfg.ADMIN_TOKEN:
        token = request.headers.get("X-Admin-Token", "")
        if token != cfg.ADMIN_TOKEN:
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "forbidden"},
            )
    return {"success": True, "data": db.get_summary(days=min(days, 365))}


# ── GET /health ────────────────────────────────────────────────────────────────
@router.get("/health")
async def health():
    return {"status": "ok", "version": cfg.VERSION, "name": cfg.APP_NAME}
