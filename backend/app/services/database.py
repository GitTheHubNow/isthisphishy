"""
Is This Phishy — Analytics database.

Supports two backends:
  • Turso via HTTP API — when TURSO_URL + TURSO_TOKEN env vars are set
  • SQLite (local)      — fallback for dev / when env vars absent

Stores rich signal data suitable for bank/ScamWatch API consumers.
Privacy: message_text stored only when STORE_MESSAGE_TEXT=true (default: true).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock

logger = logging.getLogger(__name__)

from app.config import cfg as _cfg

DB_PATH  = os.path.join(_cfg.DATA_DIR, "analytics.db")
_db_lock = Lock()

# ── Backend helpers ───────────────────────────────────────────────────────────
def _use_turso() -> bool:
    return bool(os.getenv("TURSO_URL", "").strip() and os.getenv("TURSO_TOKEN", "").strip())

def _turso_http_url() -> str:
    url = os.getenv("TURSO_URL", "").strip()
    return url.replace("libsql://", "https://")

def _turso_token() -> str:
    return os.getenv("TURSO_TOKEN", "").strip()

def _store_text() -> bool:
    """Whether to store raw message text. Default True."""
    return os.getenv("STORE_MESSAGE_TEXT", "true").lower() not in ("false", "0", "no")

# ── Turso HTTP API ────────────────────────────────────────────────────────────
def _turso_execute(statements: list[dict]) -> list[dict]:
    import httpx
    requests = [{"type": "execute", "stmt": s} for s in statements]
    requests.append({"type": "close"})
    resp = httpx.post(
        f"{_turso_http_url()}/v2/pipeline",
        headers={"Authorization": f"Bearer {_turso_token()}", "Content-Type": "application/json"},
        json={"requests": requests},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    results = []
    for item in data.get("results", []):
        if item.get("type") == "ok":
            rs   = item.get("response", {}).get("result", {})
            cols = [c["name"] for c in rs.get("cols", [])]
            rows = [dict(zip(cols, [v.get("value") for v in row])) for row in rs.get("rows", [])]
            results.append({"rows": rows, "cols": cols, "last_insert_rowid": rs.get("last_insert_rowid")})
        elif item.get("type") == "error":
            raise Exception(f"Turso error: {item.get('error')}")
    return results

def _turso_query(sql: str, args: list = None) -> list[dict]:
    stmt = {"sql": sql}
    if args:
        stmt["args"] = [{"type": "text", "value": str(a)} for a in args]
    results = _turso_execute([stmt])
    return results[0]["rows"] if results else []

def _turso_query_one(sql: str, args: list = None) -> dict | None:
    rows = _turso_query(sql, args)
    return rows[0] if rows else None

def _turso_exec(sql: str, args: list = None) -> int | None:
    stmt = {"sql": sql}
    if args:
        stmt["args"] = [{"type": "text", "value": str(a)} for a in args]
    results = _turso_execute([stmt])
    if results:
        val = results[0].get("last_insert_rowid")
        return int(val) if val is not None else None
    return None

# ── SQLite connection ─────────────────────────────────────────────────────────
@contextmanager
def _sqlite_conn():
    import time as _t
    last_exc = None
    for attempt in range(_cfg.SQLITE_MAX_RETRIES):
        if attempt > 0:
            _t.sleep(0.1 * attempt)
        with _db_lock:
            try:
                con = sqlite3.connect(DB_PATH, timeout=_cfg.SQLITE_TIMEOUT)
                con.row_factory = sqlite3.Row
                try:
                    yield con
                    con.commit()
                    return
                except sqlite3.OperationalError as exc:
                    con.rollback()
                    last_exc = exc
                except Exception:
                    con.rollback()
                    raise
                finally:
                    con.close()
            except sqlite3.OperationalError as exc:
                last_exc = exc
    if last_exc:
        raise last_exc

# ── Unified helpers ───────────────────────────────────────────────────────────
def _query(sql: str, params: list = None) -> list[dict]:
    if _use_turso():
        return _turso_query(sql, params or [])
    with _sqlite_conn() as con:
        cur = con.execute(sql, params or [])
        return [dict(r) for r in cur.fetchall()]

def _query_one(sql: str, params: list = None) -> dict | None:
    rows = _query(sql, params)
    return rows[0] if rows else None

def _exec(sql: str, params: list = None) -> int | None:
    if _use_turso():
        return _turso_exec(sql, params or [])
    with _sqlite_conn() as con:
        cur = con.execute(sql, params or [])
        return cur.lastrowid

# ── Schema ────────────────────────────────────────────────────────────────────
_TABLES = [
    """CREATE TABLE IF NOT EXISTS analyses (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at            TEXT    NOT NULL,
        day                   TEXT    NOT NULL,
        verdict               TEXT    NOT NULL,
        scam_type             TEXT    NOT NULL,
        scam_label            TEXT    NOT NULL DEFAULT '',
        risk_score            INTEGER NOT NULL,
        confidence            REAL    NOT NULL DEFAULT 0,
        message_text          TEXT,
        message_preview       TEXT    NOT NULL DEFAULT '',
        word_count            INTEGER NOT NULL DEFAULT 0,
        brand_impersonated    TEXT,
        urls_found            TEXT    NOT NULL DEFAULT '[]',
        phones_found          TEXT    NOT NULL DEFAULT '[]',
        has_url               INTEGER NOT NULL DEFAULT 0,
        has_phone             INTEGER NOT NULL DEFAULT 0,
        has_urgency           INTEGER NOT NULL DEFAULT 0,
        has_payment           INTEGER NOT NULL DEFAULT 0,
        has_impersonation     INTEGER NOT NULL DEFAULT 0,
        has_domain_mismatch   INTEGER NOT NULL DEFAULT 0,
        has_url_shortener     INTEGER NOT NULL DEFAULT 0,
        has_foreign_number    INTEGER NOT NULL DEFAULT 0,
        urgency_keywords      TEXT    NOT NULL DEFAULT '[]',
        suspicious_keywords   TEXT    NOT NULL DEFAULT '[]',
        patterns_fired        TEXT    NOT NULL DEFAULT '',
        top_reason            TEXT    NOT NULL DEFAULT ''
    )""",
    """CREATE TABLE IF NOT EXISTS feedback (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id     INTEGER NOT NULL,
        engine_verdict  TEXT    NOT NULL,
        user_label      TEXT    NOT NULL,
        agreed          INTEGER NOT NULL,
        day             TEXT    NOT NULL,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_analyses_day       ON analyses(day)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_verdict   ON analyses(verdict)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_type      ON analyses(scam_type)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_brand     ON analyses(brand_impersonated)",
    "CREATE INDEX IF NOT EXISTS idx_feedback_aid       ON feedback(analysis_id)",
]

def init_db() -> None:
    try:
        if _use_turso():
            stmts = [{"sql": s} for s in _TABLES]
            _turso_execute(stmts)
            logger.warning("Analytics DB ready: Turso (%s)", _turso_http_url())
        else:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            with _sqlite_conn() as con:
                for s in _TABLES:
                    con.execute(s)
            logger.warning("Analytics DB ready: SQLite (%s)", DB_PATH)
    except Exception as e:
        logger.warning("DB init failed (non-fatal): %s", e)

# ── Write ─────────────────────────────────────────────────────────────────────
def record_analysis(result, original_text: str = "") -> int | None:
    """
    Insert one analysis row with full signal data.
    Returns the new row id, or None on failure.
    """
    now  = datetime.now(timezone.utc)
    day  = now.strftime("%Y-%m-%d")
    ts   = now.isoformat()
    f    = result.features

    # Message text / preview
    msg_text    = original_text if (_store_text() and original_text) else None
    words       = (original_text or "").split()
    preview     = " ".join(words[:8]) + ("…" if len(words) > 8 else "")

    # Extracted signals
    urls_found   = json.dumps(f.urls[:20] if f.urls else [])
    phones_found = json.dumps(f.phone_numbers[:10] if f.phone_numbers else [])
    urgency_kw   = json.dumps(f.urgency_keywords_found[:10] if f.urgency_keywords_found else [])
    suspicious_kw= json.dumps(f.suspicious_keywords_found[:10] if f.suspicious_keywords_found else [])
    patterns     = ",".join(r.type for r in result.reasons) if result.reasons else ""
    top_reason   = result.reasons[0].detail if result.reasons else ""

    try:
        row_id = _exec(
            """INSERT INTO analyses (
                created_at, day, verdict, scam_type, scam_label,
                risk_score, confidence,
                message_text, message_preview, word_count,
                brand_impersonated,
                urls_found, phones_found,
                has_url, has_phone, has_urgency, has_payment,
                has_impersonation, has_domain_mismatch,
                has_url_shortener, has_foreign_number,
                urgency_keywords, suspicious_keywords,
                patterns_fired, top_reason
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                ts, day,
                result.verdict, result.scam_type,
                getattr(result, "scam_label", ""),
                result.risk_score, result.confidence,
                msg_text, preview, f.word_count,
                f.brand_detected,
                urls_found, phones_found,
                int(f.has_url), int(f.has_phone),
                int(f.urgency_keyword_count > 0),
                int(f.has_payment_request),
                int(f.brand_detected is not None),
                int(f.domain_mismatch),
                int(getattr(f, "has_url_shortener", False)),
                int(getattr(f, "is_foreign_number", False)),
                urgency_kw, suspicious_kw,
                patterns, top_reason,
            ],
        )
        logger.warning("record_analysis OK: id=%s turso=%s verdict=%s", row_id, _use_turso(), result.verdict)
        return row_id
    except Exception as e:
        logger.warning("record_analysis failed: %s", e)
        return None


def record_feedback(analysis_id: int, engine_verdict: str, user_label: str) -> None:
    day            = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    engine_is_scam = engine_verdict in ("high", "medium")
    user_is_scam   = user_label == "scam"
    agreed         = int(engine_is_scam == user_is_scam)
    try:
        _exec(
            "INSERT INTO feedback (analysis_id, engine_verdict, user_label, agreed, day) VALUES (?,?,?,?,?)",
            [analysis_id, engine_verdict, user_label, agreed, day],
        )
    except Exception as e:
        logger.warning("record_feedback failed: %s", e)

# ── Read — internal stats ─────────────────────────────────────────────────────
def get_stats() -> dict:
    try:
        row      = _query_one("SELECT COUNT(*) as n FROM analyses")
        total    = int(row["n"]) if row else 0
        vrows    = _query("SELECT verdict, COUNT(*) as n FROM analyses GROUP BY verdict")
        verdicts = {r["verdict"]: int(r["n"]) for r in vrows}
        fb        = _query_one("SELECT COUNT(*) as total, SUM(agreed) as agreed FROM feedback")
        fb_total  = int(fb["total"])  if fb and fb["total"]  else 0
        fb_agreed = int(fb["agreed"]) if fb and fb["agreed"] else 0
        agreement_rate = round(fb_agreed / fb_total * 100, 1) if fb_total > 0 else None
        return {
            "total_analyses": total,
            "high_risk":      verdicts.get("high",   0),
            "medium_risk":    verdicts.get("medium", 0),
            "low_risk":       verdicts.get("low",    0),
            "feedback_count": fb_total,
            "agreement_rate": agreement_rate,
        }
    except Exception as e:
        logger.warning("get_stats failed: %s", e)
        return {"total_analyses": 0, "high_risk": 0, "medium_risk": 0,
                "low_risk": 0, "feedback_count": 0, "agreement_rate": None}


def get_summary(days: int = 30) -> dict:
    try:
        row      = _query_one("SELECT COUNT(*) as n FROM analyses WHERE day >= date('now', ?)", [f"-{days} days"])
        total    = int(row["n"]) if row else 0
        vrows    = _query("SELECT verdict, COUNT(*) as n FROM analyses WHERE day >= date('now', ?) GROUP BY verdict", [f"-{days} days"])
        verdicts = {r["verdict"]: int(r["n"]) for r in vrows}
        trows    = _query(
            "SELECT scam_type, COUNT(*) as n FROM analyses WHERE day >= date('now', ?) AND scam_type != 'unknown' GROUP BY scam_type ORDER BY n DESC LIMIT 10",
            [f"-{days} days"])
        scam_types = [{"type": r["scam_type"], "count": int(r["n"])} for r in trows]
        drows    = _query("SELECT day, COUNT(*) as n FROM analyses WHERE day >= date('now', ?) GROUP BY day ORDER BY day", [f"-{days} days"])
        daily    = [{"day": r["day"], "count": int(r["n"])} for r in drows]
        srow     = _query_one(
            """SELECT SUM(has_url) as url, SUM(has_phone) as phone, SUM(has_urgency) as urgency,
               SUM(has_payment) as payment, SUM(has_impersonation) as impersonation,
               SUM(has_domain_mismatch) as domain_mismatch, SUM(has_url_shortener) as url_shortener,
               SUM(has_foreign_number) as foreign_number
               FROM analyses WHERE day >= date('now', ?)""",
            [f"-{days} days"])
        signals  = {k: int(srow[k] or 0) for k in ["url","phone","urgency","payment","impersonation","domain_mismatch","url_shortener","foreign_number"]} if srow else {}
        fb       = _query_one("SELECT COUNT(*) as total, SUM(agreed) as agreed FROM feedback WHERE day >= date('now', ?)", [f"-{days} days"])
        fb_total  = int(fb["total"])  if fb and fb["total"]  else 0
        fb_agreed = int(fb["agreed"]) if fb and fb["agreed"] else 0
        accuracy  = round(fb_agreed / fb_total * 100, 1) if fb_total > 0 else None
        fp_rows   = _query("SELECT user_label, COUNT(*) as n FROM feedback WHERE day >= date('now', ?) AND agreed = 0 GROUP BY user_label", [f"-{days} days"])
        scam_flagged = verdicts.get("high", 0) + verdicts.get("medium", 0)

        # Top brands impersonated
        brands = _query(
            "SELECT brand_impersonated, COUNT(*) as n FROM analyses WHERE day >= date('now', ?) AND brand_impersonated IS NOT NULL GROUP BY brand_impersonated ORDER BY n DESC LIMIT 10",
            [f"-{days} days"])

        return {
            "period_days":          days,
            "total_analyzed":       total,
            "scam_percentage":      round(scam_flagged / max(total, 1) * 100, 1),
            "verdicts":             verdicts,
            "top_scam_types":       scam_types,
            "top_brands_targeted":  [{"brand": r["brand_impersonated"], "count": int(r["n"])} for r in brands],
            "daily_volume":         daily,
            "signals":              signals,
            "feedback": {
                "total":           fb_total,
                "accuracy_pct":    accuracy,
                "false_positives": sum(int(r["n"]) for r in fp_rows if r["user_label"] == "not_scam"),
                "false_negatives": sum(int(r["n"]) for r in fp_rows if r["user_label"] == "scam"),
            },
        }
    except Exception as e:
        logger.warning("get_summary failed: %s", e)
        return {"period_days": days, "total_analyzed": 0, "scam_percentage": 0,
                "verdicts": {}, "top_scam_types": [], "daily_volume": [],
                "signals": {}, "feedback": {}}


def get_analysis_verdict(analysis_id: int) -> str | None:
    try:
        row = _query_one("SELECT verdict FROM analyses WHERE id = ?", [analysis_id])
        return row["verdict"] if row else None
    except Exception as e:
        logger.warning("get_analysis_verdict failed: %s", e)
        return None


def get_recent_high(limit: int = 1000) -> list[dict]:
    try:
        return _query(
            "SELECT scam_type, scam_label, verdict, risk_score, day, created_at, message_preview, brand_impersonated FROM analyses WHERE verdict = 'high' ORDER BY id DESC LIMIT ?",
            [limit])
    except Exception as e:
        logger.warning("get_recent_high failed: %s", e)
        return []


# ── Analyst report — for bank / ScamWatch API consumers ──────────────────────
def get_analyst_report(
    days: int = 30,
    scam_type: str = None,
    brand: str = None,
    verdict: str = None,
    limit: int = 500,
) -> dict:
    """
    Full analyst-ready report with individual case records.
    Suitable for bank fraud teams and ScamWatch.
    Protected by ADMIN_TOKEN in the route layer.
    """
    try:
        summary = get_summary(days)

        # Build filtered case query
        where   = ["day >= date('now', ?)"]
        params  = [f"-{days} days"]
        if scam_type:
            where.append("scam_type = ?")
            params.append(scam_type)
        if brand:
            where.append("brand_impersonated = ?")
            params.append(brand)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)

        where_sql = " AND ".join(where)
        cases = _query(
            f"""SELECT
                id, created_at, day, verdict, scam_type, scam_label,
                risk_score, confidence,
                message_text, message_preview, word_count,
                brand_impersonated, urls_found, phones_found,
                has_url, has_phone, has_urgency, has_payment,
                has_impersonation, has_domain_mismatch,
                has_url_shortener, has_foreign_number,
                urgency_keywords, suspicious_keywords,
                patterns_fired, top_reason
            FROM analyses WHERE {where_sql}
            ORDER BY id DESC LIMIT ?""",
            params + [limit],
        )

        # Parse JSON fields and cast integers
        def _parse_case(r: dict) -> dict:
            return {
                "id":                  int(r["id"]),
                "created_at":          r["created_at"],
                "day":                 r["day"],
                "verdict":             r["verdict"],
                "scam_type":           r["scam_type"],
                "scam_label":          r["scam_label"],
                "risk_score":          int(r["risk_score"] or 0),
                "confidence":          float(r["confidence"] or 0),
                "message_text":        r["message_text"],
                "message_preview":     r["message_preview"],
                "word_count":          int(r["word_count"] or 0),
                "brand_impersonated":  r["brand_impersonated"],
                "urls_found":          _safe_json(r["urls_found"]),
                "phones_found":        _safe_json(r["phones_found"]),
                "signals": {
                    "has_url":            bool(int(r["has_url"] or 0)),
                    "has_phone":          bool(int(r["has_phone"] or 0)),
                    "has_urgency":        bool(int(r["has_urgency"] or 0)),
                    "has_payment":        bool(int(r["has_payment"] or 0)),
                    "has_impersonation":  bool(int(r["has_impersonation"] or 0)),
                    "has_domain_mismatch":bool(int(r["has_domain_mismatch"] or 0)),
                    "has_url_shortener":  bool(int(r["has_url_shortener"] or 0)),
                    "has_foreign_number": bool(int(r["has_foreign_number"] or 0)),
                },
                "urgency_keywords":    _safe_json(r["urgency_keywords"]),
                "suspicious_keywords": _safe_json(r["suspicious_keywords"]),
                "patterns_fired":      r["patterns_fired"].split(",") if r["patterns_fired"] else [],
                "top_reason":          r["top_reason"],
            }

        return {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "period_days":   days,
            "filters":       {"scam_type": scam_type, "brand": brand, "verdict": verdict},
            "summary":       summary,
            "total_cases":   len(cases),
            "cases":         [_parse_case(c) for c in cases],
        }
    except Exception as e:
        logger.warning("get_analyst_report failed: %s", e)
        return {"error": str(e)}


def get_flags(
    page: int = 1,
    limit: int = 100,
    verdict: str = None,
    scam_type: str = None,
    brand: str = None,
) -> dict:
    """
    Paginated high-risk flags for the live feed and analyst use.
    Returns { total, page, pages, limit, items }
    """
    try:
        limit  = max(1, min(limit, 500))   # cap per-page at 500
        page   = max(1, page)
        offset = (page - 1) * limit

        where  = []
        params = []
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if scam_type:
            where.append("scam_type = ?")
            params.append(scam_type)
        if brand:
            where.append("brand_impersonated = ?")
            params.append(brand)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        total_row = _query_one(f"SELECT COUNT(*) as n FROM analyses {where_sql}", params)
        total     = int(total_row["n"]) if total_row else 0
        pages     = max(1, -(-total // limit))  # ceiling division

        rows = _query(
            f"""SELECT id, created_at, day, verdict, scam_type, scam_label,
                       risk_score, confidence, message_preview, brand_impersonated,
                       urls_found, phones_found, top_reason
                FROM analyses {where_sql}
                ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [limit, offset],
        )

        items = []
        for r in rows:
            try:
                from datetime import datetime, timezone
                dt       = datetime.fromisoformat(r.get("created_at") or r.get("day") or "")
                secs_ago = max(0, round((datetime.now(timezone.utc) - (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc))).total_seconds()))
            except Exception:
                secs_ago = 0
            items.append({
                "id":           int(r["id"]),
                "created_at":   r.get("created_at", r.get("day", "")),
                "verdict":      r["verdict"],
                "scam_type":    r["scam_type"],
                "scam_label":   r.get("scam_label") or r["scam_type"].replace("_", " ").title(),
                "risk_score":   int(r["risk_score"] or 0),
                "confidence":   float(r["confidence"] or 0),
                "preview":      r.get("message_preview", ""),
                "brand":        r.get("brand_impersonated"),
                "urls_found":   _safe_json(r.get("urls_found")),
                "phones_found": _safe_json(r.get("phones_found")),
                "top_reason":   r.get("top_reason", ""),
                "seconds_ago":  secs_ago,
            })

        return {"total": total, "page": page, "pages": pages, "limit": limit, "items": items}
    except Exception as e:
        logger.warning("get_flags failed: %s", e)
        return {"total": 0, "page": 1, "pages": 1, "limit": limit, "items": []}


def _safe_json(val) -> list:
    try:
        return json.loads(val) if val else []
    except Exception:
        return []
