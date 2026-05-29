"""
Is This Phishy — Analytics database.

SQLite, single file, zero configuration.
Privacy-first: stores only anonymous signals, never raw text or identifiers.

Tables:
  analyses  — one row per message checked
  feedback  — one row per user correction, linked to analysis by id

The database lives at DATA_DIR/analytics.db.
Override location: PHISHY_DATA_DIR environment variable.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Lock

logger = logging.getLogger(__name__)

# ── Location — sourced from central config ────────────────────────────────────
from app.config import cfg as _cfg  # late import avoids circular dependency
DB_PATH = os.path.join(_cfg.DATA_DIR, "analytics.db")

_db_lock = Lock()

# ── Schema ────────────────────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    day                 TEXT    NOT NULL,
    verdict             TEXT    NOT NULL,
    scam_type           TEXT    NOT NULL,
    risk_score          INTEGER NOT NULL,
    has_url             INTEGER NOT NULL DEFAULT 0,
    has_phone           INTEGER NOT NULL DEFAULT 0,
    has_urgency         INTEGER NOT NULL DEFAULT 0,
    has_payment         INTEGER NOT NULL DEFAULT 0,
    has_impersonation   INTEGER NOT NULL DEFAULT 0,
    has_domain_mismatch INTEGER NOT NULL DEFAULT 0,
    confidence          REAL    NOT NULL DEFAULT 0,
    patterns_fired      TEXT    NOT NULL DEFAULT '',
    word_count          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS feedback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER NOT NULL,
    engine_verdict  TEXT    NOT NULL,
    user_label      TEXT    NOT NULL,
    agreed          INTEGER NOT NULL,
    day             TEXT    NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
);

CREATE INDEX IF NOT EXISTS idx_analyses_day     ON analyses(day);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);
CREATE INDEX IF NOT EXISTS idx_analyses_type    ON analyses(scam_type);
CREATE INDEX IF NOT EXISTS idx_feedback_aid     ON feedback(analysis_id);
"""

# ── Connection ────────────────────────────────────────────────────────────────
@contextmanager
def _conn():
    # Thread-safe connection with retry on OperationalError (DB locked).
    # Timeout and retry count come from cfg (SQLITE_TIMEOUT, SQLITE_MAX_RETRIES).
    import time as _t
    from app.config import cfg as _cfg
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
                    logger.warning("DB locked attempt=%d: %s", attempt + 1, exc)
                except Exception:
                    con.rollback()
                    raise
                finally:
                    con.close()
            except sqlite3.OperationalError as exc:
                last_exc = exc
                logger.warning("DB connect failed attempt=%d: %s", attempt + 1, exc)
    if last_exc:
        raise last_exc


def init_db() -> None:
    """Create tables on startup. Safe to call multiple times."""
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with _conn() as con:
            con.executescript(_SCHEMA)
        logger.info("Analytics DB ready: %s", DB_PATH)
    except Exception as e:
        logger.warning("DB init failed (non-fatal): %s", e)


# ── Write ─────────────────────────────────────────────────────────────────────
def record_analysis(result) -> int | None:
    """
    Insert one anonymous analysis row.
    Returns the new row id (used to link feedback), or None on failure.
    Stores NO message text, NO IP, NO PII.
    """
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    f   = result.features
    patterns = ",".join(r.type for r in result.reasons) if result.reasons else ""

    try:
        with _conn() as con:
            cur = con.execute(
                """INSERT INTO analyses
                   (day, verdict, scam_type, risk_score,
                    has_url, has_phone, has_urgency, has_payment,
                    has_impersonation, has_domain_mismatch,
                    confidence, patterns_fired, word_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    day,
                    result.verdict,
                    result.scam_type,
                    result.risk_score,
                    int(f.has_url),
                    int(f.has_phone),
                    int(f.urgency_keyword_count > 0),
                    int(f.has_payment_request),
                    int(f.brand_detected is not None),
                    int(f.domain_mismatch),
                    result.confidence,
                    patterns,
                    f.word_count,
                ),
            )
            return cur.lastrowid
    except Exception as e:
        logger.warning("record_analysis failed (non-fatal): %s", e)
        return None


def record_feedback(analysis_id: int, engine_verdict: str, user_label: str) -> None:
    """
    Insert one feedback row linked to an analysis.
    agreed = 1 when engine and user agree on risk level.
    """
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    engine_is_scam = engine_verdict in ("high", "medium")
    user_is_scam   = user_label == "scam"
    agreed         = int(engine_is_scam == user_is_scam)

    try:
        with _conn() as con:
            con.execute(
                """INSERT INTO feedback
                   (analysis_id, engine_verdict, user_label, agreed, day)
                   VALUES (?,?,?,?,?)""",
                (analysis_id, engine_verdict, user_label, agreed, day),
            )
    except Exception as e:
        logger.warning("record_feedback failed (non-fatal): %s", e)


# ── Read ──────────────────────────────────────────────────────────────────────
def get_stats() -> dict:
    """
    Flat stats dict matching the spec:
    total_analyses, high_risk, medium_risk, low_risk,
    feedback_count, agreement_rate
    """
    try:
        with _conn() as con:
            row = con.execute("SELECT COUNT(*) as n FROM analyses").fetchone()
            total = row["n"] if row else 0

            vrows = con.execute(
                "SELECT verdict, COUNT(*) as n FROM analyses GROUP BY verdict"
            ).fetchall()
            verdicts = {r["verdict"]: r["n"] for r in vrows}

            fb = con.execute(
                "SELECT COUNT(*) as total, SUM(agreed) as agreed FROM feedback"
            ).fetchone()
            fb_total  = fb["total"]  if fb else 0
            fb_agreed = fb["agreed"] if fb and fb["agreed"] else 0
            agreement_rate = round(fb_agreed / fb_total * 100, 1) if fb_total > 0 else None

            return {
                "total_analyses":  total,
                "high_risk":       verdicts.get("high",   0),
                "medium_risk":     verdicts.get("medium", 0),
                "low_risk":        verdicts.get("low",    0),
                "feedback_count":  fb_total,
                "agreement_rate":  agreement_rate,
            }
    except Exception as e:
        logger.warning("get_stats failed: %s", e)
        return {
            "total_analyses": 0, "high_risk": 0, "medium_risk": 0,
            "low_risk": 0, "feedback_count": 0, "agreement_rate": None,
        }


def get_summary(days: int = 30) -> dict:
    """Extended summary used by report generator and /api/report endpoint."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT COUNT(*) as n FROM analyses WHERE day >= date('now', ?)",
                (f"-{days} days",)
            ).fetchone()
            total = row["n"] if row else 0

            vrows = con.execute(
                "SELECT verdict, COUNT(*) as n FROM analyses WHERE day >= date('now', ?) GROUP BY verdict",
                (f"-{days} days",)
            ).fetchall()
            verdicts = {r["verdict"]: r["n"] for r in vrows}

            trows = con.execute(
                """SELECT scam_type, COUNT(*) as n FROM analyses
                   WHERE day >= date('now', ?) AND scam_type != 'unknown'
                   GROUP BY scam_type ORDER BY n DESC LIMIT 10""",
                (f"-{days} days",)
            ).fetchall()
            scam_types = [{"type": r["scam_type"], "count": r["n"]} for r in trows]

            drows = con.execute(
                """SELECT day, COUNT(*) as n FROM analyses
                   WHERE day >= date('now', ?) GROUP BY day ORDER BY day""",
                (f"-{days} days",)
            ).fetchall()
            daily = [{"day": r["day"], "count": r["n"]} for r in drows]

            # Signal frequency
            srows = con.execute(
                """SELECT
                     SUM(has_url)             as url,
                     SUM(has_phone)           as phone,
                     SUM(has_urgency)         as urgency,
                     SUM(has_payment)         as payment,
                     SUM(has_impersonation)   as impersonation,
                     SUM(has_domain_mismatch) as domain_mismatch
                   FROM analyses WHERE day >= date('now', ?)""",
                (f"-{days} days",)
            ).fetchone()
            signals = {
                "url":            srows["url"]            or 0,
                "phone":          srows["phone"]          or 0,
                "urgency":        srows["urgency"]        or 0,
                "payment":        srows["payment"]        or 0,
                "impersonation":  srows["impersonation"]  or 0,
                "domain_mismatch":srows["domain_mismatch"]or 0,
            } if srows else {}

            # Feedback accuracy
            fb = con.execute(
                """SELECT COUNT(*) as total, SUM(agreed) as agreed FROM feedback
                   WHERE day >= date('now', ?)""",
                (f"-{days} days",)
            ).fetchone()
            fb_total  = fb["total"]  if fb else 0
            fb_agreed = fb["agreed"] if fb and fb["agreed"] else 0
            accuracy  = round(fb_agreed / fb_total * 100, 1) if fb_total > 0 else None

            fp_rows = con.execute(
                """SELECT user_label, COUNT(*) as n FROM feedback
                   WHERE day >= date('now', ?) AND agreed = 0 GROUP BY user_label""",
                (f"-{days} days",)
            ).fetchall()
            false_positives = sum(r["n"] for r in fp_rows if r["user_label"] == "not_scam")
            false_negatives = sum(r["n"] for r in fp_rows if r["user_label"] == "scam")

            scam_flagged = verdicts.get("high", 0) + verdicts.get("medium", 0)
            scam_pct = round(scam_flagged / max(total, 1) * 100, 1)

            return {
                "period_days":     days,
                "total_analyzed":  total,
                "scam_percentage": scam_pct,
                "verdicts":        verdicts,
                "top_scam_types":  scam_types,
                "daily_volume":    daily,
                "signals":         signals,
                "feedback": {
                    "total":           fb_total,
                    "accuracy_pct":    accuracy,
                    "false_positives": false_positives,
                    "false_negatives": false_negatives,
                },
            }
    except Exception as e:
        logger.warning("get_summary failed: %s", e)
        return {"period_days": days, "total_analyzed": 0, "scam_percentage": 0,
                "verdicts": {}, "top_scam_types": [], "daily_volume": [],
                "signals": {}, "feedback": {}}


def get_analysis_verdict(analysis_id: int) -> str | None:
    """Fetch the engine verdict for a given analysis_id. Used by /feedback route."""
    try:
        with _conn() as con:
            row = con.execute(
                "SELECT verdict FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            return row["verdict"] if row else None
    except Exception as e:
        logger.warning("get_analysis_verdict failed: %s", e)
        return None


def get_recent_high(limit: int = 10) -> list[dict]:
    """Recent high-risk rows for the live feed."""
    try:
        with _conn() as con:
            rows = con.execute(
                """SELECT scam_type, verdict, risk_score, day FROM analyses
                   WHERE verdict = 'high' ORDER BY id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("get_recent_high failed: %s", e)
        return []
