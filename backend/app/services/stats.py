"""
In-memory stats store for Is This Phishy.
Tracks: total analyses, verdicts, scam types, recent HIGH flags.
No database — resets on server restart, which is fine for MVP.
Swap for SQLite later when you want persistence across restarts.
"""
from __future__ import annotations
import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class RecentFlag:
    scam_type: str
    scam_label: str
    verdict: str
    risk_score: int
    timestamp: float
    message_preview: str   # first 6 words, anonymised


_lock = Lock()

# Counters
_total_analyzed: int = 0
_verdict_counts: dict[str, int] = defaultdict(int)
_scam_type_counts: dict[str, int] = defaultdict(int)
_recent_high: deque[RecentFlag] = deque(maxlen=20)

# Session start time
_started_at: float = time.time()


def record(result) -> None:
    """Record a pipeline result into the stats store. Thread-safe."""
    global _total_analyzed
    with _lock:
        _total_analyzed += 1
        _verdict_counts[result.verdict] += 1
        if result.scam_type != "unknown":
            _scam_type_counts[result.scam_type] += 1

        if result.verdict == "high":
            # Safe preview: first 6 words, no PII
            words = result.features.text_lower.split()
            preview = " ".join(words[:6])
            if len(words) > 6:
                preview += "…"

            _recent_high.appendleft(RecentFlag(
                scam_type=result.scam_type,
                scam_label=result.scam_label,
                verdict=result.verdict,
                risk_score=result.risk_score,
                timestamp=time.time(),
                message_preview=preview,
            ))


def get_stats() -> dict:
    """Return current stats snapshot."""
    with _lock:
        top_scam_types = sorted(
            _scam_type_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        scam_pct = round(
            (_verdict_counts.get("high", 0) + _verdict_counts.get("medium", 0))
            / max(_total_analyzed, 1) * 100,
            1
        )

        recent = [
            {
                "scam_type": f.scam_type,
                "scam_label": f.scam_label,
                "verdict": f.verdict,
                "risk_score": f.risk_score,
                "preview": f.message_preview,
                "seconds_ago": round(time.time() - f.timestamp),
            }
            for f in _recent_high
        ]

        return {
            "total_analyzed": _total_analyzed,
            "scam_percentage": scam_pct,
            "verdicts": dict(_verdict_counts),
            "top_scam_types": [
                {"type": t, "label": t.replace("_", " ").title(), "count": c}
                for t, c in top_scam_types
            ],
            "recent_high": recent[:10],
            "uptime_seconds": round(time.time() - _started_at),
        }
