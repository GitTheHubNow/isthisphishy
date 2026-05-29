#!/usr/bin/env python3
"""
Is This Phishy — Report Generator v1.1
========================================
Reads analytics.db and produces a markdown scam trends report.

Usage:
    python generate_report.py                      # last 30 days
    python generate_report.py --month 2026-07      # specific calendar month
    python generate_report.py --days 7             # last N days
    python generate_report.py --month 2026-07 --out report.md

Output goes to stdout by default, or to --out file.
Run from inside the backend/ directory.
"""
import argparse
import calendar
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.database import init_db, get_summary, get_stats, DB_PATH


SCAM_LABELS = {
    "phishing":    "🎣 Phishing",
    "delivery":    "📦 Delivery Scam",
    "job":         "💼 Job / Income Scam",
    "investment":  "📈 Investment Scam",
    "blackmail":   "🔒 Sextortion / Blackmail",
    "government":  "🏛️ Government Impersonation",
    "romance":     "❤️ Romance Scam",
    "prize":       "🎰 Prize / Lottery Scam",
    "tech_support":"💻 Tech Support Scam",
}

SIGNAL_LABELS = {
    "url":             "Contains URL",
    "phone":           "Contains phone number",
    "urgency":         "Uses urgency language",
    "payment":         "Payment request",
    "impersonation":   "Brand impersonation",
    "domain_mismatch": "Domain mismatch",
}


def bar(count: int, max_count: int, width: int = 24) -> str:
    if max_count == 0:
        return "░" * width
    filled = round(count / max_count * width)
    return "█" * filled + "░" * (width - filled)


def get_month_summary(year: int, month: int) -> dict:
    """Query for a specific calendar month using date range."""
    import sqlite3
    from app.services.database import _conn

    start = f"{year:04d}-{month:02d}-01"
    last  = calendar.monthrange(year, month)[1]
    end   = f"{year:04d}-{month:02d}-{last:02d}"

    try:
        with _conn() as con:
            row = con.execute(
                "SELECT COUNT(*) as n FROM analyses WHERE day BETWEEN ? AND ?",
                (start, end)
            ).fetchone()
            total = row["n"] if row else 0

            vrows = con.execute(
                "SELECT verdict, COUNT(*) as n FROM analyses WHERE day BETWEEN ? AND ? GROUP BY verdict",
                (start, end)
            ).fetchall()
            verdicts = {r["verdict"]: r["n"] for r in vrows}

            trows = con.execute(
                """SELECT scam_type, COUNT(*) as n FROM analyses
                   WHERE day BETWEEN ? AND ? AND scam_type != 'unknown'
                   GROUP BY scam_type ORDER BY n DESC LIMIT 10""",
                (start, end)
            ).fetchall()
            scam_types = [{"type": r["scam_type"], "count": r["n"]} for r in trows]

            drows = con.execute(
                "SELECT day, COUNT(*) as n FROM analyses WHERE day BETWEEN ? AND ? GROUP BY day ORDER BY day",
                (start, end)
            ).fetchall()
            daily = [{"day": r["day"], "count": r["n"]} for r in drows]

            srows = con.execute(
                """SELECT SUM(has_url) as url, SUM(has_phone) as phone,
                          SUM(has_urgency) as urgency, SUM(has_payment) as payment,
                          SUM(has_impersonation) as impersonation,
                          SUM(has_domain_mismatch) as domain_mismatch
                   FROM analyses WHERE day BETWEEN ? AND ?""",
                (start, end)
            ).fetchone()
            signals = {
                "url":            srows["url"]             or 0,
                "phone":          srows["phone"]           or 0,
                "urgency":        srows["urgency"]         or 0,
                "payment":        srows["payment"]         or 0,
                "impersonation":  srows["impersonation"]   or 0,
                "domain_mismatch":srows["domain_mismatch"] or 0,
            } if srows else {}

            fb = con.execute(
                """SELECT COUNT(*) as total, SUM(agreed) as agreed FROM feedback
                   WHERE day BETWEEN ? AND ?""",
                (start, end)
            ).fetchone()
            fb_total  = fb["total"]  if fb else 0
            fb_agreed = fb["agreed"] if fb and fb["agreed"] else 0
            accuracy  = round(fb_agreed / fb_total * 100, 1) if fb_total > 0 else None

            fp_rows = con.execute(
                """SELECT user_label, COUNT(*) as n FROM feedback
                   WHERE day BETWEEN ? AND ? AND agreed = 0 GROUP BY user_label""",
                (start, end)
            ).fetchall()
            false_positives = sum(r["n"] for r in fp_rows if r["user_label"] == "not_scam")
            false_negatives = sum(r["n"] for r in fp_rows if r["user_label"] == "scam")

            scam_flagged = verdicts.get("high", 0) + verdicts.get("medium", 0)
            scam_pct = round(scam_flagged / max(total, 1) * 100, 1)

            return {
                "period":         f"{year:04d}-{month:02d}",
                "total_analyzed": total,
                "scam_percentage":scam_pct,
                "verdicts":       verdicts,
                "top_scam_types": scam_types,
                "daily_volume":   daily,
                "signals":        signals,
                "feedback": {
                    "total":           fb_total,
                    "accuracy_pct":    accuracy,
                    "false_positives": false_positives,
                    "false_negatives": false_negatives,
                },
            }
    except Exception as e:
        print(f"ERROR: DB query failed — {e}", file=sys.stderr)
        sys.exit(1)


def generate(data: dict, period_label: str) -> str:
    now_str  = datetime.now(timezone.utc).strftime("%d %B %Y")
    total    = data["total_analyzed"]
    verdicts = data["verdicts"]
    scam_pct = data["scam_percentage"]
    types    = data["top_scam_types"]
    daily    = data["daily_volume"]
    signals  = data.get("signals", {})
    fb       = data.get("feedback", {})

    lines = []
    a = lines.append

    a("# 🐡 Is This Phishy — Scam Detection Report")
    a(f"**Period:** {period_label} &nbsp;|&nbsp; **Generated:** {now_str} UTC")
    a(f"**Source:** isthisphishy.com.au &nbsp;|&nbsp; Anonymous aggregated data only — no message text stored")
    a("")
    a("---")
    a("")

    # ── Overview ──────────────────────────────────────────────────────────────
    a("## Overview")
    a("")
    a(f"| Metric | Value |")
    a(f"|--------|-------|")
    a(f"| Total messages analysed | **{total:,}** |")
    a(f"| Flagged suspicious | **{scam_pct}%** |")
    a(f"| High risk | **{verdicts.get('high', 0):,}** ({round(verdicts.get('high',0)/max(total,1)*100,1)}%) |")
    a(f"| Medium risk | **{verdicts.get('medium', 0):,}** ({round(verdicts.get('medium',0)/max(total,1)*100,1)}%) |")
    a(f"| Low / clean | **{verdicts.get('low', 0):,}** ({round(verdicts.get('low',0)/max(total,1)*100,1)}%) |")
    if fb.get("accuracy_pct") is not None:
        a(f"| Engine accuracy (user feedback) | **{fb['accuracy_pct']}%** |")
    a("")

    # ── Scam type breakdown ────────────────────────────────────────────────────
    if types:
        a("## Top Scam Types")
        a("")
        max_c = types[0]["count"] if types else 1
        a("```")
        for i, t in enumerate(types, 1):
            label = SCAM_LABELS.get(t["type"], t["type"].replace("_", " ").title())
            pct   = round(t["count"] / max(total, 1) * 100, 1)
            b     = bar(t["count"], max_c)
            a(f"  {i:>2}. {label:<34} {b}  {t['count']:>5,}  ({pct}%)")
        a("```")
        a("")

    # ── Signal frequency ───────────────────────────────────────────────────────
    if signals and any(signals.values()):
        a("## Signal Frequency")
        a("")
        a("How often each risk signal appeared across all analysed messages:")
        a("")
        max_sig = max(signals.values()) if signals else 1
        a("```")
        for key, label in SIGNAL_LABELS.items():
            count = signals.get(key, 0)
            pct   = round(count / max(total, 1) * 100, 1)
            b     = bar(count, max_sig)
            a(f"  {label:<28} {b}  {count:>5,}  ({pct}%)")
        a("```")
        a("")

    # ── Daily volume ───────────────────────────────────────────────────────────
    if daily:
        a("## Daily Volume")
        a("")
        max_day = max(d["count"] for d in daily) if daily else 1
        show    = daily[-14:]  # last 14 days to keep readable
        a("```")
        for d in show:
            b = bar(d["count"], max_day, width=30)
            a(f"  {d['day']}  {b}  {d['count']:>4,}")
        a("```")
        a("")

    # ── Feedback accuracy ──────────────────────────────────────────────────────
    if fb.get("total", 0) > 0:
        a("## Detection Accuracy (from User Feedback)")
        a("")
        a(f"Based on **{fb['total']:,}** user corrections:")
        a("")
        a(f"| Metric | Value |")
        a(f"|--------|-------|")
        a(f"| Agreement rate | **{fb['accuracy_pct']}%** |")
        if fb.get("false_positives", 0) >= 0:
            fp_pct = round(fb.get('false_positives', 0) / max(fb['total'], 1) * 100, 1)
            a(f"| False positives | **{fb.get('false_positives', 0)}** ({fp_pct}%) — engine flagged, user said safe |")
        if fb.get("false_negatives", 0) >= 0:
            fn_pct = round(fb.get('false_negatives', 0) / max(fb['total'], 1) * 100, 1)
            a(f"| False negatives | **{fb.get('false_negatives', 0)}** ({fn_pct}%) — engine missed, user said scam |")
        a("")

    # ── Methodology ───────────────────────────────────────────────────────────
    a("## Methodology & Privacy")
    a("")
    a("- Message text is **never stored** — only anonymous aggregate statistics")
    a("- No IP addresses, no user identifiers, no personally identifiable information")
    a("- Three-layer detection: feature extraction → rule engine (14+ rules) → pattern matching (50 patterns)")
    a("- Scam classification maps signals to one of 9 named categories")
    a("- Accuracy data sourced from voluntary user feedback (\"It's a Scam\" / \"It's Safe\" buttons)")
    a("")
    a("---")
    a("")
    a("*Free to republish with attribution. Data: [isthisphishy.com.au](https://isthisphishy.com.au)*")

    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Is This Phishy scam trends report")
    parser.add_argument("--month", type=str, default=None,
                        help="Calendar month: YYYY-MM (e.g. 2026-07)")
    parser.add_argument("--days",  type=int, default=30,
                        help="Rolling window in days (default: 30). Ignored if --month set.")
    parser.add_argument("--out",   type=str, default=None,
                        help="Output file (default: stdout)")
    args = parser.parse_args()

    init_db()

    if args.month:
        try:
            year, month = map(int, args.month.split("-"))
        except ValueError:
            print(f"ERROR: --month must be YYYY-MM, got {args.month!r}", file=sys.stderr)
            sys.exit(1)
        month_name = datetime(year, month, 1).strftime("%B %Y")
        data = get_month_summary(year, month)
        period_label = month_name
    else:
        data = get_summary(days=args.days)
        period_label = f"Last {args.days} days"

    report = generate(data, period_label)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"Report written to {args.out}")
    else:
        print(report)
