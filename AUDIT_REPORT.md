# Is This Phishy? — Audit Report
**Date:** May 2026  
**Scope:** Full production readiness audit prior to public deployment  
**Result:** 14 issues found, all auto-fixed in this pass

---

## Issues Found and Fixed

| # | Severity | Location | Issue | Status |
|---|---|---|---|---|
| 1 | HIGH | `main.py` | CORS allowed all origins (`"*"`) | ✅ Fixed — configurable via `ALLOWED_ORIGINS` env var |
| 2 | HIGH | `main.py` | No global exception handler — stack traces could leak to clients | ✅ Fixed — global handler returns `{"error":"internal_error"}` |
| 3 | HIGH | `routes.py` | No file size limit — entire upload read into memory before validation | ✅ Fixed — `MAX_UPLOAD_BYTES` enforced before decode |
| 4 | HIGH | `routes.py` | No MIME type validation on uploads — only checked filename extension | ✅ Fixed — content_type checked against `_ALLOWED_MIME` whitelist |
| 5 | MED | `main.py` | Log level hardcoded to `INFO` | ✅ Fixed — `cfg.LOG_LEVEL` from env, defaults to `WARNING` |
| 6 | MED | `main.py` | No request ID middleware — logs untraceble | ✅ Fixed — `X-Request-ID` header on every response |
| 7 | MED | `routes.py` | Rate limit hardcoded (`100`) | ✅ Fixed — `cfg.RATE_LIMIT` from config |
| 8 | MED | `routes.py` | No max lines per upload | ✅ Fixed — `cfg.MAX_LINES_PER_FILE` enforced |
| 9 | MED | `routes.py` | Batch endpoint allowed 500 messages with no config override | ✅ Fixed — `cfg.MAX_BATCH_SIZE` capped per-request |
| 10 | MED | `routes.py` | Response structure inconsistent across endpoints | ✅ Fixed — all responses wrapped in `{success, data/error}` envelope |
| 11 | MED | `database.py` | Read env var directly (`os.environ.get`) instead of via config | ✅ Fixed — imports `cfg.DATA_DIR` |
| 12 | MED | Project root | `.env.example` missing | ✅ Fixed — created with all supported vars |
| 13 | LOW | `index.html` | API base hardcoded to `window.location.origin` — breaks Vercel split deploy | ✅ Fixed — checks `window.PHISHY_API_BASE` first |
| 14 | LOW | `main.py` | `catch_all` route returned `index.html` for `/api/*` 404s | ✅ Fixed — excludes `/api/` and `/static/` prefixes |

---

## Privacy Audit

| Check | Result |
|---|---|
| Raw message text logged anywhere | ✅ Never — `logger.error` only logs `type(e).__name__` |
| Uploaded file content logged | ✅ Never — content discarded after processing |
| IP addresses stored permanently | ✅ Never — IPs only held in memory for rate limiting window |
| Stack traces exposed to clients | ✅ Never — global handler returns generic `internal_error` |
| Message hashes stored | ✅ Never — only anonymous aggregate stats written to DB |

---

## Architecture Observations (No Action Required)

- **In-memory rate limiting** works for single-process deployment (Railway). If scaled to multiple workers, rate limits would not be shared. Acceptable for current scale.
- **SQLite** is suitable for low-to-medium traffic. If analyses exceed ~100k/day, consider migrating to PostgreSQL.
- **NLP layer** (`nlp.py`) present but disabled (returns 0.0). Scoring is entirely deterministic — good for explainability, acceptable for MVP.
- **`analytics.db` resets on Railway restart** unless a persistent volume is configured. See deployment notes.

---

## Remaining Known Risks

1. **Persistent storage on Railway**: The free tier does not provide persistent volumes by default. `analytics.db` will reset on redeploy. To fix: configure a Railway volume at `/data` and set `PHISHY_DATA_DIR=/data`.
2. **Single-process rate limiting**: Works correctly for one dyno. Not shared across horizontal scale.
3. **No abuse monitoring**: No alerting if one IP hits the rate limit repeatedly. Acceptable for beta.
