# 🐡 Is This Phishy?

Free Australian scam detection. Paste any SMS, email or message. Instant result. No data stored — ever.

**→ [phishy.com.au](https://phishy.com.au)**

---

## Privacy

We do not:
- Store raw messages
- Store phone numbers
- Store IP addresses
- Require user accounts
- Serve ads or sell data

Every message is analysed and immediately discarded. The only data persisted is anonymous aggregate statistics (verdict counts, scam type counts) — never message content.

---

## Architecture

```
Browser (index.html)
    │  POST /api/analyze
    ▼
FastAPI backend (Railway)
    ├── Feature extraction   — URLs, phones, brands, domain mismatches
    ├── Rule engine          — 14+ structural rules
    ├── Pattern engine       — 50 regex patterns across 10 scam categories
    ├── Scam classifier      — maps signals → human-readable type
    └── Phone trust          — checks numbers against known AU business registry
    │
    └── SQLite (analytics.db) — anonymous stats only
```

---

## Local development

**Requirements:** Python 3.10+

```bash
unzip isthisphishy-v1.zip
cd isthisphishy

# Mac/Linux
chmod +x start.sh && ./start.sh

# Windows
start.bat
```

Open **http://localhost:8000**

First run installs dependencies (~30s). Subsequent starts are instant.

---

## Railway deployment (backend + frontend)

1. **Push to GitHub**
```bash
git init && git add . && git commit -m "Is This Phishy v1.2"
git remote add origin https://github.com/YOUR/isthisphishy.git
git push -u origin main
```

2. **Deploy on Railway**
   - [railway.app](https://railway.app) → New Project → Deploy from GitHub
   - Railway reads `nixpacks.toml` automatically — no config needed
   - Settings → Generate Domain

3. **Set environment variables**
```
DEBUG=false
LOG_LEVEL=WARNING
ALLOWED_ORIGINS=https://your-app.up.railway.app
PHISHY_DATA_DIR=/data
```

4. **Add persistent volume** (keeps analytics.db across deploys)
   - Railway dashboard → your service → Volumes → Add Volume → mount `/data`

---

## Vercel deployment (frontend only)

For split deploy with Vercel frontend + Railway backend:

1. Set on Railway: `ALLOWED_ORIGINS=https://your-vercel-app.vercel.app`
2. Add to `frontend/index.html` before `</body>`:
```html
<script>window.PHISHY_API_BASE = 'https://your-railway-app.up.railway.app'</script>
```
3. Deploy the `frontend/` folder to Vercel

---

## Run preflight validation

```bash
cd backend
python preflight_check.py
# Must output: ALL CHECKS PASSED
```

---

## Generate scam trends report

```bash
cd backend
python generate_report.py --month 2026-07        # calendar month
python generate_report.py --days 30              # rolling window
python generate_report.py --days 7 --out week.md # save to file
```

---

## API reference

| Method | Endpoint | Rate limit | Description |
|---|---|---|---|
| `POST` | `/api/analyze` | 10/min | Single message analysis |
| `POST` | `/api/analyze/batch` | 10/min | Up to 100 messages |
| `POST` | `/api/analyze/file` | 2/min | .txt upload → JSON |
| `POST` | `/api/analyze/file/csv` | 2/min | .txt upload → CSV download |
| `POST` | `/api/feedback` | 20/min | Submit correction |
| `GET` | `/api/stats` | — | Live analytics |
| `GET` | `/api/report?days=30` | — | Full report (JSON) |
| `GET` | `/api/health` | — | Health check |

**Request example:**
```bash
curl -X POST https://your-app.up.railway.app/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"message_text": "Your CommBank account is suspended. Verify: http://commbank-secure.xyz"}'
```

**Response:**
```json
{
  "analysis_id": 42,
  "risk_score": 95,
  "verdict": "high",
  "scam_type": "phishing",
  "scam_label": "Phishing Scam",
  "scam_emoji": "🎣",
  "scam_description": "Tries to steal your credentials or banking details.",
  "confidence": 0.97,
  "reasons": [
    {"type": "domain_mismatch", "detail": "Claims to be Commbank but link goes to a different domain"},
    {"type": "account_suspended", "detail": "Claims your account has been suspended"}
  ],
  "phone_trust": null
}
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `false` | Enable debug mode — never in production |
| `LOG_LEVEL` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `API_HOST` | `0.0.0.0` | Bind host |
| `PORT` | `8000` | Bind port (Railway sets this automatically) |
| `ALLOWED_ORIGINS` | `localhost` | Comma-separated CORS origins |
| `RATE_LIMIT_ANALYZE` | `10` | Requests/min for /analyze |
| `RATE_LIMIT_UPLOAD` | `2` | Requests/min for file uploads |
| `RATE_LIMIT_FEEDBACK` | `20` | Requests/min for /feedback |
| `RATE_WINDOW` | `60` | Rate limit window in seconds |
| `MAX_UPLOAD_BYTES` | `1048576` | Max file size (1 MB) |
| `MAX_LINES_PER_FILE` | `500` | Max messages per file |
| `MAX_CHARS_PER_LINE` | `500` | Max chars per message |
| `MAX_BATCH_SIZE` | `100` | Max messages per batch request |
| `PHISHY_DATA_DIR` | `backend/` | Directory for analytics.db |
| `SQLITE_TIMEOUT` | `5.0` | SQLite connection timeout (seconds) |
| `SQLITE_MAX_RETRIES` | `3` | Retries on DB lock |
| `ADMIN_TOKEN` | *(empty)* | Token to protect /api/report |

---

## Detection categories

| Category | Examples |
|---|---|
| 🎣 Phishing | Account suspended, verify credentials, login urgently |
| 📦 Delivery | AusPost fees, parcel on hold, reschedule delivery |
| 💼 Job scam | Work from home, $500/day, no experience needed |
| 📈 Investment | Crypto bots, guaranteed returns, DM me |
| 🔒 Blackmail | Webcam footage, pay bitcoin |
| 🏛️ Government | ATO refund, Medicare card, Centrelink, Linkt toll |
| ❤️ Romance | Found your number, pig butchering pivot |
| 🎰 Prize | You've won, claim voucher, lottery |
| 💻 Tech support | Remote access, Microsoft technician |

---

## Beta limitations

- Rate limits are in-process (not shared across multiple workers)
- SQLite suitable for up to ~50 concurrent users
- Analytics reset on Railway free tier restart unless persistent volume configured
- NLP layer present but disabled — detection is fully deterministic rule-based
