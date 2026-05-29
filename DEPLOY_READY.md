# Is This Phishy? — Deployment Guide

## Pre-flight validation
```bash
cd backend
python preflight_check.py
```
All checks must pass before deploying.

---

## Option A — Single host (Railway, recommended)

Backend serves both the API and the frontend HTML from one process.

### Steps

1. **Push to GitHub**
```bash
git init
git add .
git commit -m "Is This Phishy v1.2"
git remote add origin https://github.com/YOURNAME/isthisphishy.git
git push -u origin main
```

2. **Connect to Railway**
   - Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
   - Select your repo — Railway reads `nixpacks.toml` automatically
   - Click Deploy

3. **Set environment variables** in Railway dashboard:
```
DEBUG=false
LOG_LEVEL=WARNING
ALLOWED_ORIGINS=https://your-app.up.railway.app
PHISHY_DATA_DIR=/data
```

4. **Add a persistent volume** (keeps analytics.db across deploys):
   - Railway dashboard → your service → Volumes → Add Volume
   - Mount path: `/data`
   - Then set `PHISHY_DATA_DIR=/data`

5. **Generate a domain**: Settings → Networking → Generate Domain

### Free tier limits
- $5/month credit — enough for low-traffic beta
- Sleeps after inactivity — wakes in ~3 seconds
- No credit card required to start

---

## Option B — Split deploy (Railway backend + Vercel frontend)

Use this when you want a custom domain on Vercel with global CDN for the frontend.

### Backend (Railway)
Follow Option A steps 1–4, plus:
```
API_BASE_URL=https://your-app.up.railway.app
ALLOWED_ORIGINS=https://isthisphishy.vercel.app,https://isthisphishy.com.au
```

### Frontend (Vercel)
1. Create `/frontend/vercel.json`:
```json
{ "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }] }
```

2. In `index.html`, before the closing `</body>`, add:
```html
<script>window.PHISHY_API_BASE = 'https://your-app.up.railway.app'</script>
```

3. Deploy frontend folder to Vercel:
```bash
cd frontend
npx vercel --prod
```

---

## Local development
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # edit as needed
uvicorn app.main:app --reload --port 8000
```
Open `http://localhost:8000`

---

## Environment variables reference

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `false` | Enable debug mode (never in production) |
| `LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `PORT` | `8000` | HTTP port (Railway sets this automatically) |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | Comma-separated CORS origins |
| `RATE_LIMIT` | `100` | Requests per IP per `RATE_WINDOW` seconds |
| `RATE_WINDOW` | `60` | Rate limit window in seconds |
| `MAX_UPLOAD_BYTES` | `1048576` | Max .txt upload size (1 MB) |
| `MAX_LINES_PER_FILE` | `500` | Max messages per file upload |
| `MAX_CHARS_PER_LINE` | `500` | Max chars per message in upload |
| `MAX_BATCH_SIZE` | `100` | Max messages per batch API request |
| `PHISHY_DATA_DIR` | `backend/` | Directory for `analytics.db` |
| `ADMIN_TOKEN` | *(empty)* | Optional token to protect `/api/report` |
| `API_BASE_URL` | *(empty)* | Set for split Vercel/Railway deploy |

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyse a single message |
| `POST` | `/api/analyze/batch` | Analyse up to 100 messages |
| `POST` | `/api/analyze/file` | Upload .txt → JSON results |
| `POST` | `/api/analyze/file/csv` | Upload .txt → CSV download |
| `POST` | `/api/feedback` | Submit user correction |
| `GET` | `/api/stats` | Live + persistent analytics |
| `GET` | `/api/report?days=30` | Full analytics report (JSON) |
| `GET` | `/api/health` | Health check |

---

## Generate a scam trends report
```bash
cd backend
python generate_report.py --month 2026-07          # specific month
python generate_report.py --days 30 --out july.md  # rolling window
```

---

## Privacy guarantees
- Message text is **never stored** — analysed and immediately discarded
- No IP addresses stored permanently
- No user identifiers, no tracking, no ads
- `analytics.db` contains only anonymous aggregate statistics
- Check history stored in browser localStorage only — never sent to server

---

## Scaling limitations (current)
- Rate limiting is in-process — not shared across multiple workers
- SQLite is single-writer — suitable up to ~50 concurrent users
- No caching layer — each request runs the full detection pipeline (~5ms)

All three are acceptable for public beta. Revisit at 10k+ daily analyses.
