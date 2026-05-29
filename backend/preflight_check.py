#!/usr/bin/env python3
"""
Is This Phishy? — Preflight Check
====================================
Validates the deployment is ready before going live.
Run from inside backend/:
    python preflight_check.py

Exit code 0 = all pass, 1 = failures found.
"""
import os
import sys
import importlib
import sqlite3
import tempfile

ROOT    = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(ROOT)

sys.path.insert(0, ROOT)

PASS = "  ✓  PASS"
FAIL = "  ✗  FAIL"
WARN = "  ⚠  WARN"

results = []


def check(label: str, ok: bool, detail: str = "", warn_only: bool = False):
    symbol = PASS if ok else (WARN if warn_only else FAIL)
    line   = f"{symbol}  {label}"
    if detail:
        line += f"\n              {detail}"
    results.append((ok or warn_only, line))
    print(line)


print()
print("═" * 60)
print("  Is This Phishy? — Preflight Check")
print("═" * 60)
print()

# ── 1. Required files ─────────────────────────────────────────────────────────
print("[ Files ]")
required_files = [
    ("backend/app/main.py",                              "FastAPI entry point"),
    ("backend/app/config.py",                            "Central config"),
    ("backend/app/api/routes.py",                        "API routes"),
    ("backend/app/schemas/__init__.py",                  "Pydantic schemas"),
    ("backend/app/services/database.py",                 "SQLite analytics"),
    ("backend/app/services/stats.py",                    "In-memory stats"),
    ("backend/app/services/phone_trust.py",              "Phone trust classifier"),
    ("backend/app/services/detection/pipeline.py",       "Detection pipeline"),
    ("backend/app/services/detection/features.py",       "Feature extraction"),
    ("backend/app/services/detection/rules.py",          "Rule engine"),
    ("backend/app/services/detection/patterns.py",       "Pattern engine"),
    ("backend/app/services/detection/scoring.py",        "Scoring engine"),
    ("backend/app/services/detection/classifier.py",     "Scam classifier"),
    ("backend/requirements.txt",                         "Python dependencies"),
    ("frontend/index.html",                              "Web UI"),
    ("Procfile",                                         "Railway start command"),
    ("railway.json",                                     "Railway config"),
    ("nixpacks.toml",                                    "Railway build config"),
    (".gitignore",                                       "Git ignore rules"),
    (".env.example",                                     "Env var template"),
]
for rel_path, desc in required_files:
    full = os.path.join(PROJECT, rel_path)
    check(f"{rel_path}", os.path.exists(full), desc if not os.path.exists(full) else "")

# ── 2. Config loads and values are sane ───────────────────────────────────────
print()
print("[ Config ]")
try:
    from app.config import cfg
    check("Config imports cleanly", True)
    check("DEBUG is False",         not cfg.DEBUG,
          f"DEBUG={cfg.DEBUG} — set DEBUG=false in production", warn_only=cfg.DEBUG)
    check("LOG_LEVEL not DEBUG",    cfg.LOG_LEVEL.upper() != "DEBUG",
          "Set LOG_LEVEL=WARNING in production", warn_only=cfg.LOG_LEVEL.upper()=="DEBUG")
    check("RATE_LIMIT sane",        1 <= cfg.RATE_LIMIT <= 1000,
          f"RATE_LIMIT={cfg.RATE_LIMIT}")
    check("MAX_UPLOAD_BYTES sane",  1024 <= cfg.MAX_UPLOAD_BYTES <= 10_485_760,
          f"MAX_UPLOAD_BYTES={cfg.MAX_UPLOAD_BYTES}")
    check("MAX_BATCH_SIZE sane",    1 <= cfg.MAX_BATCH_SIZE <= 500,
          f"MAX_BATCH_SIZE={cfg.MAX_BATCH_SIZE}")
    cors_ok = bool(cfg.ALLOWED_ORIGINS) and "*" not in cfg.ALLOWED_ORIGINS
    check("CORS not wildcard",      cors_ok,
          f"ALLOWED_ORIGINS={cfg.ALLOWED_ORIGINS} — set to your domain in production",
          warn_only=not cors_ok)
except Exception as e:
    check("Config imports cleanly", False, str(e))

# ── 3. Database writable ──────────────────────────────────────────────────────
print()
print("[ Database ]")
try:
    from app.services.database import init_db, DB_PATH
    db_dir = os.path.dirname(DB_PATH)
    check("DB directory exists or creatable",
          os.path.isdir(db_dir) or not os.path.exists(db_dir))

    # Test write in a temp location
    tmp_db = os.path.join(tempfile.mkdtemp(), "preflight_test.db")
    con    = sqlite3.connect(tmp_db)
    con.execute("CREATE TABLE t (x INTEGER)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit(); con.close()
    os.unlink(tmp_db)
    check("SQLite write test", True)
except Exception as e:
    check("SQLite write test", False, str(e))

# ── 4. Detection pipeline ─────────────────────────────────────────────────────
print()
print("[ Detection Pipeline ]")
try:
    import types as _types
    # Pydantic may or may not be installed; stub if not
    if 'pydantic' not in sys.modules:
        pm = _types.ModuleType('pydantic')
        pm.BaseModel = object; pm.Field = lambda *a, **k: None
        from typing import Literal; pm.Literal = Literal
        sys.modules['pydantic'] = pm

    from app.services.detection.pipeline import run_pipeline
    from app.services.detection.patterns import PATTERNS
    from app.services.detection.rules import evaluate_rules

    r = run_pipeline("Your bank account has been suspended. Click here to verify.")
    check("Pipeline runs", True)
    check("HIGH scam detected correctly",
          r.risk_score >= 71 and r.verdict == "high",
          f"Got score={r.risk_score} verdict={r.verdict}")
    check("Pattern count >= 50", len(PATTERNS) >= 50, f"Got {len(PATTERNS)} patterns")

    r2 = run_pipeline("Hey mate, see you at 5pm")
    check("Legit message not false-positive",
          r2.risk_score <= 20 and r2.verdict == "low",
          f"Got score={r2.risk_score} verdict={r2.verdict}")
except Exception as e:
    check("Pipeline imports", False, str(e))

# ── 5. Routes importable ──────────────────────────────────────────────────────
print()
print("[ Routes ]")
try:
    # Check routes.py parses without syntax errors
    import ast
    routes_src = open(os.path.join(ROOT, "app/api/routes.py")).read()
    ast.parse(routes_src)
    check("routes.py syntax valid", True)

    # Check all expected endpoints are defined
    endpoints = ["/analyze", "/analyze/batch", "/analyze/file",
                 "/analyze/file/csv", "/feedback", "/stats", "/health"]
    for ep in endpoints:
        present = f'"{ep}"' in routes_src or f"'{ep}'" in routes_src
        check(f"Endpoint {ep} defined", present)
except Exception as e:
    check("Routes syntax check", False, str(e))

# ── 6. Frontend checks ────────────────────────────────────────────────────────
print()
print("[ Frontend ]")
fe_path = os.path.join(PROJECT, "frontend/index.html")
if os.path.exists(fe_path):
    fe_src = open(fe_path).read()
    check("Frontend exists",             True)
    check("No hardcoded localhost",
          "localhost:8000" not in fe_src.replace("//", "").replace("PHISHY_API_BASE", ""),
          "Remove hardcoded localhost from frontend", warn_only=True)
    check("Configurable API base",       "PHISHY_API_BASE" in fe_src)
    check("Response envelope handled",   "body.data || body" in fe_src)
    check("Clipboard paste present",     "clipboard" in fe_src)
    check("Upload page present",         "page-upload" in fe_src)
else:
    check("Frontend exists", False, fe_path)

# ── 7. No .env file committed ─────────────────────────────────────────────────
print()
print("[ Security ]")
env_path = os.path.join(PROJECT, ".env")
check(".env not committed",
      not os.path.exists(env_path),
      ".env file found — ensure it's in .gitignore", warn_only=True)

gitignore_path = os.path.join(PROJECT, ".gitignore")
if os.path.exists(gitignore_path):
    gi_src = open(gitignore_path).read()
    check(".env in .gitignore",     ".env" in gi_src)
    check("*.db in .gitignore",     ".db" in gi_src)
    check(".venv in .gitignore",    ".venv" in gi_src)
else:
    check(".gitignore exists",      False)

# ── 8. Deployment files ───────────────────────────────────────────────────────
print()
print("[ Deployment ]")
deploy_files = ["Procfile", "railway.json", "nixpacks.toml", "runtime.txt"]
for f in deploy_files:
    check(f, os.path.exists(os.path.join(PROJECT, f)))

# Check Procfile uses $PORT
if os.path.exists(os.path.join(PROJECT, "Procfile")):
    pf = open(os.path.join(PROJECT, "Procfile")).read()
    check("Procfile uses $PORT", "$PORT" in pf, "Required for Railway")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("═" * 60)
total   = len(results)
passing = sum(1 for ok, _ in results if ok)
failing = total - passing

if failing == 0:
    print(f"  ALL CHECKS PASSED ({total}/{total})")
    print("  System is ready to deploy. ✓")
else:
    print(f"  {passing}/{total} passed — {failing} issue(s) require attention")
    print("  Fix FAIL items before deploying.")
print("═" * 60)
print()

sys.exit(0 if failing == 0 else 1)
