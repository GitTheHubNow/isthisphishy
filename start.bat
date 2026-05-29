@echo off
cd /d "%~dp0backend"
if not exist ".venv" (
  echo Creating virtual environment...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
echo Installing dependencies...
pip install -q -r requirements.txt
echo.
echo 🐡 Is This Phishy? is starting...
echo Open http://localhost:8000 in your browser
echo.
uvicorn app.main:app --host 0.0.0.0 --port 8000
pause
