@echo off
cd /d "%~dp0"

if not exist "let_logs" mkdir let_logs
if not exist "sessions" mkdir sessions

if not exist ".venv" (
    echo First-time setup: Creating local Python environment...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo Starting GOS LET Tracker on http://127.0.0.1:8502 ...
streamlit run let_standalone_app.py --server.address="127.0.0.1" --server.port=8502 --browser.gatherUsageStats=false
pause