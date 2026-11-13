@echo off
pushd "%~dp0"

echo "%CD%" | findstr /I "\\Mac\" >nul
if %errorlevel%==0 (
    echo [WARNING] Running from a Mac Shared Folder (\\Mac\Home).
    echo Please copy this folder to C:\Users\%USERNAME%\ so Python venv works properly.
    pause
    popd
    exit /b 1
)

if not exist "let_logs" mkdir let_logs
if not exist "sessions" mkdir sessions

if not exist ".venv\Scripts\activate.bat" (
    echo Creating local Python virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

if not exist ".venv\Scripts\streamlit.exe" (
    if exist "wheelhouse\*.whl" (
        echo Installing Streamlit offline from local wheelhouse...
        pip install --no-index --find-links=wheelhouse -r requirements.txt
    ) else (
        echo Installing Streamlit from PyPI...
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    )
)

if not exist ".venv\Scripts\streamlit.exe" (
    echo [ERROR] Streamlit is not installed. Check internet connection or wheelhouse folder.
    popd
    pause
    exit /b 1
)

echo Starting GOS LET Tracker on http://127.0.0.1:8502 ...
streamlit run let_standalone_app.py --server.address="127.0.0.1" --server.port=8502 --browser.gatherUsageStats=false
popd
pause