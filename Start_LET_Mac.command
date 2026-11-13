#!/bin/bash
cd "$(dirname -- "${BASH_SOURCE[0]:-$0}")"

mkdir -p let_logs sessions

if [ ! -f ".venv/bin/activate" ]; then
    echo "Creating local Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

if [ ! -f ".venv/bin/streamlit" ]; then
    if [ -d "wheelhouse" ] && [ -n "$(ls -A wheelhouse/*.whl 2>/dev/null)" ]; then
        echo "Installing Streamlit offline from wheelhouse..."
        pip install --no-index --find-links=wheelhouse -r requirements.txt
    else
        echo "Installing Streamlit from PyPI..."
        pip install --upgrade pip
        pip install -r requirements.txt
    fi
fi

echo "Starting LET Tracker on http://127.0.0.1:8502 ..."
streamlit run let_standalone_app.py \
    --server.address="127.0.0.1" \
    --server.port=8502 \
    --browser.gatherUsageStats=false
