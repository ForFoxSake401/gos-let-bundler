#!/bin/bash
# Move into the directory where this script lives
cd "$(dirname "$0")"

mkdir -p let_logs sessions

# Create isolated virtual environment on first run
if [ ! -d ".venv" ]; then
    echo "First-time setup: Creating local Python environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

# Launch locked strictly to 127.0.0.1 with telemetry disabled
echo "Starting GOS LET Tracker on http://127.0.0.1:8502 ..."
streamlit run let_standalone_app.py \
    --server.address="127.0.0.1" \
    --server.port=8502 \
    --browser.gatherUsageStats=false