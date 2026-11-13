import os
import sys
from pathlib import Path
import streamlit.web.cli as stcli

def resolve_path(path: str) -> str:
    if getattr(sys, "frozen", False):
        basedir = sys._MEIPASS
    else:
        basedir = os.path.dirname(__file__)
    return os.path.join(basedir, path)

if __name__ == "__main__":
    app_path = resolve_path("let_standalone_app.py")
    sys.argv = [
        "streamlit",
        "run",
        app_path,
        "--global.developmentMode=false",
        "--server.address=127.0.0.1",
        "--server.port=8502",
        "--browser.gatherUsageStats=false",
    ]
    sys.exit(stcli.main())