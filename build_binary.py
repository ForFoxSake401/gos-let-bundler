import os
import sys
import shutil
import platform
from pathlib import Path
import PyInstaller.__main__

APP_NAME = "GOS_LET_Bundler"
MAIN_SCRIPT = "let_standalone_app.py"
ENTRYPOINT = "run_app.py"

def build():
    system = platform.system().lower() # 'windows' or 'darwin'
    arch = platform.machine().lower()  # 'amd64', 'arm64', 'x86_64'
    os_label = "macOS" if system == "darwin" else "Windows"
    
    # PyInstaller uses ';' on Windows and ':' on POSIX for --add-data
    sep = ";" if system == "windows" else ":"

    print(f"--- Building {APP_NAME} for {os_label} ({arch}) ---")

    # Clean previous build artifacts
    for folder in ["build", "dist"]:
        if Path(folder).exists():
            shutil.rmtree(folder)

    # Run PyInstaller programmatically
    pyinstaller_args = [
        ENTRYPOINT,
        "--noconfirm",
        "--onedir",
        "--console",  # Keeps local terminal status visible; assures clean shutdown on close
        f"--name={APP_NAME}",
        f"--add-data={MAIN_SCRIPT}{sep}.",
        "--copy-metadata=streamlit",
        "--collect-all=streamlit",
    ]
    PyInstaller.__main__.run(pyinstaller_args)

    # Pre-create the standalone folders inside the compiled output directory
    dist_app_dir = Path("dist") / APP_NAME
    (dist_app_dir / "let_logs").mkdir(parents=True, exist_ok=True)
    (dist_app_dir / "sessions").mkdir(parents=True, exist_ok=True)
    if system == "darwin" and Path("Unlock_Mac_Gatekeeper.command").exists():
        shutil.copy("Unlock_Mac_Gatekeeper.command", dist_app_dir / "Unlock_Mac_Gatekeeper.command")
    # Add a quick-start README inside the bundle
    readme_text = (
        f"{APP_NAME} ({os_label} Standalone Build)\n"
        "==========================================\n"
        "1. Double-click the GOS_LET_Bundler executable to start the local tracker.\n"
        "2. During LET: Use Tab 1 in your browser (http://127.0.0.1:8502) to freeze timestamps.\n"
        "3. Post-LET: Drop raw GOS log files into the 'let_logs' folder in this directory,\n"
        "   then switch to Tab 2 to generate the sanitized dev handoff bundle.\n"
    )
    (dist_app_dir / "README_QUICKSTART.txt").write_text(readme_text, encoding="utf-8")

    # Package into a single portable .zip archive
    archive_name = f"{APP_NAME}_{os_label}_{arch}"
    archive_path = shutil.make_archive(
        base_name=str(Path("dist") / archive_name),
        format="zip",
        root_dir="dist",
        base_dir=APP_NAME
    )
    print(f"--- Successfully created portable bundle: {archive_path} ---")

if __name__ == "__main__":
    build()
