# 🛡️ LET Issue Tracker & Standalone Evidence Bundler

A local-first, zero-egress Live Equipment Test (LET) issue tracker and post-test log bundler designed for Gate Operating System (GOS) testing. 

During live testing, operators and Product Managers can freeze exact timestamps in a single click and tag visual symptoms without losing focus on the lane. After the test, the bundler slices multi-gigabyte log files around each marked timestamp, scrubs sensitive credentials/PII, interleaves events across streams chronologically, diffs sequential JSON payloads, and generates an objective, non-diagnostic evidence package for engineering handoff.

---

## ✨ Key Capabilities

* **⚡ Phase 1 — One-Click Live Timestamp Lock:** Freeze the exact millisecond an anomaly occurs on the lane, then calmly tag the equipment ID, relevant log streams, correlation keys, and visual notes.
* **📦 Phase 2 — Streamed Post-LET Log Harvester:** Drop raw GOS log files directly into `./let_logs/` after the test—no browser upload size limits or high RAM usage.
* **📊 Neutral Telemetry Engine:** Extracts strictly objective observations (cross-stream silence/hang gaps, HTTP status counts, correlation/visit IDs, and error signatures) without speculating on root causes.
* **🔄 Automated JSON Payload Extraction & State Diffing:** Detects embedded JSON payloads mid-line, pretty-prints them, and highlights added, removed, or modified fields between consecutive payloads.
* **🔒 100% Local & Sanitized:** Runs strictly on `127.0.0.1:8502` with telemetry disabled. Automatically masks Bearer tokens, API secrets, driver PII, and IPv4 prefixes before creating the developer `.zip` bundle.

---

## 🚀 Installation & Quick Start

You can run this tool either as a **Pre-Compiled Standalone Application** (zero Python required, built automatically via GitHub Actions) or directly **From Source** using the included double-click OS launchers.

### Option A: Pre-Compiled Standalone Binary (No Python Required)

Every push to `main` automatically compiles native standalone bundles for **macOS (Apple Silicon `arm64`)** and **Windows (`x64`)** via GitHub Actions.

1. Go to the **Actions** tab in this GitHub repository and click the latest green workflow run (`Build Cross-Platform LET Bundler`).
2. Scroll down to **Artifacts** and download the bundle for your OS:
   * **macOS:** `GOS_LET_Bundler_macOS_arm64.zip`
   * **Windows:** `GOS_LET_Bundler_Windows_x64.zip`
3. Extract the `.zip` archive to a local folder on your machine.
   * **macOS Gatekeeper Note:** Before launching the first time on macOS, open Terminal in the extracted folder and run `xattr -cr .` (or right-click **Open** on `Unlock_Mac_Gatekeeper.command`) to clear the browser quarantine flag.
4. Double-click `GOS_LET_Bundler` (macOS) or `GOS_LET_Bundler.exe` (Windows) to launch the application at `http://127.0.0.1:8502`.

---

### Option B: Run From Source (Python 3.10+)

If you have Python 3.10+ installed, you can clone or download this repository directly and use the native launcher scripts.

#### 🍎 macOS Setup
1. Clone the repository or download and unzip the source folder.
2. If downloaded as a `.zip` via a web browser, right-click `Unlock_Mac_Gatekeeper.command` and select **Open** (or run `xattr -cr . && chmod +x Start_LET_Mac.command` in Terminal).
3. Double-click **`Start_LET_Mac.command`**.
   * On first launch, it automatically creates an isolated `.venv` virtual environment, installs `streamlit`, and opens `http://127.0.0.1:8502`.

#### 🪟 Windows Setup
1. Copy the `gos-let-bundler` folder to a local drive path (e.g., `C:\Users\<YourUsername>\Tools\gos-let-bundler`).
   * *Note for Parallels / VM Users:* Do not run the `.bat` launcher directly from a `\\Mac\Home\` shared network folder, as Windows `cmd.exe` and Python `venv` do not support UNC network paths. Always copy the folder to `C:\` first.
2. Double-click **`Start_LET_Windows.bat`**.
   * On first launch, it creates `.venv`, installs dependencies (from `wheelhouse/` if offline, or PyPI if online), and launches the UI at `http://127.0.0.1:8502`.

---

### 🌐 Offline / Air-Gapped Installation (`wheelhouse`)

To run from source on a locked-down field laptop or VM without internet access:

1. On an internet-connected machine, download the required wheels into a `wheelhouse/` folder inside the project root:
   ```bash
   mkdir -p wheelhouse
   # For Windows x64 (Python 3.11):
   pip3 download -r requirements.txt --dest ./wheelhouse --platform win_amd64 --python-version 311 --only-binary=:all:
