import sys
import json
import re
import hashlib
import zipfile
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple
import streamlit as st

# --- CROSS-PLATFORM & PYINSTALLER PATH RESOLUTION ---
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent.resolve()
else:
    BASE_DIR = Path(__file__).parent.resolve()

LOG_DROP_DIR = BASE_DIR / "let_logs"
SESSION_DIR = BASE_DIR / "sessions"
LOG_DROP_DIR.mkdir(exist_ok=True)
SESSION_DIR.mkdir(exist_ok=True)

DEFAULT_STREAMS = [
    "GOS_API_Logs",
    "GOS_Console_Errors",
    "GOS_Message_Payloads",
    "Kiosk_Hardware_Events"
]

# --- SECURITY: PII & CREDENTIAL SCRUBBER ---
class LogSanitizer:
    PATTERNS = [
        (re.compile(r'(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), r'\1[REDACTED_TOKEN]'),
        (re.compile(r'("?(?:apiKey|token|password|secret|authorization|jwt)"?\s*:\s*"?)[^"\s,}]+("?)', re.IGNORECASE), r'\1[REDACTED_SECRET]\2'),
        (re.compile(r'("?(?:driverLicense|cdl|ssn|licenseNumber|rfidTag)"?\s*:\s*"?)[^"\s,}]+("?)', re.IGNORECASE), r'\1[REDACTED_PII]\2'),
    ]

    @classmethod
    def sanitize_line(cls, line: str, mask_ips: bool = True) -> str:
        scrubbed = line
        for pattern, replacement in cls.PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        if mask_ips:
            scrubbed = re.sub(r'\b(?:\d{1,3}\.){2}(\d{1,3}\.\d{1,3})\b', r'xxx.xxx.\1', scrubbed)
        return scrubbed

# --- DETERMINISTIC NEUTRAL SUMMARY ENGINE ---
class NeutralSummaryEngine:
    TS_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    CORR_REGEX = re.compile(
        r'(?:visitId|txId|transactionId|correlationId|laneId|kioskId|containerNo|chassisNo)["\s:=]+([A-Za-z0-9\-_]+)',
        re.IGNORECASE
    )
    HTTP_STATUS_REGEX = re.compile(r'(?:HTTP/\d\.\d"\s+|"status(?:Code)?"\s*:\s*|status=)(\d{3})\b', re.IGNORECASE)

    @classmethod
    def parse_ts(cls, line: str) -> datetime | None:
        match = cls.TS_REGEX.search(line)
        if not match:
            return None
        raw_ts = match.group(1).replace(" ", "T")
        try:
            return datetime.fromisoformat(raw_ts)
        except ValueError:
            return None

    @classmethod
    def extract_slice(cls, file_path: Path, start_dt: datetime, end_dt: datetime, mask_ips: bool) -> List[Tuple[datetime | None, str]]:
        extracted = []
        capturing = False
        last_valid_ts = None

        if not file_path.exists() or not file_path.is_file():
            return []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                ts = cls.parse_ts(line)
                if ts:
                    last_valid_ts = ts
                    capturing = (start_dt <= ts <= end_dt)
                    if ts > end_dt + timedelta(minutes=10):
                        break
                if capturing:
                    clean_line = LogSanitizer.sanitize_line(line, mask_ips=mask_ips)
                    extracted.append((last_valid_ts, clean_line))
        return extracted

    @classmethod
    def analyze_merged_events(cls, merged_events: List[Tuple[datetime, str, str]], gap_threshold_sec: float) -> Dict:
        flagged_events = []
        correlation_ids = set()
        http_codes = {}
        silence_gaps = []

        for i, (ts, stream, line) in enumerate(merged_events):
            for m in cls.CORR_REGEX.findall(line):
                if len(m) > 2 and m.lower() not in ("null", "none", "true", "false"):
                    correlation_ids.add(m)

            for code in cls.HTTP_STATUS_REGEX.findall(line):
                http_codes[code] = http_codes.get(code, 0) + 1

            if any(k in line.upper() for k in ["ERROR", "WARN", "EXCEPTION", "TIMEOUT", "FAILED", "FAULT", "REJECT"]):
                flagged_events.append(f"[{ts.strftime('%H:%M:%S.%f')[:-3]} | {stream}] {line[:150]}")

            if i > 0:
                prev_ts, prev_stream, prev_line = merged_events[i - 1]
                delta = (ts - prev_ts).total_seconds()
                if delta >= gap_threshold_sec:
                    silence_gaps.append({
                        "gap_sec": round(delta, 3),
                        "from_ts": prev_ts.strftime("%H:%M:%S.%f")[:-3],
                        "to_ts": ts.strftime("%H:%M:%S.%f")[:-3],
                        "before": f"[{prev_stream}] {prev_line[:85]}",
                        "after": f"[{stream}] {line[:85]}"
                    })

        return {
            "total_events": len(merged_events),
            "correlation_ids": sorted(list(correlation_ids)),
            "http_codes": http_codes,
            "flagged_events": flagged_events,
            "silence_gaps": silence_gaps
        }

# --- JSON PAYLOAD EXTRACTOR & STATE DIFF ENGINE ---
class PayloadExtractor:
    DECODER = json.JSONDecoder()

    @classmethod
    def extract_json_from_line(cls, line: str) -> Tuple[str | None, Dict | List | None]:
        for idx, char in enumerate(line):
            if char in ("{", "["):
                try:
                    obj, _ = cls.DECODER.raw_decode(line, idx)
                    if isinstance(obj, (dict, list)) and len(obj) > 0:
                        return line[:idx].strip(), obj
                except json.JSONDecodeError:
                    continue
        return None, None

    @classmethod
    def flatten_dict(cls, d: Dict, parent_key: str = "", sep: str = ".") -> Dict[str, any]:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(cls.flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v, sort_keys=True)))
            else:
                items.append((new_key, v))
        return dict(items)

    @classmethod
    def diff_consecutive_payloads(cls, prev_obj: Dict, curr_obj: Dict) -> List[str]:
        if not isinstance(prev_obj, dict) or not isinstance(curr_obj, dict):
            return []
        flat_prev = cls.flatten_dict(prev_obj)
        flat_curr = cls.flatten_dict(curr_obj)
        diffs = []

        for k in sorted(set(flat_prev.keys()) | set(flat_curr.keys())):
            if any(t in k.lower() for t in ["timestamp", "time", "createdat", "updatedat"]):
                continue
            if k not in flat_prev:
                diffs.append(f"➕ Added `{k}`: `{flat_curr[k]}`")
            elif k not in flat_curr:
                diffs.append(f"➖ Removed `{k}` (was `{flat_prev[k]}`)")
            elif flat_prev[k] != flat_curr[k]:
                diffs.append(f"🔄 Changed `{k}`: `{flat_prev[k]}` ➔ `{flat_curr[k]}`")
        return diffs

    @classmethod
    def harvest_payloads(cls, merged_events: List[Tuple[datetime, str, str]]) -> List[Dict]:
        harvested = []
        prev_dict_obj = None
        for ts, stream, line in merged_events:
            prefix, obj = cls.extract_json_from_line(line)
            if obj is not None:
                pretty_json = json.dumps(obj, indent=2, sort_keys=True)
                top_keys = list(obj.keys()) if isinstance(obj, dict) else [f"Array[{len(obj)}]"]
                state_changes = []
                if isinstance(obj, dict) and prev_dict_obj is not None:
                    state_changes = cls.diff_consecutive_payloads(prev_dict_obj, obj)
                if isinstance(obj, dict):
                    prev_dict_obj = obj
                harvested.append({
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "stream": stream,
                    "prefix": prefix[:100] if prefix else "",
                    "top_keys": top_keys,
                    "pretty_json": pretty_json,
                    "state_changes": state_changes
                })
        return harvested

# --- SESSION PERSISTENCE ---
def get_session_path(session_name: str) -> Path:
    safe_name = re.sub(r'[^A-Za-z0-9_\-]', '_', session_name)
    return SESSION_DIR / f"{safe_name}.json"

def load_session(session_name: str) -> Dict:
    path = get_session_path(session_name)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {
        "session_id": session_name,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "issues": []
    }

def save_session(data: Dict):
    path = get_session_path(data["session_id"])
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

# --- UI LAYOUT ---
st.set_page_config(page_title="LET Standalone Tracker", layout="wide")

with st.sidebar:
    st.header("🗂️ LET Session Manager")
    existing_sessions = [p.stem for p in sorted(SESSION_DIR.glob("*.json"), reverse=True)]
    default_session = f"LET_{datetime.now().strftime('%Y-%m-%d')}"
    if default_session not in existing_sessions:
        existing_sessions.insert(0, default_session)

    selected_session = st.selectbox("Active Session", options=existing_sessions)
    custom_session = st.text_input("Or Create New Session ID", placeholder="e.g., LET_GOS_2026-11-12_GateB")
    active_session_id = custom_session.strip() if custom_session.strip() else selected_session

    session_data = load_session(active_session_id)
    st.caption(f"Saved locally at: `sessions/{active_session_id}.json`")
    st.metric("Tracked Issues in Session", len(session_data["issues"]))

st.title("🛡️ LET Issue Tracker & Evidence Bundler")
st.caption("100% Offline Standalone • Streamed Disk Reader • Cross-Log Chronological Interleaving")

tab_capture, tab_harvest = st.tabs(["⚡ Phase 1: Live LET Issue Capture", "📦 Phase 2: Post-LET Log Harvester & Summary"])

with tab_capture:
    col_btn, col_form = st.columns([1, 2.2])
    with col_btn:
        st.subheader("1. Instant Timestamp Lock")
        if st.button("⚡ FREEZE TIMESTAMP NOW", type="primary", use_container_width=True):
            st.session_state["frozen_ts"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        current_frozen = st.session_state.get("frozen_ts", datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3])
        st.success(f"**Locked Mark:** `{current_frozen}`")
        q_lane = st.radio("Quick Lane Select", ["InGate 08", "InGate 09", "Trouble 29", "Trouble 30", "OutGate 27", "PED 01", "PED 02", "PED 03", "PED 04", "PED 07", "PED 08", "PED 09", "PED 10", "PED 11", "PED 12", "PED 13", "PED 14", "PED 15", "PED 16", "PED 17", "LSTZ 01", "LSTZ 02", "LSTZ 03", "LSTZ 04", "LSTZ 07", "LSTZ 08", "LSTZ 09", "LSTZ 10", "LSTZ 11", "LSTZ 12", "LSTZ 13", "LSTZ 14", "LSTZ 15", "LSTZ 16", "LSTZ 17", "Custom"], horizontal=True)

    with col_form:
        st.subheader("2. Log Symptom & Target Streams")
        with st.form("capture_form", clear_on_submit=True):
            f_c1, f_c2, f_c3 = st.columns([1.2, 1.2, 1])
            lane_val = f_c1.text_input("Lane / Equipment ID", value="" if q_lane == "Custom" else q_lane)
            ts_val = f_c2.text_input("Issue Timestamp (ISO)", value=current_frozen)
            window_override = f_c3.number_input("Custom Window (± sec)", min_value=5, max_value=600, value=45)
            streams_val = st.multiselect("Log Streams to Include", options=DEFAULT_STREAMS, default=["GOS_API_Logs", "GOS_Console_Errors", "GOS_Message_Payloads"])
            filter_key = st.text_input("Optional Correlation Key / Visit ID", placeholder="e.g., VISIT-99412")
            symptom_notes = st.text_area("Observed Symptom (Visual / Operational Fact Only)")

            if st.form_submit_button("💾 Log Issue to Session", use_container_width=True):
                new_id = f"ISS-{len(session_data['issues']) + 1:02d}"
                session_data["issues"].append({
                    "issue_id": new_id,
                    "timestamp": ts_val.strip(),
                    "location": lane_val.strip() or "Unspecified",
                    "window_sec": int(window_override),
                    "included_logs": streams_val,
                    "highlight_key": filter_key.strip(),
                    "notes": symptom_notes.strip()
                })
                save_session(session_data)
                st.rerun()

    st.divider()
    st.subheader(f"📋 Logged Issues ({len(session_data['issues'])})")
    for idx, iss in enumerate(session_data["issues"]):
        with st.expander(f"**{iss['issue_id']}** | `{iss['timestamp']}` | **{iss['location']}** — {iss['notes'][:70]}...", expanded=False):
            e_c1, e_c2, e_c3 = st.columns([2, 2, 1])
            new_ts = e_c1.text_input("Edit Timestamp", value=iss["timestamp"], key=f"ts_{idx}")
            new_loc = e_c2.text_input("Edit Location", value=iss["location"], key=f"loc_{idx}")
            new_win = e_c3.number_input("Window (±s)", value=iss.get("window_sec", 45), key=f"win_{idx}")
            new_notes = st.text_area("Edit Notes", value=iss["notes"], key=f"notes_{idx}")

            b_c1, b_c2 = st.columns([1, 5])
            if b_c1.button("💾 Update", key=f"upd_{idx}"):
                session_data["issues"][idx].update({
                    "timestamp": new_ts.strip(),
                    "location": new_loc.strip(),
                    "window_sec": int(new_win),
                    "notes": new_notes.strip()
                })
                save_session(session_data)
                st.rerun()
            if b_c2.button("🗑️ Delete Issue", key=f"del_{idx}"):
                session_data["issues"].pop(idx)
                save_session(session_data)
                st.rerun()

with tab_harvest:
    st.subheader("1. Map Raw GOS Log Files from `./let_logs/` Folder")
    local_files = ["[None]"] + [p.name for p in sorted(LOG_DROP_DIR.iterdir()) if p.is_file() and not p.name.startswith(".")]
    stream_mapping: Dict[str, Path | None] = {}
    map_cols = st.columns(len(DEFAULT_STREAMS))
    for i, stream_name in enumerate(DEFAULT_STREAMS):
        chosen = map_cols[i].selectbox(f"File for `{stream_name}`", options=local_files, key=f"map_{stream_name}")
        stream_mapping[stream_name] = (LOG_DROP_DIR / chosen) if chosen != "[None]" else None

    cfg1, cfg2, cfg3 = st.columns(3)
    clock_offset_hr = cfg1.number_input("Server Clock Offset (Hours)", min_value=-24.0, max_value=24.0, value=0.0, step=0.5)
    silence_thresh_sec = cfg2.number_input("Silence Detection Threshold (Seconds)", min_value=0.5, max_value=60.0, value=3.0, step=0.5)
    mask_ips_flag = cfg3.checkbox("Sanitize IPv4 Addresses & Tokens", value=True)

    if st.button("🚀 Generate Neutral Evidence Summary & Dev Zip Bundle", type="primary", use_container_width=True):
        if not session_data["issues"]:
            st.warning("No issues recorded in this session to bundle.")
        else:
            zip_buffer = io.BytesIO()
            report_lines = [
                f"# 🛡️ GOS Post-LET Objective Evidence Report: `{session_data['session_id']}`",
                f"- **Generated:** `{datetime.now().isoformat(timespec='seconds')}` | **Offset:** `{clock_offset_hr:+}h` | **Silence Threshold:** `≥{silence_thresh_sec}s`\n---\n"
            ]

            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for issue in session_data["issues"]:
                    iss_id = issue["issue_id"]
                    win_sec = issue.get("window_sec", 45)
                    marked_dt = datetime.fromisoformat(issue["timestamp"]) + timedelta(hours=clock_offset_hr)
                    start_dt, end_dt = marked_dt - timedelta(seconds=win_sec), marked_dt + timedelta(seconds=win_sec)

                    report_lines.append(f"## `{iss_id}` — {issue['location']} (`{issue['timestamp']}`)")
                    if issue.get("highlight_key"):
                        report_lines.append(f"- **Tagged Correlation / Lookup Key:** `{issue['highlight_key']}`")
                    report_lines.append(f"- **Observed Symptom:** {issue['notes']}\n")

                    merged_timeline: List[Tuple[datetime, str, str]] = []
                    per_stream_blocks = []

                    for stream_name in issue["included_logs"]:
                        fpath = stream_mapping.get(stream_name)
                        if not fpath or not fpath.exists():
                            per_stream_blocks.append(f"#### 📁 `{stream_name}`: *(No log file mapped)*")
                            continue
                        sliced_tuples = NeutralSummaryEngine.extract_slice(fpath, start_dt, end_dt, mask_ips=mask_ips_flag)
                        raw_lines = [line for _, line in sliced_tuples]
                        for ts, line in sliced_tuples:
                            if ts:
                                merged_timeline.append((ts, stream_name, line))
                        slice_text = "\n".join(raw_lines)
                        sha_short = hashlib.sha256(slice_text.encode("utf-8")).hexdigest()[:16]
                        zf.writestr(f"slices/{iss_id}_{stream_name}.log", slice_text or "[No matching lines]")
                        per_stream_blocks.append(
                            f"<details><summary><b>{stream_name}</b> ({len(raw_lines)} lines | SHA-256: <code>{sha_short}</code>)</summary>\n\n```text\n"
                            + ("\n".join(raw_lines[:300]) if raw_lines else "[No events in window]")
                            + "\n```\n</details>\n"
                        )

                    merged_timeline.sort(key=lambda x: x[0])
                    obs = NeutralSummaryEngine.analyze_merged_events(merged_timeline, gap_threshold_sec=silence_thresh_sec)

                    # Save unified cross-stream timeline into ZIP
                    interleaved_lines = [f"[{ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] [{st_name}] {ln}" for ts, st_name, ln in merged_timeline]
                    zf.writestr(f"slices/{iss_id}_UNIFIED_TIMELINE.log", "\n".join(interleaved_lines))

                    report_lines.append("### 📊 Automated Neutral Telemetry Breakdown")
                    report_lines.append(f"- **Total Interleaved Events:** `{obs['total_events']}`")
                    if obs["correlation_ids"]:
                        report_lines.append(f"- **Correlation / Visit IDs:** `{', '.join(obs['correlation_ids'])}`")
                    if obs["http_codes"]:
                        codes_str = ", ".join([f"`HTTP {k}`: {v}" for k, v in sorted(obs["http_codes"].items())])
                        report_lines.append(f"- **Observed HTTP Status Codes:** {codes_str}")
                    for g in obs["silence_gaps"]:
                        report_lines.append(f"- **⏱️ `{g['gap_sec']}s` Silence Gap** (`{g['from_ts']}` ➔ `{g['to_ts']}`)")
                        report_lines.append(f"  - *Before:* `{g['before']}...` | *After:* `{g['after']}...`")
                    if obs["flagged_events"]:
                        report_lines.append(f"- **⚠️ Flagged Error / Warn / Timeout Lines ({len(obs['flagged_events'])}):**")
                        for fe in obs["flagged_events"][:12]:
                            report_lines.append(f"  - `{fe}`")

                    payload_records = PayloadExtractor.harvest_payloads(merged_timeline)
                    report_lines.append(f"\n### 📦 Extracted JSON Message Payloads ({len(payload_records)} captured)")
                    if payload_records:
                        zf.writestr(f"slices/{iss_id}_EXTRACTED_PAYLOADS.json", json.dumps(payload_records, indent=2))
                        for p_idx, rec in enumerate(payload_records, start=1):
                            keys_preview = ", ".join(rec["top_keys"][:6])
                            report_lines.append(f"<details><summary><b>Payload #{p_idx}</b> | <code>{rec['timestamp']}</code> | <b>{rec['stream']}</b> — Keys: <code>[{keys_preview}]</code></summary>\n")
                            for chg in rec["state_changes"][:15]:
                                report_lines.append(f"- {chg}")
                            report_lines.append(f"\n```json\n{rec['pretty_json']}\n```\n</details>\n")

                    report_lines.append("\n### 🗂️ Individual Sanitized Log Slices")
                    report_lines.extend(per_stream_blocks)
                    report_lines.append("---\n")

                final_markdown = "\n".join(report_lines)
                zf.writestr(f"{session_data['session_id']}_Summary_Report.md", final_markdown)
                zf.writestr(f"{session_data['session_id']}_Raw_Session.json", json.dumps(session_data, indent=2))

            report_out_path = SESSION_DIR / f"{session_data['session_id']}_Summary_Report.md"
            report_out_path.write_text(final_markdown, encoding="utf-8")

            st.success(f"Evidence bundle generated and saved to `sessions/{report_out_path.name}`!")
            dl1, dl2 = st.columns(2)
            dl1.download_button("📦 Download Evidence Bundle (.zip)", data=zip_buffer.getvalue(), file_name=f"{session_data['session_id']}_Bundle.zip", mime="application/zip", use_container_width=True)
            dl2.download_button("📄 Download Summary Report (.md)", data=final_markdown, file_name=f"{session_data['session_id']}_Summary_Report.md", mime="text/markdown", use_container_width=True)

            with st.expander("Preview Generated Handoff Report", expanded=True):
                st.markdown(final_markdown, unsafe_allow_html=True)
