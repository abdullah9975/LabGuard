"""
LabGuard Web Dashboard — Flask Application
Provides a browser-based UI for running scans and viewing audit reports.
"""

from flask import Flask, render_template, request, jsonify, send_file
from scanner import scan_network, export_json, export_csv, export_txt
import json
import os
import threading
from datetime import datetime

app = Flask(__name__)
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Thread-safe scan state
scan_state = {"running": False, "progress": "", "result": None, "error": None}
scan_lock = threading.Lock()


def run_scan_thread(targets, port_range):
    """Background thread for non-blocking scan execution."""
    global scan_state
    try:
        with scan_lock:
            scan_state["running"] = True
            scan_state["progress"] = f"Scanning {len(targets)} target(s)..."
            scan_state["result"] = None
            scan_state["error"] = None

        report = scan_network(targets, port_range)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(REPORTS_DIR, f"audit_{ts}")
        export_json(report, base + ".json")
        export_csv(report, base + ".csv")
        export_txt(report, base + ".txt")

        with scan_lock:
            scan_state["running"] = False
            scan_state["progress"] = "Scan complete."
            scan_state["result"] = report
            scan_state["last_base"] = base
    except Exception as e:
        with scan_lock:
            scan_state["running"] = False
            scan_state["error"] = str(e)
            scan_state["progress"] = "Scan failed."


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json()
    raw = data.get("targets", "")
    port_range = data.get("port_range", "common")

    targets = [t.strip() for t in raw.replace(",", "\n").splitlines() if t.strip()]
    if not targets:
        return jsonify({"error": "No targets provided"}), 400
    if len(targets) > 50:
        return jsonify({"error": "Max 50 targets per scan"}), 400

    with scan_lock:
        if scan_state["running"]:
            return jsonify({"error": "Scan already running"}), 409

    t = threading.Thread(target=run_scan_thread, args=(targets, port_range), daemon=True)
    t.start()
    return jsonify({"status": "started", "targets": len(targets)})


@app.route("/api/status")
def api_status():
    with scan_lock:
        state = {
            "running": scan_state["running"],
            "progress": scan_state["progress"],
            "error": scan_state["error"],
            "has_result": scan_state["result"] is not None
        }
    return jsonify(state)


@app.route("/api/result")
def api_result():
    with scan_lock:
        result = scan_state.get("result")
    if not result:
        return jsonify({"error": "No result available"}), 404
    return jsonify(result)


@app.route("/api/download/<fmt>")
def api_download(fmt):
    with scan_lock:
        base = scan_state.get("last_base")
    if not base:
        return jsonify({"error": "No report available"}), 404
    path = base + f".{fmt}"
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True)


@app.route("/api/history")
def api_history():
    files = []
    for f in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if f.endswith(".json"):
            fp = os.path.join(REPORTS_DIR, f)
            try:
                with open(fp) as fh:
                    data = json.load(fh)
                files.append({
                    "filename": f,
                    "date": data["scan_metadata"]["scan_date"],
                    "hosts": data["summary"]["total_hosts"],
                    "critical": data["summary"]["critical_issues"],
                    "compliance": data["summary"]["compliance_status"]
                })
            except Exception:
                pass
    return jsonify(files[:20])


if __name__ == "__main__":
    print("\n  LabGuard Dashboard → http://127.0.0.1:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
