"""recon-runner Flask application.

Run with:  python app.py   (serves http://127.0.0.1:5000)
"""

from __future__ import annotations

import os

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)

from pentest import commands, tools
from pentest.config import ScanConfig
from pentest.engine import ScanEngine
from pentest.store import Store

app = Flask(__name__)
app.secret_key = os.environ.get("RECON_SECRET", "recon-runner-dev-secret")

store = Store()
engine = ScanEngine(store)


def _build_phases(cfg: ScanConfig) -> list:
    """Config-page data: modules grouped by phase, with values + command preview."""
    phases = []
    by_phase = tools.modules_by_phase()
    for pkey in tools.PHASE_ORDER:
        mods = []
        for m in by_phase.get(pkey, []):
            d = m.to_dict()
            d["enabled"] = cfg.module_enabled(m.id)
            d["optvals"] = cfg.options(m.id)
            d["preview"] = commands.preview(m.id, cfg.options(m.id))
            mods.append(d)
        if mods:
            phases.append({"key": pkey,
                           "label": tools.PHASE_LABELS.get(pkey, pkey),
                           "modules": mods})
    return phases


def _globals_from(cfg: ScanConfig, targets_text: str) -> dict:
    return {
        "scan_name": cfg.scan_name,
        "customer_name": cfg.customer_name,
        "targets": targets_text,
        "run_as_root": cfg.run_as_root,
        "module_timeout": cfg.module_timeout,
        "max_concurrency": cfg.max_concurrency,
        "rate_limit": cfg.rate_limit,
        "authorized": cfg.authorized,
        "report_theme": cfg.report_theme,
    }


@app.route("/")
def index():
    return render_template("index.html", scans=store.list_scans())


@app.route("/scan/new")
def new_scan():
    cfg = ScanConfig.defaults()
    cfg.scan_name = "external-pentest"
    return render_template("config.html", phases=_build_phases(cfg),
                           gvals=_globals_from(cfg, ""))


@app.route("/scan", methods=["POST"])
def create_scan():
    targets_text = ""
    upload = request.files.get("hostfile")
    if upload and upload.filename:
        targets_text = upload.read().decode("utf-8", "replace")

    cfg = ScanConfig.from_form(request.form, targets_text=targets_text)
    errors = cfg.validate()
    if errors:
        for e in errors:
            flash(e, "error")
        raw_targets = targets_text or request.form.get("targets", "")
        return render_template("config.html", phases=_build_phases(cfg),
                               gvals=_globals_from(cfg, raw_targets)), 400

    scan_id, _ws = engine.submit(cfg)
    flash(f"Scan started for {cfg.customer_name} ({len(cfg.targets)} target(s)).",
          "success")
    return redirect(url_for("scan_status", scan_id=scan_id))


@app.route("/demo", methods=["POST"])
def start_demo():
    cfg = ScanConfig.defaults()
    cfg.demo = True
    cfg.scan_name = "demo-scan"
    cfg.customer_name = "demo"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10", "192.0.2.20"]
    scan_id, _ws = engine.submit(cfg)
    flash("Demo scan started (renders a report from bundled sample data).", "success")
    return redirect(url_for("scan_status", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_status(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    return render_template("status.html", state=state)


@app.route("/api/scans/<scan_id>")
def api_scan_status(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    return jsonify(state)


@app.route("/api/command-preview", methods=["POST"])
def api_command_preview():
    data = request.get_json(silent=True) or {}
    module_id = data.get("module", "")
    options = data.get("options", {}) or {}
    if not tools.module_by_id(module_id):
        return jsonify(lines=[]), 404
    return jsonify(lines=commands.preview(module_id, options))


@app.route("/api/tools")
def api_tools():
    return jsonify(tools.tool_availability())


@app.route("/scan/<scan_id>/report")
def scan_report(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    path = os.path.join(ws, "report.html")
    if not os.path.isfile(path):
        flash("The report is not ready yet.", "warning")
        return redirect(url_for("scan_status", scan_id=scan_id))
    return send_file(path)


@app.route("/scan/<scan_id>/report/download")
def scan_report_download(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    path = os.path.join(ws, "report.html")
    if not os.path.isfile(path):
        abort(404)
    name = f"report_{state.get('customer_safe', 'scan')}_{scan_id}.html"
    return send_file(path, as_attachment=True, download_name=name)


if __name__ == "__main__":
    host = os.environ.get("RECON_HOST", "127.0.0.1")
    port = int(os.environ.get("RECON_PORT", "5000"))
    app.run(host=host, port=port, debug=bool(os.environ.get("RECON_DEBUG")))
