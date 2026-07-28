"""recon-runner Flask application.

Run with:  python app.py   (serves http://127.0.0.1:5000)

Authentication:
    Set RECON_AUTH=user:password to require HTTP Basic Auth on all routes.
    When binding to non-localhost (RECON_HOST != 127.0.0.1/localhost), auth is
    required — the app refuses to start without RECON_AUTH set.
"""

from __future__ import annotations

import functools
import os
import secrets
import time

from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, url_for)

from pentest import commands, coverage, tools
from pentest.config import ScanConfig
from pentest.engine import ScanEngine
from pentest.store import Store

app = Flask(__name__)

# Generate a random secret key if not provided — avoids the hardcoded default
# that would let anyone forge session cookies.
app.secret_key = os.environ.get("RECON_SECRET") or secrets.token_hex(32)

store = Store()
engine = ScanEngine(store)

# Any scan left "running"/"queued" by a previous process can't still be live;
# flag them interrupted so the operator can resume from the overview page.
store.mark_interrupted_orphans()


# ---- Authentication ---------------------------------------------------------

_AUTH_CREDENTIALS: tuple | None = None

_raw_auth = os.environ.get("RECON_AUTH", "").strip()
if _raw_auth and ":" in _raw_auth:
    _user, _pw = _raw_auth.split(":", 1)
    _AUTH_CREDENTIALS = (_user, _pw)


def _check_auth(username: str, password: str) -> bool:
    if _AUTH_CREDENTIALS is None:
        return True
    return (secrets.compare_digest(username, _AUTH_CREDENTIALS[0])
            and secrets.compare_digest(password, _AUTH_CREDENTIALS[1]))


def _auth_required(f):
    """Decorator that enforces HTTP Basic Auth when RECON_AUTH is configured."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if _AUTH_CREDENTIALS is None:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_auth(auth.username or "", auth.password or ""):
            return Response(
                "Authentication required.\n",
                401,
                {"WWW-Authenticate": 'Basic realm="recon-runner"'},
            )
        return f(*args, **kwargs)
    return decorated


# Apply auth to every request via before_request.
@app.before_request
def _enforce_auth():
    if _AUTH_CREDENTIALS is None:
        return None
    auth = request.authorization
    if not auth or not _check_auth(auth.username or "", auth.password or ""):
        return Response(
            "Authentication required.\n",
            401,
            {"WWW-Authenticate": 'Basic realm="recon-runner"'},
        )
    return None


# ---- Helpers ----------------------------------------------------------------

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


def _tail(path: str, max_lines: int = 200, max_bytes: int = 65536) -> str:
    """Return the last ``max_lines`` lines of a (possibly large) text file."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - max_bytes))
            data = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    return "\n".join(data.splitlines()[-max_lines:])


# ---- Routes -----------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", scans=store.list_scans())


@app.route("/scan/new")
def new_scan():
    cfg = ScanConfig.defaults()
    cfg.scan_name = "external-pentest"
    return render_template("config.html", phases=_build_phases(cfg),
                           gvals=_globals_from(cfg, ""),
                           missing_default_on=coverage.missing_default_on())


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
                               gvals=_globals_from(cfg, raw_targets),
                               missing_default_on=coverage.missing_default_on()), 400

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


@app.route("/scan/<scan_id>/cancel", methods=["POST"])
def scan_cancel(scan_id):
    """Cancel a running scan. It will stop after the current tool finishes."""
    if engine.cancel(scan_id):
        flash("Cancellation requested — the scan will stop after the current "
              "tool finishes.", "success")
    else:
        flash("Scan is not running (already finished or not found).", "warning")
    return redirect(url_for("scan_status", scan_id=scan_id))


@app.route("/scan/<scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    if store.delete_scan(scan_id):
        flash("Scan and all its data were deleted.", "success")
    else:
        flash("Could not delete that scan (not found or refused).", "error")
    return redirect(url_for("index"))


@app.route("/scan/<scan_id>/resume", methods=["POST"])
def scan_resume(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    if state.get("status") == "done":
        flash("Scan already completed; nothing to resume.", "warning")
        return redirect(url_for("scan_status", scan_id=scan_id))
    engine.resume(scan_id)
    flash("Resuming scan (completed steps are skipped) …", "success")
    return redirect(url_for("scan_status", scan_id=scan_id))


@app.route("/scan/<scan_id>/partial-report", methods=["POST"])
def scan_partial_report(scan_id):
    """Generate a partial report from whatever data has been collected so far."""
    rel = engine.generate_partial_report(scan_id)
    if not rel:
        flash("Could not generate partial report (scan not found).", "error")
        return redirect(url_for("scan_status", scan_id=scan_id))
    flash("Partial report generated from completed modules.", "success")
    return redirect(url_for("scan_partial_report_view", scan_id=scan_id))


@app.route("/scan/<scan_id>/partial-report/view")
def scan_partial_report_view(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    path = os.path.join(ws, "report_partial.html")
    if not os.path.isfile(path):
        flash("No partial report available yet.", "warning")
        return redirect(url_for("scan_status", scan_id=scan_id))
    return send_file(path)


@app.route("/api/scans/<scan_id>")
def api_scan_status(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    state["console"] = _tail(os.path.join(ws, "logs", "console.log"))
    # Derived, non-persistent fields for the live UI (wall-clock elapsed).
    started = state.get("started_at")
    if started:
        end = state.get("ended_at") or time.time()
        state["elapsed_seconds"] = max(0, int(end - started))
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


@app.route("/scan/<scan_id>/export")
def scan_export(scan_id):
    """Export a scan workspace as a tar.gz archive for transfer/archival."""
    import tarfile
    import tempfile

    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)

    # Create a tar.gz in a temp location.
    customer = state.get("customer_safe", "scan")
    archive_name = f"recon_{customer}_{scan_id}.tar.gz"
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        with tarfile.open(tmp.name, "w:gz") as tar:
            tar.add(ws, arcname=scan_id)
        return send_file(tmp.name, as_attachment=True, download_name=archive_name,
                         mimetype="application/gzip")
    except Exception:
        abort(500)


@app.route("/scan/import", methods=["POST"])
def scan_import():
    """Import a previously exported scan tar.gz archive.

    Extracts into the appropriate results_<customer>/ directory and registers
    the scan in the store index.
    """
    import tarfile
    import tempfile

    upload = request.files.get("archive")
    if not upload or not upload.filename:
        flash("No archive file provided.", "error")
        return redirect(url_for("index"))

    # Save upload to temp file.
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    try:
        upload.save(tmp.name)
        tmp.close()

        # Validate it's a tar.gz and peek at the scan_id (top-level dir name).
        if not tarfile.is_tarfile(tmp.name):
            flash("Uploaded file is not a valid tar.gz archive.", "error")
            return redirect(url_for("index"))

        with tarfile.open(tmp.name, "r:gz") as tar:
            # Security: reject archives with absolute paths or path traversal.
            members = tar.getmembers()
            for m in members:
                if m.name.startswith("/") or ".." in m.name:
                    flash("Archive contains unsafe paths — rejected.", "error")
                    return redirect(url_for("index"))

            # The top-level directory is the scan_id.
            top_dirs = {m.name.split("/", 1)[0] for m in members if "/" in m.name}
            if len(top_dirs) != 1:
                flash("Archive must contain exactly one scan directory.", "error")
                return redirect(url_for("index"))

            scan_id = top_dirs.pop()

            # Read config.json from the archive to determine the customer.
            config_path = f"{scan_id}/config.json"
            try:
                cfg_member = tar.getmember(config_path)
                cfg_fh = tar.extractfile(cfg_member)
                if cfg_fh:
                    import json
                    cfg_data = json.load(cfg_fh)
                    customer_safe = cfg_data.get("customer_safe") or \
                        cfg_data.get("customer_name", "imported").replace(" ", "_")
                else:
                    customer_safe = "imported"
            except (KeyError, ValueError):
                customer_safe = "imported"

            # Extract to the results directory.
            dest_root = os.path.join(store.base_dir, f"results_{customer_safe}")
            os.makedirs(dest_root, exist_ok=True)
            dest_ws = os.path.join(dest_root, scan_id)

            if os.path.exists(dest_ws):
                flash(f"Scan {scan_id} already exists — delete it first to reimport.",
                      "error")
                return redirect(url_for("index"))

            tar.extractall(path=dest_root)

        # Register in the store index.
        from pentest.store import is_valid_scan_id
        if is_valid_scan_id(scan_id) and os.path.isfile(
                os.path.join(dest_ws, "state.json")):
            with store._index_lock:
                store._index[scan_id] = dest_ws
            flash(f"Scan imported successfully: {scan_id}", "success")
            return redirect(url_for("scan_status", scan_id=scan_id))
        else:
            flash("Archive imported but scan_id format is unrecognized.", "warning")
            return redirect(url_for("index"))
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ---- Startup ----------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("RECON_HOST", "127.0.0.1")
    port = int(os.environ.get("RECON_PORT", "5000"))

    # Refuse to bind to a non-localhost address without auth configured.
    if host not in ("127.0.0.1", "localhost", "::1") and _AUTH_CREDENTIALS is None:
        import sys
        print("[!] Binding to a non-localhost address requires authentication.",
              file=sys.stderr)
        print("    Set RECON_AUTH=user:password before starting.", file=sys.stderr)
        sys.exit(1)

    app.run(host=host, port=port, debug=bool(os.environ.get("RECON_DEBUG")))
