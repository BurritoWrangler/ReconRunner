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
import tempfile
import time

from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, send_file, url_for)

from pentest import activity, archive, commands, coverage, tools
from pentest.config import ScanConfig, option_errors
from pentest.engine import ScanEngine
from pentest.store import Store
from pentest.execution import tail as _tail
from pentest.lifecycle import LifecycleConflict

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
            d["automatic"] = m.id in cfg.adaptive_modules
            d["optvals"] = cfg.options(m.id)
            try:
                d["preview"] = commands.preview(m.id, cfg.command_options(m.id))
                d.update(tools.configured_availability(m.id, cfg.command_options(m.id)))
                d["binary"] = " + ".join(d["binaries"])
            except (ValueError, TypeError, KeyError):
                d["preview"] = ["Preview unavailable — correct invalid settings."]
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


def _scan_view(ws, state):
    """Derive UI actions and readiness without overwriting persisted scan state."""
    status = state.get("status")
    terminal = status in ("done", "error", "cancelled", "interrupted")
    sid = state.get("id")
    with engine.lifecycle.lock:
        owned = sid in engine.lifecycle.owned
        reading = bool(engine.lifecycle.readers.get(sid))
    ready = status == "done" and os.path.isfile(os.path.join(ws, "report.html"))
    artifacts = any(r.get("artifacts") or r.get("files")
                    for module in state.get("modules", {}).values()
                    for r in module.get("runs", [])
                    if r.get("status") not in ("running", "pending"))
    state.update(terminal=terminal, settled=terminal and not owned, report_ready=ready,
                 report="report.html" if ready else None)
    state["actions"] = {
        "cancel": status in ("queued", "running") and state.get("phase") != "report",
        "resume": status in ("interrupted", "error", "cancelled") and not owned,
        "delete": terminal and not owned and not reading,
        "partial": bool(artifacts) and status != "queued",
    }
    if status in ("error", "cancelled", "interrupted"):
        state["coverage_status"] = "incomplete"
    elif status == "queued":
        state["coverage_status"] = "pending"
    elif terminal and state.get("coverage_status") in (None, "pending"):
        state["coverage_status"] = "unverified"
    if not terminal or "coverage_rows" not in state:
        state["coverage_rows"] = coverage.coverage_rows(None, state)
    # Live per-task activity (also for terminal scans: a stale marker with a
    # dead PID is the visible trace of an engine crash mid-task).
    state["active_tasks"] = activity.active_tasks(ws)
    try:
        state["console_output_age"] = round(
            time.time() - os.path.getmtime(os.path.join(ws, "logs", "console.log")), 1)
    except OSError:
        state["console_output_age"] = None
    return state


@app.errorhandler(LifecycleConflict)
def lifecycle_conflict(exc):
    return str(exc), 409


# ---- Routes -----------------------------------------------------------------

@app.route("/")
def index():
    scans = []
    for state in store.list_scans():
        ws, current = store.find_scan(state["id"])
        if ws and current:
            scans.append(_scan_view(ws, current))
    return render_template("index.html", scans=scans)


@app.route("/scan/new")
def new_scan():
    cfg = ScanConfig.defaults()
    cfg.run_as_root = os.geteuid() == 0
    cfg.scan_name = "external-pentest"
    return render_template("config.html", phases=_build_phases(cfg),
                           gvals=_globals_from(cfg, ""),
                           missing_default_on=coverage.missing_default_on())


@app.route("/scan", methods=["POST"])
def create_scan():
    targets_text = None
    upload = request.files.get("hostfile")
    if upload and upload.filename:
        targets_text = upload.read().decode("utf-8", "replace")

    cfg = ScanConfig.from_form(request.form, targets_text=targets_text)
    errors = cfg.validate()
    if errors:
        for e in errors:
            flash(e, "error")
        raw_targets = targets_text if targets_text is not None else request.form.get("targets", "")
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
    return render_template("status.html", state=_scan_view(ws, state))


@app.route("/scan/<scan_id>/cancel", methods=["POST"])
def scan_cancel(scan_id):
    """Cancel queued work or stop a running scan's process groups."""
    if engine.cancel(scan_id):
        flash("Cancellation requested — active tools are being stopped.", "success")
    else:
        flash("Scan is not running (already finished or not found).", "warning")
    return redirect(url_for("scan_status", scan_id=scan_id))


@app.route("/scan/<scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    if state.get("status") in ("queued", "running", "cancelling"):
        raise LifecycleConflict("Cancel the scan and wait for it to stop before deleting.")
    if store.delete_scan(scan_id):
        flash("Scan and all its data were deleted.", "success")
    else:
        raise LifecycleConflict("The scan is still active or could not be deleted.")
    return redirect(url_for("index"))


@app.route("/scan/<scan_id>/resume", methods=["POST"])
def scan_resume(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    if state.get("status") == "done":
        flash("Scan already completed; nothing to resume.", "warning")
        return redirect(url_for("scan_status", scan_id=scan_id))
    engine.resume(scan_id, confirm_unverified=request.form.get(
        "confirm_unverified") == "on")
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
    state = _scan_view(ws, state)
    state["console"] = _tail(os.path.join(ws, "logs", "console.log"))
    # Derived, non-persistent fields for the live UI (wall-clock elapsed).
    started = state.get("started_at")
    if started and (not state["terminal"] or state.get("ended_at")):
        end = state.get("ended_at") or time.time()
        state["elapsed_seconds"] = max(0, int(end - started))
    response = jsonify(state)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/command-preview", methods=["POST"])
def api_command_preview():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(lines=[], errors=["Expected a JSON object."]), 400
    module_id = data.get("module", "")
    options = data.get("options", {})
    if not isinstance(module_id, str) or not tools.module_by_id(module_id):
        return jsonify(lines=[]), 404
    if not isinstance(options, dict):
        return jsonify(lines=[], errors=["Options must be an object."]), 400
    errors = option_errors(module_id, options)
    cfg = ScanConfig.defaults()
    cfg.modules[module_id]["options"].update(options)
    if "run_as_root" in data:
        if not isinstance(data["run_as_root"], bool):
            errors.append("run_as_root must be a boolean.")
        else:
            cfg.run_as_root = data["run_as_root"]
    if "rate_limit" in data:
        try:
            cfg.rate_limit = int(str(data["rate_limit"]).strip())
            if cfg.rate_limit < 0:
                raise ValueError
        except (ValueError, TypeError):
            errors.append("Rate limit must be a nonnegative integer.")
    if errors:
        return jsonify(lines=[], errors=errors), 400
    effective = cfg.command_options(module_id)
    return jsonify(lines=commands.preview(module_id, effective),
                   availability=tools.configured_availability(module_id, effective))


@app.route("/api/tools")
def api_tools():
    return jsonify(tools.tool_availability())


@app.route("/scan/<scan_id>/report")
def scan_report(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    path = os.path.join(ws, "report.html")
    if state.get("status") != "done" or not os.path.isfile(path):
        flash("The report is not ready yet.", "warning")
        return redirect(url_for("scan_status", scan_id=scan_id))
    response = send_file(path, conditional=False)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/scan/<scan_id>/report/download")
def scan_report_download(scan_id):
    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)
    path = os.path.join(ws, "report.html")
    if state.get("status") != "done" or not os.path.isfile(path):
        abort(404)
    name = f"report_{state.get('customer_safe', 'scan')}_{scan_id}.html"
    return send_file(path, as_attachment=True, download_name=name)


@app.route("/scan/<scan_id>/export")
def scan_export(scan_id):
    """Export a scan workspace as a tar.gz archive for transfer/archival."""

    ws, state = store.find_scan(scan_id)
    if not state:
        abort(404)

    # Create a tar.gz in a temp location.
    customer = state.get("customer_safe", "scan")
    archive_name = f"recon_{customer}_{scan_id}.tar.gz"
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp.close()
    try:
        archive.export_scan_archive(ws, scan_id, tmp.name)
    except archive.ArchiveError:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        abort(500)

    response = send_file(tmp.name, as_attachment=True, download_name=archive_name,
                         mimetype="application/gzip")

    def _cleanup_export():
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    response.call_on_close(_cleanup_export)
    return response


@app.route("/scan/import", methods=["POST"])
def scan_import():
    """Import a previously exported scan tar.gz archive.

    Extracts into the appropriate results_<customer>/ directory and registers
    the scan in the store index.
    """

    upload = request.files.get("archive")
    if not upload or not upload.filename:
        flash("No archive file provided.", "error")
        return redirect(url_for("index"))

    # Save upload to temp file.
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp.close()
    try:
        upload.save(tmp.name)
        result = archive.import_scan_archive(tmp.name, store)
        flash(f"Scan imported successfully: {result.scan_id}", "success")
        return redirect(url_for("scan_status", scan_id=result.scan_id))
    except archive.ArchiveError as exc:
        flash(str(exc), "error")
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
