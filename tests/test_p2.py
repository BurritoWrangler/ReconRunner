"""P2 operator choices must agree with execution and status presentation."""

import io
import json
from pathlib import Path

import pytest

from pentest import cli, commands, tools
from pentest.config import ScanConfig, parse_targets
from pentest.engine import ScanEngine
from pentest.parsers.nmap import Inventory, Service
from pentest.store import Store, new_scan_id


@pytest.fixture
def web(tmp_path, monkeypatch):
    import app
    store = Store(str(tmp_path))
    engine = ScanEngine(store)
    monkeypatch.setattr(app, "store", store)
    monkeypatch.setattr(app, "engine", engine)
    monkeypatch.setattr(app, "_AUTH_CREDENTIALS", None)
    app.app.config["TESTING"] = True
    yield app, app.app.test_client()
    engine.shutdown()


@pytest.mark.parametrize("target", [
    "https://example.test/path", "example.test:443", "192.0.2.10:80",
    "example.test/path", "[2001:db8::1]:443", "192.0.2.999",
    "192.0.2.0/99", "-example.test", "bad host"])
def test_reject_targets_discovery_cannot_consume(target):
    assert parse_targets(target) == ([], [target])


def test_target_dedup_normalizes_equivalent_inputs():
    valid, invalid = parse_targets(
        "Example.TEST.\nexample.test\n2001:0db8::1\n2001:db8::1/128\n"
        "192.0.2.10\n192.0.2.10-11\n192.0.2.11/32")
    assert not invalid
    assert valid == ["example.test", "2001:db8::1", "192.0.2.10", "192.0.2.11"]


@pytest.mark.parametrize("key,value", [
    ("max_concurrency", "not-a-number"), ("module_timeout", "-1"),
    ("rate_limit", "-1"), ("mod__httpx__threads", "oops"),
    ("mod__nmap_tcp__timing", "invalid"), ("report_theme", "invalid")])
def test_bad_configuration_returns_400_without_submission(web, monkeypatch, key, value):
    app, client = web
    monkeypatch.setattr(app.engine, "submit", lambda *a: pytest.fail("invalid scan submitted"))
    data = {"customer_name": "test", "targets": "192.0.2.10", "authorized": "on",
            "mod__httpx__enabled": "on", "mod__nmap_tcp__enabled": "on", key: value}
    response = client.post("/scan", data=data)
    assert response.status_code == 400
    assert b"New scan" in response.data


def test_empty_upload_does_not_fall_back_to_textarea(web, monkeypatch):
    app, client = web
    monkeypatch.setattr(app.engine, "submit", lambda *a: pytest.fail("empty scope submitted"))
    response = client.post("/scan", data={
        "customer_name": "test", "authorized": "on", "targets": "192.0.2.10",
        "hostfile": (io.BytesIO(b""), "scope.txt")})
    assert response.status_code == 400
    assert b"Provide targets" in response.data


def test_enabled_and_automatic_are_mutually_exclusive():
    cfg = ScanConfig.defaults()
    cfg.modules["wpscan"]["enabled"] = True
    cfg.adaptive_modules = ["wpscan"]
    assert any("not both" in error for error in cfg.validate())


@pytest.mark.parametrize("body", [
    [], {"module": "httpx", "options": []},
    {"module": "httpx", "options": {"threads": "bad"}},
    {"module": "nmap_tcp", "options": {"timing": "invalid"}},
    {"module": "nmap_tcp", "options": {"all_ports": "false"}},
    {"module": "httpx", "run_as_root": "false"},
    {"module": "httpx", "rate_limit": -1}])
def test_preview_rejects_malformed_payloads(web, body):
    app, client = web
    response = client.post("/api/command-preview", json=body)
    assert response.status_code == 400
    assert response.json["errors"]


def test_preview_and_execution_share_effective_options(web):
    app, client = web
    cfg = ScanConfig.defaults()
    cfg.run_as_root = False
    cfg.rate_limit = 23
    for mid in ("nmap_tcp", "httpx"):
        response = client.post("/api/command-preview", json={
            "module": mid, "options": cfg.options(mid),
            "run_as_root": False, "rate_limit": 23})
        assert response.status_code == 200
        assert response.json["lines"] == commands.preview(mid, cfg.command_options(mid))
    assert "-sT" in commands.preview("nmap_tcp", cfg.command_options("nmap_tcp"))[0]
    assert "-rate-limit 23" in commands.preview("httpx", cfg.command_options("httpx"))[0]
    assert cfg.options("nmap_tcp")["scan_type"] == "-sS"


def test_availability_uses_selected_binary(web, monkeypatch):
    app, client = web
    monkeypatch.setattr(tools, "which", lambda name: "/bin/feroxbuster" if name == "feroxbuster" else None)
    response = client.post("/api/command-preview", json={
        "module": "content_discovery", "options": {"tool": "feroxbuster"}})
    assert response.json["availability"] == {
        "available": True, "binaries": {"feroxbuster": True}}


def test_dry_run_never_constructs_engine_and_uses_effective_options(monkeypatch, capsys):
    monkeypatch.setattr(cli, "ScanEngine", lambda: pytest.fail("dry run constructed engine"))
    assert cli.main(["--dry-run", "--no-root", "--only", "nmap_tcp,httpx",
                     "--rate-limit", "23"]) == 0
    output = capsys.readouterr().out
    assert "-sT" in output and "-rate-limit 23" in output


@pytest.mark.parametrize("args", [
    ["--enable", "typo"], ["--only", "typo"],
    ["--set", "httpx.threads=oops"], ["--set", "httpx.typo=1"],
    ["--timeout", "-1"], ["--concurrency", "65"],
    ["--set", "nuclei.automatic_scan=tru"],
    ["--set", "httpx.extra_args='unterminated"]])
def test_invalid_cli_choices_fail_even_in_dry_run(monkeypatch, args):
    monkeypatch.setattr(cli, "ScanEngine", lambda: pytest.fail("invalid configuration executed"))
    assert cli.main(["--dry-run"] + args) == 2


def test_cli_disable_overrides_automatic():
    args = cli.build_parser().parse_args(["--automatic", "wpscan", "--disable", "wpscan"])
    cfg = cli.build_config(args)
    assert not cfg.module_enabled("wpscan") and not cfg.adaptive_modules


def test_automatic_retry_uses_only_inventoried_origins(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.adaptive_modules = ["wpscan"]
    sid = new_scan_id()
    ws = engine.store.create_workspace(cfg, sid)
    state = engine.store.initial_state(cfg, sid, ws)
    state["execution_plan"] = {"wpscan": {"installed": False, "status": "disabled"}}
    state["modules"]["wpscan"] = {"runs": [{"status": "error", "label": "old-attempt"}]}
    Path(ws, "httpx.jsonl").write_text("\n".join(json.dumps({"url": url, "tech": ["WordPress"]})
        for url in ("https://site.test/wp-login.php", "https://outside.test/",
                    "https://site.test:443/wp-content/")))
    called = []

    def task(ws, mid, ctx, opts, timeout, resume, execution):
        called.append((ctx.host, ctx.port, ctx.url, resume))
        return [{"task_id": "retried", "label": mid, "status": "missing"}]

    monkeypatch.setattr(engine, "_run_task", task)
    engine._adaptive_trigger(cfg, ws, state,
                             Inventory([Service("site.test", 443, name="https")]), resume=True)
    assert called == [("site.test", "443", "https://site.test:443", True)]
    assert state["execution_plan"]["wpscan"]["mode"] == "automatic"
    assert state["modules"]["wpscan"]["runs"][-1]["status"] == "missing"


def scan_state(app, status):
    cfg = ScanConfig.defaults()
    sid = new_scan_id()
    ws = app.store.create_workspace(cfg, sid)
    state = app.store.initial_state(cfg, sid, ws)
    state["status"] = status
    app.store.save_state(ws, state)
    return sid, ws, state


def test_status_actions_hide_owned_cancelled_scan_and_stale_report(web):
    app, client = web
    sid, ws, state = scan_state(app, "cancelled")
    Path(ws, "report.html").write_text("old report")
    state["report"] = "report.html"
    app.store.save_state(ws, state)
    app.engine.lifecycle.owned.add(sid)
    response = client.get(f"/api/scans/{sid}")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json["terminal"] and not response.json["report_ready"]
    assert not response.json["settled"]
    assert app.store.load_state(ws)["report"] == "report.html"
    assert not response.json["actions"]["resume"] and not response.json["actions"]["delete"]
    assert client.get(f"/scan/{sid}/report").status_code == 302
    assert client.get(f"/scan/{sid}/report/download").status_code == 404
    app.engine.lifecycle.owned.discard(sid)
    released = client.get(f"/api/scans/{sid}").json
    assert released["actions"]["resume"] and released["settled"]


def test_completed_report_keeps_coverage_separate(web):
    app, client = web
    sid, ws, state = scan_state(app, "done")
    state.update(coverage_status="incomplete", coverage_rows=[
        {"id": "nuclei", "status": "failed", "note": "scanner failed"}])
    Path(ws, "report.html").write_text("complete execution, incomplete coverage")
    app.store.save_state(ws, state)
    data = client.get(f"/api/scans/{sid}").json
    assert data["report_ready"] and data["coverage_status"] == "incomplete"
    assert data["coverage_rows"][0]["status"] == "failed"
    assert client.get(f"/scan/{sid}/report").headers["Cache-Control"] == "no-store"


def test_live_execution_does_not_claim_no_findings_before_correlation(web):
    app, client = web
    sid, ws, state = scan_state(app, "running")
    state["execution_plan"] = {"nuclei": {
        "installed": True, "enabled": True, "status": "ok", "tasks": ["task"]}}
    state["modules"] = {"nuclei": {"runs": [{"task_id": "task", "status": "ok"}]}}
    app.store.save_state(ws, state)
    rows = client.get(f"/api/scans/{sid}").json["coverage_rows"]
    row = next(row for row in rows if row["id"] == "nuclei")
    assert row["status"] == "executed / awaiting correlation"


def test_status_api_exposes_live_task_activity(web):
    import os
    import time
    from pentest.checkpoints import atomic_json
    app, client = web
    sid, ws, state = scan_state(app, "running")
    marker = Path(ws, "active", "a1.json")
    marker.parent.mkdir(parents=True)
    atomic_json(str(marker), {
        "task_id": "t1", "attempt_id": "a1", "label": "nmap_tcp",
        "command": "nmap -Pn -sT <b>", "started_at": time.time() - 45,
        "pid": os.getpid()})
    data = client.get(f"/api/scans/{sid}").json
    assert data["console_output_age"] is None  # no console written yet
    (task,) = data["active_tasks"]
    assert task["label"] == "nmap_tcp" and task["process_alive"] is True
    assert task["state"] == "quiet" and task["elapsed_seconds"] >= 44
    marker.unlink()
    assert client.get(f"/api/scans/{sid}").json["active_tasks"] == []


def test_ipv6_service_urls_are_unambiguous():
    service = Service("2001:db8::1", 443, name="https")
    assert service.url() == "https://[2001:db8::1]:443"


def test_automatic_mode_is_visible_while_waiting_for_fingerprint(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.adaptive_modules = ["wpscan"]
    seen = []

    def run(cfg, ws, state, resume):
        seen.append(dict(state["execution_plan"]["wpscan"]))
        engine.lifecycle.event(state["id"]).set()

    monkeypatch.setattr(engine, "_run_real", run)
    engine.run_sync(cfg)
    assert seen[0]["mode"] == "automatic"
    assert seen[0]["status"] == "awaiting fingerprint"


def test_no_matching_automatic_origin_is_not_applicable(tmp_path):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.adaptive_modules = ["wpscan"]
    sid = new_scan_id()
    ws = engine.store.create_workspace(cfg, sid)
    state = engine.store.initial_state(cfg, sid, ws)
    state["execution_plan"] = {"wpscan": {"installed": False, "status": "awaiting fingerprint"}}
    Path(ws, "httpx.jsonl").write_text(json.dumps({
        "url": "https://outside.test", "tech": ["WordPress"]}))
    engine._adaptive_trigger(cfg, ws, state,
                             Inventory([Service("site.test", 443, name="https")]))
    assert "wpscan" not in state["modules"]
    assert state["execution_plan"]["wpscan"]["status"] == "not applicable"
