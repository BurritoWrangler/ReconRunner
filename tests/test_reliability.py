"""Regression tests for scan integrity; subprocess fixtures are local-only."""

import time
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from pentest.config import ScanConfig
from pentest.engine import ScanEngine
from pentest.store import Store
from pentest.commands import CommandSpec, Ctx, build_commands
from pentest.execution import Artifact, ExecutionContext
from pentest import checkpoints, runner, tools
from pentest.lifecycle import LifecycleConflict


def test_diagnostics_survive_recording(tmp_path):
    engine = ScanEngine(Store(str(tmp_path)))
    state = {"modules": {}}
    engine._record(str(tmp_path), state, "probe", [
        {"status": "partial", "returncode": 2, "output_warnings": ["bad JSON"],
         "started_at": 1, "ended_at": 2}])
    engine._record(str(tmp_path), state, "probe", [{"status": "ok"}])
    entry = state["modules"]["probe"]
    assert entry["status"] == "completed with errors"
    assert entry["runs"][0]["returncode"] == 2
    assert engine._tool_issues(state)[0]["error"] == "bad JSON"


def test_sync_failure_is_terminal(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(engine, "_execute",
                        lambda ws: (_ for _ in ()).throw(ValueError("broken")))
    ws, state = engine.run_sync(ScanConfig.defaults())
    assert state["status"] == "error"
    assert state["ended_at"] <= time.time()
    assert "broken" in state["diagnostics"]


def test_correlation_failure_preserves_inventory(tmp_path, monkeypatch):
    from pentest import software
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(software, "correlate",
                        lambda *a: (_ for _ in ()).throw(ValueError("bad correlation")))
    state = {"modules": {}}
    inv, findings, exploits, web = engine._gather(str(tmp_path), state)
    assert exploits == []
    assert state["collection_issues"][0]["module"] == "software-correlate"


def test_all_modules_declare_artifacts():
    for module in tools.MODULES:
        for spec in build_commands(module.id, {}, Ctx()):
            if spec.label != "nuclei_update":
                assert spec.outputs, module.id
            assert not set(spec.inputs) & {a.path for a in spec.outputs}


def test_empty_results_reused_and_inputs_invalidate(tmp_path):
    source = tmp_path / "input.txt"
    source.write_text("one")
    spec = CommandSpec("empty", [sys.executable, "-c", "pass"],
                       stdout_to=str(tmp_path / "out.jsonl"), inputs=[str(source)])
    first = runner.run_spec(spec, str(tmp_path))
    assert first["status"] == "ok"
    assert runner.run_spec(spec, str(tmp_path), resume=True)["status"] == "skipped"
    source.write_text("two")
    assert runner.run_spec(spec, str(tmp_path), resume=True)["status"] == "ok"
    assert os.path.exists(first["log"])


def test_invalid_and_nonzero_outputs_never_checkpoint(tmp_path):
    for code, expected in [("print('broken')", "partial"),
                           ("raise SystemExit(2)", "error")]:
        spec = CommandSpec("bad", [sys.executable, "-c", code],
                           stdout_to=str(tmp_path / "bad.json"))
        assert runner.run_spec(spec, str(tmp_path))["status"] == expected
        assert checkpoints.load(spec, str(tmp_path)) is None


def test_output_staging_does_not_rewrite_inputs(tmp_path):
    ctx = Ctx(ws=str(tmp_path), targets_file=str(tmp_path / "targets.txt"))
    spec = build_commands("nmap_tcp", {}, ctx)[0]
    staged = runner._stage(spec, str(tmp_path), str(tmp_path / "attempt"))
    assert ctx.targets_file in staged.argv
    assert str(tmp_path / "attempt/artifacts/nmap/tcp") in staged.argv
    assert ctx.targets_file not in runner._resume_outputs(spec, str(tmp_path))


def make_scan(store, status="interrupted"):
    from pentest.store import new_scan_id
    cfg = ScanConfig.defaults()
    sid = new_scan_id()
    ws = store.create_workspace(cfg, sid)
    state = store.initial_state(cfg, sid, ws)
    state["status"] = status
    store.save_state(ws, state)
    return sid, ws


def test_concurrent_resume_is_exclusive(tmp_path, monkeypatch):
    store = Store(str(tmp_path))
    engine = ScanEngine(store)
    sid, ws = make_scan(store)
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    barrier = threading.Barrier(2)

    def resume():
        barrier.wait()
        try:
            return engine.resume(sid)
        except LifecycleConflict:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(lambda _: resume(), range(2)))
    assert outcomes.count(sid) == outcomes.count("conflict") == 1
    assert engine._queue.qsize() == 1
    assert store.delete_scan(sid) is False
    assert engine.cancel(sid)
    # Still owned until the worker has consumed the cancelled queue entry.
    assert store.delete_scan(sid) is False


def test_worker_survives_idle_and_shutdown(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    seen = []
    monkeypatch.setattr(engine, "_execute", lambda ws: seen.append(ws))
    cfg = ScanConfig.defaults()
    engine.submit(cfg)
    engine._queue.join()
    original = engine._worker
    engine.submit(cfg)
    engine._queue.join()
    assert len(seen) == 2 and engine._worker is original
    engine.shutdown()
    assert not original.is_alive()


def test_legacy_resume_needs_confirmation(tmp_path, monkeypatch):
    store = Store(str(tmp_path))
    engine = ScanEngine(store)
    sid, ws = make_scan(store)
    state = store.load_state(ws)
    state.pop("schema_version")
    store.save_state(ws, state)
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    with pytest.raises(LifecycleConflict, match="Legacy"):
        engine.resume(sid)
    assert engine.resume(sid, confirm_unverified=True) == sid


def test_process_group_cancel_and_unique_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_KILL_GRACE", 0.2)
    context = ExecutionContext()
    launched = threading.Event()
    context.on_output = lambda label, text: launched.set() if (
        "ready" in text and not text.startswith("$ ")) else None
    spec = CommandSpec("same-label", [
        sys.executable, "-u", "-c",
        "import subprocess,time; subprocess.Popen(['sleep','30']); print('ready'); time.sleep(30)"])
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(runner.run_spec, spec, str(tmp_path), None, context)
        assert launched.wait(3)
        context.cancel.set()
        result = future.result(timeout=3)
    assert result["status"] == "cancelled"
    second = runner.run_spec(CommandSpec("same-label", ["printf", "hello"]),
                             str(tmp_path))
    assert result["log"] != second["log"]
    assert "ready" in open(result["log"]).read()


def test_large_newline_free_output_streams(tmp_path):
    spec = CommandSpec("verbose", [sys.executable, "-c",
                                  "import sys; sys.stdout.write('x'*2000000)"],
                       stdout_to=str(tmp_path / "large.txt"))
    result = runner.run_spec(spec, str(tmp_path))
    assert result["status"] == "ok"
    assert (tmp_path / "large.txt").stat().st_size == 2000000
    assert "stdout" not in result  # no unbounded captured strings in state


def test_checkpoint_relocation_and_fresh_engine(tmp_path):
    import shutil
    first = tmp_path / "first"
    first.mkdir()
    spec = CommandSpec("portable", ["printf", "[]"], stdout_to=str(first / "out.json"))
    result = runner.run_spec(spec, str(first))
    second = tmp_path / "second"
    shutil.copytree(first, second)
    relocated = CommandSpec("portable", ["printf", "[]"],
                            stdout_to=str(second / "out.json"))
    ScanEngine(Store(str(second)))  # no in-memory completion state needed
    assert runner.run_spec(relocated, str(second), resume=True)["status"] == "skipped"
    (second / "out.json").write_text("{}")
    assert not runner._resume_satisfied(relocated, str(second))
    assert result["status"] == "ok"


def test_checkpoint_publish_failure_never_claims_success(tmp_path, monkeypatch):
    spec = CommandSpec("publish", ["printf", "[]"], stdout_to=str(tmp_path / "out.json"))
    monkeypatch.setattr(checkpoints, "save",
                        lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    result = runner.run_spec(spec, str(tmp_path))
    assert result["status"] == "error"
    assert "disk full" in result["error"]
    assert not runner._resume_satisfied(spec, str(tmp_path))
    assert (tmp_path / "out.json").read_text() == "[]"


def test_inputs_changed_midrun_cannot_checkpoint(tmp_path):
    source = tmp_path / "input.txt"
    source.write_text("before")
    spec = CommandSpec("mutates-input", [
        sys.executable, "-c",
        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('after'); print('[]')",
        str(source)], stdout_to=str(tmp_path / "out.json"), inputs=[str(source)])
    result = runner.run_spec(spec, str(tmp_path))
    assert result["status"] == "partial"
    assert "changed" in result["error"]
    assert not runner._resume_satisfied(spec, str(tmp_path))


def test_cancel_before_launch_has_no_side_effect(tmp_path):
    context = ExecutionContext()
    context.cancel.set()
    marker = tmp_path / "marker"
    spec = CommandSpec("cancelled", ["touch", str(marker)])
    assert runner.run_spec(spec, str(tmp_path), on_output=context)["status"] == "cancelled"
    assert not marker.exists()


def test_known_exit_policy_and_unknown_failure(tmp_path):
    spec = CommandSpec("known", [sys.executable, "-c", "raise SystemExit(1)"],
                       success_codes=(0, 1))
    assert runner.run_spec(spec, str(tmp_path))["status"] == "ok"
    spec.success_codes = (0,)
    assert runner.run_spec(spec, str(tmp_path))["status"] == "error"


def test_snapshot_uses_terminal_attempt_not_live_canonical(tmp_path):
    from pentest.snapshots import snapshot
    spec = CommandSpec("stable", ["printf", "[]"], stdout_to=str(tmp_path / "data.json"))
    result = runner.run_spec(spec, str(tmp_path))
    (tmp_path / "data.json").write_text("being overwritten")
    state = {"schema_version": 2, "status": "running",
             "modules": {"stable": {"runs": [result]}}}
    with snapshot(str(tmp_path), state) as root:
        assert open(os.path.join(root, "data.json")).read() == "[]"
        assert not os.path.exists(os.path.join(root, "attempts"))


def test_coverage_uses_saved_plan_and_latest_results(tmp_path, monkeypatch):
    from pentest import coverage
    state = {"modules": {"nuclei": {"runs": [
        {"task_id": "one", "status": "error"},
        {"task_id": "one", "status": "ok"}]}},
        "execution_plan": {"nuclei": {"installed": True, "enabled": True,
                                    "status": "ok", "tasks": ["one"]}}}
    monkeypatch.setattr(tools.Module, "available", lambda self: False)
    row = next(r for r in coverage.coverage_rows(None, state) if r["id"] == "nuclei")
    assert row["installed"] and row["status"] == "successful / no findings"
    state["execution_plan"]["nuclei"]["tasks"].append("unfinished")
    row = next(r for r in coverage.coverage_rows(None, state) if r["id"] == "nuclei")
    assert row["status"] == "partial"


def test_configuration_rejects_invalid_scope_and_concurrency():
    from pentest.config import parse_targets
    valid, invalid = parse_targets("999.999.999.1-2\n192.0.2.0/33\n192.0.2.10")
    assert valid == ["192.0.2.10"] and len(invalid) == 2
    cfg = ScanConfig.from_form({"targets": "192.0.2.10\nbad host",
                               "customer_name": "test", "authorized": "on",
                               "max_concurrency": "999"})
    errors = cfg.validate()
    assert any("Invalid targets" in e for e in errors)
    assert any("concurrency" in e for e in errors)


def test_disabled_adaptive_tool_does_not_run(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(engine, "_ctx", lambda *a, **k: pytest.fail("must not schedule"))
    cfg = ScanConfig.defaults()
    cfg.modules["wpscan"]["enabled"] = False
    engine._adaptive_trigger(cfg, str(tmp_path), {}, None)


def test_equivalent_host_commands_are_not_scheduled_twice(tmp_path):
    from pentest.parsers.nmap import Inventory, Service
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    for mid in cfg.modules:
        cfg.modules[mid]["enabled"] = mid == "smb_enum"
    inventory = Inventory([Service("host", 139), Service("host", 445)])
    tasks = engine._plan_tasks(cfg, str(tmp_path), inventory)
    assert len(tasks) == 1


def test_demo_and_partial_report_share_collection(tmp_path):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.demo = True
    ws, state = engine.run_sync(cfg)
    assert state["status"] == "done"
    assert state["findings_summary"]["total"] > 0
    final = open(os.path.join(ws, "report.html")).read()
    assert "data:image/" in final and "Duration:" in final
    assert "Coverage:</strong> complete" in final
    assert engine.generate_partial_report(state["id"]) == "report_partial.html"
    partial = open(os.path.join(ws, "report_partial.html")).read()
    assert "PARTIAL REPORT" in partial
    assert "Software with known exploits" in partial


def test_render_failure_keeps_previous_report(tmp_path, monkeypatch):
    from pentest import report
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.demo = True
    ws, state = engine.run_sync(cfg)
    before = open(os.path.join(ws, "report.html")).read()
    replace = report.os.replace

    def fail_report(source, dest):
        if str(dest).endswith("report.html"):
            raise OSError("cannot publish report")
        return replace(source, dest)

    monkeypatch.setattr(report.os, "replace", fail_report)
    with pytest.raises(OSError, match="cannot publish"):
        engine._render_report(cfg, ws, state)
    assert open(os.path.join(ws, "report.html")).read() == before
    assert not any(p.startswith(".report-") for p in os.listdir(ws))


def test_imported_xml_survives_missing_original_on_resume(tmp_path):
    source = tmp_path / "source.xml"
    source.write_text("<nmaprun/>")
    store = Store(str(tmp_path))
    engine = ScanEngine(store)
    sid, ws = make_scan(store)
    cfg = ScanConfig.defaults()
    cfg.nmap_xml = str(source)
    state = store.load_state(ws)
    engine._seed_nmap_xml(cfg, ws, state)
    source.unlink()
    ScanEngine(store)._seed_nmap_xml(cfg, ws, state, resume=True)
    assert state["modules"]["nmap_import"]["runs"][-1]["status"] == "skipped"


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


def test_web_templates_and_conflicts(web, monkeypatch):
    app, client = web
    assert client.get("/scan/new").status_code == 200
    sid, ws = make_scan(app.store, status="running")
    assert client.get("/").status_code == 200
    assert client.get(f"/scan/{sid}").status_code == 200
    assert client.post(f"/scan/{sid}/delete").status_code == 409
    assert client.post(f"/scan/{sid}/resume").status_code == 409
    assert client.post(f"/scan/{sid}/cancel").status_code == 302
    assert client.get(f"/api/scans/{sid}").json["status"] == "cancelling"


def test_web_legacy_confirmation(web, monkeypatch):
    app, client = web
    sid, ws = make_scan(app.store)
    state = app.store.load_state(ws)
    state.pop("schema_version")
    app.store.save_state(ws, state)
    monkeypatch.setattr(app.engine, "_ensure_worker", lambda: None)
    assert client.post(f"/scan/{sid}/resume").status_code == 409
    assert client.post(f"/scan/{sid}/resume",
                       data={"confirm_unverified": "on"}).status_code == 302


def test_discovery_content_invalidates_service_checkpoint(tmp_path):
    inventory = tmp_path / "nmap"
    inventory.mkdir()
    xml = inventory / "tcp.xml"
    xml.write_text("<nmaprun/>")
    spec = build_commands("sslscan", {}, Ctx(ws=str(tmp_path), host="host", port="443"))[0]
    assert str(xml) in spec.inputs
    before = checkpoints.fingerprint(spec, str(tmp_path))
    xml.write_text("<nmaprun><host/></nmaprun>")
    assert checkpoints.fingerprint(spec, str(tmp_path)) != before


def test_nse_refreshes_dependencies_before_resume_check(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    refreshed = []
    monkeypatch.setattr(engine, "_write_open_hosts", lambda ws: refreshed.append(True))

    def done(*args):
        assert refreshed
        return False

    monkeypatch.setattr(engine, "_discovery_done", done)
    handle = engine._start_vuln_async(cfg, str(tmp_path), {"modules": {}}, True)
    engine._finish_vuln(handle, str(tmp_path), {"modules": {}})


def test_smtp_outputs_keep_real_port(tmp_path):
    from pentest.parsers import generic
    folder = tmp_path / "smtp"
    folder.mkdir()
    (folder / "mail_587_swaks.txt").write_text("220 mail ready\n")
    (folder / "mail_2525.txt").write_text("250 user exists\n")
    findings = generic.smtp(str(tmp_path))
    assert {f.primary_asset() for f in findings} == {"mail:587", "mail:2525"}


def test_queued_cancellation_never_executes_and_releases_deletion(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    start_worker = engine._ensure_worker
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    seen = []
    monkeypatch.setattr(engine, "_execute", lambda ws: seen.append(ws))
    sid, ws = engine.submit(ScanConfig.defaults())
    assert engine.cancel(sid)
    start_worker()
    engine._queue.join()
    assert not seen
    assert engine.store.delete_scan(sid)
    engine.shutdown()


def test_cli_interrupt_is_cancelled_and_handler_restored(tmp_path, monkeypatch):
    import signal
    previous = signal.getsignal(signal.SIGINT)
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(engine, "_run_real",
                        lambda *args: signal.raise_signal(signal.SIGINT))
    ws, state = engine.run_sync(ScanConfig.defaults())
    assert state["status"] == "cancelled"
    assert signal.getsignal(signal.SIGINT) == previous


def test_report_failure_is_persisted_not_done(tmp_path, monkeypatch):
    from pentest import report
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.demo = True
    monkeypatch.setattr(report, "generate",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError("report failure")))
    ws, state = engine.run_sync(cfg)
    assert state["status"] == "error"
    assert state["coverage_status"] == "incomplete"
    assert "report failure" in state["diagnostics"]


def test_resumed_task_success_supersedes_old_failure(tmp_path):
    engine = ScanEngine(Store(str(tmp_path)))
    state = {"modules": {}}
    engine._record(str(tmp_path), state, "nuclei", [
        {"task_id": "same", "status": "error", "error": "old failure"}])
    engine._record(str(tmp_path), state, "nuclei", [
        {"task_id": "same", "status": "skipped", "reused_attempt": "verified"}])
    assert state["modules"]["nuclei"]["status"] == "ok"
    assert engine._tool_issues(state) == []
    assert len(state["modules"]["nuclei"]["runs"]) == 2
