"""P1 worker liveness, bounded termination, and evidence-isolation regressions."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import sys
import threading
import time

import pytest

from pentest import runner
from pentest.commands import CommandSpec
from pentest.config import ScanConfig
from pentest.engine import ScanEngine
from pentest.execution import ExecutionContext
from pentest.lifecycle import LifecycleConflict
from pentest.store import Store


def test_cancel_during_preparation_never_launches(tmp_path, monkeypatch):
    context = ExecutionContext()
    stage = runner._stage

    def cancel_after_stage(*args):
        staged = stage(*args)
        context.cancel.set()
        return staged

    monkeypatch.setattr(runner, "_stage", cancel_after_stage)
    monkeypatch.setattr(runner.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("cancelled task launched"))
    result = runner.run_spec(CommandSpec("late-cancel", ["printf", "never"]),
                             str(tmp_path), on_output=context)
    assert result["status"] == "cancelled"
    assert Path(result["log"]).exists()


def fixture_child(tmp_path, detached=False):
    pid = tmp_path / "fixture-child.pid"
    heartbeat = tmp_path / "heartbeat"
    child = (
        "import os,signal,time,pathlib; "
        "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
        f"pathlib.Path({str(pid)!r}).write_text(str(os.getpid())); "
        f"p=pathlib.Path({str(heartbeat)!r}); "
        "\nfor i in range(1000):\n p.write_text(str(i)); time.sleep(.02)\n")
    parent = (
        "import subprocess,sys,time,pathlib; "
        f"subprocess.Popen([sys.executable,'-c',{child!r}], "
        + ("start_new_session=True" if detached else
           "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL")
        + "); "
        f"p=pathlib.Path({str(pid)!r}); "
        "\nwhile not p.exists(): time.sleep(.01)\n"
        "print('fixture-ready',flush=True); time.sleep(20)")
    return CommandSpec("tree", [sys.executable, "-u", "-c", parent]), pid, heartbeat


def cleanup_fixture(pid):
    """Only terminate the child PID created and recorded by this test fixture."""
    if pid.exists():
        try:
            os.kill(int(pid.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_term_exited_parent_does_not_leave_term_ignoring_child(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_KILL_GRACE", .15)
    spec, pid, heartbeat = fixture_child(tmp_path)
    context = ExecutionContext()
    context.on_output = lambda label, text: (
        context.cancel.set() if "fixture-ready" in text and not text.startswith("$ ") else None)
    try:
        result = runner.run_spec(spec, str(tmp_path), on_output=context)
        assert result["status"] == "cancelled"
        before = heartbeat.read_text()
        time.sleep(.1)
        assert heartbeat.read_text() == before
        assert result["duration"] < 3
    finally:
        cleanup_fixture(pid)


def test_escaped_pipe_holder_cannot_hang_output_drain(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_KILL_GRACE", .15)
    monkeypatch.setattr(runner, "_DRAIN_GRACE", .15)
    spec, pid, heartbeat = fixture_child(tmp_path, detached=True)
    context = ExecutionContext()
    context.on_output = lambda label, text: (
        context.cancel.set() if "fixture-ready" in text and not text.startswith("$ ") else None)
    try:
        result = runner.run_spec(spec, str(tmp_path), on_output=context)
        assert result["status"] == "cancelled"
        assert result["duration"] < 3
        assert any("drain deadline" in w for w in result["output_warnings"])
    finally:
        cleanup_fixture(pid)


def test_utf8_split_across_chunks_remains_intact(tmp_path):
    seen = []
    spec = CommandSpec("unicode", [sys.executable, "-c",
        "import os,time; os.write(1,b'\\xe2'); time.sleep(.1); os.write(1,b'\\x82\\xac\\n')"],
        stdout_to=str(tmp_path / "unicode.txt"))
    result = runner.run_spec(spec, str(tmp_path),
                             on_output=lambda label, text: seen.append(text))
    assert result["status"] == "ok"
    assert (tmp_path / "unicode.txt").read_text() == "€\n"
    assert "€\n" in "".join(seen)
    assert "�" not in Path(result["log"]).read_text()


@pytest.mark.parametrize("spec", [
    CommandSpec("empty", []), CommandSpec("missing", ["recon-test-missing-binary"])])
def test_nonexecuted_attempts_still_have_evidence_logs(tmp_path, spec):
    result = runner.run_spec(spec, str(tmp_path))
    log = Path(result["log"]).read_text()
    assert result["status"] in log and result["error"] in log


def test_same_label_concurrent_logs_never_overlap(tmp_path):
    specs = [CommandSpec("shared-label", ["printf", marker])
             for marker in ("FIRST-ONLY", "SECOND-ONLY")]
    with ThreadPoolExecutor(2) as pool:
        first, second = list(pool.map(lambda s: runner.run_spec(s, str(tmp_path)), specs))
    assert first["log"] != second["log"]
    assert "FIRST-ONLY" in Path(first["log"]).read_text()
    assert "SECOND-ONLY" not in Path(first["log"]).read_text()
    assert "SECOND-ONLY" in Path(second["log"]).read_text()
    assert "FIRST-ONLY" not in Path(second["log"]).read_text()


def test_worker_recovers_corrupt_state_and_continues(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    start = engine._ensure_worker
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    bad_id, bad_ws = engine.submit(ScanConfig.defaults())
    good_id, good_ws = engine.submit(ScanConfig.defaults())
    Path(bad_ws, "state.json").write_text("{broken")
    continued = threading.Event()
    monkeypatch.setattr(engine, "_execute", lambda ws: continued.set())
    try:
        start()
        assert continued.wait(3)
        engine._queue.join()
        state = engine.store.load_state(bad_ws)
        assert state["status"] == "error"
        assert list(Path(bad_ws).glob("state.json.corrupt-*"))
        assert engine._worker.is_alive()
    finally:
        engine.shutdown()


def test_failed_error_persistence_cannot_kill_worker(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    start = engine._ensure_worker
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    bad_id, bad_ws = engine.submit(ScanConfig.defaults())
    engine.submit(ScanConfig.defaults())
    continued = threading.Event()

    def execute(ws):
        if ws == bad_ws:
            raise RuntimeError("task failed")
        continued.set()

    monkeypatch.setattr(engine, "_execute", execute)
    monkeypatch.setattr(engine, "_fail",
                        lambda *a: (_ for _ in ()).throw(OSError("store unavailable")))
    try:
        start()
        assert continued.wait(3)
        engine._queue.join()
        assert engine.worker_errors[-1]["scan_id"] == bad_id
        assert engine._worker.is_alive()
    finally:
        engine.shutdown()


def test_shutdown_does_not_cancel_another_engine(tmp_path, monkeypatch):
    first = ScanEngine(Store(str(tmp_path)))
    second = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(first, "_ensure_worker", lambda: None)
    monkeypatch.setattr(second, "_ensure_worker", lambda: None)
    first_id, _ = first.submit(ScanConfig.defaults())
    second_id, _ = second.submit(ScanConfig.defaults())
    first.shutdown()
    assert first._is_cancelled(first_id)
    assert not second._is_cancelled(second_id)
    second.shutdown()


def test_console_initialization_failure_restores_context(tmp_path, monkeypatch):
    from pentest import engine as module
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(module, "_ConsoleWriter",
                        lambda *a: (_ for _ in ()).throw(OSError("console unavailable")))
    ws, state = engine.run_sync(ScanConfig.defaults())
    assert state["status"] == "error"
    assert not engine.lifecycle.owned
    assert engine._on_log is None
    assert engine._on_output.on_output is None


def test_shutdown_is_idempotent_and_rejects_new_sync_work(tmp_path):
    engine = ScanEngine(Store(str(tmp_path)))
    engine.shutdown()
    engine.shutdown()
    with pytest.raises(LifecycleConflict):
        engine.run_sync(ScanConfig.defaults())
    assert not list(tmp_path.glob("results_*"))


def test_oversized_json_is_retained_but_not_checkpointed(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_MAX_JSON_BYTES", 32)
    spec = CommandSpec("large-json", [sys.executable, "-c", "print('[1,'+'0,'*100+'2]')"],
                       stdout_to=str(tmp_path / "large.json"))
    result = runner.run_spec(spec, str(tmp_path))
    assert result["status"] == "partial"
    assert (tmp_path / "large.json").stat().st_size > 32
    assert any("bounded validation" in w for w in result["output_warnings"])
    assert not runner._resume_satisfied(spec, str(tmp_path))


def test_oversized_jsonl_record_is_not_loaded(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_MAX_JSONL_RECORD", 32)
    path = tmp_path / "large.jsonl"
    path.write_text('{"value":"' + "x" * 1000 + '"}\n')
    assert "bounded validation" in runner._check_jsonl(str(path))


def test_xml_validation_uses_streaming_parser(tmp_path, monkeypatch):
    path = tmp_path / "inventory.xml"
    path.write_text("<nmaprun>" + "<host/>" * 2000 + "</nmaprun>")
    monkeypatch.setattr(runner.ET, "parse",
                        lambda *a: pytest.fail("full XML tree must not be loaded"))
    assert runner._check_xml(str(path)) == ""
    path.write_text("<nmaprun><host>")
    assert "malformed XML" in runner._check_xml(str(path))


def test_failed_discovery_future_keeps_sibling_result(tmp_path, monkeypatch):
    from pentest import engine as module
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    for mid in cfg.modules:
        cfg.modules[mid]["enabled"] = mid in ("nmap_tcp", "nmap_udp")

    def discovery(specs, *args, **kwargs):
        mid = specs[0].label
        if mid == "nmap_tcp":
            raise OSError("tcp artifact failure")
        return [{"label": mid, "status": "ok", "duration": 0}]

    monkeypatch.setattr(module, "run_specs", discovery)
    ws, state = engine.run_sync(cfg)
    assert state["status"] == "done"
    assert state["modules"]["nmap_tcp"]["runs"][0]["status"] == "error"
    assert state["modules"]["nmap_udp"]["runs"][0]["status"] == "ok"
    assert state["coverage_status"] == "incomplete"


def test_screenshot_parser_failure_does_not_sink_report(tmp_path, monkeypatch):
    from pentest import engine as module
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.demo = True
    monkeypatch.setattr(module.gowitness, "parse",
                        lambda *a: (_ for _ in ()).throw(ValueError("bad screenshot")))
    ws, state = engine.run_sync(cfg)
    assert state["status"] == "done" and state["findings_summary"]["total"] > 0
    assert state["coverage_status"] == "incomplete"
    assert "bad screenshot" in Path(ws, "report.html").read_text()


def test_version_enumeration_failure_does_not_sink_report(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    monkeypatch.setattr(engine, "_run_real",
                        lambda cfg, ws, state, resume: engine._populate_demo(ws, state))
    monkeypatch.setattr(engine, "_searchsploit_versions",
                        lambda *a: (_ for _ in ()).throw(ValueError("bad version parser")))
    ws, state = engine.run_sync(cfg)
    assert state["status"] == "done" and state["findings_summary"]["total"] > 0
    assert state["coverage_status"] == "incomplete"
    assert "bad version parser" in Path(ws, "report.html").read_text()


def test_one_attempt_persistence_failure_preserves_sibling_results(tmp_path, monkeypatch):
    def execute(spec, *args, **kwargs):
        if spec.label == "bad":
            raise OSError("attempt record unavailable")
        return {"label": spec.label, "status": "ok"}

    monkeypatch.setattr(runner, "run_spec", execute)
    results = runner.run_specs([
        CommandSpec("before", ["printf", "before"]),
        CommandSpec("bad", ["printf", "bad"]),
        CommandSpec("after", ["printf", "after"])], str(tmp_path))
    assert [r["status"] for r in results] == ["ok", "error", "ok"]
    assert "attempt record unavailable" in results[1]["error"]


def test_shutdown_with_corrupt_queued_state_still_signals_cancellation(tmp_path, monkeypatch):
    engine = ScanEngine(Store(str(tmp_path)))
    monkeypatch.setattr(engine, "_ensure_worker", lambda: None)
    sid, ws = engine.submit(ScanConfig.defaults())
    Path(ws, "state.json").write_text("{invalid")
    engine.shutdown()
    assert engine._is_cancelled(sid)
    assert engine.worker_errors[-1]["scan_id"] == sid
