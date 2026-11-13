"""Live activity markers expose executing tasks and orphaned attempts."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import time

from pentest import activity, runner
from pentest.checkpoints import atomic_json
from pentest.commands import CommandSpec
from pentest.execution import ExecutionContext


def marker(ws, attempt, **fields):
    path = Path(ws, "active", attempt + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(str(path), {"task_id": "tid", "attempt_id": attempt,
                            "label": "probe", "command": "printf hi",
                            "started_at": time.time() - 45, **fields})
    return path


def test_no_tasks_without_active_directory(tmp_path):
    assert activity.active_tasks(str(tmp_path)) == []


def test_output_age_drives_state_and_dead_pid_is_orphaned(tmp_path):
    attempt = Path(tmp_path, "attempts", "tid", "a1")
    attempt.mkdir(parents=True)
    output = attempt / "stdout.log"
    output.write_text("x")
    now = time.time()

    def state_at(age):
        os.utime(output, (now - age, now - age))
        return activity.active_tasks(str(tmp_path))

    # The task started 300s ago; output ages below are all realistic.
    marker(tmp_path, "a1", pid=os.getpid(), log=str(output),
           started_at=now - 300)
    streaming = state_at(5)[0]
    assert streaming["state"] == "streaming"
    assert streaming["process_alive"] is True
    assert streaming["output_bytes"] == 1
    assert streaming["elapsed_seconds"] >= 299
    assert state_at(60)[0]["state"] == "quiet"
    assert state_at(200)[0]["state"] == "silent"

    marker(tmp_path, "a2", pid=999999999)
    orphan = next(t for t in activity.active_tasks(str(tmp_path))
                  if t["attempt_id"] == "a2")
    assert orphan["state"] == "orphaned" and orphan["process_alive"] is False


def test_runner_writes_live_marker_and_removes_it_on_completion(tmp_path):
    ws = str(tmp_path)
    spec = CommandSpec("slow-echo", ["sh", "-c", "echo hi; sleep 1.2"])
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(runner.run_spec, spec, ws, timeout=10)
        deadline = time.monotonic() + 5
        live = []
        while time.monotonic() < deadline:
            live = activity.active_tasks(ws)
            if live:
                break
            time.sleep(0.05)
        assert live, "no live marker appeared while the subprocess ran"
        assert live[0]["pid"] > 0 and live[0]["process_alive"] is True
        assert live[0]["state"] in ("streaming", "quiet")
        result = future.result(timeout=10)
    assert result["status"] == "ok" and result["pid"] == live[0]["pid"]
    assert activity.active_tasks(ws) == []


def test_marker_removed_after_timeout_and_cancellation(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_KILL_GRACE", 0.2)
    ws = str(tmp_path / "timeout")
    result = runner.run_spec(CommandSpec("t", ["sh", "-c", "sleep 5"]),
                             ws, timeout=0.4)
    assert result["status"] == "timeout"
    assert activity.active_tasks(ws) == []

    ws = str(tmp_path / "cancelled")
    context = ExecutionContext()
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(runner.run_spec,
                             CommandSpec("c", ["sh", "-c", "sleep 5"]),
                             ws, 30, context)
        context.cancel.set()
        result = future.result(timeout=10)
    assert result["status"] == "cancelled"
    assert activity.active_tasks(ws) == []
