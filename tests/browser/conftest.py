"""Real-browser fixtures: isolated localhost server, never installed scanners."""

import importlib.metadata
import importlib.util
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit
import uuid

import pytest
from werkzeug.serving import make_server

from pentest import runner
from pentest.commands import CommandSpec


@pytest.fixture
def expect():
    from playwright.sync_api import expect as assertion
    return assertion


@pytest.fixture(scope="session")
def chromium(verification_evidence):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.fail("Install requirements-browser.txt and Playwright Chromium before --run-browser.")
    with sync_playwright() as driver:
        try:
            browser = driver.chromium.launch()
        except Exception as exc:
            verification_evidence.record("chromium launch", "blocked", error=str(exc))
            pytest.fail("Chromium unavailable; run .venv/bin/python -m playwright install chromium.")
        verification_evidence.data["browser"] = {
            "engine": "chromium", "version": browser.version,
            "playwright": importlib.metadata.version("playwright"),
        }
        verification_evidence.save()
        yield browser
        browser.close()


@pytest.fixture
def web_app(isolated_scans, tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    results = tmp_path / "browser-results"
    monkeypatch.setenv("RECON_RESULTS_DIR", str(results))
    monkeypatch.delenv("RECON_AUTH", raising=False)
    monkeypatch.delenv("RECON_SECRET", raising=False)
    name = "recon_browser_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, root / "app.py")
    app = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, app)
    spec.loader.exec_module(app)
    assert app.store.base_dir == str(results)
    app.app.config["TESTING"] = True
    finish = tmp_path / "release-controlled-tool"
    fixture = Path(__file__).with_name("controlled_tool.py")
    real_run = runner.run_spec
    calls = []

    def guarded_run(command, *args, **kwargs):
        if command.argv[:3] != [sys.executable, "-u", str(fixture)]:
            raise AssertionError("Installed scanner execution is forbidden in browser verification.")
        calls.append(command.label)
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(runner, "run_spec", guarded_run)

    def controlled(cfg, ws, state, resume=False):
        app.engine._populate_demo(ws, state)
        cfg.demo = True
        state["demo"] = True
        state["phase"] = "phase2"
        state["verification_fixture"] = True
        state["progress"] = {"total": 1, "completed": 0}
        state["execution_plan"]["nuclei"].update(enabled=True, status="pending")
        app.engine._save(ws, state)
        command = CommandSpec("nuclei-fixture",
            [sys.executable, "-u", str(fixture), str(finish)],
            stdout_to=str(Path(ws) / "nuclei.jsonl"))
        result = runner.run_spec(command, ws, on_output=app.engine._on_output, resume=resume)
        app.engine._record(ws, state, "nuclei", [result])
        state["progress"]["completed"] = 1
        state["execution_plan"]["sslscan"].update(enabled=True, status="pending")
        app.engine._record(ws, state, "sslscan", [{
            "label": "fixture-gap", "status": "error",
            "error": "<script>window.__fixtureXSS=true</script> controlled coverage gap",
            "duration": 0}])
        app.engine._save(ws, state)

    monkeypatch.setattr(app.engine, "_run_real", controlled)
    server = make_server("127.0.0.1", 0, app.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixture_app = SimpleNamespace(
        app=app, origin=f"http://127.0.0.1:{server.server_port}", results=results,
        complete=lambda: finish.touch(), calls=calls, start_worker=app.engine._ensure_worker)
    yield fixture_app
    finish.touch()
    app.engine.shutdown()
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not app.engine._worker or not app.engine._worker.is_alive()
    assert all(label == "nuclei-fixture" for label in calls)


@pytest.fixture
def browser_page(request, chromium, web_app, verification_evidence):
    directory = verification_evidence.directory / request.node.name
    directory.mkdir(parents=True, exist_ok=True)
    context = chromium.new_context(
        base_url=web_app.origin, viewport={"width": 1280, "height": 900},
        accept_downloads=True)
    blocked = []
    errors = []
    def route(request):
        parsed = urlsplit(request.request.url)
        if (request.request.url.startswith(web_app.origin + "/")
                or parsed.scheme in ("file", "data", "about")):
            request.continue_()
        else:
            blocked.append(request.request.url)
            request.abort()
    context.route("**/*", route)
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("dialog", lambda dialog: dialog.accept())
    yield page
    failed = bool(getattr(request.node, "rep_call", None) and request.node.rep_call.failed) or bool(errors)
    try:
        if failed:
            page.screenshot(path=str(directory / "failure.png"), full_page=True)
            context.tracing.stop(path=str(directory / "trace.zip"))
        else:
            context.tracing.stop()
        verification_evidence.record(request.node.name, "failed" if failed else "passed",
                                     page_errors=errors, blocked_requests=blocked,
                                     artifacts=str(directory))
    finally:
        context.close()
    assert not errors, errors
