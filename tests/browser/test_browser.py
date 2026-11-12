"""Browser checks use only the isolated Flask server and controlled fixtures."""

import time

import pytest

from pentest.config import ScanConfig
from pentest.store import new_scan_id

pytestmark = pytest.mark.browser


def start_controlled(page, app, expect, theme="dark"):
    page.goto(app.origin + "/scan/new")
    page.locator('[name="scan_name"]').fill("browser-controlled")
    page.locator('[name="customer_name"]').fill("browser-fixture")
    page.locator('[name="targets"]').fill("127.0.0.1")
    page.locator('[name="report_theme"]').select_option(theme)
    page.locator('[name="authorized"]').check()
    page.get_by_role("button", name="Start scan", exact=True).click()
    expect(page.locator("#st-status")).to_have_text("running")
    expect(page.locator("#st-console")).to_contain_text("owned-browser-fixture")
    return page.url.rsplit("/", 1)[-1]


def seed_status(app, status, error=""):
    cfg = ScanConfig.defaults()
    cfg.demo = True
    cfg.targets = ["127.0.0.1"]
    sid = new_scan_id()
    store = app.app.store
    ws = store.create_workspace(cfg, sid)
    state = store.initial_state(cfg, sid, ws)
    state.update(status=status, phase="phase2", error=error, started_at=time.time())
    if status != "running":
        state["ended_at"] = time.time()
    store.save_state(ws, state)
    return sid, ws


def wait_requests(page, pending, count):
    deadline = time.monotonic() + 5
    while len(pending) < count and time.monotonic() < deadline:
        page.wait_for_timeout(20)
    assert len(pending) >= count


def test_invalid_upload_and_preview_controls(browser_page, web_app, expect):
    page = browser_page
    page.goto(web_app.origin + "/scan/new")
    page.locator('[name="customer_name"]').fill("browser-fixture")
    page.locator('[name="authorized"]').check()
    page.locator('[name="hostfile"]').set_input_files({
        "name": "bad-scope.txt", "mimeType": "text/plain",
        "buffer": b"https://outside.invalid/path\n999.999.999.1-2\n"})
    page.get_by_role("button", name="Start scan", exact=True).click()
    expect(page.locator(".flash-error").filter(has_text="Invalid targets")).to_be_visible()
    assert not web_app.app.store.list_scans()
    page.locator('[name="run_as_root"]').uncheck()
    page.locator('[name="rate_limit"]').fill("23")
    page.locator('[name="rate_limit"]').press("Tab")
    expect(page.locator("#preview-nmap_tcp")).to_contain_text("-sT")
    expect(page.locator("#preview-httpx")).to_contain_text("-rate-limit 23")
    automatic = page.locator('[name="mod__wpscan__automatic"]')
    enabled = page.locator('[name="mod__wpscan__enabled"]')
    automatic.check()
    expect(enabled).not_to_be_checked()
    expect(page.locator("#preview-wpscan")).to_contain_text("Automatic")
    enabled.check()
    expect(automatic).not_to_be_checked()
    assert not web_app.calls


def test_newest_preview_wins_in_real_browser(browser_page, web_app, expect):
    page = browser_page
    page.goto(web_app.origin + "/scan/new")
    pending = []
    def preview(route):
        body = route.request.post_data_json
        if body["module"] == "httpx":
            pending.append(route)
        else:
            route.continue_()
    page.route("**/api/command-preview", preview)
    threads = page.locator('[name="mod__httpx__threads"]')
    threads.fill("11")
    wait_requests(page, pending, 1)
    threads.fill("12")
    wait_requests(page, pending, 2)
    pending[1].fulfill(json={"lines": ["NEW effective command"]})
    expect(page.locator("#preview-httpx")).to_have_text("NEW effective command")
    pending[0].fulfill(json={"lines": ["OLD stale command"]})
    page.wait_for_timeout(100)
    expect(page.locator("#preview-httpx")).to_have_text("NEW effective command")


def test_cancel_resume_and_incomplete_coverage(browser_page, web_app, expect):
    page = browser_page
    sid = start_controlled(page, web_app, expect)
    page.locator("#cancel-action button").click()
    expect(page.locator("#st-status")).to_have_text("cancelling")
    expect(page.locator("#st-status")).to_have_text("cancelled")
    expect(page.locator("#resume-action")).to_be_visible()
    expect(page.locator("#report-link")).to_be_hidden()
    page.locator("#resume-action button").click()
    expect(page.locator("#st-status")).to_have_text("running")
    web_app.complete()
    expect(page.locator("#st-status")).to_have_text("done")
    expect(page.locator("#report-link")).to_be_visible()
    expect(page.locator("#st-coverage-warning")).to_be_visible()
    expect(page.locator("#st-coverage")).to_contain_text("incomplete")
    page.locator("#st-modules .mod-row[data-mid='sslscan']").click()
    expect(page.locator(".runs .err").filter(has_text="controlled coverage gap").first).to_be_visible()
    assert not page.evaluate("window.__fixtureXSS")
    _, state = web_app.app.store.find_scan(sid)
    assert state["verification_fixture"] is True
    assert len(web_app.calls) == 2
    assert any(run["status"] == "cancelled" for run in state["modules"]["nuclei"]["runs"])


def test_queued_cancel_waits_for_ownership_release(browser_page, web_app, expect, monkeypatch):
    page = browser_page
    monkeypatch.setattr(web_app.app.engine, "_ensure_worker", lambda: None)
    page.goto(web_app.origin + "/scan/new")
    page.locator('[name="customer_name"]').fill("queued-fixture")
    page.locator('[name="targets"]').fill("127.0.0.1")
    page.locator('[name="authorized"]').check()
    page.get_by_role("button", name="Start scan", exact=True).click()
    expect(page.locator("#st-status")).to_have_text("queued")
    page.locator("#cancel-action button").click()
    expect(page.locator("#st-status")).to_have_text("cancelled")
    expect(page.locator("#resume-action")).to_be_hidden()
    web_app.start_worker()
    expect(page.locator("#resume-action")).to_be_visible()
    assert not web_app.calls


def test_network_error_retries_without_erasing_scan_failure(browser_page, web_app, expect):
    page = browser_page
    sid, _ = seed_status(web_app, "running", "existing scan diagnostic")
    count = []
    def status(route):
        count.append(route)
        if len(count) == 1:
            route.fulfill(status=500, json={})
        else:
            route.continue_()
    page.route(f"**/api/scans/{sid}", status)
    page.clock.install()
    page.goto(web_app.origin + f"/scan/{sid}")
    expect(page.locator("#st-connection")).to_contain_text("500")
    expect(page.locator("#st-error")).to_have_text("existing scan diagnostic")
    expect(page.locator("#cancel-action button")).to_be_disabled()
    page.clock.fast_forward(5000)
    expect(page.locator("#st-connection")).to_be_hidden()
    expect(page.locator("#cancel-action button")).to_be_enabled()
    expect(page.locator("#st-error")).to_have_text("existing scan diagnostic")


def test_request_timeout_and_missing_scan_stop_behavior(browser_page, web_app, expect):
    page = browser_page
    sid, _ = seed_status(web_app, "running")
    pending = []
    def status(route):
        pending.append(route)
        if len(pending) > 1:
            route.fulfill(status=404, json={})
        # First request deliberately held until AbortController's watchdog fires.
    page.route(f"**/api/scans/{sid}", status)
    page.clock.install()
    page.goto(web_app.origin + f"/scan/{sid}")
    wait_requests(page, pending, 1)
    page.clock.fast_forward(10001)
    expect(page.locator("#st-connection")).to_contain_text("timed out")
    page.clock.fast_forward(5000)
    expect(page.locator("#st-connection")).to_contain_text("no longer exists")
    page.clock.fast_forward(30000)
    assert len(pending) == 2
    expect(page.locator("#cancel-action button")).to_be_disabled()


@pytest.mark.parametrize("status", ["error", "interrupted"])
def test_terminal_failures_hide_stale_reports(browser_page, web_app, expect, status):
    from pathlib import Path
    page = browser_page
    sid, ws = seed_status(web_app, status, "controlled terminal diagnostic")
    state = web_app.app.store.load_state(ws)
    state["report"] = "report.html"
    Path(ws, "report.html").write_text("<h1>STALE REPORT</h1>")
    web_app.app.store.save_state(ws, state)
    page.goto(web_app.origin + f"/scan/{sid}")
    expect(page.locator("#st-status")).to_have_text(status)
    expect(page.locator("#report-link")).to_be_hidden()
    expect(page.locator("#resume-action")).to_be_visible()
    expect(page.locator("#st-error")).to_have_text("controlled terminal diagnostic")
    result = page.request.get(web_app.origin + f"/scan/{sid}/report", max_redirects=0)
    assert result.status == 302


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_report_themes_download_and_standalone_render(
        browser_page, web_app, expect, verification_evidence, tmp_path, theme):
    page = browser_page
    if theme == "dark":
        page.goto(web_app.origin + "/")
        page.get_by_role("button", name="Run demo scan", exact=True).click()
        expect(page.locator("#st-status")).to_have_text("done")
    else:
        start_controlled(page, web_app, expect, theme="light")
        web_app.complete()
        expect(page.locator("#st-status")).to_have_text("done")
    status_url = page.url
    page.locator("#theme-toggle").click()
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    page.reload()
    expect(page.locator("html")).to_have_attribute("data-theme", "light")
    page.screenshot(path=str(verification_evidence.directory / f"status-{theme}.png"),
                    full_page=True, animations="disabled")
    page.screenshot(path=str(verification_evidence.directory / f"status-{theme}-viewport.png"),
                    animations="disabled")
    page.locator("#report-link").click()
    expect(page.get_by_role("heading", name="Prioritized findings")).to_be_visible()
    expected = "rgb(5, 8, 10)" if theme == "dark" else "rgb(244, 246, 248)"
    assert page.evaluate("getComputedStyle(document.body).backgroundColor") == expected
    page.screenshot(path=str(verification_evidence.directory / f"report-{theme}.png"),
                    full_page=True, animations="disabled")
    page.screenshot(path=str(verification_evidence.directory / f"report-{theme}-viewport.png"),
                    animations="disabled")
    verification_evidence.data.setdefault("screenshots", []).extend(
        [f"status-{theme}.png", f"status-{theme}-viewport.png",
         f"report-{theme}.png", f"report-{theme}-viewport.png"])
    verification_evidence.save()
    download_url = status_url + "/report/download"
    with page.expect_download() as event:
        page.evaluate("""url => {
          const a = document.createElement('a'); a.href = url;
          document.body.appendChild(a); a.click(); a.remove();
        }""", download_url)
    destination = tmp_path / f"report-{theme}.html"
    event.value.save_as(destination)
    html = destination.read_text()
    assert "data:image/" in html and "<style>" in html
    page.goto(destination.as_uri())
    expect(page.get_by_role("heading", name="Prioritized findings")).to_be_visible()
    assert page.locator(".shot img").count() > 0
    assert page.locator(".shot img").first.evaluate("img => img.complete && img.naturalWidth > 0")
    page.locator("details").filter(has=page.locator("summary", has_text="proof output")).first.locator("summary").click()
    expect(page.locator("details[open] pre").first).to_be_visible()
