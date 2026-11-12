"""Repository-wide opt-in verification options, collection gates, and evidence."""

from pathlib import Path
import time

import pytest

from pentest.verification import Evidence, validate_lab


def pytest_addoption(parser):
    group = parser.getgroup("recon verification")
    group.addoption("--run-browser", action="store_true", help="Run scanner-free Chromium integration tests.")
    group.addoption("--run-kali", action="store_true", help="Run approved, isolated Linux compatibility checks.")
    group.addoption("--lab-config", help="Operator-approved isolated lab JSON (no target addresses).")
    group.addoption("--verification-artifacts", help="Parent directory for unique evidence runs.")


def pytest_configure(config):
    config.addinivalue_line("markers", "browser: opt-in real-browser tests with scanner execution blocked")
    config.addinivalue_line("markers", "kali: opt-in real-tool tests against owned loopback fixture services")
    if config.getoption("--run-kali") and config.getoption("--run-browser"):
        raise pytest.UsageError("Run browser and Kali verification separately.")
    if config.getoption("--run-kali"):
        try:
            config.recon_lab = validate_lab(config.getoption("--lab-config"))
        except (OSError, ValueError) as exc:
            raise pytest.UsageError(str(exc)) from exc
    if config.getoption("--verification-artifacts") and not (
            config.getoption("--run-browser") or config.getoption("--run-kali")):
        config.recon_evidence = Evidence(
            config.getoption("--verification-artifacts"), "default",
            Path(__file__).resolve().parent)


def pytest_ignore_collect(collection_path, config):
    name = Path(collection_path).name
    if name == "verification-artifacts":
        return True
    if name == "browser" and not config.getoption("--run-browser"):
        return True
    if name == "compat" and not config.getoption("--run-kali"):
        return True
    return None


def pytest_collection_modifyitems(config, items):
    for item in items:
        for marker, option in (("browser", "--run-browser"), ("kali", "--run-kali")):
            if marker in item.keywords and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"Requires explicit {option}."))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    setattr(item, "rep_" + call.when, outcome.get_result())


def pytest_sessionfinish(session, exitstatus):
    evidence = getattr(session.config, "recon_evidence", None)
    if evidence is not None:
        from pentest.verification import source_identity
        current = source_identity(Path(__file__).resolve().parent)
        unchanged = bool(current["source_fingerprint"]) and current == evidence.data["source"]
        if not unchanged:
            session.exitstatus = 1
            exitstatus = 1
        if evidence.data["suite"] == "kali":
            selected = session.config.recon_lab["tools"]
            if any(evidence.data["tools"][mid]["status"] != "validated-for-selected-checks"
                   for mid in selected):
                session.exitstatus = 1
                exitstatus = 1
        evidence.data.update(
            finished_at=time.time(), exit_status=int(exitstatus),
            collected=session.testscollected, failed=session.testsfailed,
            source_unchanged=unchanged)
        evidence.record("pytest session", "passed" if exitstatus == 0 else "failed",
                        collected=session.testscollected, failed=session.testsfailed)


@pytest.fixture(scope="session")
def verification_evidence(request):
    root = Path(__file__).resolve().parent
    suite = "kali" if request.config.getoption("--run-kali") else "browser"
    directory = request.config.getoption("--verification-artifacts") or root / "verification-artifacts"
    evidence = Evidence(directory, suite, root, getattr(request.config, "recon_lab", None))
    request.config.recon_evidence = evidence
    yield evidence
    evidence.data["finished_at"] = time.time()
    evidence.save()
    print(f"\nVerification evidence: {evidence.directory}")
