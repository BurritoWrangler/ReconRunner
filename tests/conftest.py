"""Default tests never launch installed scanners or touch existing results."""

import pytest

from pentest import engine, store


@pytest.fixture(autouse=True)
def isolated_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "BASE_DIR", str(tmp_path))
    monkeypatch.setenv("RECON_RESULTS_DIR", str(tmp_path))
    monkeypatch.delenv("RECON_NOTIFY_WEBHOOK", raising=False)
    monkeypatch.delenv("RECON_NOTIFY_DESKTOP", raising=False)

    def no_scanners(specs, ws, timeout=None, on_output=None, resume=False):
        return [{"label": s.label, "command": s.display(), "status": "missing",
                 "error": "scanner execution disabled by test fixture",
                 "duration": 0, "log": ""} for s in specs]

    monkeypatch.setattr(engine, "run_specs", no_scanners)
    monkeypatch.setattr(engine.ScanEngine, "_notify", lambda self, state: None)
