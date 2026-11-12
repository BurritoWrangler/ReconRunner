"""Verification gates are tested without Playwright or installed scanners."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from pentest.config import ScanConfig
from pentest.store import Store, new_scan_id
from pentest.verification import Evidence, LAB_TOOLS, fixture_spec, validate_lab


def approved_lab():
    return {"schema_version": 1, "lab_id": "local-fixture-lab",
            "approved": True, "isolated": True, "egress_blocked": True,
            "target_mode": "owned-loopback-fixtures", "tools": ["nmap_tcp", "httpx"]}


def test_results_directory_override_and_explicit_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("RECON_RESULTS_DIR", str(tmp_path / "environment"))
    assert Store().base_dir == str(tmp_path / "environment")
    assert Store(str(tmp_path / "explicit")).base_dir == str(tmp_path / "explicit")


def test_results_directory_default_is_unchanged(tmp_path, monkeypatch):
    from pentest import store
    monkeypatch.delenv("RECON_RESULTS_DIR")
    monkeypatch.setattr(store, "BASE_DIR", str(tmp_path / "default"))
    assert Store().base_dir == str(tmp_path / "default")


def test_application_import_reconciles_only_override_directory(tmp_path):
    isolated = tmp_path / "isolated"
    outside = Store(str(tmp_path / "outside"))
    cfg = ScanConfig.defaults()
    sid = new_scan_id()
    ws = outside.create_workspace(cfg, sid)
    state = outside.initial_state(cfg, sid, ws)
    state["status"] = "running"
    outside.save_state(ws, state)
    before = Path(ws, "state.json").read_bytes()
    env = os.environ.copy()
    env["RECON_RESULTS_DIR"] = str(isolated)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run([sys.executable, "-c",
        "import app,os; assert app.store.base_dir == os.environ['RECON_RESULTS_DIR']; "
        "assert app.store.list_scans() == []"], env=env, capture_output=True,
        text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert Path(ws, "state.json").read_bytes() == before


@pytest.mark.parametrize("key,value", [
    ("approved", False), ("approved", "true"), ("isolated", False),
    ("egress_blocked", False), ("target_mode", "operator-targets"),
    ("tools", ["bruteforce"]), ("tools", ["nmap_udp"]),
    ("tools", ["subdomain"]), ("tools", []), ("schema_version", 2),
    ("lab_id", ""), ("targets", ["127.0.0.1"]), ("extra_args", "--anything"),
])
def test_lab_gate_rejects_unsafe_or_incomplete_configuration(tmp_path, key, value):
    lab = approved_lab()
    lab[key] = value
    path = tmp_path / "lab.json"
    path.write_text(json.dumps(lab))
    with pytest.raises(ValueError):
        validate_lab(path, system="linux")


def test_lab_gate_requires_linux_and_explicit_file(tmp_path):
    with pytest.raises(ValueError, match="lab-config"):
        validate_lab(None)
    path = tmp_path / "lab.json"
    path.write_text(json.dumps(approved_lab()))
    with pytest.raises(ValueError, match="Linux"):
        validate_lab(path, system="darwin")
    assert validate_lab(path, system="linux")["target_mode"] == "owned-loopback-fixtures"


def test_example_lab_is_deliberately_unapproved():
    path = Path(__file__).parent / "compat/example.lab.json"
    with pytest.raises(ValueError, match="approved"):
        validate_lab(path, system="linux")


def test_gate_failure_precedes_collection_and_tool_execution(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([
        sys.executable, "-m", "pytest", str(root / "tests"), "--run-kali",
        "-p", "no:cacheprovider", "--collect-only", "-q"],
        cwd=str(root), capture_output=True, text=True, timeout=15)
    assert result.returncode == 4
    assert "--lab-config" in result.stderr


def test_evidence_never_claims_unexecuted_tool_compatibility(tmp_path):
    root = Path(__file__).resolve().parents[1]
    evidence = Evidence(tmp_path, "browser", root)
    data = json.loads((evidence.directory / "manifest.json").read_text())
    assert data["source"]["base_commit"]
    assert data["source"]["source_fingerprint"]
    assert data["reliability_signoff"] is False
    assert set(LAB_TOOLS) <= set(data["tools"])
    assert all(tool["status"] == "unverified" for tool in data["tools"].values())


def test_connect_discovery_is_narrow_and_never_privileged(tmp_path):
    spec = fixture_spec("nmap_tcp", tmp_path, 45678)
    assert "-sT" in spec.argv and "-n" in spec.argv
    assert spec.argv[spec.argv.index("-p") + 1] == "45678"
    assert "-p-" not in spec.argv and "-sV" not in spec.argv and "--script" not in spec.argv
    assert spec.inputs == [str(tmp_path / "targets.txt")]


def test_http_probe_has_no_redirects_or_update_checks(tmp_path):
    spec = fixture_spec("httpx", tmp_path, 45678)
    assert "-follow-redirects" not in spec.argv
    assert "-disable-update-check" in spec.argv
    assert str(tmp_path / "web_urls.txt") in spec.argv


def test_nuclei_uses_only_owned_templates_without_callbacks(tmp_path):
    for variant, template in (("output", "owned-positive.yaml"), ("empty", "owned-negative.yaml")):
        spec = fixture_spec("nuclei", tmp_path, 45678, variant=variant)
        assert spec.argv[spec.argv.index("-t") + 1] == str(tmp_path / template)
        assert "-no-interactsh" in spec.argv and "-disable-update-check" in spec.argv
        assert "-update-templates" not in spec.argv and "-as" not in spec.argv


@pytest.mark.parametrize("mid", ["nmap_udp", "nmap_vuln", "bruteforce", "subdomain", "passive_urls"])
def test_no_nonfixture_module_can_be_selected(mid, tmp_path):
    with pytest.raises(ValueError):
        fixture_spec(mid, tmp_path, 45678)


@pytest.mark.parametrize("port", [0, -1, 65536, "45678", True])
def test_fixture_ports_are_not_operator_target_strings(tmp_path, port):
    with pytest.raises(ValueError):
        fixture_spec("httpx", tmp_path, port)


def test_optional_screenshot_command_reads_only_fixture_inventory(tmp_path):
    spec = fixture_spec("gowitness", tmp_path, 45678)
    assert spec.argv[spec.argv.index("-f") + 1] == str(tmp_path / "nmap/tcp.xml")
    assert spec.argv[spec.argv.index("--screenshot-path") + 1] == str(tmp_path / "screens")


def test_failed_compatibility_cannot_be_erased_by_later_success(tmp_path):
    evidence = Evidence(tmp_path, "kali", Path(__file__).resolve().parents[1])
    evidence.tool("httpx", "failed", reason="Observed incompatible output")
    evidence.tool("httpx", "validated-for-selected-checks", checks={"output": {"passed": True}})
    assert evidence.data["tools"]["httpx"]["status"] == "failed"
    assert evidence.data["tools"]["httpx"]["failure_reasons"] == ["Observed incompatible output"]


def test_verification_options_are_registered_without_explicit_test_path():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--help", "-p", "no:cacheprovider"],
        cwd=str(root), capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "--run-browser" in result.stdout
    assert "--run-kali" in result.stdout
    assert "--verification-artifacts" in result.stdout
