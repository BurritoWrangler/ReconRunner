"""Only owned, dynamically allocated loopback services may be probed here."""

from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

import pytest

from pentest import runner
from pentest.commands import CommandSpec
from pentest.execution import ExecutionContext
from pentest.parsers import gowitness, httpx, nmap, nuclei

pytestmark = pytest.mark.kali


def valid_output(native):
    ws, mid = native.ws, native.mid
    if mid == "nmap_tcp":
        return any(s.host == "127.0.0.1" and s.port == native.services.http_port
                   for s in nmap.parse_xml(str(ws / "nmap/tcp.xml")).services)
    if mid == "httpx":
        return any(e["status"] == 200 and "127.0.0.1" in e["url"]
                   for e in httpx.parse(str(ws / "httpx.jsonl")))
    if mid == "nuclei":
        return any("Owned local fixture" in f.title
                   for f in nuclei.parse(str(ws / "nuclei.jsonl")))
    if mid == "sslscan":
        return ET.parse(ws / "sslscan/127.0.0.1_{}.xml".format(
            native.services.tls_port)).find(".//ssltest") is not None
    if mid == "gowitness":
        shots = gowitness.parse(str(ws / "gowitness.jsonl"))
        return bool(shots) and any((ws / "screens").iterdir())
    return False


@pytest.mark.parametrize("native", ["nmap_tcp", "httpx", "nuclei", "sslscan", "gowitness"], indirect=True)
def test_native_output_and_verified_resume(native):
    result = native.run(timeout=60)
    native.check("output", result, lambda: valid_output(native))
    resumed = native.run(timeout=60, resume=True)
    native.check("resume", resumed, lambda: bool(resumed.get("reused_attempt")), expected="skipped")


@pytest.mark.parametrize("native", ["nuclei"], indirect=True)
def test_legitimate_zero_findings(native):
    result = native.run("empty", timeout=60)
    native.check("no_findings", result, lambda: (
        (native.ws / "nuclei.jsonl").is_file()
        and (native.ws / "nuclei.jsonl").stat().st_size == 0))


@pytest.mark.parametrize("native", ["httpx"], indirect=True)
def test_real_tool_timeout(native):
    result = native.run("slow", timeout=5)
    native.check("timeout", result, lambda: result["duration"] < 20, expected="timeout")


@pytest.mark.parametrize("native", ["httpx"], indirect=True)
def test_real_tool_cancellation(native):
    context = ExecutionContext()
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(native.run, "slow", timeout=30, on_output=context)
        entered = native.services.entered.wait(10)
        context.cancel.set()
        result = future.result(timeout=20)
    native.check("cancellation", result, lambda: entered and result["duration"] < 25,
                 expected="cancelled")


def test_missing_binary_is_reported_without_execution(tmp_path, verification_evidence):
    workspace = verification_evidence.directory / "missing-binary"
    workspace.mkdir()
    result = runner.run_spec(CommandSpec("missing-owned-fixture",
        [str(workspace / "does-not-exist")]), str(workspace))
    assert result["status"] == "missing"
    verification_evidence.record("missing binary handling", "passed", result=result)
