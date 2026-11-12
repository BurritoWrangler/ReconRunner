"""Approved lab fixtures. No target URLs or executable arguments come from users."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import shutil
import ssl
import subprocess
import threading
from types import SimpleNamespace

import pytest

from pentest import runner, tools
from pentest.checkpoints import digest
from pentest.commands import CommandSpec
from pentest.execution import tail
from pentest.verification import REQUIRED_CHECKS, fixture_spec

MARKER = "recon-runner-owned-fixture"


@contextmanager
def owned_services(directory, tls=False):
    entered, release = threading.Event(), threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def reply(self, body=True):
            if self.path.startswith("/slow"):
                entered.set()
                release.wait(30)
            content = f"<html><title>Owned fixture</title><body>{MARKER}</body></html>".encode()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                if body:
                    self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
        def do_GET(self):
            self.reply()
        def do_HEAD(self):
            self.reply(False)
        def log_message(self, *args):
            pass
    servers, threads = [], []
    try:
        http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        servers.append(http)
        tls_server = None
        if tls:
            openssl = shutil.which("openssl")
            if not openssl:
                pytest.fail("openssl is required to create the owned TLS fixture.")
            cert, key = directory / "fixture.crt", directory / "fixture.key"
            # Dummy, short-lived test key stays in this temporary directory.
            subprocess.run([
                openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=127.0.0.1"], check=True, timeout=15,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tls_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            servers.append(tls_server)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
        for server in servers:
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        yield SimpleNamespace(
            http_port=http.server_port, tls_port=tls_server.server_port if tls_server else None,
            entered=entered, release=release)
    finally:
        release.set()
        for server, thread in zip(servers, threads):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive()
        for server in servers[len(threads):]:
            server.server_close()


def write_inputs(ws, services):
    port = services.http_port
    (ws / "targets.txt").write_text("127.0.0.1\n")
    (ws / "web_urls.txt").write_text(f"http://127.0.0.1:{port}/\n")
    (ws / "slow_urls.txt").write_text(f"http://127.0.0.1:{port}/slow\n")
    (ws / "nmap").mkdir()
    (ws / "nmap/tcp.xml").write_text(
        '<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        '<service name="http"/></port></ports></host></nmaprun>')
    for name, word in (("positive", MARKER), ("negative", "never-present-owned-marker")):
        (ws / f"owned-{name}.yaml").write_text(
            f"id: recon-owned-{name}\ninfo:\n  name: Owned local fixture\n"
            "  author: recon-runner\n  severity: info\n"
            "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"
            f"    matchers:\n      - type: word\n        words:\n          - '{word}'\n")


class NativeCheck:
    def __init__(self, mid, ws, services, evidence, version):
        self.mid, self.ws, self.services = mid, ws, services
        self.evidence, self.version = evidence, version

    def spec(self, variant="output"):
        return fixture_spec(self.mid, self.ws, self.services.http_port,
                            self.services.tls_port, variant)

    def run(self, variant="output", **kwargs):
        return runner.run_spec(self.spec(variant), str(self.ws), **kwargs)

    def check(self, name, result, assertion, expected="ok"):
        passed, error = False, ""
        try:
            assert result["status"] == expected, (
                result.get("error") or result.get("output_warnings") or result["status"])
            assert assertion(), "Fixture output/schema assertion failed."
            passed = True
        except Exception as exc:
            error = str(exc)
        entry = self.evidence.data["tools"][self.mid]
        checks = dict(entry.get("checks", {}))
        checks[name] = {"passed": passed, "error": error, "result": result}
        status = ("failed" if any(not c["passed"] for c in checks.values()) else
                  "validated-for-selected-checks" if REQUIRED_CHECKS[self.mid] <= checks.keys()
                  else "partially-verified")
        self.evidence.tool(self.mid, status, checks=checks, version=self.version,
                           reason="Only the recorded fixture checks are covered.")
        self.evidence.record(f"{self.mid}:{name}", "passed" if passed else "failed")
        assert passed, error


@pytest.fixture
def native(request, tmp_path, monkeypatch, verification_evidence):
    # pytest_configure validates the flag, approval, tool allowlist and Linux
    # before this fixture can inspect an executable or bind a service.
    lab = getattr(request.config, "recon_lab", None)
    if not request.config.getoption("--run-kali") or not lab:
        pytest.fail("Approved --run-kali configuration is required.")
    mid = request.param
    if mid not in lab["tools"]:
        pytest.skip(f"{mid} was not selected in the approved lab configuration.")
    binary = tools.module_by_id(mid).binary
    executable = shutil.which(binary)
    if not executable:
        verification_evidence.tool(mid, "blocked", reason=f"{binary} is not installed.")
        pytest.skip(f"{binary} is not installed in this lab.")
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                "all_proxy", "PDCP_API_KEY", "INTERACTSH_SERVER"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "owned-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / "cache"))
    ws = verification_evidence.directory / request.node.name
    ws.mkdir(parents=True)
    flags = ["version"] if mid == "gowitness" else ["--version"] if mid in (
        "nmap_tcp", "sslscan") else ["-version", "-disable-update-check"]
    version_run = runner.run_spec(CommandSpec("version", [executable, *flags],
        stdout_to=str(ws / "version.txt")), str(ws), timeout=10)
    version = {
        "executable": executable, "sha256": digest(executable),
        "stdout": tail(str(ws / "version.txt")),
        "stderr": version_run.get("stderr_tail", ""), "result": version_run,
        "euid": os.geteuid(), "scan_mode": "connect/non-raw",
    }
    previous = verification_evidence.data["tools"][mid].get("version")
    if previous and previous["sha256"] != version["sha256"]:
        verification_evidence.tool(mid, "failed", reason="Executable changed during verification.")
        pytest.fail(f"{binary} executable changed during verification; rerun from a stable lab.")
    verification_evidence.tool(mid, "partially-verified", version=version,
                               reason="Version recorded; fixture checks not complete.")
    if version_run["status"] != "ok":
        verification_evidence.tool(mid, "failed", reason="Version probe failed.", version=version)
        pytest.fail(f"{binary} version probe failed; inspect its recorded logs.")
    with owned_services(tmp_path, tls=mid == "sslscan") as services:
        write_inputs(ws, services)
        yield NativeCheck(mid, ws, services, verification_evidence, version)
