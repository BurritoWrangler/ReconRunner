"""Tests for the v1.1 CLI — run anywhere (no scanning tools required)."""

import os
import shutil

from pentest import cli
from pentest.store import BASE_DIR

SAMPLE_XML = os.path.join(os.path.dirname(__file__), "..", "samples", "nmap_tcp.xml")


def test_list_tools(capsys):
    assert cli.main(["--list-tools"]) == 0
    out = capsys.readouterr().out
    assert "nmap" in out and "nuclei" in out


def test_list_modules(capsys):
    assert cli.main(["--list-modules"]) == 0
    out = capsys.readouterr().out
    assert "nuclei" in out and "bruteforce" in out


def test_dry_run_nmap_xml(capsys):
    rc = cli.main(["--customer", "t", "--nmap-xml", SAMPLE_XML, "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "discovery skipped" in out
    assert "nuclei -l" in out and "-jsonl" in out
    assert "> " in out and "nuclei.jsonl" in out   # captured via stdout_to


def test_missing_input_errors(capsys):
    rc = cli.main(["--customer", "t", "--authorize"])
    assert rc == 2
    assert "provide --hosts" in capsys.readouterr().err


def test_build_config_only_and_set():
    args = cli.build_parser().parse_args([
        "--customer", "t", "--nmap-xml", SAMPLE_XML,
        "--only", "nuclei", "--set", "nuclei.severities=high,critical",
        "--no-root",
    ])
    cfg = cli.build_config(args)
    assert cfg.module_enabled("nuclei")
    assert not cfg.module_enabled("sslscan")
    assert cfg.option("nuclei", "severities") == "high,critical"
    assert cfg.run_as_root is False
    assert cfg.nmap_xml.endswith("nmap_tcp.xml")


def test_bruteforce_confirm_flag():
    args = cli.build_parser().parse_args([
        "--customer", "t", "--nmap-xml", SAMPLE_XML, "--authorize",
        "--enable", "bruteforce", "--confirm-bruteforce",
    ])
    cfg = cli.build_config(args)
    assert cfg.module_enabled("bruteforce")
    assert cfg.option("bruteforce", "confirm") is True
    assert cfg.validate() == []  # confirm satisfied


def test_nmap_xml_end_to_end(capsys):
    customer = "clitest_xml"
    results = os.path.join(BASE_DIR, f"results_{customer}")
    shutil.rmtree(results, ignore_errors=True)
    try:
        rc = cli.main(["--customer", customer, "--nmap-xml", SAMPLE_XML,
                       "--authorize"])
        assert rc == 0
        # A report was produced from the imported inventory.
        reports = []
        for root, _dirs, files in os.walk(results):
            if "report.html" in files:
                reports.append(os.path.join(root, "report.html"))
        assert reports, "no report.html generated"
        html = open(reports[0], encoding="utf-8").read()
        assert "Open services" in html
        assert "web.example.com" in html  # host (hostname) from the imported nmap XML
    finally:
        shutil.rmtree(results, ignore_errors=True)


def test_light_report_flag():
    args = cli.build_parser().parse_args([
        "--customer", "t", "--nmap-xml", SAMPLE_XML, "--light-report",
    ])
    assert cli.build_config(args).report_theme == "light"
    args2 = cli.build_parser().parse_args([
        "--customer", "t", "--nmap-xml", SAMPLE_XML, "--report-theme", "light",
    ])
    assert cli.build_config(args2).report_theme == "light"
    # default stays dark
    args3 = cli.build_parser().parse_args(["--customer", "t", "--nmap-xml", SAMPLE_XML])
    assert cli.build_config(args3).report_theme == "dark"
