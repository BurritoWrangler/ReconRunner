"""Unit tests — run anywhere (no scanning tools required).

They exercise the parsers against the committed samples plus the finding model,
command builder, config parsing and report rendering.
"""

import os
import shutil

from pentest import commands, config, findings, report, software
from pentest.config import ScanConfig
from pentest.findings import Finding
from pentest.parsers import (dnsrecon, gowitness, generic, httpx, nmap, nuclei,
                             searchsploit, shcheck, smb, sslscan, sshaudit, whatweb)

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def s(name):
    return os.path.join(SAMPLES, name)


# ---- nmap -------------------------------------------------------------------

def test_nmap_inventory_and_web_tls():
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    assert len(inv.services) == 7
    ports = {(svc.host, svc.port) for svc in inv.services}
    assert ("web.example.com", 80) in ports
    assert any(svc.is_web() for svc in inv.services)
    assert any(svc.is_tls() and svc.port == 443 for svc in inv.services)
    assert "web.example.com" in inv.hosts()


def test_nmap_vulners_cves():
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    fs = nmap.inventory_findings(inv)
    cves = {r for f in fs for r in f.references if r.startswith("CVE-")}
    assert "CVE-2021-42013" in cves
    crit = [f for f in fs if "CVE-2021-42013" in f.references]
    assert crit and crit[0].severity == "critical"


def test_nmap_udp_merge():
    inv = nmap.merge_inventories(nmap.parse_xml(s("nmap_tcp.xml")),
                                 nmap.parse_xml(s("nmap_udp.xml")))
    assert any(svc.port == 161 and svc.proto == "udp" for svc in inv.services)


# ---- web pipeline -----------------------------------------------------------

def test_httpx_parse():
    entries = httpx.parse(s("httpx.jsonl"))
    assert len(entries) == 2
    assert entries[0]["url"].startswith("http")


def test_nuclei_parse_severity():
    fs = nuclei.parse(s("nuclei.jsonl"))
    assert any(f.severity == "critical" and f.category == "cve" for f in fs)


def test_sslscan_findings():
    fs = sslscan.parse(s("sslscan_example.xml"))
    titles = " ".join(f.title for f in fs)
    assert "SSLv3" in titles
    assert any("Weak TLS cipher" in f.title for f in fs)
    assert any("Expired" in f.title for f in fs)


def test_shcheck_missing_headers():
    fs = shcheck.parse(s("shcheck_example.json"))
    assert len(fs) == 1
    assert fs[0].severity == "medium"  # HSTS/CSP missing
    assert "Strict-Transport-Security" in fs[0].evidence


def test_whatweb_versions():
    fs = whatweb.parse(s("whatweb_example.json"))
    outdated = {(f.product, f.version) for f in fs if f.category == "outdated"}
    assert ("Apache", "2.4.49") in outdated
    assert ("PHP", "5.6.40") in outdated


def test_searchsploit_exploit():
    fs = searchsploit.parse(s("searchsploit.json"))
    assert fs and fs[0].category == "exploit"
    assert fs[0].exploitable()
    assert any("EDB-ID:50383" in r for r in fs[0].references)


def test_sshaudit_findings():
    fs = sshaudit.parse(s("sshaudit_example.json"))
    assert any(f.category == "cve" for f in fs)
    assert any("Weak SSH algorithms" in f.title for f in fs)


def test_gowitness_parse():
    shots = gowitness.parse(s("gowitness.jsonl"))
    assert len(shots) == 2
    assert shots[0]["file"].endswith(".png")


def test_generic_snmp(tmp_path):
    ws = tmp_path
    snmp_dir = ws / "snmp"
    snmp_dir.mkdir()
    with open(s("snmp_onesixtyone.txt")) as fh:
        (snmp_dir / "192.0.2.10_onesixtyone.txt").write_text(fh.read())
    fs = generic.snmp(str(ws))
    assert any("community" in f.title.lower() and f.severity == "medium" for f in fs)


# ---- findings + prioritization ---------------------------------------------

def test_prioritize_orders_and_scores():
    items = [
        Finding(title="info svc", severity="info", category="service",
                assets=["h:80"], confidence=0.9),
        Finding(title="Critical RCE", severity="critical", category="cve",
                assets=["h:80"], confidence=0.8, references=["CVE-2021-42013"]),
        Finding(title="Weak TLS", severity="medium", category="tls",
                assets=["h:443"], confidence=0.8),
    ]
    ranked = findings.prioritize(items)
    assert ranked[0].severity == "critical"
    assert ranked[0].rank == 1
    summ = findings.summarize(ranked)
    assert summ["total"] == 3 and summ["critical"] == 1


def test_exposure_boosts_sensitive_service():
    rdp = Finding(title="x", severity="medium", assets=["h:3389"])
    web = Finding(title="y", severity="medium", assets=["h:8080"])
    assert findings.compute_score(rdp) > findings.compute_score(web)


def test_merge_dedup_corroboration():
    a = Finding(title="Same", severity="medium", category="tls",
                assets=["h:443"], source_tools=["sslscan"], confidence=0.6)
    b = Finding(title="Same", severity="high", category="tls",
                assets=["h:443"], source_tools=["sslyze"], confidence=0.6)
    merged = findings.merge([a, b])
    assert len(merged) == 1
    assert merged[0].severity == "high"
    assert set(merged[0].source_tools) == {"sslscan", "sslyze"}


# ---- command builder --------------------------------------------------------

def test_preview_matches_plan_flags():
    line = commands.preview("nmap_tcp", {"scan_type": "-sS", "all_ports": True,
                                         "version_detection": True, "timing": "T4"})[0]
    assert line.startswith("nmap -Pn -sS -p- -sV -T4")
    assert "-oA <ws>/nmap/tcp" in line and "-iL <ws>/targets.txt" in line


def test_preview_stdout_redirect_for_shcheck():
    line = commands.preview("shcheck", {})[0]
    assert line.startswith("shcheck.py -j -d <url>")
    assert "> <ws>/shcheck/<host>_<port>.json" in line


def test_preview_nuclei_outputs():
    line = commands.preview("nuclei", {"severities": "high,critical",
                                       "rate_limit": 100})[0]
    assert "-jsonl-export <ws>/nuclei.jsonl" in line
    assert "-o <ws>/nuclei.txt" in line


# ---- config -----------------------------------------------------------------

def test_parse_targets_and_sanitize():
    valid, invalid = config.parse_targets("192.0.2.10\nmail.example.com\n# c\n\nbad host")
    assert "192.0.2.10" in valid and "mail.example.com" in valid
    assert "bad host" in invalid
    assert config.sanitize_customer("Acme Corp, Inc.") == "Acme_Corp_Inc"


def test_validate_requires_auth_and_customer():
    cfg = ScanConfig.defaults()
    cfg.targets = ["192.0.2.10"]
    cfg.customer_name = ""
    cfg.authorized = False
    errs = cfg.validate()
    assert any("authorized" in e for e in errs)
    assert any("Customer name" in e for e in errs)


def test_bruteforce_requires_confirmation():
    cfg = ScanConfig.defaults()
    cfg.targets = ["192.0.2.10"]
    cfg.customer_name = "c"
    cfg.authorized = True
    cfg.modules["bruteforce"]["enabled"] = True
    cfg.modules["bruteforce"]["options"]["confirm"] = False
    assert any("brute force" in e for e in cfg.validate())


# ---- report -----------------------------------------------------------------

def test_report_renders(tmp_path):
    inv = nmap.merge_inventories(nmap.parse_xml(s("nmap_tcp.xml")),
                                 nmap.parse_xml(s("nmap_udp.xml")))
    fs = (nmap.inventory_findings(inv) + nuclei.parse(s("nuclei.jsonl"))
          + sslscan.parse(s("sslscan_example.xml")) + whatweb.parse(s("whatweb_example.json"))
          + searchsploit.parse(s("searchsploit.json")))
    ranked = findings.prioritize(fs)
    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.targets = ["192.0.2.10"]
    state = {"id": "t1", "customer": "acme", "scan_name": "s", "created_at": 0,
             "modules": {}}
    rel = report.generate(str(tmp_path), cfg, state, inv, ranked, [])
    out = tmp_path / rel
    assert out.exists()
    html = out.read_text()
    assert "Prioritized findings" in html
    assert "Open services" in html
    assert "CVE-2021-41773" in html or "CVE-2021-42013" in html


def test_report_theme_switch(tmp_path):
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    ranked = findings.prioritize(nmap.inventory_findings(inv))
    state = {"id": "t", "customer": "c", "scan_name": "s", "created_at": 0,
             "modules": {}}

    (tmp_path / "dark").mkdir()
    dark_cfg = ScanConfig.defaults()
    dark_cfg.customer_name = "c"
    report.generate(str(tmp_path / "dark"), dark_cfg, state, inv, ranked, [])
    dark_html = (tmp_path / "dark" / "report.html").read_text()
    assert "#05080a" in dark_html  # dark (hacker) background

    (tmp_path / "light").mkdir()
    light_cfg = ScanConfig.defaults()
    light_cfg.customer_name = "c"
    light_cfg.report_theme = "light"
    report.generate(str(tmp_path / "light"), light_cfg, state, inv, ranked, [])
    light_html = (tmp_path / "light" / "report.html").read_text()
    assert "#f4f6f8" in light_html  # light (printable) background
    assert "#05080a" not in light_html


def test_runner_creates_output_dirs(tmp_path):
    from pentest import runner
    ws = str(tmp_path)
    argv = ["nmap", "-Pn", "-oA", f"{ws}/nmap/tcp",
            f"--xml={ws}/sslscan/h_443.xml", "-iL", f"{ws}/targets.txt"]
    runner._ensure_output_dirs(argv, ws)
    assert (tmp_path / "nmap").is_dir()      # nmap -oA parent
    assert (tmp_path / "sslscan").is_dir()   # sslscan --xml= parent


# ---- software version enumeration + exploit correlation --------------------

def test_is_precise():
    assert software.is_precise("2.4.49")
    assert software.is_precise("7.4")
    assert software.is_precise("1.0.1f")
    assert not software.is_precise("")
    assert not software.is_precise("Postfix")
    assert not software.is_precise("5")        # no concrete X.Y version


def test_software_exploit_correlation():
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    exploits = searchsploit.entries(s("searchsploit.json"))
    sw_findings, rows = software.correlate(inv, [], exploits)
    apache = [r for r in rows
              if r["product"].lower().startswith("apache") and r["version"] == "2.4.49"]
    assert apache, "Apache 2.4.49 was not correlated to its public exploit"
    r = apache[0]
    assert any(e["edb"] == "50383" for e in r["exploits"])
    assert "CVE-2021-41773" in r["exploits"][0]["cves"]
    assert r["severity"] == "critical"   # exploit title contains RCE
    assert any(f.category == "exploit" and f.version == "2.4.49" and f.assets
               for f in sw_findings)


def test_no_correlation_without_precise_version():
    # Product detected but no precise version -> never correlated, even if an
    # exploit title mentions the product ("precise before reporting").
    inv = nmap.Inventory(services=[nmap.Service(
        host="h", port=25, proto="tcp", name="smtp", product="Postfix", version="")])
    exploits = [{"title": "Postfix 2.0 - Something", "edb": "1", "url": "", "cves": []}]
    _f, rows = software.correlate(inv, [], exploits)
    assert rows == []


def test_report_has_known_exploits_section(tmp_path):
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    exploits = searchsploit.entries(s("searchsploit.json"))
    sw_findings, rows = software.correlate(inv, [], exploits)
    ranked = findings.prioritize(nmap.inventory_findings(inv) + sw_findings)
    cfg = ScanConfig.defaults()
    cfg.customer_name = "c"
    state = {"id": "t", "customer": "c", "scan_name": "s", "created_at": 0,
             "modules": {}, "software_exploits": rows}
    report.generate(str(tmp_path), cfg, state, inv, ranked, [])
    html = (tmp_path / "report.html").read_text()
    assert "Software with known exploits" in html
    assert "EDB-50383" in html and "2.4.49" in html


# ---- SMB + DNS modules ------------------------------------------------------

def test_smb_parsers(tmp_path):
    d = tmp_path / "smb"
    d.mkdir()
    shutil.copyfile(s("enum4linux_example.json"), d / "192.0.2.30_enum4linux.json")
    shutil.copyfile(s("smbmap_example.txt"), d / "192.0.2.30_smbmap.txt")
    fs = smb.parse_dir(str(d))
    titles = {f.title: f for f in fs}
    assert "SMB shares enumerated" in titles
    assert "SMB null/guest session permitted" in titles
    assert titles["SMB null/guest session permitted"].severity == "medium"
    acc = [f for f in fs if f.title.startswith("SMB shares accessible")]
    assert acc and acc[0].severity == "high"          # backups is READ, WRITE
    assert acc[0].assets == ["192.0.2.30:445"]


def test_dnsrecon_parser(tmp_path):
    d = tmp_path / "dnsrecon"
    d.mkdir()
    shutil.copyfile(s("dnsrecon_example.json"), d / "192.0.2.30.json")
    shutil.copyfile(s("dnsrecon_example.txt"), d / "192.0.2.30.txt")
    fs = dnsrecon.parse_dir(str(d))
    axfr = [f for f in fs if "zone transfer" in f.title.lower()]
    assert axfr and axfr[0].severity == "high"
    assert axfr[0].assets == ["192.0.2.30:53"]
    assert any(f.title == "DNS records enumerated" for f in fs)


def test_smb_dns_command_preview():
    smb_lines = "\n".join(commands.preview("smb_enum", {}))
    assert "enum4linux-ng -A <host> -oJ <ws>/smb/<host>_enum4linux" in smb_lines
    assert "smbmap -H <host> > <ws>/smb/<host>_smbmap.txt" in smb_lines
    dns_lines = "\n".join(commands.preview("dnsrecon", {}))
    assert "dnsrecon -d <host> -t std,axfr -j <ws>/dnsrecon/<host>.json" in dns_lines


# ---- live stdout streaming (status-page console) ----------------------------

def test_run_spec_streams_stdout(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    seen = []
    spec = CommandSpec("probe", ["printf", "alpha\nbeta\n"])
    res = runner.run_spec(spec, str(tmp_path), timeout=30,
                          on_output=lambda label, line: seen.append((label, line)))
    assert res["status"] == "ok" and res["returncode"] == 0
    text = "".join(line for _, line in seen)
    assert "alpha" in text and "beta" in text
    assert all(label == "probe" for label, _ in seen)


def test_run_spec_stdout_to_excludes_stderr(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    out = tmp_path / "o.txt"
    spec = CommandSpec("mix", ["sh", "-c", "echo OUT; echo ERR 1>&2"],
                       stdout_to=str(out))
    runner.run_spec(spec, str(tmp_path), timeout=30)
    assert "OUT" in out.read_text() and "ERR" not in out.read_text()
    assert "ERR" in (tmp_path / "logs" / "mix.log").read_text()  # stderr kept in log


def test_tail_helper(tmp_path):
    import app as webapp
    p = tmp_path / "c.log"
    p.write_text("\n".join("line%d" % i for i in range(500)) + "\n")
    tail = webapp._tail(str(p), max_lines=10)
    assert tail.splitlines()[-1] == "line499"
    assert len(tail.splitlines()) == 10
