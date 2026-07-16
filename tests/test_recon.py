"""Unit tests — run anywhere (no scanning tools required).

They exercise the parsers against the committed samples plus the finding model,
command builder, config parsing and report rendering.
"""

import os
import shutil

from pentest import commands, config, findings, report, software
from pentest.config import ScanConfig
from pentest.findings import Finding
from pentest.parsers import (bruteforce, content, dnsrecon, dnsx, gowitness,
                             generic, httpx, nmap, nikto, nuclei, recon,
                             searchsploit, shcheck, smb, sslscan, sshaudit,
                             testssl, whatweb, wpscan)

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


def _curated_finding(port, script_id, output, name="tcpwrapped"):
    inv = nmap.Inventory()
    inv.add(nmap.Service(host="10.0.0.1", port=port, proto="tcp", state="open",
                         name=name, scripts={script_id: output}))
    return [f for f in nmap.inventory_findings(inv) if f.category != "service"]


def test_nmap_eternalblue_finding():
    # Real smb-vuln-ms17-010 output uses the vulns-library "State: VULNERABLE" token.
    out = ("VULNERABLE:\nRemote Code Execution vulnerability in Microsoft "
           "SMBv1 servers (ms17-010)\n  State: VULNERABLE\n  IDs:  CVE:CVE-2017-0143")
    fs = _curated_finding(445, "smb-vuln-ms17-010", out, name="microsoft-ds")
    assert fs, "EternalBlue script output produced no curated finding"
    f = fs[0]
    assert f.severity == "critical"
    assert "EternalBlue" in f.title and "MS17-010" in f.title
    assert "CVE-2017-0143" in f.references
    assert "MS17-010" in f.references
    assert "smb-vuln-ms17-010" in f.source_tools
    # No duplicate: the generic VULNERABLE handler must not also fire.
    assert len(fs) == 1


def test_nmap_bluekeep_finding():
    out = ("VULNERABLE:\nRemote Code Execution vulnerability in Microsoft RDP "
           "(CVE-2019-0708)\n  State: VULNERABLE")
    fs = _curated_finding(3389, "rdp-vuln-cve-2019-0708", out, name="ms-wbt-server")
    assert fs, "BlueKeep script output produced no curated finding"
    f = fs[0]
    assert f.severity == "critical"
    assert "BlueKeep" in f.title
    assert "CVE-2019-0708" in f.references
    assert len(fs) == 1


def test_nmap_cisco_smart_install_finding():
    # cisco-siet (third-party NSE) prints "Status: VULNERABLE" when the Smart
    # Install service is vulnerable to abuse / CVE-2018-0171 RCE.
    fs = _curated_finding(4786, "cisco-siet", "Host: 10.0.0.1\nStatus: VULNERABLE",
                          name="smart-install")
    assert fs, "cisco-siet 'Status: VULNERABLE' produced no curated finding"
    f = fs[0]
    assert f.severity == "high"
    assert "Smart Install" in f.title
    assert "CVE-2018-0171" in f.references
    assert len(fs) == 1


def test_nmap_ftp_anon_finding():
    fs = _curated_finding(21, "ftp-anon", "Anonymous FTP login allowed (FTP code 230)",
                          name="ftp")
    assert fs, "ftp-anon output produced no curated finding"
    f = fs[0]
    assert f.severity == "low"
    assert f.category == "exposure"
    assert "Anonymous FTP" in f.title
    # No CVE for the exposure category.
    assert not any(r.startswith("CVE-") for r in f.references)


def test_nmap_curated_not_fired_on_negatives():
    # Positive markers are exact tokens; negatives must not trigger a curated
    # OR generic finding.
    assert not _curated_finding(445, "smb-vuln-ms17-010",
                                "This system is patched.", name="microsoft-ds")
    # "Status: NOT VULNERABLE" must not match "Status: VULNERABLE" (curated) and
    # must also be suppressed by the generic handler's NOT-VULNERABLE guard.
    assert not _curated_finding(4786, "cisco-siet",
                                "Host: 10.0.0.1\nStatus: NOT VULNERABLE",
                                name="smart-install")


def test_preview_nmap_vuln_default_scripts():
    line = commands.preview("nmap_vuln", {})[0]
    assert "smb-vuln-ms17-010" in line
    assert "rdp-vuln-cve-2019-0708" in line
    assert "cisco-siet" in line
    assert "ftp-anon" in line
    assert "--script" in line


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
                assets=["h:443"], source_tools=["sslscan"], confidence=0.6,
                proofs=[findings.proof("sslscan", "sslscan output")])
    b = Finding(title="Same", severity="high", category="tls",
                assets=["h:443"], source_tools=["sslyze"], confidence=0.6,
                proofs=[findings.proof("sslyze", "sslyze output")])
    merged = findings.merge([a, b])
    assert len(merged) == 1
    assert merged[0].severity == "high"
    assert set(merged[0].source_tools) == {"sslscan", "sslyze"}
    # Both tools' proofs survive dedup.
    assert len(merged[0].proofs) == 2
    assert {p["tool"] for p in merged[0].proofs} == {"sslscan", "sslyze"}


def test_heuristic_flag_low_confidence():
    f = Finding(title="x", severity="medium", confidence=0.5)
    assert f.heuristic() is True
    assert f.to_dict()["heuristic"] is True
    f2 = Finding(title="y", severity="medium", confidence=0.9)
    assert f2.heuristic() is False


def test_proofs_dedup_no_duplicate_on_remerge():
    p = [findings.proof("sslscan", "out")]
    a = Finding(title="z", severity="medium", category="tls",
                assets=["h:443"], source_tools=["sslscan"], proofs=p)
    # Merging the same finding twice must not double the proof.
    merged = findings.merge([a, a])
    assert len(merged[0].proofs) == 1


def test_parser_emits_proof():
    fs = nuclei.parse(s("nuclei.jsonl"))
    f = next((x for x in fs if x.category == "cve"), None)
    assert f and f.proofs, "nuclei finding has no proof"
    assert f.proofs[0]["tool"] == "nuclei"
    assert "template:" in f.proofs[0]["output"]
    # EternalBlue curated NSE finding carries the script output as its proof.
    eb = _curated_finding(445, "smb-vuln-ms17-010",
                          "State: VULNERABLE\nIDs: CVE:CVE-2017-0143",
                          name="microsoft-ds")[0]
    assert eb.proofs and eb.proofs[0]["tool"] == "smb-vuln-ms17-010"
    assert "VULNERABLE" in eb.proofs[0]["output"]


def test_report_renders_proofs_webapps_and_heuristic(tmp_path):
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    lo = Finding(title="Heuristic XSS", severity="low", category="exposure",
                 assets=["h:80"], confidence=0.5,
                 proofs=[findings.proof("nikto", "reflected param")])
    hi = Finding(title="CVE-2021-42013 Apache RCE", severity="critical",
                 category="cve", assets=["web.example.com:80"], confidence=0.85,
                 proofs=[findings.proof("nuclei", "template: CVE-2021-42013\nmatched")])
    ranked = findings.prioritize(nmap.inventory_findings(inv) + [lo, hi])
    cfg = ScanConfig.defaults()
    cfg.customer_name = "c"
    state = {"id": "t", "customer": "c", "scan_name": "s", "created_at": 0,
             "modules": {}}
    web_apps = [{"url": "http://web.example.com:80", "status": 200,
                 "title": "Home", "webserver": "Apache", "tech": ["PHP"]}]
    tool_issues = [{"module": "nikto", "label": "nikto", "status": "missing",
                    "error": "nikto: not found", "command": "nikto ..."}]
    report.generate(str(tmp_path), cfg, state, inv, ranked, [],
                    web_apps=web_apps, tool_issues=tool_issues)
    html = (tmp_path / "report.html").read_text()
    # Proof block: tool name + output rendered.
    assert "<details><summary><span class=\"ptool\">nuclei</span>" in html
    assert "template: CVE-2021-42013" in html
    # Web applications section.
    assert "Web applications" in html and "web.example.com:80" in html
    # Coverage notes callout.
    assert "Coverage notes" in html and "nikto" in html and "not found" in html
    # Heuristic flag + validate note for the low-confidence finding.
    assert "heuristic" in html and "validate before acting" in html
    assert "confidence 50%" in html


def test_gather_isolates_parser_failures(tmp_path, monkeypatch):
    """One parser raising must not sink the report — others still gathered."""
    from pentest.engine import ScanEngine
    from pentest.store import Store, new_scan_id
    monkeypatch.setattr("pentest.engine.tools.Module.available", lambda self: True)
    store = Store(base_dir=str(tmp_path))
    eng = ScanEngine(store)
    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    ws = store.create_workspace(cfg, new_scan_id())
    _wjsonl(os.path.join(ws, "dnsx.jsonl"), [{"host": "h", "a": ["1.2.3.4"]}])
    # Make one parser blow up; _gather must still return the rest.
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr("pentest.engine.nuclei.parse", boom)
    inv, found, _exploits, web_apps = eng._gather(ws, state={"log": []})
    # dnsx still parsed despite nuclei raising.
    assert any(t == "dnsx" for f in found for t in f.source_tools)
    assert inv.services or web_apps or found  # not all empty


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
    assert "-jsonl " in line                 # JSONL emitted to stdout
    assert "> <ws>/nuclei.jsonl" in line      # runner captures stdout -> nuclei.jsonl
    assert "-severity high,critical" in line
    assert "-rate-limit 100" in line


def test_nuclei_stdout_captured_to_jsonl(tmp_path):
    """nuclei emits JSONL to stdout; the runner must capture it to nuclei.jsonl
    (which the parser reads). Stats/progress go to stderr and must NOT pollute it."""
    from pentest import commands, runner
    from pentest.commands import Ctx
    c = Ctx(ws=str(tmp_path),
            web_urls_file=str(tmp_path / "web_urls.txt"))
    (tmp_path / "web_urls.txt").write_text("http://x\n")
    spec = commands.build_commands("nuclei", {"severities": "high,critical"}, c)[0]
    # `printf` emits a nuclei-style JSONL line to stdout; `echo STATS` to stderr.
    spec = commands.CommandSpec(
        spec.label, ["sh", "-c", "printf '%s\n' '{\"template-id\":\"CVE-1\",\"info\":{\"name\":\"x\",\"severity\":\"high\"}}'; echo STATS 1>&2"],
        stdout_to=spec.stdout_to)
    runner.run_spec(spec, str(tmp_path), timeout=30)
    out = (tmp_path / "nuclei.jsonl").read_text()
    assert "CVE-1" in out and "STATS" not in out   # clean JSONL, no stats


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


# ---- previously-dropped tools now gathered into the report -------------------

def _wjson(path, obj):
    import json as _j
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(str(path), "w") as fh:
        fh.write(_j.dumps(obj))


def _wjsonl(path, rows):
    import json as _j
    os.makedirs(os.path.dirname(str(path)), exist_ok=True)
    with open(str(path), "w") as fh:
        for r in rows:
            fh.write(_j.dumps(r) + "\n")


def test_nikto_parser(tmp_path):
    d = tmp_path / "nikto"
    _wjson(d / "192.0.2.10_80.json", [
        {"msg": "Server may leak version via header", "item": "X-Powered-By", "url": "/"},
        {"msg": "OSVDB-3092: /admin SQL injection CVE-2020-1234", "item": "/admin", "osvdb": "3092", "url": "/admin"},
    ])
    fs = nikto.parse_dir(str(d))
    assert len(fs) == 2
    assert any(f.category == "cve" and "CVE-2020-1234" in f.references for f in fs)
    assert any(f.category == "exposure" and f.severity == "low" for f in fs)  # header keyword


def test_testssl_parser(tmp_path):
    d = tmp_path / "testssl"
    _wjsonl(d / "192.0.2.10_443.json", [
        {"severity": "CRITICAL", "id": "heartbleed", "finding": "Vulnerable to Heartbleed", "cve": "CVE-2014-0160"},
        {"severity": "OK", "id": "protocols", "finding": "TLS 1.2 offered"},  # dropped (OK, no cve)
        {"severity": "MEDIUM", "id": "cbc", "finding": "CBC ciphers offered"},
    ])
    fs = testssl.parse_dir(str(d))
    assert any(f.severity == "critical" and "CVE-2014-0160" in f.references for f in fs)
    assert any(f.severity == "medium" for f in fs)
    assert not any("TLS 1.2 offered" in f.title for f in fs)   # OK record dropped


def test_wpscan_parser(tmp_path):
    d = tmp_path / "wpscan"
    _wjson(d / "192.0.2.10_80.json", {
        "interesting_findings": [{"to_s": "WordPress version 5.0 identified", "url": "http://x"}],
        "version": {"number": "5.0", "vulnerabilities": [
            {"title": "WP 5.0 XSS", "references": {"cve": ["CVE-2018-1234"]}, "fixed_in": "5.0.1"}]},
        "plugins": {"contact-form-7": {"version": "5.1", "vulnerabilities": []}},
    })
    fs = wpscan.parse_dir(str(d))
    assert any(f.category == "outdated" and f.product == "WordPress" and f.version == "5.0" for f in fs)
    assert any(f.category == "cve" and "CVE-2018-1234" in f.references for f in fs)
    assert any(f.category == "exposure" for f in fs)   # interesting_finding


def test_content_parser_ffuf_and_feroxbuster(tmp_path):
    _wjson(tmp_path / "ffuf" / "192.0.2.10_80.json",
           {"results": [{"input": {"FUZZ": "/admin"}, "status": 200, "length": 1234},
                         {"input": {"FUZZ": "/secret"}, "status": 403, "length": 90}]})
    _wjsonl(tmp_path / "ferox" / "192.0.2.20_80.json",
            [{"type": "response", "url": "http://192.0.2.20/login", "status": 401},
             {"type": "response", "url": "http://192.0.2.20/api", "status": 404}])
    fs = content.parse_dir(str(tmp_path))
    assert len(fs) == 3   # ffuf 2 + feroxbuster 1 (404 skipped)
    assert any("/admin" in f.title and f.severity == "low" for f in fs)
    assert any("/secret" in f.title and f.severity == "medium" for f in fs)  # 403 auth-gated
    assert any("/login" in f.title and f.severity == "medium" for f in fs)  # 401


def test_recon_parser_katana_gau_subfinder(tmp_path):
    _wjsonl(tmp_path / "katana.jsonl", [{"endpoint": "https://x.com/a"}, {"endpoint": "https://x.com/b"}])
    _wjsonl(tmp_path / "subfinder" / "example.com.jsonl", [{"host": "a.example.com"}, {"host": "b.example.com"}])
    gau = tmp_path / "gau"
    gau.mkdir()
    (gau / "example.com.txt").write_text("https://x.com/old\nhttps://x.com/older\n")
    (gau / "example.com_wayback.txt").write_text("https://x.com/wb1\n")
    fs = recon.parse_dir(str(tmp_path))
    assert any(f.source_tools == ["katana"] and "2 endpoint" in f.title for f in fs)
    assert any(f.source_tools == ["gau"] and "2 historical" in f.title for f in fs)
    assert any(f.source_tools == ["waybackurls"] for f in fs)
    assert any(f.source_tools == ["subfinder"] and "2 subdomain" in f.title for f in fs)


def test_recon_parser_amass(tmp_path):
    _wjsonl(tmp_path / "amass" / "example.com.json",
            [{"name": "a.example.com"}, {"name": "b.example.com"}])
    fs = recon.parse_dir(str(tmp_path))
    assert any(f.source_tools == ["amass"] and "2 subdomain" in f.title for f in fs)


def test_bruteforce_parser_hydra_medusa_ncrack(tmp_path):
    d = tmp_path / "bruteforce"
    _wjson(d / "192.0.2.10_ssh.json",
           {"results": [{"host": "192.0.2.10", "login": "root", "password": "toor", "service": "ssh", "port": 22}]})
    (d / "192.0.2.20_ssh.log").write_text(
        "ACCOUNT FOUND: [ssh] Host: 192.0.2.20 User: admin Password: admin123\n")
    (d / "192.0.2.30_ftp.txt").write_text(
        "Discovered credentials for ftp on 192.0.2.30:21:\n  user:pass  success\n")
    fs = bruteforce.parse_dir(str(d))
    assert len(fs) == 3
    assert all(f.severity == "critical" and f.category == "exploit" for f in fs)
    assert any(f.source_tools == ["hydra"] and "root@192.0.2.10" in f.title for f in fs)
    assert any(f.source_tools == ["medusa"] and "admin@192.0.2.20" in f.title for f in fs)
    assert any(f.source_tools == ["ncrack"] and "user@192.0.2.30" in f.title for f in fs)


def test_dnsx_findings(tmp_path):
    _wjsonl(tmp_path / "dnsx.jsonl",
            [{"host": "mail.example.com", "a": ["192.0.2.10"], "cname": ["web.example.com"]}])
    fs = dnsx.findings(str(tmp_path / "dnsx.jsonl"))
    assert fs and fs[0].category == "recon" and fs[0].source_tools == ["dnsx"]
    assert "192.0.2.10" in fs[0].evidence and "CNAME" in fs[0].evidence


def test_engine_gathers_all_tools(tmp_path, monkeypatch):
    """_gather must parse every tool's artifacts, not just the original 12."""
    from pentest.engine import ScanEngine
    from pentest.store import Store, new_scan_id
    monkeypatch.setattr("pentest.engine.tools.Module.available", lambda self: True)
    store = Store(base_dir=str(tmp_path))
    eng = ScanEngine(store)
    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    # Enable every module so each produces an artifact.
    for mid in list(cfg.modules):
        cfg.modules[mid]["enabled"] = True
    cfg.modules["bruteforce"]["options"]["confirm"] = True
    sid = new_scan_id()
    ws = store.create_workspace(cfg, sid)
    # Seed a minimal artifact per tool so the (no-tool) parsers have something.
    _wjson(os.path.join(ws, "nikto", "h_80.json"), [{"msg": "x", "item": "y"}])
    _wjsonl(os.path.join(ws, "testssl", "h_443.json"), [{"severity": "HIGH", "finding": "x"}])
    _wjson(os.path.join(ws, "wpscan", "h_80.json"), {"version": {"number": "5.0"}})
    _wjson(os.path.join(ws, "ffuf", "h_80.json"),
           {"results": [{"input": {"FUZZ": "/a"}, "status": 200}]})
    _wjsonl(os.path.join(ws, "katana.jsonl"), [{"endpoint": "https://x/a"}])
    _wjson(os.path.join(ws, "bruteforce", "h_ssh.json"),
           {"results": [{"host": "h", "login": "r", "password": "p", "service": "ssh"}]})
    _wjsonl(os.path.join(ws, "dnsx.jsonl"), [{"host": "h", "a": ["1.2.3.4"]}])
    inv, found, _, web_apps = eng._gather(ws)
    tools_seen = {t for f in found for t in f.source_tools}
    for tool in ("nikto", "testssl", "wpscan", "ffuf", "katana", "dnsx"):
        assert tool in tools_seen, f"{tool} output not gathered into report"


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


# ---- delete + resume --------------------------------------------------------

def _make_scan(store, customer="acme", status="queued"):
    """Create a persisted scan workspace and return (scan_id, ws)."""
    from pentest.store import new_scan_id
    cfg = ScanConfig.defaults()
    cfg.customer_name = customer
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    scan_id = new_scan_id()
    ws = store.create_workspace(cfg, scan_id)
    state = store.initial_state(cfg, scan_id, ws)
    state["status"] = status
    store.save_state(ws, state)
    return scan_id, ws


def test_delete_scan_removes_only_that_workspace(tmp_path):
    from pentest.store import Store
    store = Store(base_dir=str(tmp_path))
    keep_id, keep_ws = _make_scan(store)
    drop_id, drop_ws = _make_scan(store)            # same customer -> same root

    assert store.delete_scan(drop_id) is True
    assert not os.path.exists(drop_ws)
    assert os.path.isdir(keep_ws)                   # sibling untouched
    assert os.path.isdir(os.path.dirname(drop_ws))  # results_<customer> root kept
    assert store.find_scan(drop_id) == (None, None)
    # Unknown id is a no-op, not an error.
    assert store.delete_scan("nope") is False


def test_delete_scan_refuses_path_outside_results(tmp_path, monkeypatch):
    from pentest.store import Store
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep.txt").write_text("do not delete")
    base = tmp_path / "base"
    base.mkdir()
    store = Store(base_dir=str(base))
    # Simulate find_scan resolving to a directory outside the results tree.
    monkeypatch.setattr(store, "find_scan",
                        lambda sid: (str(precious), {"id": sid}))
    assert store.delete_scan("x") is False
    assert (precious / "keep.txt").exists()


def test_mark_interrupted_orphans(tmp_path):
    from pentest.store import Store
    store = Store(base_dir=str(tmp_path))
    run_id, run_ws = _make_scan(store, status="running")
    q_id, q_ws = _make_scan(store, status="queued")
    done_id, done_ws = _make_scan(store, customer="beta", status="done")

    assert store.mark_interrupted_orphans() == 2
    assert store.load_state(run_ws)["status"] == "interrupted"
    assert store.load_state(q_ws)["status"] == "interrupted"
    assert "resume" in store.load_state(run_ws)["error"].lower()
    assert store.load_state(done_ws)["status"] == "done"   # finished scan untouched


def test_runner_resume_skips_when_output_present(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    ws = str(tmp_path)
    out = tmp_path / "x.json"
    out.write_text("OLD")
    spec = CommandSpec("probe", ["printf", "NEW"], stdout_to=str(out))

    res = runner.run_spec(spec, ws, timeout=30, resume=True)
    assert res["status"] == "skipped"
    assert out.read_text() == "OLD"            # command did not run

    # Empty output does not count as complete -> the command runs.
    out.write_text("")
    res = runner.run_spec(spec, ws, timeout=30, resume=True)
    assert res["status"] == "ok"
    assert out.read_text() == "NEW"

    # Without resume the command always runs.
    out.write_text("OLD")
    res = runner.run_spec(spec, ws, timeout=30, resume=False)
    assert res["status"] == "ok" and out.read_text() == "NEW"


def test_runner_resume_satisfied_handles_nmap_oa(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    ws = str(tmp_path)
    (tmp_path / "targets.txt").write_text("192.0.2.10\n")
    os.makedirs(tmp_path / "nmap")
    xml = tmp_path / "nmap" / "tcp.xml"
    xml.write_text("<nmaprun/>\n")
    spec = CommandSpec("nmap_tcp",
                       ["nmap", "-Pn", "-oA", f"{ws}/nmap/tcp",
                        "-iL", f"{ws}/targets.txt"])
    assert f"{ws}/nmap/tcp.xml" in runner._resume_outputs(spec, ws)
    assert runner._resume_satisfied(spec, ws) is True
    xml.unlink()
    assert runner._resume_satisfied(spec, ws) is False


def test_engine_resume_skips_completed_discovery(tmp_path):
    from pentest.engine import ScanEngine
    from pentest.store import Store, new_scan_id
    store = Store(base_dir=str(tmp_path))
    engine = ScanEngine(store)

    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    cfg.demo = False
    # Keep it tool-free and deterministic: only nmap_tcp "enabled", and it will
    # be skipped on resume because we seed its output below.
    for mid in list(cfg.modules):
        cfg.modules[mid]["enabled"] = (mid == "nmap_tcp")

    scan_id = new_scan_id()
    ws = store.create_workspace(cfg, scan_id)
    state = store.initial_state(cfg, scan_id, ws)
    state["status"] = "interrupted"
    store.save_state(ws, state)
    # Seed a completed nmap_tcp artifact from the committed sample.
    os.makedirs(os.path.join(ws, "nmap"))
    shutil.copyfile(s("nmap_tcp.xml"), os.path.join(ws, "nmap", "tcp.xml"))

    assert engine.resume(scan_id) == scan_id
    engine._queue.join()                 # wait for the background worker

    final = store.load_state(ws)
    assert final["status"] == "done"
    assert "resume" not in final         # the one-shot flag was consumed
    assert "nmap_tcp" not in final["modules"]   # skipped: never executed/recorded
    assert any("nmap_tcp already complete" in ln for ln in final["log"])
    assert final["inventory"]["services"]       # inventory built from seeded XML
    assert os.path.isfile(os.path.join(ws, "report.html"))

    assert engine.resume("unknown-id") is None


# ---- timeouts (only the initial port scans are bounded) ---------------------

def test_run_spec_untimed_runs_to_completion(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    # timeout=None must not arm a watchdog; the command runs to completion.
    spec = CommandSpec("slow", ["sh", "-c", "sleep 0.3; echo done"])
    res = runner.run_spec(spec, str(tmp_path), timeout=None)
    assert res["status"] == "ok" and res["returncode"] == 0


def test_run_spec_timeout_still_kills(tmp_path):
    from pentest import runner
    from pentest.commands import CommandSpec
    # A positive timeout is still honoured (port scans rely on this).
    spec = CommandSpec("hang", ["sh", "-c", "sleep 3"])
    res = runner.run_spec(spec, str(tmp_path), timeout=1)
    assert res["status"] == "timeout"


def test_engine_timeout_only_for_port_scans():
    from pentest.engine import ScanEngine, PORT_SCAN_MODULES
    eng = ScanEngine()
    cfg = ScanConfig.defaults()
    cfg.module_timeout = 900
    # Only the initial nmap port scans are time-bounded.
    assert eng._timeout_for(cfg, "nmap_tcp") == 900
    assert eng._timeout_for(cfg, "nmap_udp") == 900
    # Everything else (incl. vuln scripts, httpx, nuclei, searchsploit) is untimed.
    for mid in ("nmap_vuln", "httpx", "nuclei", "searchsploit", "sslscan"):
        assert eng._timeout_for(cfg, mid) is None
    assert PORT_SCAN_MODULES == {"nmap_tcp", "nmap_udp"}


def test_engine_timeout_default_untimed():
    """By default (module_timeout == 0) nothing is bounded — not even the port
    scans. A timeout is only applied when the user opts in to a positive value."""
    from pentest.engine import ScanEngine
    eng = ScanEngine()
    cfg = ScanConfig.defaults()          # module_timeout defaults to 0
    assert cfg.module_timeout == 0
    # Port scans are untimed unless the user sets a positive timeout.
    assert eng._timeout_for(cfg, "nmap_tcp") is None
    assert eng._timeout_for(cfg, "nmap_udp") is None
    # Opting in (positive value) bounds them again.
    cfg.module_timeout = 900
    assert eng._timeout_for(cfg, "nmap_tcp") == 900


def test_nmap_vuln_runs_async_and_bounded(tmp_path, monkeypatch):
    """nmap_vuln must run off the main thread (so it can't block the pipeline)
    AND be bounded by the configured timeout (so it can't hang forever)."""
    import threading
    from pentest import engine as eng_mod
    from pentest.engine import ScanEngine
    from pentest.store import Store

    calls = []

    def fake_run_specs(specs, ws, timeout=None, on_output=None, resume=False):
        labels = [sp.label for sp in specs]
        calls.append({"labels": labels, "timeout": timeout,
                      "thread": threading.current_thread().name})
        return [{"label": lb, "command": "x", "status": "ok",
                 "duration": 0.1, "error": "", "log": ""} for lb in labels]

    # Run without real tools: stub execution and force availability.
    monkeypatch.setattr(eng_mod, "run_specs", fake_run_specs)
    monkeypatch.setattr(eng_mod.tools.Module, "available", lambda self: True)

    store = Store(base_dir=str(tmp_path))
    engine = ScanEngine(store)
    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    cfg.module_timeout = 600
    for mid in list(cfg.modules):
        cfg.modules[mid]["enabled"] = mid in ("nmap_tcp", "nmap_vuln")

    ws, state = engine.run_sync(cfg)

    assert state["status"] == "done"
    assert "nmap_vuln" in state["modules"]          # joined + recorded

    vuln_calls = [c for c in calls if "nmap_vuln" in c["labels"]]
    tcp_calls = [c for c in calls if "nmap_tcp" in c["labels"]]
    assert vuln_calls and tcp_calls
    # Bounded by the configured timeout (the regression left it untimed/None).
    assert all(c["timeout"] == 600 for c in vuln_calls)
    # Ran asynchronously on the background executor thread, while the port scan
    # stayed inline on the calling thread.
    assert all(c["thread"].startswith("nmap-vuln") for c in vuln_calls)
    assert not any(c["thread"].startswith("nmap-vuln") for c in tcp_calls)


def test_nmap_vuln_default_untimed(tmp_path, monkeypatch):
    """With the default module_timeout (0) the background nmap_vuln scan runs
    untimed (timeout=None) — the user must opt in to bound it."""
    import threading
    from pentest import engine as eng_mod
    from pentest.engine import ScanEngine
    from pentest.store import Store

    calls = []

    def fake_run_specs(specs, ws, timeout=None, on_output=None, resume=False):
        labels = [sp.label for sp in specs]
        calls.append({"labels": labels, "timeout": timeout,
                      "thread": threading.current_thread().name})
        return [{"label": lb, "command": "x", "status": "ok",
                 "duration": 0.1, "error": "", "log": ""} for lb in labels]

    monkeypatch.setattr(eng_mod, "run_specs", fake_run_specs)
    monkeypatch.setattr(eng_mod.tools.Module, "available", lambda self: True)

    store = Store(base_dir=str(tmp_path))
    engine = ScanEngine(store)
    cfg = ScanConfig.defaults()          # module_timeout == 0 (untimed)
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    for mid in list(cfg.modules):
        cfg.modules[mid]["enabled"] = mid in ("nmap_tcp", "nmap_vuln")

    ws, state = engine.run_sync(cfg)
    assert state["status"] == "done"
    vuln_calls = [c for c in calls if "nmap_vuln" in c["labels"]]
    assert vuln_calls and all(c["timeout"] is None for c in vuln_calls)


def test_run_spec_timeout_is_graceful(tmp_path):
    """On timeout the tool gets SIGTERM first (so it can flush partial output),
    not an immediate SIGKILL."""
    from pentest import runner
    from pentest.commands import CommandSpec
    marker = tmp_path / "flushed.txt"
    # Trap SIGTERM, write a marker, then exit; `sleep & wait` makes the trap fire
    # promptly when the signal arrives.
    script = f"trap 'echo flushed > {marker}; exit 0' TERM; sleep 5 & wait"
    spec = CommandSpec("graceful", ["sh", "-c", script])
    res = runner.run_spec(spec, str(tmp_path), timeout=1)
    assert res["status"] == "timeout"
    assert marker.exists()   # SIGTERM let it flush before any force-kill


def test_nmap_parse_recovers_truncated(tmp_path):
    """A killed/timed-out nmap leaves an unclosed XML; completed <host> blocks
    must still be recovered so findings aren't lost."""
    from pentest.parsers import nmap
    full = open(s("nmap_tcp.xml")).read()
    cut = full.index("</host>") + len("</host>")   # keep one complete host, drop the close tag
    truncated = tmp_path / "tcp.xml"
    truncated.write_text(full[:cut])
    inv = nmap.parse_xml(str(truncated))
    assert inv.services                 # recovered, not parsed-as-empty
    assert len(inv.hosts()) == 1


def test_report_lists_nuclei_cves(tmp_path):
    from pentest import report
    from pentest.parsers import nmap, nuclei
    inv = nmap.parse_xml(s("nmap_tcp.xml"))
    ranked = findings.prioritize(nuclei.parse(s("nuclei.jsonl")))
    cfg = ScanConfig.defaults()
    cfg.customer_name = "c"
    state = {"id": "t", "customer": "c", "scan_name": "s", "created_at": 0,
             "modules": {}}
    ctx = report.build_context(str(tmp_path), cfg, state, inv, ranked, [])
    assert "CVE-2021-41773" in [r["cve"] for r in ctx["cves"]]
    assert any("nuclei" in r["sources"] for r in ctx["cves"])
    report.generate(str(tmp_path), cfg, state, inv, ranked, [])
    html = (tmp_path / "report.html").read_text()
    assert "Known CVEs" in html and "CVE-2021-41773" in html
