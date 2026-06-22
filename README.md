# recon-runner

A self-hosted web app that drives an **external network penetration test** from a
single, per-scan configurable frontend. Upload a host file (one IP/FQDN per line),
and the backend runs an NMAP discovery sweep (full TCP + top-1000 UDP), then fans
out service-appropriate tooling and produces a self-contained HTML report with
open services, software versions with known public exploits, outdated software,
and a prioritized findings list.

> **Authorized testing only.** Only scan hosts you have explicit, written
> permission to test. The app requires an authorization acknowledgement before
> every scan.

## How it works

```
Config page ─▶ Phase 0: dnsx (resolve/validate)
            ─▶ Phase 1: nmap full TCP + top-1000 UDP (+ vulners NSE)
            ─▶ Phase 2: service-driven modules (gated by what nmap found open)
            ─▶ Phase 3: correlate + prioritize + outdated-software
            ─▶ Phase 4: self-contained HTML report
```

Every active test is **gated on the nmap results** — a module only runs against a
host/port that the TCP/UDP scan found open. The only non-nmap-gated modules are
subdomain enumeration and passive URL recon, which are **off by default**.

All per-tool output is written under `results_<CUSTOMERNAME>/<scan-id>/`, including
a `logs/` directory that captures every module's stdout+stderr.

## Quick start (development, macOS or Linux)

```bash
cd recon-runner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # serves http://127.0.0.1:5000
```

On **Kali Linux** (the intended runtime), run the setup script to install
*everything* in one shot — system packages, the full scanning toolset (apt + Go
tools), `shcheck.py`, nuclei templates, and the Python virtualenv:

```bash
./setup.sh            # Kali Linux; uses sudo for system + tool installs
```

On macOS (or any box without the scanning tools installed) the UI and report can
still be exercised via **Demo mode** (button on the home page), which renders a
full report from the bundled sample tool outputs in `samples/`.

## CLI (v1.1)

A headless alternative to the web app that runs the **same** engine and produces the
same `results_<customer>/<scan-id>/report.html`. It needs only Python + Jinja2
(Flask is not required).

```bash
# From a host file (runs nmap discovery, then the inventory-gated modules):
python recon_cli.py --customer acme --hosts scope.txt --authorize

# From an existing nmap XML (skips discovery; runs the gated modules on it):
python recon_cli.py --customer acme --nmap-xml acme_tcp.xml --authorize

# Preview the exact commands without running anything:
python recon_cli.py --customer acme --hosts scope.txt --dry-run

# Inspect installed tools / available modules:
python recon_cli.py --list-tools
python recon_cli.py --list-modules

# Render a report from bundled samples (no tools needed) and open it:
python recon_cli.py --customer demo --demo --open
```

Useful flags: `--enable/--disable/--only <ids>`, `--no-root` (nmap `-sT`),
`--rate-limit/--timeout/--concurrency`, `--set nuclei.severities=high,critical`,
and `--confirm-bruteforce`. `--authorize` is required for real scans.

## Running real scans (Kali Linux)

Real scans shell out to external CLI tools. The config page shows a green/red
availability badge per tool (and the exact command that will run). Install the
toolset on Kali:

```bash
sudo apt update && sudo apt install -y \
  nmap sslscan sslyze whatweb nikto testssl.sh wpscan \
  snmp onesixtyone ike-scan swaks smtp-user-enum \
  seclists hydra medusa ncrack exploitdb

# ProjectDiscovery + others (Go tooling) — install per upstream docs:
#   dnsx, httpx, katana, nuclei, subfinder, gau, waybackurls, gowitness, ffuf, feroxbuster, amass

# shcheck.py and ssh-audit are available via apt/pip depending on your Kali release.
nuclei -update-templates    # first run downloads templates
```

Many tools require **root** for raw scans (nmap `-sS`, UDP). Run accordingly, or
toggle the "running as root" option off to use nmap `-sT` connect scans.

## Managing scans (delete & resume)

From the **scans overview** page you can:

- **Delete** a scan and all of its data (per-tool artifacts, logs, report). A
  confirmation is required; deletion only ever removes that scan's own
  `results_<customer>/<scan-id>/` directory.
- **Resume** a scan that was interrupted (e.g. the server was restarted mid-run)
  or that ended in error. Resume is **idempotent**: completed steps are detected
  by their existing output (discovery artifacts, finished per-service tools) and
  skipped, so only the unfinished work runs.

On startup the app reconciles state: any scan still marked `running`/`queued`
from a previous process is flagged `interrupted` so it can be resumed.

## Deployment (production)

`python app.py` starts Flask's **development** server — fine for local use. For a
persistent install, run the app under a production WSGI server. Two properties of
the app shape how it must be deployed:

- **Single process, multiple threads.** The scan engine uses an in-process
  background worker and an in-memory queue, so the app must run as **one worker
  process**. Use threads for request concurrency — never multiple worker
  processes, since a second process would have its own queue and never see scans
  submitted to the first.
- **No built-in authentication.** The app shells out to real scanning tools and
  must never be exposed to an untrusted network. Bind it to localhost and/or put
  it behind an authenticating reverse proxy on a trusted management network.

**1. Install a WSGI server** (into the same virtualenv):

```bash
source .venv/bin/activate
pip install gunicorn          # Linux; or `pip install waitress` (cross-platform)
```

**2. Set a real secret key** (signs Flask session/flash cookies):

```bash
export RECON_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

`RECON_HOST` / `RECON_PORT` (default `127.0.0.1:5000`) and `RECON_DEBUG` only
affect the built-in dev server; under gunicorn/waitress you set the bind address
on the command line and leave debug off.

**3. Serve it** (single worker, threaded):

```bash
# gunicorn: --workers 1 is required; --timeout 0 lets long scans run
# (only the initial nmap port scan is time-bounded; other tools run untimed).
gunicorn --workers 1 --threads 8 --timeout 0 --bind 127.0.0.1:5000 app:app

# waitress is single-process by design, so it satisfies the constraint too:
waitress-serve --threads=8 --listen=127.0.0.1:5000 app:app
```

**4. Run it as a service** (systemd, e.g. on Kali):

```ini
# /etc/systemd/system/recon-runner.service
[Unit]
Description=recon-runner
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/recon-runner
Environment=RECON_SECRET=replace-with-a-random-value
ExecStart=/opt/recon-runner/.venv/bin/gunicorn --workers 1 --threads 8 --timeout 0 --bind 127.0.0.1:5000 app:app
Restart=on-failure
# nmap -sS/UDP need root; if you run as root, keep the bind on localhost.
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recon-runner
sudo journalctl -u recon-runner -f
```

Restarting the service is safe: in-flight scans are flagged `interrupted` on the
next startup and can be resumed from the overview page (see *Managing scans*).

**TLS & access control.** Because the app has no authentication, anything beyond
localhost should sit behind a reverse proxy (nginx/Caddy) that terminates TLS and
enforces auth (HTTP basic, mTLS, or SSO), with access restricted to a management
network.

**Results & retention.** Scan output accumulates under `results_<customer>/`
(gitignored). Prune or back it up per your retention policy; individual scans can
be removed from the overview page.

## Tests

```bash
pip install pytest
pytest -q
```

Tests run anywhere (no scanning tools required) — they exercise the parsers
against the committed sample outputs in `samples/`.

## Project structure

```text
recon-runner/
├── app.py                      # Flask web app (routes; background-queue scans)
├── recon_cli.py                # v1.1 CLI entry point (alternative to the web app)
├── requirements.txt            # Flask + Jinja2 (the CLI needs only Jinja2)
├── README.md
├── .gitignore                  # ignores results_*/, venvs, caches
├── pentest/                    # core package — shared by the web app and the CLI
│   ├── __init__.py
│   ├── config.py               # ScanConfig: targets, customer, options, report_theme, validation
│   ├── tools.py                # module/tool registry, option schema, availability, severities
│   ├── commands.py             # command builder (config preview == executed command)
│   ├── runner.py               # subprocess exec: timeout, capture, tee to <ws>/logs/
│   ├── engine.py               # phase pipeline; background submit() + synchronous run_sync()
│   ├── store.py                # per-customer persistence: results_<customer>/<scan-id>/
│   ├── findings.py             # Finding model, dedup/merge, prioritization scoring
│   ├── report.py               # build context + render report.html (dark/light)
│   ├── cli.py                  # argparse CLI: --hosts|--nmap-xml, --dry-run, --list-*, --demo
│   └── parsers/                # tolerant tool-output parsers -> Findings / inventory
│       ├── __init__.py
│       ├── util.py             # shared JSON/JSONL readers
│       ├── nmap.py             # nmap XML -> Service inventory + vulners CVEs
│       ├── httpx.py            # live web services + tech
│       ├── dnsx.py             # DNS resolution map
│       ├── nuclei.py           # templated findings (CVEs / exposures)
│       ├── sslscan.py          # TLS protocols / ciphers / cert / heartbleed
│       ├── sslyze.py           # TLS JSON cross-check
│       ├── shcheck.py          # missing HTTP security headers
│       ├── whatweb.py          # tech + version disclosure (outdated)
│       ├── gowitness.py        # screenshot entries
│       ├── searchsploit.py     # public Exploit-DB matches
│       ├── sshaudit.py          # SSH CVEs / weak algorithms
│       ├── smb.py               # enum4linux-ng + smbmap: shares / null sessions
│       ├── dnsrecon.py          # DNS records + zone transfer (AXFR)
│       └── generic.py           # SNMP / IKE / SMTP heuristics
├── templates/                  # Jinja2 templates
│   ├── base.html               # shared layout (top bar, flashes)
│   ├── index.html              # scan list + demo button
│   ├── config.html             # per-scan config form (cards, live command preview)
│   ├── status.html             # live status (polls the JSON API)
│   └── report.html             # self-contained report (dark hacker / light printable)
├── static/
│   ├── css/styles.css          # hacker dark theme (web UI)
│   └── js/app.js               # command preview + status polling
├── samples/                    # sample tool outputs (parser tests + demo mode)
│   ├── nmap_tcp.xml  nmap_udp.xml  httpx.jsonl  nuclei.jsonl
│   ├── sslscan_example.xml  whatweb_example.json  shcheck_example.json
│   ├── searchsploit.json  sshaudit_example.json  gowitness.jsonl  snmp_onesixtyone.txt
│   ├── enum4linux_example.json  smbmap_example.txt  dnsrecon_example.json  dnsrecon_example.txt
│   └── screens/                # demo screenshots referenced by gowitness.jsonl
├── tests/                      # pytest — run anywhere, no scanning tools required
│   ├── test_recon.py           # parsers, prioritization, report, theme, delete/resume
│   └── test_cli.py             # CLI: dry-run, list-*, nmap-xml ingestion, theme flag
├── docs/                       # theme preview screenshots
│   ├── config_preview.png  config_preview_dark.png
│   └── report_dark.png  report_light.png
└── results_<CUSTOMER>/         # scan output (gitignored): <scan-id>/ holds per-tool
                                #   artifacts, logs/, state.json, config.json, report.html
```

Data flow: `config.py` (ScanConfig) -> `engine.py` (phases) -> `commands.py` +
`runner.py` (execute) -> `parsers/` -> `findings.py` (prioritize) -> `report.py`.
The **web app** (`app.py`) and **CLI** (`recon_cli.py`/`pentest/cli.py`) are thin
front-ends over the same `pentest/` core.
