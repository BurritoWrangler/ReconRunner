# recon-runner

A self-hosted web app that drives an **external network penetration test** from a
single, per-scan configurable frontend. Upload a host file (one IP/FQDN per line),
and the backend runs an NMAP discovery sweep (full TCP + top-1000 UDP), then fans
out service-appropriate tooling and produces a self-contained, **actionable**
HTML report. Each prioritized finding carries a per-tool **proof block** — the
tool name and its raw output snippet — so a pentester can validate and act on
the report directly. The report also includes open services, live web
applications, software versions with known public exploits, outdated software,
known CVEs, and a **coverage notes** callout that surfaces any tool that failed
or timed out, so a "clean" result is never trusted blindly. Low-confidence /
heuristic findings are flagged with a confidence percentage and a
"validate before acting" note.

> **Authorized testing only.** Only scan hosts you have explicit, written
> permission to test. The app requires an authorization acknowledgement before
> every scan.

## How it works

```
Config page ─▶ Phase 0: dnsx (resolve/validate)
            ─▶ Phase 1: nmap full TCP + top-1000 UDP (+ vulners + high-impact NSE:
              EternalBlue/BlueKeep/Cisco Smart Install/ftp-anon)
            ─▶ Phase 2: service-driven modules (gated by what nmap found open)
            ─▶ Phase 3: correlate + prioritize + outdated-software
            ─▶ Phase 4: self-contained HTML report (per-finding proofs + coverage notes)
```

Every active test is **gated on the nmap results** — a module only runs against a
host/port that the TCP/UDP scan found open. The only non-nmap-gated modules are
subdomain enumeration and passive URL recon, which are **off by default**.

All per-tool output is written under `results_<CUSTOMERNAME>/<scan-id>/`, including
a `logs/` directory that captures every module's stdout+stderr.

## Report contents

The generated `report.html` is built to be read and acted on as a pentester. In
order, it contains:

- **Executive summary** — severity counts (critical/high/medium/low) and total
  findings.
- **Coverage notes** — any module that errored, timed out, or produced no output,
  with the failing command and error text. If a tool is missing, its section may
  be empty — confirm coverage before trusting a "clean" result.
- **Software with known exploits** — detected software whose *exact version*
  matches a public Exploit-DB entry (version confirmed in the exploit title).
- **Known CVEs** — every CVE surfaced (nuclei, nmap vulners, version
  correlation), with the detecting tool(s) and affected assets.
- **Prioritized findings** — ranked by severity + exploitability. Each row shows
  the finding, assets, score, source tool(s), confidence %, remediation, and
  references. Heuristic / low-confidence findings are badged and carry a
  "validate before acting" warning. Expand the **proof block** under any finding
  to see the exact tool and raw output that produced it.
- **Open services** — host/port/proto/service/product+version/TLS, straight from
  the nmap inventory.
- **Web applications** — live web surface confirmed by httpx
  (URL/status/title/server/tech); each URL is a testing entry point.
- **Outdated / version-flagged software** — detected versions flagged where a
  public exploit or known-vuln match exists.
- **Web screenshots** — gowitness captures of live web apps.
- **Appendix — tools executed** — every command run, its status, duration, and
  error text; full stdout/stderr is saved under `logs/`.

The report is self-contained (inline CSS, base64 screenshots) and renders in any
browser; toggle the **dark hacker / light printable** theme from the config page
or `--theme`.

## Quick start (macOS or Linux)

One command bootstraps a Python virtualenv (first run only) and launches the
web UI:

```bash
./run.sh            # -> http://127.0.0.1:5000  (creates .venv first run)
```

`run.sh` subcommands cover everything you need without manual venv activation:

```bash
./run.sh demo          # render a sample report from bundled data (no scanning tools)
./run.sh test          # run the pytest suite
./run.sh cli -- --list-tools     # see which scanning tools are installed
./run.sh setup         # Kali Linux: install the full scanning toolset (runs setup.sh)
./run.sh --help
```

Run as root (`sudo ./run.sh`) only if you want nmap `-sS`/UDP raw scans; without
root the UI uses nmap `-sT` connect scans. Set `RECON_HOST`/`RECON_PORT`/
`RECON_DEBUG` env vars to override the bind.

On **Kali Linux** (the intended runtime for real scans), run the setup script to
install *everything* in one shot — system packages, the full scanning toolset
(apt + Go tools), `shcheck.py`, nuclei templates, and the Python virtualenv:

```bash
./run.sh setup       # Kali Linux; uses sudo for system + tool installs
```

(That's `setup.sh` under the hood; see its header for details.)

On macOS (or any box without the scanning tools installed) the UI and report can
still be exercised via **Demo mode**: `./run.sh demo` (or the Demo button on the
home page) renders a full report from the bundled sample tool outputs in
`samples/`.

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

# Optional: the Smart Install check uses the third-party cisco-siet NSE script
# (not shipped with nmap). Drop cisco-siet.nse into your nmap scripts dir and
# run `nmap --script-updatedb` to enable it; otherwise nmap skips it with a
# warning and the check is a no-op. EternalBlue/BlueKeep/ftp-anon ship with nmap.
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
# (the nmap port + vuln scans are time-bounded; other tools run untimed).
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
./run.sh test      # bootstraps the venv if needed, runs pytest
```

Tests run anywhere (no scanning tools required) — they exercise the parsers
against the committed sample outputs in `samples/`.

## Project structure

```text
recon-runner/
├── app.py                      # Flask web app (routes; background-queue scans)
├── recon_cli.py                # v1.1 CLI entry point (alternative to the web app)
├── run.sh                      # one-command install & run (bootstraps .venv + launches)
├── setup.sh                    # Kali: install all scanning tools + Python deps
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
│       ├── nmap.py             # nmap XML -> Service inventory + vulners CVEs + curated NSE findings
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
