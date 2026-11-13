# recon-runner

A self-hosted web app that drives an **external network penetration test** from a
single, per-scan configurable frontend. Upload a host file (one IP/FQDN per line),
and the backend runs an NMAP discovery sweep (full TCP + configurable UDP), then
fans out service-appropriate tooling and produces a self-contained, **actionable**
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
            ─▶ Phase 1: nmap full TCP + configurable UDP (+ vulners + high-impact NSE:
              EternalBlue/BlueKeep/Cisco Smart Install/ftp-anon)
            ─▶ Phase 2: service-driven modules (gated by what nmap found open)
            ─▶ Phase 3: correlate + prioritize + outdated-software
            ─▶ Phase 4: self-contained HTML report (per-finding proofs + coverage notes)
```

Every active test is **gated on the nmap results** — a module only runs against a
host/port that the TCP/UDP scan found open. The only non-nmap-gated modules are
subdomain enumeration and passive URL recon, which are **off by default**.

All per-tool output is written under `results_<CUSTOMERNAME>/<scan-id>/`.
Task-specific stdout/stderr and artifacts are retained under `attempts/`;
`logs/console.log` provides the combined live console.

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

> **Moved the folder between machines/OSes?** `.venv` is machine-specific: a
> virtualenv created on macOS points at macOS Python paths and is unusable on
> Linux (its dangling symlinks can also trip file scanners with errors like
> *"Dangerous link via another link"*). `run.sh` now detects a stale/foreign
> `.venv` and rebuilds it automatically. If anything else stumbles on it first,
> just delete it — it's disposable and gitignored — and re-run:
>
> ```bash
> rm -rf .venv && ./run.sh
> ```
>
> Better yet, transfer the code with `git clone` (or `git archive`) rather than
> copying the working folder, so `.venv/`, `results_*/` and caches never come
> along.

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

Use `--automatic wpscan` for fingerprint-triggered WordPress checks instead of
always enabling WPScan. `--disable wpscan` overrides automatic mode. The web UI
also makes enabled and automatic mutually exclusive. Automatic checks are
restricted to matching web-service origins already in the nmap inventory.

Target files accept bare IP addresses/hostnames, CIDRs, and IPv4 ranges—not URLs
or `host:port` expressions. Equivalent hostnames/IP spellings are deduplicated,
and rejected lines are reported rather than silently omitted. An uploaded file
always takes precedence over the textarea, including when the file is empty.
Invalid module names, numeric values, option selections, or argument quoting
produce validation errors. Dry runs validate settings but never construct a scan
engine; their command options match execution's root and rate-limit behavior.

`--timeout N` **opts in** to bounding the nmap port + vuln NSE scans (default:
untimed — those scans run as long as they need; set a positive N to kill them
after N seconds). Other tools always run untimed.

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

### Nmap scan performance

nmap is single-threaded per process, so speed comes from probe parallelism,
rate, and scope — not threads. The engine already runs TCP and UDP as two
parallel processes and the vuln NSE scan in the background.

Per-scan knobs (config page or `--set nmap_tcp.<key>=<value>`):

- `timing` — already `T4` (nmap's "aggressive" template). `T5` is faster but
  nmap's own docs call it "insane": it can miss open ports on lossy links.
- `min_rate` — packets/second floor (`--min-rate`). The strongest raw-speed
  knob; on WAN paths it can drop replies and trigger IDS.
- `min_parallelism` — probes kept in flight (`--min-parallelism`), the closest
  thing nmap has to threads.
- `max_retries` — nmap retries up to 10 times by default; `1`–`2` greatly
  speeds up lossy or filtered hosts at a small accuracy cost.
- `version_intensity` — `2` approximates `--version-light`, cutting `-sV`
  follow-up probes (nmap's default intensity is 7).
- `all_ports` — untick for nmap's top-1,000 (~65× fewer probes). Full-range is
  the external-pentest standard; treat this as a per-engagement choice.
- `shards` — split the host list across N concurrent nmap processes (default
  1). Since nmap is single-process, this is the only true multi-core speedup
  for multi-host scopes. Shard XMLs are merged into the canonical
  `nmap/tcp.xml`, a configured `--min-rate` is divided across shards so the
  aggregate budget holds, and each shard is its own task — so resume skips
  finished shards only. Changing the shard count invalidates per-shard
  checkpoints.

UDP defaults favor speed: `top_ports` 250 (raise to 1,000 for broader
coverage) and version detection off — service names still come from the port
scan, and UDP `-sV` retransmits are the slowest part of discovery. Enable
`nmap_udp.version_detection` for UDP product/version probing.

A two-phase sweep (fast top-1,000 first, full range in the background) was
considered and deliberately deferred: services found only by the full-range
pass would otherwise miss Phase-2 gating, which would understate coverage.

## Managing scans (delete & resume)

From the **scans overview** page you can:

- **Delete** a scan and all of its data (per-tool artifacts, logs, report). A
  confirmation is required; deletion only ever removes that scan's own
  `results_<customer>/<scan-id>/` directory.
- **Resume** a scan that was interrupted (e.g. the server was restarted mid-run)
  or that ended in error. Resume reuses only successful steps with a matching,
  versioned checkpoint: effective command, declared input contents, tool identity,
  and output integrity must still match. Valid empty results can be reused;
  truncated, malformed, timed-out, or cancelled output cannot prove completion.
  Old scans without checkpoints require confirmation before uncertain work is rerun.

Queued/running scans cannot be resumed twice or deleted while active. Cancellation
stops pending work and sends TERM to active tool process groups, allowing up to
10 seconds to flush output before KILL. Untimed scans remain the default; the
configured nmap deadline covers TCP, UDP, and background NSE consistently.

Output capture uses fixed-size nonblocking reads. After forced termination, pipe
draining and parent reaping each have a one-second bound. A descendant that
deliberately starts a separate session can escape the tool's process group;
an inherited pipe cannot keep the runner waiting indefinitely, and incomplete
drain/cleanup is recorded for operator review.

Artifact validation also limits memory: XML is checked incrementally, single
JSON documents larger than 16 MiB and JSONL records larger than 1,048,576
characters are retained but marked unverified rather than loaded without bound.
These validation limits do not terminate scans or discard their output; affected
attempts remain partial and cannot supply successful resume checkpoints.

Each task has a stable identity and each execution has a separate attempt under
`attempts/<task-id>/<attempt-id>/`, retaining stdout, stderr, result metadata,
and artifacts. Existing artifact paths remain compatibility views for parsers.
`logs/console.log` appends across resumes. Unknown nonzero exit codes are treated
conservatively as failures, with valid partial findings retained for review.

Execution completion and coverage completeness are separate: `done` does not mean
every tool succeeded. The report and CLI explicitly show incomplete coverage,
including skipped import-mode discovery, output-validation errors, and collection
failures. Partial reports use completed immutable artifacts, not live tool writes.
Automatic WordPress-triggered WPScan now requires its explicit configuration opt-in.

Live status distinguishes execution from coverage. Planned disabled/unavailable
modules stay visible, completed tools await correlation before claiming no
findings, and incomplete coverage has a separate warning. Action availability
comes from the API; polling continues through terminal cleanup, then stops.
Connection failures use a separate message from scan failures, retry with a
backoff, and disable stale action buttons. Missing or inaccessible scans stop
polling. Old report files are not presented as ready during resumed/failed scans.

The status page also shows **active tasks**: every executing command with its
elapsed time, seconds since its last output, captured output volume, PID, and
whether that process is still alive. Output states are `streaming` (<10s since
last output), `quiet` (<2m), and `silent` (≥2m) — reported as data, not verdicts,
because long silences are normal for untimed nmap sweeps. A "process exited"
badge on a lingering attempt means the engine died mid-task: that scan is
flagged interrupted on the next startup and can be resumed, and stale markers
are cleared when the scan restarts.

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

The default suite blocks external scanner execution and notifications and uses
temporary stores. It exercises sample parsers, CLI/web integration, checkpoint
recovery, lifecycle races, report publication failures, and local fixture
subprocesses for streaming/cancellation. It never scans sample targets even if
scanning tools are installed. Real-tool compatibility testing remains a separate,
explicitly authorized activity.

## Releasing

Before release sign-off, run the opt-in integration verification below. The
scanner-free unit/DOM suite does not establish installed-tool compatibility.

### Browser and Kali verification (opt-in)

`RECON_RESULTS_DIR` overrides the results parent for both web and CLI runs.
Existing installations keep the project-root default when it is unset. An
explicit `Store(base_dir=...)` takes precedence. Samples and templates always
come from the source package, not the results directory. Browser fixtures set
this override **before importing the app**, so startup reconciliation never
touches existing scan workspaces.

Install browser-only development dependencies deliberately; neither normal tests
nor verification commands download them automatically:

```bash
.venv/bin/python -m pip install -r requirements-browser.txt
.venv/bin/python -m playwright install chromium
./run.sh test-browser
```

This runs real Chromium against a temporary localhost Flask server. Installed
scanners and notifications remain blocked; lifecycle tests use a controlled
local Python stdout fixture. Checks cover form uploads, effective previews,
preview races, queue ownership, cancel/resume, polling failures, escaped
diagnostics, dark/light presentation, and standalone downloaded reports.
Browser requests outside the fixture origin are blocked. Failed checks save
screenshots and Playwright traces; passing theme checks also save screenshots.

The default suite still needs no browser or scanning tools. To retain a
scanner-free baseline manifest alongside the browser evidence:

```bash
./run.sh test --verification-artifacts verification-artifacts
```

Real-tool checks require an **independently isolated Linux/Kali lab** with
egress blocked, supported tools already installed, and explicit operator
approval. This harness does not provision a VM, install scanners, configure a
firewall, or prove the lab's isolation. The JSON approval fields are operator
attestations. Never approve an ordinary workstation as an isolated lab.

Copy `tests/compat/example.lab.json` to a gitignored file such as
`verification.lab.local.json`, identify the actual lab, and set its approval
and isolation attestations only after the lab is ready. The shipped example
is deliberately unapproved and cannot run. No target addresses, extra command
arguments, passive enumeration, brute-force modules, or remote templates are
accepted by the harness.

Inside the approved lab:

```bash
./run.sh test-kali --lab-config verification.lab.local.json
```

Checks target only dynamically allocated **owned loopback HTTP/TLS fixture
services**. TLS uses a short-lived dummy certificate; private fixture keys stay
in temporary directories, not evidence exports. User home/config/proxy settings
are isolated. The initial allowlist covers nmap TCP **connect** discovery,
httpx, nuclei with owned local templates and Interactsh/updates disabled,
sslscan, and optional gowitness. Raw TCP/UDP and all other modules are rejected
or remain unverified; no root/sudo scan is enabled implicitly.

The harness records executable versions/checksums, commands, exit codes, raw
logs, schema checks, checkpoint reuse, nuclei no-findings output, and httpx
timeout/cancellation behavior. Missing tools are blocked, not compatible.
The suite exits nonzero if any selected tool lacks its complete required
checks—even when pytest itself only reports skips.

Each run creates a unique, gitignored `verification-artifacts/<suite>-.../`
directory. `manifest.json` is the compatibility matrix for **all 28 modules**:
unexecuted modules remain unverified and `reliability_signoff` stays false.
Evidence includes the base commit and source fingerprint for uncommitted
changes, exact browser/tool versions, outcomes, and whether source changed
during the run. Source changes during verification make the run fail.
A dirty-source fingerprint is not a released commit claim.
Use `--verification-artifacts <parent>` to choose another parent directory.
Traces can be inspected with `.venv/bin/python -m playwright show-trace <trace.zip>`.

Current readiness: automated scanner-free and Chromium verification can run
locally; real-tool compatibility remains **unverified until executed in an
approved lab**. Re-run all required suites against a committed release candidate
before reliability sign-off. These checks do not close the separate
authentication, CSRF, secret-redaction, or archive-limit workstreams.

### Packaging a release

Cut a versioned release as a clean, self-contained archive. The golden rule:
**export from git, never zip the working folder.** `zip -r` and `tar` on the live
checkout ignore `.gitignore` and will ship `.venv/` (full of symlinks that break
on extract), `results_*/`, and caches. `git archive` only exports tracked files,
so none of that leaks in.

```bash
REL=v1.9.0

# 1. Pre-flight — green suite + clean tree
./run.sh test            # all tests pass
./run.sh demo            # report renders from bundled samples
git status --short       # clean, or stage only intended changes

# 2. Commit + annotated tag (include Co-Authored-By attribution)
git add -A
git commit -m "<summary>"
git tag -a "$REL" -m "$REL — <one-line summary>"

# 3. Export a clean snapshot into a sibling folder (no .venv / caches / results)
mkdir -p ../"recon-runner-$REL"
git archive "$REL" | tar -x -C ../"recon-runner-$REL"

# 4. VERSION marker (points at the commit the tag resolves to)
printf 'recon-runner\nversion: %s\ncommit:  %s\ntag:     %s\nsource:  git archive %s\n' \
  "$REL" "$(git rev-list -n 1 "$REL")" "$REL" "$REL" \
  > ../"recon-runner-$REL"/VERSION

# 5. Portable archives from the CLEAN export (safe to zip here — no venv inside)
tar -czf ../"recon-runner-$REL".tar.gz -C .. "recon-runner-$REL"
( cd .. && zip -r -q "recon-runner-$REL".zip "recon-runner-$REL" )

# 6. Verify the extracted release runs standalone (bootstraps a fresh .venv)
( cd ../"recon-runner-$REL" && ./run.sh test && ./run.sh demo )

# 7. Publish (if a remote is configured)
git push origin main "$REL"
```

Recipients install from an archive with no special steps — `./run.sh` recreates
the `.venv` on first run:

```bash
unzip recon-runner-v1.9.0.zip && cd recon-runner-v1.9.0
./run.sh demo    # smoke-test (renders a report, no scanning tools needed)
./run.sh         # launch the web UI
```

The release archives themselves are gitignored (`recon-runner-*.zip`,
`recon-runner-*.tar.gz` in `.gitignore`), so they won't be committed by accident.

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
│   ├── archive.py              # safe scan-archive export/import (validated tar.gz)
│   ├── config.py               # ScanConfig: targets, customer, options, report_theme, validation
│   ├── tools.py                # module/tool registry, option schema, availability, severities
│   ├── commands.py             # command builder (config preview == executed command)
│   ├── runner.py               # subprocess exec: timeout, capture, tee to <ws>/logs/
│   ├── engine.py               # phase pipeline; background submit() + synchronous run_sync()
│   ├── execution.py            # artifact contracts, scan-local context, outcome reduction
│   ├── checkpoints.py          # versioned task completion + dependency/artifact integrity
│   ├── lifecycle.py            # synchronized ownership, cancellation, lifecycle conflicts
│   ├── collection.py           # fault-isolated parsing + typed collection results
│   ├── snapshots.py            # immutable completed-artifact snapshots for reports
│   ├── store.py                # per-customer persistence: results_<customer>/<scan-id>/
│   ├── findings.py             # Finding model, dedup/merge, prioritization scoring
│   ├── report.py               # build context + render report.html (dark/light)
│   ├── cli.py                  # argparse CLI: --hosts|--nmap-xml, --dry-run, --list-*, --demo
│   ├── coverage.py             # coverage assurance: missing/failed tools never silently blank a section
│   ├── software.py             # precise version enumeration + searchsploit exploit correlation
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
│       ├── redis.py             # Redis unauthenticated-access check
│       ├── mongodb.py           # MongoDB unauthenticated-access check
│       ├── nikto.py             # web server scan findings
│       ├── testssl.py           # deep TLS findings (Heartbleed / ROBOT / ...)
│       ├── wpscan.py            # WordPress audit findings
│       ├── content.py           # ffuf / feroxbuster content discovery
│       ├── bruteforce.py        # hydra / medusa / ncrack credential results
│       ├── recon.py             # katana / gau / waybackurls / subfinder / amass recon
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
│   ├── redis_unauth.txt  redis_auth.txt  mongodb_unauth.txt  mongodb_auth.txt
│   └── screens/                # demo screenshots referenced by gowitness.jsonl
├── tests/                      # pytest — run anywhere, no scanning tools required
│   ├── test_recon.py           # parsers, prioritization, report, theme, delete/resume
│   ├── test_archive.py         # scan-archive round trip + malicious-archive rejection
│   └── test_cli.py             # CLI: dry-run, list-*, nmap-xml ingestion, theme flag
├── docs/                       # theme preview screenshots
│   ├── config_preview.png  config_preview_dark.png
│   └── report_dark.png  report_light.png
└── results_<CUSTOMER>/         # scan output (gitignored): <scan-id>/ holds per-tool
                                #   artifacts, logs/, state.json, config.json, report.html
```

Data flow: `config.py` (ScanConfig) -> `engine.py` (phases) -> `commands.py` +
`runner.py` (execute) -> `parsers/` -> `findings.py` (prioritize) +
`software.py` (exploit correlation) -> `report.py` (`coverage.py` assurance).
The **web app** (`app.py`) and **CLI** (`recon_cli.py`/`pentest/cli.py`) are thin
front-ends over the same `pentest/` core.
