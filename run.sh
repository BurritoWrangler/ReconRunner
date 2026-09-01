#!/usr/bin/env bash
#
# recon-runner — one-command install & run (macOS / Linux)
# ---------------------------------------------------------
# Bootstraps the Python virtualenv on first use (then just launches), so you
# never have to manually create/activate a venv or pip-install.
#
#   ./run.sh              launch the web UI  -> http://127.0.0.1:5000
#   ./run.sh demo         render a demo report from bundled samples (no tools)
#   ./run.sh test         run the pytest suite
#   ./run.sh cli -- ...   pass-through to recon_cli.py  (e.g. --list-tools)
#   ./run.sh install      (re)create .venv + install deps, then stop
#   ./run.sh setup        Kali Linux: install ALL scanning tools (runs setup.sh)
#
# The web UI uses Flask's dev server (fine for local use). For a persistent /
# production install see the "Deployment" section of README.md (gunicorn +
# systemd). Env vars: RECON_HOST, RECON_PORT, RECON_DEBUG (e.g.
# RECON_PORT=8000 ./run.sh).
#
set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
PY="$VENV/bin/python"
REQ="requirements.txt"

c_g(){ printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_y(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_r(){ printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

ensure_venv() {
  # Already bootstrapped and importable? Skip the work (fast no-op on reruns).
  if [ -x "$PY" ] && "$PY" -c 'import flask, jinja2' >/dev/null 2>&1; then
    return
  fi
  command -v python3 >/dev/null 2>&1 || { c_r "python3 not found. Install Python 3 first."; exit 1; }
  # A .venv copied between machines/OSes (e.g. a macOS venv moved onto Kali) has
  # interpreter symlinks pointing at paths that don't exist here — the venv is
  # unusable and its dangling/chained symlinks can trip file scanners
  # ("Dangerous link via another link"). If a .venv exists but its interpreter
  # can't run, it's stale: remove it so we rebuild cleanly for THIS machine.
  if [ -d "$VENV" ]; then
    if [ ! -x "$PY" ] || ! "$PY" -c 'import sys' >/dev/null 2>&1; then
      c_y "Existing $VENV is broken or from another machine/OS — recreating it."
      rm -rf "$VENV"
    fi
  fi
  c_g "Bootstrapping Python virtualenv ($VENV) + app deps (one-time)"
  python3 -m venv "$VENV"
  "$PY" -m pip install --quiet --upgrade pip
  "$PY" -m pip install --quiet -r "$REQ" || { c_r "pip install failed"; exit 1; }
  c_g "Python environment ready ($VENV)"
}

# Drop the subcommand from the front of $@ (if any) so the rest can be forwarded.
cmd="${1:-}"
if [ $# -gt 0 ]; then shift; fi
# Be forgiving: strip a single leading "--" so both `./run.sh cli --list-tools`
# and `./run.sh cli -- --list-tools` work (a bare "--" would confuse argparse).
if [ "${1:-}" = "--" ]; then shift; fi

case "$cmd" in
  ""|run|web|serve)
    ensure_venv
    if [ "$(id -u)" -ne 0 ]; then
      c_y "Not root: nmap will use -sT connect scans (the UI's \"run as root\" toggle is off)."
    fi
    c_g "Starting web UI -> http://${RECON_HOST:-127.0.0.1}:${RECON_PORT:-5000}"
    exec "$PY" app.py "$@"
    ;;
  demo)
    ensure_venv
    exec "$PY" recon_cli.py --demo --open "$@"
    ;;
  test)
    ensure_venv
    "$PY" -c 'import pytest' >/dev/null 2>&1 || "$PY" -m pip install --quiet pytest
    exec "$PY" -m pytest -q "$@"
    ;;
  cli)
    ensure_venv
    exec "$PY" recon_cli.py "$@"
    ;;
  install)
    ensure_venv
    c_g "Ready. Next: ./run.sh        (web UI)   or   ./run.sh demo   (sample report)"
    ;;
  setup)
    exec ./setup.sh "$@"
    ;;
  -h|--help|help)
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    c_r "Unknown command: '$cmd'  (try: ./run.sh --help)"
    exit 2
    ;;
esac
