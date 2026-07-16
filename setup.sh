#!/usr/bin/env bash
#
# recon-runner setup  (Kali Linux)
# --------------------------------
# Installs EVERYTHING required to run real scans, in one shot:
#   1. system packages   (python3-venv/pip, git, curl, golang, chromium, ...)
#   2. scanning toolset   via apt (nmap, sslscan, sslyze, whatweb, nikto, ...)
#   3. Go / ProjectDiscovery tools via `go install` (symlinked into /usr/local/bin)
#   4. shcheck.py         (apt, or from source)
#   5. nuclei templates
#   6. Python virtualenv  (.venv) with Flask + Jinja2 + pytest
#
# Usage (from the project root):
#   ./setup.sh            # uses sudo for system/tool installs (or run as root)
#
# Targets Kali Linux / Debian (apt). Best-effort: a failing package warns and
# the script keeps going, then prints a tool-availability summary at the end.
#
set -uo pipefail   # intentionally NOT -e: keep installing on individual failures

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_g(){ printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_y(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_r(){ printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }

case "${1:-}" in -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0;; esac

# This script targets Kali/Debian.
if ! command -v apt-get >/dev/null 2>&1; then
  c_r "setup.sh targets Kali Linux (apt-get not found). Aborting."
  exit 1
fi

# Use sudo for system installs unless already root.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
if [ -n "$SUDO" ] && ! command -v sudo >/dev/null 2>&1; then
  c_r "Not running as root and 'sudo' is unavailable. Re-run as root."; exit 1
fi
export DEBIAN_FRONTEND=noninteractive

apt_install(){
  for p in "$@"; do
    if $SUDO apt-get install -y "$p" >/dev/null 2>&1; then c_g "apt: $p"
    else c_y "apt: $p failed (package name may differ on your release)"; fi
  done
}

# --- 1. system prerequisites ------------------------------------------------
c_g "apt-get update"
$SUDO apt-get update -y || c_y "apt-get update failed; continuing"
c_g "Installing system prerequisites"
apt_install python3 python3-venv python3-pip git curl wget ca-certificates \
            golang-go chromium

# --- 2. scanning toolset (apt) ----------------------------------------------
c_g "Installing scanning tools via apt"
apt_install nmap sslscan sslyze whatweb nikto testssl.sh wpscan snmp onesixtyone \
            ike-scan swaks smtp-user-enum seclists hydra medusa ncrack exploitdb \
            dnsutils ssh-audit ffuf feroxbuster amass enum4linux-ng smbmap dnsrecon

# --- 3. shcheck.py ----------------------------------------------------------
if command -v shcheck.py >/dev/null 2>&1; then
  c_g "shcheck.py present"
else
  apt_install shcheck
  if ! command -v shcheck.py >/dev/null 2>&1 && command -v shcheck >/dev/null 2>&1; then
    $SUDO ln -sf "$(command -v shcheck)" /usr/local/bin/shcheck.py && c_g "linked shcheck -> shcheck.py"
  fi
  if ! command -v shcheck.py >/dev/null 2>&1; then
    c_g "Installing shcheck from source -> /opt/shcheck"
    $SUDO rm -rf /opt/shcheck
    if $SUDO git clone --depth 1 https://github.com/santiko/SHCheck.git /opt/shcheck >/dev/null 2>&1; then
      $SUDO chmod +x /opt/shcheck/shcheck.py
      $SUDO ln -sf /opt/shcheck/shcheck.py /usr/local/bin/shcheck.py
      c_g "shcheck.py installed"
    else
      c_y "shcheck install failed (the shcheck module will be skipped at scan time)"
    fi
  fi
fi

# --- 4. Go / ProjectDiscovery tools -----------------------------------------
# httpx (>= Go 1.25) and gowitness v3 (>= Go 1.23.1) need a recent Go. Kali's
# apt golang-go can lag, which silently breaks `go install ...@latest` — the
# install fails, setup.sh used to warn and continue, and the user never noticed
# the missing tool until a scan came back with blank report sections. Gate on
# Go >= 1.25 and pin the known-problematic tools to verified upstream versions
# (httpx v1.10.0, gowitness 3.1.1) so an install is reproducible, not broken by
# a future @latest needing a newer Go. The rest track @latest (guarded by the
# gate); bump the pins when you refresh this script.
if command -v go >/dev/null 2>&1; then
  GOBIN_DIR="$(go env GOPATH)/bin"
  go_ver=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
  go_ok=1
  if [ -n "$go_ver" ]; then
    go_major=$(echo "$go_ver" | cut -d. -f1)
    go_minor=$(echo "$go_ver" | cut -d. -f2)
    if [ "$go_major" -lt 1 ] || { [ "$go_major" -eq 1 ] && [ "$go_minor" -lt 25 ]; }; then
      go_ok=0
    fi
  fi
  if [ "$go_ok" -ne 1 ]; then
    c_r "Go $go_ver is older than 1.25 — httpx/gowitness need >= 1.25. Skipping Go tool installs."
    c_r "Upgrade Go: https://go.dev/doc/install (apt golang-go may lag; use the official tarball)."
  else
    c_g "Installing Go tools into $GOBIN_DIR (symlinked into /usr/local/bin)"
    go_install(){  # name  module@version
      local name="$1" mod="$2"
      if command -v "$name" >/dev/null 2>&1; then c_g "go: $name present"; return; fi
      if GO111MODULE=on go install "$mod" >/dev/null 2>&1 && [ -x "$GOBIN_DIR/$name" ]; then
        $SUDO ln -sf "$GOBIN_DIR/$name" "/usr/local/bin/$name"
        c_g "go: $name"
      else
        c_y "go install failed: $name"
      fi
    }
    go_install dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go_install httpx       github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0
    go_install katana      github.com/projectdiscovery/katana/cmd/katana@latest
    go_install nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go_install subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go_install gau         github.com/lc/gau/v2/cmd/gau@latest
    go_install waybackurls github.com/tomnomnom/waybackurls@latest
    go_install gowitness   github.com/sensepost/gowitness@3.1.1
  fi
else
  c_y "go unavailable; skipped Go tools (dnsx httpx katana nuclei subfinder gau waybackurls gowitness)."
fi

# --- 5. nuclei templates ----------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
  c_g "Updating nuclei templates"
  nuclei -update-templates >/dev/null 2>&1 || c_y "nuclei template update failed"
fi

# --- 6. Python virtualenv + app deps ----------------------------------------
# Delegated to ./run.sh so there is one source of truth for the venv bootstrap.
c_g "Creating Python virtualenv (.venv) + installing Flask/Jinja2/pytest"
if ./run.sh install >/dev/null 2>&1; then
  .venv/bin/python -m pip install --quiet pytest && c_g "Python environment ready (.venv)"
else
  c_r "Python virtualenv setup failed"
fi

# --- 7. availability summary + default-ON gate ------------------------------
setup_incomplete=0
echo
c_g "Tool availability:"
.venv/bin/python recon_cli.py --list-tools 2>/dev/null || c_y "could not run --list-tools"

# Loud default-ON gate: a missing default-ON tool silently blanks report
# sections, so fail the setup (non-zero) with an unmissable block if any are
# missing after all installs.
echo
if .venv/bin/python recon_cli.py --check-tools >/tmp/recon-check.out 2>&1; then
  c_g "All default-ON tools are installed."
else
  setup_incomplete=1
  c_r "================ MISSING DEFAULT-ON TOOLS ================"
  sed 's/^/  /' /tmp/recon-check.out
  c_r "========================================================="
  c_r "Setup is incomplete: the tools above are not in PATH. Their report"
  c_r "sections will be empty or a fallback. Re-run setup after upgrading Go"
  c_r "(https://go.dev/doc/install) or install them manually."
  c_r "========================================================="
fi

cat <<'EOF'

Setup complete. Next steps:
  ./run.sh                 # web UI  -> http://127.0.0.1:5000  (root for -sS/UDP)
  ./run.sh demo            # render a sample report (no tools needed)
  ./run.sh test            # run the pytest suite
  ./run.sh cli -- --list-tools    # see which scanning tools were found
  ./run.sh cli -- --check-tools   # verify no default-ON tools are missing
EOF

exit $setup_incomplete
