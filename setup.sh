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
            dnsutils ssh-audit ffuf feroxbuster amass

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
if command -v go >/dev/null 2>&1; then
  GOBIN_DIR="$(go env GOPATH)/bin"
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
  go_install httpx       github.com/projectdiscovery/httpx/cmd/httpx@latest
  go_install katana      github.com/projectdiscovery/katana/cmd/katana@latest
  go_install nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go_install subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go_install gau         github.com/lc/gau/v2/cmd/gau@latest
  go_install waybackurls github.com/tomnomnom/waybackurls@latest
  go_install gowitness   github.com/sensepost/gowitness@latest
else
  c_y "go unavailable; skipped Go tools (dnsx httpx katana nuclei subfinder gau waybackurls gowitness)."
fi

# --- 5. nuclei templates ----------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
  c_g "Updating nuclei templates"
  nuclei -update-templates >/dev/null 2>&1 || c_y "nuclei template update failed"
fi

# --- 6. Python virtualenv + app deps ----------------------------------------
c_g "Creating Python virtualenv (.venv) + installing Flask/Jinja2/pytest"
if python3 -m venv .venv \
   && .venv/bin/python -m pip install --quiet --upgrade pip \
   && .venv/bin/python -m pip install --quiet -r requirements.txt pytest; then
  c_g "Python environment ready (.venv)"
else
  c_r "Python virtualenv setup failed"
fi

# --- 7. availability summary ------------------------------------------------
echo
c_g "Tool availability:"
.venv/bin/python recon_cli.py --list-tools 2>/dev/null || c_y "could not run --list-tools"

cat <<'EOF'

Setup complete. Next steps:
  source .venv/bin/activate
  sudo .venv/bin/python app.py        # web UI (root needed for -sS / UDP) -> http://127.0.0.1:5000
  # or the CLI:
  sudo .venv/bin/python recon_cli.py --customer acme --hosts scope.txt --authorize
  pytest -q                           # run the test suite
EOF
