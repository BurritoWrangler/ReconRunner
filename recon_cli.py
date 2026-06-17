#!/usr/bin/env python3
"""recon-runner CLI entry point (v1.1) — alternative to the web app.

Usage examples:
    python recon_cli.py --customer acme --hosts scope.txt --authorize
    python recon_cli.py --customer acme --nmap-xml acme_tcp.xml --authorize
    python recon_cli.py --customer demo --demo --open
    python recon_cli.py --list-tools
"""

import sys

from pentest.cli import main

if __name__ == "__main__":
    sys.exit(main())
