"""Local stdout fixture only. No sockets, scanners, or external callbacks."""

import json
from pathlib import Path
import signal
import sys
import time


def stop(*_):
    print("controlled fixture flushing after TERM", file=sys.stderr, flush=True)
    time.sleep(.6)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
print(json.dumps({
    "template-id": "owned-browser-fixture",
    "info": {"name": "Controlled fixture finding", "severity": "high"},
    "matched-at": "http://127.0.0.1/owned-fixture",
}), flush=True)
while not Path(sys.argv[1]).is_file():
    time.sleep(.05)
