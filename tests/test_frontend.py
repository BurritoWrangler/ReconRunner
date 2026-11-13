"""Run the DOM-fixture suite with Node or macOS JavaScriptCore; no network."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_frontend_behavior():
    root = Path(__file__).resolve().parents[1]
    source = root / "static/js/app.js"
    harness = root / "tests/js/p2.test.js"
    if shutil.which("node"):
        script = (
            "const fs=require('fs');"
            f"const source=fs.readFileSync({json.dumps(str(source))},'utf8');"
            f"const harness=fs.readFileSync({json.dumps(str(harness))},'utf8');"
            "console.log(new Function('source',harness)(source));")
        command = ["node", "-e", script]
    elif shutil.which("osascript"):
        script = (
            'ObjC.import("Foundation");'
            "function read(p){return $.NSString.stringWithContentsOfFileEncodingError("
            "p,$.NSUTF8StringEncoding,null).js;}"
            f"var source=read({json.dumps(str(source))});"
            f"var harness=read({json.dumps(str(harness))});"
            "new Function('source',harness)(source);")
        command = ["osascript", "-l", "JavaScript", "-e", script]
    else:
        pytest.skip("Frontend behavior tests require Node or macOS JavaScriptCore.")
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "14 frontend behavior checks passed" in result.stdout
