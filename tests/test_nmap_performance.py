"""Nmap performance knobs: speed options, UDP defaults, and host sharding."""

import os
from pathlib import Path

import pytest

from pentest import checkpoints, commands, runner
from pentest.parsers import nmap
from pentest.commands import Ctx, build_commands
from pentest.config import ScanConfig
from pentest.engine import ScanEngine
from pentest.store import Store, new_scan_id


def tcp_opts(**overrides):
    opts = ScanConfig.defaults().command_options("nmap_tcp")
    opts.update(overrides)
    return opts


def test_tcp_speed_flags_emitted_only_when_set():
    line = commands.preview("nmap_tcp", tcp_opts())[0]
    for flag in ("--min-parallelism", "--max-retries", "--version-intensity"):
        assert flag not in line
    assert "-p-" in line and "-sV" in line and "-T4" in line  # defaults unchanged

    line = commands.preview("nmap_tcp", tcp_opts(
        min_parallelism=64, max_retries=2, version_intensity=2))[0]
    assert "--min-parallelism 64" in line
    assert "--max-retries 2" in line
    assert "--version-intensity 2" in line


def test_udp_defaults_are_fast():
    cfg = ScanConfig.defaults()
    assert cfg.option("nmap_udp", "top_ports") == 250
    assert cfg.option("nmap_udp", "version_detection") is False
    line = commands.preview("nmap_udp", cfg.command_options("nmap_udp"))[0]
    assert "--top-ports 250" in line and "-sV" not in line

    opts = cfg.command_options("nmap_udp")
    opts.update(top_ports=1000, version_detection=True,
                max_retries=2, min_parallelism=32)
    line = commands.preview("nmap_udp", opts)[0]
    assert "--top-ports 1000" in line and "-sV" in line
    assert "--max-retries 2" in line and "--min-parallelism 32" in line


@pytest.mark.parametrize("key,value,fragment", [
    ("shards", 0, "at least 1"),
    ("shards", 33, "cannot exceed 32"),
    ("min_parallelism", -1, "at least 0"),
    ("min_parallelism", 300, "cannot exceed 256"),
    ("max_retries", 11, "cannot exceed 10"),
    ("version_intensity", 10, "cannot exceed 9"),
])
def test_speed_option_bounds_are_validated(key, value, fragment):
    cfg = ScanConfig.defaults()
    cfg.modules["nmap_tcp"]["options"][key] = value
    errors = cfg.validate()
    assert any(fragment in e for e in errors), errors


def test_zero_means_unset_and_passes_validation():
    cfg = ScanConfig.defaults()
    cfg.customer_name = "c"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    for key in ("min_parallelism", "max_retries", "version_intensity"):
        cfg.modules["nmap_tcp"]["options"][key] = 0
    for key in ("min_parallelism", "max_retries"):
        cfg.modules["nmap_udp"]["options"][key] = 0
    assert cfg.validate() == []


def test_ctx_overrides_build_shard_specs():
    ws = "/tmp/recon-shard-ws"
    ctx = Ctx(ws=ws, targets_file=f"{ws}/shards/tcp_0.txt",
              nmap_tcp_prefix=f"{ws}/nmap/shard_0", task_label="nmap_tcp_s0")
    spec = build_commands("nmap_tcp", tcp_opts(), ctx)[0]
    assert spec.label == "nmap_tcp_s0"
    assert spec.task_key.startswith("nmap_tcp:nmap_tcp_s0")
    assert f"{ws}/nmap/shard_0" in spec.argv
    xml_out = next(a for a in spec.outputs if a.path.endswith(".xml"))
    assert xml_out.path == f"{ws}/nmap/shard_0.xml"
    assert xml_out.required is True
    assert spec.inputs == [f"{ws}/shards/tcp_0.txt"]


def sharded_engine(tmp_path, targets, shards):
    engine = ScanEngine(Store(str(tmp_path)))
    cfg = ScanConfig.defaults()
    cfg.customer_name = "acme"
    cfg.authorized = True
    cfg.targets = targets
    for mid in cfg.modules:
        cfg.modules[mid]["enabled"] = mid == "nmap_tcp"
    cfg.modules["nmap_tcp"]["options"]["shards"] = shards
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    return engine, cfg, ws


def test_sharding_builds_deterministic_specs_and_files(tmp_path):
    engine, cfg, ws = sharded_engine(tmp_path, [f"10.0.0.{i}" for i in range(1, 9)], 3)
    cfg.modules["nmap_tcp"]["options"]["min_rate"] = 900
    specs = engine._nmap_specs(ws, cfg)
    assert [s.label for s in specs] == ["nmap_tcp_s0", "nmap_tcp_s1", "nmap_tcp_s2"]
    contents = []
    for index, spec in enumerate(specs):
        shard_file = Path(ws, "shards", f"tcp_{index}.txt")
        assert shard_file.is_file()
        contents.append(shard_file.read_text().split())
        assert spec.argv[spec.argv.index("-iL") + 1] == str(shard_file)
        assert f"{ws}/nmap/shard_{index}" in spec.argv
        assert "--min-rate 300" in spec.display()  # 900 divided by 3 shards
    assert sorted(sum(contents, [])) == sorted(cfg.targets)
    # Deterministic identity: identical targets rebuild identical tasks.
    again = engine._nmap_specs(ws, cfg)
    assert [checkpoints.task_id(s, ws) for s in again] == \
           [checkpoints.task_id(s, ws) for s in specs]


def test_sharding_disabled_or_small_scope_stays_single(tmp_path):
    engine, cfg, ws = sharded_engine(tmp_path, ["10.0.0.1", "10.0.0.2"], 1)
    specs = engine._nmap_specs(ws, cfg)
    assert len(specs) == 1 and specs[0].label == "nmap_tcp"
    assert not Path(ws, "shards").exists()

    cfg.modules["nmap_tcp"]["options"]["shards"] = 8  # more shards than targets
    specs = engine._nmap_specs(ws, cfg)
    assert len(specs) == 2  # clamped to the target count


def _host_xml(addr):
    return (f'<host><address addr="{addr}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port></ports></host>')


def test_merge_host_xml_combines_and_recovers(tmp_path):
    a = tmp_path / "shard_0.xml"
    a.write_text("<nmaprun>" + _host_xml("10.0.0.1") + "</nmaprun>")
    b = tmp_path / "shard_1.xml"
    # One complete host plus a truncated tail (killed mid-write).
    b.write_text("<nmaprun>" + _host_xml("10.0.0.2") + '<host><address addr="10.0.0.3"')
    dest = tmp_path / "tcp.xml"

    merged = nmap.merge_host_xml([str(a), str(b), str(tmp_path / "missing.xml")],
                                 str(dest))
    assert merged == 2
    inv = nmap.parse_xml(str(dest))
    assert {(s.host, s.port) for s in inv.services} == \
           {("10.0.0.1", 80), ("10.0.0.2", 80)}

    # Nothing readable at all -> no destination written (parses as empty).
    dest2 = tmp_path / "tcp2.xml"
    assert nmap.merge_host_xml([str(tmp_path / "absent.xml")], str(dest2)) == 0
    assert not dest2.exists()


def shard_fake(specs, ws, timeout=None, on_output=None, resume=False):
    """Mimic the real runner: skip satisfied shards on resume, write XML otherwise."""
    results = []
    for spec in specs:
        task = checkpoints.task_id(spec, ws)
        if resume and runner._resume_satisfied(spec, ws):
            saved = checkpoints.load(spec, ws)
            results.append({"task_id": task, "label": spec.label,
                            "command": spec.display(), "status": "skipped",
                            "reused_attempt": saved["attempt_id"], "duration": 0})
            continue
        index = int(spec.label.rsplit("_s", 1)[-1])
        xml = next(a.path for a in spec.outputs if a.path.endswith(".xml"))
        os.makedirs(os.path.dirname(xml), exist_ok=True)
        with open(xml, "w", encoding="utf-8") as fh:
            fh.write("<nmaprun>" + _host_xml(f"10.1.0.{index}") + "</nmaprun>")
        results.append({"task_id": task, "label": spec.label,
                        "command": spec.display(), "status": "ok",
                        "duration": 0.1})
    return results


def test_sharded_discovery_runs_parallel_and_merges(tmp_path, monkeypatch):
    calls = []

    def fake(specs, ws, timeout=None, on_output=None, resume=False):
        results = shard_fake(specs, ws, timeout, on_output, resume)
        calls.extend(r["label"] for r in results if r["status"] == "ok")
        return results

    monkeypatch.setattr("pentest.engine.run_specs", fake)
    engine, cfg, _ = sharded_engine(tmp_path, [f"10.0.0.{i}" for i in range(1, 5)], 2)
    ws, state = engine.run_sync(cfg)

    assert state["status"] == "done"
    assert sorted(calls) == ["nmap_tcp_s0", "nmap_tcp_s1"]
    assert sorted(r["label"] for r in state["modules"]["nmap_tcp"]["runs"]) == \
           ["nmap_tcp_s0", "nmap_tcp_s1"]
    inv = nmap.parse_xml(os.path.join(ws, "nmap", "tcp.xml"))
    assert {(s.host, s.port) for s in inv.services} == \
           {("10.1.0.0", 80), ("10.1.0.1", 80)}
    assert state["inventory"]["services"]


def seed_sharded_scan(engine, cfg, ws, scan_id):
    state = engine.store.initial_state(cfg, scan_id, ws)
    state["status"] = "interrupted"
    engine.store.save_state(ws, state)
    for spec in engine._nmap_specs(ws, cfg):
        xml = next(a.path for a in spec.outputs if a.path.endswith(".xml"))
        os.makedirs(os.path.dirname(xml), exist_ok=True)
        with open(xml, "w", encoding="utf-8") as fh:
            index = int(spec.label.rsplit("_s", 1)[-1])
            fh.write("<nmaprun>" + _host_xml(f"10.1.0.{index}") + "</nmaprun>")
        checkpoints.save(spec, ws, {"attempt_id": f"seed{index}", "returncode": 0})


def test_sharded_resume_skips_everything_and_rebuilds_inventory(tmp_path, monkeypatch):
    calls = []

    def fake(specs, ws, timeout=None, on_output=None, resume=False):
        results = shard_fake(specs, ws, timeout, on_output, resume)
        calls.extend(r["label"] for r in results if r["status"] == "ok")
        return results

    monkeypatch.setattr("pentest.engine.run_specs", fake)
    engine, cfg, _ = sharded_engine(tmp_path, [f"10.0.0.{i}" for i in range(1, 5)], 2)
    scan_id = new_scan_id()
    ws = engine.store.create_workspace(cfg, scan_id)
    seed_sharded_scan(engine, cfg, ws, scan_id)
    # Simulate a crash between the last shard and the merge: no tcp.xml yet.
    assert not os.path.isfile(os.path.join(ws, "nmap", "tcp.xml"))

    assert engine.resume(scan_id) == scan_id
    engine._queue.join()

    final = engine.store.load_state(ws)
    assert final["status"] == "done"
    assert calls == []  # nothing re-executed
    assert all(r["status"] == "skipped" for r in final["modules"]["nmap_tcp"]["runs"])
    # The resume path rebuilt the canonical inventory from the shard XMLs, and
    # the report snapshot carried it through (merge recorded as its own run).
    assert final["inventory"]["services"]
    inv = nmap.parse_xml(os.path.join(ws, "nmap", "tcp.xml"))
    assert {(s.host, s.port) for s in inv.services} == \
           {("10.1.0.0", 80), ("10.1.0.1", 80)}
    assert final["modules"]["nmap_merge"]["runs"][0]["status"] == "ok"


def test_partial_shard_resume_reruns_only_the_missing_shard(tmp_path, monkeypatch):
    calls = []

    def fake(specs, ws, timeout=None, on_output=None, resume=False):
        results = shard_fake(specs, ws, timeout, on_output, resume)
        calls.extend(r["label"] for r in results if r["status"] == "ok")
        return results

    monkeypatch.setattr("pentest.engine.run_specs", fake)
    engine, cfg, _ = sharded_engine(tmp_path, [f"10.0.0.{i}" for i in range(1, 5)], 2)
    scan_id = new_scan_id()
    ws = engine.store.create_workspace(cfg, scan_id)
    seed_sharded_scan(engine, cfg, ws, scan_id)
    # Shard 1 failed previously: no checkpoint, no XML.
    shard1 = engine._nmap_specs(ws, cfg)[1]
    os.unlink(checkpoints.path_for(shard1, ws))
    os.unlink(next(a.path for a in shard1.outputs if a.path.endswith(".xml")))

    assert engine.resume(scan_id) == scan_id
    engine._queue.join()

    final = engine.store.load_state(ws)
    assert final["status"] == "done"
    assert calls == ["nmap_tcp_s1"]  # only the unfinished shard executed
    labels = [r["label"] for r in final["modules"]["nmap_tcp"]["runs"]]
    assert sorted(labels) == ["nmap_tcp_s0", "nmap_tcp_s1"]
    inv = nmap.parse_xml(os.path.join(ws, "nmap", "tcp.xml"))
    assert {(s.host, s.port) for s in inv.services} == \
           {("10.1.0.0", 80), ("10.1.0.1", 80)}
