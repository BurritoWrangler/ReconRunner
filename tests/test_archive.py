"""Tests for safe scan archive import/export."""

import io
import json
import os
import tarfile

import pytest

from pentest import archive
from pentest.config import ScanConfig, sanitize_customer
from pentest.store import Store, new_scan_id


def _add_json(tar, name, value):
    data = json.dumps(value).encode("utf-8")
    member = tarfile.TarInfo(name)
    member.size = len(data)
    tar.addfile(member, io.BytesIO(data))


def _add_bytes(tar, name, data=b"x"):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    tar.addfile(member, io.BytesIO(data))


def _make_archive(path, scan_id, customer="Acme / West", extras=None,
                  state_id=None, include_state_customer_safe=False):
    config = {"customer_name": customer}
    state = {"id": state_id or scan_id, "customer": customer, "status": "done"}
    if include_state_customer_safe:
        state["customer_safe"] = sanitize_customer(customer)
    with tarfile.open(path, "w:gz") as tar:
        _add_json(tar, f"{scan_id}/config.json", config)
        _add_json(tar, f"{scan_id}/state.json", state)
        _add_bytes(tar, f"{scan_id}/report.html", b"<html>report</html>")
        for member, data in extras or []:
            tar.addfile(member, io.BytesIO(data) if data is not None else None)


def test_archive_export_import_round_trip(tmp_path):
    source_store = Store(base_dir=str(tmp_path / "source"))
    cfg = ScanConfig.defaults()
    cfg.customer_name = "Acme / West"
    cfg.authorized = True
    cfg.targets = ["192.0.2.10"]
    scan_id = new_scan_id()
    ws = source_store.create_workspace(cfg, scan_id)
    state = source_store.initial_state(cfg, scan_id, ws)
    state["status"] = "done"
    source_store.save_state(ws, state)
    with open(os.path.join(ws, "report.html"), "w", encoding="utf-8") as fh:
        fh.write("<html>report</html>")

    path = tmp_path / "scan.tar.gz"
    archive.export_scan_archive(ws, scan_id, str(path))
    info = archive.inspect_scan_archive(str(path))
    assert info.scan_id == scan_id
    assert info.customer_safe == "Acme_West"

    dest_store = Store(base_dir=str(tmp_path / "dest"))
    result = archive.import_scan_archive(str(path), dest_store)
    expected_ws = os.path.join(
        dest_store.base_dir, "results_Acme_West", scan_id
    )
    assert result.workspace == expected_ws
    assert os.path.isfile(os.path.join(expected_ws, "report.html"))
    found_ws, imported_state = dest_store.find_scan(scan_id)
    assert found_ws == expected_ws
    assert imported_state["id"] == scan_id
    assert imported_state["customer_safe"] == "Acme_West"
    assert imported_state["workspace"] == expected_ws
    assert imported_state["results_dir"] == os.path.relpath(
        expected_ws, dest_store.base_dir
    )

    with pytest.raises(archive.ArchiveError, match="already exists"):
        archive.import_scan_archive(str(path), dest_store)


def test_archive_import_sanitizes_customer_name(tmp_path):
    scan_id = new_scan_id()
    path = tmp_path / "customer.tar.gz"
    _make_archive(path, scan_id, customer="../../ACME West!")
    store = Store(base_dir=str(tmp_path / "dest"))

    result = archive.import_scan_archive(str(path), store)
    assert result.customer_safe == "ACME_West"
    assert result.workspace == os.path.join(
        store.base_dir, "results_ACME_West", scan_id
    )


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/tmp/recon-runner-outside.txt",
        "{scan_id}/../../outside.txt",
        "{scan_id}/nested/../outside.txt",
    ],
)
def test_archive_rejects_absolute_and_traversal_paths(tmp_path, unsafe_name):
    scan_id = new_scan_id()
    name = unsafe_name.format(scan_id=scan_id)
    member = tarfile.TarInfo(name)
    member.size = 1
    path = tmp_path / "unsafe.tar.gz"
    _make_archive(path, scan_id, extras=[(member, b"x")])
    store = Store(base_dir=str(tmp_path / "dest"))

    with pytest.raises(archive.ArchiveError, match="unsafe path"):
        archive.import_scan_archive(str(path), store)
    assert store.find_scan(scan_id) == (None, None)
    assert not (tmp_path / "outside.txt").exists()


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_archive_rejects_links(tmp_path, member_type):
    scan_id = new_scan_id()
    member = tarfile.TarInfo(f"{scan_id}/unsafe-link")
    member.type = member_type
    member.linkname = "/tmp/outside"
    path = tmp_path / "link.tar.gz"
    _make_archive(path, scan_id, extras=[(member, None)])

    with pytest.raises(archive.ArchiveError, match="unsupported member type"):
        archive.inspect_scan_archive(str(path))


def test_archive_rejects_invalid_scan_id(tmp_path):
    path = tmp_path / "invalid-id.tar.gz"
    _make_archive(path, "not-a-scan-id")

    with pytest.raises(archive.ArchiveError, match="scan ID is invalid"):
        archive.inspect_scan_archive(str(path))


def test_archive_rejects_mismatched_state_scan_id(tmp_path):
    scan_id = new_scan_id()
    path = tmp_path / "mismatch.tar.gz"
    _make_archive(path, scan_id, state_id=new_scan_id())

    with pytest.raises(archive.ArchiveError, match="does not match"):
        archive.inspect_scan_archive(str(path))


def test_archive_rejects_symlinked_results_directory(tmp_path):
    scan_id = new_scan_id()
    path = tmp_path / "symlink-dest.tar.gz"
    _make_archive(path, scan_id, customer="acme")
    base = tmp_path / "dest"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    # Pre-create results_acme as a symlink pointing outside the results tree.
    (base / "results_acme").symlink_to(outside, target_is_directory=True)
    store = Store(base_dir=str(base))

    with pytest.raises(archive.ArchiveError, match="symlink"):
        archive.import_scan_archive(str(path), store)
    assert not (outside / scan_id).exists()


def test_archive_rejects_state_without_scan_id(tmp_path):
    scan_id = new_scan_id()
    path = tmp_path / "no-id.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        _add_json(tar, f"{scan_id}/config.json", {"customer_name": "acme"})
        _add_json(tar, f"{scan_id}/state.json", {"status": "done"})

    with pytest.raises(archive.ArchiveError, match="does not match"):
        archive.inspect_scan_archive(str(path))


def test_archive_rejects_non_gzip_tar(tmp_path):
    scan_id = new_scan_id()
    path = tmp_path / "plain.tar"
    with tarfile.open(path, "w") as tar:
        _add_json(tar, f"{scan_id}/config.json", {"customer_name": "acme"})
        _add_json(tar, f"{scan_id}/state.json", {"id": scan_id})

    with pytest.raises(archive.ArchiveError, match="not a valid tar.gz archive"):
        archive.inspect_scan_archive(str(path))


def test_archive_rejects_duplicate_member_paths(tmp_path):
    scan_id = new_scan_id()
    duplicate = tarfile.TarInfo(f"{scan_id}/report.html")
    duplicate.size = 9
    path = tmp_path / "duplicate.tar.gz"
    _make_archive(path, scan_id, extras=[(duplicate, b"duplicate")])

    with pytest.raises(archive.ArchiveError, match="duplicate path"):
        archive.inspect_scan_archive(str(path))
