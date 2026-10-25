"""Root launchers copy shared runtime credentials instead of re-owning them."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat

from cmdscripts import prepare_conf_credentials_for_worker


def _as_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def test_external_webdav_tpc_key_gets_a_worker_private_copy(tmp_path, monkeypatch):
    _as_root(monkeypatch)
    shared = tmp_path / "shared" / "userkey.pem"
    shared.parent.mkdir()
    shared.write_bytes(b"private-key")
    shared.chmod(0o400)
    prefix = tmp_path / "instance"
    prefix.mkdir()
    config = tmp_path / "nginx.conf"
    config.write_text(f"brix_webdav_tpc_key {shared};\n", encoding="utf-8")

    prepare_conf_credentials_for_worker(
        config, prefix, pwd.getpwuid(os.getuid()).pw_name
    )

    rewritten = config.read_text(encoding="utf-8")
    assert str(shared) not in rewritten
    copied = prefix / ".worker-creds" / shared.name
    assert copied.read_bytes() == b"private-key"
    assert stat.S_IMODE(copied.stat().st_mode) == 0o600


def test_copy_leaves_the_shared_client_credential_unchanged(tmp_path, monkeypatch):
    _as_root(monkeypatch)
    shared = tmp_path / "client.key"
    shared.write_bytes(b"client-owned")
    shared.chmod(0o400)
    before = shared.stat()
    prefix = tmp_path / "instance"
    prefix.mkdir()
    config = tmp_path / "nginx.conf"
    config.write_text(f"brix_upstream_x509_key {shared};\n", encoding="utf-8")

    prepare_conf_credentials_for_worker(
        config, prefix, pwd.getpwuid(os.getuid()).pw_name
    )

    after = shared.stat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert stat.S_IMODE(after.st_mode) == 0o400
    assert shared.read_bytes() == b"client-owned"


def test_missing_worker_credential_fails_closed_without_rewrite(tmp_path, monkeypatch):
    _as_root(monkeypatch)
    missing = tmp_path / "missing.key"
    prefix = tmp_path / "instance"
    prefix.mkdir()
    config = tmp_path / "nginx.conf"
    original = f"brix_webdav_tpc_key {missing};\n"
    config.write_text(original, encoding="utf-8")

    prepare_conf_credentials_for_worker(
        config, prefix, pwd.getpwuid(os.getuid()).pw_name
    )

    assert config.read_text(encoding="utf-8") == original
    assert not (prefix / ".worker-creds").exists()
