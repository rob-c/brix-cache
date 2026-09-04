"""Phase-91 outbound FTP storage-driver integration and security envelope."""

from __future__ import annotations

import http.client
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

import pytest

from fleet_lifecycle_ports import lifecycle_ports_for
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN, SERVER_HOST


pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(180),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-gsiftp-backend"),
]


def _request(port: int, method: str, path: str, body: bytes | None = None,
             headers: dict[str, str] | None = None):
    connection = http.client.HTTPConnection(SERVER_HOST, port, timeout=30)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


class _BackendLab:
    def __init__(self, harness: LifecycleHarness, root: Path, tmp: Path):
        origin_port, _ = lifecycle_ports_for("lc-gsiftp-backend-origin")
        origin = harness.start(NginxInstanceSpec(
            name="lc-gsiftp-backend-origin",
            template="",
            kind="proc",
            protocol="ftp",
            readiness="tcp",
            data_root=str(root),
            template_values={"argv": [
                sys.executable, "-m", "brix_suite.servers.ftp_origin_server",
                str(origin_port), str(root), "--audit", str(tmp / "ftp-origin.log"),
            ]},
            env={"PYTHONPATH": os.path.dirname(__file__)},
            reason="confined RFC-959 origin for the outbound storage driver",
        ))
        endpoint = harness.start(NginxInstanceSpec(
            name="lc-gsiftp-backend",
            template="nginx_lc_gsiftp_backend.conf",
            protocol="http",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "ORIGIN_PORT": origin.port,
                "ORIGIN_BASE": "/base",
                "RW_EXPORT": str(tmp / "rw-export"),
                "RO_EXPORT": str(tmp / "ro-export"),
            },
            reason="WebDAV fronts over the outbound FTP storage driver",
        ))
        self.harness = harness
        self.port = endpoint.port
        self.ro_port = endpoint.extra_ports["RO_PORT"]
        self.root = root
        self.error_log = Path(endpoint.prefix, "logs", "error.log")

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    tmp = tmp_path_factory.mktemp("gsiftp-backend")
    root = tmp / "origin"
    (root / "base" / "folder").mkdir(parents=True)
    (tmp / "rw-export").mkdir()
    (tmp / "ro-export").mkdir()
    (root / "base" / "seed.bin").write_bytes(b"0123456789" * 100)
    (root / "base" / "folder" / "child.txt").write_text("child", encoding="utf-8")
    lab = _BackendLab(LifecycleHarness(), root, tmp)
    yield lab
    lab.close()


def test_read_and_range_are_byte_exact(backend):
    status, _, body = _request(backend.port, "GET", "/seed.bin")
    assert (status, body) == (200, b"0123456789" * 100)
    status, headers, body = _request(
        backend.port, "GET", "/seed.bin", headers={"Range": "bytes=123-178"})
    assert status == 206
    assert headers["Content-Range"] == "bytes 123-178/1000"
    assert body == (b"0123456789" * 100)[123:179]


def test_directory_listing_uses_mlsd(backend):
    status, _, body = _request(
        backend.port, "PROPFIND", "/folder/", headers={"Depth": "1"})
    assert status == 207
    assert b"child.txt" in body


def test_staged_put_promotes_atomically(backend):
    payload = os.urandom(131_071)
    status, _, _ = _request(backend.port, "PUT", "/written.bin", payload)
    assert status in {201, 204}
    assert (backend.root / "base" / "written.bin").read_bytes() == payload
    status, _, body = _request(backend.port, "GET", "/written.bin")
    assert (status, body) == (200, payload)
    assert not list((backend.root / "base").glob("written.bin.brix-tmp-*"))


def test_namespace_create_move_delete(backend):
    status, _, _ = _request(backend.port, "MKCOL", "/newdir")
    assert status == 201
    status, _, _ = _request(backend.port, "PUT", "/newdir/a.txt", b"move-me")
    assert status in {201, 204}
    destination = f"http://{SERVER_HOST}:{backend.port}/newdir/b.txt"
    status, _, _ = _request(
        backend.port, "MOVE", "/newdir/a.txt", headers={"Destination": destination})
    assert status in {201, 204}
    assert not (backend.root / "base" / "newdir" / "a.txt").exists()
    assert (backend.root / "base" / "newdir" / "b.txt").read_bytes() == b"move-me"
    assert _request(backend.port, "DELETE", "/newdir/b.txt")[0] == 204
    assert _request(backend.port, "DELETE", "/newdir")[0] == 204


def test_missing_origin_object_is_not_a_gateway_crash(backend):
    status, _, body = _request(backend.port, "GET", "/missing.bin")
    assert status == 404
    assert body
    assert _request(backend.port, "GET", "/seed.bin")[0] == 200


def test_read_only_gate_rejects_before_origin_mutation(backend):
    before = (backend.root / "base" / "seed.bin").read_bytes()
    status, _, _ = _request(backend.ro_port, "PUT", "/seed.bin", b"clobber")
    assert status == 403
    assert (backend.root / "base" / "seed.bin").read_bytes() == before


def test_path_traversal_cannot_escape_origin_base(backend):
    outside = backend.root / "outside.txt"
    status, _, _ = _request(backend.port, "PUT", "/%2e%2e/outside.txt", b"escape")
    assert status in {400, 403, 404}
    assert not outside.exists()
