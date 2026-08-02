"""Cross-protocol translation through the gsiftp:// GridFTP gateway.

The gridftp door is not a bolt-on posix silo: like root://, WebDAV and S3, it
terminates on the shared ``brix_vfs_*`` storage seam. One posix export is
fronted here by BOTH a gsiftp gateway (``stream{}``) and a WebDAV endpoint
(``http{}``); a byte written through one front-end is byte-identical when read
through the other. That is the concrete meaning of gridftp being a *fully-fledged
bidirectional protocol* — usable as a front-end (ingress) AND as a back-end /
egress translation of the very same namespace another protocol wrote.

  * Direction A — gsiftp STOR then WebDAV GET: the door as an ingress front-end.
  * Direction B — WebDAV PUT then gsiftp RETR: the door serving bytes a foreign
    protocol persisted (gsiftp as the read/egress translation).
  * error — RETR of an object that was never written returns 550.
  * security-neg — a STOR whose path escapes the export is refused and writes
    nothing outside the export root (INVARIANT 4: resolve_path before open).

The gateway is driven with stdlib ``ftplib`` over the cleartext control channel
(no GSI tooling required); WebDAV is driven with stdlib ``urllib``.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        python3 -m pytest tests/test_gridftp_translation.py -v -p no:xdist
"""

import ftplib
import io
import os
import socket
import time
import urllib.error
import urllib.request

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("gridftp-xproto")]


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="gridftp-xproto",
        template="nginx_gridftp_xproto.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST},
    ))
    dav_port = endpoint.extra_ports["DAV_PORT"]

    # Harness waited on the gsiftp {PORT}; poll the WebDAV plane too.
    for _ in range(50):
        if _port_up(HOST, dav_port):
            break
        time.sleep(0.1)

    yield {"port": endpoint.port, "dav_port": dav_port,
           "data_root": endpoint.data_root}
    harness.close()


def _connect(gateway):
    ftp = ftplib.FTP()
    ftp.connect(SERVER_HOST, gateway["port"], timeout=30)
    ftp.login()
    return ftp


def _dav_get(gateway, name):
    url = f"http://{HOST}:{gateway['dav_port']}/{name}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read()


def _dav_put(gateway, name, payload):
    url = f"http://{HOST}:{gateway['dav_port']}/{name}"
    req = urllib.request.Request(url, data=payload, method="PUT")
    with urllib.request.urlopen(req, timeout=30) as resp:
        # brix_webdav replies 201 Created / 204 No Content on a fresh PUT.
        assert resp.status in (200, 201, 204), resp.status


def test_gsiftp_write_reads_back_over_webdav(gateway):
    """Direction A: a file the gsiftp door STORed is byte-identical when a
    different protocol (WebDAV GET) reads it off the same VFS export."""
    payload = os.urandom(48000)
    ftp = _connect(gateway)
    try:
        ftp.storbinary("STOR a2b.bin", io.BytesIO(payload))
        assert ftp.size("a2b.bin") == len(payload)
    finally:
        ftp.quit()
    assert _dav_get(gateway, "a2b.bin") == payload


def test_webdav_write_reads_back_over_gsiftp(gateway):
    """Direction B: a file a foreign protocol (WebDAV PUT) persisted is served
    byte-identical by the gsiftp door — gsiftp as the read/egress translation."""
    payload = os.urandom(52000)
    _dav_put(gateway, "b2a.bin", payload)
    ftp = _connect(gateway)
    try:
        assert ftp.size("b2a.bin") == len(payload)
        got = []
        ftp.retrbinary("RETR b2a.bin", got.append)
        assert b"".join(got) == payload
    finally:
        ftp.quit()


def test_retr_missing_object_is_550(gateway):
    """error path: RETR of an object no protocol ever wrote is refused, not a
    silent empty transfer."""
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm) as exc:
            ftp.retrbinary("RETR never_written.bin", lambda _b: None)
        assert exc.value.args[0].startswith("550")
    finally:
        ftp.quit()


def test_stor_path_escape_is_confined(gateway):
    """security-neg: a STOR whose path climbs out of the export is refused and
    writes nothing outside the export root — translation does not widen the
    attack surface (INVARIANT 4)."""
    escape = os.path.join(gateway["data_root"], "..", "xproto_escape.bin")
    assert not os.path.exists(escape)
    ftp = _connect(gateway)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.storbinary("STOR ../xproto_escape.bin", io.BytesIO(b"x" * 16))
    finally:
        ftp.quit()
    assert not os.path.exists(escape), "path traversal escaped the export root"
