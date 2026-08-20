"""
test_audit15_read_only.py — live coverage for the hard read-only switch
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15: `brix_read_only`
had ZERO test coverage on every plane while being fully wired).

The enforcement under test is brix_shared_apply_read_only()
(src/core/config/shared_conf.h): when `brix_read_only on`, allow_write is
forced OFF at merge time — even against an explicit `brix_allow_write on` —
so every existing protocol-edge write gate rejects writes before the VFS and
BEFORE token scope (INVARIANT 3).  These tests deliberately configure
`brix_allow_write on; brix_read_only on;` together: a pass proves the override,
not just the ordinary allow_write-off path (which other suites already cover).

  * WebDAV plane: PUT/DELETE/MKCOL -> 403 at the access phase
    (src/protocols/webdav/access.c write-method gate), GET still 200,
    and the backing store is byte-identical afterwards.
  * root:// plane: a write-mode kXR_open -> kXR_fsReadOnly
    "this is a read-only server" (src/protocols/root/read/open_request.c),
    read-mode opens unaffected.
  * Control: an identical instance WITHOUT read_only accepts the same PUT —
    the refusals above are read_only-driven, not a broken write path.
"""

import os
import struct

import pytest
import requests

from settings import NGINX_BIN, HOST
from port_ladder import PORT_LAST
from test_phase25_ratelimit import (
    _start_http,
    _start_stream,
    _xrd_login,
    _xrd_open,
    _xrd_recv_status,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15-readonly")]

KXR_OK = 0
KXR_ERROR = 4003
KXR_FS_READONLY = 3025    # filesystem is mounted read-only (opcodes.h)

SEED = "read-only-seed\n"

# Both flags together on purpose — see module docstring.
_RO_KNOBS = ("            brix_allow_write on;\n"
             "            brix_read_only on;\n")
_RW_KNOBS = "            brix_allow_write on;\n"


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _xrd_open_write(s, path):
    # kXR_open = 3010; body: mode[2] options[2] reserved[12]; payload=path.
    payload = path.encode()
    opts = 0x0008 | 0x4000 | 0x0100   # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, opts, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def test_webdav_read_only_rejects_writes_serves_reads(lifecycle, tmp_path):
    """Success + error path (WebDAV): reads flow, every write method is 403,
    and the store on disk is untouched afterwards."""
    port = _start_http(lifecycle, tmp_path, "lc-audit15-readonly-http-reload",
                       _RO_KNOBS, seed_files=(("seed.txt", SEED),),
                       port=PORT_LAST + 1)
    base = f"http://{HOST}:{port}"
    data = tmp_path / "data"

    r = requests.get(f"{base}/seed.txt", timeout=5)
    assert r.status_code == 200 and r.text == SEED

    assert requests.put(f"{base}/new.txt", data=b"x", timeout=5).status_code == 403
    assert not (data / "new.txt").exists(), \
        "read-only PUT was refused but still materialised a file"

    assert requests.delete(f"{base}/seed.txt", timeout=5).status_code == 403
    assert (data / "seed.txt").read_text() == SEED, \
        "read-only DELETE was refused but still mutated the store"

    assert requests.request("MKCOL", f"{base}/newdir", timeout=5).status_code == 403
    assert not (data / "newdir").exists()


def test_webdav_control_without_read_only_accepts_put(lifecycle, tmp_path):
    """Negative control: the identical instance minus read_only accepts the
    same PUT — proving the 403s above are the read_only override at work."""
    port = _start_http(lifecycle, tmp_path,
                       "lc-audit15-readonly-http-ctl-reload", _RW_KNOBS,
                       port=PORT_LAST + 2)
    r = requests.put(f"http://{HOST}:{port}/new.txt", data=b"payload", timeout=5)
    assert r.status_code in (200, 201, 204), r.status_code
    assert (tmp_path / "data" / "new.txt").read_bytes() == b"payload"


def test_root_read_only_write_open_refused_read_open_ok(lifecycle, tmp_path):
    """Security-negative (root://): with allow_write EXPLICITLY on, read_only
    still refuses a write-mode open with kXR_fsReadOnly at the protocol edge
    (nothing is created on disk), while a read open of the seeded file works."""
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "seed.bin").write_bytes(b"\x5a" * 64)
    knobs = ("        brix_allow_write on;\n"
             "        brix_read_only on;\n")
    port = _start_stream(lifecycle, data,
                         "lc-audit15-readonly-stream-reload", knobs, "",
                         port=PORT_LAST + 3)
    s = _xrd_login(HOST, port)
    try:
        st_r, b_r = _xrd_open(s, "/seed.bin")
        assert st_r == KXR_OK, (st_r, b_r)

        st_w, b_w = _xrd_open_write(s, "/forged.bin")
        assert st_w == KXR_ERROR, (st_w, b_w)
        assert struct.unpack(">I", b_w[:4])[0] == KXR_FS_READONLY, b_w
        assert b"read-only" in b_w, b_w
    finally:
        s.close()
    assert not (data / "forged.bin").exists(), \
        "write-open was refused but still created the file"
