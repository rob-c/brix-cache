"""brix_checksum_default — the configurable default checksum algorithm.

Stock XRootD's `xrootd.chksum` sets the server's default/preferred checksum
algorithm; BriX hard-coded adler32. This adds `brix_checksum_default <algo>`,
which drives two things:

  * a kXR_Qcksum that names NO algorithm (no "<algo>:" prefix, no "?cks.type="
    CGI) computes the configured algorithm instead of adler32, and
  * the Qconfig "chksum" cslist advertises it FIRST — the entry a client takes
    as this server's preference when intersecting preference lists.

An explicit per-request algorithm still wins, and an unset (or unrecognized)
value falls back to adler32 — byte-identical to the prior behaviour.

Coverage: default drives path-Qcksum + Qconfig order; explicit ?cks.type
overrides; unset ⇒ adler32 (regression); a bad value degrades to adler32; the
directive passes `nginx -t`. Self-contained (no shared fleet).
"""

import struct
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-checksum-default")]

_SERVER = "lc-checksum-default"

kXR_query = 3001
kXR_Qcksum = 3
kXR_Qconfig = 7


def _spec(extra):
    return NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_checksum_default.conf",
        template_values={"BIND_HOST": BIND_HOST, "CHECKSUM_DIRECTIVE": extra},
        reason="checksum-default wire and config coverage")


def _launch(lifecycle, extra):
    endpoint = lifecycle.start(_spec(extra))
    Path(endpoint.data_root, "f.bin").write_bytes(b"checksum default payload\n")
    return endpoint.port


def _query(port, subcode, payload):
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", subcode) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=payload)
        assert status == H.kXR_ok, f"query {subcode} failed: {status}"
        return resp.split(b"\x00", 1)[0]
    finally:
        sock.close()


def _cksum_algo(port, path):
    """The algorithm token from a kXR_Qcksum reply ('algo hexvalue')."""
    return _query(port, kXR_Qcksum, path).split(b" ", 1)[0]


def test_default_drives_qcksum_and_qconfig(lifecycle):
    """(success) crc32c default ⇒ path-Qcksum computes crc32c and Qconfig leads
    with it (once, not duplicated)."""
    port = _launch(lifecycle, "brix_checksum_default crc32c;")
    assert _cksum_algo(port, b"/f.bin") == b"crc32c"
    chksum = _query(port, kXR_Qconfig, b"chksum")
    assert chksum.startswith(b"crc32c,"), f"chksum list: {chksum!r}"
    assert chksum.count(b"crc32c") == 1, "default duplicated in cslist"
    assert b"adler32" in chksum, "full algo set no longer advertised"


def test_explicit_request_algo_overrides_default(lifecycle):
    """(override) an explicit ?cks.type=md5 still wins over the default."""
    port = _launch(lifecycle, "brix_checksum_default crc32c;")
    assert _cksum_algo(port, b"/f.bin?cks.type=md5") == b"md5"


def test_unset_defaults_to_adler32(lifecycle):
    """(regression) no directive ⇒ adler32 leads Qconfig and answers Qcksum."""
    port = _launch(lifecycle, "")
    assert _cksum_algo(port, b"/f.bin") == b"adler32"
    assert _query(port, kXR_Qconfig, b"chksum").startswith(b"adler32,")


def test_bad_value_degrades_to_adler32(lifecycle):
    """(robustness) an unrecognized algo does not break checksums — it falls
    back to adler32 at use, never erroring the request."""
    port = _launch(lifecycle, "brix_checksum_default not_an_algo;")
    assert _cksum_algo(port, b"/f.bin") == b"adler32"
    assert _query(port, kXR_Qconfig, b"chksum").startswith(b"adler32,")


def test_directive_accepted_by_config_test(lifecycle):
    """(config) brix_checksum_default passes `nginx -t`."""
    lifecycle.register(_spec("brix_checksum_default sha256;"))
    lifecycle.reconfigure(_SERVER)
    r = lifecycle.nginx_test(_SERVER, check=False)
    assert r.returncode == 0, f"rejected by -t: {r.stderr}"
    assert "unknown directive" not in r.stderr
