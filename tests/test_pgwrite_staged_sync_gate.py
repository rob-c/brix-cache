"""
Native kXR_pgwrite CSE close/sync gate on the phase-70 STAGED write path
(fault-hardening finding #10).

THE BREAK: on a whole-object staged backend (s3://, sd_http — no random-write fd,
so a WRITE open routes through the phase-70 staged writer), a kXR_pgwrite whose
page failed CRC32c was still handled by the accept-then-correct machine:
pgwrite_decode_collect registered the bad page in the per-handle Fob, but the
staged branch then (a) APPENDED the corrupt bytes to the staged temp and (b)
answered a *clean* kXR_status — never the CSE retransmit list.  Worse, kXR_sync
COMMITS a staged object (single backend PUT) and did so with NO Fob check at all,
while kXR_close is gated by brix_close_pgw_gate.  A hostile middlebox (or client)
could therefore pgwrite a corrupt page and then kXR_sync to publish the poison as
a complete object — sidestepping the close gate that INVARIANT 1 relies on.

THE FIX (fail-closed, both facets):
  * A staged handle is sequential append-only, so pgwrite accept-then-correct is
    impossible (a page can never be re-sent to its passed offset).  The staged
    pgwrite branch now HARD-REJECTS any CRC32c failure with kXR_ChkSumErr instead
    of appending corrupt bytes behind a misleading clean status.
  * kXR_sync consults the very same Fob commit gate as kXR_close
    (brix_pgw_fob_commit_blocked): a staged object is never published while any
    page remains uncorrected.

CONTRACT proven here, driven over the native root:// wire (the shared pgwrite
helpers from test_pgwrite_cse) against a root:// server whose storage backend is
a co-hosted brix_s3 object store (the staged writer path):
  * clean staged pgwrite + kXR_sync -> kXR_ok, object committed byte-exact  [no FP]
  * pgwrite with a corrupt page      -> kXR_ChkSumErr immediately (not a clean
    status), corrupt bytes never appended                                  [facet B]
  * kXR_sync after that corrupt page -> kXR_ChkSumErr, object NEVER published to
    the store (the poison-commit the fix closes)                           [facet A]

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_pgwrite_staged_sync_gate.py -v -p no:xdist
"""

import os
import socket
import struct
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Reuse the battle-tested native pgwrite wire client verbatim.
from test_pgwrite_cse import (
    _handshake_login,
    _open,
    _close,
    _read_response,
    send_pgwrite,
    build_payload,
    kXR_ok,
    kXR_error,
    kXR_status,
    kXR_ChkSumErr,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-staged")]

kXR_sync = 3016

S3_AK = "AKIDPGWSTAGEDSYNC1"
S3_SK = "cGd3cml0ZS1zdGFnZWQtc3luYy1nYXRlLXNlY3JldC10ZXN0"


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _sync(sock, fhandle):
    """Send kXR_sync (3016); return (status, errcode|None). A staged handle
    COMMITS the whole object here (single backend PUT)."""
    sock.sendall(struct.pack("!2sH4s12sI",
                             b"\x00\x0a", kXR_sync, fhandle, b"\x00" * 12, 0))
    status, body = _read_response(sock)
    errcode = (struct.unpack("!I", body[:4])[0]
               if (status == kXR_error and len(body) >= 4) else None)
    return status, errcode


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # The S3 endpoint's posix root must exist (with the bucket dir) at parse.
    # brix_s3 (posix backend) stores objects FLAT under this root — the posix
    # root IS the bucket root — so committed objects land directly in s3_dir.
    s3_dir = tmp_path_factory.mktemp("s3store")
    (s3_dir / "testbucket").mkdir()
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="root-s3-staged",
        template="nginx_root_s3_staged.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST,
                         "S3_DIR": str(s3_dir),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
    ))
    # S3_PORT is a second embedded listen owned by the lifecycle ledger
    # (fleet_lifecycle_ports.root-s3-staged); read it back post-start.
    s3_port = endpoint.extra_ports["S3_PORT"]

    # The harness waits on the root:// {PORT}; poll the S3 plane too.
    for _ in range(50):
        if _port_up(HOST, s3_port):
            break
        time.sleep(0.1)

    yield {"port": endpoint.port, "store": s3_dir}
    harness.close()


def _store_objects(node):
    """The set of committed object files in the store (the pre-created
    `testbucket` dir entry is not an object)."""
    root = node["store"]
    return {n for n in os.listdir(root) if (root / n).is_file()}


def _login(node):
    return _handshake_login(host=SERVER_HOST, port=node["port"])


def test_clean_staged_pgwrite_sync_commits(node):
    """No false positive: a clean staged pgwrite followed by kXR_sync commits the
    whole object (single PUT) — the object appears in the store byte-exact."""
    before = _store_objects(node)
    sock = _login(node)
    try:
        fh = _open(sock, b"/staged-clean.bin")
        good = os.urandom(6000)
        st, _off, cse = send_pgwrite(sock, fh, 0, build_payload(good, 0))
        assert st == kXR_status and cse == b"", "clean staged pgwrite must succeed"
        st, err = _sync(sock, fh)
        assert st == kXR_ok, f"clean staged sync must commit, got status={st} err={err}"
        _close(sock, fh)
    finally:
        sock.close()

    new = _store_objects(node) - before
    assert len(new) == 1, f"exactly one object should be published, got {new}"
    committed = (node["store"] / new.pop()).read_bytes()
    assert committed == good, "committed object must be byte-exact"


def test_staged_pgwrite_corrupt_page_rejected(node):
    """Facet B: on a sequential append-only staged handle, accept-then-correct is
    impossible, so a page that fails CRC32c is HARD-REJECTED with kXR_ChkSumErr
    right away (never a misleading clean status), and nothing is published."""
    before = _store_objects(node)
    sock = _login(node)
    try:
        fh = _open(sock, b"/staged-corrupt.bin")
        good = os.urandom(6000)
        # Page 0 arrives mutated while carrying the original CRC (in-transit
        # corruption) -> the server's CRC check must fail the write.
        st, err, _msg = send_pgwrite(sock, fh, 0,
                                     build_payload(good, 0, corrupt_data=[0]))
        assert st == "error", f"a corrupt staged pgwrite must error, got {st}"
        assert err == kXR_ChkSumErr, f"expected kXR_ChkSumErr, got {err}"
    finally:
        sock.close()

    assert _store_objects(node) == before, \
        "a rejected staged pgwrite must not publish any object"


def test_staged_sync_refuses_commit_with_uncorrected_page(node):
    """Facet A (the poison-commit the fix closes): after a corrupt pgwrite has
    registered an uncorrected page in the Fob, kXR_sync must refuse to publish
    (kXR_ChkSumErr) exactly as kXR_close does — never committing the poison as a
    complete object to the backing store."""
    before = _store_objects(node)
    sock = _login(node)
    try:
        fh = _open(sock, b"/staged-sync-poison.bin")
        good = os.urandom(6000)
        st, err, _msg = send_pgwrite(sock, fh, 0,
                                     build_payload(good, 0, corrupt_data=[0]))
        assert st == "error" and err == kXR_ChkSumErr, (st, err)

        # The uncorrected page is in the Fob; a sync MUST NOT publish it.
        st, err = _sync(sock, fh)
        assert st == kXR_error and err == kXR_ChkSumErr, \
            f"sync must refuse to commit an uncorrected staged object, got {st}/{err}"

        # And close must equally refuse (parity with the sync gate).
        st, err = _close(sock, fh)
        assert st == kXR_error and err == kXR_ChkSumErr, (st, err)
    finally:
        sock.close()

    assert _store_objects(node) == before, \
        "a gated staged handle must never publish the poison object"
