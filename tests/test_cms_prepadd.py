"""
tests/test_cms_prepadd.py — forwarded staging ops (kYR_prepadd / kYR_prepdel).

Phase-89 W2 (PR-6): a CMS manager forwards a client's stage-in request down to
a data node as kYR_prepadd (Pup padArgs: ident, reqid, notify, prty, mode,
path) and the cancellation as kYR_prepdel (pdlArgs: ident, reqid).  The node
admits the path into the durable stage-request registry (the same store
kXR_prepare and the Tape REST API use) and keys the manager's reqid to the
registry's own reqid via the ADR-2b sidecar map so the later prepdel can
delete the right row.

The observable is the registry's durable journal
`<control_dir>/stage_requests.dat`: prepadd makes the LFN bytes appear in it;
prepdel memzeroes the record so the LFN bytes vanish.  Replies match stock
cmsd do_PrepAdd/do_PrepDel: silent on success and on an idempotent no-op
delete; kYR_error (code 1, [4B ecode][text NUL]) only for a refused prepadd.

Like test_cms_state_have_select.py, nginx dials OUT to a Python manager peer
that listens on a dedicated port, so each test drives the accepted socket.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_prepadd.py -v
"""

import os
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import free_port
from test_cms_state_have_select import (
    _ManagerPeer,
    _send_frame,
    _drain_until,
    _ping_sanity,
    _NOISE,
)

pytestmark = pytest.mark.uses_lifecycle_harness

_DIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_prepadd")

CMS_RR_ERROR   = 1
CMS_RR_PREPADD = 6
CMS_RR_PREPDEL = 7


# ---------------------------------------------------------------------------
# Pup string encoding (rrdata.c read_str): [2B BE len incl NUL][bytes][NUL];
# an absent/empty field is a bare 2-byte zero.
# ---------------------------------------------------------------------------

def _pstr(s):
    if not s:
        return struct.pack(">H", 0)
    b = s.encode() if isinstance(s, str) else s
    return struct.pack(">H", len(b) + 1) + b + b"\x00"


def _pad_payload(ident, reqid, notify, prty, mode, path):
    """padArgs wire order (rrdata.c parse_pad): ident reqid notify prty mode path."""
    return b"".join(_pstr(f) for f in (ident, reqid, notify, prty, mode, path))


def _pdl_payload(ident, reqid):
    """pdlArgs wire order (rrdata.c parse_pdl): ident reqid."""
    return _pstr(ident) + _pstr(reqid)


def _journal_contains(control_dir, needle, deadline_s=5.0):
    """Poll the durable stage-request journal for `needle` bytes."""
    journal = os.path.join(control_dir, "stage_requests.dat")
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            with open(journal, "rb") as f:
                if needle in f.read():
                    return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def _journal_scrubbed(control_dir, needle, deadline_s=5.0):
    """Poll until `needle` bytes are GONE from the journal (record memzeroed)."""
    journal = os.path.join(control_dir, "stage_requests.dat")
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            with open(journal, "rb") as f:
                if needle not in f.read():
                    return True
        except OSError:
            return True    # journal gone entirely == scrubbed
        time.sleep(0.1)
    return False


def _expect_error(conn, streamid, deadline_s=6.0):
    """Assert a kYR_error frame echoing `streamid` arrives; return its text."""
    got = _drain_until(conn, CMS_RR_ERROR, time.time() + deadline_s,
                       allow_codes=_NOISE)
    assert got is not None, "expected kYR_error, got nothing"
    sid, code, _mod, payload = got
    assert code == CMS_RR_ERROR, f"expected kYR_error, got code={code}"
    assert sid == streamid, f"error streamid {sid} != request {streamid}"
    assert len(payload) >= 4, "kYR_error body must carry [4B ecode][text]"
    return payload[4:].rstrip(b"\x00")


def _expect_silence(conn, deadline_s=2.0):
    """Assert NO kYR_error arrives within the window (success is silent)."""
    got = _drain_until(conn, CMS_RR_ERROR, time.time() + deadline_s,
                       allow_codes=_NOISE)
    assert got is None or got[1] != CMS_RR_ERROR, \
        f"unexpected kYR_error: {got[3][4:] if got else b''!r}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _start_stack(lifecycle, name, template, extra_values):
    mgr_port = free_port()
    data_dir = os.path.join(_DIR, name, "data")
    os.makedirs(data_dir, exist_ok=True)

    peer = _ManagerPeer(mgr_port)
    peer.start()
    values = {"MANAGER_PORT": mgr_port}
    values.update(extra_values)
    try:
        lifecycle.start(NginxInstanceSpec(
            name=name,
            template=template,
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values=values,
            reason="CMS forwarded staging (prepadd/prepdel) conformance.",
        ))
    except Exception:
        peer.stop()
        raise
    conn = peer.wait_login()
    if conn is None:
        peer.stop()
        pytest.skip(f"nginx never dialled in to the CMS manager peer "
                    f"(err={peer._err})")
    return peer, conn


@pytest.fixture
def prep_stack(lifecycle):
    """nginx CMS-client with the staging engine ON (brix_frm + control_dir)."""
    control_dir = os.path.join(_DIR, "prep", "control")
    queue_dir = os.path.join(_DIR, "prep", "queue")
    os.makedirs(control_dir, exist_ok=True)
    os.makedirs(queue_dir, exist_ok=True)
    peer, conn = _start_stack(
        lifecycle, "lc-cms-prep-client", "nginx_cms_prep_client.conf",
        {"CONTROL_DIR": control_dir,
         "QUEUE_PATH": os.path.join(queue_dir, "frm.q")})
    try:
        yield {"conn": conn, "control_dir": control_dir}
    finally:
        peer.stop()


@pytest.fixture
def noengine_stack(lifecycle):
    """nginx CMS-client WITHOUT brix_frm — no stage-request registry."""
    peer, conn = _start_stack(
        lifecycle, "lc-cms-prep-noengine", "nginx_cms_state_client.conf", {})
    try:
        yield {"conn": conn}
    finally:
        peer.stop()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPrepAddDel:

    def test_prepadd_admits_then_prepdel_scrubs(self, prep_stack):
        """Success path: prepadd lands the LFN in the durable journal (silent
        reply); prepdel with the SAME manager reqid deletes/memzeroes it; a
        second prepdel is an idempotent silent no-op and the connection
        survives (ping/pong)."""
        conn = prep_stack["conn"]
        control = prep_stack["control_dir"]
        lfn = b"/atlas/stagefile.root"

        _send_frame(conn, 0x71, CMS_RR_PREPADD,
                    payload=_pad_payload("usr.1:23@cli", "42.7@mgr",
                                         "udp://cli:2033", "1", "wq",
                                         lfn.decode()))
        assert _journal_contains(control, lfn), \
            "prepadd did not admit the LFN into the stage-request journal"
        _expect_silence(conn)

        _send_frame(conn, 0x72, CMS_RR_PREPDEL,
                    payload=_pdl_payload("usr.1:23@cli", "42.7@mgr"))
        assert _journal_scrubbed(control, lfn), \
            "prepdel did not scrub the LFN from the stage-request journal"
        _expect_silence(conn)

        # Idempotent repeat: silent, connection intact.
        _send_frame(conn, 0x73, CMS_RR_PREPDEL,
                    payload=_pdl_payload("usr.1:23@cli", "42.7@mgr"))
        _expect_silence(conn)
        _ping_sanity(conn)

    def test_prepadd_malformed_or_refused_gets_error(self, prep_stack,
                                                     noengine_stack):
        """Error paths: a truncated padArgs and a reqid-less prepadd are
        answered kYR_error 'badly formed request'; a prepadd on a node WITHOUT
        the staging engine is answered kYR_error 'no staging engine'.  Every
        error leaves the CMS connection usable."""
        conn = prep_stack["conn"]

        # Truncated: only ident+reqid of the six padArgs fields.
        _send_frame(conn, 0x81, CMS_RR_PREPADD,
                    payload=_pstr("usr.1:23@cli") + _pstr("9.9@mgr"))
        assert b"badly formed" in _expect_error(conn, 0x81)

        # Decodes, but no reqid -> planner refuses.
        _send_frame(conn, 0x82, CMS_RR_PREPADD,
                    payload=_pad_payload("usr.1:23@cli", "", "", "", "wq",
                                         "/atlas/x.root"))
        assert b"badly formed" in _expect_error(conn, 0x82)
        _ping_sanity(conn)

        # No engine configured (no brix_frm): registry singleton is NULL.
        conn2 = noengine_stack["conn"]
        _send_frame(conn2, 0x83, CMS_RR_PREPADD,
                    payload=_pad_payload("usr.1:23@cli", "5.5@mgr", "", "",
                                         "wq", "/held.bin"))
        assert b"no staging engine" in _expect_error(conn2, 0x83)
        _ping_sanity(conn2)

    def test_prepadd_traversal_path_refused(self, prep_stack):
        """Security-neg: a hostile manager forwarding a '..' escape path is
        refused (kYR_error) and the path NEVER reaches the durable journal."""
        conn = prep_stack["conn"]
        control = prep_stack["control_dir"]
        evil = "/../etc/stolen"

        _send_frame(conn, 0x91, CMS_RR_PREPADD,
                    payload=_pad_payload("usr.1:23@cli", "66.6@mgr", "", "",
                                         "wq", evil))
        assert b"denied" in _expect_error(conn, 0x91)
        assert not _journal_contains(control, evil.encode(), deadline_s=1.0), \
            "escape path must never be admitted into the journal"

        # Relative path (no leading '/') is refused by the same gate.
        _send_frame(conn, 0x92, CMS_RR_PREPADD,
                    payload=_pad_payload("usr.1:23@cli", "66.7@mgr", "", "",
                                         "wq", "relative/path"))
        assert b"denied" in _expect_error(conn, 0x92)
        _ping_sanity(conn)
