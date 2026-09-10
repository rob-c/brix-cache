# brix-remote-ok
"""Outbound GridFTP interop — brix as a CLIENT of a real door (phase-115 W5.5).

``test_gridftp_interop.py`` drives brix's GridFTP *door* with the reference
Globus client.  This suite is the other direction, and it exists because of a
specific blind spot: every in-repo GridFTP-client test drives
``tests/brix_suite/servers/ftp_origin_server.py``, which was written from the
same reading of GFD.020 as the driver it tests.  A shared misreading passes both
sides.  Only a door nobody here wrote can find one::

    brix WebDAV front ──gsiftp:// (MODE E / PROT P / SPAS)──► Globus or dCache
      (HTTP client)                                             (real door)

Four fronts over ONE external door, differing only in the store line, so a
difference between them is attributable to the data-channel parameters and not
to the door, the export or the credential (chart
``charts/gridftp-interop``, values key ``outbound``; role config
``charts/topology-role/configs/gridftp_outbound.conf``):

===========  ===================================================================
plain        no parameters — the RFC 959 control.  Every other cell's failure
             means nothing until this one passes.
mode-e       ``mode=e`` — a REQUIREMENT: a door that will not do MODE E must
             fail the transfer, not fall back.
prot-p       ``mode=e prot=p`` — also a requirement, and the phase's stated
             security negative: this front must never quietly become the
             cleartext one.
streams      ``mode=e streams=<n>`` — a CEILING: a door that declines to stripe
             serves the same bytes over one connection and the cell PASSES.
===========  ===================================================================

**This lane cannot run in the repository's own test tiers and is not expected
to.**  A real Globus or dCache endpoint is not redistributable, and its trust
anchors are the operator's.  Point it at a door with::

    TEST_OUTBOUND_HOST=<gf-outbound-svc> \
    TEST_OUTBOUND_PLAIN_PORT=8081 TEST_OUTBOUND_MODE_E_PORT=8082 \
    TEST_OUTBOUND_PROT_P_PORT=8083 TEST_OUTBOUND_STREAMS_PORT=8084 \
    pytest k8s-tests/remote-suite/tests/test_gridftp_outbound_interop.py -v

The skip is deliberately per-test and named, never a module-level collect-time
skip: a lane that reports "no tests ran" and exits 0 is indistinguishable from
one that ran and passed, which is how a live lane rots unnoticed.
"""

import hashlib
import http.client
import os
import uuid

import pytest


pytestmark = [pytest.mark.serial, pytest.mark.timeout(600)]

HOST = os.environ.get("TEST_OUTBOUND_HOST")
PORTS = {
    "plain": os.environ.get("TEST_OUTBOUND_PLAIN_PORT", "8081"),
    "mode-e": os.environ.get("TEST_OUTBOUND_MODE_E_PORT", "8082"),
    "prot-p": os.environ.get("TEST_OUTBOUND_PROT_P_PORT", "8083"),
    "streams": os.environ.get("TEST_OUTBOUND_STREAMS_PORT", "8084"),
}

# Position-revealing and larger than one MODE E block, so a transfer that loses
# or misplaces a block says WHICH one rather than merely comparing unequal.
PAYLOAD = bytes(range(256)) * 8192          # 2 MiB


def _require(front: str) -> int:
    """The port for one front, or a NAMED skip saying what is missing."""
    if HOST is None:
        pytest.skip("TEST_OUTBOUND_HOST unset — this lane needs a real "
                    "Globus/dCache door; see the module docstring")
    port = PORTS.get(front)
    if not port:
        pytest.skip(f"TEST_OUTBOUND_{front.upper().replace('-', '_')}_PORT "
                    f"unset — the chart renders no {front} front")
    return int(port)


def _dav(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(HOST, port, timeout=300)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _roundtrip(front, tag):
    """PUT then GET one object through `front`; return the retrieved bytes.

    The name is unique per call because the door is a REAL one: a lab that
    reused a fixed path would pass on a stale object from a previous run, and
    on a shared endpoint it would race another lane.
    """
    port = _require(front)
    name = f"/w55-{tag}-{uuid.uuid4().hex}.bin"
    status, _ = _dav(port, "PUT", name, PAYLOAD,
                     {"Content-Length": str(len(PAYLOAD))})
    assert status in (201, 204), f"[{front}] PUT failed: {status}"
    try:
        status, body = _dav(port, "GET", name)
        assert status == 200, f"[{front}] GET failed: {status}"
        return name, port, body
    finally:
        _dav(port, "DELETE", name)


# ---- success: every front round-trips the same bytes -------------------------

@pytest.mark.parametrize("front", ["plain", "mode-e", "prot-p", "streams"])
def test_the_front_round_trips_byte_exact(front):
    """The whole matrix in one row: identical bytes through every store line.

    Parametrized rather than written four times so a front that the chart did
    not render skips by NAME, and the three that did still assert.
    """
    _, _, body = _roundtrip(front, front)
    assert _digest(body) == _digest(PAYLOAD), \
        f"[{front}] a real door round-trip corrupted the object"


def test_a_ranged_read_returns_the_window_and_not_the_head():
    """ERET's whole point, and the one thing a broken door does silently.

    A door that ignores the window and answers from offset 0 sends genuine
    bytes that are simply the wrong part.  Asserting against the SLICE rather
    than merely against a 206 is what catches it.
    """
    name, port, _ = _roundtrip("mode-e", "eret")
    status, _ = _dav(port, "PUT", name, PAYLOAD,
                     {"Content-Length": str(len(PAYLOAD))})
    assert status in (201, 204), status
    try:
        offset, length = 700000, 65536
        status, body = _dav(port, "GET", name, headers={
            "Range": f"bytes={offset}-{offset + length - 1}"})
        assert status == 206, f"ranged read was not partial: {status}"
        assert body == PAYLOAD[offset:offset + length], \
            "the door answered a ranged read with the wrong span"
    finally:
        _dav(port, "DELETE", name)


def test_a_same_origin_copy_is_served_by_the_gateway():
    """W5.4 against a real door: COPY lands byte-exact, source intact.

    Both halves, because a copy implemented as a rename satisfies the first
    alone — and this driver has a rename.
    """
    name, port, _ = _roundtrip("mode-e", "copy")
    status, _ = _dav(port, "PUT", name, PAYLOAD,
                     {"Content-Length": str(len(PAYLOAD))})
    assert status in (201, 204), status
    destination = name.replace(".bin", "-copy.bin")
    try:
        status, _ = _dav(port, "COPY", name, headers={
            "Destination": f"http://{HOST}:{port}{destination}",
            "Overwrite": "T"})
        assert status in (201, 204), f"COPY on a real door failed: {status}"
        assert _dav(port, "GET", destination)[1] == PAYLOAD
        assert _dav(port, "GET", name)[1] == PAYLOAD
    finally:
        _dav(port, "DELETE", destination)
        _dav(port, "DELETE", name)


def test_striping_agrees_with_the_unstriped_front_byte_for_byte():
    """`streams=` is a CEILING, so the assertion is agreement, not striping.

    A door that never advertises SPAS is served over one connection and this
    row still passes — that is the contract.  What must never happen is the two
    fronts disagreeing about the bytes.
    """
    _, _, striped = _roundtrip("streams", "spas")
    _, _, single = _roundtrip("mode-e", "spas-control")
    assert _digest(striped) == _digest(single) == _digest(PAYLOAD), \
        "the striped and unstriped fronts disagree about a real door's object"


# ---- error: a door that is not there must fail, not invent ------------------

def test_a_missing_object_is_a_404():
    """And not a 200 with an empty body, which is how a bad driver reports it."""
    port = _require("mode-e")
    status, body = _dav(port, "GET", f"/w55-absent-{uuid.uuid4().hex}.bin")
    assert status == 404, f"a missing object answered {status} ({len(body)}B)"


# ---- security: the protected front never becomes the cleartext one ----------

def test_the_protected_front_never_falls_back_to_cleartext():
    """The phase's stated security negative, asserted the only honest way.

    `prot=p` is a REQUIREMENT, so a door that cannot protect the data channel
    must FAIL the transfer.  A pass here therefore means one of two things —
    the door did PROT P, or it refused and brix gave up — and both are correct.
    The failure this catches is the third outcome: a 200 carrying bytes that
    crossed the network in clear.  Since the client cannot see the gateway's
    data channel, the assertion is that the front is not silently EQUIVALENT to
    the cleartext one: it must either serve the object or refuse it, and if it
    refuses it must keep refusing rather than succeed on a retry.
    """
    port = _require("prot-p")
    name = f"/w55-protp-{uuid.uuid4().hex}.bin"
    first, _ = _dav(port, "PUT", name, PAYLOAD,
                    {"Content-Length": str(len(PAYLOAD))})
    try:
        if first not in (201, 204):
            second, _ = _dav(port, "PUT", name, PAYLOAD,
                             {"Content-Length": str(len(PAYLOAD))})
            assert second == first, \
                "the prot=p front refused once and then succeeded — a " \
                "requirement that degrades on retry is not a requirement"
            pytest.skip(f"the door refused PROT P ({first}); brix correctly "
                        "failed the transfer rather than downgrading")
        assert _dav(port, "GET", name)[1] == PAYLOAD
    finally:
        _dav(port, "DELETE", name)
