"""
test_audit15h_tpc_sss.py — native root:// TPC where SSS is the authentication
on both ends of the CLIENT's legs, and the destination's pull leg has to live
without it (audit §C, testsuite-combinatorial-coverage-audit 2026-08-15:
"Still open, and deliberately so — each needs infrastructure the suite cannot
stand up in-process: TPC x sss (live) ...").

Nothing external is needed.  The reason the row read as needing live
infrastructure is that every SSS test in the tree drives the protocol through
``client/bin/xrdsssadmin-brix`` + ``client/bin/xrdfs`` and skips when the
native client is unbuilt.  The credential is a short, fully specified byte
layout and ``cryptography`` (a declared requirement) carries Blowfish, so
_test_sss_helpers.py mints one in Python and this file drives the whole cross
over sockets.

THE FINDING THE CROSS PRODUCES — the pull leg has no sss and cannot get one.
``grep -r sss src/tpc/`` is empty, and src/tpc/gsi/gsi_outbound_finish.c
selects the outbound credential from exactly two advertised names, "ztn" and
"gsi".  A source that offers sss alone therefore leaves the destination with
nothing to send, no matter what is configured on it.  That is a real capability
boundary rather than a defect — but it is only defensible if the refusal is
ACTIONABLE, and it only counts as tested if the destination genuinely holds the
shared secret when it happens.  Here it does: source and destination load the
same keytab, the client authenticates to both with it, the rendezvous key is
armed by that authenticated client, and the pull is still refused.  The
refusal must name what would actually work (a bearer file or a GSI credential),
because "sss" is not one of the answers and an operator who configured
brix_sss_keytab has every reason to expect it to be.

Topology — three single-face instances:

    src   brix_auth sss + the keytab   the source the destination cannot reach
    open  brix_auth none               the same export, unauthenticated
    dst   brix_auth sss + the keytab   client face; brix_allow_write on

``open`` is the attribution control.  Every refusal against ``src`` is paired
with the same drive against ``open``, so a failure is only ever attributable to
sss and never to the path, the rendezvous key, the file size or the write gate.

Every negative asserts twice: the pull reports an error AND the destination
file was never committed.

Drive: read-open on the source with tpc.key+tpc.dst registers the rendezvous ->
write-open on the destination with tpc.src/tpc.key/tpc.stage=copy -> kXR_sync
#1 arms -> kXR_sync #2 starts the pull, whose reply carries the outcome.
"""

import os
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import (KXR_OK, _xrd_login, _xrd_open,
                                    _xrd_recv_status)
from _test_sss_helpers import sss_auth_frame, sss_credential, sss_write_keytab

pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-tpcsss")]

KXR_ERROR = 4003
SEED = b"tpc-under-sss-payload\n"
SRC_LFN = "/src.bin"
CLIENT_NAME = "audit15h-sss-client"

# What a source that speaks only sss leaves the outbound leg able to offer.
# The refusal has to name these, because the credential the operator DID
# configure (the keytab) is not among them.
ACTIONABLE = (b"brix_tpc_outbound_bearer_file", b"brix_certificate")


@pytest.fixture(scope="module")
def secret(tmp_path_factory):
    """The one shared secret, and the keytab both ends load from it.

    A single keytab for source and destination is deliberate: it removes the
    "they just had different keys" reading from every refusal below.
    """
    base = tmp_path_factory.mktemp("tpcsss")
    key = os.urandom(32)
    keytab = sss_write_keytab(str(base / "brix.keytab"), key)
    return {"key": key, "keytab": keytab, "wrong_key": os.urandom(32)}


@pytest.fixture(scope="module")
def trees(tmp_path_factory):
    """Source and destination exports; every test writes a distinct
    destination path, so a leftover is evidence for that test alone."""
    base = tmp_path_factory.mktemp("tpcsss-data")
    srcdata, dstdata = base / "src", base / "dst"
    for d in (srcdata, dstdata):
        d.mkdir()
    (srcdata / SRC_LFN.lstrip("/")).write_bytes(SEED)
    if os.geteuid() == 0:
        os.chmod(base, 0o755)
        for d in (srcdata, dstdata):
            os.chmod(d, 0o777)
    return srcdata, dstdata


@pytest.fixture()
def tpcsss(lifecycle, trees, secret):
    """(endpoints, dstdata).

    Function-scoped because ``lifecycle`` is: the harness stops and unregisters
    everything it started when the test ends.
    """
    srcdata, dstdata = trees
    kt = {"KEYTAB": secret["keytab"]}

    src = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15h-tpcsss-src",
        template="nginx_audit15h_tpcsss_src.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(srcdata),
        template_values=kt,
        reason="audit-15h §C: SSS-guarded TPC pull source."))
    open_ = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15h-tpcsss-open",
        template="nginx_audit15h_tpcsss_open.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(srcdata),
        reason="audit-15h §C: anonymous control source."))
    dst = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15h-tpcsss-dst",
        template="nginx_audit15h_tpcsss_dst.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(dstdata),
        template_values=kt,
        reason="audit-15h §C: TPC destination with an SSS client face."))
    return {"src": src, "open": open_, "dst": dst}, dstdata


# --------------------------------------------------------------------------- #
# wire drive                                                                   #
# --------------------------------------------------------------------------- #
def _sss_login(port, secret, key=None, username=CLIENT_NAME):
    """A logged-in, SSS-authenticated session.  Returns (socket, status, body)
    so the negatives can inspect a refusal instead of tripping over it."""
    s = _xrd_login(HOST, port)
    s.sendall(sss_auth_frame(
        sss_credential(key if key is not None else secret["key"],
                       username=username)))
    status, body = _xrd_recv_status(s)
    return s, status, body


def _arm(endpoints, secret, key, which="src", authenticate=True):
    """Register the rendezvous key on a source.  Returns the open socket — the
    registration is the client's leg and lives as long as it does."""
    port = endpoints[which].port
    if authenticate:
        s, status, body = _sss_login(port, secret)
        assert status == KXR_OK, ("client sss auth refused by the source",
                                  status, body)
    else:
        s = _xrd_login(HOST, port)
    status, body = _xrd_open(
        s, f"{SRC_LFN}?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    return s, status, body


def _dest_open(s, dest_path, src_port, key):
    opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
              f"&tpc.lfn={SRC_LFN}&tpc.stage=copy&oss.asize={len(SEED)}")
    payload = (dest_path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _pull(endpoints, secret, dest_path, source="open", dest_key=None):
    """Run one pull end to end as an SSS-authenticated client; returns the
    terminal (status, body)."""
    rk = "a15hsss" + dest_path.strip("/").replace(".", "").replace("-", "")
    armed, status, body = _arm(endpoints, secret, rk, which=source)
    try:
        assert status == KXR_OK, ("arm open refused", status, body)
        s, status, body = _sss_login(endpoints["dst"].port, secret,
                                     key=dest_key)
        s.settimeout(60)
        try:
            assert status == KXR_OK, ("client sss auth refused by the "
                                      "destination", status, body)
            status, body = _dest_open(s, dest_path,
                                      endpoints[source].port, rk)
            assert status == KXR_OK, ("dest-open refused", status, body)
            return _drive_pull(s, body[:4])
        finally:
            s.close()
    finally:
        armed.close()


def _landed(dstdata, dest_path, timeout=10):
    target = dstdata / dest_path.lstrip("/")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if target.exists() and target.read_bytes() == SEED:
            return True
        time.sleep(0.2)
    return False


def _uncommitted(dstdata, dest_path):
    target = dstdata / dest_path.lstrip("/")
    return not target.exists() or target.read_bytes() != SEED


# --------------------------------------------------------------------------- #
# the cross: a TPC transfer whose client legs are both SSS                     #
# --------------------------------------------------------------------------- #
def test_an_sss_client_drives_a_pull_through_an_sss_destination(tpcsss, secret):
    """The cross itself.  The initiating client authenticates with sss to the
    destination, arms the rendezvous, and the pull completes."""
    endpoints, dstdata = tpcsss
    status, body = _pull(endpoints, secret, "/sss-cross.bin")
    assert status == KXR_OK, ("the sss-driven pull failed", status, body)
    assert _landed(dstdata, "/sss-cross.bin"), \
        "the pull reported ok but the destination file never matched the source"


def test_an_unauthenticated_client_cannot_launch_a_pull(tpcsss, secret):
    """The destination's write face is the sss gate: no credential, no
    transfer, and specifically not a transfer that starts and then fails."""
    endpoints, dstdata = tpcsss
    armed, status, body = _arm(endpoints, secret, "a15hsssnoauth")
    try:
        assert status == KXR_OK, ("arm open refused", status, body)
        s = _xrd_login(HOST, endpoints["dst"].port)
        try:
            status, body = _dest_open(s, "/sss-noauth.bin",
                                      endpoints["open"].port, "a15hsssnoauth")
        finally:
            s.close()
    finally:
        armed.close()
    assert status == KXR_ERROR, \
        ("an unauthenticated client launched a TPC pull", status, body)
    assert _uncommitted(dstdata, "/sss-noauth.bin"), \
        "the refused launch still committed the source bytes"


def test_an_unauthenticated_client_cannot_arm_the_rendezvous(tpcsss, secret):
    """Arming is a read-open, so it is behind the same gate.  If it were not,
    an outsider could pre-register keys for transfers it does not own."""
    endpoints, _ = tpcsss
    armed, status, body = _arm(endpoints, secret, "a15hsssunauth",
                               authenticate=False)
    armed.close()
    assert status == KXR_ERROR, \
        ("an unauthenticated client armed a rendezvous key on an sss source",
         status, body)


def test_a_wrong_key_credential_is_refused_by_the_destination(tpcsss, secret):
    """The shared secret is the whole of the authentication: a well-formed
    credential minted under a different key must not open the write face."""
    endpoints, dstdata = tpcsss
    with pytest.raises(AssertionError) as excinfo:
        _pull(endpoints, secret, "/sss-wrongkey.bin",
              dest_key=secret["wrong_key"])
    assert "client sss auth refused by the destination" in str(excinfo.value), \
        f"refused for the wrong reason: {excinfo.value}"
    assert _uncommitted(dstdata, "/sss-wrongkey.bin")


# --------------------------------------------------------------------------- #
# the boundary: sss stops at the client legs                                   #
# --------------------------------------------------------------------------- #
def test_the_pull_leg_cannot_authenticate_to_an_sss_source(tpcsss, secret):
    """The destination holds the same keytab the source loads, the client is
    authenticated on both legs, and the rendezvous is armed — and the pull is
    still refused, because src/tpc/ has no sss at all."""
    endpoints, dstdata = tpcsss
    status, body = _pull(endpoints, secret, "/sss-source.bin", source="src")
    assert status == KXR_ERROR, \
        ("the pull leg authenticated to an sss-only source, which no code in "
         "src/tpc/ can do", status, body)
    assert _uncommitted(dstdata, "/sss-source.bin"), \
        "the refused pull still committed the source bytes"


def test_the_refusal_names_a_credential_that_would_actually_work(tpcsss,
                                                                 secret):
    """An operator who set brix_sss_keytab on both ends has configured the only
    shared secret in the deployment and will read a bare 'auth failed' as a key
    mismatch.  The message has to say that the outbound leg wants a bearer file
    or a GSI credential instead."""
    endpoints, _ = tpcsss
    status, body = _pull(endpoints, secret, "/sss-message.bin", source="src")
    assert status == KXR_ERROR, (status, body)
    for want in ACTIONABLE:
        assert want in body, \
            (f"the refusal does not mention {want.decode()}, so it does not "
             "tell the operator what to configure", body)


def test_the_same_destination_pulls_from_the_anonymous_source(tpcsss, secret):
    """Attribution: everything above except the source's auth mode is held
    fixed, and the transfer completes."""
    endpoints, dstdata = tpcsss
    status, body = _pull(endpoints, secret, "/sss-control.bin", source="open")
    assert status == KXR_OK, \
        ("the control pull failed too, so the sss refusals are not "
         "attributable to sss", status, body)
    assert _landed(dstdata, "/sss-control.bin")
