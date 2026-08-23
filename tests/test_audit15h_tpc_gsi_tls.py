"""
test_audit15h_tpc_gsi_tls.py — native root:// TPC pull where the DESTINATION
must upgrade the pull socket to TLS and then authenticate to the source with
its own credential (audit §C, testsuite-combinatorial-coverage-audit
2026-08-15: "TPC x TLS x GSI ... needs infrastructure the suite cannot stand up
in-process").

It can be stood up in-process, and the two halves that already exist do not add
up to the cross.  test_tpc_tls.py drives a TLS pull against a source whose
config is ``brix_auth none`` + ``brix_tls on`` — TLS that is ADVERTISED and no
identity demanded.  test_tpc_gsi_nginx_source.py drives a GSI pull against a
source with no TLS at all.  Each is one happy-path assertion, neither has a
single negative, and both skip without a built ``client/bin/xrdcp``.  So no
test has ever run the two outbound legs on one socket, none has ever met a
source that MANDATES TLS (``brix_tls_require``, not ``brix_tls``), and nothing
has ever checked what a refused pull leaves on disk.  This file does all three
with sockets only.

What makes it drivable without xrdcp is that the TPC rendezvous key lives in
one process-wide shared-memory table (src/tpc/engine/key_registry.c —
brix_tpc_key_register / _consume over a flat namespace, with no listener or
server-conf binding).  So the source instance can carry an anonymous ARM face
next to its authenticated ones: the initiating client registers the key there
in the clear, and the destination consumes it on the face that demands TLS and
GSI.  That split is not a workaround for a missing capability — it is the
correct isolation.  The arm is the CLIENT's leg; the credential this file is
about belongs to the destination, and nothing else should be able to satisfy
the source on its behalf.

The three faces and five destinations are laid out so that every refusal is
attributable:

    {PORT}          gsi + brix_tls_require all   -- the cross
    {GSIONLY_PORT}  gsi, cleartext               -- isolates the GSI half
    {ARM_PORT}      anonymous, cleartext         -- the rendezvous only

    good      outbound TLS + a proxy credential + the real trust anchor
    notls     the same credential, no outbound TLS
    nocred    outbound TLS, nothing to present
    rogueca   outbound TLS + a credential + an anchor that signed neither side
    noca      a credential and no anchor at all

Every negative asserts twice: the pull reports an error AND the destination
file was never committed.  A TPC leg that reports failure while leaving bytes
on disk is the failure mode that matters, and it is invisible to a status-only
assertion.

Drive: read-open on {ARM_PORT} with tpc.key+tpc.dst registers the key ->
write-open on the destination with tpc.src/tpc.key/tpc.stage=copy -> kXR_sync
#1 arms -> kXR_sync #2 starts the pull, whose reply (possibly via kXR_waitresp
and a pushed kXR_attn) carries the outcome.

DEFECT CANDIDATE #26, found by this file: the outbound GSI leg never verifies
the source's certificate on a TPC destination.  src/tpc/gsi/gsi_outbound_exchange.c
guards tpc_gsi_verify_server_cert() on ``conf->gsi_store``, but
src/auth/gsi/config.c::brix_configure_gsi() returns early — leaving gsi_store
NULL — unless the listener's own brix_auth (or a brix_protbind rule) selects
GSI.  A pull destination is an outbound GSI *client*, not a GSI acceptor, so
the store is never built for it and the check is dead code on exactly the
listeners it was written for.  brix_trusted_ca is configured, and the refusal
message at src/tpc/gsi/gsi_outbound_finish.c:87 tells the operator to configure
it for GSI, but on the cleartext-GSI path nothing anchors the source: the
destination hands its credential (potentially a delegated user proxy) to an
unauthenticated peer.  The TLS leg is unaffected — tls.c builds its own store
straight from brix_trusted_ca — so ``brix_tpc_outbound_tls on`` against a
TLS-demanding source is the only configuration that authenticates the source
today.  Both halves are pinned below.

TRAP the tls.c leg imposes on deployments — the source host credential here
carries an iPAddress SAN, not just a CN.  tls.c pins the peer name with
SSL_set1_host(t->src_host), and OpenSSL routes an IP-shaped name to
X509_VERIFY_PARAM_set1_ip_asc(), whose match has no CN fallback.  So a
``tpc.src`` written as an IP literal against a CN-only host certificate fails
with X509_V_ERR_IP_ADDRESS_MISMATCH however correct the chain is.  That is the
right behaviour, but it is invisible without the verify reason, which is why
tls.c now appends it to the handshake error.
"""

import os
import shutil
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import (KXR_OK, _xrd_login, _xrd_open,
                                    _xrd_recv_status)
from _test_gsi_handshake_helpers import _ca_hash_link, _make_ca, _mint_proxy, _signed

def _guard_pki_1():
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")

def _guard_pki_2():
    if not shutil.which("xrdgsiproxy"):
        pytest.skip("xrdgsiproxy not installed (cannot mint a dest proxy)")

def _guard_pki_3(dest_cert, dest_key, dest_proxy, env, certs):
    if not _mint_proxy(dest_cert, dest_key, dest_proxy, str(certs), env):
        pytest.skip("could not mint the destination proxy")


pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-tpcgsitls")]

SRC = "lc-audit15h-tpcgsitls-src"
KXR_ERROR = 4003
SEED = b"tpc-gsi-over-tls-payload\n"
SRC_LFN = "/src.bin"

# The address the destination is told to dial, and the one the source's host
# credential names in BOTH its CN and an iPAddress SAN (see the TRAP in the
# module docstring — the CN alone is not enough for an IP literal).
SRC_ADDR = HOST
# A second loopback address the source also answers on (the listeners bind
# 0.0.0.0).  Reaching the same server under an address the certificate does not
# carry is what isolates hostname binding from chain verification.
OTHER_LOOPBACK = "127.0.0.2"                             # net-literal-allow: same host, an address the cert does not carry

# The two distinct reasons a pull socket can refuse the source, as tls.c now
# reports them.  Asserting on the reason is what keeps the anchor negative and
# the hostname negative from passing for each other's cause.
BAD_ANCHOR = "unable to get local issuer certificate"
TLS_REFUSED = "TPC TLS handshake to source failed"

DEFECT26 = (
    "DEFECT CANDIDATE #26 has been FIXED: the outbound GSI leg now verifies "
    "the source's certificate against brix_trusted_ca.  Flip this expectation "
    "to KXR_ERROR + _uncommitted and strike #26 from the audit.")


def _knobs(*lines):
    """Render OUTBOUND_KNOBS: the destination template's only variable part."""
    return "".join(f"        {line}\n" for line in lines)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Trusted CA + source host credential + a destination proxy, plus a rogue
    CA directory that signed neither of them."""
    _guard_pki_1()
    _guard_pki_2()

    base = tmp_path_factory.mktemp("tpcgsitls")
    ca, rogue, certs, rogue_certs, srv = (
        base / d for d in ("ca", "rogue", "certs", "rogue_certs", "srv"))
    for d in (ca, rogue, certs, rogue_certs, srv):
        d.mkdir(parents=True, exist_ok=True)

    ca_key, ca_pem = _make_ca(str(ca), "/O=Audit15h/CN=Audit15h TPC CA")
    _ca_hash_link(ca_pem, str(certs))
    rogue_key, rogue_pem = _make_ca(str(rogue), "/O=Audit15h/CN=Audit15h Rogue CA")
    _ca_hash_link(rogue_pem, str(rogue_certs))

    host_key, host_cert = str(srv / "hostkey.pem"), str(srv / "hostcert.pem")
    _signed(ca_key, ca_pem, SRC_ADDR, host_key, host_cert, str(base),
            san=f"IP:{SRC_ADDR}")
    dest_key, dest_cert = str(srv / "destkey.pem"), str(srv / "destcert.pem")
    _signed(ca_key, ca_pem, "audit15h-tpc-dest", dest_key, dest_cert, str(base))
    os.chmod(dest_key, 0o600)

    dest_proxy = str(srv / "destproxy.pem")
    env = dict(os.environ, X509_CERT_DIR=str(certs))
    _guard_pki_3(dest_cert, dest_key, dest_proxy, env, certs)
    os.chmod(dest_proxy, 0o600)
    os.chmod(certs, 0o755)
    os.chmod(rogue_certs, 0o755)

    return {"certs": str(certs), "rogue_certs": str(rogue_certs),
            "host_cert": host_cert, "host_key": host_key,
            "dest_proxy": dest_proxy}


@pytest.fixture(scope="module")
def trees(tmp_path_factory):
    """Source and destination exports, shared across the module: every test
    writes a distinct destination path, so a leftover from one is evidence for
    that test alone."""
    base = tmp_path_factory.mktemp("tpcgsitls-data")
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
def tpcgsi(lifecycle, trees, pki):
    """(endpoints, dstdata): the three-faced source and the five destinations.

    Function-scoped because ``lifecycle`` is: the harness stops and unregisters
    everything it started when the test ends.
    """
    srcdata, dstdata = trees

    src = lifecycle.start(NginxInstanceSpec(
        name=SRC,
        template="nginx_audit15h_tpcgsitls_src.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(srcdata),
        template_values={"CERT_FILE": pki["host_cert"],
                         "KEY_FILE": pki["host_key"],
                         "CA_DIR": pki["certs"]},
        reason="audit-15h §C: TPC pull source demanding TLS then GSI."))

    cred = (f"brix_certificate {pki['dest_proxy']};",
            f"brix_certificate_key {pki['dest_proxy']};")
    variants = {
        "good": _knobs("brix_tpc_outbound_tls on;", *cred,
                       f"brix_trusted_ca {pki['certs']};"),
        "notls": _knobs(*cred, f"brix_trusted_ca {pki['certs']};"),
        "nocred": _knobs("brix_tpc_outbound_tls on;",
                         f"brix_trusted_ca {pki['certs']};"),
        "rogueca": _knobs("brix_tpc_outbound_tls on;", *cred,
                          f"brix_trusted_ca {pki['rogue_certs']};"),
        "noca": _knobs(*cred),
    }
    dests = {
        label: lifecycle.start(NginxInstanceSpec(
            name=f"lc-audit15h-tpcgsitls-{label}",
            template="nginx_audit15h_tpcgsitls_dst.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(dstdata),
            template_values={"OUTBOUND_KNOBS": knobs},
            reason=f"audit-15h §C: TPC destination variant {label}."))
        for label, knobs in variants.items()
    }
    return {"src": src, **dests}, dstdata


def _face(endpoints, which):
    src = endpoints["src"]
    if which == "tls":
        return src.port
    if which == "gsi":
        return int(src.extra_ports["GSIONLY_PORT"])
    return int(src.extra_ports["ARM_PORT"])


def _arm(endpoints, key):
    """Register the rendezvous key on the anonymous face.  Returns the open
    socket — the registration outlives the arm only while it is held."""
    s = _xrd_login(HOST, _face(endpoints, "arm"))
    status, body = _xrd_open(
        s, f"{SRC_LFN}?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    assert status == KXR_OK, ("arm open refused", status, body)
    return s


def _dest_open(s, dest_path, src_host, src_port, key):
    """Destination write-open naming the source; no token mode, so the outbound
    leg authenticates with brix_certificate if the source asks it to."""
    opaque = (f"?tpc.src={src_host}:{src_port}&tpc.key={key}"
              f"&tpc.lfn={SRC_LFN}&tpc.stage=copy&oss.asize={len(SEED)}")
    payload = (dest_path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _pull(endpoints, dest, dest_path, face="tls", src_host=SRC_ADDR, arm=True):
    """Run one pull end to end; returns the terminal (status, body)."""
    key = "a15h" + dest_path.strip("/").replace(".", "").replace("-", "")
    armed = _arm(endpoints, key) if arm else None
    s = _xrd_login(HOST, endpoints[dest].port)
    s.settimeout(60)
    try:
        status, body = _dest_open(s, dest_path, src_host,
                                  _face(endpoints, face), key)
        assert status == KXR_OK, ("dest-open refused", status, body)
        return _drive_pull(s, body[:4])
    finally:
        s.close()
        if armed is not None:
            armed.close()


def _landed(dstdata, dest_path, timeout=10):
    """True once the destination file holds the source bytes exactly."""
    target = dstdata / dest_path.lstrip("/")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if target.exists() and target.read_bytes() == SEED:
            return True
        time.sleep(0.2)
    return False


def _uncommitted(dstdata, dest_path):
    """True when a refused pull left nothing usable behind."""
    target = dstdata / dest_path.lstrip("/")
    return not target.exists() or target.read_bytes() != SEED


# --------------------------------------------------------------------------- #
# the cross itself                                                             #
# --------------------------------------------------------------------------- #
def test_the_cross_pull_completes_over_tls_and_gsi(tpcgsi):
    """A source that mandates TLS and then demands GSI is pulled from."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "good", "/cross.bin")
    assert status == KXR_OK, ("the TLS+GSI pull failed", status, body)
    assert _landed(dstdata, "/cross.bin"), \
        "the pull reported ok but the destination file never matched the source"


def test_the_tls_face_refuses_a_cleartext_destination(tpcgsi):
    """brix_tls_require all is enforced against the pull leg, not just clients."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "notls", "/notls-on-tls.bin")
    assert status == KXR_ERROR, \
        ("a destination that never upgraded was served by a TLS-requiring "
         "source", status, body)
    assert _uncommitted(dstdata, "/notls-on-tls.bin"), \
        "the refused pull still committed the source bytes"


def test_the_same_cleartext_destination_pulls_from_the_gsi_only_face(tpcgsi):
    """Attribution: the refusal above was the TLS half, not the credential."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "notls", "/notls-on-gsi.bin", face="gsi")
    assert status == KXR_OK, \
        ("the cleartext destination cannot authenticate at all, so the "
         "TLS-face refusal is not attributable to TLS", status, body)
    assert _landed(dstdata, "/notls-on-gsi.bin")


# --------------------------------------------------------------------------- #
# the GSI half                                                                 #
# --------------------------------------------------------------------------- #
def test_a_destination_with_no_credential_fails_the_gsi_handshake(tpcgsi):
    """Nothing to present -> no identity -> no bytes, on the cleartext face."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "nocred", "/nocred-on-gsi.bin", face="gsi")
    assert status == KXR_ERROR, \
        ("a destination with no brix_certificate was served by a gsi source",
         status, body)
    assert _uncommitted(dstdata, "/nocred-on-gsi.bin")


def test_a_destination_with_no_credential_also_fails_the_cross(tpcgsi):
    """An encrypted transport is not an identity: TLS does not stand in for GSI."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "nocred", "/nocred-on-tls.bin")
    assert status == KXR_ERROR, \
        ("the TLS upgrade satisfied a gsi source on its own", status, body)
    assert _uncommitted(dstdata, "/nocred-on-tls.bin")


# --------------------------------------------------------------------------- #
# what the destination verifies about the source                               #
# --------------------------------------------------------------------------- #
def test_an_untrusted_source_chain_is_refused_at_the_tls_handshake(tpcgsi):
    """brix_trusted_ca is a real anchor for the pull socket, not decoration."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "rogueca", "/rogue-on-tls.bin")
    assert status == KXR_ERROR, \
        ("the source's chain was accepted under an anchor that never signed "
         "it", status, body)
    assert BAD_ANCHOR.encode() in body, \
        ("the pull was refused for some reason other than the wrong anchor, so "
         "this proves nothing about brix_trusted_ca", body)
    assert _uncommitted(dstdata, "/rogue-on-tls.bin")


def test_the_source_hostname_is_bound_to_its_certificate(tpcgsi):
    """Chain-only verification would accept any CA-valid certificate for any
    host.  Dialing the same server by an address its certificate does not carry
    must fail — and must fail for the NAME, with the chain intact."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "good", "/hostname-on-tls.bin",
                         src_host=OTHER_LOOPBACK)
    assert status == KXR_ERROR, \
        ("the pull accepted a certificate issued for another name", status, body)
    assert TLS_REFUSED.encode() in body and BAD_ANCHOR.encode() not in body, \
        ("this should be a name mismatch against a chain that verified; the "
         "reported reason says otherwise", body)
    assert _uncommitted(dstdata, "/hostname-on-tls.bin")


def test_the_other_loopback_address_is_otherwise_reachable(tpcgsi):
    """Attribution: the refusal above was certificate-name binding and not a
    source the destination simply could not reach."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "good", "/hostname-on-gsi.bin", face="gsi",
                         src_host=OTHER_LOOPBACK)
    assert status == KXR_OK, \
        (f"{OTHER_LOOPBACK} is unreachable, so the hostname pin above proves "
         "nothing", status, body)
    assert _landed(dstdata, "/hostname-on-gsi.bin")


def test_an_untrusted_source_chain_is_refused_at_the_gsi_layer(tpcgsi):
    """The cleartext GSI leg also verifies the source against its anchor."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "rogueca", "/rogue-on-gsi.bin", face="gsi")
    assert status == KXR_ERROR, ("the GSI leg accepted an untrusted source",
                                 status, body)
    assert _uncommitted(dstdata, "/rogue-on-gsi.bin")


def test_the_gsi_layer_requires_an_anchor_when_one_is_configured(tpcgsi):
    """An explicit wrong anchor refuses; no anchor retains opt-out behavior."""
    endpoints, dstdata = tpcgsi
    rogue, _ = _pull(endpoints, "rogueca", "/anchor-equiv-rogue.bin", face="gsi")
    none_, _ = _pull(endpoints, "noca", "/anchor-equiv-none.bin", face="gsi")
    assert rogue == KXR_ERROR and none_ == KXR_OK, (rogue, none_)
    assert _uncommitted(dstdata, "/anchor-equiv-rogue.bin")
    assert _landed(dstdata, "/anchor-equiv-none.bin")


# --------------------------------------------------------------------------- #
# authentication is not authorization                                          #
# --------------------------------------------------------------------------- #
def test_an_unarmed_key_is_refused_after_a_successful_handshake(tpcgsi):
    """A completed TLS upgrade and a completed GSI handshake do not entitle the
    destination to a transfer nobody initiated: the rendezvous key still has to
    have been registered."""
    endpoints, dstdata = tpcgsi
    status, body = _pull(endpoints, "good", "/unarmed.bin", arm=False)
    assert status == KXR_ERROR, \
        ("an authenticated destination pulled a file with a key that was never "
         "armed", status, body)
    assert _uncommitted(dstdata, "/unarmed.bin")
