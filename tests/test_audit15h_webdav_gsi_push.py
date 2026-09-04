"""
test_audit15h_webdav_gsi_push.py — the identity the WebDAV HTTP-TPC PUSH leg
presents to the destination (audit §C: "Still open, and deliberately so — each
needs infrastructure the suite cannot stand up in-process: ... the WebDAV
GSI/delegation *push* leg").

Nothing external is needed, and the push leg is not what was missing:
test_webdav_tpc.py already drives ten pushes end to end.  What was missing is a
peer that can SAY WHO DIALLED IT.  Every destination in the tree is
`ssl_verify_client optional_no_ca` with the access log off, so no test has ever
observed the client certificate the outbound leg presents, and none has ever
made that certificate MANDATORY.  This file adds both — a peer that logs
`$ssl_client_s_dn`, and a second peer that will not complete a handshake
without a CA-issued client certificate — and the whole row becomes assertable.

THE CROSS.  One user, one grid proxy, one request header, two directions:

    COPY /x  Source: https://peer/seed.bin       X-Brix-Delegate-Proxy: <b64>
    COPY /y  Destination: https://peer/out.bin   X-Brix-Delegate-Proxy: <b64>

The pull reaches the peer as the USER.  The push reaches the same peer, from
the same server, in the same nginx, carrying the same header, as the SERVICE.

DEFECT CANDIDATE #27 — credential forwarding is silently PULL-ONLY.
`webdav_tpc_run_curl_push` (tpc_curl.c:401) hands NULL/NULL to the client-cred
slot with the comment "the per-user client-cert override is a pull-leg
concern", and `webdav_tpc_handle_push` (tpc_push.c:277) calls neither
`webdav_tpc_apply_user_proxy` nor `webdav_tpc_forward_user_bearer` — both of
which the pull path calls (tpc.c:393, tpc.c:408).  Three consequences, each
measured below:

  * a push runs under the SOURCE HOST's service identity no matter who asked
    for it, so a destination that authorizes or accounts by DN attributes the
    write to the deputy rather than the principal;
  * `brix_webdav_tpc_credential_forward` — on by default, and the documented
    switch for exactly this — changes the pull and changes NOTHING on the push,
    so an operator cannot turn the behaviour off either;
  * `X-Brix-Delegate-Proxy` is still PARSED on a push (access_capture_deleg_proxy
    runs in the access phase, before the method is dispatched) and its
    security check still fires, so a client is told its delegation was
    accepted and then it is discarded.

That last point is why this is filed as a defect rather than a design note: the
failure mode is silent.  A push whose delegation was ignored is
indistinguishable, from the client, from one that honoured it.

WHAT WOULD MAKE IT NOT A DEFECT.  If push delegation is genuinely out of scope,
the honest behaviour is to REFUSE a push that carries X-Brix-Delegate-Proxy —
the same shape as the native TPC destination refusing a source it cannot
authenticate to.  The tests below name the current answer in their messages, so
fixing it either way breaks them loudly.

Faces (one nginx, six server blocks — see nginx_audit15h_wdpush.conf):

    PORT          initiator, forwarding at its default (on)
    FWDOFF_PORT   initiator, brix_webdav_tpc_credential_forward off
    NOCERT_PORT   initiator, no brix_webdav_tpc_cert at all
    ROGUECA_PORT  initiator, an outbound anchor that does not sign the peer
    PEER_PORT     peer, logs $ssl_client_s_dn, reachable by a proxy chain
    STRICT_PORT   peer, ssl_verify_client on — a CA-issued cert or no handshake

Cases:
  * success       — a delegated PULL reaches the peer as the user
  * defect        — a delegated PUSH reaches it as the service
  * success       — the pushed bytes do land, under that identity
  * success       — turning forwarding off moves the pull to the service cert
  * defect        — turning it off changes nothing on the push
  * success       — a destination that MANDATES a client cert accepts the push
  * error         — an initiator with no service cert cannot reach that peer
  * error         — an outbound anchor that does not sign the peer refuses it
  * error         — only TransferHeader* crosses; the client's own does not
  * sec-negative  — a delegated proxy that is not the authenticated identity is
                    refused on the push path too
"""

import base64
import os
import re
import shutil
import subprocess
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from _test_gsi_handshake_helpers import (_ca_hash_link, _make_ca, _mint_proxy,
                                         _signed, _split_for_curl)

def _expression_1(handle):
    return (
        [m.groupdict() for m in _LINE.finditer(handle.read())]
    )

def _expression_2(seen, uri, method):
    return (
        [h for h in seen
                         if h["uri"] == uri and h["method"] == method]
    )


def _check_copy_1(done):
    assert done.returncode == 0, f"curl failed: {done.stderr.strip()}"


pytestmark = [pytest.mark.timeout(600),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-wdpush")]

NAME = "lc-audit15h-wdpush"

# Disjoint on purpose: every assertion below is "this CN and not that one", and
# a CN that were a substring of the other would make half of them pass for the
# wrong reason.
USER_CN = "wdpush-user"
OTHER_CN = "wdpush-bystander"
SERVICE_CN = "wdpush-service"

SEED = b"webdav tpc push delegation payload\n"
LOCAL_SEED = "/local.bin"        # lives on the initiator; the push leg reads it

# Two seed files on the peer rather than one, because the peer's log is keyed by
# URI: giving each pull its own source means a line left by another test can
# never be read as this one's, whatever the harness does with the prefix
# between tests.
PEER_SEED = "/seed.bin"
PEER_SEED_FWDOFF = "/seed-fwdoff.bin"

PROBE = "brix-push-probe-value"

DEFECT27 = (
    "DEFECT CANDIDATE #27 has been FIXED: the push leg now carries the "
    "requesting user's delegated credential.  Flip this expectation to the "
    "user CN (or to a refusal, if push delegation was closed off instead) and "
    "strike #27 from the audit.")


# --------------------------------------------------------------------------- #
# PKI — one CA, a host cert with an IP SAN, a service EEC, two users' proxies
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A hard requirement rather than a skip: the row exists to prove which
    REAL credential crosses the wire, so a missing openssl or xrdgsiproxy is a
    broken environment and not a reason to pass."""
    assert shutil.which("openssl"), "openssl is required to build the chain"
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint a real proxy"
    base = str(tmp_path_factory.mktemp("a15hwdpush"))

    ca_key, ca_pem = _make_ca(base, "/O=XrdTest/CN=wdpush-CA")
    certs = os.path.join(base, "certs")
    os.makedirs(certs, exist_ok=True)
    _ca_hash_link(ca_pem, certs)
    os.chmod(certs, 0o755)

    # The outbound leg is curl with CURLOPT_SSL_VERIFYHOST 2 against a URL that
    # names an IP literal, so the peer's certificate needs an iPAddress SAN —
    # the CN is not consulted for an IP-shaped name.
    host_key = os.path.join(base, "hostkey.pem")
    host_cert = os.path.join(base, "hostcert.pem")
    _signed(ca_key, ca_pem, HOST, host_key, host_cert, base,
            san=f"IP:{HOST},DNS:localhost")  # net-literal-allow: certificate DNS SAN test identity
    os.chmod(host_key, 0o600)

    def _eec(cn, tag):
        key = os.path.join(base, f"{tag}key.pem")
        cert = os.path.join(base, f"{tag}cert.pem")
        _signed(ca_key, ca_pem, cn, key, cert, base)
        os.chmod(key, 0o600)
        return cert, key

    service_cert, service_key = _eec(SERVICE_CN, "service")
    user_cert, user_key = _eec(USER_CN, "user")
    other_cert, other_key = _eec(OTHER_CN, "other")

    def _proxy(cert, key, tag):
        out = os.path.join(base, f"{tag}proxy.pem")
        env = dict(os.environ, X509_CERT_DIR=certs, X509_USER_PROXY=out)
        assert _mint_proxy(cert, key, out, certs, env), \
            f"xrdgsiproxy could not mint the {tag} proxy"
        return out

    user_proxy = _proxy(user_cert, user_key, "user")
    other_proxy = _proxy(other_cert, other_key, "other")

    # A second, unrelated anchor: the ROGUECA_PORT initiator trusts only this
    # one, so its outbound verification of the peer must fail.
    rogue_home = os.path.join(base, "rogue")
    os.makedirs(rogue_home, exist_ok=True)
    _, rogue_pem = _make_ca(rogue_home, "/O=XrdTest/CN=wdpush-rogueCA")

    return {"ca": ca_pem, "rogue_ca": rogue_pem, "certs": certs, "base": base,
            "host_cert": host_cert, "host_key": host_key,
            "service_cert": service_cert, "service_key": service_key,
            "user_proxy": user_proxy, "other_proxy": other_proxy}


@pytest.fixture(scope="module")
def creds(pki):
    """The proxy in the two shapes a delegating client needs: split for curl's
    --cert/--key, and base64 of the WHOLE file for X-Brix-Delegate-Proxy (the
    destination needs the private key to use it, so the header carries it)."""
    out = {}
    for tag in ("user", "other"):
        proxy = pki[f"{tag}_proxy"]
        cert, key = _split_for_curl(proxy, pki["base"], f"wp_{tag}")
        assert cert and key, f"could not split {proxy} for curl"
        with open(proxy, "rb") as handle:
            out[tag] = (cert, key,
                        base64.b64encode(handle.read()).decode())
    return out


# --------------------------------------------------------------------------- #
# The six faces
# --------------------------------------------------------------------------- #
@pytest.fixture()
def wdpush(lifecycle, tmp_path, pki):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if shutil.which("curl") is None:
        pytest.skip("curl is not on PATH")

    data = tmp_path / "data"
    (data / "src").mkdir(parents=True)
    (data / "peer").mkdir(parents=True)
    (data / "src" / LOCAL_SEED.lstrip("/")).write_bytes(SEED)
    for name in (PEER_SEED, PEER_SEED_FWDOFF):
        (data / "peer" / name.lstrip("/")).write_bytes(SEED)

    cred_dir = tmp_path / "cred"
    # 0700: brix_cred_write (phase-108 C11) refuses a group/other-accessible
    # credential store with EPERM, so the fixture matches the store's own bar.
    cred_dir.mkdir(mode=0o700)
    cred_dir.chmod(0o700)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_wdpush.conf",
        protocol="https",
        readiness="webdav",
        data_root=str(data),
        template_values={"HOSTCERT": pki["host_cert"],
                         "HOSTKEY": pki["host_key"],
                         "CA": pki["ca"],
                         "ROGUE_CA": pki["rogue_ca"],
                         "SERVICE_CERT": pki["service_cert"],
                         "SERVICE_KEY": pki["service_key"],
                         "CRED_DIR": str(cred_dir),
                         "TMP_DIR": str(tmp)},
        reason="audit-15h §C: WebDAV HTTP-TPC GSI/delegation push leg"))
    return endpoint, data


# --------------------------------------------------------------------------- #
# Driving and observing
# --------------------------------------------------------------------------- #
def _header_option(value, header):
    return [] if value is None else ["-H", header]


def _copy(creds, port, uri, *, source=None, dest=None, who="user",
          delegate=None, extra=()):
    """One WebDAV COPY as an X.509 user; returns (http_code, body).

    `-k` because server verification is curl's business here and the row is
    about the CLIENT credential; the OUTBOUND leg's verification is a separate
    matter and is asserted on its own below (it uses brix_webdav_tpc_cafile,
    not this flag)."""
    cert, key, b64 = creds[who]
    cmd = ["curl", "-sS", "-k", "--max-time", "60", "-w", "\n%{http_code}",
           "--cert", cert, "--key", key, "-X", "COPY",
           "-H", "Credential: none"]
    cmd += _header_option(source, f"Source: {source}")
    cmd += _header_option(dest, f"Destination: {dest}")
    delegated = creds[delegate][2] if delegate is not None else None
    cmd += _header_option(delegate, f"X-Brix-Delegate-Proxy: {delegated}")
    for header in extra:
        cmd += ["-H", header]
    cmd.append(f"https://{HOST}:{port}{uri}")
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    _check_copy_1(done)
    text, _, code = done.stdout.rpartition("\n")
    return code.strip(), text


def _peer_url(endpoint, path, face="PEER_PORT"):
    return f"https://{HOST}:{endpoint.extra_ports[face]}{path}"


_LINE = re.compile(r'method=(?P<method>\S+) uri=(?P<uri>\S+) '
                   r'status=(?P<status>\S+) dn="(?P<dn>[^"]*)" '
                   r'probe="(?P<probe>[^"]*)" authz="(?P<authz>[^"]*)"')


def _peer_hit(endpoint, uri, method, timeout=30):
    """The peer's own record of the request the outbound leg made.

    Polled rather than read once: the COPY response is sent from the thread-pool
    completion handler, so the peer's log line and the client's status code are
    not ordered with respect to each other.  The LAST match wins for the same
    reason a distinct URI is used per drive — the most recent line is this
    test's even if an earlier one survived."""
    path = os.path.join(endpoint.prefix, "logs", "peer.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, "r", errors="replace") as handle:
                seen = _expression_1(handle)
        except OSError:
            seen = []
        match = _expression_2(seen, uri, method)
        if match:
            return match[-1]
        time.sleep(0.2)
    return None


def _require_hit(endpoint, uri, method):
    hit = _peer_hit(endpoint, uri, method)
    assert hit is not None, (
        f"the peer never logged a {method} for {uri}, so the outbound leg "
        "never reached it and nothing below is about delegation")
    return hit


def _landed(data, name, timeout=20):
    target = data / "peer" / name.lstrip("/")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if target.exists() and target.read_bytes() == SEED:
            return True
        time.sleep(0.2)
    return False


def _absent(data, name):
    target = data / "peer" / name.lstrip("/")
    return not target.exists() or target.read_bytes() != SEED


# --------------------------------------------------------------------------- #
# The cross: one header, two directions                                        #
# --------------------------------------------------------------------------- #
def test_a_delegated_pull_reaches_the_source_as_the_user(wdpush, creds):
    """The positive control for the whole mechanism.  Without this the push
    result below would be unreadable: it could mean the delegation header was
    never honoured anywhere, rather than not honoured on one leg."""
    endpoint, _ = wdpush
    code, body = _copy(creds, endpoint.port, "/pulled.bin",
                       source=_peer_url(endpoint, PEER_SEED), delegate="user")
    assert code in ("200", "201", "204"), (code, body)

    hit = _require_hit(endpoint, PEER_SEED, "GET")
    assert f"CN={USER_CN}" in hit["dn"], (
        "the pull leg did not present the delegated proxy, so this file cannot "
        "say anything about the push leg either", hit)


def test_a_delegated_push_reaches_the_destination_as_the_service(wdpush, creds):
    """The row.  Same client, same header, same peer — the other direction."""
    endpoint, _ = wdpush
    dest = _peer_url(endpoint, "/pushed-deleg.bin")
    code, body = _copy(creds, endpoint.port, LOCAL_SEED, dest=dest,
                       delegate="user")
    assert code in ("200", "201", "204"), (code, body)

    hit = _require_hit(endpoint, "/pushed-deleg.bin", "PUT")
    assert f"CN={SERVICE_CN}" in hit["dn"], (DEFECT27, hit)
    assert f"CN={USER_CN}" not in hit["dn"], (DEFECT27, hit)


def test_the_pushed_bytes_land_under_the_service_identity(wdpush, creds):
    """The transfer is not merely attributed to the service — it SUCCEEDS as
    the service, which is what makes the attribution consequential."""
    endpoint, data = wdpush
    dest = _peer_url(endpoint, "/pushed-bytes.bin")
    code, body = _copy(creds, endpoint.port, LOCAL_SEED, dest=dest,
                       delegate="user")
    assert code in ("200", "201", "204"), (code, body)
    assert _landed(data, "/pushed-bytes.bin"), \
        "the push reported success but the peer's copy never matched"


# --------------------------------------------------------------------------- #
# The switch that governs it — on one leg                                      #
# --------------------------------------------------------------------------- #
def test_turning_credential_forwarding_off_moves_the_pull_to_the_service(
        wdpush, creds):
    """brix_webdav_tpc_credential_forward off, one face over.  The peer's log
    is what proves the toggle is wired at all — and therefore that the push
    result in the next test is the toggle being ignored, not being absent."""
    endpoint, _ = wdpush
    code, body = _copy(creds, endpoint.extra_ports["FWDOFF_PORT"],
                       "/pulled-fwdoff.bin",
                       source=_peer_url(endpoint, PEER_SEED_FWDOFF),
                       delegate="user")
    assert code in ("200", "201", "204"), (code, body)

    hit = _require_hit(endpoint, PEER_SEED_FWDOFF, "GET")
    assert f"CN={SERVICE_CN}" in hit["dn"], (
        "forwarding is off and the pull still did not fall back to the "
        "service cert", hit)


def test_turning_credential_forwarding_off_changes_nothing_on_the_push(
        wdpush, creds):
    """The same knob, the same server, the other direction: no effect, because
    the push leg never consults it."""
    endpoint, _ = wdpush
    dest = _peer_url(endpoint, "/pushed-fwdoff.bin")
    code, body = _copy(creds, endpoint.extra_ports["FWDOFF_PORT"], LOCAL_SEED,
                       dest=dest, delegate="user")
    assert code in ("200", "201", "204"), (code, body)

    hit = _require_hit(endpoint, "/pushed-fwdoff.bin", "PUT")
    assert f"CN={SERVICE_CN}" in hit["dn"], (DEFECT27, hit)


# --------------------------------------------------------------------------- #
# A destination that actually demands the certificate                          #
# --------------------------------------------------------------------------- #
def test_a_destination_that_mandates_a_client_certificate_accepts_the_push(
        wdpush, creds):
    """ssl_verify_client on: no CA-issued client certificate, no handshake.
    Nothing in the tree has ever made the push leg's certificate mandatory, so
    nothing has ever proven it presents one."""
    endpoint, data = wdpush
    dest = _peer_url(endpoint, "/pushed-strict.bin", face="STRICT_PORT")
    code, body = _copy(creds, endpoint.port, LOCAL_SEED, dest=dest,
                       delegate="user")
    assert code in ("200", "201", "204"), (code, body)
    assert _landed(data, "/pushed-strict.bin"), \
        "the strict peer reported success but never wrote the bytes"

    hit = _require_hit(endpoint, "/pushed-strict.bin", "PUT")
    assert f"CN={SERVICE_CN}" in hit["dn"], (DEFECT27, hit)


def test_an_initiator_with_no_service_certificate_cannot_reach_it(wdpush,
                                                                  creds):
    """The negative half of the same fact: strip brix_webdav_tpc_cert and the
    mandatory-certificate peer refuses the connection outright."""
    endpoint, data = wdpush
    dest = _peer_url(endpoint, "/pushed-nocert.bin", face="STRICT_PORT")
    code, body = _copy(creds, endpoint.extra_ports["NOCERT_PORT"], LOCAL_SEED,
                       dest=dest, delegate="user")
    assert code not in ("200", "201", "204"), (
        "an initiator with no service certificate satisfied a peer that "
        "requires one", code, body)
    assert _absent(data, "/pushed-nocert.bin"), \
        "the refused push still committed the bytes"


def test_an_outbound_anchor_that_does_not_sign_the_peer_refuses_it(wdpush,
                                                                   creds):
    """The other direction of trust on the same leg: brix_webdav_tpc_cafile
    names an anchor the peer's certificate does not chain to.  Distinct from
    the case above — there the PEER refuses us; here WE refuse the peer."""
    endpoint, data = wdpush
    dest = _peer_url(endpoint, "/pushed-rogueca.bin")
    code, body = _copy(creds, endpoint.extra_ports["ROGUECA_PORT"], LOCAL_SEED,
                       dest=dest, delegate="user")
    assert code not in ("200", "201", "204"), (
        "the push leg accepted a peer certificate that does not chain to "
        "brix_webdav_tpc_cafile", code, body)
    assert _absent(data, "/pushed-rogueca.bin"), \
        "the refused push still committed the bytes"
    assert _peer_hit(endpoint, "/pushed-rogueca.bin", "PUT", timeout=3) is None, \
        "the peer served a request the outbound verification should have stopped"


# --------------------------------------------------------------------------- #
# What else does and does not cross                                            #
# --------------------------------------------------------------------------- #
def test_only_transfer_headers_cross_to_the_destination(wdpush, creds):
    """TransferHeader* is the ONLY channel a push has to the far side, which is
    the practical consequence of the defect above: a client that wants the
    destination to see anything about it must say so explicitly, because
    nothing about its own request is carried.

    Both halves in one drive so the pair cannot drift: X-Brix-Probe sent
    directly must not appear, the TransferHeader-prefixed one must."""
    endpoint, _ = wdpush
    dest = _peer_url(endpoint, "/pushed-headers.bin")
    code, body = _copy(
        creds, endpoint.port, LOCAL_SEED, dest=dest, delegate="user",
        extra=(f"TransferHeaderX-Brix-Probe: {PROBE}",
               "X-Brix-Probe: not-forwarded-directly"))
    assert code in ("200", "201", "204"), (code, body)

    hit = _require_hit(endpoint, "/pushed-headers.bin", "PUT")
    assert hit["probe"] == PROBE, (
        "TransferHeaderX-Brix-Probe did not reach the destination, so the "
        "push has no delegation channel at all", hit)
    assert "not-forwarded-directly" not in hit["probe"], (
        "the client's own X-Brix-Probe was forwarded verbatim — a push must "
        "not relay the requesting client's headers to a third party", hit)


def test_a_proxy_that_is_not_the_authenticated_identity_is_refused(wdpush,
                                                                   creds):
    """Security-negative on the capture itself, on the push path where it has
    never been driven: authenticate as one user, delegate another user's
    proxy.  brix_proto_deleg_capture_proxy_header binds the header's leaf DN to
    the authenticated identity precisely so a push cannot be made to run as
    somebody else — and the refusal must land before any byte moves."""
    endpoint, data = wdpush
    dest = _peer_url(endpoint, "/pushed-swap.bin")
    code, body = _copy(creds, endpoint.port, LOCAL_SEED, dest=dest,
                       who="user", delegate="other")
    assert code == "403", (
        "a client delegated a proxy that is not its authenticated identity "
        "and the push was not refused", code, body)
    assert _absent(data, "/pushed-swap.bin"), \
        "the refused push still committed the bytes"
    assert _peer_hit(endpoint, "/pushed-swap.bin", "PUT", timeout=3) is None, \
        "the peer was dialled despite the delegation being refused"
