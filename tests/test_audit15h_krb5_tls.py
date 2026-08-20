"""
test_audit15h_krb5_tls.py — Kerberos 5 on a TLS listener (audit §B1.8:
"`brix_auth krb5` on a TLS listener: zero").

krb5 was the one authentication backend the suite had never combined with TLS.
Every krb5 test in the tree — ``test_krb5_auth.py``, ``test_native_krb5.py``,
the authdb and cache-origin pairings — runs the acceptor on a plain socket, so
nothing anywhere asserted that a ticket still authenticates once the channel is
upgraded, nor that a krb5 server can be stopped from doing the AP-REQ exchange
in the clear.  Both matter, and for opposite reasons:

  * TLS and Kerberos are two independent claims.  A server that conflated them
    would treat "the channel is encrypted" as "the peer is known" and let an
    unauthenticated client through the moment it completed a handshake — the
    classic transport-vs-identity confusion.  Two tests here hold that line by
    presenting NO ticket over a perfectly good TLS channel.
  * conversely, krb5 without TLS puts the AP-REQ, and the session key derived
    from it, on the wire in the clear.  ``brix_tls_require`` is what makes that
    impossible, and it had never been pointed at a krb5 listener.

WHY THIS ROW STAYED OPEN, AND WHAT CLOSES IT.  It needs a real realm — an
acceptor validates a ticket against a keytab, and there is no faking one.  The
suite already provisions a throwaway MIT KDC (``kdc_helpers.up()``), so the
missing half was only the PKI; this file mints its own CA and a host cert whose
SANs cover ``localhost``, so the krb5 service principal
(``xrootd/localhost@…``) and the TLS name the client verifies are the same
host, and neither half has to be relaxed to let the other work.

THE ATTRIBUTION CONTROL.  Three planes share one realm, one keytab and one data
root, differing only in transport: ``PORT`` (krb5 + TLS), ``PLAIN_PORT`` (krb5,
no TLS) and ``TLSREQ_PORT`` (krb5 + TLS + ``brix_tls_require all``).  Every
failure asserted below is paired with the identical operation succeeding on
another plane with the identical credential, so "refused" can never be a
mis-provisioned KDC wearing a policy's clothes.

Cases:
  * success       — a kinit'd client authenticates over the TLS upgrade and can
                    stat and read
  * success       — the same credential on the cleartext plane (the control)
  * success       — a write survives the upgrade: upload, read back, byte-compare
  * error         — no ticket over TLS is denied; encryption is not identity
  * error         — a client that does not trust the host cert cannot connect,
                    which is what proves the TLS half is really being verified
  * sec-negative  — the gated plane advertises kXR_tlsLogin and the ungated one
                    does not, so the credential is demanded *before* it can be
                    sent in the clear rather than refused after
  * sec-negative  — a forged / truncated ticket is still refused over the
                    upgraded channel: encryption does not soften the acceptor
  * sec-negative  — a logged-in, fully upgraded session that never sends
                    kXR_auth cannot read, and no ticket is still denied on the
                    gated plane — satisfying the transport requirement never
                    satisfies authentication
"""

import os
import shutil
import socket
import ssl
import struct
import time
import subprocess

import pytest

import kdc_helpers
from server_registry import NginxInstanceSpec
from settings import (
    KRB5_CCACHE,
    KRB5_CONF,
    KRB5_KEYTAB,
    KRB5_SERVICE_PRINCIPAL,
    NGINX_BIN,
)
from test_min_sec_level import KXR_ERROR, _errcode, _send_initial
from _test_phase25_ratelimit_helpers import _xrd_recv_status, _xrd_stat

pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-krb5tls")]

NAME = "lc-audit15h-krb5tls"

# The service principal is xrootd/localhost@REALM (settings.py), so the client
# has to reach the server as `localhost` for the ticket to name it — and the
# host cert below carries a matching SAN, so the same name satisfies the TLS
# verification.  One name for both halves is the whole trick.
CONNECT_HOST = "localhost"  # net-literal-allow: Kerberos service principal and TLS SAN

READ_FILE = "/hello.txt"
READ_BODY = b"krb5 over tls\n"

KXR_OK = 0
kXR_NotAuthorized = 3010

# kXR_protocol reply flags (XProtocol.hh) — the wire-visible statement of what
# this listener demands.  `brix_tls_require login` sets kXR_tlsLogin, which is
# what makes a stock client upgrade before it will send its credential.
kXR_haveTLS = 0x80000000
kXR_tlsData = 0x01000000
kXR_tlsLogin = 0x04000000
kXR_tlsSess = 0x08000000

SYS_XRDFS = shutil.which("xrdfs")
SYS_XRDCP = shutil.which("xrdcp")


# --------------------------------------------------------------------------- #
# PKI — a throwaway CA and a host cert named for the krb5 service host
# --------------------------------------------------------------------------- #

def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True,
                   timeout=60)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """CA + host cert (SAN localhost / fqdn / 127.0.0.1) + a hashed CA dir.

    A hard requirement, not a skip: this row exists precisely to prove the two
    halves compose, so a missing openssl is a failure, not an excuse."""
    assert shutil.which("openssl"), "openssl is required for the TLS half"
    base = tmp_path_factory.mktemp("a15hkrb5tls")
    ca_key, ca_pem = str(base / "ca.key"), str(base / "ca.pem")
    key, csr, cert = (str(base / "hostkey.pem"), str(base / "host.csr"),
                      str(base / "hostcert.pem"))

    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/O=brix-test/CN=audit15h krb5 CA",
             "-keyout", ca_key, "-out", ca_pem)
    _openssl("req", "-nodes", "-newkey", "rsa:2048",
             "-subj", f"/O=brix-test/CN={CONNECT_HOST}",
             "-keyout", key, "-out", csr)

    ext = base / "host.ext"
    ext.write_text(
        f"subjectAltName=DNS:{CONNECT_HOST},DNS:{socket.getfqdn()},"
        "IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"  # net-literal-allow: TLS SAN test identity
        )
    _openssl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
             "-CAcreateserial", "-days", "2", "-out", cert,
             "-extfile", str(ext))
    os.chmod(key, 0o600)

    # The client verifies the host cert out of an OpenSSL hashed CA directory.
    # 0755, deliberately: the fleet runs under umask 000 and XrdCl's TLS init
    # refuses a group/other-writable CA dir as "excessive access rights", which
    # fails every roots:// connection for a reason that looks nothing like the
    # cause (see the note on the GSI suite's own `pki` fixture).
    certs = base / "certs"
    certs.mkdir()
    subject_hash = subprocess.run(
        ["openssl", "x509", "-subject_hash", "-noout", "-in", ca_pem],
        check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    shutil.copyfile(ca_pem, certs / f"{subject_hash}.0")
    os.chmod(certs, 0o755)

    # A CA directory that knows nothing of our CA — the "client does not trust
    # the server" negative needs a well-formed but wrong trust store, not an
    # empty one, so the failure is a verification failure and not a setup error.
    stranger = base / "stranger"
    stranger.mkdir()
    other_key, other_pem = str(base / "other.key"), str(base / "other.pem")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/O=brix-test/CN=audit15h stranger CA",
             "-keyout", other_key, "-out", other_pem)
    other_hash = subprocess.run(
        ["openssl", "x509", "-subject_hash", "-noout", "-in", other_pem],
        check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    shutil.copyfile(other_pem, stranger / f"{other_hash}.0")
    os.chmod(stranger, 0o755)

    return {"ca": ca_pem, "cert": cert, "key": key,
            "certs": str(certs), "stranger": str(stranger)}


# --------------------------------------------------------------------------- #
# The three planes, off one realm
# --------------------------------------------------------------------------- #

@pytest.fixture
def krb5tls(lifecycle, tmp_path, pki):
    if SYS_XRDFS is None or SYS_XRDCP is None:
        pytest.skip("stock xrdfs/xrdcp not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if not kdc_helpers.krb5_tools_available():
        pytest.skip("MIT KDC tooling not installed (install krb5-server)")
    if not kdc_helpers.up():
        pytest.skip("krb5 realm could not be provisioned")

    data = tmp_path / "data"
    data.mkdir()
    (data / os.path.basename(READ_FILE)).write_bytes(READ_BODY)

    # The acceptor resolves auth_to_local and the default realm out of the
    # generated profile; `nginx -t` runs in the launcher's own process, so the
    # ambient env needs it too, not just the daemon's.
    os.environ["KRB5_CONFIG"] = KRB5_CONF

    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15h_krb5tls.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(data),
            template_values={"PRINCIPAL": KRB5_SERVICE_PRINCIPAL,
                             "KEYTAB": KRB5_KEYTAB,
                             "CERT": pki["cert"],
                             "KEY": pki["key"],
                             "CA": pki["ca"]},
            env={"KRB5_CONFIG": KRB5_CONF},
            reason="audit-15h krb5 x TLS (§B1.8)"))
    except Exception:
        kdc_helpers.down()
        raise

    try:
        yield endpoint, data
    finally:
        kdc_helpers.down()


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

def _env(pki, *, ccache=KRB5_CCACHE, certs=None):
    """Drive the stock client to krb5 + a specific trust store.

    X509_* is stripped so a stray proxy in the ambient environment can never
    make this a GSI test by accident, and TlsNoCertVerify is pinned off so the
    host-cert negative below is testing the server's cert and not the client's
    default."""
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "krb5"
    env["KRB5_CONFIG"] = KRB5_CONF
    if ccache is None:
        env.pop("KRB5CCNAME", None)
    else:
        env["KRB5CCNAME"] = ccache
    env["X509_CERT_DIR"] = certs or pki["certs"]
    env["XRD_TLSNOCERTVERIFY"] = "0"
    for stray in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY"):
        env.pop(stray, None)
    return env


def _url(port, *, tls=True):
    return f"{'roots' if tls else 'root'}://{CONNECT_HOST}:{port}"


def _xrdfs(pki, port, *args, tls=True, **env_kw):
    return subprocess.run(["xrdfs", _url(port, tls=tls), *args],
                          env=_env(pki, **env_kw), capture_output=True,
                          timeout=60)


# --------------------------------------------------------------------------- #
# Raw wire.
#
# Needed because the stock client is *correct*: told by the kXR_protocol reply
# that this listener demands TLS for login, it upgrades even for a root:// URL.
# There is therefore no client-side way to ask for a cleartext krb5 session on
# the gated plane, and no way to present a forged ticket over an upgraded one.
# Both are wire-level questions and are asked on the wire.
# --------------------------------------------------------------------------- #

def _connect(port):
    last_error = None
    for _attempt in range(5):
        sock = socket.create_connection((CONNECT_HOST, port), timeout=10)
        sock.settimeout(10)
        try:
            _send_initial(sock)
            return sock
        except (ConnectionResetError, BrokenPipeError, TimeoutError) as exc:
            last_error = exc
            sock.close()
            time.sleep(0.1)
    raise last_error


def _protocol_flags(sock):
    """kXR_protocol advertising kXR_ableTLS; return the reply's flags word.

    kXR_protocol is exempt from the TLS gate by design (policy.c: the opcode
    that arms the upgrade must not be blocked by the policy demanding it), so
    this always answers, on every plane."""
    sock.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006,
                             0x00000520, 0x02, 0x03, 0))
    status, body = _xrd_recv_status(sock)
    assert status == KXR_OK, (status, body)
    return struct.unpack(">I", body[4:8])[0]


def _upgrade(raw):
    """Complete the in-protocol upgrade the ableTLS kXR_protocol armed.

    Verification is off here on purpose: the client's trust decision is the
    subject of its own test above, and pinning it off keeps these cases about
    what the *server* does once the channel is encrypted."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=CONNECT_HOST)


def _login(sock):
    """Anonymous kXR_login.  On a krb5 listener a successful reply is kXR_ok
    with the `&P=krb5,<principal>` security token in the body — the session is
    open but nobody is authenticated yet; that only happens at kXR_auth."""
    sock.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    return _xrd_recv_status(sock)


def _auth_krb5(sock, payload):
    """kXR_auth carrying a credential tagged `krb5` (src/auth/krb5/auth.c)."""
    request = struct.pack(">BB H", 0, 3, 3000) + b"\x00" * 12 + b"krb5"
    request += struct.pack(">I", len(payload)) + payload
    sock.sendall(request)
    return _xrd_recv_status(sock)


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_krb5_authenticates_over_a_tls_upgraded_channel(krb5tls, pki):
    """The row itself: a ticket still authenticates once the channel upgrades,
    and the session stays usable for a real metadata op afterwards."""
    endpoint, _data = krb5tls
    result = _xrdfs(pki, endpoint.port, "stat", READ_FILE)
    assert result.returncode == 0, \
        f"krb5 stat over TLS failed: {result.stderr.decode(errors='replace')}"

    result = subprocess.run(
        ["xrdcp", "-f", f"{_url(endpoint.port)}/{READ_FILE}", "-"],
        env=_env(pki), capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == READ_BODY, result.stdout


def test_the_same_ticket_works_on_the_cleartext_plane(krb5tls, pki):
    """The attribution control.  One realm, one keytab, one ticket — if this
    passes and the TLS plane fails, the cross is what broke, not the tier."""
    endpoint, _data = krb5tls
    result = _xrdfs(pki, endpoint.extra_ports["PLAIN_PORT"], "stat", READ_FILE,
                    tls=False)
    assert result.returncode == 0, \
        f"the control plane rejected a good ticket: " \
        f"{result.stderr.decode(errors='replace')}"


def test_a_write_survives_the_tls_upgrade(krb5tls, pki, tmp_path):
    """Success in the other data direction.  A read proves the server can send
    under the upgraded channel; only a write proves it can receive under it,
    and the round trip plus the on-disk bytes prove nothing was mangled by the
    TLS record layer on the way through."""
    endpoint, data = krb5tls
    payload = bytes(range(256)) * 64          # 16 KiB, spans several records
    local = tmp_path / "upload.bin"
    local.write_bytes(payload)

    up = subprocess.run(
        ["xrdcp", "-f", str(local), f"{_url(endpoint.port)}//uploaded.bin"],
        env=_env(pki), capture_output=True, timeout=60)
    assert up.returncode == 0, up.stderr.decode(errors="replace")
    assert (data / "uploaded.bin").read_bytes() == payload, \
        "the bytes that landed on disk are not the bytes that were sent"

    down = subprocess.run(
        ["xrdcp", "-f", f"{_url(endpoint.port)}//uploaded.bin", "-"],
        env=_env(pki), capture_output=True, timeout=60)
    assert down.returncode == 0, down.stderr.decode(errors="replace")
    assert down.stdout == payload


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

def test_no_ticket_is_denied_over_tls(krb5tls, pki, tmp_path):
    """The transport-is-not-identity case.  The TLS handshake completes exactly
    as it does above — same server, same trust store — and the client simply has
    no Kerberos credential.  If encryption were being read as authentication
    this is where it would show."""
    endpoint, _data = krb5tls
    empty = str(tmp_path / "no-such-ccache")
    result = _xrdfs(pki, endpoint.port, "stat", READ_FILE, ccache=empty)
    assert result.returncode != 0, \
        "a client with no Kerberos ticket was served over TLS"


def test_a_client_that_does_not_trust_the_host_cert_fails(krb5tls, pki):
    """The control for the TLS half.  Everything else here would pass just as
    well against a server whose certificate was never checked; pointing the
    client at a trust store holding a different CA is what proves the upgrade
    is a verified one.  The ticket is valid — only the trust store is wrong."""
    endpoint, _data = krb5tls
    result = _xrdfs(pki, endpoint.port, "stat", READ_FILE,
                    certs=pki["stranger"])
    assert result.returncode != 0, \
        "the client accepted a host cert signed by a CA it does not trust"


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

def test_the_krb5_listener_demands_tls_before_the_credential(krb5tls):
    """`brix_tls_require all` pointed at a krb5 listener, read off the wire.

    kXR_tlsLogin in the kXR_protocol reply is the server telling every client
    "do not send me a credential in the clear", and it is why the stock client
    upgrades even for a root:// URL.  On a krb5 plane that flag is what keeps
    the AP-REQ — and the session key derived from it — off the cleartext wire
    in the first place; a refusal after the fact would already be too late.

    The ungated plane is the control: same acceptor, same keytab, and it
    advertises no such requirement, so the flag belongs to the directive."""
    endpoint, _data = krb5tls

    # The upgrade this kXR_protocol arms is then COMPLETED before the socket is
    # dropped.  Walking away from an armed upgrade instead crashes the worker —
    # a defect with its own pin in test_audit15h_tls_upgrade_abort.py — and a
    # test that tripped it here would poison every case after it in this file.
    gated = _connect(endpoint.extra_ports["TLSREQ_PORT"])
    try:
        flags = _protocol_flags(gated)
        _upgrade(gated).close()
    finally:
        gated.close()
    assert flags & kXR_haveTLS, f"the TLS plane did not advertise TLS: {flags:#x}"
    for bit, name in ((kXR_tlsLogin, "login"), (kXR_tlsSess, "session"),
                      (kXR_tlsData, "data")):
        assert flags & bit, f"`all` did not demand TLS for {name}: {flags:#x}"

    plain = _connect(endpoint.extra_ports["PLAIN_PORT"])
    try:
        plain_flags = _protocol_flags(plain)
    finally:
        plain.close()
    assert not (plain_flags & kXR_tlsLogin), \
        f"the ungated plane demanded TLS for login too: {plain_flags:#x}"


def test_a_forged_ticket_is_refused_over_the_upgraded_channel(krb5tls):
    """Encrypting the channel must not soften the acceptor.

    Everything that reaches ``krb5_rd_req`` here arrives over a genuine TLS
    upgrade, so a server that took the upgrade as evidence of anything would
    show it by accepting a credential it cannot decrypt.  Two shapes: a bare
    4-byte tag with no AP-REQ body (the length guard) and a well-tagged blob of
    garbage (the guard behind it, real ticket verification)."""
    endpoint, _data = krb5tls

    for payload, what in ((b"krb5", "a 4-byte credential"),
                          (b"krb5" + bytes(range(64)), "a forged AP-REQ")):
        raw = _connect(endpoint.port)
        try:
            _protocol_flags(raw)
            sock = _upgrade(raw)
            status, body = _login(sock)
            assert status == KXR_OK, ("login failed over TLS", status, body)
            status, body = _auth_krb5(sock, payload)
            assert status == KXR_ERROR, (what, status, body)
            assert _errcode(body) == kXR_NotAuthorized, \
                (what, _errcode(body), body)
        finally:
            raw.close()


def test_an_unauthenticated_session_cannot_read_over_tls(krb5tls):
    """The transport-is-not-identity claim, at the point it is decided.

    The session below is fully upgraded and logged in — the server has answered
    kXR_login with its `&P=krb5` token — and simply never sends kXR_auth.  A
    server that let the TLS handshake stand in for the AP-REQ would serve this
    stat; the acceptor has to refuse it with kXR_NotAuthorized."""
    endpoint, _data = krb5tls

    raw = _connect(endpoint.port)
    try:
        _protocol_flags(raw)
        sock = _upgrade(raw)
        status, body = _login(sock)
        assert status == KXR_OK, (status, body)
        assert b"krb5" in body, \
            f"the login reply did not offer krb5 at all: {body!r}"

        status, body = _xrd_stat(sock, READ_FILE)
        assert status == KXR_ERROR, \
            ("an unauthenticated TLS session was served", status, body)
        assert _errcode(body) == kXR_NotAuthorized, (_errcode(body), body)
    finally:
        raw.close()


def test_no_ticket_is_denied_even_on_the_tls_required_plane(krb5tls, pki,
                                                            tmp_path):
    """The two policies are independent and both must hold.  Satisfying
    `brix_tls_require` says nothing about who the peer is, so a TLS client with
    no ticket has to be refused by the acceptor exactly as it is on the plane
    with no requirement at all."""
    endpoint, _data = krb5tls
    empty = str(tmp_path / "still-no-ccache")
    result = _xrdfs(pki, endpoint.extra_ports["TLSREQ_PORT"], "stat",
                    READ_FILE, ccache=empty)
    assert result.returncode != 0, \
        "meeting the TLS requirement was treated as meeting the auth one"
