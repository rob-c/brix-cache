"""
test_audit15m_stream_coresidency.py — §Method step 3 at block granularity, the
STREAM plane (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

Tranche 11 re-ran the pairwise matrix per SERVER BLOCK instead of per file and
found 24 pairs that no single block in the tree runs; tranches 11 and 12 closed
the sixteen that live on the http plane (the S3 security cluster, then the
ordinary WLCG storage element).  Re-running the matrix after tranche 12 leaves
SIX, not the eight that tranche 12 reported, and the difference is a
measurement fix rather than new work: `proto:tap_proxy` was scored on the HTTP
plane by the matrix script, so it paired with `proto:webdav` and `proto:s3` —
two pairs that cannot exist, because `brix_tap_proxy` is
NGX_STREAM_SRV_CONF-only.  Correcting the plane dismisses both as vacuous.

What genuinely survives is entirely stream-plane, in two clusters:

    proto:tap_proxy × sec:tls · proto:tap_proxy × sec:readonly
    proto:gridftp × store:posix · proto:gridftp × proto:root
    proto:gridftp × xfer:cms · store:httpbe × xfer:cms

`nginx_audit15m_streamcores.conf` runs all six in one nginx: a writable posix
origin, the tap proxy that fronts it carrying both a TLS identity and a
read-only policy, a gridftp door carrying root-plane storage AND a CMS client
leg, the mirrored block that writes the same two protocol directives the other
way round, an http-backed data server that is also a cluster member, and the
manager's two faces.

WHAT THE BLOCK ESTABLISHES

- The gridftp namespace is disjoint, not overlaid: a door reads
  `brix_gridftp_export` and ignores the `brix_storage_backend` written beside
  it, so the decoy tree the root plane points at is invisible to FTP.
- `brix_tls` on a stream listener ARMS the in-protocol upgrade without
  demanding it: the same port serves a TLSv1.3 session and a client that
  advertises no TLS at all — but a client that advertises kXR_ableTLS and then
  speaks cleartext is refused, which is the upgrade being an actual commitment.
- An http-backed export works as a CMS member: it registers, and it serves the
  remote origin's bytes to a client that arrives directly.
- A remote `brix_storage_backend` declared on a proxy listener is inert for the
  same reason the door's is: the proxy diversion precedes storage, so the http
  origin's object is a "no such file" through the proxy and a 200 through the
  member — which is also the pair this file creates by existing
  (`proto:tap_proxy × store:httpbe`), carried in the proxy block rather than
  left as a fresh gap.
- `brix_read_only` works exactly as documented on a listener that serves its own
  storage — open-new, mkdir and rm all come back "this is a read-only server".

DEFECT CANDIDATE #45 (configuration, silent shadowing) — two brix protocols on
one STREAM listen port are accepted and resolved by declaration order.  The
http plane rejects that shape by name: `brix_http_proto_exclusive_check()`
(proto_exclusive.c:265) fails `nginx -t` with "one brix protocol per port".
The stream plane has no such check — three modules assign `cscf->handler` from
their own directive setter (`core/config/server_conf.c:365` root,
`protocols/gridftp/ftp_module.c:54` gridftp, `net/cms/server_module.c:126` cms)
and nothing arbitrates, so the LAST directive written owns the port and the
loser vanishes with no diagnostic at parse time and none at runtime.  The two
blocks this file runs differ in nothing but that order: one greets with "220
BriX GridFTP Gateway ready", the other answers kXR_stat, and an operator
reading either config would say both listeners serve both protocols.

DEFECT CANDIDATE #46 (security, fail-OPEN) — `brix_read_only on` is not
enforced on a tap-proxy listener.  `brix_shared_apply_read_only()` forces
`allow_write` off so that "EVERY existing write gate ... rejects writes at the
protocol edge" (shared_conf.h:135-144), and the startup banner duly announces
`root:// endpoint ready — export "/" (read-only)`.  But the proxy diversion in
`brix_root_dispatch()` runs FIRST: `if (conf->proxy.enable &&
ctx->login.auth_done) return brix_proxy_dispatch(...)` (dispatch.c:94) hands the
opcode to the upstream before `brix_dispatch_require_write()` is ever reached
(dispatch_write.c:159 → policy.c:188), so through a read-only proxy an open-new
succeeds, a write lands on the origin's disk, mkdir creates the directory and
rm DELETES the origin's file — every one of them kXR_ok.  The identical
directive on the non-proxy listener in the same nginx refuses all three.  A
site that fronts a writable origin with a "read-only" proxy — the standard
shape for a read-only cache in front of a writable SE — is publishing a
delete-capable endpoint.

DEFECT CANDIDATE #47 (clustering, protocol mismatch) — a gridftp door that
carries a CMS client leg registers as a data server, and the manager then
redirects XROOTD clients to it.  The door logs `cmsd role: this node is a
client (listen :<door port>)`, and every kXR_dirlist and kXR_open the manager
receives for the namespace the door registered comes back kXR_redirect to that
port — where the client that follows the redirect is greeted with "220 BriX
GridFTP Gateway ready" and can do nothing with it.  Nothing at parse time or at
registration time asks whether the advertised endpoint speaks the protocol the
cluster redirects.  The door registers /doorspace and the root member registers
/httpspace so that placement is decided by the path: a query in the other
namespace is placed on the root member, which is the control proving the manager
is choosing correctly and the registration is what is wrong.

NOT A DEFECT, PINNED AS A FACT.  `brix_storage_backend` on a door is inert
rather than dangerous — the door serves `brix_gridftp_export` and the decoy
tree stays invisible; and the root export shadowed on that same port answers
nothing at all, because the FTP command parser owns the socket.
"""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import time
from pathlib import Path

import pytest

from cmdscripts.live_common import inject_nginx_load_modules
from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN, BIND_HOST
from _test_proxy_mode_helpers import (_read_resp, _stat, _open, _fh, _read,
                                      _write, _close, _rm, _mkdir, _dirlist,
                                      kXR_ok, kXR_error, kXR_open_read,
                                      kXR_delete, kXR_mkpath)

def _guard_manager_targets_1(status, seen, body):
    if status == kXR_redirect:
        seen.append(("redirect", *_redirect_target(body)))
    elif status == kXR_wait:
        seen.append(("wait", "", struct.unpack(">i", body[:4])[0]))
    else:
        seen.append(("status", repr(body[:40]), status))


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15m-streamcores")]

REPO = Path(__file__).resolve().parents[1]

NAME = "lc-audit15m-streamcores"
CERT_HOST = "localhost"        # net-literal-allow: TLS certificate test identity

kXR_redirect = 4004
kXR_wait = 4005

kXR_haveTLS = 0x80000000
kXR_gotoTLS = 0x40000000

ORIGIN_BYTES = b"origin bytes\n"
DOOR_BYTES = b"ftp door bytes\n"
DECOY_BYTES = b"decoy bytes\n"
REMOTE_BYTES = b"http origin bytes\n"

FTP_BANNER = b"220 BriX GridFTP Gateway ready"
READ_ONLY_MSG = b"this is a read-only server"

DEFECT45 = (
    "DEFECT CANDIDATE #45 has been FIXED: two brix protocols on one stream "
    "listen port are no longer resolved by declaration order. Flip this "
    "expectation — `nginx -t` should refuse the pair the way "
    "brix_http_proto_exclusive_check() refuses it on the http plane.")
DEFECT46 = (
    "DEFECT CANDIDATE #46 has been FIXED: brix_read_only now binds on a "
    "tap-proxy listener. Flip this expectation — the write should be refused "
    "at the protocol edge with 'this is a read-only server', and nothing "
    "should change at the origin.")
DEFECT47 = (
    "DEFECT CANDIDATE #47 has been FIXED: the manager no longer redirects "
    "xrootd clients to a gridftp door. Flip this expectation — either the "
    "door must not register, or the redirect must name an xrootd endpoint.")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway CA and one server certificate for the proxy's client leg."""
    assert shutil.which("openssl"), (
        "openssl is required to build the TLS leg of the tap proxy")
    base = tmp_path_factory.mktemp("a15m-pki")
    ca_key, ca_pem = str(base / "ca.key"), str(base / "ca.pem")
    key, csr, cert = (str(base / "hostkey.pem"), str(base / "host.csr"),
                      str(base / "hostcert.pem"))

    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True,
                       timeout=60)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/O=brix-test/CN=audit15m streamcores CA",
            "-keyout", ca_key, "-out", ca_pem)
    openssl("req", "-nodes", "-newkey", "rsa:2048",
            "-subj", f"/O=brix-test/CN={CERT_HOST}",
            "-keyout", key, "-out", csr)
    ext = base / "host.ext"
    ext.write_text(f"subjectAltName=DNS:{CERT_HOST},IP:{HOST}\n"
                   "extendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
            "-CAcreateserial", "-days", "2", "-out", cert,
            "-extfile", str(ext))
    os.chmod(key, 0o600)
    return {"ca": ca_pem, "cert": cert, "key": key}


@pytest.fixture()
def cores(lifecycle, tmp_path, pki):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for sub in ("origin", "ftp", "decoy", "mgr", "httporigin"):
        (data / sub).mkdir(parents=True)
    (data / "origin" / "hello.txt").write_bytes(ORIGIN_BYTES)
    (data / "origin" / "doomed.txt").write_bytes(ORIGIN_BYTES)
    (data / "ftp" / "door.txt").write_bytes(DOOR_BYTES)
    (data / "decoy" / "decoy.txt").write_bytes(DECOY_BYTES)
    # The http origin's tree lives under the namespace its member registers,
    # so a client that follows the manager's redirect asks for a path the
    # member can actually resolve.
    (data / "httporigin" / "httpspace").mkdir()
    (data / "httporigin" / "httpspace" / "remote.txt").write_bytes(REMOTE_BYTES)

    export_root = tmp_path / "exports"
    (export_root / "httpbe").mkdir(parents=True)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15m_streamcores.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "EXPORT_ROOT": str(export_root),
                         "TMP_DIR": str(tmp),
                         "CERT": pki["cert"],
                         "KEY": pki["key"],
                         "CA": pki["ca"]},
        reason="audit-15m: the stream plane's protocols and policies in one nginx"))
    return endpoint, data


# --------------------------------------------------------------------------- #
# Wire helpers.  The proxy listener carries brix_tls, so the handshake has to   #
# say explicitly whether it can do TLS: _connect_plain advertises NO ableTLS    #
# bit, because advertising it arms the upgrade and the cleartext login that     #
# follows is then read as a TLS record.                                        #
# --------------------------------------------------------------------------- #

def _handshake(sock, able_tls):
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    sock.sendall(struct.pack(">2sHIBB10sI", b"\x00\x01", 3006, 0x00000520,
                             0x02 if able_tls else 0x00, 0x03, b"\x00" * 10, 0))
    sock.recv(16)
    status, body = _read_resp(sock)
    assert status == kXR_ok, f"kXR_protocol refused: {status} {body!r}"
    return struct.unpack(">I", body[4:8])[0] if len(body) >= 8 else 0


def _login(sock):
    sock.sendall(struct.pack(">2sHI8sBBBBI", b"\x00\x01", 3007,
                             os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00",
                             0, 0, 5, 0, 0))
    return _read_resp(sock)


def _connect_plain(port, host=None):
    """A cleartext session that never claims it can speak TLS."""
    sock = socket.create_connection((host or HOST, port), timeout=10)
    sock.settimeout(15)
    _handshake(sock, able_tls=False)
    status, body = _login(sock)
    assert status == kXR_ok, f"login refused on :{port}: {status} {body!r}"
    return sock


def _connect_tls(port):
    """The same session, taking the in-protocol upgrade brix_tls arms."""
    raw = socket.create_connection((CERT_HOST, port), timeout=10)
    raw.settimeout(15)
    flags = _handshake(raw, able_tls=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(raw, server_hostname=CERT_HOST)
    status, body = _login(tls)
    assert status == kXR_ok, f"login over TLS refused: {status} {body!r}"
    return tls, flags


def _ftp_connect(port, host=None):
    """Open the door, take the banner, log in anonymously."""
    sock = socket.create_connection((host or HOST, port), timeout=10)
    sock.settimeout(10)
    banner = sock.recv(128)
    assert banner.startswith(FTP_BANNER), (
        f"the door on :{port} did not greet with the gridftp banner: {banner!r}")
    _ftp_cmd(sock, "USER anonymous")
    _ftp_cmd(sock, "PASS brix@example.org")
    return sock


def _ftp_cmd(sock, line):
    sock.sendall(line.encode() + b"\r\n")
    time.sleep(0.2)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return b""


def _redirect_target(body):
    """A kXR_redirect body is a 4-byte port followed by the host."""
    return body[4:].decode(errors="replace"), struct.unpack(">i", body[:4])[0]


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        return (Path(endpoint.prefix) / "logs" / "error.log").read_text(
            errors="replace")
    except FileNotFoundError:
        return ""


def _wait_for_log(endpoint, needle, timeout=25.0):
    deadline = time.monotonic() + timeout
    while True:
        log = _errlog(endpoint)
        if needle in log:
            return log
        if time.monotonic() >= deadline:
            return ""
        time.sleep(0.25)


# --------------------------------------------------------------------------- #
# proto:gridftp × store:posix — whose namespace does a door actually serve?     #
# --------------------------------------------------------------------------- #

