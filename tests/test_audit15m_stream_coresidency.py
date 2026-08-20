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

def test_the_door_serves_its_own_export_and_not_the_root_backend(cores):
    """`brix_gridftp_export` wins; the `brix_storage_backend` written three
    lines above it on the same listener is inert on the FTP surface."""
    endpoint, _ = cores
    sock = _ftp_connect(endpoint.extra_ports["GRIDFTP_PORT"])
    try:
        mine = _ftp_cmd(sock, "MLST /door.txt")
        theirs = _ftp_cmd(sock, "MLST /decoy.txt")
    finally:
        sock.close()

    assert mine.startswith(b"250"), (
        f"the door cannot see its own brix_gridftp_export: {mine!r}")
    assert b"/door.txt" in mine, mine
    assert theirs.startswith(b"550"), (
        "the root-plane brix_storage_backend leaked into the door's namespace: "
        f"{theirs!r}")


def test_the_shadowed_root_export_on_the_door_answers_nothing(cores):
    """The other half of the same fact: the FTP command parser owns the socket,
    so the root export declared on that port is not merely a different tree —
    it is unreachable.  An xrootd handshake gets no reply at all."""
    endpoint, _ = cores
    sock = socket.create_connection((HOST, endpoint.extra_ports["GRIDFTP_PORT"]),
                                    timeout=10)
    sock.settimeout(4)
    try:
        sock.recv(128)                                  # the FTP banner
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        sock.sendall(struct.pack(">2sHIBB10sI", b"\x00\x01", 3006, 0x00000520,
                                 0x00, 0x03, b"\x00" * 10, 0))
        with pytest.raises((socket.timeout, ConnectionError)):
            got = sock.recv(64)
            raise AssertionError(
                f"the shadowed root export answered the handshake: {got!r}")
    finally:
        sock.close()


def test_the_door_refuses_a_path_that_climbs_out_of_its_export(cores):
    """Security-negative for the pair: the decoy tree is the door's sibling on
    disk, so a traversal that escaped `brix_gridftp_export` would reach a file
    that demonstrably exists."""
    endpoint, _ = cores
    sock = _ftp_connect(endpoint.extra_ports["GRIDFTP_PORT"])
    try:
        escaped = _ftp_cmd(sock, "MLST /../decoy/decoy.txt")
        escaped_rel = _ftp_cmd(sock, "MLST ../decoy/decoy.txt")
    finally:
        sock.close()

    assert not escaped.startswith(b"250"), (
        f"the door served a path outside its export: {escaped!r}")
    assert not escaped_rel.startswith(b"250"), (
        f"the door served a relative escape from its export: {escaped_rel!r}")


# --------------------------------------------------------------------------- #
# proto:gridftp × proto:root — DEFECT CANDIDATE #45.                           #
# --------------------------------------------------------------------------- #

def test_declaration_order_decides_which_protocol_owns_the_port(cores):
    """The two blocks differ in nothing but the order of `brix_root on` and
    `brix_gridftp on`; the last one written owns the handler."""
    endpoint, _ = cores

    door = _ftp_connect(endpoint.extra_ports["GRIDFTP_PORT"])
    door.close()

    shadow = socket.create_connection((HOST, endpoint.extra_ports["SHADOW_PORT"]),
                                      timeout=10)
    shadow.settimeout(3)
    try:
        with pytest.raises(socket.timeout):
            banner = shadow.recv(128)
            raise AssertionError(
                f"the shadowed door still greets on :SHADOW_PORT: {banner!r}", )
    finally:
        shadow.close()

    root = _connect_plain(endpoint.extra_ports["SHADOW_PORT"])
    try:
        status, body = _stat(root, "/decoy.txt")
    finally:
        root.close()

    assert status == kXR_ok, DEFECT45 + (
        f" (root did not win the port it was declared last on: "
        f"{status} {body!r})")


def test_two_stream_protocols_on_one_port_pass_nginx_t_without_a_word(tmp_path):
    """DEFECT CANDIDATE #45.  The damage is done to a tmp_path config."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root            on;
        brix_auth            none;
        brix_storage_backend posix:{tmp_path};
        brix_gridftp         on;
        brix_gridftp_export  {tmp_path};
""")

    assert rc == 0, DEFECT45 + f"\n{diag}"
    assert "emerg" not in diag, DEFECT45 + f"\n{diag}"
    assert "one brix protocol per port" not in diag, DEFECT45 + f"\n{diag}"


def test_the_http_plane_refuses_the_same_shape_by_name(tmp_path):
    """The control that makes #45 a defect rather than a design choice: the
    diagnostic exists, and one plane away it fires."""
    (tmp_path / "repo").mkdir(exist_ok=True)
    rc, diag = _nginx_t_http(tmp_path, f"""
        location /dav/ {{ brix_webdav on;
            brix_storage_backend posix:{tmp_path}; brix_webdav_auth none; }}
        location /cvmfs/ {{ brix_cvmfs on;
            brix_storage_backend posix:{tmp_path / "repo"}; }}
""")

    assert rc != 0, f"the http plane stopped refusing two protocols:\n{diag}"
    assert "one brix protocol per port" in diag, (
        f"the refusal is no longer the exclusivity check:\n{diag}")


def test_only_the_http_plane_has_a_protocol_exclusivity_check():
    """Structural anchor for #45: three stream modules assign cscf->handler and
    nothing arbitrates between them."""
    exclusive = (REPO / "src" / "protocols" / "shared" / "proto_exclusive.c").read_text()
    assert "brix_http_proto_exclusive_check" in exclusive, (
        "the exclusivity check moved; re-derive the guard-negatives above")

    sites = subprocess.run(["grep", "-rln", "cscf->handler =",
                            str(REPO / "src")],
                           capture_output=True, text=True, timeout=60).stdout
    owners = {Path(line).name for line in sites.split() if line.endswith(".c")}
    assert owners == {"server_conf.c", "ftp_module.c", "server_module.c"}, (
        "the set of stream handler owners changed; #45's blast radius is now "
        f"{sorted(owners)} and the config's comment needs re-deriving")

    for name in ("core/config/server_conf.c", "protocols/gridftp/ftp_module.c",
                 "net/cms/server_module.c"):
        src = (REPO / "src" / name).read_text()
        assert "proto_exclusive" not in src, (
            f"{name} now consults an exclusivity check — #45 may be fixed")


# --------------------------------------------------------------------------- #
# proto:tap_proxy × sec:readonly — DEFECT CANDIDATE #46.                       #
# --------------------------------------------------------------------------- #

def test_the_read_only_proxy_announces_a_read_only_export_at_startup(cores):
    """The banner is what an operator checks, and it agrees with the config."""
    endpoint, _ = cores
    log = _wait_for_log(endpoint, "root:// endpoint ready")

    assert 'export "/" (read-only)' in log, (
        "the proxy listener no longer reports itself read-only at startup; the "
        f"defect below may be fixed:\n{log[-2000:]}")


def test_reads_through_the_proxy_are_forwarded_to_the_origin(cores):
    """The positive half of the pair: a read-only proxy is still a proxy."""
    endpoint, _ = cores
    sock = _connect_plain(endpoint.port)
    try:
        status, body = _stat(sock, "/hello.txt")
        assert status == kXR_ok, f"stat through the proxy failed: {body!r}"
        status, body = _open(sock, "/hello.txt", kXR_open_read)
        assert status == kXR_ok, f"open through the proxy failed: {body!r}"
        fh = _fh(body)
        status, payload = _read(sock, fh, 0, 64)
        _close(sock, fh)
    finally:
        sock.close()

    assert status == kXR_ok, f"read through the proxy failed: {payload!r}"
    assert payload == ORIGIN_BYTES, payload


def test_a_write_through_the_read_only_proxy_lands_on_the_origin_disk(cores):
    """DEFECT CANDIDATE #46."""
    endpoint, data = cores
    sock = _connect_plain(endpoint.port)
    try:
        status, body = _open(sock, "/written-by-proxy.txt",
                             kXR_mkpath | kXR_delete)
        assert status == kXR_ok, DEFECT46 + f" (open-new: {status} {body!r})"
        fh = _fh(body)
        wstatus, wbody = _write(sock, fh, 0, b"through the read-only proxy\n")
        _close(sock, fh)
    finally:
        sock.close()

    assert wstatus == kXR_ok, DEFECT46 + f" (write: {wstatus} {wbody!r})"
    landed = data / "origin" / "written-by-proxy.txt"
    assert landed.exists(), DEFECT46 + " (nothing was created at the origin)"
    assert landed.read_bytes() == b"through the read-only proxy\n", DEFECT46


def test_mkdir_through_the_read_only_proxy_creates_the_directory(cores):
    """DEFECT CANDIDATE #46 — namespace mutation, not just data."""
    endpoint, data = cores
    sock = _connect_plain(endpoint.port)
    try:
        status, body = _mkdir(sock, "/viaproxy")
    finally:
        sock.close()

    assert status == kXR_ok, DEFECT46 + f" (mkdir: {status} {body!r})"
    assert (data / "origin" / "viaproxy").is_dir(), DEFECT46


def test_rm_through_the_read_only_proxy_deletes_the_origin_file(cores):
    """DEFECT CANDIDATE #46, the destructive arm: the read-only endpoint is a
    delete-capable endpoint."""
    endpoint, data = cores
    doomed = data / "origin" / "doomed.txt"
    assert doomed.exists(), "fixture seed missing"

    sock = _connect_plain(endpoint.port)
    try:
        status, body = _rm(sock, "/doomed.txt")
    finally:
        sock.close()

    assert status == kXR_ok, DEFECT46 + f" (rm: {status} {body!r})"
    assert not doomed.exists(), DEFECT46 + " (the origin file survived)"


def test_the_same_directive_on_a_non_proxy_listener_refuses_every_write(cores):
    """The control that makes #46 the proxy's doing and not the directive's:
    `brix_allow_write on; brix_read_only on;` on the mirrored block refuses
    open-new, mkdir and rm with the documented message."""
    endpoint, data = cores
    sock = _connect_plain(endpoint.extra_ports["SHADOW_PORT"])
    try:
        opened = _open(sock, "/nope.txt", kXR_mkpath | kXR_delete)
        made = _mkdir(sock, "/nope")
        removed = _rm(sock, "/decoy.txt")
    finally:
        sock.close()

    for label, (status, body) in (("open-new", opened), ("mkdir", made),
                                  ("rm", removed)):
        assert status == kXR_error, f"{label} was not refused: {status} {body!r}"
        assert READ_ONLY_MSG in body, f"{label}: {body!r}"
    assert (data / "decoy" / "decoy.txt").exists(), (
        "the refused rm removed the file anyway")


def test_the_proxy_diversion_runs_before_the_write_gate(cores):
    """Structural anchor for #46: in `brix_root_dispatch()` the proxy branch
    returns, and the write gate lives in the dispatcher it never reaches."""
    dispatch = (REPO / "src" / "protocols" / "root" / "handshake"
                / "dispatch.c").read_text()
    write = (REPO / "src" / "protocols" / "root" / "handshake"
             / "dispatch_write.c").read_text()

    assert "conf->proxy.enable && ctx->login.auth_done" in dispatch, (
        "the proxy diversion moved; re-derive #46 from the new call site")
    assert "brix_dispatch_require_write" not in dispatch, (
        "the write gate now runs in dispatch.c — #46 may be fixed; check "
        "whether it runs before or after the proxy branch")
    assert "brix_dispatch_require_write" in write, (
        "the write gate moved out of dispatch_write.c")

    branch = dispatch.split("conf->proxy.enable && ctx->login.auth_done")[1]
    assert branch.split("\n")[1].strip().startswith("return brix_proxy_dispatch("), (
        "the proxy branch no longer returns unconditionally: " + branch[:160])


def test_a_storage_backend_declared_on_the_proxy_is_never_read(cores):
    """proto:tap_proxy × store:httpbe — the pair this file creates by existing.

    The proxy block names the same http origin the cluster member below reads,
    and the object that member serves with kXR_ok is "no such file" here: the
    diversion at dispatch.c:94 forwards to the upstream before any storage
    backend is consulted, so the declaration is inert rather than a second
    source of data."""
    endpoint, _ = cores

    proxied = _connect_plain(endpoint.port)
    try:
        via_proxy = _stat(proxied, "/httpspace/remote.txt")
    finally:
        proxied.close()

    member = _connect_plain(endpoint.extra_ports["HTTPBE_PORT"])
    try:
        direct = _stat(member, "/httpspace/remote.txt")
    finally:
        member.close()

    assert direct[0] == kXR_ok, (
        f"the http origin's object is not readable at all: {direct}")
    assert via_proxy[0] == kXR_error, (
        "the proxy served its own storage backend instead of forwarding: "
        f"{via_proxy}")
    assert b"No such file" in via_proxy[1], via_proxy[1]


def test_the_proxy_logs_the_write_it_should_have_refused(cores):
    """The tap log is the operator's evidence trail, and it shows the mutation
    crossing the read-only listener rather than being stopped at it."""
    endpoint, _ = cores
    sock = _connect_plain(endpoint.port)
    try:
        status, body = _open(sock, "/tapped-write.txt", kXR_mkpath | kXR_delete)
        if status == kXR_ok:
            _close(sock, _fh(body))
    finally:
        sock.close()

    log = _wait_for_log(endpoint, "/tapped-write.txt")
    assert '"op":"open"' in log and "/tapped-write.txt" in log, (
        DEFECT46 + f" (the tap never saw the open):\n{log[-2000:]}")


# --------------------------------------------------------------------------- #
# proto:tap_proxy × sec:tls — the pair that works.                             #
# --------------------------------------------------------------------------- #

def test_the_proxy_listener_advertises_tls_to_a_client_that_can_take_it(cores):
    endpoint, _ = cores
    tls, flags = _connect_tls(endpoint.port)
    try:
        assert flags & kXR_haveTLS, f"kXR_haveTLS missing: 0x{flags:08x}"
        assert flags & kXR_gotoTLS, f"kXR_gotoTLS missing: 0x{flags:08x}"
        assert tls.version() and tls.version().startswith("TLSv1."), tls.version()
    finally:
        tls.close()


def test_a_read_through_the_proxy_works_over_the_upgraded_session(cores):
    endpoint, _ = cores
    tls, _flags = _connect_tls(endpoint.port)
    try:
        status, body = _stat(tls, "/hello.txt")
        assert status == kXR_ok, f"stat over TLS failed: {body!r}"
        status, body = _open(tls, "/hello.txt", kXR_open_read)
        assert status == kXR_ok, f"open over TLS failed: {body!r}"
        fh = _fh(body)
        status, payload = _read(tls, fh, 0, 64)
        _close(tls, fh)
    finally:
        tls.close()

    assert status == kXR_ok, f"read over TLS failed: {payload!r}"
    assert payload == ORIGIN_BYTES, payload


def test_the_same_listener_still_serves_a_client_that_cannot_do_tls(cores):
    """`brix_tls on` arms the upgrade; it does not demand it.  Without this the
    TLS arm above would prove nothing about co-residency — the port would
    simply be a TLS port."""
    endpoint, _ = cores
    sock = _connect_plain(endpoint.port)
    try:
        status, body = _stat(sock, "/hello.txt")
    finally:
        sock.close()

    assert status == kXR_ok, f"the cleartext client was refused: {body!r}"


def test_a_client_that_claims_tls_and_then_speaks_cleartext_is_refused(cores):
    """Security-negative for the pair: the advertisement is a commitment.  A
    session that arms the upgrade and then sends a cleartext login must not be
    served — the bytes are parsed as a TLS record and the session dies."""
    endpoint, _ = cores
    sock = socket.create_connection((HOST, endpoint.port), timeout=10)
    sock.settimeout(10)
    try:
        flags = _handshake(sock, able_tls=True)
        assert flags & kXR_gotoTLS, f"the upgrade was not armed: 0x{flags:08x}"
        try:
            status, body = _login(sock)
        except (ConnectionError, socket.timeout, OSError) as exc:
            status, body = None, repr(exc).encode()
    finally:
        sock.close()

    assert status != kXR_ok, (
        f"a cleartext login was accepted after arming the upgrade: {body!r}")


# --------------------------------------------------------------------------- #
# store:httpbe × xfer:cms — a cluster member whose storage is a remote origin.  #
# --------------------------------------------------------------------------- #

def test_the_http_backed_member_serves_the_remote_object(cores):
    endpoint, _ = cores
    sock = _connect_plain(endpoint.extra_ports["HTTPBE_PORT"])
    try:
        status, body = _stat(sock, "/httpspace/remote.txt")
        assert status == kXR_ok, f"stat of the http-backed object: {body!r}"
        assert str(len(REMOTE_BYTES)).encode() in body, body
        status, body = _open(sock, "/httpspace/remote.txt", kXR_open_read)
        assert status == kXR_ok, f"open of the http-backed object: {body!r}"
        fh = _fh(body)
        status, payload = _read(sock, fh, 0, 64)
        _close(sock, fh)
    finally:
        sock.close()

    assert status == kXR_ok, f"read of the http-backed object: {payload!r}"
    assert payload == REMOTE_BYTES, payload


def test_the_http_backed_member_registers_as_a_cluster_client(cores):
    endpoint, _ = cores
    port = endpoint.extra_ports["HTTPBE_PORT"]
    log = _wait_for_log(endpoint, f"this node is a client (listen :{port}")

    assert f"this node is a client (listen :{port}" in log, (
        "the http-backed server never joined the cluster:\n" + log[-2000:])
    assert f"this node is a manager (listen :{endpoint.extra_ports['MGR_PORT']}" in log, (
        "the manager never announced itself:\n" + log[-2000:])


def test_a_path_the_http_origin_does_not_have_is_an_error(cores):
    """Security/error-negative: an absent object at the remote origin is an
    error at the member, not an empty success."""
    endpoint, _ = cores
    sock = _connect_plain(endpoint.extra_ports["HTTPBE_PORT"])
    try:
        status, body = _stat(sock, "/not-at-the-origin.txt")
        opened = _open(sock, "/not-at-the-origin.txt", kXR_open_read)
    finally:
        sock.close()

    assert status == kXR_error, f"stat of a missing object: {status} {body!r}"
    assert opened[0] == kXR_error, f"open of a missing object: {opened}"


# --------------------------------------------------------------------------- #
# proto:gridftp × xfer:cms — DEFECT CANDIDATE #47.                             #
# --------------------------------------------------------------------------- #

def test_the_gridftp_door_registers_into_the_cluster(cores):
    endpoint, _ = cores
    port = endpoint.extra_ports["GRIDFTP_PORT"]
    log = _wait_for_log(endpoint, f"this node is a client (listen :{port}")

    assert f"this node is a client (listen :{port}" in log, (
        "the door no longer registers; #47 may be fixed at the join:\n"
        + log[-2000:])


DOORSPACE = "/doorspace"          # the namespace the door alone registers


def _manager_targets(endpoint, want_port, prefix=DOORSPACE, tries=24, pause=0.5):
    """Ask the manager to place a path until it names `want_port`, collecting
    every answer on the way (registration takes a heartbeat or two).

    `prefix` is the namespace the query falls in, and it is the whole
    experiment: the door registers /doorspace and the http-backed member
    registers /httpspace, so which member answers is decided by the path.  Give
    either one `brix_cms_paths /` instead and it becomes a candidate for the
    other's subtree — srv_path_matches() (registry_select.c:28) short-circuits a
    bare "/" token to `return 1` before the directory-boundary logic runs — so
    the winner is whatever the load ladder picks, and a coin flip proves nothing
    about what the door does when it IS chosen."""
    seen = []
    for _ in range(tries):
        sock = _connect_plain(endpoint.extra_ports["MGR_PORT"])
        try:
            for status, body in (_dirlist(sock, prefix),
                                 _open(sock, f"{prefix}/door.txt",
                                       kXR_open_read)):
                if status == kXR_redirect:
                    seen.append(("redirect", *_redirect_target(body)))
                elif status == kXR_wait:
                    seen.append(("wait", "", struct.unpack(">i", body[:4])[0]))
                else:
                    seen.append(("status", repr(body[:40]), status))
        finally:
            sock.close()
        if any(kind == "redirect" and port == want_port for kind, _h, port in seen):
            return seen
        time.sleep(pause)
    return seen


def test_the_manager_redirects_xrootd_clients_to_the_gridftp_door(cores):
    """DEFECT CANDIDATE #47."""
    endpoint, _ = cores
    door = endpoint.extra_ports["GRIDFTP_PORT"]
    seen = _manager_targets(endpoint, door)

    assert any(kind == "redirect" and port == door for kind, _h, port in seen), (
        DEFECT47 + f" (the manager never named the door; answers were {seen[:8]})")


def test_the_endpoint_the_manager_redirects_to_speaks_ftp(cores):
    """DEFECT CANDIDATE #47 — following the redirect is the whole point: an
    xrootd client that obeys the manager lands on a GridFTP banner."""
    endpoint, _ = cores
    door = endpoint.extra_ports["GRIDFTP_PORT"]
    seen = _manager_targets(endpoint, door)
    assert any(kind == "redirect" and port == door for kind, _h, port in seen), (
        DEFECT47 + f" (no redirect to the door: {seen[:8]})")

    sock = socket.create_connection((HOST, door), timeout=10)
    sock.settimeout(5)
    try:
        banner = sock.recv(128)
    finally:
        sock.close()

    assert banner.startswith(FTP_BANNER), DEFECT47 + f" (banner was {banner!r})"


def test_the_manager_never_serves_the_data_itself(cores):
    """The fact the defect sits on: manager mode is a redirector, so whatever it
    names is what the client gets — there is no fallback that would mask #47."""
    endpoint, _ = cores
    seen = _manager_targets(endpoint, endpoint.extra_ports["GRIDFTP_PORT"])

    assert seen, "the manager answered nothing at all"
    assert all(kind in ("redirect", "wait") for kind, _h, _p in seen), (
        f"the manager served a request itself: {seen}")


def test_the_manager_sends_the_other_namespace_to_the_other_member(cores):
    """store:httpbe × xfer:cms, and the control that makes #47 an indictment
    rather than an accident: the same manager, asked for a path outside
    /doorspace, names the http-backed root member instead.  Placement is
    therefore doing its job — it is the door's registration, not a confused
    manager, that puts an xrootd client in front of an FTP banner."""
    endpoint, _ = cores
    httpbe = endpoint.extra_ports["HTTPBE_PORT"]
    door = endpoint.extra_ports["GRIDFTP_PORT"]

    seen = []
    for _ in range(24):
        sock = _connect_plain(endpoint.extra_ports["MGR_PORT"])
        try:
            status, body = _open(sock, "/httpspace/remote.txt", kXR_open_read)
        finally:
            sock.close()
        if status == kXR_redirect:
            seen.append(_redirect_target(body))
            if seen[-1][1] == httpbe:
                break
        time.sleep(0.5)

    assert any(port == httpbe for _h, port in seen), (
        f"the manager never placed /httpspace/remote.txt on the http-backed member: {seen[:8]}")
    assert all(port != door for _h, port in seen), (
        f"a path outside /doorspace was sent to the gridftp door: {seen[:8]}")


# --------------------------------------------------------------------------- #
# Guard-negatives.  Every one damages a tmp_path config; no tracked file is    #
# ever touched.                                                                #
# --------------------------------------------------------------------------- #

def _nginx_t(root, text):
    (root / "logs").mkdir(exist_ok=True)
    conf = root / "coresidency.conf"
    conf.write_text(text)
    inject_nginx_load_modules(conf)
    proc = subprocess.run([str(NGINX_BIN), "-t", "-p", str(root), "-c", str(conf)],
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stderr + proc.stdout


def _nginx_t_stream(root, body):
    return _nginx_t(root, f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
  server {{ listen {BIND_HOST}:13297;
{body}
  }}
}}
""")


def _nginx_t_http(root, body):
    return _nginx_t(root, f"""daemon off; error_log {root}/logs/e.log info;
pid {root}/n.pid; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ access_log off;
  server {{ listen {BIND_HOST}:13297;
{body}
  }}
}}
""")


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_the_tls_leg_needs_a_certificate(tmp_path):
    """Guard-negative for sec:tls on this plane: `brix_tls` is not a switch
    that silently degrades to cleartext when the identity is missing."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root            on;
        brix_auth            none;
        brix_storage_backend posix:{tmp_path};
        brix_tls             on;
""")

    assert rc != 0, f"brix_tls parsed with no certificate:\n{diag}"
    assert "brix_tls requires brix_certificate" in diag, diag


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_the_proxys_upstream_tls_leg_refuses_to_be_unauthenticated(tmp_path):
    """Security-negative on the tap proxy's own namespace: an upstream TLS leg
    with no CA is refused at parse time rather than opened MITM-able.  It is
    also the contrast that makes #46 sharp — the proxy's directives ARE
    validated where the module owns them; the write policy beside them is the
    one the module skips."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root                    on;
        brix_auth                    none;
        brix_storage_backend         posix:{tmp_path};
        brix_tap_proxy               on;
        brix_tap_proxy_upstream      {BIND_HOST}:13298;
        brix_tap_proxy_upstream_tls  on;
""")

    assert rc != 0, f"an unauthenticated proxy TLS upstream parsed:\n{diag}"
    assert "MITM-able TLS upstream" in diag, diag


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_a_door_needs_an_export_of_its_own(tmp_path):
    """Guard-negative for proto:gridftp × store:posix: a door will not fall
    back to the root plane's storage when its own export is missing — the two
    namespaces are disjoint at parse time as well as on the wire."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root            on;
        brix_auth            none;
        brix_storage_backend posix:{tmp_path};
        brix_gridftp         on;
""")

    assert rc != 0, f"a door with no export parsed:\n{diag}"
    assert "brix_gridftp_export is unset" in diag, diag


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_a_tap_proxy_with_no_upstream_at_all_still_parses(tmp_path):
    """Pinned as a fact, not a defect: the destination is the one part of the
    proxy's configuration nothing checks.  `brix_tap_proxy on` with no
    `brix_tap_proxy_upstream` passes `nginx -t` and the server starts, so the
    first client is the first thing to learn the proxy has nowhere to go —
    unlike the TLS leg above, which is refused before the port opens."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root            on;
        brix_auth            none;
        brix_storage_backend posix:{tmp_path};
        brix_tap_proxy       on;
""")

    assert rc == 0, (
        "an upstream-less tap proxy is now refused at parse time — that is an "
        f"improvement; delete this pin and record it:\n{diag}")


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_the_http_only_directives_are_refused_on_a_stream_listener(tmp_path):
    """Guard-negative for the plane split this tranche's remeasurement turned
    on: `brix_webdav` is http-only, which is why proto:tap_proxy × proto:webdav
    is a vacuous pair rather than an untested one."""
    rc, diag = _nginx_t_stream(tmp_path, f"""
        brix_root   on;
        brix_auth   none;
        brix_webdav on;
        brix_storage_backend posix:{tmp_path};
""")

    assert rc != 0, f"brix_webdav parsed inside stream {{}}:\n{diag}"
    assert "brix_webdav" in diag, diag


@pytest.mark.skipif(not os.access(NGINX_BIN, os.X_OK),
                    reason=f"nginx not executable: {NGINX_BIN}")
def test_the_stream_only_directives_are_refused_on_an_http_listener(tmp_path):
    """The mirror: `brix_tap_proxy` is stream-only, so no http-plane pair with
    it can exist."""
    rc, diag = _nginx_t_http(tmp_path, f"""
        location / {{ brix_webdav on; brix_webdav_auth none;
            brix_tap_proxy on;
            brix_storage_backend posix:{tmp_path}; }}
""")

    assert rc != 0, f"brix_tap_proxy parsed inside http {{}}:\n{diag}"
    assert "brix_tap_proxy" in diag, diag
