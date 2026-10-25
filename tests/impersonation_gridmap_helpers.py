"""Helpers for the host-root grid-mapfile impersonation suite
(test_impersonation_gridmap_root.py).

These back tests that can ONLY be exercised when the nginx binary is launched as
real root: `brix_idmap map` makes the master spawn a privileged broker
that setfsuid()s to the local account an authenticated identity maps to via a
grid-mapfile, so backend files land owned by that real UNIX user.  Proving that
requires real system accounts and a real setfsuid — impossible without root.

Everything here is deliberately self-contained (own account prefix, own PKI-free
token authority, own export tree) so the suite integrates with the registry
LifecycleHarness without disturbing the multi-user conformance fleet
(mu_authz_lib/, which uses `brix_idmap off`).
"""
from __future__ import annotations

import datetime as _dt
import errno
import hashlib
import hmac
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote
import pytest

from lib_py.util import nologin_shell
from lib_py import account_host

# utils/ lives at the repo root, one level above tests/.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from utils.make_token import TokenIssuer  # noqa: E402

# --------------------------------------------------------------------------- #
# Real local accounts                                                         #
# --------------------------------------------------------------------------- #
# Distinct prefix from the MU suite's ``brixtest_`` so the two never collide.
ACCT_PREFIX = "brixgm_"

# name -> uid (== gid).  All >= 1000 so the impersonation reserved-id floor
# (brix_idmap_min_uid, hard-clamped to >=1000) admits them. Ids must be
# unique: a foreign account/group collision must fail rather than alias it.
ACCOUNTS: "dict[str, int]" = {
    "alice": 61001,
    "bob": 61002,
    "squash": 61003,
    "broker": 61004,
}


def acct(name: str) -> str:
    """Local system account name for a logical principal ('alice' -> 'brixgm_alice')."""
    return ACCT_PREFIX + name


def uid_of(name: str) -> int:
    return pwd.getpwnam(acct(name)).pw_uid


def gid_of(name: str) -> int:
    return pwd.getpwnam(acct(name)).pw_gid


def _tools_present() -> bool:
    return account_host.available()


def reap_accounts() -> None:
    """Remove every brixgm_* account/group. Idempotent; ignores failures."""
    for u in [p.pw_name for p in pwd.getpwall() if p.pw_name.startswith(ACCT_PREFIX)]:
        subprocess.run(account_host.user_delete(u), capture_output=True)
    for name in ACCOUNTS:
        subprocess.run(account_host.group_delete(acct(name)), capture_output=True)


def provision_accounts() -> None:
    """Create brixgm_<name> nologin system users at fixed uid==gid. Crash-safe:
    sweeps first so a leaked prior run cannot poison the box."""
    reap_accounts()
    for name, uid in ACCOUNTS.items():
        u = acct(name)
        subprocess.run(account_host.group_add(u, uid),
                       check=True, capture_output=True)
        subprocess.run(
            account_host.user_add(u, uid, uid, nologin_shell()),
            check=True, capture_output=True)


# --------------------------------------------------------------------------- #
# Filesystem layout (world-traversable so the unprivileged worker can reach it) #
# --------------------------------------------------------------------------- #
def make_world_traversable(path: str) -> None:
    """Add o+x on every ancestor of `path` up to '/', so the `nobody` worker (and
    the broker impersonating a mapped uid) can traverse to the export/socket."""
    p = Path(path).resolve()
    for anc in [p, *p.parents]:
        if str(anc) == "/":
            break
        try:
            mode = anc.stat().st_mode & 0o777
            anc.chmod(mode | 0o001)
        except (PermissionError, FileNotFoundError):
            pass


def prepare_export(base: str, name: str) -> "tuple[str, str, str]":
    """Create <base>/<name>/{export,run,auth} and return (export, run_dir, auth_dir).

    - export is 0777 so any mapped user may create files in it (the broker writes
      as the mapped user, which does not own the dir);
    - run holds the broker socket, auth holds the grid-mapfile + token JWKS;
    - the whole chain is made traversable for the unprivileged worker/broker.
    """
    root = Path(base) / name
    export = root / "export"
    run_dir = root / "run"
    auth_dir = root / "auth"
    for d in (export, run_dir, auth_dir):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(export, 0o777)
    os.chmod(run_dir, 0o755)
    os.chmod(auth_dir, 0o755)
    make_world_traversable(str(export))
    return str(export), str(run_dir), str(auth_dir)


# --------------------------------------------------------------------------- #
# grid-mapfile                                                                #
# --------------------------------------------------------------------------- #
def write_gridmap(path: str, entries: "list[tuple[str, str]]") -> None:
    """Write a classic grid-mapfile: one `"<principal>" <localuser>` line each.
    Readable by the root master that loads it; world-readable is harmless."""
    lines = [f'"{principal}" {localuser}\n' for principal, localuser in entries]
    Path(path).write_text("".join(lines))
    os.chmod(path, 0o644)


# --------------------------------------------------------------------------- #
# Token authority (WLCG JWT — subject is the impersonation principal)          #
# --------------------------------------------------------------------------- #
ISSUER = "https://test.example.com"
AUDIENCE = "nginx-xrootd"
RW_SCOPE = "storage.read:/ storage.modify:/ storage.create:/"


def token_authority(auth_dir: str) -> TokenIssuer:
    """A signing authority whose jwks.json (0644, worker-readable) the WebDAV
    server validates against; the token `sub` is looked up in the grid-mapfile."""
    ti = TokenIssuer(auth_dir, issuer=ISSUER, audience=AUDIENCE)
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    os.chmod(ti.jwks_path, 0o644)
    return ti


# --------------------------------------------------------------------------- #
# X.509 proxy DN (the impersonation principal for GSI)                         #
# --------------------------------------------------------------------------- #
def _subject_oneline(pem_text: str) -> str:
    """OpenSSL oneline slash-form subject of the first cert in `pem_text`."""
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "compat"],
        input=pem_text, check=True, capture_output=True, text=True).stdout.strip()
    return out.split("=", 1)[1] if out.startswith("subject=") else out


def _split_pem_certs(proxy_pem: str) -> "list[str]":
    """The PEM blocks of `proxy_pem`, leaf first, keys and other blocks dropped."""
    certs, cur = [], None
    for line in Path(proxy_pem).read_text().splitlines(keepends=True):
        if line.startswith("-----BEGIN CERTIFICATE"):
            cur = [line]
        elif cur is not None:
            cur.append(line)
            if line.startswith("-----END CERTIFICATE"):
                certs.append("".join(cur))
                cur = None
    return certs


def _is_rfc3820_proxy(pem_text: str) -> bool:
    """True iff the cert carries the RFC 3820 proxyCertInfo extension."""
    text = subprocess.run(
        ["openssl", "x509", "-noout", "-text"],
        input=pem_text, check=True, capture_output=True, text=True).stdout
    return "Proxy Certificate Information" in text


def proxy_leaf_dn(proxy_pem: str) -> str:
    """Slash-form subject of the proxy's LEAF cert, trailing /CN=<serial> and all.

    This is a per-SESSION string — a fresh delegation mints a new serial — so it
    is the identity a grid-mapfile must NOT be keyed on.  Kept for the tests that
    assert exactly that (see test_audit15h_authdb_delegation.py)."""
    return _subject_oneline(_split_pem_certs(proxy_pem)[0])


def proxy_eec_dn(proxy_pem: str) -> str:
    """Slash-form subject of the chain's End-Entity Cert — the grid-mapfile key.

    brix keys both authorization and impersonation on the EEC DN, not the leaf:
    the leaf's trailing proxy RDNs carry a serial that changes on every
    delegation, so a grid-mapfile line naming the leaf would map a user for
    exactly one session and then silently stop (`no UNIX mapping for principal
    ... -> deny`).  ``brix_gsi_extract_eec_dn`` finds it by walking the verified
    chain leaf-upwards to the first certificate WITHOUT the RFC 3820
    proxyCertInfo extension; this walks the same order over the PEM file so the
    fixture and the server agree by construction rather than by a literal a
    change in the test PKI could invalidate.

    Note the test PKI's own EEC subject ends in ``/CN=12345`` — that RDN is part
    of the user certificate, not a proxy layer, which is precisely why the shape
    has to be read from the extension instead of guessed from the name."""
    certs = _split_pem_certs(proxy_pem)
    for pem in certs:
        if not _is_rfc3820_proxy(pem):
            return _subject_oneline(pem)
    # Every cert in the file is a proxy: the EEC was not bundled, so the highest
    # proxy's ISSUER is the EEC.  Report the least-derived subject we can see.
    return _subject_oneline(certs[-1])


# --------------------------------------------------------------------------- #
# On-disk assertions                                                          #
# --------------------------------------------------------------------------- #
def stat_export(export: str, rel: str) -> os.stat_result:
    return os.stat(os.path.join(export, rel.lstrip("/")))


def native_creation_gid(export: str, logical: str) -> int:
    """Probe this directory's real creation semantics under the mapped account.

    BSD normally inherits the directory gid even without its setgid bit. A
    direct, permanently dropped process is the oracle, not BriX's broker.
    """
    probe = str(Path(export) / f'.native-gid-{os.getpid()}-{time.time_ns()}')
    program = ('import os,sys; p=sys.argv[1]; '
               'f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); '
               's=os.fstat(f); os.close(f); os.unlink(p); print(s.st_uid,s.st_gid)')
    result = subprocess.run([os.path.realpath(sys.executable), '-c', program, probe],
        user=uid_of(logical), group=gid_of(logical), extra_groups=[gid_of(logical)],
        check=True, capture_output=True, text=True, timeout=10)
    actual_uid, actual_gid = map(int, result.stdout.split())
    assert actual_uid == uid_of(logical), 'independent identity probe did not drop uid'
    return actual_gid


# --------------------------------------------------------------------------- #
# S3 SigV4 (header auth, UNSIGNED-PAYLOAD) — the access key is the principal    #
# --------------------------------------------------------------------------- #
def s3_headers(method: str, path: str, host: str, *, access_key: str,
               secret_key: str, region: str) -> "dict[str, str]":
    """Minimal AWS SigV4 header-auth signer (UNSIGNED-PAYLOAD) for a PUT/GET on a
    path-style S3 endpoint. `access_key` is what the gateway records as the
    identity subject → the grid-mapfile principal."""
    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical = (f"{method}\n{quote(path, safe='/-_.~')}\n\n"
                 f"host:{host}\nx-amz-date:{amz_date}\n\n"
                 f"host;x-amz-date\nUNSIGNED-PAYLOAD")
    scope = f"{date}/{region}/s3/aws4_request"
    sts = (f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(("AWS4" + secret_key).encode(), date.encode(), hashlib.sha256).digest()
    k = hmac.new(k, region.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"s3", hashlib.sha256).digest()
    k = hmac.new(k, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                          f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }


# --------------------------------------------------------------------------- #
# Broker teardown                                                             #
# --------------------------------------------------------------------------- #
def reap_broker(sock_path: str) -> None:
    """Reap the double-forked impersonation broker for an instance.

    The broker runs in its OWN session (init-reparented), so a graceful
    `nginx -s quit` on the master (which the registry teardown does) stops the
    master + workers but leaves the broker running.  The broker records its pid in
    ``<sock>.pid`` at startup; reap it directly so the suite leaks no privileged
    daemons."""
    pidfile = sock_path + ".pid"
    try:
        pid = int(Path(pidfile).read_text().strip())
    except (FileNotFoundError, ValueError, OSError):
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.3)


def _broker_pid(sock: str) -> int:
    """Wait for this fixture's broker to record its owned process identity."""
    for _ in range(50):
        try:
            return int(Path(sock + ".pid").read_text().strip())
        except (FileNotFoundError, ValueError, OSError):
            time.sleep(0.1)
    raise AssertionError(f"broker never recorded a pid at {sock}.pid")


def assert_mapped_read_ready(response, expected):
    """TCP/PID publication precedes setup; require an actual mapped backend read."""
    assert response.status_code == 200, (
        f'broker readiness read failed with HTTP {response.status_code}')
    assert response.content == expected, 'broker readiness read returned incorrect bytes'


def _fd_targets(pid: int) -> "dict[int, str]":
    """Read the actual native descriptor authority list, not a guessed empty set."""
    if sys.platform.startswith('freebsd'):
        from lib_py.process_host import native_descriptor_targets
        return native_descriptor_targets(pid)
    base = f"/proc/{pid}/fd"
    if not os.path.isdir(base):
        pytest.skip("descriptor introspection needs /proc (Linux)")
    out = {}
    for name in os.listdir(base):
        try:
            out[int(name)] = os.readlink(os.path.join(base, name))
        except OSError:
            continue
    return out


def _tcp_socket_inodes() -> "set[str]":
    """Every TCP/TCP6 socket inode on the host, from /proc/net."""
    out = set()
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(name).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9:
                out.add(fields[9])
    return out


def _assert_stdio_is_null(targets: "dict[int, str]") -> None:
    """Inherited stdio must not retain the launching supervisor's pipes."""
    bad = {fd: targets.get(fd) for fd in (0, 1, 2)
           if targets.get(fd) != "/dev/null"}
    assert not bad, f"broker stdio is {bad}, not /dev/null"


def _assert_no_network_socket(targets: "dict[int, str]") -> None:
    """Local IPC is expected; inherited TCP listeners are forbidden authority."""
    assert not any(target.startswith('network:') for target in targets.values()), targets
    inodes = {t[len("socket:["):-1] for t in targets.values()
              if t.startswith("socket:[")}
    held = inodes & _tcp_socket_inodes()
    assert not held, f"broker holds inherited TCP socket(s) {sorted(held)}: {targets}"


def _is_export_object(target: str, root: str) -> bool:
    """Distinguish a regular export file from its allowed directory anchor."""
    real = os.path.realpath(target.removesuffix(" (deleted)"))
    return real.startswith(root + os.sep) and os.path.isfile(real)


def _assert_no_export_object(targets: "dict[int, str]", export: str) -> None:
    """No inherited data handle may bypass mapped identity selection."""
    root = os.path.realpath(export)
    held = [target for target in targets.values() if _is_export_object(target, root)]
    assert not held, f"broker holds inherited handle(s) on export object(s) {held}"


def assert_listener_released(host, port):
    """A reusable listener may replace TIME_WAIT, but never a live listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        probe.listen(1)


def listener_release_control(case, host):
    """Prove release semantics against actual closed, active and TIME_WAIT sockets."""
    from ephemeral_port import free_port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, free_port(host)))
        server.listen(1)
        port = server.getsockname()[1]
        if case == 'active':
            with pytest.raises(OSError) as refused:
                assert_listener_released(host, port)
            assert refused.value.errno == errno.EADDRINUSE
            with socket.create_connection((host, port), timeout=2):
                pass
            return
        if case == 'timewait':
            with socket.create_connection((host, port), timeout=2) as client:
                accepted, _peer = server.accept()
                accepted.close()
                assert client.recv(1) == b''
        else:
            assert case == 'closed'
        server.close()
        assert_listener_released(host, port)
