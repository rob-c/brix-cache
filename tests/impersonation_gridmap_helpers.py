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
import hashlib
import hmac
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

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
# (brix_idmap_min_uid, hard-clamped to >=1000) admits them.  `-o` makes the ids
# non-unique so a stray pre-existing account at the same number cannot fail us.
ACCOUNTS: "dict[str, int]" = {
    "alice": 61001,
    "bob": 61002,
    "squash": 61003,
}


def acct(name: str) -> str:
    """Local system account name for a logical principal ('alice' -> 'brixgm_alice')."""
    return ACCT_PREFIX + name


def uid_of(name: str) -> int:
    return pwd.getpwnam(acct(name)).pw_uid


def gid_of(name: str) -> int:
    return pwd.getpwnam(acct(name)).pw_gid


def _tools_present() -> bool:
    return all(shutil.which(t) for t in ("useradd", "userdel", "groupadd", "groupdel"))


def reap_accounts() -> None:
    """Remove every brixgm_* account/group. Idempotent; ignores failures."""
    for u in [p.pw_name for p in pwd.getpwall() if p.pw_name.startswith(ACCT_PREFIX)]:
        subprocess.run(["userdel", "-r", u], capture_output=True)
    for name in ACCOUNTS:
        subprocess.run(["groupdel", acct(name)], capture_output=True)


def provision_accounts() -> None:
    """Create brixgm_<name> nologin system users at fixed uid==gid. Crash-safe:
    sweeps first so a leaked prior run cannot poison the box."""
    reap_accounts()
    for name, uid in ACCOUNTS.items():
        u = acct(name)
        subprocess.run(["groupadd", "-o", "-g", str(uid), u],
                       check=True, capture_output=True)
        subprocess.run(
            ["useradd", "-M", "-N", "-o", "-u", str(uid), "-g", str(uid),
             "-s", "/usr/sbin/nologin", u],
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
