"""pblock per-group multi-user authz + attribution suite (phase-80, P80.24).

One pblock-backed ``root://``-over-GSI server shared by grid users with **no
per-user server-side provisioning beyond a gridmap line + local account**.  The
posture (docs/05-operations/pblock-multiuser.md) is **gate decides, catalog
attests**:

  * the ``brix_authdb`` ``g``-rule gate makes every allow/deny decision from the
    gridmap-mapped local user's unix **group** membership (P80.21, resolved
    worker-side with no impersonation broker), and
  * the pblock catalog stamps each written object's ``uid`` from the request
    identity (P80.22) as ground-truth attribution — never as a second gate.

The **attribution oracle** is the analog of the S3 suite's ``mc admin trace``:
direct ``sqlite3`` queries against the pblock catalog, external to the server,
prove *who* owns *what* by joining ``objects.uid`` back to the ``ids`` registry
and recovering the writer's exact EEC DN.

Why this suite is root-only (skips cleanly otherwise):

  * the ``g``-rule groups come from ``getgrouplist`` of the gridmap-mapped local
    account, so real ``groupadd``/``useradd`` accounts are required, and
  * a real GSI proxy client (pyxrootd) drives the ``root://`` plane.

Off a root host — or without ``useradd``/pyxrootd/the shared GSI PKI — every
test skips, so the module is CI-safe everywhere.

Run privileged:
  sudo -E env PYTHONPATH=tests pytest tests/test_pblock_group_multiuser.py -v

Design note — the pblock POSIX layer vs. the gate.  pblock's ``*_cred`` slots
run their own catalog-internal POSIX mode-bit checks (``sd_pblock_ident.c``); a
no-VOMS GSI identity carries no VO, so each principal gets a *private* catalog
gid, which would make a shared group directory collide at the pblock layer.  To
realize the documented "gate is the sole enforcement point" posture we seed the
governed prefixes ``/phys`` and ``/eng`` as world-writable service-owned
directories (0777) directly in the catalog before launch: the pblock layer is
then permissive for every authenticated user (created files default to 0644, so
cross-group *reads* also pass it), leaving the ``g``-rule gate the sole
differentiator — and the catalog still stamps each object's true owner.
"""
from __future__ import annotations

import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import time
from types import SimpleNamespace

import pytest

import settings
import x509forge
from server_launcher import LifecycleHarness, launch_fleet_nginx
from server_registry import NginxInstanceSpec, endpoint_for
from settings import BIND_HOST

from cryptography import x509 as _x509
from cryptography.hazmat.primitives import serialization as _ser

def _expression_1(ca, proxies_dir):
    return (
        {u: _mint_proxy(ca, CN[u], proxies_dir, 200001 + i)
                       for i, u in enumerate(USERS)}
    )


def _guard_server_1(f):
    if not os.path.exists(f):
        pytest.skip(f"GSI PKI not provisioned ({f} missing)")

def _guard_server_2(cat):
    if not os.path.exists(cat):
        _seed_world_writable_dirs(cat, ["/phys", "/eng"])


pytestmark = [
    pytest.mark.privileged,  # conftest auto-marks privileged tests serial
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="pblock g-rule gate needs real local accounts "
                              "(getgrouplist) + a real GSI proxy client"),
]

BIND = BIND_HOST
BASE = os.path.join(settings.TEST_ROOT, "pbgm")

# --------------------------------------------------------------------------- #
# Local accounts + groups (distinct prefix so they never collide with other    #
# suites' brixgm_/brixtest_ accounts).                                          #
# --------------------------------------------------------------------------- #
GRP_PREFIX = "brixpg_"

# unix group name -> gid.  The g-rules reference these names verbatim.
GROUPS = {"brixpg_phys": 62001, "brixpg_eng": 62002}

# logical user -> (system account, uid, primary unix group, logical group).
USERS = {
    "pa": ("brixpg_pa", 62011, "brixpg_phys", "phys"),
    "pb": ("brixpg_pb", 62012, "brixpg_phys", "phys"),
    "ea": ("brixpg_ea", 62013, "brixpg_eng", "eng"),
}

# GSI principal (EEC common-name) per logical user, plus one deliberately
# unmapped principal that authenticates (same CA) but has no gridmap line.
CN = {"pa": "pblock-pa", "pb": "pblock-pb", "ea": "pblock-ea"}
CN_UNMAPPED = "pblock-nobody"

# EEC DN is what brix keys authz/ownership on post-P80.11 (proxy serial stripped);
# X509_NAME_oneline renders the slash form in the order the RDNs were built.
def _eec_dn(cn: str) -> str:
    return f"/DC=test/DC=xrootd/CN={cn}"


# --------------------------------------------------------------------------- #
# Account provisioning                                                         #
# --------------------------------------------------------------------------- #
def _tools_present() -> bool:
    return all(shutil.which(t)
               for t in ("useradd", "userdel", "groupadd", "groupdel"))


def _reap_accounts() -> None:
    for acct, *_ in USERS.values():
        subprocess.run(["userdel", "-r", acct], capture_output=True)
    for grp_name in GROUPS:
        subprocess.run(["groupdel", grp_name], capture_output=True)


def _provision_accounts() -> None:
    _reap_accounts()  # crash-safe: sweep a leaked prior run first
    for grp_name, gid in GROUPS.items():
        subprocess.run(["groupadd", "-o", "-g", str(gid), grp_name],
                       check=True, capture_output=True)
    for acct, uid, primary_grp, _ in USERS.values():
        subprocess.run(
            ["useradd", "-M", "-N", "-o", "-u", str(uid), "-g", primary_grp,
             "-s", "/usr/sbin/nologin", acct],
            check=True, capture_output=True)


@pytest.fixture(scope="module", autouse=True)
def _accounts():
    if not _tools_present():
        pytest.skip("useradd/userdel/groupadd/groupdel not available")
    _provision_accounts()
    try:
        yield
    finally:
        _reap_accounts()


# --------------------------------------------------------------------------- #
# PKI: reuse the shared GSI CA + host cert, mint one proxy per principal.       #
# --------------------------------------------------------------------------- #
def _load_ca() -> x509forge.Cert:
    with open(settings.CA_CERT, "rb") as f:
        ca_cert = _x509.load_pem_x509_certificate(f.read())
    with open(settings.CA_KEY, "rb") as f:
        ca_key = _ser.load_pem_private_key(f.read(), password=None)
    return x509forge.Cert(ca_cert, ca_key)


def _mint_proxy(ca: x509forge.Cert, cn: str, out_dir: str, serial: int) -> str:
    """Mint an EEC (under the CA's ``/DC=test/DC=xrootd/*`` signing policy) and a
    valid RFC 3820 proxy off it; write the standard GSI proxy file
    (proxy cert + EEC chain + proxy key, 0600) and return its path."""
    # not_after must clear x509forge's fixed 2026-01-01 epoch (default proxy
    # validity is 1 day → long-expired); clientAuth EKU mirrors a real user cert.
    eec = x509forge.make_eec(ca, dn=_eec_dn(cn), not_after_days=4000,
                             eku=["1.3.6.1.5.5.7.3.2"])
    proxy = x509forge.make_proxy(eec, kind="rfc3820", not_after_days=4000,
                                 serial=serial)
    path = os.path.join(out_dir, f"proxy_{cn}.pem")
    with open(path, "wb") as f:
        f.write(proxy.pem)
        f.write(eec.pem)
        f.write(proxy.key_pem)
    os.chmod(path, 0o600)
    return path


# --------------------------------------------------------------------------- #
# Catalog seeding + oracle (direct sqlite3, external to the server)            #
# --------------------------------------------------------------------------- #
_OBJECTS_DDL = (
    "CREATE TABLE IF NOT EXISTS objects("
    "  path TEXT PRIMARY KEY, parent TEXT NOT NULL, is_dir INTEGER NOT NULL,"
    "  blob_id TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0,"
    "  block_size INTEGER NOT NULL DEFAULT 0, mtime INTEGER NOT NULL DEFAULT 0,"
    "  ctime INTEGER NOT NULL DEFAULT 0, mode INTEGER NOT NULL DEFAULT 0,"
    "  uid INTEGER NOT NULL DEFAULT 0, gid INTEGER NOT NULL DEFAULT 0,"
    "  xform TEXT NOT NULL DEFAULT '')"
)


def _seed_world_writable_dirs(db: str, dirs: "list[str]") -> None:
    """Pre-create governed prefixes as service-owned (uid/gid 0), world-writable
    directories so the pblock POSIX layer admits every authenticated user and the
    g-rule gate is the sole differentiator (see the module docstring)."""
    con = sqlite3.connect(db)
    try:
        con.execute(_OBJECTS_DDL)
        for d in dirs:
            con.execute(
                "INSERT OR REPLACE INTO objects(path, parent, is_dir, mode, "
                "uid, gid) VALUES(?, '/', 1, ?, 0, 0)",
                (d, stat.S_IFDIR | 0o777))
        con.commit()
    finally:
        con.close()


def _catalog_owner_dn(db: str, path: str) -> "str | None":
    """The writer's EEC DN recovered from the catalog: join the object's synthetic
    ``uid`` back to the ``ids`` registry (kind 0 = principal).  ``None`` if the
    object row is absent (a denied write leaves no trace)."""
    con = sqlite3.connect(db)
    try:
        row = con.execute(
            "SELECT i.name FROM objects o JOIN ids i "
            "ON i.kind = 0 AND i.id = o.uid WHERE o.path = ?", (path,)
        ).fetchone()
    finally:
        con.close()
    return row[0] if row else None


def _catalog_uid(db: str, path: str) -> "int | None":
    con = sqlite3.connect(db)
    try:
        row = con.execute("SELECT uid FROM objects WHERE path = ?",
                          (path,)).fetchone()
    finally:
        con.close()
    return row[0] if row else None


# --------------------------------------------------------------------------- #
# Server fixture                                                               #
# --------------------------------------------------------------------------- #
def _wait_tcp(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not become ready on {host}:{port}")


@pytest.fixture(scope="module")
def server(_accounts):
    for f in (settings.CA_CERT, settings.CA_KEY, settings.SERVER_CERT,
              settings.SERVER_KEY, settings.CA_DIR):
        _guard_server_1(f)

    root = os.path.join(BASE, "srv")
    data = os.path.join(root, "data")
    auth = os.path.join(root, "auth")
    proxies_dir = os.path.join(root, "proxies")
    for d in (data, auth, proxies_dir):
        os.makedirs(d, exist_ok=True)

    ca = _load_ca()
    proxies = _expression_1(ca, proxies_dir)
    proxies["unmapped"] = _mint_proxy(ca, CN_UNMAPPED, proxies_dir, 200099)

    # gridmap: mapped principals only — CN_UNMAPPED is deliberately absent.
    gridmap = os.path.join(auth, "gridmap")
    with open(gridmap, "w", encoding="utf-8") as f:
        for u, (acct, *_rest) in USERS.items():
            f.write(f'"{_eec_dn(CN[u])}" {acct}\n')
    os.chmod(gridmap, 0o644)

    # authdb: the whole per-group policy in three g-rules.
    authdb = os.path.join(auth, "authdb")
    with open(authdb, "w", encoding="utf-8") as f:
        f.write("g brixpg_phys /phys a\n"   # phys: full access on /phys
                "g brixpg_eng  /phys rl\n"  # eng: read + lookup only on /phys
                "g brixpg_eng  /eng  a\n")  # eng: full access on /eng
    os.chmod(authdb, 0o644)

    # Seed governed prefixes world-writable *before* the server opens the catalog.
    _seed_world_writable_dirs(os.path.join(data, "catalog.db"), ["/phys", "/eng"])

    harness = LifecycleHarness()
    spec = NginxInstanceSpec(
        name="pbgm-gsi",
        template="nginx_pblock_group_gsi.conf",
        protocol="root",
        data_root=data,
        readiness="tcp",
        template_values={
            "GRIDMAP": gridmap,
            "AUTHDB": authdb,
            "CERT": settings.SERVER_CERT,
            "KEY": settings.SERVER_KEY,
            "CA": settings.CA_DIR,
        },
    )
    try:
        unique = harness.register(spec)
        ep = endpoint_for(unique)
        harness.launcher.render_nginx(unique)   # writes conf, creates prefix
        # render may have created a fresh data dir; re-seed if the catalog got wiped.
        cat = os.path.join(data, "catalog.db")
        _guard_server_2(cat)
        harness.nginx_test(unique.name)
        launch_fleet_nginx(ep.config, prefix=ep.prefix)
        _wait_tcp(BIND, ep.port)
        yield SimpleNamespace(url=f"root://{BIND}:{ep.port}", data=data,
                              catalog=cat, proxies=proxies)
    finally:
        harness.close()
        shutil.rmtree(BASE, ignore_errors=True)


# --------------------------------------------------------------------------- #
# GSI root:// client helpers (pyxrootd)                                        #
# --------------------------------------------------------------------------- #
def _with_proxy(proxy: str):
    """Context-free env swap: point the pyxrootd GSI client at `proxy` + the
    shared trusted-CA dir, returning a restore callback."""
    prev = {k: os.environ.get(k) for k in ("X509_USER_PROXY", "X509_CERT_DIR")}
    os.environ["X509_USER_PROXY"] = proxy
    os.environ["X509_CERT_DIR"] = settings.CA_DIR

    def restore():
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def _write(server, proxy: str, path: str, data: bytes = b"payload"):
    from XRootD import client
    from XRootD.client.flags import OpenFlags
    restore = _with_proxy(proxy)
    try:
        f = client.File()
        st, _ = f.open(server.url + "/" + path.lstrip("/"),
                       OpenFlags.NEW | OpenFlags.WRITE)
        if not st.ok:
            return st
        wst, _ = f.write(data)
        f.close()
        return wst
    finally:
        restore()


def _read(server, proxy: str, path: str):
    from XRootD import client
    from XRootD.client.flags import OpenFlags
    restore = _with_proxy(proxy)
    try:
        f = client.File()
        st, _ = f.open(server.url + "/" + path.lstrip("/"), OpenFlags.READ)
        if not st.ok:
            return st, None
        rst, data = f.read()
        f.close()
        return rst, data
    finally:
        restore()


def _denied(st) -> bool:
    """A gate denial surfaces as a not-ok status; NotAuthorized is kXR 3010."""
    return (not st.ok) and (st.errno == 3010 or "auth" in (st.message or "").lower()
                            or "permission" in (st.message or "").lower())


# --------------------------------------------------------------------------- #
# Grant: a group member reads+writes its own space, and the catalog attests    #
# the object to that member's exact DN.                                        #
# --------------------------------------------------------------------------- #
def test_phys_member_writes_phys_and_catalog_attests_owner(server):
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    st = _write(server, server.proxies["pa"], "/phys/pa.dat", b"from-pa")
    assert st.ok, f"phys member write on /phys must succeed: {st.message}"
    # Attribution oracle: the object's synthetic owner resolves to pa's EEC DN.
    assert _catalog_owner_dn(server.catalog, "/phys/pa.dat") == _eec_dn(CN["pa"])

    rst, data = _read(server, server.proxies["pa"], "/phys/pa.dat")
    assert rst.ok and data == b"from-pa", "owner must read its own object back"


def test_distinct_members_stamp_distinct_owners(server):
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    assert _write(server, server.proxies["pa"], "/phys/pa2.dat").ok
    assert _write(server, server.proxies["pb"], "/phys/pb.dat").ok
    # Two different principals → two different synthetic uids, each traceable to
    # its own DN: the catalog is per-identity, not a squashed service owner.
    assert _catalog_owner_dn(server.catalog, "/phys/pa2.dat") == _eec_dn(CN["pa"])
    assert _catalog_owner_dn(server.catalog, "/phys/pb.dat") == _eec_dn(CN["pb"])
    assert _catalog_uid(server.catalog, "/phys/pa2.dat") \
        != _catalog_uid(server.catalog, "/phys/pb.dat")


def test_eng_member_reads_phys_but_write_is_denied(server):
    """Read-only crossing: the eng g-rule grants r+l on /phys, so an eng member
    reads a phys object, but a write returns kXR 3010 at the gate — and leaves no
    catalog row (the write never reached the backend)."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    assert _write(server, server.proxies["pa"], "/phys/shared.dat", b"hi").ok

    rst, data = _read(server, server.proxies["ea"], "/phys/shared.dat")
    assert rst.ok and data == b"hi", "eng member must read /phys (rl grant)"

    st = _write(server, server.proxies["ea"], "/phys/eng_attempt.dat")
    assert _denied(st), f"eng write on /phys must be denied (3010): {st.message}"
    assert _catalog_owner_dn(server.catalog, "/phys/eng_attempt.dat") is None


def test_eng_member_writes_own_space(server):
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    st = _write(server, server.proxies["ea"], "/eng/ea.dat", b"from-ea")
    assert st.ok, f"eng member write on /eng must succeed: {st.message}"
    assert _catalog_owner_dn(server.catalog, "/eng/ea.dat") == _eec_dn(CN["ea"])


# --------------------------------------------------------------------------- #
# Deny: cross-group both directions + fail-closed unmapped principal.          #
# --------------------------------------------------------------------------- #
def test_phys_member_denied_on_eng_space(server):
    """The other crossing direction: a phys member has no rule granting them /eng,
    so a write there is denied — cross-group isolation is symmetric."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    st = _write(server, server.proxies["pa"], "/eng/phys_attempt.dat")
    assert _denied(st), f"phys write on /eng must be denied (3010): {st.message}"
    assert _catalog_owner_dn(server.catalog, "/eng/phys_attempt.dat") is None


def test_unmapped_dn_denied_everywhere(server):
    """A principal that authenticates (same CA) but has no gridmap line maps to no
    local user, resolves to no groups, and matches no g-rule under a governed
    prefix: denied on both spaces, never a silent fall-through to a group grant."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    for space in ("/phys/x.dat", "/eng/x.dat"):
        st = _write(server, server.proxies["unmapped"], space)
        assert _denied(st), f"unmapped DN must be denied on {space}: {st.message}"
        assert _catalog_owner_dn(server.catalog, space) is None
