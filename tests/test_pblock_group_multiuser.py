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

import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

import impersonation_gridmap_helpers as H
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
    # The POSIX layer must admit every authenticated user so the g-rule gate is
    # the sole differentiator (see the module docstring and
    # _seed_world_writable_dirs) — and the worker that has to create the block
    # files, the catalog and the checkpoint lock under here is neither root nor
    # the mapped account that owns this tree. A 0755 export made pblock init
    # itself fail with EACCES, so the catalog never existed and every case here
    # read back "no such table: ids".
    os.chmod(data, 0o777)
    H.make_world_traversable(data)

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
        # The template selects `brix_authdb_engine xrdacc`, whose authfile takes
        # ONE record per id carrying every <path> <privs> pair for it — a repeated
        # id is a duplicate and fails config, exactly as stock XrdAcc does. Two
        # `g brixpg_eng` lines (the native engine's one-rule-per-line idiom) killed
        # the worker at startup with "duplicate rule for id", and every test here
        # then hung on a server that was never up.
        f.write("g brixpg_phys /phys a\n"        # phys: full access on /phys
                "g brixpg_eng  /phys rl /eng a\n")  # eng: read+lookup on /phys, all on /eng
    os.chmod(authdb, 0o644)

    # Seed governed prefixes world-writable *before* the server opens the catalog.
    catalog = os.path.join(data, "catalog.db")
    _seed_world_writable_dirs(catalog, ["/phys", "/eng"])
    # Seeded as root; the worker that opens it is not root, and SQLite needs
    # write on the file itself (its -wal/-shm siblings the worker creates itself).
    os.chmod(catalog, 0o666)

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
# Each op runs in its OWN interpreter, one identity per process.  XrdCl pools a
# physical connection per (user, host, port) and authenticates it ONCE, so an
# in-process X509_USER_PROXY swap changes nothing: the second identity is handed
# the first identity's authenticated session.  That is not a hypothetical — it
# made pb's write land under pa's DN, let an unmapped DN through on pa's session
# and denied eng its own space on a phys session, i.e. every identity assertion
# in this module silently tested pa four times.  A process per op is how the rest
# of the suite keeps GSI identities apart (see the xrdfs/xrdcp subprocess idiom
# in test_release20_tlsca_residuals.py); this one keeps pyxrootd so the kXR
# errno (3010) stays readable, and reports the status as JSON.
_CLIENT_OP = r'''
import json, sys
from XRootD import client
from XRootD.client.flags import OpenFlags

url, mode, payload = sys.argv[1], sys.argv[2], sys.argv[3]
f = client.File()
st, _ = f.open(url, OpenFlags.READ if mode == "read"
                    else OpenFlags.NEW | OpenFlags.WRITE)
out = {"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or "",
       "data": None}
if st.ok:
    if mode == "read":
        rst, buf = f.read()
        out.update(ok=bool(rst.ok), errno=int(rst.errno),
                   message=rst.message or "",
                   data=bytes(buf).hex() if rst.ok else None)
    else:
        wst, _ = f.write(bytes.fromhex(payload))
        out.update(ok=bool(wst.ok), errno=int(wst.errno),
                   message=wst.message or "")
    f.close()
sys.stdout.write(json.dumps(out))
'''


def _url(server, path: str, lead: int = 1) -> str:
    """The object `path` spelled with `lead` slashes after the authority.

    The count is the client's choice and it changes what arrives on the wire:
    one slash sends the export-relative "phys/x", two send the absolute
    "/phys/x", three send "//phys/x".  All three name the same object — the I/O
    layer's brix_beneath_rel() strips every leading slash — so all three must get
    the same authorization verdict.  Default 1 (the relative spelling) because
    that is the one the authfile's absolute rules used to miss entirely."""
    return server.url + "/" * lead + path.lstrip("/")


def _client_op(server, proxy: str, path: str, mode: str, data: bytes = b"",
               lead: int = 1):
    """Run one open(+read/write) as `proxy` in a fresh interpreter; return a
    status object shaped like pyxrootd's (.ok/.errno/.message) plus .data."""
    env = dict(os.environ,
               X509_USER_PROXY=proxy,
               X509_CERT_DIR=settings.CA_DIR,
               XrdSecPROTOCOL="gsi")
    env.pop("BEARER_TOKEN", None)
    r = subprocess.run(
        [sys.executable, "-c", _CLIENT_OP,
         _url(server, path, lead), mode, data.hex()],
        capture_output=True, text=True, timeout=60, env=env)
    if r.returncode != 0 or not r.stdout:
        return SimpleNamespace(ok=False, errno=-1, data=None,
                               message=f"client op failed rc={r.returncode}: "
                                       f"{(r.stderr or '')[-400:]}")
    out = json.loads(r.stdout)
    return SimpleNamespace(ok=out["ok"], errno=out["errno"],
                           message=out["message"],
                           data=(bytes.fromhex(out["data"])
                                 if out["data"] is not None else None))


def _write(server, proxy: str, path: str, data: bytes = b"payload",
           lead: int = 1):
    return _client_op(server, proxy, path, "write", data, lead)


def _read(server, proxy: str, path: str, lead: int = 1):
    st = _client_op(server, proxy, path, "read", lead=lead)
    return st, st.data


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


# --------------------------------------------------------------------------- #
# One object, one verdict: the spelling the client picks for the path must not  #
# change the decision.  An authfile writes its rules absolute ("/phys"), but    #
# the client chooses how many slashes follow the authority, and the I/O layer   #
# treats every spelling as the same object (brix_beneath_rel strips them all).  #
# The gate used to match the raw string, so "phys/x" hit no rule at all — which #
# loses grants and, far worse, loses DENIES.  brix_acc_canon_path() gives the   #
# engine one spelling to match; these three pin the contract in both directions.#
# --------------------------------------------------------------------------- #
_SPELLINGS = [(1, "relative 'phys/x'"), (2, "absolute '/phys/x'"),
              (3, "doubled '//phys/x'")]


def test_grant_holds_in_every_path_spelling(server):
    """SUCCESS: a member's own-space grant applies however the path is spelled —
    each spelling writes a distinct object and each is attributed to that member."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    for lead, label in _SPELLINGS:
        obj = f"/phys/spell{lead}.dat"
        st = _write(server, server.proxies["pa"], obj, b"spelled", lead=lead)
        assert st.ok, f"phys member write must succeed with a {label} path: {st.message}"
        assert _catalog_owner_dn(server.catalog, obj) == _eec_dn(CN["pa"]), \
            f"a {label} path must attribute to the same DN as any other spelling"
        rst, data = _read(server, server.proxies["pa"], obj, lead=lead)
        assert rst.ok and data == b"spelled", f"read back must work for a {label} path"


def test_unmapped_dn_denied_in_every_path_spelling(server):
    """ERROR: the fail-closed verdict for a principal matching no rule is reached
    in every spelling — canonicalization must not turn "no rule" into a match."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    for lead, label in _SPELLINGS:
        obj = f"/phys/unmapped{lead}.dat"
        st = _write(server, server.proxies["unmapped"], obj, lead=lead)
        assert _denied(st), \
            f"unmapped DN must be denied with a {label} path: {st.message}"
        assert _catalog_owner_dn(server.catalog, obj) is None


def test_deny_cannot_be_dodged_by_respelling_the_path(server):
    """SECURITY-NEG: the attack the raw-string match allowed — an eng member has
    r+l but no write on /phys, and simply dropping the leading slash used to miss
    the "/phys" rule, so the write was evaluated against no rule under the governed
    prefix.  Every spelling must land on the same deny, and leave no catalog row
    and no object behind."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    for lead, label in _SPELLINGS:
        obj = f"/phys/dodge{lead}.dat"
        st = _write(server, server.proxies["ea"], obj, b"should-not-land", lead=lead)
        assert _denied(st), \
            f"eng write on /phys must stay denied with a {label} path: {st.message}"
        assert _catalog_owner_dn(server.catalog, obj) is None, \
            f"a {label} path must not create a catalog row for a denied write"
        # The deny is the whole point: the object must not be readable either,
        # by anyone, in any spelling.
        rst, _ = _read(server, server.proxies["pa"], obj, lead=2)
        assert not rst.ok, f"a denied {label} write must leave no readable object"
