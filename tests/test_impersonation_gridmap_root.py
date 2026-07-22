"""Host-root grid-mapfile UNIX-impersonation end-to-end tests (phase 40).

These tests can ONLY be exercised when the nginx binary is launched as **real
root**.  With ``brix_impersonation map`` the master runs as root and spawns a
privileged identity broker that ``setfsuid()``s per request to the local UNIX
account the authenticated identity maps to through a **grid-mapfile**; the backend
file is then created owned by — and DAC-checked for — that real account.  There is
no way to observe real on-disk ``st_uid``/``st_gid`` ownership, nor real kernel DAC
between two mapped accounts, without a real root master and real system users.

What is genuinely new here (vs. the existing coverage):

  * ``tests/userns/`` proves ownership WITHOUT real root, inside an unprivileged
    user namespace, and maps the *token subject* via ``getpwnam`` — never a
    grid-mapfile.
  * ``tests/c/idmap_test.c`` resolves a grid-mapfile DN to a uid but never writes
    a file.
  * the multi-user conformance fleet (``mu_authz_lib/``) runs
    ``brix_impersonation off``.

This module launches the real nginx binary as host root, through the registry
``LifecycleHarness``, maps an incoming **WLCG token** (WebDAV) and an incoming
**X.509 GSI proxy DN** (``root://``) via a grid-mapfile to real local accounts,
and asserts the written backend object is owned by the mapped account with sane
permissions — plus the security corollaries (per-identity kernel DAC, the
reserved-id floor, and fail-closed deny for unmapped principals).

Run privileged:  sudo -E env PYTHONPATH=tests pytest tests/test_impersonation_gridmap_root.py -v
Off a root host every test skips cleanly (the ``skipif`` below), so the suite is
CI-safe everywhere.
"""
from __future__ import annotations

import os
import pwd
import socket
import stat
import time
from types import SimpleNamespace

import pytest
import requests

import settings
from server_launcher import LifecycleHarness, launch_fleet_nginx
from server_registry import NginxInstanceSpec, endpoint_for

import impersonation_gridmap_helpers as H
from settings import BIND_HOST

# The whole point of the suite is the root-only setfsuid broker.  Off a root host
# there is nothing to prove — skip cleanly rather than fail.
pytestmark = [
    pytest.mark.privileged,  # conftest auto-marks privileged tests serial
    pytest.mark.skipif(os.geteuid() != 0,
                       reason="grid-mapfile impersonation ownership needs a real "
                              "root master + real setfsuid broker"),
]

BIND = BIND_HOST
BASE = os.path.join(settings.TEST_ROOT, "impgm")

# Token subjects used as grid-mapfile principals.
P_ALICE = "gm-alice"
P_BOB = "gm-bob"
P_ROOT = "gm-root"          # maps to the reserved `root` account on purpose
P_UNMAPPED = "gm-nobody-here"  # deliberately absent from every grid-mapfile

WORKER_UID = pwd.getpwnam("nobody").pw_uid  # the unprivileged nginx worker uid

# Broker socket paths of every instance this module launches — reaped on teardown
# (the double-forked broker survives the master's `nginx -s quit`).
_BROKER_SOCKS: "list[str]" = []


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module", autouse=True)
def _accounts():
    """Provision the real brixgm_* system accounts for the module; reap after."""
    if not H._tools_present():
        pytest.skip("useradd/userdel/groupadd not available")
    H.provision_accounts()
    try:
        yield
    finally:
        H.reap_accounts()


@pytest.fixture(scope="module")
def harness(_accounts):
    os.makedirs(BASE, exist_ok=True)
    os.chmod(BASE, 0o755)
    _BROKER_SOCKS.clear()
    h = LifecycleHarness()
    try:
        yield h
    finally:
        h.close()  # graceful `nginx -s quit`: reaps each master + its workers
        for sock in _BROKER_SOCKS:
            H.reap_broker(sock)  # the broker outlives the master — reap it too
        _BROKER_SOCKS.clear()
        import shutil
        shutil.rmtree(BASE, ignore_errors=True)


def _wait_tcp(host: str, port: int, deadline: float = 15.0) -> None:
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not become ready on {host}:{port}")


def _render_and_launch(harness, spec) -> object:
    """Render + validate through the registry harness, then launch via the
    detached fleet seam.

    We deliberately avoid ``harness.start()`` here: its launch pipes the child's
    stdout/stderr and waits for EOF, but ``brix_impersonation map`` double-forks a
    long-lived privileged broker during ``init_module`` (before nginx daemonizes),
    so the broker inherits and holds that pipe open forever.  ``launch_fleet_nginx``
    is the registry's own fire-and-forget seam (``start_new_session``, inherited
    fds) used for exactly this class of long-lived daemon; the instance is still
    registered, so ``harness.close()`` reaps it by pidfile on teardown.
    """
    unique = harness.register(spec)
    ep = endpoint_for(unique)
    harness.launcher.render_nginx(unique)   # write conf + create prefix dirs
    harness.nginx_test(unique.name)         # `nginx -t` as root (raises on error)
    launch_fleet_nginx(ep.config, prefix=ep.prefix)
    sock = spec.template_values.get("SOCK")  # single mode has no broker socket
    if sock:
        _BROKER_SOCKS.append(sock)
    _wait_tcp(BIND, ep.port)
    return ep


def _put(url: str, path: str, token: str, data: bytes = b"payload") -> requests.Response:
    return requests.put(url + path, data=data,
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)


def _get(url: str, path: str, token: str) -> requests.Response:
    return requests.get(url + path,
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)


def _start_webdav(harness, name, entries, default_user):
    """Bring up a WebDAV/token nginx instance under `brix_impersonation map` with
    the given grid-mapfile `entries` [(principal, localuser)]; `default_user` is a
    logical account name for squash mode, or None for fail-closed deny mode."""
    export, run_dir, auth_dir = H.prepare_export(BASE, name)
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, entries)
    ti = H.token_authority(auth_dir)
    default_line = (f"    brix_idmap_default_user {H.acct(default_user)};"
                    if default_user else "")
    ep = _render_and_launch(harness, NginxInstanceSpec(
        name=name,
        template="nginx_impersonate_gridmap_webdav.conf",
        protocol="http",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export,
            "SOCK": os.path.join(run_dir, "impersonate.sock"),
            "GRIDMAP": gridmap,
            "JWKS": ti.jwks_path,
            "ISSUER": H.ISSUER,
            "AUDIENCE": H.AUDIENCE,
            "DEFAULT_USER_LINE": default_line,
        },
    ))
    return SimpleNamespace(url=f"http://{BIND}:{ep.port}", export=export, ti=ti)


@pytest.fixture(scope="module")
def webdav_squash(harness):
    """map mode with a squash account: alice/bob mapped, gm-root -> reserved root,
    everything else squashes to brixgm_squash."""
    return _start_webdav(
        harness, "impgm-wd-squash",
        entries=[(P_ALICE, H.acct("alice")),
                 (P_BOB, H.acct("bob")),
                 (P_ROOT, "root")],
        default_user="squash",
    )


@pytest.fixture(scope="module")
def webdav_deny(harness):
    """map mode with NO default_user: unmapped / reserved principals fail closed."""
    return _start_webdav(
        harness, "impgm-wd-deny",
        entries=[(P_ALICE, H.acct("alice")),
                 (P_ROOT, "root")],
        default_user=None,
    )


@pytest.fixture(scope="module")
def single_mode(harness):
    """`brix_impersonation single`: every identity squashes to one fixed account
    (brixgm_squash), which is also the worker `user`. No broker, no grid-mapfile."""
    export, _run, auth_dir = H.prepare_export(BASE, "impgm-single")
    # The worker runs as the single account, so the export must be writable by it.
    os.chown(export, H.uid_of("squash"), H.gid_of("squash"))
    ti = H.token_authority(auth_dir)
    ep = _render_and_launch(harness, NginxInstanceSpec(
        name="impgm-single",
        template="nginx_impersonate_single_webdav.conf",
        protocol="http",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export,
            "JWKS": ti.jwks_path,
            "ISSUER": H.ISSUER,
            "AUDIENCE": H.AUDIENCE,
            "SINGLE_USER": H.acct("squash"),
        },
    ))
    return SimpleNamespace(url=f"http://{BIND}:{ep.port}", export=export, ti=ti)


def test_single_mode_squashes_every_identity_to_one_account(single_mode):
    """Two different token subjects both land files owned by the single configured
    account — `single` mode ignores identity and never yields root/other owners."""
    for sub, name in ((P_ALICE, "one.dat"), (P_BOB, "two.dat")):
        tok = single_mode.ti.generate(sub=sub, scope=H.RW_SCOPE)
        r = _put(single_mode.url, f"/{name}", tok)
        assert r.status_code in (200, 201, 204), r.text
        _assert_owned_by(H.stat_export(single_mode.export, name), "squash")


S3_ACCESS_KEY = "gm-alice-s3key"   # the SigV4 access key == impersonation principal
S3_SECRET = "gm-alice-s3secret"
S3_REGION = "us-east-1"
S3_BUCKET = "gmbucket"


@pytest.fixture(scope="module")
def s3_map(harness):
    """map mode S3 gateway: the SigV4 access key maps via the grid-mapfile to
    brixgm_alice; unmapped keys squash to brixgm_squash."""
    export, run_dir, auth_dir = H.prepare_export(BASE, "impgm-s3")
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, [(S3_ACCESS_KEY, H.acct("alice"))])
    ep = _render_and_launch(harness, NginxInstanceSpec(
        name="impgm-s3",
        template="nginx_impersonate_gridmap_s3.conf",
        protocol="http",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export,
            "SOCK": os.path.join(run_dir, "impersonate.sock"),
            "GRIDMAP": gridmap,
            "ACCESS_KEY": S3_ACCESS_KEY,
            "SECRET_KEY": S3_SECRET,
            "REGION": S3_REGION,
            "BUCKET": S3_BUCKET,
        },
    ))
    return SimpleNamespace(url=f"http://{BIND}:{ep.port}", host=f"{BIND}:{ep.port}",
                           export=export)


def test_s3_access_key_gridmap_write_owned_by_mapped_account(s3_map):
    """An S3 PUT authenticated with a SigV4 access key that the grid-mapfile maps
    to brixgm_alice lands the backend object owned by alice's real uid/gid — the
    S3 analogue of the token/X.509 cases (subject = the access key)."""
    obj = "s3_alice.dat"                  # object key; the bucket prefixes the URL
    path = f"/{S3_BUCKET}/{obj}"
    hdrs = H.s3_headers("PUT", path, s3_map.host, access_key=S3_ACCESS_KEY,
                        secret_key=S3_SECRET, region=S3_REGION)
    r = requests.put(s3_map.url + path, data=b"s3-object-from-alice", headers=hdrs,
                     timeout=30)
    assert r.status_code in (200, 201, 204), f"{r.status_code} {r.text}"
    st = H.stat_export(s3_map.export, obj)  # bucket is stripped from the on-disk path
    _assert_owned_by(st, "alice")


@pytest.fixture(scope="module")
def root_gsi(harness):
    """map mode root:// GSI server: the X.509 proxy leaf DN maps to brixgm_alice."""
    proxy = settings.PROXY_STD
    for f in (proxy, settings.SERVER_CERT, settings.SERVER_KEY):
        if not os.path.exists(f):
            pytest.skip(f"GSI PKI not provisioned ({f} missing)")
    export, run_dir, auth_dir = H.prepare_export(BASE, "impgm-root-gsi")
    dn = H.proxy_leaf_dn(proxy)
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, [(dn, H.acct("alice"))])
    ep = _render_and_launch(harness, NginxInstanceSpec(
        name="impgm-root-gsi",
        template="nginx_impersonate_gridmap_root.conf",
        protocol="root",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export,
            "SOCK": os.path.join(run_dir, "impersonate.sock"),
            "GRIDMAP": gridmap,
            "CERT": settings.SERVER_CERT,
            "KEY": settings.SERVER_KEY,
            "CA": settings.CA_DIR,
        },
    ))
    return SimpleNamespace(url=f"root://{BIND}:{ep.port}", export=export,
                           proxy=proxy, dn=dn)


# --------------------------------------------------------------------------- #
# Shared ownership assertion                                                   #
# --------------------------------------------------------------------------- #
def _assert_owned_by(st: os.stat_result, logical: str):
    """The written object is owned by the mapped real account, not the worker or
    root, and carries no group/other write bit (impersonation created it as the
    user, so it is a private, non-shared object)."""
    assert st.st_uid == H.uid_of(logical), (
        f"file uid {st.st_uid} != mapped {logical} uid {H.uid_of(logical)}")
    assert st.st_gid == H.gid_of(logical), (
        f"file gid {st.st_gid} != mapped {logical} gid {H.gid_of(logical)}")
    assert st.st_uid != 0, "file must never be owned by root"
    assert st.st_uid != WORKER_UID, "file must not be owned by the nginx worker"
    assert st.st_uid >= 1000, "mapped uid must be above the reserved-id floor"
    assert not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)), (
        f"impersonated object should not be group/other writable: mode "
        f"{stat.S_IMODE(st.st_mode):o}")


# --------------------------------------------------------------------------- #
# Token (WebDAV) -> grid-mapfile -> local account                             #
# --------------------------------------------------------------------------- #
def test_token_write_owned_by_gridmap_mapped_account(webdav_squash):
    """A WLCG-token PUT whose subject the grid-mapfile maps to brixgm_alice lands
    a backend file owned by alice's real uid/gid — not the worker, not root."""
    tok = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    r = _put(webdav_squash.url, "/alice_wrote.dat", tok, b"hello-from-alice")
    assert r.status_code in (200, 201, 204), r.text
    st = H.stat_export(webdav_squash.export, "alice_wrote.dat")
    _assert_owned_by(st, "alice")


def test_distinct_tokens_map_to_distinct_accounts(webdav_squash):
    """Two different token subjects land files owned by two different real
    accounts — the mapping is per-identity, not a single squashed uid."""
    ta = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    tb = webdav_squash.ti.generate(sub=P_BOB, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/a_owned.dat", ta).status_code in (200, 201, 204)
    assert _put(webdav_squash.url, "/b_owned.dat", tb).status_code in (200, 201, 204)
    sa = H.stat_export(webdav_squash.export, "a_owned.dat")
    sb = H.stat_export(webdav_squash.export, "b_owned.dat")
    _assert_owned_by(sa, "alice")
    _assert_owned_by(sb, "bob")
    assert sa.st_uid != sb.st_uid


def test_kernel_dac_enforced_between_mapped_accounts(webdav_squash):
    """Real per-identity kernel DAC: alice creates a private (0600) object; alice
    can read it back but bob — a different mapped account — is denied at open time
    by the kernel, even though the worker uid could read it.  This is the property
    that is meaningless without a real setfsuid broker holding no CAP_DAC_OVERRIDE."""
    ta = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    tb = webdav_squash.ti.generate(sub=P_BOB, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/dac_secret.dat", ta, b"sekret").status_code \
        in (200, 201, 204)
    st = H.stat_export(webdav_squash.export, "dac_secret.dat")
    _assert_owned_by(st, "alice")
    assert not (st.st_mode & (stat.S_IRGRP | stat.S_IROTH)), \
        "object must be owner-private for the DAC test to be meaningful"

    assert _get(webdav_squash.url, "/dac_secret.dat", ta).status_code == 200, \
        "the owning account must be able to read its own file"
    assert _get(webdav_squash.url, "/dac_secret.dat", tb).status_code == 403, \
        "a different mapped account must be denied by kernel DAC"


def test_unmapped_token_squashes_to_default_user(webdav_squash):
    """A principal absent from the grid-mapfile squashes to brix_idmap_default_user
    (brixgm_squash) — owned by the squash account, still never the worker/root."""
    tok = webdav_squash.ti.generate(sub=P_UNMAPPED, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/squashed.dat", tok).status_code in (200, 201, 204)
    st = H.stat_export(webdav_squash.export, "squashed.dat")
    _assert_owned_by(st, "squash")


def test_gridmap_to_system_account_never_writes_as_root(webdav_squash):
    """Defence in depth: a grid-mapfile line that explicitly maps a principal to
    the reserved `root` account can NEVER yield a root-owned file — the reserved-id
    floor rejects uid 0 and (a default_user being set) it squashes instead.  The
    written object is owned by the squash account, uid >= 1000, never uid 0."""
    tok = webdav_squash.ti.generate(sub=P_ROOT, scope=H.RW_SCOPE)
    _put(webdav_squash.url, "/root_attempt.dat", tok)
    st = H.stat_export(webdav_squash.export, "root_attempt.dat")
    assert st.st_uid != 0, "a gridmap->root line must never produce a root-owned file"
    assert st.st_uid >= 1000
    _assert_owned_by(st, "squash")


def test_deny_mode_reserved_and_unmapped_fail_closed(webdav_deny):
    """With no default_user, unmapped and reserved principals fail closed: the PUT
    is denied and NO backend object is created — never a silent fallback to the
    worker's own (export-owning) identity.  A properly mapped principal still
    succeeds on the same server, proving the deny is selective, not blanket."""
    ta = webdav_deny.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    assert _put(webdav_deny.url, "/deny_alice.dat", ta).status_code in (200, 201, 204)
    _assert_owned_by(H.stat_export(webdav_deny.export, "deny_alice.dat"), "alice")

    tr = webdav_deny.ti.generate(sub=P_ROOT, scope=H.RW_SCOPE)
    tu = webdav_deny.ti.generate(sub=P_UNMAPPED, scope=H.RW_SCOPE)
    assert _put(webdav_deny.url, "/deny_root.dat", tr).status_code >= 400
    assert _put(webdav_deny.url, "/deny_unmapped.dat", tu).status_code >= 400
    for rel in ("deny_root.dat", "deny_unmapped.dat"):
        assert not os.path.exists(os.path.join(webdav_deny.export, rel)), \
            f"{rel} must not exist — the denied write must create no file"


# --------------------------------------------------------------------------- #
# X.509 GSI (root://) -> grid-mapfile -> local account                        #
# --------------------------------------------------------------------------- #
def test_x509_dn_gridmap_write_owned_by_mapped_account(root_gsi):
    """An X.509/GSI ``root://`` write, whose proxy leaf DN the grid-mapfile maps to
    brixgm_alice, lands a backend file owned by alice's real uid/gid.  This is the
    classic grid case: X.509 identity -> grid-mapfile -> local user ownership."""
    pytest.importorskip("XRootD", reason="pyxrootd client not installed")
    from XRootD import client
    from XRootD.client.flags import OpenFlags

    prev_proxy = os.environ.get("X509_USER_PROXY")
    prev_certdir = os.environ.get("X509_CERT_DIR")
    os.environ["X509_USER_PROXY"] = root_gsi.proxy
    os.environ["X509_CERT_DIR"] = settings.CA_DIR
    try:
        f = client.File()
        st, _ = f.open(root_gsi.url + "//x509_alice.dat",
                       OpenFlags.NEW | OpenFlags.WRITE)
        assert st.ok, f"GSI root:// open failed: {st.message}"
        ok, _ = f.write(b"hello-from-x509-alice")
        assert ok.ok, f"write failed: {ok.message}"
        f.close()
    finally:
        for k, v in (("X509_USER_PROXY", prev_proxy), ("X509_CERT_DIR", prev_certdir)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    s = H.stat_export(root_gsi.export, "x509_alice.dat")
    _assert_owned_by(s, "alice")
