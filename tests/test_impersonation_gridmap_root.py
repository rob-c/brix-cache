"""Real host-root grid-mapfile ownership, authorization and broker confinement.

The registry launches nginx with a root master and unprivileged workers. WLCG
subjects and X.509 proxy DNs map to real local accounts; inode ownership and
kernel DAC prove the selected credentials, not merely an idmap lookup. Linux
uses its capability broker; FreeBSD uses fixed-identity Capsicum helpers.
Tests cover reserved/unmapped refusal, WebDAV lock ownership, idle transport,
saved-ID loss, sealed descriptors and release of inherited listeners.

Run: sudo -E env PYTHONPATH=tests pytest tests/test_impersonation_gridmap_root.py -v
The standalone FreeBSD privileged target also selects this module explicitly.
"""
from __future__ import annotations

import os
import pwd
import socket
import stat
import sys
import time
from types import SimpleNamespace

import pytest
import requests

import settings
from server_launcher import LifecycleHarness, launch_fleet_nginx
from server_registry import NginxInstanceSpec, endpoint_for

import impersonation_gridmap_helpers as H
from impersonation_gridmap_helpers import (
    _broker_pid, _fd_targets, _assert_stdio_is_null,
    _assert_no_network_socket, _assert_no_export_object,
)
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

    ``launch_fleet_nginx`` is the registry's own fire-and-forget seam
    (``start_new_session``, inherited fds) for this class of long-lived daemon;
    the instance is still registered, so ``harness.close()`` reaps it by pidfile
    on teardown.

    It used to be the only seam that worked: ``harness.start()`` pipes the
    child's stdout/stderr and waits for EOF, and ``brix_idmap map`` double-forks
    its privileged broker during ``init_module`` — before nginx daemonizes — so
    the broker inherited those pipe write ends and never gave EOF up.  The broker
    now seals its inherited descriptors and either seam works;
    ``sealed_broker`` below deliberately uses the piped one to keep that true.
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
    """Bring up a WebDAV/token nginx instance under `brix_idmap map` with
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
    """`brix_idmap single`: every identity squashes to one fixed account
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
        _assert_owned_by(H.stat_export(single_mode.export, name), "squash", single_mode.export)


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
    _assert_owned_by(st, "alice", s3_map.export)


@pytest.fixture(scope="module")
def root_gsi(harness):
    """map mode root:// GSI server: the X.509 proxy leaf DN maps to brixgm_alice."""
    proxy = settings.PROXY_STD
    for f in (proxy, settings.SERVER_CERT, settings.SERVER_KEY):
        if not os.path.exists(f):
            pytest.skip(f"GSI PKI not provisioned ({f} missing)")
    export, run_dir, auth_dir = H.prepare_export(BASE, "impgm-root-gsi")
    # The EEC DN, not the proxy leaf: brix maps on the stable end-entity subject
    # so a re-delegation (new serial, new leaf DN) does not silently unmap the
    # user.  Keying this fixture on the leaf made the broker log "no UNIX mapping
    # for principal" and the write come back kXR_NotAuthorized.
    dn = H.proxy_eec_dn(proxy)
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
def _assert_owned_by(st: os.stat_result, logical: str, export: str):
    """The written object is owned by the mapped real account, not the worker or
    root, and carries no group/other write bit (impersonation created it as the
    user, so it is a private, non-shared object)."""
    assert st.st_uid == H.uid_of(logical), (
        f"file uid {st.st_uid} != mapped {logical} uid {H.uid_of(logical)}")
    expected_gid = H.native_creation_gid(export, logical)
    assert st.st_gid == expected_gid, (
        f"file gid {st.st_gid} != native {logical} creation gid {expected_gid}")
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
    _assert_owned_by(st, "alice", webdav_squash.export)


def test_distinct_tokens_map_to_distinct_accounts(webdav_squash):
    """Two different token subjects land files owned by two different real
    accounts — the mapping is per-identity, not a single squashed uid."""
    ta = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    tb = webdav_squash.ti.generate(sub=P_BOB, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/a_owned.dat", ta).status_code in (200, 201, 204)
    assert _put(webdav_squash.url, "/b_owned.dat", tb).status_code in (200, 201, 204)
    sa = H.stat_export(webdav_squash.export, "a_owned.dat")
    sb = H.stat_export(webdav_squash.export, "b_owned.dat")
    _assert_owned_by(sa, "alice", webdav_squash.export)
    _assert_owned_by(sb, "bob", webdav_squash.export)
    assert sa.st_uid != sb.st_uid


def test_kernel_dac_enforced_between_mapped_accounts(webdav_squash):
    """Real per-identity kernel DAC: alice owns a private (0600) object; alice can
    read it back but bob — a different mapped account — is denied at open time by
    the kernel, even though the worker uid could read it.  This is the property
    that is meaningless without a real setfsuid broker holding no CAP_DAC_OVERRIDE.

    The private mode is applied here, not expected from the PUT: a WebDAV upload
    creates at NGX_FILE_DEFAULT_ACCESS (0644) like every other nginx-written
    file, and the subject of this test is the kernel's per-uid check, not the
    create mode.  Asserting 0600 straight out of the PUT made it fail on a
    premise the product never promised."""
    ta = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    tb = webdav_squash.ti.generate(sub=P_BOB, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/dac_secret.dat", ta, b"sekret").status_code \
        in (200, 201, 204)
    st = H.stat_export(webdav_squash.export, "dac_secret.dat")
    _assert_owned_by(st, "alice", webdav_squash.export)
    os.chmod(os.path.join(webdav_squash.export, "dac_secret.dat"), 0o600)
    st = H.stat_export(webdav_squash.export, "dac_secret.dat")
    assert not (st.st_mode & (stat.S_IRGRP | stat.S_IROTH)), \
        "object must be owner-private for the DAC test to be meaningful"

    assert _get(webdav_squash.url, "/dac_secret.dat", ta).status_code == 200, \
        "the owning account must be able to read its own file"
    assert _get(webdav_squash.url, "/dac_secret.dat", tb).status_code == 403, \
        "a different mapped account must be denied by kernel DAC"


@pytest.mark.timeout(60)
def test_map_mode_identity_survives_an_idle_transport(webdav_squash):
    """A helper's reply deadline must not terminate it between requests."""
    token = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, '/idle.dat', token, b'after idle').status_code in (200, 201, 204)
    time.sleep(31)
    response = _get(webdav_squash.url, '/idle.dat', token)
    assert response.status_code == 200 and response.content == b'after idle'


@pytest.fixture
def mapped_webdav_lock(webdav_squash):
    """A fresh actual persisted lock owned by a mapped user."""
    from test_webdav_unlock_ownership import LOCK_BODY

    token = webdav_squash.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    path = f'/mapped-lock-{time.time_ns()}.dat'
    assert _put(webdav_squash.url, path, token).status_code in (200, 201, 204)
    headers = {'Authorization': f'Bearer {token}', 'Timeout': 'Second-3600', 'Depth': '0'}
    response = requests.request('LOCK', webdav_squash.url + path, data=LOCK_BODY,
                                headers=headers, timeout=10)
    assert response.status_code in (200, 201), response.text
    lock = response.headers['Lock-Token']
    url = webdav_squash.url + path
    try:
        yield url, token, lock
    finally:
        requests.request('UNLOCK', url,
            headers={'Authorization': f'Bearer {token}', 'Lock-Token': lock}, timeout=10)


def test_mapped_webdav_lock_roundtrip(mapped_webdav_lock):
    """LOCK updates must run as the mapped owner, not the worker's credentials."""
    url, token, lock = mapped_webdav_lock
    unlocked = requests.request('UNLOCK', url,
        headers={'Authorization': f'Bearer {token}', 'Lock-Token': lock}, timeout=10)
    assert unlocked.status_code == 204, unlocked.text


def test_mapped_webdav_lock_refresh_preserves_ownership(mapped_webdav_lock):
    """The owner can replace its exact persisted expiry record."""
    url, token, lock = mapped_webdav_lock
    response = requests.request('LOCK', url, headers={
        'Authorization': f'Bearer {token}', 'If': f'({lock})',
        'Timeout': 'Second-1800'}, timeout=10)
    assert response.status_code == 200, response.text


def test_mapped_webdav_forged_unlock_keeps_the_lock(mapped_webdav_lock):
    """A stale/forged lock id cannot clear the persisted owner record."""
    url, token, _lock = mapped_webdav_lock
    response = requests.request('UNLOCK', url, headers={
        'Authorization': f'Bearer {token}',
        'Lock-Token': '<opaquelocktoken:00000000-0000-0000-0000-000000000000>'}, timeout=10)
    assert response.status_code == 409, response.text
    response = requests.put(url, data=b'forged', headers={
        'Authorization': f'Bearer {token}'}, timeout=10)
    assert response.status_code == 423, response.text


def test_mapped_webdav_other_user_cannot_clear_owner_lock(mapped_webdav_lock, webdav_squash):
    """Even a known lock token cannot borrow the mapped owner's kernel rights."""
    url, owner, lock = mapped_webdav_lock
    other = webdav_squash.ti.generate(sub=P_BOB, scope=H.RW_SCOPE)
    response = requests.request('UNLOCK', url, headers={
        'Authorization': f'Bearer {other}', 'Lock-Token': lock}, timeout=10)
    assert response.status_code == 403, response.text
    response = requests.put(url, data=b'owner', headers={
        'Authorization': f'Bearer {owner}'}, timeout=10)
    assert response.status_code == 423, response.text


def test_unmapped_token_squashes_to_default_user(webdav_squash):
    """A principal absent from the grid-mapfile squashes to brix_idmap_default_user
    (brixgm_squash) — owned by the squash account, still never the worker/root."""
    tok = webdav_squash.ti.generate(sub=P_UNMAPPED, scope=H.RW_SCOPE)
    assert _put(webdav_squash.url, "/squashed.dat", tok).status_code in (200, 201, 204)
    st = H.stat_export(webdav_squash.export, "squashed.dat")
    _assert_owned_by(st, "squash", webdav_squash.export)


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
    _assert_owned_by(st, "squash", webdav_squash.export)


def test_deny_mode_reserved_and_unmapped_fail_closed(webdav_deny):
    """With no default_user, unmapped and reserved principals fail closed: the PUT
    is denied and NO backend object is created — never a silent fallback to the
    worker's own (export-owning) identity.  A properly mapped principal still
    succeeds on the same server, proving the deny is selective, not blanket."""
    ta = webdav_deny.ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    assert _put(webdav_deny.url, "/deny_alice.dat", ta).status_code in (200, 201, 204)
    _assert_owned_by(H.stat_export(webdav_deny.export, "deny_alice.dat"),
                     "alice", webdav_deny.export)

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
    _assert_owned_by(s, "alice", root_gsi.export)


# --------------------------------------------------------------------------- #
# What the broker may still be holding after the fork                         #
# --------------------------------------------------------------------------- #
# The broker is forked out of init_module, which nginx runs INSIDE
# ngx_init_cycle() — after the listening sockets are bound and before
# ngx_daemon() — and the double-fork then reparents it to init.  So it starts
# life holding a copy of every descriptor the master had at that instant and,
# unlike a worker, it outlives the nginx generation that made it.  Left alone it
# kept the bound TCP listener (the next start of that server died with
# EADDRINUSE against a process absent from nginx's pid file), the open log files
# (pinning deleted inodes), and the supervising launcher's stdout/stderr pipes
# (withholding EOF from a parent that reads them to completion — which is why
# _render_and_launch above uses the detached seam instead of harness.start()).
# These three pin the sealing: the port comes back, the piped seam returns, and
# a root daemon holds nothing it was not handed.


@pytest.fixture(scope="module")
def sealed_broker(harness):
    """A map-mode instance started through the PIPED launcher seam.

    Deliberately ``harness.start()`` and not ``_render_and_launch``: the piped
    seam is the one the broker used to wedge, so a fixture that avoided it could
    not observe the sealing at all."""
    export, run_dir, auth_dir = H.prepare_export(BASE, "impgm-sealed")
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, [(P_ALICE, H.acct("alice"))])
    ti = H.token_authority(auth_dir)
    payload = b'broker-mapped-readiness\x00\xff'
    ready_file = os.path.join(export, '.broker-ready')
    with open(ready_file, 'xb') as output:
        output.write(payload)
    os.chown(ready_file, H.uid_of('alice'), H.gid_of('alice'))
    os.chmod(ready_file, 0o600)
    sock = os.path.join(run_dir, "impersonate.sock")
    spec = NginxInstanceSpec(
        name="impgm-sealed",
        template="nginx_impersonate_gridmap_webdav.conf",
        protocol="http",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export, "SOCK": sock, "GRIDMAP": gridmap,
            "JWKS": ti.jwks_path, "ISSUER": H.ISSUER, "AUDIENCE": H.AUDIENCE,
            "DEFAULT_USER_LINE": "",
        },
    )
    started = time.monotonic()
    ep = harness.start(spec)
    elapsed = time.monotonic() - started
    _BROKER_SOCKS.append(sock)
    # The child publishes its PID before creating/attesting native helpers.
    # Prove the mapped I/O path is serving before inspecting its final IDs;
    # keep the original launch timing and all saved-root assertions unchanged.
    token = ti.generate(sub=P_ALICE, scope=H.RW_SCOPE)
    H.assert_mapped_read_ready(_get(f'http://{BIND}:{ep.port}', '/.broker-ready', token), payload)
    return SimpleNamespace(ep=ep, sock=sock, export=export,
                           start_seconds=elapsed)


def test_piped_launch_of_a_map_mode_node_is_not_withheld_by_the_broker(sealed_broker):
    """``harness.start()`` reads the child's stdout/stderr to EOF.  nginx
    daemonizes and exits immediately, so EOF is due at once — unless the broker
    is still holding the write ends, in which case the read blocks for the whole
    launcher timeout and a node that is already serving looks like a slow start.
    Ten seconds is far above a real start here (sub-second) and far below the
    ~23 s the held pipe cost."""
    assert sealed_broker.start_seconds < 10.0, (
        f"piped start of a map-mode node took {sealed_broker.start_seconds:.1f}s; "
        "the broker is holding the launcher's pipe write ends open")


def test_broker_holds_nothing_it_was_not_handed(sealed_broker):
    """Security: this daemon runs as root for the life of the node, so its
    descriptor table is an authority list.  It may hold its own 0600 AF_UNIX
    listener, the O_PATH export root it confines every impersonated open to, and
    its log — nothing else.  In particular an inherited WRITE handle on an export
    object would be a path around the confinement the broker exists to enforce,
    reachable without ever presenting an identity."""
    targets = _fd_targets(_broker_pid(sealed_broker.sock))
    _assert_stdio_is_null(targets)
    _assert_no_network_socket(targets)
    _assert_no_export_object(targets, sealed_broker.export)


def test_serving_broker_identities_have_no_saved_root(sealed_broker):
    """Verify actual kernel credentials, including each native fixed helper."""
    psutil = pytest.importorskip('psutil')
    broker = psutil.Process(_broker_pid(sealed_broker.sock))
    expected_uid, expected_gid = H.uid_of('broker'), H.gid_of('broker')
    assert tuple(broker.uids()) == (expected_uid,) * 3
    assert tuple(broker.gids()) == (expected_gid,) * 3
    if sys.platform.startswith('freebsd'):
        from lib_py.process_host import native_process_record
        helpers = broker.children()
        assert helpers, 'native model must have real fixed-identity helpers'
        for helper in helpers:
            credentials = native_process_record(helper.pid, 'credentials', '-s')
            uid, gid = credentials['uid'], credentials['group']
            assert uid >= 1000 and uid not in (expected_uid, WORKER_UID)
            assert gid >= 1000
            assert (credentials['ruid'], credentials['svuid']) == (uid, uid)
            assert (credentials['rgid'], credentials['svgid']) == (gid, gid)
            assert 'C' in credentials['cr_flags'], 'helper is outside capability mode'
            targets = _fd_targets(helper.pid)
            _assert_stdio_is_null(targets)
            _assert_no_network_socket(targets)
            _assert_no_export_object(targets, sealed_broker.export)


def test_listener_is_released_when_the_master_stops(harness):
    """The port must come back when nginx does, not when the broker does.

    Stopping the master is `nginx -s quit`, which reaps the master and its
    workers and leaves the init-reparented broker running by design.  If that
    broker still holds the inherited listener the socket stays bound to a
    process nginx does not know about, and the next start of the same server
    fails with EADDRINUSE — attributed to whatever is starting, never to the
    daemon actually holding the port.

    This owns its instance rather than sharing ``sealed_broker``: it stops the
    server it measures, and a shared one would make the other two tests depend
    on running first."""
    export, run_dir, auth_dir = H.prepare_export(BASE, "impgm-rebind")
    gridmap = os.path.join(auth_dir, "gridmap")
    H.write_gridmap(gridmap, [(P_ALICE, H.acct("alice"))])
    ti = H.token_authority(auth_dir)
    sock = os.path.join(run_dir, "impersonate.sock")
    ep = _render_and_launch(harness, NginxInstanceSpec(
        name="impgm-rebind",
        template="nginx_impersonate_gridmap_webdav.conf",
        protocol="http",
        data_root=export,
        readiness="tcp",
        template_values={
            "EXPORT": export, "SOCK": sock, "GRIDMAP": gridmap,
            "JWKS": ti.jwks_path, "ISSUER": H.ISSUER, "AUDIENCE": H.AUDIENCE,
            "DEFAULT_USER_LINE": "",
        },
    ))
    pid = _broker_pid(sock)

    harness.stop("impgm-rebind")

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pytest.fail(f"broker {pid} died with the master — this test can only "
                    "prove the release if the broker is still running")

    try:
        H.assert_listener_released(BIND, ep.port)
    except OSError as exc:
        raise AssertionError(
            f"{BIND}:{ep.port} still bound after nginx stopped (broker pid "
            f"{pid} holds the inherited listener): {exc}") from None


@pytest.mark.parametrize('case', ['closed', 'active', 'timewait'])
def test_listener_release_probe_distinguishes_real_kernel_states(case):
    """The release assertion must not mistake TIME_WAIT for an inherited listener."""
    H.listener_release_control(case, BIND)
