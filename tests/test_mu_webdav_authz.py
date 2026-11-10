"""No-root verification of WebDAV native authorization read parity (FIX 3 + VOMS follow-up).

WebDAV GET/HEAD/PROPFIND now enforce native authdb (per-DN/VO/host) AND VO-ACL for reads — the
mechanisms root:// uses — including on a cached GET (the access-phase gate fronts the content
handler). This test stands up a WebDAV server (no impersonation — the gate is a worker-level
decision) and proves both:

  * authdb path scoping — with `u * /cms rl` + `u * /restricted rl`, an authenticated reader is
    served under those subtrees but REFUSED elsewhere (/private) with 403.
  * VO ACL — with `require_vo /restricted cms`, a VO=cms proxy reads /restricted but a VO=atlas
    proxy is refused 403. This exercises the VOMS VO extraction fix: WebDAV now (a) warms
    the native VOMS trust store even in a WebDAV-only deployment and (b) re-derives the VO
    on cached TLS connections, so the identity carries its VOs (previously vos="-").

Run: PYTHONPATH=tests pytest tests/test_mu_webdav_authz.py -v   (no root needed)
"""
import os
from types import SimpleNamespace

import pytest
import requests

from mu_authz_lib import creds, ports, principals
from mu_authz_lib.adapters import measure_webdav
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-mu-webdav-authz")]


def _spec(authdb):
    return NginxInstanceSpec(
        name="lc-mu-webdav-authz",
        template="nginx_mu_webdav_authz.conf",
        protocol="https",
        readiness="webdav",
        data_root=ports.MU.DATA_ROOT,
        template_values={
            "CERT": os.path.join(ports.MU.PKI_DIR, "server", "hostcert.pem"),
            "KEY": os.path.join(ports.MU.PKI_DIR, "server", "hostkey.pem"),
            "CA": os.path.join(ports.MU.CA_DIR, "ca.pem"),
            "VOMSDIR": ports.MU.VOMSDIR,
            "CA_DIR": ports.MU.CA_DIR,
            "AUTHDB": str(authdb),
        },
        reason="MU WebDAV read node: native authdb + VO-ACL read parity.",
    )


@pytest.fixture(scope="module")
def cast():
    """Build the MU PKI/principal cast once for the module (idempotent)."""
    principals.build_cast()


@pytest.fixture
def webdav_authz_env(lifecycle, cast, tmp_path):
    for sub in ("cms", "restricted", "private"):
        d = os.path.join(ports.MU.DATA_ROOT, sub)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "secret.dat"), "wb") as f:
            f.write(b"S" * 4096)
    # The policy is private: parallel MU groups grant different identities/paths.
    authdb = tmp_path / "authdb"
    authdb.write_text("u * /cms rl\nu * /restricted rlw\n")
    return lifecycle.start(_spec(authdb))


@pytest.fixture
def webdav_lock_authz_env(lifecycle, cast, tmp_path):
    """Native authdb fixture with distinct read-only and mutable lock paths."""
    for sub in ("lock-read", "lock-write"):
        directory = os.path.join(ports.MU.DATA_ROOT, sub)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "target.dat"), "wb") as target:
            target.write(b"lock-policy\n")
    authdb = tmp_path / "lock-authdb"
    authdb.write_text("u * /lock-read r\nu * /lock-write rw\n")
    return lifecycle.start(_spec(authdb))


@pytest.fixture
def webdav_mutation_authz_env(lifecycle, cast, tmp_path):
    """Native authdb fixture spanning each single-resource write privilege."""
    rules = {
        "put-read": "r", "put-write": "rw",
        "delete-write": "rw", "delete-allowed": "rwd",
        "mkdir-write": "rw", "mkdir-allowed": "rwm",
        "prop-read": "r", "prop-write": "rw",
        "acl-read": "r", "acl-admin": "rk",
    }
    for sub in rules:
        directory = os.path.join(ports.MU.DATA_ROOT, sub)
        os.makedirs(directory, exist_ok=True)
    _seed_mutation_targets()
    authdb = tmp_path / "mutation-authdb"
    authdb.write_text("".join(
        f"u * /{path} {privs}\n" for path, privs in rules.items()))
    return lifecycle.start(_spec(authdb))


def _seed_mutation_targets():
    """Populate delete and metadata fixtures with their expected payloads."""
    for sub in ("delete-write", "delete-allowed"):
        with open(os.path.join(ports.MU.DATA_ROOT, sub, "target.dat"), "wb") as target:
            target.write(b"retain-on-deny\n")
    for sub in ("prop-read", "prop-write", "acl-read", "acl-admin"):
        with open(os.path.join(ports.MU.DATA_ROOT, sub, "target.dat"), "wb") as target:
            target.write(b"metadata-target\n")


def _proxy(name, vo=None):
    cert = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_userkey.pem")
    proxy = (creds.gen_voms_proxy(cert, key, f"wdauthz_{name}_{vo}", vo) if vo
             else creds.gen_gsi_proxy(cert, key, f"wdauthz_{name}"))
    return SimpleNamespace(name=name, proxy=proxy, token="", s3_key="", s3_secret="")


def _lock(url, path, proxy):
    """Issue one authenticated RFC 4918 write-lock request."""
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<D:lockinfo xmlns:D="DAV:">'
        '<D:lockscope><D:exclusive/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        '<D:owner>native-authdb</D:owner>'
        '</D:lockinfo>'
    )
    return requests.request(
        "LOCK", f"{url}{path}", data=body, cert=proxy,
        headers={"Content-Type": "application/xml"}, verify=False, timeout=15)


@pytest.mark.parametrize("op", ["read", "stat", "list"])
def test_webdav_authdb_path_scoping(webdav_authz_env, op):
    """Native authdb read gate: an authenticated reader is served under a granted subtree
    (/cms) but REFUSED outside it (/private) — for GET, HEAD, and PROPFIND."""
    url = webdav_authz_env.url
    alice = _proxy("alice")

    assert measure_webdav(url, "/cms/secret.dat", op, principal=alice).decision == "ALLOW", \
        f"{op} under granted /cms must be served"
    denied = measure_webdav(url, "/private/secret.dat", op, principal=alice)
    assert denied.decision == "DENY", f"LEAK: {op} of ungranted /private was served: {denied}"


@pytest.mark.parametrize("op", ["read", "stat", "list"])
def test_webdav_vo_acl_read(webdav_authz_env, op):
    """VO ACL read gate (VOMS extraction fix): on /restricted (require_vo cms), a VO=cms
    reader is served but a VO=atlas reader is refused 403 — for GET, HEAD, and PROPFIND."""
    url = webdav_authz_env.url
    alice = _proxy("alice", vo="cms")     # VO cms — admitted by require_vo /restricted cms
    bob = _proxy("bob", vo="atlas")       # VO atlas — refused

    assert measure_webdav(url, "/restricted/secret.dat", op, principal=alice).decision == "ALLOW", \
        f"{op} by VO=cms on /restricted must be served (VOMS extracted)"
    denied = measure_webdav(url, "/restricted/secret.dat", op, principal=bob)
    assert denied.decision == "DENY", (
        f"LEAK: out-of-VO bob (atlas) was served a {op} of /restricted: {denied}")


def test_webdav_vo_acl_applies_to_writes(webdav_authz_env):
    """Required-VO membership gates writes even when native UPDATE is granted."""
    cms = _proxy("alice", vo="cms")
    atlas = _proxy("bob", vo="atlas")
    allowed_path = os.path.join(ports.MU.DATA_ROOT, "restricted", "cms-write.dat")
    denied_path = os.path.join(ports.MU.DATA_ROOT, "restricted", "atlas-write.dat")

    allowed = requests.put(
        f"{webdav_authz_env.url}/restricted/cms-write.dat", data=b"cms\n",
        cert=cms.proxy, verify=False, timeout=15)
    denied = requests.put(
        f"{webdav_authz_env.url}/restricted/atlas-write.dat", data=b"atlas\n",
        cert=atlas.proxy, verify=False, timeout=15)

    assert allowed.status_code in (201, 204), allowed.text
    assert denied.status_code == 403, denied.text
    assert os.path.exists(allowed_path)
    assert not os.path.exists(denied_path)


def test_webdav_native_authdb_gates_single_resource_mutations(
        webdav_mutation_authz_env):
    """Native r/w/d/m/k privileges independently gate every write family."""
    url = webdav_mutation_authz_env.url
    proxy = _proxy("alice").proxy

    put_denied = requests.put(
        f"{url}/put-read/new.dat", data=b"denied", cert=proxy,
        verify=False, timeout=15)
    put_allowed = requests.put(
        f"{url}/put-write/new.dat", data=b"allowed", cert=proxy,
        verify=False, timeout=15)
    assert put_denied.status_code == 403, put_denied.text
    assert put_allowed.status_code in (201, 204), put_allowed.text

    delete_denied = requests.delete(
        f"{url}/delete-write/target.dat", cert=proxy,
        verify=False, timeout=15)
    delete_allowed = requests.delete(
        f"{url}/delete-allowed/target.dat", cert=proxy,
        verify=False, timeout=15)
    assert delete_denied.status_code == 403, delete_denied.text
    assert delete_allowed.status_code == 204, delete_allowed.text

    mkdir_denied = requests.request(
        "MKCOL", f"{url}/mkdir-write/child", cert=proxy,
        verify=False, timeout=15)
    mkdir_allowed = requests.request(
        "MKCOL", f"{url}/mkdir-allowed/child", cert=proxy,
        verify=False, timeout=15)
    assert mkdir_denied.status_code == 403, mkdir_denied.text
    assert mkdir_allowed.status_code == 201, mkdir_allowed.text

    prop_body = (
        '<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
        'xmlns:X="urn:brix:test"><D:set><D:prop><X:policy>ok</X:policy>'
        '</D:prop></D:set></D:propertyupdate>'
    )
    prop_denied = requests.request(
        "PROPPATCH", f"{url}/prop-read/target.dat", data=prop_body,
        cert=proxy, headers={"Content-Type": "application/xml"},
        verify=False, timeout=15)
    prop_allowed = requests.request(
        "PROPPATCH", f"{url}/prop-write/target.dat", data=prop_body,
        cert=proxy, headers={"Content-Type": "application/xml"},
        verify=False, timeout=15)
    assert prop_denied.status_code == 403, prop_denied.text
    assert prop_allowed.status_code == 207, prop_allowed.text

    acl_body = '<D:acl xmlns:D="DAV:"/>'
    acl_denied = requests.request(
        "ACL", f"{url}/acl-read/target.dat", data=acl_body, cert=proxy,
        headers={"Content-Type": "application/xml"}, verify=False, timeout=15)
    acl_authorized = requests.request(
        "ACL", f"{url}/acl-admin/target.dat", data=acl_body, cert=proxy,
        headers={"Content-Type": "application/xml"}, verify=False, timeout=15)
    assert acl_denied.status_code == 403, acl_denied.text
    assert acl_authorized.status_code == 403, acl_authorized.text
    assert "cannot-modify-protected-property" in acl_authorized.text


def test_webdav_native_authdb_lock_requires_update(webdav_lock_authz_env):
    """Native READ cannot lock; UPDATE retains the ordinary lock lifecycle."""
    alice = _proxy("alice")
    denied = _lock(webdav_lock_authz_env.url,
                   "/lock-read/target.dat", alice.proxy)
    allowed = _lock(webdav_lock_authz_env.url,
                    "/lock-write/target.dat", alice.proxy)

    assert denied.status_code == 403, denied.text
    assert allowed.status_code in (200, 201), allowed.text
    lock_token = allowed.headers.get("Lock-Token")
    assert lock_token
    released = requests.request(
        "UNLOCK", f"{webdav_lock_authz_env.url}/lock-write/target.dat",
        cert=alice.proxy, headers={"Lock-Token": lock_token},
        verify=False, timeout=15)
    assert released.status_code == 204, released.text
