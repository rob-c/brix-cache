"""No-root verification of WebDAV native authorization read parity (FIX 3 + VOMS follow-up).

WebDAV GET/HEAD/PROPFIND now enforce native authdb (per-DN/VO/host) AND VO-ACL for reads — the
mechanisms root:// uses — including on a cached GET (the access-phase gate fronts the content
handler). This test stands up a WebDAV server (no impersonation — the gate is a worker-level
decision) and proves both:

  * authdb path scoping — with `u * /cms rl` + `u * /restricted rl`, an authenticated reader is
    served under those subtrees but REFUSED elsewhere (/private) with 403.
  * VO ACL — with `require_vo /restricted cms`, a VO=cms proxy reads /restricted but a VO=atlas
    proxy is refused 403. This exercises the VOMS VO extraction fix: WebDAV now (a) loads
    libvomsapi even in a WebDAV-only deployment and (b) re-derives the VO on cached TLS
    connections, so the identity carries its VOs (previously vos="-").

Run: PYTHONPATH=tests pytest tests/test_mu_webdav_authz.py -v   (no root needed)
"""
import os
from types import SimpleNamespace

import pytest

from mu_authz_lib import creds, ports, principals
from mu_authz_lib.adapters import measure_webdav
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-mu-webdav-authz")]


def _spec():
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
            "AUTHDB": ports.MU.AUTHDB,
        },
        reason="MU WebDAV read node: native authdb + VO-ACL read parity.",
    )


@pytest.fixture(scope="module")
def cast():
    """Build the MU PKI/principal cast once for the module (idempotent)."""
    principals.build_cast()


@pytest.fixture
def webdav_authz_env(lifecycle, cast):
    for sub in ("cms", "restricted", "private"):
        d = os.path.join(ports.MU.DATA_ROOT, sub)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "secret.dat"), "wb") as f:
            f.write(b"S" * 4096)
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    with open(ports.MU.AUTHDB, "w") as f:
        # authdb grants any authenticated reader on /cms and /restricted; nothing else.
        f.write("u * /cms rl\nu * /restricted rl\n")
    return lifecycle.start(_spec())


def _proxy(name, vo=None):
    cert = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_userkey.pem")
    proxy = (creds.gen_voms_proxy(cert, key, f"wdauthz_{name}_{vo}", vo) if vo
             else creds.gen_gsi_proxy(cert, key, f"wdauthz_{name}"))
    return SimpleNamespace(name=name, proxy=proxy, token="", s3_key="", s3_secret="")


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
