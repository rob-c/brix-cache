"""No-root verification that internal metadata/staging sidecars are NEVER exposed to a client.

Internal artifacts — cache sidecars (.cinfo/.meta/.xrdcinfo), the stage-out crash-recovery
marker (.commit), and in-flight upload temps (…​.xrd-tmp.… / …​.xrdresume.…) — can sit inside a
client-visible export namespace (the upload temps do so by default; the cache sidecars if the
cache tree is misconfigured under an export). A single predicate (brix_is_internal_name) now
gates every client-facing checkpoint: enumeration skips them, and a direct request by name is
answered as if the path does not exist. This test plants such files inside the export and proves
that neither a listing nor a direct fetch/stat ever reveals them — across root:// and WebDAV —
while a genuine sibling file remains fully accessible.

Run: PYTHONPATH=tests pytest tests/test_mu_sidecar_hidden.py -v   (no root needed)
"""
import os
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest
import requests

from mu_authz_lib import creds, ports, principals
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

_PROBE = "sidecarprobe"
_KEEP = "keep.dat"                       # a genuine user file — must stay visible
_INTERNAL = [                            # must all be invisible
    "keep.dat.cinfo",
    "keep.dat.meta",
    "keep.dat.xrdcinfo",
    "keep.dat.xrdt",                     # XrdOssCsi per-page tag sidecar (interop)
    "keep.dat.xrd-tmp.7.9",
    "keep.dat.xrdresume.abcd1234.part",
    "note.commit",
]

# Inline pyxrootd probe (anon) — dirlist a directory or stat a path; prints JSON.
_ROOT_LS_STAT = r"""
import json, sys
from XRootD import client
from XRootD.client.flags import OpenFlags
url, path, op = sys.argv[1], sys.argv[2], sys.argv[3]
fs = client.FileSystem(url)
if op == "ls":
    st, listing = fs.dirlist(path)
    names = [e.name for e in listing] if (st.ok and listing) else []
    print(json.dumps({"ok": st.ok, "names": names}))
else:
    st, info = fs.stat(path)
    print(json.dumps({"ok": st.ok, "code": st.code, "errno": st.errno}))
"""


def _webdav_spec():
    return NginxInstanceSpec(
        name="lc-mu-sidecar-webdav",
        template="nginx_mu_stage_modes_webdav.conf",
        protocol="https",
        readiness="webdav",
        data_root=ports.MU.DATA_ROOT,
        template_values={
            "CERT": os.path.join(ports.MU.PKI_DIR, "server", "hostcert.pem"),
            "KEY": os.path.join(ports.MU.PKI_DIR, "server", "hostkey.pem"),
            "CA": os.path.join(ports.MU.CA_DIR, "ca.pem"),
        },
        reason="MU WebDAV node: internal-sidecar hiding (PROPFIND/GET).",
    )


def _root_spec():
    return NginxInstanceSpec(
        name="lc-mu-sidecar-root",
        template="nginx_mu_sidecar_root.conf",
        protocol="root",
        readiness="root",
        data_root=ports.MU.DATA_ROOT,
        reason="MU root:// anon node: internal-sidecar hiding (dirlist/stat).",
    )


@pytest.fixture(scope="module")
def cast():
    """Build the MU PKI/principal cast once for the module (idempotent)."""
    principals.build_cast()


@pytest.fixture
def sidecar_env(lifecycle, cast):
    d = os.path.join(ports.MU.DATA_ROOT, _PROBE)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, _KEEP), "wb") as f:
        f.write(b"K" * 2048)
    for nm in _INTERNAL:
        with open(os.path.join(d, nm), "wb") as f:
            f.write(b"SECRET-METADATA")
    webdav = lifecycle.start(_webdav_spec())
    root = lifecycle.start(_root_spec())
    return SimpleNamespace(webdav=webdav.url, root=root.url.rstrip("/"))


@pytest.fixture(scope="module")
def alice_proxy(cast):
    cert = os.path.join(ports.MU.PKI_DIR, "user", "alice_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", "alice_userkey.pem")
    return creds.gen_gsi_proxy(cert, key, "sidecar_alice")


def _root_probe(root_url, path, op):
    import json
    r = subprocess.run([sys.executable, "-c", _ROOT_LS_STAT, root_url, path, op],
                       capture_output=True, text=True, timeout=30)
    for line in r.stdout.splitlines():
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise AssertionError(f"root probe failed: {r.stderr[:300]}")


# ----------------------------- WebDAV ---------------------------------------- #

def test_webdav_propfind_hides_internal(sidecar_env, alice_proxy):
    """PROPFIND enumerates the genuine file but none of the internal artifacts."""
    r = requests.request("PROPFIND", f"{sidecar_env.webdav}/{_PROBE}",
                         headers={"Depth": "1"}, cert=alice_proxy, verify=False, timeout=30)
    assert r.status_code in (207, 200), f"PROPFIND failed: {r.status_code} {r.text[:200]}"
    hrefs = re.findall(r"<[^>]*href>([^<]+)<", r.text, re.IGNORECASE)
    bases = {h.rstrip("/").rsplit("/", 1)[-1] for h in hrefs}
    assert _KEEP in bases, f"genuine file {_KEEP} missing from PROPFIND: {bases}"
    leaked = bases & set(_INTERNAL)
    assert not leaked, f"LEAK: PROPFIND exposed internal artifacts: {leaked}"


def test_webdav_get_internal_is_404(sidecar_env, alice_proxy):
    """A direct GET of the genuine file works; a GET of any internal artifact is 404."""
    ok = requests.get(f"{sidecar_env.webdav}/{_PROBE}/{_KEEP}", cert=alice_proxy, verify=False, timeout=30)
    assert ok.status_code == 200, f"genuine GET should succeed: {ok.status_code}"
    for nm in _INTERNAL:
        rr = requests.get(f"{sidecar_env.webdav}/{_PROBE}/{nm}", cert=alice_proxy, verify=False, timeout=30)
        assert rr.status_code == 404, (
            f"LEAK: GET of internal {nm} returned {rr.status_code} (must be 404); "
            f"body[:80]={rr.text[:80]!r}")


# ----------------------------- root:// --------------------------------------- #

def test_root_dirlist_hides_internal(sidecar_env):
    """kXR_dirlist enumerates the genuine file but none of the internal artifacts."""
    res = _root_probe(sidecar_env.root, f"/{_PROBE}", "ls")
    assert res["ok"], f"dirlist failed: {res}"
    names = set(res["names"])
    assert _KEEP in names, f"genuine file {_KEEP} missing from dirlist: {names}"
    leaked = names & set(_INTERNAL)
    assert not leaked, f"LEAK: dirlist exposed internal artifacts: {leaked}"


def test_root_stat_internal_is_absent(sidecar_env):
    """kXR_stat of the genuine file succeeds; stat of any internal artifact reports absent."""
    assert _root_probe(sidecar_env.root, f"/{_PROBE}/{_KEEP}", "stat")["ok"], "genuine stat should succeed"
    for nm in _INTERNAL:
        res = _root_probe(sidecar_env.root, f"/{_PROBE}/{nm}", "stat")
        assert not res["ok"], f"LEAK: stat of internal {nm} succeeded: {res}"
