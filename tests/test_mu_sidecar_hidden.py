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
import socket
import subprocess
import sys
import time

import pytest
import requests

from mu_authz_lib import creds, fleet, ports, principals

_PROBE = "sidecarprobe"
_KEEP = "keep.dat"                       # a genuine user file — must stay visible
_INTERNAL = [                            # must all be invisible
    "keep.dat.cinfo",
    "keep.dat.meta",
    "keep.dat.xrdcinfo",
    "keep.dat.xrd-tmp.7.9",
    "keep.dat.xrdresume.abcd1234.part",
    "note.commit",
]

_WEBDAV = f"https://{ports.MU.HOST}:{ports.MU.WEBDAV_STAGE}"
_ROOT = f"root://{ports.MU.HOST}:{ports.MU.SIDECAR_ROOT}"

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


def _port_open(p):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((ports.MU.HOST, p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _start(cfg_name, pid_name, port):
    subst = fleet._base_subst()
    text = open(os.path.join(fleet._CFG_SRC, cfg_name)).read()
    for k, v in subst.items():
        text = text.replace(k, v)
    dst = os.path.join(ports.MU.CONFIG_DIR, cfg_name)
    with open(dst, "w") as f:
        f.write(text)
    pidf = os.path.join(ports.MU.MU_ROOT, pid_name)
    subprocess.run([fleet.NGINX, "-c", dst, "-g", f"pid {pidf};"], check=True, capture_output=True)
    deadline = time.time() + 15
    while time.time() < deadline and not _port_open(port):
        time.sleep(0.2)
    if not _port_open(port):
        raise TimeoutError(f"server for {cfg_name} never listened on {port}")
    return pidf


@pytest.fixture(scope="module")
def sidecar_env():
    principals.build_cast()
    d = os.path.join(ports.MU.DATA_ROOT, _PROBE)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, _KEEP), "wb") as f:
        f.write(b"K" * 2048)
    for nm in _INTERNAL:
        with open(os.path.join(d, nm), "wb") as f:
            f.write(b"SECRET-METADATA")
    for dd in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR, os.path.join(ports.MU.LOG_DIR, "nginx_tmp")):
        os.makedirs(dd, exist_ok=True)
    pids = [
        _start("webdav_stage_noimp.conf", "sidecar_webdav.pid", ports.MU.WEBDAV_STAGE),
        _start("sidecar_root_anon.conf", "sidecar_root.pid", ports.MU.SIDECAR_ROOT),
    ]
    try:
        yield
    finally:
        for pidf in pids:
            try:
                os.kill(int(open(pidf).read().strip()), 15)
            except (ProcessLookupError, ValueError, FileNotFoundError):
                pass


@pytest.fixture(scope="module")
def alice_proxy():
    cert = os.path.join(ports.MU.PKI_DIR, "user", "alice_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", "alice_userkey.pem")
    return creds.gen_gsi_proxy(cert, key, "sidecar_alice")


def _root_probe(path, op):
    import json
    r = subprocess.run([sys.executable, "-c", _ROOT_LS_STAT, _ROOT, path, op],
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
    r = requests.request("PROPFIND", f"{_WEBDAV}/{_PROBE}",
                         headers={"Depth": "1"}, cert=alice_proxy, verify=False, timeout=30)
    assert r.status_code in (207, 200), f"PROPFIND failed: {r.status_code} {r.text[:200]}"
    hrefs = re.findall(r"<[^>]*href>([^<]+)<", r.text, re.IGNORECASE)
    bases = {h.rstrip("/").rsplit("/", 1)[-1] for h in hrefs}
    assert _KEEP in bases, f"genuine file {_KEEP} missing from PROPFIND: {bases}"
    leaked = bases & set(_INTERNAL)
    assert not leaked, f"LEAK: PROPFIND exposed internal artifacts: {leaked}"


def test_webdav_get_internal_is_404(sidecar_env, alice_proxy):
    """A direct GET of the genuine file works; a GET of any internal artifact is 404."""
    ok = requests.get(f"{_WEBDAV}/{_PROBE}/{_KEEP}", cert=alice_proxy, verify=False, timeout=30)
    assert ok.status_code == 200, f"genuine GET should succeed: {ok.status_code}"
    for nm in _INTERNAL:
        rr = requests.get(f"{_WEBDAV}/{_PROBE}/{nm}", cert=alice_proxy, verify=False, timeout=30)
        assert rr.status_code == 404, (
            f"LEAK: GET of internal {nm} returned {rr.status_code} (must be 404); "
            f"body[:80]={rr.text[:80]!r}")


# ----------------------------- root:// --------------------------------------- #

def test_root_dirlist_hides_internal(sidecar_env):
    """kXR_dirlist enumerates the genuine file but none of the internal artifacts."""
    res = _root_probe(f"/{_PROBE}", "ls")
    assert res["ok"], f"dirlist failed: {res}"
    names = set(res["names"])
    assert _KEEP in names, f"genuine file {_KEEP} missing from dirlist: {names}"
    leaked = names & set(_INTERNAL)
    assert not leaked, f"LEAK: dirlist exposed internal artifacts: {leaked}"


def test_root_stat_internal_is_absent(sidecar_env):
    """kXR_stat of the genuine file succeeds; stat of any internal artifact reports absent."""
    assert _root_probe(f"/{_PROBE}/{_KEEP}", "stat")["ok"], "genuine stat should succeed"
    for nm in _INTERNAL:
        res = _root_probe(f"/{_PROBE}/{nm}", "stat")
        assert not res["ok"], f"LEAK: stat of internal {nm} succeeded: {res}"
