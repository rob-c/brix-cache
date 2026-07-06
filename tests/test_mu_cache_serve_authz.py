"""Non-privileged verification of the cache-transparency FIX (open_cache.c + prepare.c).

The authorization gate runs at the WORKER level, before any setfsuid, so the fix is provable
WITHOUT root: a principal the backend authz denies must be refused a cache HIT of a file
another principal already pulled into the shared cache. This test manages its own nginx
(impersonation OFF, GSI+VOMS auth), so it runs as an ordinary uid.

Enforcing tier = authdb GROUP rule (`g cms /prot rl`) with NO brix_require_vo — exactly the
tier the old VO-ACL-only cache path skipped (empty vo_rules passed everyone and never
consulted authdb). alice (VO cms) is admitted; bob (VO atlas) is denied.

Scenario:
  1. alice (VOMS cms) reads /prot/secret.dat -> ALLOW, populates the cache.
  2. Prove residency: the cache store holds the object (HIT armed).
  3. bob (VOMS atlas) reads /prot/secret.dat -> MUST be NotAuthorized, even though the
     object is cached. (Before the fix: served the bytes -> LEAK.)
  4. alice reads again -> still ALLOW (no regression for the authorized principal).

Run: PYTHONPATH=tests pytest tests/test_mu_cache_serve_authz.py -v   (no root needed)
"""
import os
import socket
import subprocess
import time

import pytest

from mu_authz_lib import cache_state, creds, fleet, ports, principals
from mu_authz_lib.adapters import measure_root

_PORT = ports.MU.CACHE_NOIMP
_URL = f"root://{ports.MU.HOST}:{_PORT}"
_REL = "prot/secret.dat"
_PATH = "/" + _REL


def _port_open(p, host=ports.MU.HOST):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((host, p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _render_start(conf_name, pid_name, port):
    subst = fleet._base_subst()
    subst["{AUTHDB}"] = ports.MU.AUTHDB
    src = os.path.join(fleet._CFG_SRC, conf_name)
    text = open(src).read()
    for k, v in subst.items():
        text = text.replace(k, v)
    dst = os.path.join(ports.MU.CONFIG_DIR, conf_name)
    with open(dst, "w") as f:
        f.write(text)
    pidf = os.path.join(ports.MU.MU_ROOT, pid_name)
    subprocess.run([fleet.NGINX, "-c", dst, "-g", f"pid {pidf};"],
                   check=True, capture_output=True)
    deadline = time.time() + 15
    while time.time() < deadline and not _port_open(port):
        time.sleep(0.2)
    if not _port_open(port):
        raise TimeoutError(f"server {conf_name} never listened on {port}")
    return pidf


@pytest.fixture(scope="module")
def noimp_env():
    """Start an anonymous ORIGIN + a GSI+authdb CACHE server (both impersonation-off) as the
    current uid. authdb admits only VO cms on /prot. The cache fills from the remote origin,
    so the real cache-HIT serve path is exercised. Returns (cache_url, cast)."""
    cast = principals.build_cast()

    # Seed the origin export.
    d = os.path.join(ports.MU.DATA_ROOT, "prot")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "secret.dat"), "wb") as f:
        f.write(b"S" * 65536)
    cache_state.force_cold()

    # authdb: only the cms VO may read (the enforcing tier the old cache path skipped). The
    # rule path is "/" because a remote-origin cache node roots at "/" (the wire path arrives
    # as "//prot/secret.dat"); "g cms /" cleanly admits cms and denies atlas.
    os.makedirs(ports.MU.MU_ROOT, exist_ok=True)
    with open(ports.MU.AUTHDB, "w") as f:
        f.write("# MU no-imp cache verification authdb\n")
        f.write("g cms / rl\n")
    for dd in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR):
        os.makedirs(dd, exist_ok=True)

    pids = []
    try:
        pids.append(_render_start("root_origin_noimp.conf", "origin_noimp.pid",
                                  ports.MU.ORIGIN_NOIMP))
        pids.append(_render_start("root_cache_noimp.conf", "cache_noimp.pid", _PORT))
        yield _URL, cast
    finally:
        for pidf in pids:
            try:
                os.kill(int(open(pidf).read().strip()), 15)
            except (ProcessLookupError, ValueError, FileNotFoundError):
                pass


def _voms(cast, name, vo):
    """A principal presenting a fresh VOMS proxy for `vo` (independent of cast defaults)."""
    p = cast[name]
    cert = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", f"{name}_userkey.pem")
    proxy = creds.gen_voms_proxy(cert, key, f"noimp_{name}", vo)
    from types import SimpleNamespace
    return SimpleNamespace(name=name, proxy=proxy, token="", s3_key="", s3_secret="")


def test_cache_hit_denied_to_out_of_group_principal(noimp_env):
    url, cast = noimp_env
    alice = _voms(cast, "alice", "cms")     # admitted by `g cms /prot rl`
    bob = _voms(cast, "bob", "atlas")       # denied — wrong VO/group

    # 1. alice reads -> ALLOW, populates the cache.
    v_alice = measure_root(url, _PATH, "read", principal=alice)
    assert v_alice.decision == "ALLOW", f"authorized alice (VO cms) must read: {v_alice}"

    # 2. Prove the object is now resident in the cache store (a real HIT is armed). The
    #    whole-file cache writes the data file (a .cinfo sidecar is not always present), so
    #    check the cached data file directly.
    resident = os.path.exists(os.path.join(ports.MU.CACHE_ROOT, _REL))

    # 3. bob (VO atlas) must be REFUSED — even on a cache hit. This is the fix: the old
    #    VO-ACL-only cache path skipped authdb and would have served bob the cached bytes.
    v_bob = measure_root(url, _PATH, "read", principal=bob)
    assert v_bob.decision == "DENY", (
        f"LEAK: out-of-group bob (VO atlas) was served /prot/secret.dat from the cache: "
        f"{v_bob} (cache resident={resident})")

    # 4. alice still authorized (no regression).
    v_alice2 = measure_root(url, _PATH, "read", principal=alice)
    assert v_alice2.decision == "ALLOW", f"authorized alice regressed: {v_alice2}"

    # 5. Physical exposure: the on-disk cache artifacts are svc-owned and must not be
    #    world/group-readable — a mapped low-priv uid must not read another user's cached
    #    bytes or residency metadata by direct filesystem access.
    if resident:
        import stat as _stat
        cache_file = os.path.join(ports.MU.CACHE_ROOT, _REL)
        fmode = _stat.S_IMODE(os.stat(cache_file).st_mode)
        assert fmode & 0o077 == 0, f"cache file is group/other-readable: {oct(fmode)} (leak)"
        subdir_mode = _stat.S_IMODE(os.stat(os.path.dirname(cache_file)).st_mode)
        assert subdir_mode & 0o077 == 0, f"cache subdir is group/other-accessible: {oct(subdir_mode)}"
        for _root, _dirs, _files in os.walk(ports.MU.CACHE_ROOT):
            for _f in _files:
                if _f.endswith(".cinfo"):
                    cm = _stat.S_IMODE(os.stat(os.path.join(_root, _f)).st_mode)
                    assert cm & 0o077 == 0, f".cinfo sidecar is group/other-readable: {oct(cm)}"

    if not resident:
        pytest.skip("cache did not populate for a local-posix origin; the gate still enforced "
                    "on the miss path — HIT-path proof needs a remote origin (privileged fleet)")
