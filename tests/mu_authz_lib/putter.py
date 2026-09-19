"""Thin write helper for F6 byte-ownership tests (spec §6/F6).

put_as(principal, path, data, proto) writes `data` to `path` as `principal` via the given
protocol's cache (write-through) server. Used to assert the on-disk object is owned by the
principal's mapped uid (real setfsuid impersonation).
"""
import os
import subprocess
import sys

from . import fleet, ports
from .adapters import _root_env

_PUT_PROBE = r'''
import sys
from XRootD import client
from XRootD.client.flags import OpenFlags
url, path, data = sys.argv[1], sys.argv[2], sys.argv[3].encode()
f = client.File()
# lstrip: exactly two slashes after the authority — see mu_authz_lib.adapters.
st, _ = f.open(url + "//" + path.lstrip("/"), OpenFlags.NEW | OpenFlags.WRITE)
if st.ok:
    f.write(data)
    f.close()
sys.exit(0 if st.ok else 3)
'''


def put_as(principal, path: str, data: bytes, proto: str = "root") -> bool:
    """Write `data` to `path` as `principal`. Returns True on success.

    The root plane writes to the IMPERSONATING node, not to the cache node.  Two
    reasons, and both would otherwise silently defeat the attribution these
    writes exist to prove: the cache node fills from a remote anonymous origin,
    so a write through it is performed by that server's worker and lands owned
    by ``nobody``; and it enforces the corpus authdb, whose grants are `rl`, so
    the write is refused before it can be attributed to anyone at all."""
    if proto == "root":
        url = fleet.url("root", "write")
        r = subprocess.run([sys.executable, "-c", _PUT_PROBE, url, path, data.decode()],
                           env=_root_env(principal), capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    if proto == "webdav":
        import requests
        kw: dict = {"timeout": 30, "verify": False, "data": data}
        if getattr(principal, "token", ""):
            kw["headers"] = {"Authorization": "Bearer " + open(principal.token).read().strip()}
        elif getattr(principal, "proxy", ""):
            kw["cert"] = principal.proxy
        # The WebDAV write plane is the STAGE node — the cache node enforces the
        # read-only corpus grants, same as the root plane above.
        resp = requests.put(fleet.url("webdav", "stage") + path, **kw)
        return resp.status_code in (200, 201, 204)
    raise ValueError(f"put_as: unsupported proto {proto}")


def export_stat(rel_path: str) -> os.stat_result:
    """Stat the on-disk export object (to check the owning uid of a written file)."""
    return os.stat(os.path.join(ports.MU.DATA_ROOT, rel_path.lstrip("/")))
