"""
Functional test: compare `xrdcp` downloads from the anonymous (no-auth)
endpoint of the local nginx-xrootd instance and an official xrootd reference
server. The test ensures both servers serve identical bytes for the same
on-disk file under `/tmp/xrd-test/data`.

This test attempts to start nginx (via `tests/manage_test_servers.sh start nginx`)
if it's not already responsive, and starts a short-lived reference xrootd
instance on port 11096 for the duration of the test module.
"""

# --- Python 3.9 compat (EL9 system python) --------------------------------
# This suite uses PEP 604 unions (`X | None`) in annotations. On Python 3.9
# those are evaluated at def-time and raise TypeError; PEP 604 only works at
# runtime on Python >= 3.10. `from __future__ import annotations` (PEP 563)
# makes ALL annotations in this module lazy strings, so 3.9 imports cleanly.
# DROP this block (and the import) once the minimum supported Python is >=3.10.
from __future__ import annotations
# --------------------------------------------------------------------------


import os
import subprocess
import tempfile
import time
import hashlib

import pytest
from settings import DATA_ROOT, HOST, NGINX_ANON_PORT, REF_BRIX_PORT, SERVER_HOST

# Each xrdcp call has a 20 s subprocess timeout; two calls + overhead = ~50 s.
# Set the function timeout above that to avoid pytest-timeout firing first.
pytestmark = pytest.mark.timeout(60)

NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL   = f"root://{HOST}:{REF_BRIX_PORT}"
DATA_DIR  = DATA_ROOT


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _run_xrdcp_get(remote: str) -> (int, bytes | None):
    """Run `xrdcp` to fetch a remote path to a temporary file and return
    (returncode, data_bytes_or_None).
    """
    with tempfile.NamedTemporaryFile(delete=False) as out:
        out_name = out.name
    env = os.environ.copy()
    env.pop("X509_USER_PROXY", None)
    env.pop("X509_CERT_DIR", None)
    proc = subprocess.run(["xrdcp", "-f", remote, out_name], env=env, capture_output=True, timeout=20)
    rc = proc.returncode
    data = None
    if rc == 0:
        try:
            with open(out_name, "rb") as fh:
                data = fh.read()
        except Exception:
            data = None
    try:
        os.unlink(out_name)
    except Exception:
        pass
    return rc, data


def test_xrdcp_compare_anon():
    """Create a small on-disk file and verify `xrdcp` can download the
    same bytes via the anonymous endpoint on both nginx and the reference
    xrootd server.
    """
    name = f"_xrdcp_cmp_{os.getpid()}_{int(time.time() * 1000)}.bin"
    disk_path = os.path.join(DATA_DIR, name)
    payload = os.urandom(4096)
    with open(disk_path, "wb") as fh:
        fh.write(payload)

    try:
        nginx_remote = f"{NGINX_URL}//{name}"
        ref_remote = f"{REF_URL}//{name}"

        rc_n, data_n = _run_xrdcp_get(nginx_remote)
        assert rc_n == 0 and data_n is not None, f"xrdcp failed against nginx anon: rc={rc_n}"

        rc_r, data_r = _run_xrdcp_get(ref_remote)
        assert rc_r == 0 and data_r is not None, f"xrdcp failed against ref xrootd: rc={rc_r}"

        assert _md5(data_n) == _md5(payload), "nginx served bytes differ from on-disk file"
        assert _md5(data_r) == _md5(payload), "ref xrootd served bytes differ from on-disk file"

    finally:
        try:
            os.unlink(disk_path)
        except Exception:
            pass
