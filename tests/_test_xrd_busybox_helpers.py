"""
Phase-41 BusyBox-style POSIX verbs on the unified `xrd` front-end:

    xrd head [-c BYTES] [-n LINES] <url>      first bytes/lines
    xrd tail [-n LINES] [-f] <url>            last lines / follow
    xrd df [-h] <url>                         friendly disk-space report (Qspace)
    xrd touch [-c] <url>                       create-if-absent + set times (NO chown)
    xrd ln [-s] <target> <url>                 hard / symbolic link
    xrd readlink <url>                         print a symlink target
    xrd chmod [-R] <url> <octal>               octal chmod (+ recursive)
    xrd mount | xrd mounts                     list active XRootD FUSE mounts

Self-hosts a writable root:// server (the module advertises `xrdfs.ext`
unconditionally, so the link/setattr verbs work end-to-end). The mount-listing
tests need no server — they drive the /proc/self/mountinfo parser via the
XRD_MOUNTINFO_PATH override.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_xrd_busybox.py -v -p no:xdist
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, NGINX_WEBDAV_PORT
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrd-busybox")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrd", "xrdfs", "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    for b in ("xrd", "xrdfs"):
        if not os.path.exists(os.path.join(CLIENT_DIR, "bin", b)):
            pytest.skip(f"{b} build failed")


@pytest.fixture()
def rw(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / "lines.txt").write_text("".join(f"line{i}\n" for i in range(1, 21)))
    (data / "small.txt").write_text("abcdefghij")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrd-busybox",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="BusyBox-style POSIX verbs against a writable anon root server"))
    return {"port": ep.port, "data": data}


def _url(rw, path=""):
    return f"root://{HOST}:{rw['port']}/{path}"


def _run(*args, **kw):
    return subprocess.run([XRD, *args], capture_output=True, text=True,
                          timeout=kw.pop("timeout", 30), **kw)


# ----------------------------- head -----------------------------------------

def _clean_cred_env(tmp_path):
    """Env with no discoverable token/proxy, so doctor's local-cred check (which would
    flag a stray expired ~/x509 proxy on the host) doesn't perturb the exit code."""
    env = dict(os.environ, X509_USER_PROXY=str(tmp_path / "no_such_proxy"))
    for k in ("BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR"):
        env.pop(k, None)
    return env
