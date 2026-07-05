# brix-remote-skip
"""
Conformance gate (phase-37 M10): the native xrdcp/xrdfs vs the system tools.

For a matrix of operations this runs the SAME command through the project's
clean-room binaries (TEST_XRDCP_BIN / TEST_XRDFS_BIN, default ./client/xrdcp,
xrdfs) and through the system XRootD tools (/usr/bin/xrdcp, /usr/bin/xrdfs),
against both the nginx anon endpoint (direct) and the CMS redirector (:11160 →
data server :11162), then asserts identical observable behaviour:

  - same exit-code class (success vs failure),
  - same parsed value for stat (Size) and query (checksum hex),
  - same directory-entry SET for ls,
  - identical bytes (md5) for copies, including cross-tool (native↔system).

This is the gating behavioural diff behind the "clean-room, drop-in" claim: the
native tools must be indistinguishable from the reference for the user-visible
contract, while linking none of libXrdCl/libXrdSec*.

Run (against a manually-started fleet, dodging the conftest start-all flake):
    TEST_SKIP_SERVER_SETUP=1 \
    TEST_XRDFS_BIN=$PWD/client/bin/xrdfs TEST_XRDCP_BIN=$PWD/client/bin/xrdcp \
    PYTHONPATH=tests pytest tests/test_native_client_conformance.py -v
"""

import hashlib
import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from settings import (
    CLUSTER_DS_DATA_ROOT,
    CLUSTER_REDIR_PORT,
    DATA_ROOT,
    NGINX_ANON_PORT,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

pytestmark = pytest.mark.timeout(120)

SYS_XRDFS = "/usr/bin/xrdfs"
SYS_XRDCP = "/usr/bin/xrdcp"

_CLEAN_ENV = {k: v for k, v in os.environ.items()}
_CLEAN_ENV.pop("X509_USER_PROXY", None)
_CLEAN_ENV.pop("X509_CERT_DIR", None)


def _have_system_tools():
    return os.path.exists(SYS_XRDFS) and os.path.exists(SYS_XRDCP)


if not _have_system_tools():
    pytest.skip("system xrootd tools not installed", allow_module_level=True)


def _port_up(port, timeout=1.0):
    try:
        with socket.create_connection((SERVER_HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


# Endpoint matrix: (label, url, data_root_that_backs_it).
def _endpoints():
    eps = [("direct", f"root://{SERVER_HOST}:{NGINX_ANON_PORT}", DATA_ROOT)]
    if _port_up(CLUSTER_REDIR_PORT):
        eps.append(("redir", f"root://{SERVER_HOST}:{CLUSTER_REDIR_PORT}",
                    CLUSTER_DS_DATA_ROOT))
    return eps


ENDPOINTS = _endpoints()
EP_IDS = [e[0] for e in ENDPOINTS]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _run(argv, timeout=60, **kw):
    return subprocess.run(argv, capture_output=True, text=True,
                          env=_CLEAN_ENV, timeout=timeout, **kw)


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _stat_size(stdout):
    m = re.search(r"^Size:\s*(\d+)\s*$", stdout, re.MULTILINE)
    return m.group(1) if m else None


def _ls_set(stdout):
    return {ln.strip().rstrip("/").rsplit("/", 1)[-1]
            for ln in stdout.splitlines() if ln.strip()}


def _ck_hex(stdout):
    parts = stdout.split()
    return parts[-1].lower() if len(parts) >= 1 and parts else None


def _ok(rc):
    """Collapse an exit code to its class: True=success, False=failure."""
    return rc == 0


def _seed(data_root, name, payload):
    path = os.path.join(data_root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(payload)
    return path


# --------------------------------------------------------------------------
# stat
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,url,droot", ENDPOINTS, ids=EP_IDS)
def test_conformance_stat(label, url, droot):
    name = f"_conf_stat_{os.getpid()}_{int(time.time()*1000)}.bin"
    path = _seed(droot, name, os.urandom(4321))
    try:
        n = _run([XRDFS_BIN, url, "stat", f"/{name}"])
        s = _run([SYS_XRDFS, url, "stat", f"/{name}"])
        assert _ok(n.returncode) == _ok(s.returncode) == True, \
            f"[{label}] rc native={n.returncode} system={s.returncode}\n{n.stderr}"
        assert _stat_size(n.stdout) == _stat_size(s.stdout) == "4321", \
            f"[{label}] size native={_stat_size(n.stdout)} system={_stat_size(s.stdout)}"
    finally:
        os.unlink(path)


@pytest.mark.parametrize("label,url,droot", ENDPOINTS, ids=EP_IDS)
def test_conformance_stat_missing(label, url, droot):
    missing = f"/_conf_absent_{os.getpid()}.bin"
    n = _run([XRDFS_BIN, url, "stat", missing])
    s = _run([SYS_XRDFS, url, "stat", missing])
    assert _ok(n.returncode) == _ok(s.returncode) == False, \
        f"[{label}] both should fail: native={n.returncode} system={s.returncode}"


# --------------------------------------------------------------------------
# ls
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,url,droot", ENDPOINTS, ids=EP_IDS)
def test_conformance_ls_set(label, url, droot):
    uid = f"{os.getpid()}_{int(time.time()*1000)}"
    sub = f"_conf_ls_{uid}"
    names = [f"{sub}/f{i}.bin" for i in range(3)]
    for nm in names:
        _seed(droot, nm, b"x")
    try:
        n = _run([XRDFS_BIN, url, "ls", f"/{sub}"])
        s = _run([SYS_XRDFS, url, "ls", f"/{sub}"])
        assert _ok(n.returncode) and _ok(s.returncode), \
            f"[{label}] ls rc native={n.returncode} system={s.returncode}"
        assert _ls_set(n.stdout) == _ls_set(s.stdout), (
            f"[{label}] ls set differs:\n"
            f"native={_ls_set(n.stdout)}\nsystem={_ls_set(s.stdout)}"
        )
    finally:
        shutil.rmtree(os.path.join(droot, sub), ignore_errors=True)


# --------------------------------------------------------------------------
# download / upload (md5, incl. cross-tool)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,url,droot", ENDPOINTS, ids=EP_IDS)
def test_conformance_download_md5(label, url, droot, tmp_path):
    name = f"_conf_dl_{os.getpid()}_{int(time.time()*1000)}.bin"
    path = _seed(droot, name, os.urandom(200000))
    origin = _md5(path)
    try:
        outn = str(tmp_path / "n.bin")
        outs = str(tmp_path / "s.bin")
        n = _run([XRDCP_BIN, "-f", f"{url}//{name}", outn])
        s = _run([SYS_XRDCP, "-f", f"{url}//{name}", outs])
        assert _ok(n.returncode) and _ok(s.returncode), \
            f"[{label}] download rc native={n.returncode} system={s.returncode}"
        assert _md5(outn) == origin, f"[{label}] native download bytes differ"
        assert _md5(outs) == origin, f"[{label}] system download bytes differ"
    finally:
        os.unlink(path)


def test_conformance_upload_cross_tool(tmp_path):
    """native-upload → system-download and system-upload → native-download both
    preserve md5 (the two tools write/read mutually compatible bytes)."""
    url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(123457))
    want = _md5(src)
    a = f"_conf_up_native_{os.getpid()}.bin"
    b = f"_conf_up_system_{os.getpid()}.bin"
    try:
        # native up → system down
        assert _ok(_run([XRDCP_BIN, "-f", src, f"{url}//{a}"]).returncode)
        outa = str(tmp_path / "a.bin")
        assert _ok(_run([SYS_XRDCP, "-f", f"{url}//{a}", outa]).returncode)
        assert _md5(outa) == want, "native-upload → system-download md5 mismatch"
        # system up → native down
        assert _ok(_run([SYS_XRDCP, "-f", src, f"{url}//{b}"]).returncode)
        outb = str(tmp_path / "b.bin")
        assert _ok(_run([XRDCP_BIN, "-f", f"{url}//{b}", outb]).returncode)
        assert _md5(outb) == want, "system-upload → native-download md5 mismatch"
    finally:
        for nm in (a, b):
            try:
                os.unlink(os.path.join(DATA_ROOT, nm))
            except OSError:
                pass


# --------------------------------------------------------------------------
# query checksum
# --------------------------------------------------------------------------

def test_conformance_query_checksum():
    url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
    name = f"_conf_ck_{os.getpid()}_{int(time.time()*1000)}.bin"
    path = _seed(DATA_ROOT, name, os.urandom(65537))
    try:
        n = _run([XRDFS_BIN, url, "query", "checksum", f"/{name}"])
        s = _run([SYS_XRDFS, url, "query", "checksum", f"/{name}"])
        assert _ok(n.returncode) and _ok(s.returncode), \
            f"checksum rc native={n.returncode} system={s.returncode}"
        assert _ck_hex(n.stdout) == _ck_hex(s.stdout), (
            f"checksum differs: native={_ck_hex(n.stdout)} system={_ck_hex(s.stdout)}"
        )
    finally:
        os.unlink(path)


# --------------------------------------------------------------------------
# cross-tool namespace interop (native mkdir, system sees it; and vice-versa)
# --------------------------------------------------------------------------

def test_conformance_mkdir_cross_tool():
    url = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
    d = f"_conf_mkdir_{os.getpid()}_{int(time.time()*1000)}"
    try:
        # native creates → system stats
        assert _ok(_run([XRDFS_BIN, url, "mkdir", f"/{d}"]).returncode)
        assert _ok(_run([SYS_XRDFS, url, "stat", f"/{d}"]).returncode), \
            "system xrdfs cannot see native-created dir"
        # native removes → system stat fails
        assert _ok(_run([XRDFS_BIN, url, "rmdir", f"/{d}"]).returncode)
        assert not _ok(_run([SYS_XRDFS, url, "stat", f"/{d}"]).returncode), \
            "system xrdfs still sees a native-removed dir"
    finally:
        shutil.rmtree(os.path.join(DATA_ROOT, d), ignore_errors=True)
