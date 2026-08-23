# tests/test_cvmfs_mount_opts.py — brixcvmfs `-o` parse contract.
#
# Theme: `parse_opts` splits every `-o` list into brix flag tokens
# (`opts_o_flag`), brix key=value tokens (`opts_o_kv`), and a libfuse
# passthrough tail (`fuse_extra`) — client/apps/fs/brixcvmfs.c. The contract
# pinned here:
#   * success — unknown VALUES of known brix keys (cache_format=, index=) warn
#     and fall back (flat / none); the mount still comes up and serves.
#   * error — an unknown TOKEN is not silently swallowed as a brix option: it
#     is forwarded to libfuse, which refuses the mount ("unknown option").
#   * security-neg — an explicit `-o pin=` wins over a hostile $BRIXCVMFS_PIN:
#     garbage in the environment cannot unpin or re-pin a mount that names its
#     root catalog on the command line (user.root_hash reports the CLI pin).
#
# Deeper pin semantics (drift, tamper, unparsable refusal) live in
# test_cvmfs_pin_root.py; packed/tiering arming lives in
# test_cvmfs_packed_client.py. Origin ports are OS-assigned (bind 0).
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

def _guard_opt_mount_1(env_extra, env):
    if env_extra:
        env.update(env_extra)

def _guard_opt_mount_2(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import File, RepoForge  # noqa: E402
from settings import BIND_HOST, HOST  # noqa: E402

REPO = "test.cern.ch"
HELLO = b"mount-opts corpus\n"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def repo():
    """Forged single-file repo served on an OS-assigned port for the whole
    module. Private mkdtemp, not tmp_path: the shared basetemp rotates under
    concurrent sessions and this webroot must survive the module."""
    work = Path(tempfile.mkdtemp(prefix="cvmfs_opts."))
    forge = RepoForge(REPO, work / "web").build({"hello.txt": File(HELLO)},
                                                work / "master.pub")
    httpd = ThreadingHTTPServer((BIND_HOST, 0),
                                partial(_QuietHandler, directory=str(work / "web")))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield {"pub": work / "master.pub", "port": httpd.server_address[1],
               "root_hash": forge.root_catalog_hash}
    finally:
        httpd.shutdown()
        httpd.server_close()
        shutil.rmtree(work, ignore_errors=True)


@contextmanager
def opt_mount(repo, opts, *, env_extra=None, timeout=15):
    """brixMount with a caller-built `-o` list; yields (mnt, log path). The
    mount may legitimately not come up — callers check os.path.ismount."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_opts_mnt."))
    mnt = workdir / "mnt"
    for d in ("mnt", "tmp", "cache"):
        (workdir / d).mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(repo["pub"])
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    env["BRIXCVMFS_SERVER"] = f"http://{HOST}:{repo['port']}/cvmfs/{REPO}"
    _guard_opt_mount_1(env_extra, env)

    log = workdir / "brixmount.log"
    with open(log, "wb") as lf:
        proc = subprocess.Popen([BRIXMOUNT, "cvmfs", REPO, str(mnt), "-o", opts, "-f"],
                                env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, log
    finally:
        _unmount(mnt)
        _guard_opt_mount_2(proc)
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


BASE = "auto_unmount,attr_timeout=0,entry_timeout=0,retries=1"


def test_unknown_values_of_known_keys_warn_and_fall_back(repo):
    """cache_format=/index= with unknown values must warn (naming the value)
    but keep the mount serving on the flat/none fallbacks."""
    with opt_mount(repo, BASE + ",quota=1,cache_format=bogus,index=bogus") as (mnt, log):
        assert os.path.ismount(mnt), log.read_text(errors="replace")
        assert (mnt / "hello.txt").read_bytes() == HELLO
        text = log.read_text(errors="replace")
        assert "unknown cache_format 'bogus'" in text
        assert "unknown index 'bogus'" in text


def test_unknown_token_forwarded_to_fuse_not_swallowed(repo):
    """A token that is neither a brix flag nor key=value must reach libfuse
    verbatim — fuse's refusal is the proof it was not silently eaten."""
    with opt_mount(repo, BASE + ",definitely_not_an_option_xyz", timeout=5) as (mnt, log):
        assert not os.path.ismount(mnt), "unknown -o token must not be swallowed"
        assert "unknown option" in log.read_text(errors="replace")


def test_cli_pin_wins_over_hostile_env_pin(repo):
    """`-o pin=` takes precedence over $BRIXCVMFS_PIN: garbage in the
    environment neither refuses nor re-pins an explicitly pinned mount."""
    with opt_mount(repo, BASE + f",pin={repo['root_hash']}",
                   env_extra={"BRIXCVMFS_PIN": "not-a-hash"}) as (mnt, log):
        assert os.path.ismount(mnt), log.read_text(errors="replace")
        assert os.getxattr(mnt, "user.root_hash").decode() == repo["root_hash"]
        assert (mnt / "hello.txt").read_bytes() == HELLO
