# tests/test_cvmfs_pin_root.py — Phase-85 F6: reproducibility pin.
# `-o pin=<root-catalog-hash>` (or $BRIXCVMFS_PIN) pins a brixMount cvmfs mount
# to an exact root catalog.  Port block 13460-13479.
#
# Contract (docs/refactor/phase-85-cvmfs-swiss-army-features.md § F6):
#   * the pinned mount serves the pinned catalog even when the upstream repo has
#     already advanced (user.root_hash reports the PIN, listing = pinned tree);
#   * a TTL refresh against an advanced upstream keeps serving the pin and emits
#     exactly ONE `signal=pindrift` audit line per drift transition;
#   * a tampered pin target is refused (the CAS fetch is hash-verified), even
#     though the un-pinned trust chain is perfectly healthy;
#   * an unparsable pin refuses the mount up front.
#
# Source contracts pinned from:
#   shared/cvmfs/client/client.c   — load_trust_and_catalog opens the PIN hash
#       instead of the manifest's and records drift; cvmfs_client_refresh never
#       swaps a pinned catalog; user.root_hash/user.revision describe the pin.
#   client/apps/fs/brixcvmfs.c     — `-o pin=` / $BRIXCVMFS_PIN parse,
#       brix_refresh() audit line `signal=pindrift ... serving=pinned`.
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from test_cvmfs_conformance_fuse_refresh_failover import publish_revision  # noqa: E402

REPO = "test.cern.ch"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

# ---- port block 13460-13479 (tests/cvmfs/conformance_common.py) ------------
P_PIN_SERVE = 13460
P_PIN_TAMPER = 13461
P_PIN_BADHEX = 13462


# ---- static origin (no fault injection needed: tamper edits the webroot) ----
class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


@contextmanager
def static_origin(port, webroot):
    handler = partial(_QuietHandler, directory=str(webroot))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()


@contextmanager
def pin_mount(pubkey, port, *, pin, expect_mounted=True, timeout=15):
    """brixMount with `-o pin=`; yields (mnt, proc, brixmount-log path). Unlike
    conf_mount it exposes the log (the pindrift audit contract lives there) and
    tolerates an expected mount refusal without retrying."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_pin."))
    mnt = workdir / "mnt"
    for d in ("mnt", "tmp", "cache"):
        (workdir / d).mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIXCVMFS_")}
    for k in ("http_proxy", "https_proxy", "all_proxy",
              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    env["BRIXCVMFS_SERVER"] = f"http://127.0.0.1:{port}/cvmfs/{REPO}"

    opts = f"auto_unmount,attr_timeout=0,entry_timeout=0,retries=1,pin={pin}"
    log = workdir / "brixmount.log"
    with open(log, "wb") as lf:
        proc = subprocess.Popen([BRIXMOUNT, "cvmfs", REPO, str(mnt), "-o", opts, "-f"],
                                env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc, log
    finally:
        if expect_mounted and not os.path.ismount(mnt) and log.exists():
            keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
            keep.mkdir(exist_ok=True)
            shutil.copy(log, keep / f"{workdir.name}.log")
        _unmount(mnt)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


def xattr(path, name):
    return os.getxattr(path, name).decode()


V1_ONLY = b"only-in-rev1\n"
V2_ONLY = b"only-in-rev2\n"


def _tree_v1():
    return {"stable.txt": File(b"stable\n"), "v1.txt": File(V1_ONLY)}


def _tree_v2():
    return {"stable.txt": File(b"stable\n"), "v2.txt": File(V2_ONLY)}


# ============================================================================
# Pinned mount vs an already-advanced upstream: serve the pin, record drift
# exactly once, never swap.
# ============================================================================

@pytest.mark.timeout(120)
class TestPinServesPinnedAcrossUpstreamAdvance:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("pin_serve")
        forge = RepoForge(REPO, tmp / "web", ttl=self.TTL, revision=1).build(
            _tree_v1(), tmp / "repo.pub")
        rev1_hash = forge.root_catalog_hash
        # upstream advances to rev2 BEFORE the pinned mount even starts: the
        # manifest the mount verifies already disagrees with the pin
        rev2_hash = publish_revision(forge, _tree_v2(), 2, ttl=self.TTL)
        obs = {"rev1_hash": rev1_hash, "rev2_hash": rev2_hash}
        try:
            with static_origin(P_PIN_SERVE, tmp / "web"), \
                 pin_mount(tmp / "repo.pub", P_PIN_SERVE, pin=rev1_hash) as (mnt, _, log):
                assert os.path.ismount(mnt), "pinned mount failed to come up"
                obs["ls"] = sorted(os.listdir(mnt))
                obs["v1_body"] = (mnt / "v1.txt").read_bytes()
                obs["root"] = xattr(mnt, "user.root_hash")
                obs["rev"] = xattr(mnt, "user.revision")

                # ride through TWO TTL refreshes: still pinned, still rev1
                for _ in range(2):
                    time.sleep(self.TTL + 1.0)
                    os.stat(mnt)          # getattr triggers the TTL refresh
                    os.listdir(mnt)
                obs["post_ls"] = sorted(os.listdir(mnt))
                obs["post_root"] = xattr(mnt, "user.root_hash")
                obs["log"] = log.read_text(errors="replace")
            yield obs
        finally:
            forge.close()

    def test_serves_pinned_tree(self, scn):
        assert scn["ls"] == ["stable.txt", "v1.txt"]
        assert scn["v1_body"] == V1_ONLY

    def test_root_hash_xattr_reports_pin(self, scn):
        assert scn["root"] == scn["rev1_hash"]

    def test_revision_xattr_reports_served_catalog(self, scn):
        assert scn["rev"] == "1"

    def test_refresh_never_swaps(self, scn):
        assert scn["post_ls"] == ["stable.txt", "v1.txt"]
        assert scn["post_root"] == scn["rev1_hash"]

    def test_exactly_one_drift_audit_line(self, scn):
        drift = [ln for ln in scn["log"].splitlines() if "signal=pindrift" in ln]
        assert len(drift) == 1, scn["log"]
        assert f"pinned={scn['rev1_hash']}" in drift[0]
        assert f"upstream={scn['rev2_hash']}" in drift[0]
        assert "serving=pinned" in drift[0]


# ============================================================================
# Security-negative: tampered pin target → mount refused (hash-verified fetch),
# even though the un-pinned repo is perfectly healthy at rev2.
# ============================================================================

@pytest.mark.timeout(120)
def test_tampered_pin_target_refused(tmp_path):
    forge = RepoForge(REPO, tmp_path / "web", revision=1).build(
        _tree_v1(), tmp_path / "repo.pub")
    rev1_hash = forge.root_catalog_hash
    try:
        publish_revision(forge, _tree_v2(), 2)
        forge.flip_byte(rev1_hash + "C", 40)      # corrupt the PINNED catalog object
        with static_origin(P_PIN_TAMPER, tmp_path / "web"), \
             pin_mount(tmp_path / "repo.pub", P_PIN_TAMPER, pin=rev1_hash,
                       expect_mounted=False, timeout=45) as (mnt, proc, log):
            proc.wait(60)                          # exits after its retry budget
            assert not os.path.ismount(mnt), "tampered pin target must not mount"
            assert proc.returncode != 0
            assert "trust/catalog error" in log.read_text(errors="replace")
    finally:
        forge.close()


# ============================================================================
# Error path: unparsable pin → refused up front, before any network activity.
# ============================================================================

@pytest.mark.timeout(60)
def test_unparsable_pin_refused(tmp_path):
    forge = RepoForge(REPO, tmp_path / "web", revision=1).build(
        _tree_v1(), tmp_path / "repo.pub")
    try:
        with static_origin(P_PIN_BADHEX, tmp_path / "web"), \
             pin_mount(tmp_path / "repo.pub", P_PIN_BADHEX, pin="not-a-hash",
                       expect_mounted=False, timeout=5) as (mnt, proc, log):
            proc.wait(10)
            assert not os.path.ismount(mnt)
            assert proc.returncode != 0
            assert "bad pin" in log.read_text(errors="replace")
    finally:
        forge.close()
