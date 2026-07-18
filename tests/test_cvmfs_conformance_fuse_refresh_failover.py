# tests/test_cvmfs_conformance_fuse_refresh_failover.py — Phase-84 fuse corpus:
# TTL-gated refresh, replica failover, retry budget, range-resume, proxy
# precedence, -o fresh / -o tls.  Port block 13400-13419.
#
# Reference-correctness rule: official CVMFS behaviour is asserted; where brix
# deliberately or accidentally diverges the test is xfail(strict=True) with a
# `# DIVERGENCE:` comment (see docs/refactor/phase-84-cvmfs-conformance-corpus.md).
#
# Source contracts pinned from:
#   shared/cvmfs/client/client.c      — cvmfs_client_refresh: TTL-gated (manifest
#       D field, default 240), keeps old catalog on ANY refresh failure, swaps on
#       root-hash change only (no revision monotonicity check), and commits
#       cl->manifest at parse time BEFORE verify/catalog fetch.
#   shared/cvmfs/failover/failover.c  — sticky lowest-live-index selection,
#       snap-back blacklist (2s base, doubling), proxy groups.
#   shared/cvmfs/config/cvmfs_conf.c  — CVMFS_SERVER_URL split on ";,",
#       CVMFS_HTTP_PROXY groups ';' members '|', @fqrn@ expansion.
#   client/apps/fs/brixcvmfs.c        — transport: range-resume with 200-slide,
#       only NO-PROGRESS attempts consume the -o retries budget, -o fresh =
#       FRESH_CONNECT+FORBID_REUSE, -o tls = https-first with http fallback,
#       env-proxy (brix_proxy_resolve) beats config proxy beats DIRECT;
#       BRIXCVMFS_SERVER pins ONE host verbatim (never split as a list).
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zlib
import hashlib
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from random import Random

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402

REPO = "test.cern.ch"
TINY_PROXY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "tiny_proxy.py")

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

# ---- port block 13400-13419 (design doc §"Port blocks") --------------------
P_TTL = 13400
P_DOWN = 13401
P_TAMPER = 13402
P_DOWNGRADE = 13403
P_MIDREF = 13404
P_FO_A_DEAD, P_FO_A_LIVE = 13405, 13406
P_FO_B_PRI, P_FO_B_SEC = 13407, 13408
P_FO_C_PRI, P_FO_C_SEC = 13409, 13410
P_FO_D_PRI, P_FO_D_SEC = 13411, 13412
P_SYN_LIVE, P_SYN_DEAD = 13413, 13414
P_RETRY = 13415
P_RESUME = 13416
P_BLIND = 13417
P_PROXY_ORIGIN, P_PROXY_A = 13418, 13419
P_PROXY_B = 13405          # reused after the failover classes have torn down
P_OPTS = 13406             # reused after the failover classes have torn down

_PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


# ---- local in-process origin -----------------------------------------------
# mock_stratum1.py cannot express a Range-HONOURING mid-body sever (its fault
# modes replay the full body from 0), does not log the Range header, and its
# ctl plane is HTTP-only.  This origin serves a forged webroot in-process with:
#   * per-request log incl. the Range header (resume observation),
#   * sever_after=N: honour Range, send at most N body bytes, then close
#     (true mid-transfer sever → the client's range-resume path),
#   * ignore_range: answer every request 200-full (the 200-slide path),
#   * one-shot faults ("refuse" = close pre-status, "http500", "sever_half"),
#   * TCP connection counting (for -o fresh) and a stock geo API endpoint.
class LocalOrigin:
    def __init__(self, port, webroot, keepalive=False):
        self.port = port
        self.webroot = Path(webroot)
        self.keepalive = keepalive
        self.lock = threading.Lock()
        self.log = []               # [{"path","range"}]
        self.connections = 0
        self.ignore_range = False
        self.sever_after = 0
        self.faults = []            # [[mode, count, path_re]]
        self._httpd = None
        self._thread = None

    def start(self):
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def set_fault(self, mode, count, path_re=None):
        with self.lock:
            self.faults.append([mode, count, path_re])

    def clear_faults(self):
        with self.lock:
            self.faults.clear()

    def take_fault(self, path):
        with self.lock:
            for f in self.faults:
                if f[1] > 0 and (f[2] is None or f[2] in path):
                    f[1] -= 1
                    return f[0]
        return None

    def reset_counters(self):
        with self.lock:
            self.log.clear()
            self.connections = 0

    def requests(self, needle):
        with self.lock:
            return [dict(e) for e in self.log if needle in e["path"]]


def _make_handler(origin):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1" if origin.keepalive else "HTTP/1.0"

        def log_message(self, *a):
            pass

        def setup(self):
            with origin.lock:
                origin.connections += 1
            super().setup()

        def _reply(self, code, body, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            rng = self.headers.get("Range")
            with origin.lock:
                origin.log.append({"path": self.path, "range": rng})

            if "/api/v1.0/geo/" in self.path:          # identity proximity order
                n = len(self.path.rsplit("/", 1)[-1].split(","))
                order = ",".join(str(i + 1) for i in range(n))
                return self._reply(200, order.encode() + b"\n")

            mode = origin.take_fault(self.path)
            if mode == "refuse":                        # close before any status
                self.close_connection = True
                self.connection.close()
                return
            if mode == "http500":
                return self._reply(500, b"origin error")

            full = origin.webroot / self.path.lstrip("/")
            if not full.is_file():
                return self._reply(404, b"not found")
            body = full.read_bytes()

            start, end, code, extra = 0, len(body) - 1, 200, {}
            if rng and rng.startswith("bytes=") and not origin.ignore_range:
                a, _, b = rng[len("bytes="):].partition("-")
                try:
                    start = int(a)
                    end = int(b) if b else len(body) - 1
                except ValueError:
                    start, end = 0, len(body) - 1
                if start >= len(body):
                    return self._reply(416, b"", {"Content-Range": f"bytes */{len(body)}"})
                end = min(end, len(body) - 1)
                code = 206
                extra = {"Content-Range": f"bytes {start}-{end}/{len(body)}"}
            part = body[start:end + 1]

            sever = origin.sever_after
            if mode == "sever_half":
                sever = max(1, len(part) // 2)
            if sever and sever < len(part):
                # correct Content-Length, partial body, hard close: a true
                # mid-transfer sever (curl: CURLE_PARTIAL_FILE, keeps the bytes).
                self.send_response(code)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(part)))
                for k, v in extra.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(part[:sever])
                self.wfile.flush()
                self.close_connection = True
                self.connection.close()
                return
            self._reply(code, part, extra)

    return H


# ---- local helpers ----------------------------------------------------------

def cas_key(content, compressed=True):
    """CAS hex of a forged File(content) — hash of the STORED bytes, identical
    zlib.compress call to repo_forge._write_cas."""
    stored = zlib.compress(content) if compressed else content
    return hashlib.sha1(stored).hexdigest()


def cas_needle(content):
    k = cas_key(content)
    return f"{k[:2]}/{k[2:]}"


def publish_revision(forge, tree, revision, *, ttl=None):
    """Re-forge a NEW revision in place: rebuild the root catalog from `tree`,
    then rewrite + resign the manifest (repo_forge gap: no public revision-bump
    API — uses its internal builders, keys are kept until forge.close())."""
    forge.revision = revision
    # A coherent publisher stamps the catalog's own 'revision' property too —
    # the client cross-checks it against the manifest 'S' (rollback protection)
    # and refuses a catalog/manifest revision mismatch.
    forge.properties["revision"] = str(revision)
    if ttl is not None:
        forge.ttl = ttl
    root = Dir(entries=tree)
    forge.root_catalog_hash, forge.root_catalog_size = forge._build_catalog(
        "", "", root, is_nested=False, props=forge.properties)
    forge.rewrite_manifest(forge._manifest_fields())
    return forge.root_catalog_hash


@contextmanager
def conf_mount(fqrn, pubkey, *, server_env=None, server_url=None, proxy_conf=None,
               env_extra=None, opts_extra="", retries=1, timeout=15):
    """Full-control brixMount wrapper.  Unlike conformance_common.fuse_mount it
    can leave BRIXCVMFS_SERVER UNSET (required for CVMFS_SERVER_URL mirror lists
    — the env var pins a single host verbatim) and always strips ambient proxy
    variables for determinism.  ALWAYS unmounts on exit."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_rf."))
    mnt = workdir / "mnt"
    for d in ("mnt", "tmp", "cache"):
        (workdir / d).mkdir()
    env = {k: v for k, v in os.environ.items()
           if k not in _PROXY_VARS and not k.startswith("BRIXCVMFS_")}
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    if server_env is not None:
        env["BRIXCVMFS_SERVER"] = server_env
    if server_url is not None or proxy_conf is not None:
        etc = workdir / "etc"
        etc.mkdir()
        text = ""
        if server_url is not None:
            text += f'CVMFS_SERVER_URL="{server_url}"\n'
        if proxy_conf is not None:
            text += f'CVMFS_HTTP_PROXY="{proxy_conf}"\n'
        (etc / "default.conf").write_text(text)
        env["BRIXCVMFS_ETC"] = str(etc)
    for k, v in (env_extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = v

    opts = "auto_unmount,attr_timeout=0,entry_timeout=0"
    if retries is not None:
        opts += f",retries={retries}"
    if opts_extra:
        opts += "," + opts_extra
    argv = [BRIXMOUNT, "cvmfs", fqrn, str(mnt), "-o", opts, "-f"]
    bm_log = workdir / "brixmount.log"
    with open(bm_log, "wb") as lf:
        proc = subprocess.Popen(argv, env=env, stdout=lf, stderr=lf)
    try:
        _wait_mounted(mnt, timeout)
        if not os.path.ismount(mnt) and proc.poll() is not None:
            # rare transient full-trust-chain failure observed on this host
            # (~1/40 mounts; brixMount exits after its 6 attempts) — one retry
            # keeps genuinely-broken configs failing while absorbing the blip
            time.sleep(2.0)
            with open(bm_log, "ab") as lf:
                proc = subprocess.Popen(argv, env=env, stdout=lf, stderr=lf)
            _wait_mounted(mnt, timeout)
        yield mnt, proc
    finally:
        if not os.path.ismount(mnt) and bm_log.exists():
            # preserve diagnostics for mount failures (flake triage)
            keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
            keep.mkdir(exist_ok=True)
            shutil.copy(bm_log, keep / f"{workdir.name}.log")
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


def _forge(tmp, ttl=240, revision=1, tree=None):
    forge = RepoForge(REPO, tmp / "web", ttl=ttl, revision=revision).build(
        tree if tree is not None else _tree_v1(), tmp / "repo.pub")
    return forge, tmp / "web", tmp / "repo.pub"


CHANGE_V1 = b"change-v1\n"
CHANGE_V2 = b"change-v2-different-content\n"
KEEP_V1 = b"keep-v1\n"
REMOVE_V1 = b"remove-me-v1\n"
NEW_V2 = b"new-in-rev2\n"
LEAF_V1 = b"leaf-v1\n"


def _tree_v1():
    return {"keep.txt": File(KEEP_V1), "change.txt": File(CHANGE_V1),
            "remove.txt": File(REMOVE_V1), "sub": Dir({"leaf.txt": File(LEAF_V1)})}


def _tree_v2():
    return {"keep.txt": File(KEEP_V1), "change.txt": File(CHANGE_V2),
            "new.txt": File(NEW_V2), "sub": Dir({"leaf.txt": File(LEAF_V1)})}


def _url(port):
    return f"http://127.0.0.1:{port}/cvmfs/{REPO}"


def _stat_errno(path):
    try:
        os.stat(path)
        return 0
    except OSError as e:
        return e.errno


# ============================================================================
# TTL refresh — publish rev2 at origin; nothing changes inside D, everything
# switches atomically after D + a triggering getattr.
# ============================================================================

@pytest.mark.timeout(60)
class TestTtlRefresh:
    TTL = 5

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("ttl")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_TTL, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_TTL)) as (mnt, _):
                assert os.path.ismount(mnt), "brixMount failed to mount rev1"
                t0 = time.monotonic()
                obs["pre_ls"] = sorted(os.listdir(mnt))
                obs["pre_keep"] = (mnt / "keep.txt").read_bytes()
                obs["pre_rev"] = xattr(mnt, "user.revision")
                obs["pre_root"] = xattr(mnt, "user.root_hash")

                obs["rev2_hash"] = publish_revision(forge, _tree_v2(), 2)

                # -- inside the TTL window: the OLD catalog must keep serving --
                obs["in_ls"] = sorted(os.listdir(mnt))
                obs["in_change"] = (mnt / "change.txt").read_bytes()
                # deleted-in-rev2 file: still readable from the old catalog
                obs["in_remove"] = (mnt / "remove.txt").read_bytes()
                obs["in_rev"] = xattr(mnt, "user.revision")
                obs["in_root"] = xattr(mnt, "user.root_hash")
                assert time.monotonic() - t0 < self.TTL - 1, \
                    "in-TTL observations took too long to be meaningful"

                # -- past the TTL: a getattr triggers the refresh --
                time.sleep(max(0.0, (self.TTL + 1.5) - (time.monotonic() - t0)))
                os.stat(mnt)
                obs["post_ls"] = sorted(os.listdir(mnt))
                obs["post_new"] = (mnt / "new.txt").read_bytes()
                obs["post_change"] = (mnt / "change.txt").read_bytes()
                obs["post_keep"] = (mnt / "keep.txt").read_bytes()
                obs["post_remove_errno"] = _stat_errno(mnt / "remove.txt")
                obs["post_rev"] = xattr(mnt, "user.revision")
                obs["post_root"] = xattr(mnt, "user.root_hash")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_pre_listing_is_rev1(self, scn):
        assert scn["pre_ls"] == ["change.txt", "keep.txt", "remove.txt", "sub"]

    def test_pre_content(self, scn):
        assert scn["pre_keep"] == KEEP_V1

    def test_pre_revision_xattr(self, scn):
        assert scn["pre_rev"] == "1"

    def test_pre_root_hash_xattr(self, scn):
        assert scn["pre_root"] == scn["rev1_hash"]

    def test_within_ttl_new_file_not_visible(self, scn):
        assert "new.txt" not in scn["in_ls"]

    def test_within_ttl_listing_unchanged(self, scn):
        assert scn["in_ls"] == scn["pre_ls"]

    def test_within_ttl_changed_file_serves_old_bytes(self, scn):
        assert scn["in_change"] == CHANGE_V1

    def test_within_ttl_deleted_file_still_readable(self, scn):
        # rev2 removed it, but inside D the old catalog still serves it.
        assert scn["in_remove"] == REMOVE_V1

    def test_within_ttl_revision_xattr_stable(self, scn):
        assert scn["in_rev"] == "1"

    def test_within_ttl_root_hash_stable(self, scn):
        assert scn["in_root"] == scn["rev1_hash"]

    def test_post_ttl_new_file_visible(self, scn):
        assert "new.txt" in scn["post_ls"]

    def test_post_ttl_new_file_content(self, scn):
        assert scn["post_new"] == NEW_V2

    def test_post_ttl_changed_file_serves_new_bytes(self, scn):
        assert scn["post_change"] == CHANGE_V2

    def test_post_ttl_unchanged_file_stable(self, scn):
        assert scn["post_keep"] == KEEP_V1

    def test_post_ttl_removed_file_enoent(self, scn):
        import errno
        assert scn["post_remove_errno"] == errno.ENOENT

    def test_post_ttl_revision_xattr_updated(self, scn):
        assert scn["post_rev"] == "2"

    def test_post_ttl_root_hash_updated(self, scn):
        assert scn["post_root"] == scn["rev2_hash"]


# ============================================================================
# Refresh failure — origin down at TTL expiry: old catalog keeps serving,
# origin return → the NEXT due refresh succeeds.
# ============================================================================

@pytest.mark.timeout(90)
class TestRefreshOriginDown:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("down")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_DOWN, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_DOWN)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()          # warm the cache
                (mnt / "change.txt").read_bytes()
                publish_revision(forge, _tree_v2(), 2)
                origin.stop()

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                             # refresh attempt → fails
                obs["out_keep"] = (mnt / "keep.txt").read_bytes()
                obs["out_change"] = (mnt / "change.txt").read_bytes()
                obs["out_ls"] = sorted(os.listdir(mnt))
                obs["out_rev"] = xattr(mnt, "user.revision")
                obs["out_root"] = xattr(mnt, "user.root_hash")

                origin.start()                           # origin returns
                time.sleep(self.TTL + 1.5)               # next refresh window + blacklist lapse
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
                obs["rec_change"] = (mnt / "change.txt").read_bytes()
                obs["rec_rev"] = xattr(mnt, "user.revision")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_outage_warm_reads_still_correct(self, scn):
        assert scn["out_keep"] == KEEP_V1

    def test_outage_changed_file_serves_old_bytes(self, scn):
        assert scn["out_change"] == CHANGE_V1

    def test_outage_listing_unchanged(self, scn):
        assert "new.txt" not in scn["out_ls"] and "remove.txt" in scn["out_ls"]

    def test_outage_revision_xattr_stable(self, scn):
        # raw whitelist fetch fails FIRST, before the manifest buffer is touched,
        # so the manifest state stays rev1 on a full-outage refresh failure.
        assert scn["out_rev"] == "1"

    def test_outage_root_hash_stable(self, scn):
        assert scn["out_root"] == scn["rev1_hash"]

    def test_recovery_new_revision_visible(self, scn):
        assert "new.txt" in scn["rec_ls"] and "remove.txt" not in scn["rec_ls"]

    def test_recovery_changed_content(self, scn):
        assert scn["rec_change"] == CHANGE_V2

    def test_recovery_revision_xattr(self, scn):
        assert scn["rec_rev"] == "2"


# ============================================================================
# Refresh to a TAMPERED rev2 manifest — rejected; old catalog keeps serving.
# ============================================================================

@pytest.mark.timeout(90)
class TestRefreshTamperedManifest:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("tamper")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_TAMPER, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_TAMPER)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["rev2_hash"] = publish_revision(forge, _tree_v2(), 2)
                # tamper: zero out the manifest signature (verify must fail)
                forge.rewrite_manifest(forge._manifest_fields(), stale_sig=True)

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                             # refresh → verify fails
                obs["t_change"] = (mnt / "change.txt").read_bytes()
                obs["t_ls"] = sorted(os.listdir(mnt))
                obs["t_rev"] = xattr(mnt, "user.revision")
                obs["t_root"] = xattr(mnt, "user.root_hash")

                # repair the manifest signature → refresh should now succeed
                forge.rewrite_manifest(forge._manifest_fields())
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
                obs["rec_rev"] = xattr(mnt, "user.revision")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_tampered_manifest_old_content_keeps_serving(self, scn):
        assert scn["t_change"] == CHANGE_V1

    def test_tampered_manifest_no_partial_upgrade_in_listing(self, scn):
        assert "new.txt" not in scn["t_ls"] and "remove.txt" in scn["t_ls"]

    # RETIRED DIVERGENCE: refresh is now staged — load_trust_and_catalog parses
    # into a staging buffer and commit_manifest() installs it only after the
    # full chain verifies (client.c), so a rejected refresh leaves metadata
    # untouched and recovery is not wedged on "same revision".
    def test_tampered_manifest_revision_xattr_stable(self, scn):
        assert scn["t_rev"] == "1"

    def test_tampered_manifest_root_hash_xattr_stable(self, scn):
        assert scn["t_root"] == scn["rev1_hash"]

    def test_repaired_manifest_recovers_to_rev2(self, scn):
        assert "new.txt" in scn["rec_ls"]

    def test_repaired_manifest_revision_consistent_with_content(self, scn):
        # Official: metadata and served catalog always agree post-recovery.
        assert (scn["rec_rev"] == "2") == ("new.txt" in scn["rec_ls"])


# ============================================================================
# Revision downgrade — official client refuses a root-catalog rollback.
# ============================================================================

@pytest.mark.timeout(60)
class TestRevisionDowngrade:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("downgrade")
        forge, web, pub = _forge(tmp, ttl=self.TTL, revision=2, tree=_tree_v2())
        origin = LocalOrigin(P_DOWNGRADE, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_DOWNGRADE)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["pre_rev"] = xattr(mnt, "user.revision")
                obs["pre_ls"] = sorted(os.listdir(mnt))
                publish_revision(forge, _tree_v1(), 1)   # properly signed rollback
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["post_ls"] = sorted(os.listdir(mnt))
                obs["post_rev"] = xattr(mnt, "user.revision")
                obs["post_keep"] = (mnt / "keep.txt").read_bytes()
                obs["mount_alive"] = os.path.ismount(mnt)
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_mounted_rev2_before_rollback(self, scn):
        assert scn["pre_rev"] == "2" and "new.txt" in scn["pre_ls"]

    # RETIRED DIVERGENCE: cvmfs_client_refresh now refuses a revision downgrade
    # (staged manifest revision < installed revision → refresh rejected), so a
    # properly-signed rollback is ignored and rev2 keeps serving.
    def test_rollback_rejected_content_stays_rev2(self, scn):
        assert "new.txt" in scn["post_ls"]

    def test_rollback_rejected_revision_xattr_stays_2(self, scn):
        assert scn["post_rev"] == "2"

    def test_mount_remains_consistent_after_rollback_event(self, scn):
        # Whatever was decided, the mount must stay healthy and self-consistent.
        assert scn["mount_alive"] and scn["post_keep"] == KEEP_V1


# ============================================================================
# Mid-refresh catalog-object 404 — manifest bumped but new catalog CAS missing.
# ============================================================================

@pytest.mark.timeout(90)
class TestMidRefreshCatalog404:
    TTL = 6

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("midref")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_MIDREF, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_MIDREF)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                rev2_hash = publish_revision(forge, _tree_v2(), 2)
                obs["rev2_hash"] = rev2_hash
                cat = forge.artifact_path(rev2_hash + "C")
                saved = cat.read_bytes()
                cat.unlink()                              # the new catalog CAS is missing

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                              # refresh → catalog fetch 404
                # the 404 blacklists the (only) host+proxy for 2s — let the
                # snap-back lapse so observations reflect steady-state serving,
                # inside the TTL window so no second refresh interferes
                time.sleep(2.7)
                obs["m_change"] = (mnt / "change.txt").read_bytes()
                obs["m_ls"] = sorted(os.listdir(mnt))
                obs["m_root"] = xattr(mnt, "user.root_hash")

                cat.write_bytes(saved)                    # catalog appears at origin
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_missing_catalog_old_content_keeps_serving(self, scn):
        assert scn["m_change"] == CHANGE_V1

    def test_missing_catalog_no_partial_upgrade(self, scn):
        assert "new.txt" not in scn["m_ls"] and "remove.txt" in scn["m_ls"]

    # RETIRED DIVERGENCE: the staged refresh commits nothing until the new root
    # catalog is fetched and verified, so a mid-refresh 404 leaves rev1 metadata
    # intact and the restored catalog upgrades cleanly to rev2.
    def test_missing_catalog_root_hash_xattr_stable(self, scn):
        assert scn["m_root"] == scn["rev1_hash"]

    def test_catalog_restored_recovers_to_rev2(self, scn):
        assert "new.txt" in scn["rec_ls"]


# ============================================================================
# Host failover — CVMFS_SERVER_URL mirror lists (conf cascade; the env var
# BRIXCVMFS_SERVER pins a single host and cannot express a list).
# ============================================================================

# RETIRED DIVERGENCE (D5): cvmfs_failover_record() no longer blacklists a
# DIRECT pseudo-proxy on failure (failover.c) — a replica failure marks only the
# host, so cvmfs_failover_select() hands back the next replica instead of
# reporting offline.  Replica failover now matches official CVMFS.


@pytest.mark.timeout(90)
class TestFailoverPrimaryDownAtMount:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_a")
        forge, web, pub = _forge(tmp)
        sec = LocalOrigin(P_FO_A_LIVE, web).start()      # nothing on P_FO_A_DEAD
        obs = {"mounted": False, "keep": None, "sec_manifest_hits": 0}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_A_DEAD)};{_url(P_FO_A_LIVE)}"
                            ) as (mnt, _):
                obs["mounted"] = os.path.ismount(mnt)
                if obs["mounted"]:
                    obs["keep"] = (mnt / "keep.txt").read_bytes()
                obs["sec_manifest_hits"] = len(sec.requests(".cvmfspublished"))
            yield obs
        finally:
            sec.stop()
            forge.close()

    def test_mounts_despite_dead_primary(self, scn):
        assert scn["mounted"], "secondary mirror did not carry the mount"

    def test_reads_correct_via_secondary(self, scn):
        assert scn["keep"] == KEEP_V1

    def test_trust_chain_fetched_from_secondary(self, scn):
        assert scn["sec_manifest_hits"] >= 1


@pytest.mark.timeout(60)
class TestFailoverPrimaryDiesMidSession:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_b")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_B_PRI, web).start()
        sec = LocalOrigin(P_FO_B_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_B_PRI)};{_url(P_FO_B_SEC)}"
                            ) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["warm"] = (mnt / "keep.txt").read_bytes()
                obs["keep_via_pri"] = len(pri.requests(cas_needle(KEEP_V1)))
                pri.stop()
                try:
                    obs["cold"] = (mnt / "change.txt").read_bytes()
                    obs["cold_errno"] = 0
                except OSError as e:
                    obs["cold"] = None
                    obs["cold_errno"] = e.errno
                obs["change_via_sec"] = len(sec.requests(cas_needle(CHANGE_V1)))
                obs["warm_again"] = (mnt / "keep.txt").read_bytes()
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_sticky_primary_served_the_warm_read(self, scn):
        assert scn["keep_via_pri"] >= 1

    def test_cold_read_continues_via_secondary(self, scn):
        assert scn["cold"] == CHANGE_V1

    def test_secondary_actually_served_the_object(self, scn):
        assert scn["change_via_sec"] >= 1

    def test_cold_read_never_serves_wrong_bytes(self, scn):
        # holds in both worlds: either the correct bytes or a clean EIO.
        import errno
        assert scn["cold"] == CHANGE_V1 or scn["cold_errno"] == errno.EIO

    def test_warm_reread_unaffected(self, scn):
        assert scn["warm_again"] == KEEP_V1


@pytest.mark.timeout(60)
class TestFailoverBothDownAfterWarm:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_c")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_C_PRI, web).start()
        sec = LocalOrigin(P_FO_C_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_C_PRI)};{_url(P_FO_C_SEC)}"
                            ) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()          # warm one file
                pri.stop()
                sec.stop()
                obs["warm"] = (mnt / "keep.txt").read_bytes()
                try:
                    (mnt / "change.txt").read_bytes()
                    obs["cold_exc"] = None
                except OSError as e:
                    obs["cold_exc"] = e.errno
                obs["ls"] = sorted(os.listdir(mnt))
                obs["alive"] = os.path.ismount(mnt)
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_warm_read_served_from_cache_offline(self, scn):
        assert scn["warm"] == KEEP_V1

    def test_cold_read_fails_cleanly(self, scn):
        import errno
        assert scn["cold_exc"] == errno.EIO, \
            "offline cold read must be a clean EIO, never wrong bytes"

    def test_catalog_listing_still_works_offline(self, scn):
        assert "keep.txt" in scn["ls"]

    def test_mount_survives_total_outage(self, scn):
        assert scn["alive"]


@pytest.mark.timeout(90)
class TestFailoverPrimaryReturns:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_d")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_D_PRI, web).start()
        sec = LocalOrigin(P_FO_D_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_D_PRI)};{_url(P_FO_D_SEC)}",
                            timeout=25) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()
                pri.stop()
                try:
                    (mnt / "change.txt").read_bytes()    # official: via secondary
                except OSError:
                    pass                                 # brix D5: EIO while pri is dead
                pri.start()                              # primary returns
                time.sleep(3.5)                          # snap-back blacklist lapses
                obs["leaf"] = (mnt / "sub" / "leaf.txt").read_bytes()
                obs["leaf_via_pri"] = len(pri.requests(cas_needle(LEAF_V1)))
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_read_after_recovery_correct(self, scn):
        assert scn["leaf"] == LEAF_V1

    def test_sticky_selection_returns_to_primary(self, scn):
        assert scn["leaf_via_pri"] >= 1, \
            "after the blacklist lapses the geo-closest mirror must be reused"


@pytest.mark.timeout(120)
class TestServerListSyntax:
    @pytest.fixture(scope="class")
    def live(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("syntax")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_SYN_LIVE, web).start()
        try:
            yield web, pub
        finally:
            origin.stop()
            forge.close()

    def test_comma_separated_server_list_survives_dead_first_entry(self, live):
        # comma is a valid CVMFS_SERVER_URL separator; official mounts via the
        # live second entry (fails here per D5: no replica failover).
        _, pub = live
        with conf_mount(REPO, pub, timeout=20,
                        server_url=f"{_url(P_SYN_DEAD)},{_url(P_SYN_LIVE)}") as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_comma_separated_server_list_parses(self, live):
        # separator acceptance alone (both entries live — no failover needed).
        _, pub = live
        with conf_mount(REPO, pub,
                        server_url=f"{_url(P_SYN_LIVE)},{_url(P_SYN_LIVE)}") as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_fqrn_placeholder_expansion(self, live):
        _, pub = live
        url = f"http://127.0.0.1:{P_SYN_LIVE}/cvmfs/@fqrn@"
        with conf_mount(REPO, pub, server_url=url) as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_env_pin_beats_config_server_list(self, live):
        _, pub = live
        with conf_mount(REPO, pub, server_env=_url(P_SYN_LIVE),
                        server_url=_url(P_SYN_DEAD)) as (mnt, _):
            assert os.path.ismount(mnt), \
                "BRIXCVMFS_SERVER must override the config server list"
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    @pytest.mark.timeout(90)
    def test_env_pin_is_single_host_not_a_list(self, live):
        # brixcvmfs.c: BRIXCVMFS_SERVER is added verbatim as ONE host — a
        # semicolon list is not split, so the mount cannot come up.
        _, pub = live
        with conf_mount(REPO, pub,
                        server_env=f"{_url(P_SYN_LIVE)};{_url(P_SYN_LIVE)}",
                        timeout=20) as (mnt, _):
            assert not os.path.ismount(mnt)


# ============================================================================
# Retry budget — only NO-PROGRESS attempts consume `-o retries=N`.
# ============================================================================

@pytest.mark.timeout(150)
class TestRetryBudget:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        rnd = Random(84)
        obj_a, obj_b, obj_c = (rnd.randbytes(4096) for _ in range(3))
        payload = rnd.randbytes(6144)
        tree = {"a.bin": File(obj_a), "b.bin": File(obj_b),
                "c.bin": File(obj_c), "payload.bin": File(payload)}
        tmp = tmp_path_factory.mktemp("retry")
        forge, web, pub = _forge(tmp, tree=tree)
        origin = LocalOrigin(P_RETRY, web).start()
        obs = {}
        try:
            # -- resets within budget: N=2 faults, retries=3 → success ---------
            origin.set_fault("refuse", 2, path_re=cas_needle(obj_a))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=3) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["a"] = (mnt / "a.bin").read_bytes()
            obs["a_attempts"] = len(origin.requests(cas_needle(obj_a)))
            origin.clear_faults()

            # -- resets beyond budget: retries=1 → clean error, then recovery --
            origin.set_fault("refuse", 5, path_re=cas_needle(obj_b))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                try:
                    (mnt / "b.bin").read_bytes()
                    obs["b_exc"] = None
                except OSError as e:
                    obs["b_exc"] = e.errno
                origin.clear_faults()
                time.sleep(2.5)                          # snap-back blacklist lapses
                obs["b_retry"] = (mnt / "b.bin").read_bytes()
            origin.clear_faults()

            # -- retries=0 falls back to the built-in default budget (6) -------
            origin.set_fault("refuse", 4, path_re=cas_needle(obj_c))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=0) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["c"] = (mnt / "c.bin").read_bytes()
            origin.clear_faults()

            # -- progress does NOT consume budget: 1KiB sever per response,
            #    ~6 resumes needed, but retries=1 still succeeds ---------------
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.reset_counters()
                origin.sever_after = 1024
                obs["p"] = (mnt / "payload.bin").read_bytes()
                origin.sever_after = 0
            obs["p_reqs"] = origin.requests(cas_needle(payload))
            obs["payload"] = payload
            obs["obj_a"], obs["obj_b"], obs["obj_c"] = obj_a, obj_b, obj_c
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_resets_within_budget_read_succeeds(self, scn):
        assert scn["a"] == scn["obj_a"]

    def test_each_reset_consumed_one_attempt(self, scn):
        assert scn["a_attempts"] == 3          # 2 refused + 1 clean

    def test_resets_beyond_budget_clean_error(self, scn):
        import errno
        assert scn["b_exc"] == errno.EIO

    def test_recovery_after_faults_cleared(self, scn):
        assert scn["b_retry"] == scn["obj_b"]

    def test_retries_zero_means_default_budget(self, scn):
        assert scn["c"] == scn["obj_c"]

    def test_progress_attempts_do_not_consume_budget(self, scn):
        # ~6 severed-but-progressing attempts, budget 1: delivered-bytes progress
        # resets the stall counter (brixcvmfs.c transport loop).
        assert scn["p"] == scn["payload"]

    def test_progress_path_used_multiple_resumes(self, scn):
        assert len(scn["p_reqs"]) >= 3

    def test_resume_offsets_strictly_increase(self, scn):
        offs = [int(r["range"][len("bytes="):].rstrip("-"))
                for r in scn["p_reqs"] if r["range"]]
        assert offs == sorted(offs) and len(offs) == len(set(offs)) and offs, \
            "resume must continue from delivered bytes, never restart"


# ============================================================================
# Range-resume — severed large-object transfer resumes with a Range request;
# a Range-blind origin (200-full) is still handled byte-exactly (200-slide).
# ============================================================================

@pytest.mark.timeout(150)
class TestRangeResume:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        rnd = Random(85)
        big = rnd.randbytes(256 * 1024)
        blind_big = rnd.randbytes(128 * 1024)
        small = rnd.randbytes(4096)
        tmp = tmp_path_factory.mktemp("resume")
        forge, web, pub = _forge(
            tmp, tree={"big.bin": File(big), "blind.bin": File(blind_big),
                       "small.bin": File(small)})
        origin = LocalOrigin(P_RESUME, web).start()
        obs = {"big": big, "blind_big": blind_big, "small": small}
        try:
            # -- honouring origin, 64KiB sever per response --------------------
            with conf_mount(REPO, pub, server_env=_url(P_RESUME), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.reset_counters()
                origin.sever_after = 64 * 1024
                obs["got_big"] = (mnt / "big.bin").read_bytes()
                origin.sever_after = 0
            obs["big_reqs"] = origin.requests(cas_needle(big))
            obs["big_stored_len"] = len(zlib.compress(big))
            origin.stop()

            # -- Range-blind origin: one sever, resume answered 200-full -------
            blind = LocalOrigin(P_BLIND, web)
            blind.ignore_range = True
            blind.start()
            try:
                with conf_mount(REPO, pub, server_env=_url(P_BLIND), retries=2) as (mnt, _):
                    assert os.path.ismount(mnt), "mount failed"
                    blind.reset_counters()
                    blind.set_fault("sever_half", 1, path_re=cas_needle(blind_big))
                    try:
                        obs["got_blind"] = (mnt / "blind.bin").read_bytes()
                        obs["blind_errno"] = 0
                    except OSError as e:
                        obs["got_blind"] = None
                        obs["blind_errno"] = e.errno
                    obs["blind_reqs"] = blind.requests(cas_needle(blind_big))
                    blind.clear_faults()
                    time.sleep(2.5)                      # failure blacklist lapses

                    # persistent sever + Range-blind: can never progress past the
                    # sever point → must end in a clean error, never bad bytes
                    blind.sever_after = 1024
                    try:
                        (mnt / "small.bin").read_bytes()
                        obs["stuck_exc"] = None
                    except OSError as e:
                        obs["stuck_exc"] = e.errno
                    blind.sever_after = 0
                    time.sleep(2.5)                      # blacklist lapses
                    obs["small_after"] = (mnt / "small.bin").read_bytes()
            finally:
                blind.stop()
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_severed_transfer_delivers_byte_exact_result(self, scn):
        assert scn["got_big"] == scn["big"]

    def test_client_actually_resumed(self, scn):
        assert len(scn["big_reqs"]) >= 3

    def test_first_request_has_no_range_header(self, scn):
        assert scn["big_reqs"][0]["range"] is None

    def test_resume_requests_carry_range_from_delivered_offset(self, scn):
        offs = [int(r["range"][len("bytes="):].rstrip("-"))
                for r in scn["big_reqs"][1:]]
        step = 64 * 1024
        assert offs == list(range(step, scn["big_stored_len"], step))

    def test_range_blind_origin_still_byte_exact(self, scn):
        # RETIRED DIVERGENCE (D6): CURLE_RANGE_ERROR on a resume attempt now
        # discards the partial prefix and restarts the object from byte 0
        # (brixcvmfs_transport), matching official CVMFS's prompt full restart
        # against Range-blind origins — byte-exact, no stall-out.
        assert scn["got_blind"] == scn["blind_big"]

    def test_range_blind_resume_request_was_sent(self, scn):
        # the client did attempt Range-resume after the sever (first request
        # plain, followed by bytes=<offset>- retries) — observable regardless
        # of the D6 outcome.  Later from-scratch retries (range None) may
        # follow once the resume attempts stall out.
        ranges = [r["range"] for r in scn["blind_reqs"]]
        assert (len(ranges) >= 2 and ranges[0] is None
                and any(r and r.startswith("bytes=") for r in ranges[1:]))

    def test_range_blind_never_wrong_bytes(self, scn):
        # holds in both worlds: byte-exact success or a clean error, never a
        # corrupted/short object served as good.
        import errno
        assert scn["got_blind"] == scn["blind_big"] or scn["blind_errno"] == errno.EIO

    def test_range_blind_persistent_sever_fails_cleanly(self, scn):
        import errno
        assert scn["stuck_exc"] == errno.EIO

    def test_range_blind_recovers_once_sever_lifted(self, scn):
        assert scn["small_after"] == scn["small"]


# ============================================================================
# Proxy precedence — env http_proxy beats CVMFS_HTTP_PROXY beats DIRECT.
# ============================================================================

def _spawn_proxy(procs, port, logfile):
    p = subprocess.Popen([sys.executable, TINY_PROXY, str(port), str(logfile)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if logfile.exists() and "listening" in logfile.read_text():
            return p
        time.sleep(0.1)
    raise RuntimeError(f"tiny_proxy did not start on {port}")


def _forwards(logfile):
    return [l for l in logfile.read_text().splitlines() if l.startswith("GET-forward")]


@pytest.mark.timeout(120)
class TestProxyPrecedence:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("proxy")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_PROXY_ORIGIN, web).start()
        procs = []
        obs = {}
        try:
            log_a = tmp / "proxy_a.log"
            log_b = tmp / "proxy_b.log"
            _spawn_proxy(procs, P_PROXY_A, log_a)
            _spawn_proxy(procs, P_PROXY_B, log_b)
            purl_a = f"http://127.0.0.1:{P_PROXY_A}"
            purl_b = f"http://127.0.0.1:{P_PROXY_B}"

            # env http_proxy → all traffic through proxy A
            with conf_mount(REPO, pub, server_env=_url(P_PROXY_ORIGIN),
                            env_extra={"http_proxy": purl_a}) as (mnt, _):
                obs["env_mounted"] = os.path.ismount(mnt)
                if obs["env_mounted"]:
                    obs["env_keep"] = (mnt / "keep.txt").read_bytes()
            obs["env_fwd"] = len(_forwards(log_a))

            # env http_proxy + matching no_proxy → direct again
            mark = len(_forwards(log_a))
            with conf_mount(REPO, pub, server_env=_url(P_PROXY_ORIGIN),
                            env_extra={"http_proxy": purl_a,
                                       "no_proxy": "127.0.0.1"}) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["np_keep"] = (mnt / "change.txt").read_bytes()
            obs["np_new_fwd"] = len(_forwards(log_a)) - mark

            # config CVMFS_HTTP_PROXY, no env → proxy B
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf=purl_b) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["cfg_keep"] = (mnt / "keep.txt").read_bytes()
            obs["cfg_fwd"] = len(_forwards(log_b))

            # both set → env wins over config
            mark_a, mark_b = len(_forwards(log_a)), len(_forwards(log_b))
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf=purl_b,
                            env_extra={"http_proxy": purl_a}) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "sub" / "leaf.txt").read_bytes()
            obs["both_a"] = len(_forwards(log_a)) - mark_a
            obs["both_b"] = len(_forwards(log_b)) - mark_b

            # explicit DIRECT in config, no env → direct works
            mark_a, mark_b = len(_forwards(log_a)), len(_forwards(log_b))
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf="DIRECT") as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["direct_keep"] = (mnt / "keep.txt").read_bytes()
            obs["direct_a"] = len(_forwards(log_a)) - mark_a
            obs["direct_b"] = len(_forwards(log_b)) - mark_b
            yield obs
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(3)
                except subprocess.TimeoutExpired:
                    p.kill()
            origin.stop()
            forge.close()

    def test_env_proxy_carries_the_mount(self, scn):
        assert scn["env_mounted"] and scn["env_keep"] == KEEP_V1

    def test_env_proxy_actually_used(self, scn):
        assert scn["env_fwd"] >= 1

    def test_no_proxy_exclusion_bypasses_env_proxy(self, scn):
        assert scn["np_new_fwd"] == 0 and scn["np_keep"] == CHANGE_V1

    def test_config_proxy_used_when_env_absent(self, scn):
        assert scn["cfg_fwd"] >= 1 and scn["cfg_keep"] == KEEP_V1

    def test_env_proxy_wins_over_config_proxy(self, scn):
        assert scn["both_a"] >= 1

    def test_config_proxy_unused_when_env_present(self, scn):
        assert scn["both_b"] == 0

    def test_explicit_direct_bypasses_all_proxies(self, scn):
        assert (scn["direct_keep"] == KEEP_V1
                and scn["direct_a"] == 0 and scn["direct_b"] == 0)


# ============================================================================
# Options — -o fresh (no connection reuse) and -o tls (https-first fallback).
# ============================================================================

@pytest.mark.timeout(120)
class TestOptions:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("opts")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_OPTS, web, keepalive=True).start()
        obs = {}
        try:
            # -o fresh: one TCP connection per request, cache-first thereafter
            with conf_mount(REPO, pub, server_env=_url(P_OPTS),
                            opts_extra="fresh") as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.reset_counters()
                for f in ("keep.txt", "change.txt", "remove.txt"):
                    (mnt / f).read_bytes()
                with origin.lock:
                    obs["fresh_conns"] = origin.connections
                    obs["fresh_reqs"] = len(origin.log)
                (mnt / "keep.txt").read_bytes()          # warm re-read: cache only
                with origin.lock:
                    obs["fresh_conns_after_warm"] = origin.connections

            # default mount (no fresh) against the same keepalive origin
            origin.reset_counters()
            with conf_mount(REPO, pub, server_env=_url(P_OPTS)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                for f in ("keep.txt", "change.txt", "remove.txt"):
                    (mnt / f).read_bytes()
                with origin.lock:
                    obs["dflt_conns"] = origin.connections
                    obs["dflt_reqs"] = len(origin.log)

            # -o tls against a plain-HTTP origin: https probe fails, http works
            with conf_mount(REPO, pub, server_env=_url(P_OPTS),
                            opts_extra="tls", timeout=25) as (mnt, _):
                obs["tls_mounted"] = os.path.ismount(mnt)
                if obs["tls_mounted"]:
                    obs["tls_keep"] = (mnt / "keep.txt").read_bytes()
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_fresh_forbids_connection_reuse(self, scn):
        assert scn["fresh_reqs"] >= 3
        assert scn["fresh_conns"] >= scn["fresh_reqs"], \
            "-o fresh must open a new TCP connection per request"

    def test_fresh_warm_reread_hits_cache_not_network(self, scn):
        assert scn["fresh_conns_after_warm"] == scn["fresh_conns"]

    def test_default_mount_reuses_connections(self, scn):
        # Official CVMFS keeps persistent origin connections when not configured
        # otherwise; brixcvmfs matches via a persistent curl easy handle whose
        # connection cache spans fetches (http_get_range g_curl), so a keepalive
        # origin sees fewer connections than requests.
        assert scn["dflt_conns"] < scn["dflt_reqs"]

    def test_tls_option_falls_back_to_plain_http(self, scn):
        assert scn["tls_mounted"], \
            "-o tls against an http-only origin must fall back, not fail"

    def test_tls_fallback_reads_correct_bytes(self, scn):
        assert scn.get("tls_keep") == KEEP_V1
