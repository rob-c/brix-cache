# tests/test_cvmfs_conformance_smoke.py — Wave-1 infrastructure smoke tests.
#
# Proves the Phase-84 shared harness end-to-end: repo_forge builds a signed repo
# brixMount actually mounts; a tamper knob makes reads fail (never wrong bytes);
# the extended mock serves a forged webroot with per-path fault targeting; and
# srv_instance fetches a CAS object through nginx with a single origin fill.
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (BRIXMOUNT, NGINX_BIN, PortBlock, fuse_mount,
                                request, srv_instance)
from repo_forge import Dir, File, RepoForge, Symlink
from settings import free_port

REPO = "test.cern.ch"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
requires_fuse = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")
requires_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                     reason=f"nginx binary not found: {NGINX_BIN}")


@pytest.fixture
def spawn():
    """A background-process spawner that kills everything it started at teardown."""
    procs = []

    def _spawn(argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        return p

    yield _spawn
    for p in reversed(procs):
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()


def _forge(tmp_path, tree, **kw):
    web = tmp_path / "web"
    pub = tmp_path / "repo.pub"
    forge = RepoForge(REPO, web, **kw).build(tree, pub)
    return forge, web, pub


def _serve_webroot(spawn, web):
    port = free_port()
    mock = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "mock_stratum1.py")
    spawn([sys.executable, mock, "--port", str(port), "--repo", REPO, "--webroot", str(web)])
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log", timeout=0.3)
            return port
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("webroot mock did not start")


# ---- forge structure (no server, no mount) --------------------------------

def test_forge_writes_complete_webroot(tmp_path):
    forge, web, pub = _forge(tmp_path, {"hello": File(b"hi\n")})
    repo = web / "cvmfs" / REPO
    assert (repo / ".cvmfspublished").is_file()
    assert (repo / ".cvmfswhitelist").is_file()
    assert (repo / "data").is_dir()
    assert pub.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert forge.fingerprint.count(":") == 19          # 20-byte SHA1, colon-separated
    forge.close()


def test_forge_manifest_has_expected_fields(tmp_path):
    forge, web, _ = _forge(tmp_path, {"hello": File(b"hi\n")})
    manifest = (web / "cvmfs" / REPO / ".cvmfspublished").read_bytes()
    head = manifest.split(b"\n--\n", 1)[0].decode()
    fields = {line[0]: line[1:] for line in head.splitlines() if line}
    assert fields["C"] == forge.root_catalog_hash and fields["N"] == REPO
    assert fields["X"] == forge.cert_hash and int(fields["B"]) == forge.root_catalog_size
    forge.close()


def test_forge_cas_identity_is_hash_of_stored_bytes(tmp_path):
    import hashlib
    forge, web, _ = _forge(tmp_path, {"hello": File(b"payload\n")})
    key = next(k for k in forge.cas if len(k) == 40)   # a content object (no suffix)
    stored = (web / "cvmfs" / REPO / "data" / key[:2] / key[2:]).read_bytes()
    assert hashlib.sha1(stored).hexdigest() == key
    forge.close()


# ---- extended mock: webroot mode + faults ---------------------------------

def test_webroot_mock_serves_manifest_and_objects(tmp_path, spawn):
    forge, web, _ = _forge(tmp_path, {"hello": File(b"served\n")})
    port = _serve_webroot(spawn, web)
    disk = (web / "cvmfs" / REPO / ".cvmfspublished").read_bytes()
    served = urllib.request.urlopen(f"http://127.0.0.1:{port}/cvmfs/{REPO}/.cvmfspublished").read()
    assert served == disk
    key = next(k for k in forge.cas if len(k) == 40)
    obj = urllib.request.urlopen(
        f"http://127.0.0.1:{port}/cvmfs/{REPO}/data/{key[:2]}/{key[2:]}").read()
    assert obj == (web / "cvmfs" / REPO / "data" / key[:2] / key[2:]).read_bytes()
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/cvmfs/{REPO}/data/aa/{'0' * 38}")
    assert e.value.code == 404
    forge.close()


def test_per_path_fault_targeting(tmp_path, spawn):
    forge, web, _ = _forge(tmp_path, {"hello": File(b"target\n")})
    port = _serve_webroot(spawn, web)
    base = f"http://127.0.0.1:{port}/cvmfs/{REPO}"
    key = next(k for k in forge.cas if len(k) == 40)
    obj_path = f"/cvmfs/{REPO}/data/{key[:2]}/{key[2:]}"
    # fault targets ONLY the manifest; a CAS GET must pass through untouched.
    urllib.request.urlopen(urllib.request.Request(
        f"http://127.0.0.1:{port}/ctl/fault", method="POST",
        data=b'{"mode":"http500","count":1,"path_re":"cvmfspublished"}'))
    assert urllib.request.urlopen(f"http://127.0.0.1:{port}{obj_path}").status == 200
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(base + "/.cvmfspublished")
    assert e.value.code == 500
    # fault consumed: manifest healthy again
    assert urllib.request.urlopen(base + "/.cvmfspublished").status == 200
    forge.close()


def test_reset_log_clears_history(tmp_path, spawn):
    import json
    forge, web, _ = _forge(tmp_path, {"hello": File(b"log\n")})
    port = _serve_webroot(spawn, web)
    urllib.request.urlopen(f"http://127.0.0.1:{port}/cvmfs/{REPO}/.cvmfspublished").read()
    assert json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log"))
    urllib.request.urlopen(urllib.request.Request(
        f"http://127.0.0.1:{port}/ctl/reset-log", method="POST"))
    assert json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log")) == []
    forge.close()


# ---- real fuse mount roundtrip + tamper -----------------------------------

@requires_fuse
def test_forge_serve_mount_read_roundtrip(tmp_path, spawn):
    forge, web, pub = _forge(tmp_path, {
        "hello": File(b"Hello forged CVMFS!\n"),
        "sub": Dir({"leaf.txt": File(b"leaf\n")}),
        "link": Symlink("hello"),
        "empty": Dir({}),
    })
    port = _serve_webroot(spawn, web)
    url = f"http://127.0.0.1:{port}/cvmfs/{REPO}"
    with fuse_mount(REPO, url, pub, cache=str(tmp_path / "cache")) as (mnt, _):
        assert os.path.ismount(str(mnt)), "brixMount failed to mount the forged repo"
        assert sorted(os.listdir(mnt)) == ["empty", "hello", "link", "sub"]
        assert (mnt / "hello").read_bytes() == b"Hello forged CVMFS!\n"
        assert (mnt / "sub" / "leaf.txt").read_bytes() == b"leaf\n"
        assert os.readlink(mnt / "link") == "hello"
    forge.close()


@requires_fuse
def test_tamper_flipped_content_byte_fails_read(tmp_path, spawn):
    forge, web, pub = _forge(tmp_path, {"secret": File(b"trust me exactly\n")})
    key = next(k for k in forge.cas if len(k) == 40)
    forge.flip_byte(key, 6)                              # corrupt the STORED bytes
    port = _serve_webroot(spawn, web)
    url = f"http://127.0.0.1:{port}/cvmfs/{REPO}"
    with fuse_mount(REPO, url, pub, cache=str(tmp_path / "cache")) as (mnt, _):
        if os.path.ismount(str(mnt)):
            with pytest.raises(OSError):
                data = (mnt / "secret").read_bytes()
                assert data != b"trust me exactly\n", "corrupt object served as clean bytes"
    forge.close()


@requires_fuse
def test_tamper_deleted_cas_fails_read(tmp_path, spawn):
    forge, web, pub = _forge(tmp_path, {"gone": File(b"disappears\n")})
    key = next(k for k in forge.cas if len(k) == 40)
    forge.delete_cas(key)
    port = _serve_webroot(spawn, web)
    url = f"http://127.0.0.1:{port}/cvmfs/{REPO}"
    with fuse_mount(REPO, url, pub, cache=str(tmp_path / "cache")) as (mnt, _):
        if os.path.ismount(str(mnt)):
            with pytest.raises(OSError):
                (mnt / "gone").read_bytes()
    forge.close()


# ---- nginx site-cache through srv_instance --------------------------------

@requires_nginx
def test_srv_instance_serves_cas_and_logs_one_fill():
    block = PortBlock("srv_cas")
    with srv_instance(block, objects=6, seed=11) as srv:
        obj = srv.objects()[1]
        origin = urllib.request.urlopen(srv.mock_url + obj).read()   # reference (pre-reset)
        srv.reset_log()
        through = urllib.request.urlopen(srv.base_url + obj).read()
        assert through == origin, "site-cache serve differs from origin"
        # second fetch is a cache hit — origin fill count stays at one.
        urllib.request.urlopen(srv.base_url + obj).read()
        assert srv.count_log(obj) == 1, "cache did not coalesce to a single origin fill"


@requires_nginx
def test_srv_instance_rejects_unknown_cas_with_404():
    block = PortBlock("srv_gate")
    with srv_instance(block, objects=4, seed=3) as srv:
        bogus = f"/cvmfs/{REPO}/data/aa/" + "cd" * 19
        status, _, _ = request("127.0.0.1", srv.nginx_port, "GET", bogus)
        assert status == 404
