"""
xrdfs power tools (swiss-army-knife cluster 1): recursive filesystem ergonomics.

  * du [-h]                 — recursive size + file/dir counts
  * tree [-d] [-L N]        — visual directory tree
  * find <p> [-name/-type/-size]  — recursive predicate search
  * ls -R                   — recursive listing

Self-hosts its own root:// (stream) server with a known tree on a free port.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrdfs_tools.py -v -p no:xdist
"""

import os
import shutil
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrdfs-tools")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs build failed")


@pytest.fixture()
def tree_root(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # Nest test data under /t so a server-created dotfile at the data root
    # (e.g. .nginx-xrootd-ckp-recovery.lock) can't pollute the recursive walks.
    data = tmp_path / "data"
    t = data / "t"
    (t / "sub" / "deep").mkdir(parents=True)
    (t / "a.txt").write_bytes(b"0123456789")          # 10
    (t / "sub" / "b.txt").write_bytes(b"nested\n")     # 7
    (t / "sub" / "c.bin").write_bytes(os.urandom(4096))
    (t / "sub" / "deep" / "d.log").write_bytes(b"x" * 20)
    total = 10 + 7 + 4096 + 20

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrdfs-tools",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrdfs recursive tools against a writable anon root server"))
    return {"port": ep.port, "total": total}


def _run(tree_root, *args):
    url = f"root://{HOST}:{tree_root['port']}"
    return subprocess.run([XRDFS, url, *args], capture_output=True, text=True, timeout=30)


def test_du_total_and_counts(tree_root):
    p = _run(tree_root, "du", "/t")
    assert p.returncode == 0, p.stderr
    assert str(tree_root["total"]) in p.stdout, p.stdout
    assert "4 files" in p.stdout and "2 dirs" in p.stdout, p.stdout


def test_du_human(tree_root):
    p = _run(tree_root, "du", "-h", "/t")
    assert p.returncode == 0, p.stderr
    # 4133 bytes -> "4.0K"
    assert "K" in p.stdout.split()[0], p.stdout


def test_tree(tree_root):
    p = _run(tree_root, "tree", "/t")
    assert p.returncode == 0, p.stderr
    for name in ("a.txt", "sub", "b.txt", "c.bin", "deep", "d.log"):
        assert name in p.stdout, f"{name} missing\n{p.stdout}"
    assert "2 directories, 4 files" in p.stdout, p.stdout


def test_find_name_glob(tree_root):
    p = _run(tree_root, "find", "/t", "-name", "*.txt")
    assert p.returncode == 0, p.stderr
    lines = sorted(x for x in p.stdout.split("\n") if x)
    assert lines == ["/t/a.txt", "/t/sub/b.txt"], lines


def test_find_type_dir(tree_root):
    p = _run(tree_root, "find", "/t", "-type", "d")
    assert p.returncode == 0, p.stderr
    lines = sorted(x for x in p.stdout.split("\n") if x)
    assert lines == ["/t/sub", "/t/sub/deep"], lines


def test_find_file_size_filter(tree_root):
    # -size matches all types (GNU-find semantics); combine with -type f.
    p = _run(tree_root, "find", "/t", "-type", "f", "-size", "+1000")
    assert p.returncode == 0, p.stderr
    lines = [x for x in p.stdout.split("\n") if x]
    assert lines == ["/t/sub/c.bin"], lines


def test_ls_recursive(tree_root):
    p = _run(tree_root, "ls", "-R", "/t")
    assert p.returncode == 0, p.stderr
    assert "/t/sub:" in p.stdout and "/t/sub/deep:" in p.stdout, p.stdout
    assert "d.log" in p.stdout, p.stdout
