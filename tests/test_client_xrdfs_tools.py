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
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST
from config_templates import render_config

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def tree_root(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDFS):
        pytest.skip("xrdfs build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # Nest test data under /t so a server-created dotfile at the data root
    # (e.g. .nginx-xrootd-ckp-recovery.lock) can't pollute the recursive walks.
    root = tmp_path_factory.mktemp("xtools")
    data = root / "data"
    t = data / "t"
    (t / "sub" / "deep").mkdir(parents=True)
    (t / "a.txt").write_bytes(b"0123456789")          # 10
    (t / "sub" / "b.txt").write_bytes(b"nested\n")     # 7
    (t / "sub" / "c.bin").write_bytes(os.urandom(4096))
    (t / "sub" / "deep" / "d.log").write_bytes(b"x" * 20)
    total = 10 + 7 + 4096 + 20

    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(render_config("nginx_stream_posix_anon.conf",
                                  BASE_DIR=root, BIND_HOST=BIND_HOST,
                                  PORT=port, DATA_DIR=data,
                                  WORKER_CONNECTIONS=64))
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield {"port": port, "total": total}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


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
