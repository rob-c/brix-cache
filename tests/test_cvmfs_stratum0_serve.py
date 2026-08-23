"""Phase-96 S13 — nginx serves a repotool-published Stratum-0 tree.

`brix_cvmfs_stratum0_root` points the cvmfs location at the published repo
(alias for brix_export with the Stratum-0 contract enforced at nginx -t):

  success:      manifest / whitelist / reflog / CAS objects byte-identical to
                disk over HTTP, geo class answers, `.cvmfs_master_replica`
                marker served (the `cvmfs_server add-replica` probe), and a
                brixMount FUSE mount through nginx reads published content.
  error:        the alias combined with cache-fill upstream grammar
                (brix_cache_store / http brix_storage_backend /
                brix_cvmfs_upstream_allow) or a second export root
                (brix_export) → EMERG at config load.
  security-neg: every write method still 405s (publishing never leaks into
                the serve plane) and the replication marker is directive-gated
                (a plain brix_export cache node cannot be spoofed into
                advertising itself as a replication source).
"""

import os
import subprocess
import sys

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
def _check_test_stratum0_serve_success_1(status, got, repo, root_hex):
    assert status == 200 and got == cas_path(repo, root_hex, "C").read_bytes()

def _check_test_stratum0_serve_success_2(status, got, chunk):
    assert status == 200 and got == chunk.read_bytes()

def _check_test_stratum0_serve_success_3(status, got):
    assert status == 200 and got.strip(), f"geo: {status} {got[:80]!r}"

def _check_test_stratum0_serve_success_4(status, got):
    assert status == 200 and b"Stratum-0" in got, f"marker: {status}"

def _check_test_stratum0_serve_success_5(status, got):
    assert status == 200 and got == b""

def _check_test_stratum0_serve_success_6(mnt):
    assert (mnt / "docs/guide.md").read_bytes() == FILES["docs/guide.md"]


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, NGINX_BIN, PortBlock, fuse_mount, request
from cmdscripts.cvmfs_publish_txn import _upper, cas_path, parse_manifest, repotool
from cmdscripts.cvmfs_repo_cli import _build_repotool
from cmdscripts.live_common import LiveRun
from settings import BIND_HOST, HOST

FQRN = "s0.brix.io"
FILES = {
    "hello.txt": b"stratum-zero hello\n",
    "docs/guide.md": b"guide-v1 " * 2000 + b"\n",   # >4096-floor: chunks
}

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")

_BLOCK = PortBlock("srv_stratum0")


def _nginx_conf(run: LiveRun, port: int, loc_lines: str) -> "os.PathLike":
    user_line = "user root;\n" if os.geteuid() == 0 else ""
    return run.write(
        run.root / f"nginx.{port}.conf",
        f"""{user_line}daemon on; error_log {run.root}/logs/e.{port}.log info;
pid {run.root}/nginx.{port}.pid;
worker_processes 1; thread_pool default threads=2;
events {{ worker_connections 256; }}
http {{ access_log off; server {{ listen {BIND_HOST}:{port};
    location /cvmfs/ {{
        {loc_lines}
    }}
}} }}
""")


@pytest.fixture(scope="module")
def stratum0():
    """Publish a repo at <web>/cvmfs/<fqrn> and serve it via the alias."""
    with LiveRun("cvmfs_s0", NGINX_BIN) as run:
        run.mkdir("logs")
        binary, err = _build_repotool(run.mkdir("bin"))
        assert binary is not None, f"repotool build failed: {err}"
        web = run.mkdir("web")
        repo = run.mkdir("web", "cvmfs") / FQRN
        assert repotool(binary, "mkfs", FQRN, str(repo)).returncode == 0
        assert repotool(binary, "transaction", str(repo)).returncode == 0
        for rel, content in FILES.items():
            target = _upper(repo) / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        assert repotool(binary, "publish", str(repo),
                        "--chunk-size", "4096").returncode == 0

        port = _BLOCK.nginx()
        conf = _nginx_conf(run, port, f"""
        brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};
        brix_cvmfs_geo_answer rtt;""")
        run.start_nginx(run.root, conf, port)
        yield run, repo, port


def _get(port: int, path: str, method: str = "GET", body: bytes = b""):
    return request(HOST, port, method, path, body=body)


def test_stratum0_serve_success(stratum0):
    run, repo, port = stratum0
    base = f"/cvmfs/{FQRN}"

    # signed metadata: byte-identical to the published tree
    for name in (".cvmfspublished", ".cvmfswhitelist", ".cvmfsreflog"):
        status, _, got = _get(port, f"{base}/{name}")
        def _assert_test_stratum0_serve_success_1():
            assert status == 200, f"{name}: {status}"
            assert got == (repo / name).read_bytes(), f"{name} bytes differ"

        _assert_test_stratum0_serve_success_1()

    # CAS: the root catalog and one chunk object, straight from the manifest
    man = parse_manifest(repo)
    root_hex = man["C"]
    status, _, got = _get(port, f"{base}/data/{root_hex[:2]}/{root_hex[2:]}C")
    _check_test_stratum0_serve_success_1(status, got, repo, root_hex)
    chunk = next(f for f in (repo / "data").glob("*/*P"))
    status, _, got = _get(port, f"{base}/data/{chunk.parent.name}/{chunk.name}")
    _check_test_stratum0_serve_success_2(status, got, chunk)

    # geo class answers locally (rtt mode — localhost probe, no upstream)
    status, _, got = _get(port, f"{base}/api/v1.0/geo/x/{HOST}")
    _check_test_stratum0_serve_success_3(status, got)

    # replication marker: the cvmfs_server add-replica probe (GET + HEAD)
    status, _, got = _get(port, f"{base}/.cvmfs_master_replica")
    _check_test_stratum0_serve_success_4(status, got)
    status, _, got = _get(port, f"{base}/.cvmfs_master_replica", method="HEAD")
    _check_test_stratum0_serve_success_5(status, got)

    # client leg: a real brixMount FUSE mount through this nginx
    if not (os.path.exists("/dev/fuse") and os.path.exists(BRIXMOUNT)):
        pytest.skip("HTTP surface verified; no /dev/fuse or brixMount "
                    "for the mount leg")
    pub = repo / "keys" / f"{FQRN}.pub"
    with fuse_mount(FQRN, f"http://{HOST}:{port}/cvmfs/{FQRN}", pub) as (mnt, _proc):
        def _assert_test_stratum0_serve_success_2():
            assert os.path.ismount(mnt), "mount did not come up"
            assert (mnt / "hello.txt").read_bytes() == FILES["hello.txt"]

        _assert_test_stratum0_serve_success_2()
        _check_test_stratum0_serve_success_6(mnt)


def test_stratum0_upstream_grammar_emerg(stratum0):
    run, repo, _ = stratum0
    web = repo.parent.parent
    store = run.mkdir("emerg_store")
    cases = [
        (f"brix_cache_store posix:{store};", "remove brix_cache_store"),
        ('brix_storage_backend "http://127.0.0.1:1/";', "has no upstream"),  # net-literal-allow: EMERG-needle config line, refused at nginx -t, never dialed
        (f"brix_cvmfs_upstream_allow {HOST};", "remove brix_cvmfs_upstream_allow"),
        (f"brix_export {store};", "configure exactly one"),
    ]
    for i, (extra, needle) in enumerate(cases):
        conf = _nginx_conf(run, 65000 + i, f"""
        brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};
        {extra}""")
        r = subprocess.run([NGINX_BIN, "-t", "-p", str(run.root), "-c", str(conf)],
                           capture_output=True, text=True)
        assert r.returncode != 0, f"{extra} passed nginx -t"
        assert needle in r.stderr, f"{extra}: EMERG line missing {needle!r}: {r.stderr}"

    # control: the plain Stratum-0 shape passes -t
    conf = _nginx_conf(run, 65010, f"""
        brix_cvmfs on;
        brix_cvmfs_stratum0_root {web};""")
    r = subprocess.run([NGINX_BIN, "-t", "-p", str(run.root), "-c", str(conf)],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"clean stratum0 config failed -t: {r.stderr}"


def test_stratum0_write_methods_405_and_marker_gated(stratum0):
    run, repo, port = stratum0
    base = f"/cvmfs/{FQRN}"
    man_disk = (repo / ".cvmfspublished").read_bytes()
    root_hex = parse_manifest(repo)["C"]

    # every write method 405s on every class — publishing never leaks in
    for method, path in [
        ("PUT", f"{base}/.cvmfspublished"),
        ("DELETE", f"{base}/data/{root_hex[:2]}/{root_hex[2:]}C"),
        ("POST", f"{base}/.cvmfs_master_replica"),
        ("MKCOL", f"{base}/newdir"),
        ("PUT", f"{base}/data/00/{'0' * 38}"),
    ]:
        status, _, _ = _get(port, path, method=method, body=b"evil")
        assert status == 405, f"{method} {path}: {status}"

    # nothing changed on disk or over the wire
    status, _, got = _get(port, f"{base}/.cvmfspublished")
    assert status == 200 and got == man_disk == (repo / ".cvmfspublished").read_bytes()

    # the marker is directive-gated: the SAME tree behind plain brix_export
    # must NOT advertise itself as a replication source (403 reject)
    web = repo.parent.parent
    cache_port = _BLOCK.nginx()
    conf = _nginx_conf(run, cache_port, f"""
        brix_cvmfs on;
        brix_export {web};""")
    run.start_nginx(run.root, conf, cache_port)
    status, _, _ = _get(cache_port, f"{base}/.cvmfs_master_replica")
    assert status == 403, f"marker leaked on a non-stratum0 location: {status}"
    status, _, got = _get(cache_port, f"{base}/.cvmfspublished")
    assert status == 200 and got == man_disk   # same tree still serves
