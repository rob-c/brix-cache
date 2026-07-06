"""
xrdcp bulk/batch transfer (swiss-army-knife cluster 2, slice 1):
multiple sources / globs / --from manifest into a destination directory, plus
--retry, all while keeping the classic single `xrdcp SRC DST` behaviour intact.

Self-hosts a writable root:// (stream) server on a free port.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrdcp_bulk.py -v -p no:xdist
"""

import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")


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


def _md5(p):
    return hashlib.md5(p.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def rw(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"], capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("bulk")
    data = root / "data"
    (data / "g").mkdir(parents=True)
    (data / "g" / "a.txt").write_bytes(b"alpha\n")
    (data / "g" / "b.txt").write_bytes(b"bravo\n")
    (data / "g" / "c.dat").write_bytes(b"charlie\n")     # excluded by *.txt
    (data / "destdir").mkdir()                            # pre-existing remote dir
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{ listen {BIND_HOST}:{port}; brix_root on; brix_storage_backend posix:{data};
             brix_auth none; brix_allow_write on; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)], capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield {"port": port, "data": data}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def _url(rw, path=""):
    return f"root://{HOST}:{rw['port']}/{path}"


def test_single_copy_backcompat(rw, tmp_path):
    """Classic `xrdcp SRC DST` (one source, explicit dst) is unchanged."""
    src = tmp_path / "one.bin"
    src.write_bytes(os.urandom(2048))
    up = subprocess.run([XRDCP, "-f", str(src), _url(rw, "/single.bin")],
                        capture_output=True, text=True, timeout=60)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    back = tmp_path / "one.back"
    dn = subprocess.run([XRDCP, "-f", _url(rw, "/single.bin"), str(back)],
                        capture_output=True, text=True, timeout=60)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert _md5(src) == _md5(back)


def test_multi_source_download_into_dir(rw, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    r = subprocess.run([XRDCP, _url(rw, "/g/a.txt"), _url(rw, "/g/b.txt"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert (out / "a.txt").read_bytes() == b"alpha\n"
    assert (out / "b.txt").read_bytes() == b"bravo\n"


def test_glob_download(rw, tmp_path):
    out = tmp_path / "g_out"
    out.mkdir()
    r = subprocess.run([XRDCP, _url(rw, "/g/*.txt"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    got = sorted(os.listdir(out))
    assert got == ["a.txt", "b.txt"], got            # c.dat excluded


def test_manifest_download(rw, tmp_path):
    out = tmp_path / "m_out"
    out.mkdir()
    man = tmp_path / "list.txt"
    man.write_text(f"# files to fetch\n{_url(rw, '/g/a.txt')}\n\n{_url(rw, '/g/c.dat')}\n")
    r = subprocess.run([XRDCP, "--from", str(man), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert sorted(os.listdir(out)) == ["a.txt", "c.dat"]


def test_multi_source_upload_into_remote_dir(rw, tmp_path):
    f1 = tmp_path / "u1.bin"; f1.write_bytes(b"u-one\n")
    f2 = tmp_path / "u2.bin"; f2.write_bytes(b"u-two\n")
    r = subprocess.run([XRDCP, str(f1), str(f2), _url(rw, "/destdir")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert (rw["data"] / "destdir" / "u1.bin").read_bytes() == b"u-one\n"
    assert (rw["data"] / "destdir" / "u2.bin").read_bytes() == b"u-two\n"


def test_parallel_jobs_download(rw, tmp_path):
    """-j N copies many files concurrently; all land intact."""
    # seed 12 files on the server
    src = rw["data"] / "many"
    src.mkdir(exist_ok=True)
    expect = {}
    for i in range(12):
        b = (b"file-%02d-" % i) + os.urandom(64)
        (src / f"f{i:02d}.bin").write_bytes(b)
        expect[f"f{i:02d}.bin"] = hashlib.md5(b).hexdigest()
    out = tmp_path / "pout"
    out.mkdir()
    r = subprocess.run([XRDCP, "-j", "4", _url(rw, "/many/*.bin"), str(out)],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    got = {p: hashlib.md5((out / p).read_bytes()).hexdigest() for p in os.listdir(out)}
    assert got == expect, f"{sorted(got)} != {sorted(expect)}"


def test_batch_requires_existing_dir(rw, tmp_path):
    missing = tmp_path / "nope"   # does not exist
    r = subprocess.run([XRDCP, _url(rw, "/g/a.txt"), _url(rw, "/g/b.txt"), str(missing)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0
    assert "directory" in r.stderr.lower(), r.stderr


def test_sync_skips_up_to_date(rw, tmp_path):
    """--sync skips a file whose destination already has the same size, and copies
    one whose size differs."""
    out = tmp_path / "syncout"
    out.mkdir()
    # a.txt (6 bytes) already present at dest, same size -> should be skipped
    (out / "a.txt").write_bytes(b"alpha\n")
    # b.txt present but WRONG size -> should be (re)copied
    (out / "b.txt").write_bytes(b"x")
    r = subprocess.run([XRDCP, "--sync", _url(rw, "/g/a.txt"), _url(rw, "/g/b.txt"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "1 copied" in r.stderr and "1 skipped" in r.stderr, r.stderr
    assert (out / "a.txt").read_bytes() == b"alpha\n"
    assert (out / "b.txt").read_bytes() == b"bravo\n"   # got fixed to the real content


def test_progress_bar_rendered(rw, tmp_path):
    """--progress renders a rate/ETA bar to stderr and completes at 100%."""
    (rw["data"] / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024 + 5))
    out = tmp_path / "big.out"
    p = subprocess.run([XRDCP, "--progress", "-f", _url(rw, "/big.bin"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert out.stat().st_size == 3 * 1024 * 1024 + 5
    assert "MiB/s" in p.stderr, p.stderr
    assert "100%" in p.stderr, p.stderr


def test_progress_off_by_default_on_pipe(rw, tmp_path):
    """No progress on a non-TTY stderr unless --progress is given."""
    (rw["data"] / "big2.bin").write_bytes(os.urandom(1024 * 1024 + 3))
    out = tmp_path / "big2.out"
    p = subprocess.run([XRDCP, "-f", _url(rw, "/big2.bin"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "MiB/s" not in p.stderr, p.stderr


def test_verify_checksum(rw, tmp_path):
    """--verify checks the transferred file's checksum against the server."""
    (rw["data"] / "vf.bin").write_bytes(os.urandom(65536))
    out = tmp_path / "vf.out"
    p = subprocess.run([XRDCP, "--verify", "-f", _url(rw, "/vf.bin"), str(out)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "matches server" in (p.stdout + p.stderr), (p.stdout, p.stderr)


def test_retry_then_fail_no_hang(tmp_path):
    """--retry on an unreachable endpoint fails cleanly after retries (no hang)."""
    out = tmp_path / "x.bin"
    r = subprocess.run([XRDCP, "--retry", "1", "-s", "root://127.0.0.1:1//x", str(out)],
                       capture_output=True, text=True, timeout=40)
    assert r.returncode != 0
    assert not out.exists()


def test_block_url_remote_to_block(rw, tmp_path):
    """root:// → block:// single-file copy: VFS block backend receives the bytes.

    A regular pre-allocated file acts as the block target (block:// treats it
    as a device: open O_WRONLY in-place, no temp+rename, commit=fsync).
    Content equality is verified by sha256.
    """
    content = os.urandom(256 * 1024)   # 256 KiB of noise
    (rw["data"] / "block_src.bin").write_bytes(content)

    dst = tmp_path / "block_dst.bin"
    dst.write_bytes(b"\x00" * len(content))   # pre-allocate: block backend needs existing target

    r = subprocess.run(
        [XRDCP, "-f", _url(rw, "/block_src.bin"), f"block://{dst}"],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, f"remote→block failed: {r.stdout}\n{r.stderr}"
    assert hashlib.sha256(dst.read_bytes()).hexdigest() == hashlib.sha256(content).hexdigest(), \
        "sha256 mismatch: remote→block content corrupted"


def test_block_url_local_to_block(tmp_path):
    """local-file → block:// copy: both sides go through brix_vfs (POSIX → block).

    No server required.  The source is a plain local file; the destination is a
    pre-allocated file opened via the block:// scheme (in-place write, no rename).
    """
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp not built")

    content = os.urandom(128 * 1024)   # 128 KiB
    src = tmp_path / "local_src.bin"
    src.write_bytes(content)

    dst = tmp_path / "block_local_dst.bin"
    dst.write_bytes(b"\x00" * len(content))

    r = subprocess.run(
        [XRDCP, "-f", str(src), f"block://{dst}"],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, f"local→block failed: {r.stdout}\n{r.stderr}"
    assert dst.read_bytes() == content, "content mismatch: local→block"


def test_block_url_block_to_local(tmp_path):
    """block:// → local-file copy: block backend reads, POSIX backend writes.

    Verifies the reverse direction: block:// as a source endpoint.
    """
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp not built")

    content = os.urandom(64 * 1024)   # 64 KiB
    src = tmp_path / "block_read_src.bin"
    src.write_bytes(content)

    dst = tmp_path / "block_to_local.bin"

    r = subprocess.run(
        [XRDCP, "-f", f"block://{src}", str(dst)],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, f"block→local failed: {r.stdout}\n{r.stderr}"
    assert dst.read_bytes() == content, "content mismatch: block→local"


def test_large_file_integrity_uring(rw, tmp_path):
    """Download a 16 MiB file via xrdcp --io-uring=on and verify byte-exact content.

    Exercises the posix_pwrite splitting loop added in the A6 bug fix: the
    io_uring ring uses 64 KiB buffers, so an 8 MiB COPY_CHUNK is split into
    128 ring ops each at a distinct file offset.  A wrong per-piece offset
    (dropped tail, off-by-one, missing += chunk) corrupts the output and is
    caught by the sha256 comparison.

    If liburing is unavailable the transfer falls back to classic pread/pwrite
    via AUTO mode; content equality is still verified.
    """
    size = 16 * 1024 * 1024
    src_bytes = os.urandom(size)
    src_sha256 = hashlib.sha256(src_bytes).hexdigest()
    (rw["data"] / "large_uring.bin").write_bytes(src_bytes)

    out = tmp_path / "large_uring.out"
    r = subprocess.run(
        [XRDCP, "--io-uring=on", "-f", _url(rw, "/large_uring.bin"), str(out)],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0 and "io_uring" in (r.stdout + r.stderr).lower():
        # liburing absent or kernel lacks io_uring; retry with AUTO (classic path)
        r = subprocess.run(
            [XRDCP, "-f", _url(rw, "/large_uring.bin"), str(out)],
            capture_output=True, text=True, timeout=120,
        )
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert out.stat().st_size == size, f"size mismatch: {out.stat().st_size} != {size}"
    got_sha256 = hashlib.sha256(out.read_bytes()).hexdigest()
    assert got_sha256 == src_sha256, "sha256 mismatch — per-piece write offset is wrong"
