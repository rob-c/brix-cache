"""
Native-client gap closures (phase-37 §16): capabilities the clients previously
lacked, now implemented.

  * kXR_readv  — xrdfs readv <path> <off len>...        (scatter-gather read)
  * kXR_writev — xrdfs writev <path> <off hexdata>...   (scatter-gather write)
  * recursive  — xrdcp -r <dir> <dir>                   (directory-tree copy)
  * SRR        — xrddiag srr <http-url>                 (WLCG Storage Resource Reporting)

Each test self-hosts its own nginx (root stream server for readv/writev/recursive;
an http SRR location for srr) on free loopback ports, so it never needs the fleet.

Run:
    PYTHONPATH=tests pytest tests/test_client_gaps.py -v -p no:xdist
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
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
XRDDIAG = os.path.join(CLIENT_DIR, "bin", "xrddiag")


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


def _build(*targets):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, *targets],
                       capture_output=True, text=True, timeout=240)
    for t in targets:
        if not os.path.exists(os.path.join(CLIENT_DIR, "bin", t)):
            pytest.skip(f"{t} build failed:\n{r.stdout}\n{r.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


@pytest.fixture(scope="module")
def rw_root(tmp_path_factory):
    """A writable root:// (stream) server."""
    _build("xrdfs", "xrdcp")
    root = tmp_path_factory.mktemp("cgaps")
    data = root / "data"
    data.mkdir()
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{ listen {BIND_HOST}:{port}; xrootd on; xrootd_storage_backend posix:{data};
             xrootd_auth none; xrootd_allow_write on; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield {"port": port, "data": data, "root": root}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_readv_scatter_gather(rw_root):
    (rw_root["data"] / "f.txt").write_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    url = f"root://{HOST}:{rw_root['port']}"
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "5", "10", "6"],
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    # segments [0,5)=ABCDE and [10,16)=KLMNOP, concatenated
    assert p.stdout == b"ABCDEKLMNOP", p.stdout


def test_readv_past_eof_clean_error(rw_root):
    """A segment that runs past EOF must fail cleanly (nonzero, no partial/garbage
    bytes on stdout) — the server rejects it; the client must surface the error
    without emitting uninitialized segment buffers."""
    (rw_root["data"] / "f.txt").write_bytes(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    url = f"root://{HOST}:{rw_root['port']}"
    # [0,5)=ABCDE and [30,20) which runs 14 bytes past the 36-byte EOF
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "5", "30", "20"],
                       capture_output=True, timeout=30)
    assert p.returncode != 0
    assert p.stdout == b"", p.stdout   # nothing written on the error path


def test_readv_bad_args_rejected(rw_root):
    """Non-numeric offset/length is rejected cleanly (no crash, nonzero exit)."""
    url = f"root://{HOST}:{rw_root['port']}"
    p = subprocess.run([XRDFS, url, "readv", "/f.txt", "0", "notanumber"],
                       capture_output=True, timeout=30)
    assert p.returncode != 0
    assert b"bad offset/length" in p.stderr, p.stderr


def test_writev_scatter_gather(rw_root):
    url = f"root://{HOST}:{rw_root['port']}"
    # write 'aa' (6161) at 0 and 'ZZ' (5a5a) at 4 → "aa\0\0ZZ"
    w = subprocess.run([XRDFS, url, "writev", "/wv.txt", "0", "6161", "4", "5a5a"],
                       capture_output=True, timeout=30)
    assert w.returncode == 0, w.stderr
    got = (rw_root["data"] / "wv.txt").read_bytes()
    assert got == b"aa\x00\x00ZZ", got


def test_recursive_copy_roundtrip(rw_root, tmp_path):
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"top-level\n")
    (src / "sub" / "b.txt").write_bytes(b"nested\n")
    (src / "sub" / "c.bin").write_bytes(os.urandom(4096))
    url = f"root://{HOST}:{rw_root['port']}"

    # `xrdcp -r` nests the copied tree under the source's last path component
    # (stock parity: the reference client preserves the source dir name rather
    # than flattening it). So `xrdcp -r src //tree` lands src's contents under
    # //tree/src, and the reverse `xrdcp -r //tree back` lands //tree's contents
    # under back/tree. A round trip therefore re-nests at each leg.
    up = subprocess.run([XRDCP, "-r", str(src), f"{url}//tree"],
                        capture_output=True, text=True, timeout=60)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    back = tmp_path / "back"
    dn = subprocess.run([XRDCP, "-r", f"{url}//tree", str(back)],
                        capture_output=True, text=True, timeout=60)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"

    # every source file must round-trip byte-exact under the nested dest root
    # (back/tree/src/<rel>); the recursive download must create the missing
    # parent directories itself (mkdir -p), not just the leaf.
    landed = back / "tree" / "src"
    for rel in ("a.txt", "sub/b.txt", "sub/c.bin"):
        orig = (src / rel).read_bytes()
        rt = (landed / rel).read_bytes()
        assert hashlib.md5(orig).hexdigest() == hashlib.md5(rt).hexdigest(), rel


@pytest.fixture(scope="module")
def srr_server(tmp_path_factory):
    _build("xrddiag")
    root = tmp_path_factory.mktemp("cgaps_srr")
    data = root / "data"
    data.mkdir()
    port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/cbt;
    proxy_temp_path {root}/pt;
    fastcgi_temp_path {root}/ft;
    uwsgi_temp_path {root}/ut;
    scgi_temp_path {root}/sct;
    server {{
        listen {BIND_HOST}:{port};
        location = /.well-known/wlcg-storage-resource-reporting {{
            xrootd_srr on;
            xrootd_srr_name "TEST-SE";
            xrootd_srr_quality production;
            xrootd_srr_version "3.5";
            xrootd_srr_share atlasdata {data} atlas,cms;
        }}
    }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed (srr)")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, port):
            break
        time.sleep(0.1)
    yield {"port": port}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_srr_consumer(srr_server):
    p = subprocess.run([XRDDIAG, "srr", f"http://{HOST}:{srr_server['port']}",
                        "--probe-timeout", "6000"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "implementation=GNUBall" in p.stdout, p.stdout
    assert "shares:" in p.stdout and "capacity:" in p.stdout, p.stdout


def test_srr_json(srr_server):
    p = subprocess.run([XRDDIAG, "srr", f"http://{HOST}:{srr_server['port']}",
                        "--json", "--probe-timeout", "6000"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    import json
    doc = json.loads(p.stdout)
    assert "storageservice" in doc, p.stdout
