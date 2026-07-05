"""
Native-client production transfer over web schemes (phase-37 §16 gap A):
xrdcp can now GET/PUT over davs:// / http(s):// (WebDAV) and s3:// (S3 REST,
AWS SigV4), not just root://.

  * WebDAV: streaming HTTP PUT/GET, bearer-token or anonymous.
  * S3:     SigV4-signed PUT (UNSIGNED-PAYLOAD) + GET (empty-body hash).

Each test self-hosts its own nginx (a WebDAV server + a SigV4-required S3 server)
on free loopback ports, so it never needs the shared fleet.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_web_transfer.py -v -p no:xdist
"""

import hashlib
import os
import socket
import subprocess
import threading
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(120)

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")

S3_AK = "AKIDTESTCLIENT0001"
S3_SK = "c3RyZWFtaW5nLXNlY3JldC1rZXktZm9yLXRlc3Rpbmc="


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


def _md5(path):
    return hashlib.md5(path.read_bytes()).hexdigest()


def _build_tree(root):
    """Create a small nested local tree under `root`; return {rel: bytes}."""
    (root / "sub" / "deep").mkdir(parents=True)
    files = {
        "top.txt": b"top-level\n",
        "sub/mid.bin": os.urandom(2048),
        "sub/deep/leaf.dat": b"deep-leaf\n",
    }
    for rel, data in files.items():
        (root / rel).write_bytes(data)
    return files


@pytest.fixture(scope="module")
def web_servers(tmp_path_factory):
    import shutil
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                       capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip(f"xrdcp build failed:\n{r.stdout}\n{r.stderr}")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("webxfer")
    dav_data = root / "dav"
    s3_data = root / "s3"
    dav_data.mkdir()
    s3_data.mkdir()
    (s3_data / "testbucket").mkdir()
    dav_port = _free_port()
    s3_port = _free_port()
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
        listen {BIND_HOST}:{dav_port};
        client_max_body_size 64m;
        location / {{
            brix_webdav on;
            brix_webdav_storage_backend posix:{dav_data};
            brix_webdav_auth none;
            brix_webdav_allow_write on;
        }}
    }}
    server {{
        listen {BIND_HOST}:{s3_port};
        client_max_body_size 64m;
        location / {{
            brix_s3 on;
            brix_s3_storage_backend posix:{s3_data};
            brix_s3_bucket testbucket;
            brix_s3_access_key {S3_AK};
            brix_s3_secret_key {S3_SK};
            brix_s3_region us-east-1;
            brix_s3_allow_write on;
        }}
    }}
}}
""")
    chk = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip(f"nginx -t failed:\n{chk.stderr}")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, dav_port) and _port_up(HOST, s3_port):
            break
        time.sleep(0.1)
    yield {"dav_port": dav_port, "s3_port": s3_port, "root": root,
           "dav_data": dav_data}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_webdav_upload_download_roundtrip(web_servers, tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(1024 * 1024 + 17))   # 1 MiB + odd tail
    base = f"http://{HOST}:{web_servers['dav_port']}"

    up = subprocess.run([XRDCP, "-f", str(src), f"{base}/up.bin"],
                        capture_output=True, text=True, timeout=60)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    back = tmp_path / "back.bin"
    dn = subprocess.run([XRDCP, "-f", f"{base}/up.bin", str(back)],
                        capture_output=True, text=True, timeout=60)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert _md5(src) == _md5(back)


def test_webdav_download_to_stdout(web_servers, tmp_path):
    src = tmp_path / "s.bin"
    src.write_bytes(b"hello-webdav-stdout\n")
    base = f"http://{HOST}:{web_servers['dav_port']}"
    subprocess.run([XRDCP, "-f", str(src), f"{base}/s.bin"],
                   capture_output=True, timeout=60, check=True)
    p = subprocess.run([XRDCP, f"{base}/s.bin", "-"],
                       capture_output=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert p.stdout == b"hello-webdav-stdout\n", p.stdout


def test_s3_put_get_roundtrip_sigv4(web_servers, tmp_path):
    src = tmp_path / "obj.bin"
    src.write_bytes(os.urandom(512 * 1024 + 3))
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    creds = ["--s3-access", S3_AK, "--s3-secret", S3_SK, "--s3-region", "us-east-1"]

    up = subprocess.run([XRDCP, *creds, "-f", str(src), f"{base}/obj.bin"],
                        capture_output=True, text=True, timeout=60)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    back = tmp_path / "obj.back"
    dn = subprocess.run([XRDCP, *creds, "-f", f"{base}/obj.bin", str(back)],
                        capture_output=True, text=True, timeout=60)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert _md5(src) == _md5(back)


def test_s3_put_via_env_credentials(web_servers, tmp_path):
    """Credentials may come from the AWS_* environment, not just flags."""
    src = tmp_path / "envobj.bin"
    src.write_bytes(b"env-cred-object\n")
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    env = dict(os.environ, AWS_ACCESS_KEY_ID=S3_AK, AWS_SECRET_ACCESS_KEY=S3_SK,
               AWS_DEFAULT_REGION="us-east-1")
    up = subprocess.run([XRDCP, "-f", str(src), f"{base}/envobj.bin"],
                        capture_output=True, text=True, timeout=60, env=env)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"


def test_webdav_recursive_download(web_servers, tmp_path, request):
    """xrdcp -r over davs/http lists the collection (PROPFIND) and downloads the whole
    tree, preserving subdirectory structure."""
    # build a tree under the WebDAV data dir via the fixture's data path
    dav_data = web_servers.get("dav_data")
    if dav_data is None:
        pytest.skip("fixture does not expose dav_data")
    tree = dav_data / "rtree"
    (tree / "sub").mkdir(parents=True)
    (tree / "top.txt").write_bytes(b"top\n")
    (tree / "sub" / "deep.bin").write_bytes(b"deepdata\n")
    base = f"http://{HOST}:{web_servers['dav_port']}"
    out = tmp_path / "rout"
    r = subprocess.run([XRDCP, "-r", f"{base}/rtree", str(out)],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert (out / "top.txt").read_bytes() == b"top\n"
    assert (out / "sub" / "deep.bin").read_bytes() == b"deepdata\n"


def _mock_propfind_once(port, ready, body):
    """A throwaway HTTP server that answers one PROPFIND with `body` (207)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, port))
    srv.listen(1)
    srv.settimeout(20)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        conn.recv(65536)   # drain the request headers
        hdr = ("HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        conn.sendall(hdr.encode() + body)
    except OSError:
        pass
    finally:
        conn.close()
        srv.close()


def test_s3_recursive_download(web_servers, tmp_path):
    """xrdcp -r over s3:// lists the prefix (SigV4-signed ListObjectsV2) and downloads
    the whole tree, preserving structure. Objects are uploaded through the client first
    so they land wherever the server maps the bucket (no FS-layout assumption)."""
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    creds = ["--s3-access", S3_AK, "--s3-secret", S3_SK, "--s3-region", "us-east-1"]

    top = tmp_path / "top.txt"
    top.write_bytes(b"s3-top\n")
    deep = tmp_path / "deep.bin"
    deep.write_bytes(b"s3-nested\n")
    for src, key in ((top, "rtree/a.txt"), (deep, "rtree/sub/b.bin")):
        up = subprocess.run([XRDCP, *creds, "-f", str(src), f"{base}/{key}"],
                            capture_output=True, text=True, timeout=60)
        assert up.returncode == 0, f"upload {key}: {up.stdout}\n{up.stderr}"

    out = tmp_path / "s3out"
    r = subprocess.run([XRDCP, "-r", *creds, f"{base}/rtree", str(out)],
                       capture_output=True, text=True, timeout=90)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    got = list(out.rglob("*")) if out.exists() else []
    assert (out / "a.txt").exists(), f"out={got}\nSTDOUT={r.stdout}\nSTDERR={r.stderr}"
    assert (out / "a.txt").read_bytes() == b"s3-top\n"
    assert (out / "sub" / "b.bin").read_bytes() == b"s3-nested\n"


def test_webdav_recursive_upload(web_servers, tmp_path):
    """xrdcp -r ./localtree davs://h/coll walks the local tree, MKCOLs each
    collection and PUTs each file; verified by recursively downloading it back."""
    src = tmp_path / "tree"
    expect = _build_tree(src)
    base = f"http://{HOST}:{web_servers['dav_port']}"
    coll = f"{base}/uptree"

    up = subprocess.run([XRDCP, "-r", str(src), coll],
                        capture_output=True, text=True, timeout=90)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    out = tmp_path / "back"
    dn = subprocess.run([XRDCP, "-r", coll, str(out)],
                        capture_output=True, text=True, timeout=90)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    for rel, data in expect.items():
        got = out / rel
        assert got.exists(), (f"missing {rel}; out={list(out.rglob('*'))}\n"
                              f"UP={up.stderr}\nDN={dn.stderr}")
        assert got.read_bytes() == data, rel


def test_s3_recursive_upload(web_servers, tmp_path):
    """xrdcp -r ./localtree s3://h/bucket/prefix uploads each file as a flat key
    (no MKCOL); verified by recursively downloading the prefix back."""
    src = tmp_path / "s3tree"
    expect = _build_tree(src)
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    creds = ["--s3-access", S3_AK, "--s3-secret", S3_SK, "--s3-region", "us-east-1"]

    up = subprocess.run([XRDCP, "-r", *creds, str(src), f"{base}/uptree"],
                        capture_output=True, text=True, timeout=90)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    out = tmp_path / "s3back"
    dn = subprocess.run([XRDCP, "-r", *creds, f"{base}/uptree", str(out)],
                        capture_output=True, text=True, timeout=90)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    for rel, data in expect.items():
        got = out / rel
        assert got.exists(), (f"missing {rel}; out={list(out.rglob('*'))}\n"
                              f"UP={up.stderr}\nDN={dn.stderr}")
        assert got.read_bytes() == data, rel


def _spool_env(tmp_path):
    """A subprocess env whose TMPDIR is an isolated dir, so we can assert the
    web->web relay leaves no staging temp behind."""
    spool = tmp_path / "spool"
    spool.mkdir(exist_ok=True)
    return dict(os.environ, TMPDIR=str(spool)), spool


def test_web2web_davs_to_davs(web_servers, tmp_path):
    """`xrdcp davs://A/f davs://B/g` (web->web) stages through a local temp and
    leaves no temp behind."""
    base = f"http://{HOST}:{web_servers['dav_port']}"
    payload = os.urandom(64 * 1024 + 7)
    src = tmp_path / "src.bin"
    src.write_bytes(payload)
    env, spool = _spool_env(tmp_path)

    up = subprocess.run([XRDCP, "-f", str(src), f"{base}/w2w_src.bin"],
                        capture_output=True, text=True, timeout=60, env=env)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    r = subprocess.run([XRDCP, f"{base}/w2w_src.bin", f"{base}/w2w_dst.bin"],
                       capture_output=True, text=True, timeout=90, env=env)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"

    back = tmp_path / "back.bin"
    dn = subprocess.run([XRDCP, "-f", f"{base}/w2w_dst.bin", str(back)],
                        capture_output=True, text=True, timeout=60, env=env)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert back.read_bytes() == payload
    assert list(spool.glob("xrdcp-w2w-*")) == [], "staging temp leaked"


def test_web2web_s3_to_davs_cross_protocol(web_servers, tmp_path):
    """Cross-protocol relay: s3:// source -> davs:// destination (SigV4 read leg,
    bearer/anon write leg) round-trips byte-exact."""
    s3 = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    dav = f"http://{HOST}:{web_servers['dav_port']}"
    creds = ["--s3-access", S3_AK, "--s3-secret", S3_SK, "--s3-region", "us-east-1"]
    payload = b"cross-protocol-relay\n" * 100
    src = tmp_path / "x.bin"
    src.write_bytes(payload)
    env, spool = _spool_env(tmp_path)

    up = subprocess.run([XRDCP, *creds, "-f", str(src), f"{s3}/x.bin"],
                        capture_output=True, text=True, timeout=60, env=env)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    r = subprocess.run([XRDCP, *creds, f"{s3}/x.bin", f"{dav}/relayed.bin"],
                       capture_output=True, text=True, timeout=90, env=env)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"

    back = tmp_path / "relayed.back"
    dn = subprocess.run([XRDCP, "-f", f"{dav}/relayed.bin", str(back)],
                        capture_output=True, text=True, timeout=60, env=env)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert back.read_bytes() == payload
    assert list(spool.glob("xrdcp-w2w-*")) == [], "staging temp leaked"


def test_web2web_recursive_davs_to_s3(web_servers, tmp_path):
    """`xrdcp -r davs://A/coll s3://B/bucket/pfx` relays a whole tree web->web,
    verified by downloading the s3 prefix back."""
    dav = f"http://{HOST}:{web_servers['dav_port']}"
    s3 = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    creds = ["--s3-access", S3_AK, "--s3-secret", S3_SK, "--s3-region", "us-east-1"]
    env, spool = _spool_env(tmp_path)

    # build a tree locally, upload it to davs as the source collection
    local = tmp_path / "tree"
    expect = _build_tree(local)
    up = subprocess.run([XRDCP, "-r", str(local), f"{dav}/w2wtree"],
                        capture_output=True, text=True, timeout=90, env=env)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"

    relay = subprocess.run([XRDCP, "-r", *creds, f"{dav}/w2wtree", f"{s3}/relaytree"],
                           capture_output=True, text=True, timeout=120, env=env)
    assert relay.returncode == 0, f"{relay.stdout}\n{relay.stderr}"

    out = tmp_path / "out"
    dn = subprocess.run([XRDCP, "-r", *creds, f"{s3}/relaytree", str(out)],
                        capture_output=True, text=True, timeout=120, env=env)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    for rel, data in expect.items():
        got = out / rel
        assert got.exists(), (f"missing {rel}; out={list(out.rglob('*'))}\n"
                              f"RELAY={relay.stderr}\nDN={dn.stderr}")
        assert got.read_bytes() == data, rel
    assert list(spool.glob("xrdcp-w2w-*")) == [], "staging temp leaked"


def test_web2web_missing_source_cleans_temp(web_servers, tmp_path):
    """A web->web copy whose source 404s fails cleanly, does NOT create the dst,
    and leaves no staging temp."""
    base = f"http://{HOST}:{web_servers['dav_port']}"
    env, spool = _spool_env(tmp_path)
    r = subprocess.run([XRDCP, "--retry", "0",
                        f"{base}/no_such_w2w_src", f"{base}/w2w_should_not_exist"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode != 0, f"expected failure: {r.stdout}\n{r.stderr}"
    assert list(spool.glob("xrdcp-w2w-*")) == [], "staging temp leaked on error"
    # the dst must not have been created
    head = subprocess.run([XRDCP, f"{base}/w2w_should_not_exist", "-"],
                          capture_output=True, text=True, timeout=60, env=env)
    assert head.returncode != 0, "dst should not exist after a failed relay"


def test_webdav_recursive_rejects_traversal(tmp_path):
    """Security-negative: a hostile server returning a '..'-laden href must NOT let
    `xrdcp -r` write outside the destination directory."""
    port = _free_port()
    body = (b'<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">'
            b'<D:response><D:href>/rtree/../../escape.txt</D:href>'
            b'<D:propstat><D:prop><D:resourcetype/></D:prop>'
            b'<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'
            b'</D:multistatus>')
    ready = threading.Event()
    t = threading.Thread(target=_mock_propfind_once, args=(port, ready, body), daemon=True)
    t.start()
    ready.wait(5)
    out = tmp_path / "out"
    out.mkdir()
    p = subprocess.run([XRDCP, "-r", f"http://{HOST}:{port}/rtree", str(out)],
                       capture_output=True, text=True, timeout=30)
    t.join(10)
    assert p.returncode != 0
    assert "unsafe path" in p.stderr.lower(), p.stderr
    # nothing escaped the sandbox
    assert not (tmp_path / "escape.txt").exists()
    assert not (tmp_path.parent / "escape.txt").exists()


def test_s3_creds_from_xrdrc(web_servers, tmp_path):
    """Per-endpoint credentials in ~/.xrdrc: an s3 alias carries the SigV4 keys, so
    the transfer works with NO --s3-* flags and NO AWS_* environment."""
    src = tmp_path / "rcobj.bin"
    src.write_bytes(os.urandom(4096))
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    rc = tmp_path / "xrdrc"
    rc.write_text(f"[alias s3lab]\nurl = {base}\n"
                  f"s3_access = {S3_AK}\ns3_secret = {S3_SK}\ns3_region = us-east-1\n")
    env = {k: v for k, v in os.environ.items()
           if k not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION")}
    env["XRDRC"] = str(rc)

    up = subprocess.run([XRDCP, "-f", str(src), "s3lab:/rcobj.bin"],
                        capture_output=True, text=True, timeout=60, env=env)
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    back = tmp_path / "rcback.bin"
    dn = subprocess.run([XRDCP, "-f", "s3lab:/rcobj.bin", str(back)],
                        capture_output=True, text=True, timeout=60, env=env)
    assert dn.returncode == 0, f"{dn.stdout}\n{dn.stderr}"
    assert _md5(src) == _md5(back)


def test_s3_unsigned_put_rejected(web_servers, tmp_path):
    """Security-negative: with keys configured, an unsigned PUT must be refused."""
    src = tmp_path / "noauth.bin"
    src.write_bytes(b"should-not-land\n")
    base = f"s3://{HOST}:{web_servers['s3_port']}/testbucket"
    # No --s3-* flags and no AWS_* env → anonymous request.
    env = {k: v for k, v in os.environ.items()
           if k not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
    p = subprocess.run([XRDCP, "-f", str(src), f"{base}/noauth.bin"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert p.returncode != 0, f"unsigned PUT unexpectedly succeeded: {p.stdout}"


# ---------------------------------------------------------------------------
# Task A5: brix_vfs S3 backend smoke tests
# ---------------------------------------------------------------------------

VFS_S3_SMOKE = os.path.join(CLIENT_DIR, "bin", "vfs_s3_smoke")
_S3_PART_OVERRIDE = "512"   # force MPU with tiny parts for testing


def _build_vfs_s3_smoke():
    """Build the vfs_s3_smoke binary; skip if no C compiler or build fails."""
    import shutil
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    r = subprocess.run(["make", "-C", CLIENT_DIR, "vfs-s3-smoke"],
                       capture_output=True, text=True, timeout=300)
    if not os.path.exists(VFS_S3_SMOKE):
        pytest.skip(f"vfs-s3-smoke build failed:\n{r.stdout}\n{r.stderr}")


def test_vfs_s3_backend_roundtrip(web_servers):
    """A5: brix_vfs S3 backend — single-PUT + multipart write→read round-trip.

    Builds the vfs_s3_smoke C driver and runs it against the module's own S3
    endpoint (web_servers fixture).  S3_PART_MAX_OVERRIDE is set to 512 bytes
    so the multipart path is exercised without needing a large test object.

    NOTE: this tests the VFS backend directly (not via xrdcp), so it exercises
    code that copy_web does NOT exercise — confirming Task A5's code path.
    """
    _build_vfs_s3_smoke()
    s3_url = (f"s3://{HOST}:{web_servers['s3_port']}"
              f"/testbucket/vfs_smoke.bin")
    env = dict(os.environ,
               S3_URL=s3_url,
               AWS_ACCESS_KEY_ID=S3_AK,
               AWS_SECRET_ACCESS_KEY=S3_SK,
               AWS_DEFAULT_REGION="us-east-1",
               S3_PART_MAX_OVERRIDE=_S3_PART_OVERRIDE)
    p = subprocess.run([VFS_S3_SMOKE, "roundtrip"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert p.returncode == 0, (
        f"vfs_s3_smoke roundtrip failed:\n{p.stdout}\n{p.stderr}"
    )


def test_vfs_s3_bad_credentials(web_servers):
    """A5 error path: wrong AWS credentials produce XRDC_EAUTH (not a crash)."""
    _build_vfs_s3_smoke()
    s3_url = (f"s3://{HOST}:{web_servers['s3_port']}"
              f"/testbucket/vfs_smoke.bin")
    env = dict(os.environ,
               S3_URL=s3_url,
               AWS_ACCESS_KEY_ID=S3_AK,
               AWS_SECRET_ACCESS_KEY=S3_SK,
               AWS_DEFAULT_REGION="us-east-1",
               S3_PART_MAX_OVERRIDE=_S3_PART_OVERRIDE)
    p = subprocess.run([VFS_S3_SMOKE, "badcreds"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert p.returncode == 0, (
        f"vfs_s3_smoke badcreds failed:\n{p.stdout}\n{p.stderr}"
    )


def test_vfs_s3_nonsequential_write(web_servers):
    """A5 negative path: non-sequential pwrite returns XRDC_EUSAGE."""
    _build_vfs_s3_smoke()
    s3_url = (f"s3://{HOST}:{web_servers['s3_port']}"
              f"/testbucket/vfs_smoke.bin")
    env = dict(os.environ,
               S3_URL=s3_url,
               AWS_ACCESS_KEY_ID=S3_AK,
               AWS_SECRET_ACCESS_KEY=S3_SK,
               AWS_DEFAULT_REGION="us-east-1",
               S3_PART_MAX_OVERRIDE=_S3_PART_OVERRIDE)
    p = subprocess.run([VFS_S3_SMOKE, "nonseq"],
                       capture_output=True, text=True, timeout=60, env=env)
    assert p.returncode == 0, (
        f"vfs_s3_smoke nonseq failed:\n{p.stdout}\n{p.stderr}"
    )
