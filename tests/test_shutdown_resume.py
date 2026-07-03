"""
Fast worker teardown + mid-transfer resume across an nginx reload/restart.

Verifies the Phase-1 fast-teardown work:
  * an idle root:// connection does NOT keep a draining worker alive — the old
    worker exits promptly after `nginx -s reload` (background timers stop
    re-arming, idle connections are dropped, a clean FIN is the retry signal);
  * a large download survives repeated reload + hard-kill of the serving worker
    mid-transfer and lands BYTE-EXACT, because the resilient client reconnects
    to the freshly-spawned worker and resumes from its last offset — on BOTH
    root:// (idempotent reopen+pread) and http:// (RFC 7233 Range GET).

Self-hosts its own nginx (stream root:// + http webdav) on free ports.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_shutdown_resume.py -v -p no:xdist
"""

import glob
import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(180)

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


def _master_pid(root):
    return int((root / "nginx.pid").read_text().strip())


def _worker_pids(master):
    """Live worker pids = children of the nginx master."""
    out = subprocess.run(
        ["ps", "-o", "pid", "--no-headers", "--ppid", str(master)],
        capture_output=True, text=True,
    ).stdout
    return [int(x) for x in out.split()]


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@pytest.fixture()
def srv(tmp_path_factory):
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp build failed")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("shutdown")
    data = root / "data"
    data.mkdir(parents=True)
    rport = _free_port()
    hport = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
thread_pool default threads=4 max_queue=65536;
stream {{
    server {{ listen {BIND_HOST}:{rport}; xrootd on; brix_root {data};
             brix_auth none; brix_allow_write on;
             brix_upload_resume on; }}
}}
http {{
    access_log off;
    client_max_body_size 64m;
    client_body_temp_path {root}/body_tmp;
    proxy_temp_path {root}/proxy_tmp;
    fastcgi_temp_path {root}/fcgi_tmp;
    uwsgi_temp_path {root}/uwsgi_tmp;
    scgi_temp_path {root}/scgi_tmp;
    server {{
        listen {BIND_HOST}:{hport};
        location / {{ brix_webdav on; brix_webdav_root {data};
                     brix_webdav_auth none; brix_webdav_allow_write on;
                     brix_webdav_upload_resume on; }}
    }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    for _ in range(50):
        if _port_up(HOST, rport) and _port_up(HOST, hport):
            break
        time.sleep(0.1)
    yield {"root": root, "conf": conf, "data": data, "rport": rport, "hport": hport}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"], capture_output=True)
    time.sleep(0.3)


def test_idle_connection_does_not_block_fast_teardown(srv):
    """An idle root:// connection must not pin a draining worker: the old
    worker exits within a couple of seconds of reload, not at worker_shutdown_
    timeout (which is unset here = would otherwise hang indefinitely)."""
    master = _master_pid(srv["root"])
    old = _worker_pids(master)
    assert old, "no worker running"

    # Park an idle root:// connection (handshake then sit).
    s = socket.create_connection((HOST, srv["rport"]))
    s.sendall(b"\x00" * 16 + b"\x00\x00\x07\xd0")  # 20-byte client hello

    try:
        subprocess.run([NGINX_BIN, "-c", str(srv["conf"]), "-s", "reload"],
                       capture_output=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            if all(not _alive(p) for p in old):
                break
            time.sleep(0.1)
        elapsed = "alive" if any(_alive(p) for p in old) else "exited"
        assert all(not _alive(p) for p in old), \
            f"old worker(s) {old} still {elapsed} 15s after reload"
    finally:
        s.close()
    # let a fresh worker come up for the next test
    for _ in range(50):
        if _worker_pids(_master_pid(srv["root"])):
            break
        time.sleep(0.1)


def _wait_progress(glob_pat, timeout=15.0):
    """Wait until some file matching glob_pat has grown past 0 bytes — i.e. the
    transfer is actively flowing — so kills land MID-transfer (a real restart)
    rather than during connection establishment."""
    import glob as _glob
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in _glob.glob(glob_pat):
            try:
                if os.path.getsize(p) > 0:
                    return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def _xrdcp_under_chaos(srv, argv, verify_path, want_md5,
                       n_kills=4, spacing=0.8, warmup_glob=None):
    """Run `xrdcp argv`, hard-killing the serving worker up to `n_kills` times
    mid-transfer (the master auto-respawns one, forcing the client to reconnect +
    resume), then STOP and let the transfer finish uninterrupted.  Bounding the
    chaos keeps the test load-robust — a respawn storm can't starve the transfer
    past the client's stall window — while still exercising several real mid-
    transfer severs.  Asserts completion and that verify_path is byte-exact.

    warmup_glob: if set, wait until a matching file is non-empty before the first
    kill, so severs land on an established, actively-flowing transfer."""
    master = _master_pid(srv["root"])
    env = dict(os.environ, XRDC_MAX_STALL_MS="60000")
    proc = subprocess.Popen([XRDCP, "-f", *argv],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env)
    if warmup_glob is not None:
        _wait_progress(warmup_glob)
    kills = 0
    while proc.poll() is None and kills < n_kills:
        for w in _worker_pids(master):    # force a true TCP sever
            try:
                os.kill(w, 9)
                kills += 1
            except OSError:
                pass
        time.sleep(spacing)               # let the respawned worker serve a chunk
    rc = proc.wait()                      # finish uninterrupted after n_kills
    log = proc.stdout.read() if proc.stdout else ""
    assert rc == 0, f"xrdcp failed rc={rc} kills={kills}\n{log}"
    assert verify_path.exists(), "no output file"
    got = hashlib.md5(verify_path.read_bytes()).hexdigest()
    assert got == want_md5, f"byte mismatch after {kills} mid-transfer kills"
    return kills


@pytest.mark.parametrize("scheme", ["root", "http"])
def test_download_resumes_across_restart(srv, tmp_path, scheme):
    """A large download survives reload + hard worker-kill mid-transfer and is
    byte-exact, on both root:// and http://."""
    big = srv["data"] / "resume.bin"
    payload = os.urandom(1 << 20) * 384          # 384 MiB, incompressible
    big.write_bytes(payload)
    src_md5 = hashlib.md5(payload).hexdigest()

    if scheme == "root":
        url = f"root://{HOST}:{srv['rport']}//resume.bin"
    else:
        url = f"http://{HOST}:{srv['hport']}//resume.bin"

    out = tmp_path / f"out-{scheme}.bin"
    # Downloads are idempotent reopen+pread, so kill from t=0 (catches connection
    # establishment + early transfer) at a survivable cadence.
    kills = _xrdcp_under_chaos(srv, [url, str(out)], out, src_md5, spacing=0.3)
    # best-effort: confirm we actually severed the connection at least once
    assert kills >= 1


def test_upload_resumes_across_restart(srv, tmp_path):
    """A large root:// UPLOAD survives reload + hard worker-kill mid-transfer
    (including the commit-on-close) and the committed file is byte-exact —
    requires brix_upload_resume on (deterministic preserved partial)."""
    src = tmp_path / "upload-src.bin"
    payload = os.urandom(1 << 20) * 256          # 256 MiB, incompressible
    src.write_bytes(payload)
    src_md5 = hashlib.md5(payload).hexdigest()

    url = f"root://{HOST}:{srv['rport']}//uploaded.bin"
    dst = srv["data"] / "uploaded.bin"
    # The resilient initial-open + sink + close ride out each sever and resume
    # from the server's preserved partial; a slightly wider spacing lets the
    # respawned worker durably write a chunk between kills.  Wait for the staging
    # partial to start filling before killing, so severs land mid-transfer (a real
    # restart), not during connection establishment.
    warmup = str(srv["data"] / "*.xrdresume.*.part")
    kills = _xrdcp_under_chaos(srv, [str(src), url], dst, src_md5,
                               spacing=1.0, warmup_glob=warmup)
    assert kills >= 1
    # the staging partial must have been committed (renamed) and cleaned up
    leftover = list(srv["data"].glob("*.xrdresume.*.part"))
    assert not leftover, f"uncommitted resume partial left behind: {leftover}"


def test_webdav_upload_resumes_across_restart(srv, tmp_path):
    """A large http:// (WebDAV) UPLOAD survives reload + hard worker-kill mid-
    transfer and the committed file is byte-exact — the native client streams
    Content-Range PUT chunks and resumes from the server's durable offset
    (brix_webdav_upload_resume on)."""
    src = tmp_path / "webup-src.bin"
    payload = os.urandom(1 << 20) * 128          # 128 MiB, incompressible
    src.write_bytes(payload)
    src_md5 = hashlib.md5(payload).hexdigest()

    url = f"http://{HOST}:{srv['hport']}//webuploaded.bin"
    dst = srv["data"] / "webuploaded.bin"
    warmup = str(srv["data"] / "*.xrdresume.*.part")
    kills = _xrdcp_under_chaos(srv, [str(src), url], dst, src_md5,
                               spacing=1.0, warmup_glob=warmup)
    assert kills >= 1
    leftover = list(srv["data"].glob("*.xrdresume.*.part"))
    assert not leftover, f"uncommitted resume partial left behind: {leftover}"


def test_upload_resume_stage_dir(tmp_path_factory):
    """Uploads stage on a CONFIGURABLE directory (brix_stage_dir) — typically a
    fast caching device — then commit to the storage.  Prefers /dev/shm (tmpfs, a
    different device) to exercise the cross-device copy commit; the partial lives
    in the stage dir during transfer, survives worker-kills, lands byte-exact on
    storage, and the stage dir is emptied on commit."""
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(XRDCP) or not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("xrdcp/nginx unavailable")

    root = tmp_path_factory.mktemp("stagedir")
    data = root / "data"
    data.mkdir(parents=True)
    shm = "/dev/shm"
    if os.path.isdir(shm) and os.access(shm, os.W_OK):
        stage = os.path.join(shm, f"xrd-stage-{os.getpid()}")  # tmpfs => cross-device
    else:
        stage = str(root / "stage")
    os.makedirs(stage, exist_ok=True)
    rport = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 256; }}
thread_pool default threads=4 max_queue=65536;
stream {{
    server {{ listen {BIND_HOST}:{rport}; xrootd on; brix_root {data};
             brix_auth none; brix_allow_write on;
             brix_stage_dir {stage}; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    try:
        for _ in range(50):
            if _port_up(HOST, rport):
                break
            time.sleep(0.1)
        srv = {"root": root, "conf": conf, "data": data, "rport": rport}

        src = root / "src.bin"
        payload = os.urandom(1 << 20) * 128
        src.write_bytes(payload)
        src_md5 = hashlib.md5(payload).hexdigest()
        dst = data / "staged.bin"
        url = f"root://{HOST}:{rport}//staged.bin"

        kills = _xrdcp_under_chaos(srv, [str(src), url], dst, src_md5,
                                   spacing=1.0,
                                   warmup_glob=os.path.join(stage, "*.part"))
        assert kills >= 1
        # commit moved the partial off the stage device onto storage and removed
        # the pending-commit marker (.part and .part.commit both gone)
        assert not glob.glob(os.path.join(stage, "*.xrdresume*")), \
            "staged partial/marker left on the stage device after commit"
    finally:
        subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"],
                       capture_output=True)
        time.sleep(0.3)
        shutil.rmtree(stage, ignore_errors=True)


def test_stage_reaper_recovers_stranded_upload(tmp_path_factory):
    """A COMPLETE upload left in the cache by a worker death mid-commit (a partial
    + a '.commit' marker naming its final path) is tracked across the restart: the
    startup stage-out reaper moves it to storage byte-exact and clears the cache."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx unavailable")
    root = tmp_path_factory.mktemp("reap")
    data = root / "data"
    data.mkdir(parents=True)
    shm = "/dev/shm"
    stage = os.path.join(shm, f"xrd-reap-{os.getpid()}") \
        if os.path.isdir(shm) and os.access(shm, os.W_OK) else str(root / "stage")
    os.makedirs(stage, exist_ok=True)

    # Seed a stranded COMPLETE partial + its pending-commit marker.
    payload = os.urandom(1 << 20) * 32
    src_md5 = hashlib.md5(payload).hexdigest()
    part = os.path.join(stage, "deadbeefcafe0001.xrdresume.part")
    final = data / "recovered.bin"
    with open(part, "wb") as f:
        f.write(payload)
    with open(part + ".commit", "w") as f:
        f.write(str(final))

    rport = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
stream {{
    server {{ listen {BIND_HOST}:{rport}; xrootd on; brix_root {data};
             brix_auth none; brix_allow_write on; brix_stage_dir {stage}; }}
}}
""")
    if subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                      capture_output=True, text=True).returncode != 0:
        shutil.rmtree(stage, ignore_errors=True)
        pytest.skip("nginx -t failed")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    try:
        # reaper first tick ~1s after startup
        for _ in range(50):
            if final.exists():
                break
            time.sleep(0.2)
        assert final.exists(), "reaper did not recover the stranded upload"
        assert hashlib.md5(final.read_bytes()).hexdigest() == src_md5, \
            "recovered file is not byte-exact"
        assert not glob.glob(os.path.join(stage, "*.xrdresume*")), \
            "cache not cleared after stage-out recovery"
    finally:
        subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "quit"],
                       capture_output=True)
        time.sleep(0.3)
        shutil.rmtree(stage, ignore_errors=True)
