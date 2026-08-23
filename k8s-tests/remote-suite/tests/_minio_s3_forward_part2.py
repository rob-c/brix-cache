# --------------------------------------------------------------------------
# Stream-plane static credential (P80.1 regression). Bug 1.1: the per-worker
# credential replay (process_server_init.c) hand-copied 4 of 8 credential
# fields, so every worker spawn / SIGHUP wiped the parse-time S3 keys to ""
# and all stream-plane S3 requests signed with an empty access key. The
# WebDAV plane (above) never replayed, hiding the asymmetry — this lane pins
# the stream plane to the same static-credential contract.
# --------------------------------------------------------------------------

WRONG_SECRET = "definitely-wrong-secret"


def _xrdcp(src, dst, timeout=60):
    env = {**os.environ,
           "XRD_CONNECTIONRETRY": "1",
           "XRD_REQUESTTIMEOUT": "30",
           "XRD_STREAMTIMEOUT": "30"}
    return subprocess.run([XRDCP_BIN, "-f", src, dst],
                          capture_output=True, text=True,
                          timeout=timeout, env=env)


def _sighup_and_wait(base, port):
    """Reload the instance (SIGHUP) so a FRESH worker serves — the 1.1 wipe
    fired in the worker-init replay, i.e. on every (re)spawn."""
    with open(os.path.join(base, "logs", "nginx.pid")) as f:
        os.kill(int(f.read().strip()), signal.SIGHUP)
    time.sleep(1.0)
    assert _wait_port("127.0.0.1", port), \
        "[brix-machinery] stream node gone after SIGHUP reload"


def _start_stream_node(minio, secret_key, tag):
    (port,) = free_ports(1)
    base, p = _start_nginx(port, minio["port"], secret_key, tag,
                           conf_fn=_stream_conf)
    if p.returncode != 0:
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] nginx rejected the stream s3 config: "
                    f"{p.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        err = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] stream node never listened: {err}")
    return base, port


@pytest.fixture(scope="module")
def brix_stream(minio):
    """root:// front with the correct static credential, reloaded once so a
    respawned worker (the bug-1.1 trigger) serves every request."""
    if REMOTE_MODE:
        pytest.skip("stream static-cred lane is launched locally only")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip("xrdcp not available for the stream lane")
    base, port = _start_stream_node(minio, MINIO_SK, "stream_ok")
    _sighup_and_wait(base, port)
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)


@pytest.fixture(scope="module")
def brix_stream_bad(minio):
    """root:// front signing with a wrong secret — error + leak-probe lane."""
    if REMOTE_MODE:
        pytest.skip("stream static-cred lane is launched locally only")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip("xrdcp not available for the stream lane")
    base, port = _start_stream_node(minio, WRONG_SECRET, "stream_bad")
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)


def _root_url(node, key):
    return f"root://{node['host']}:{node['port']}//{key}"


class TestStreamStaticCredential:

    def test_roundtrip_survives_worker_respawn(self, minio, brix_stream,
                                               tmp_path):
        """Success: with a static brix_storage_credential, a post-respawn
        worker must still sign upstream S3 requests with the configured keys
        (upload through brix lands in MinIO; direct-seeded object reads back
        byte-exact)."""
        _assert_stream_upload(minio, brix_stream, tmp_path)
        _assert_stream_download(brix_stream, tmp_path)


def _assert_stream_upload(minio, node, tmp_path):
    body = os.urandom(200_000)
    src = tmp_path / "stream_up.bin"
    src.write_bytes(body)
    p = _xrdcp(str(src), _root_url(node, "stream_up.bin"))
    if p.returncode != 0:
        attribute_failure(f"stream PUT (xrdcp) failed: "
                          f"{(p.stderr or p.stdout)[-300:]}")
    r = minio_request("GET", f"/{BUCKET}/stream_up.bin")
    if r.status_code != 200:
        attribute_failure(f"stream-uploaded object absent from MinIO "
                          f"(direct GET {r.status_code})")
    assert _sha256(r.content) == _sha256(body), \
        "[brix-machinery] stream upload corrupted in MinIO"


def _assert_stream_download(node, tmp_path):
    seed = os.urandom(150_000)
    r = minio_request("PUT", f"/{BUCKET}/stream_seed.bin", seed)
    assert r.status_code == 200, f"[backend] seed PUT {r.status_code}"
    dst = tmp_path / "stream_down.bin"
    p = _xrdcp(_root_url(node, "stream_seed.bin"), str(dst))
    if p.returncode != 0:
        attribute_failure(f"stream GET (xrdcp) failed: "
                          f"{(p.stderr or p.stdout)[-300:]}")
    assert _sha256(dst.read_bytes()) == _sha256(seed), \
        "[brix-machinery] stream download corrupted"


class TestStreamStaticCredentialContinued:

    def test_wrong_secret_is_rejected(self, minio, brix_stream_bad,
                                      tmp_path):
        """Error: a wrong static secret must fail the stream ops upstream —
        proving the stream-plane credential is load-bearing (not anonymous
        fallback, not a stale cached instance)."""
        body = os.urandom(4096)
        src = tmp_path / "stream_forged.bin"
        src.write_bytes(body)
        p = _xrdcp(str(src), _root_url(brix_stream_bad, "stream_forged.bin"))
        assert p.returncode != 0, \
            "SECURITY: stream PUT with a wrong backend secret succeeded"
        g = minio_request("GET", f"/{BUCKET}/stream_forged.bin")
        assert g.status_code == 404, \
            "SECURITY: object written to MinIO despite a bad stream credential"
        dst = tmp_path / "stream_forged_down.bin"
        p = _xrdcp(_root_url(brix_stream_bad, "direct.bin"), str(dst))
        assert p.returncode != 0, \
            "SECURITY: stream GET with a wrong backend secret succeeded"

    def test_secret_never_leaks_into_logs(self, minio, brix_stream_bad,
                                          tmp_path):
        """Security-negative: the S3 secret must not appear in the server's
        error log, even on signing/auth failures (uses the distinctive
        wrong-secret instance so the probe string is unambiguous)."""
        dst = tmp_path / "leak_probe.bin"
        _xrdcp(_root_url(brix_stream_bad, "direct.bin"), str(dst))
        log = _tail(os.path.join(brix_stream_bad["base"], "logs",
                                 "error.log"), n=200_000)
        assert WRONG_SECRET not in log, \
            "SECURITY: backend S3 secret leaked into error.log"


# --------------------------------------------------------------------------
# P80.2 — staged-write residue: resume divert, MPU boundary, exclusive publish
# --------------------------------------------------------------------------

def _stream_resume_conf(port, minio_port, root, logs, secret_key):
    """Same stream front but with brix_upload_resume ON — the 1.2c trap: a
    staged-only backend must divert resume (drop it for the open) so bytes
    still land in MinIO instead of stranding in the local skeleton file."""
    return _stream_conf(port, minio_port, root, logs, secret_key).replace(
        "brix_upload_resume off;", "brix_upload_resume on;")


def _require_local_xrdcp_lane(label):
    if REMOTE_MODE:
        pytest.skip(f"{label} lane is launched locally only")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"xrdcp not available for the {label} lane")


def _start_checked_node(minio, tag, conf_fn, label):
    (port,) = free_ports(1)
    base, result = _start_nginx(port, minio["port"], MINIO_SK, tag,
                                conf_fn=conf_fn)
    if result.returncode != 0:
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] nginx rejected the {label} config: "
                    f"{result.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        error = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] {label} node never listened: {error}")
    return base, port


def _s3front_conf(port, minio_port, root, logs, secret_key):
    """S3 protocol front (anonymous) over the same MinIO backend — the plane
    whose PutObject `If-None-Match: *` drives noreplace=1 into
    sd_remote_staged_commit (exclusive publish, P80.2)."""
    return f"""
daemon on;
error_log {logs}/error.log info;
pid {logs}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {logs}/body;
    proxy_temp_path {logs}/proxy;
    fastcgi_temp_path {logs}/fcgi;
    uwsgi_temp_path {logs}/uwsgi;
    scgi_temp_path {logs}/scgi;
    brix_credential minio {{
        s3_access_key {MINIO_AK};
        s3_secret_key {secret_key};
        s3_region {REGION};
    }}
    server {{
        listen 127.0.0.1:{port};
        client_max_body_size 64m;
        location / {{
            brix_s3 on;
            brix_s3_bucket frontbucket;
            brix_export {root};
            brix_storage_backend s3://127.0.0.1:{minio_port}/{BUCKET};
            brix_storage_credential minio;
            brix_allow_write on;
        }}
    }}
}}
"""


@pytest.fixture(scope="module")
def brix_stream_resume(minio):
    """root:// front with brix_upload_resume on over the staged-only backend."""
    _require_local_xrdcp_lane("resume-divert")
    base, port = _start_checked_node(
        minio, "stream_resume", _stream_resume_conf, "resume-on stream s3")
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)


@pytest.fixture(scope="module")
def brix_s3front(minio):
    """S3 protocol front over the MinIO backend (exclusive-publish lane)."""
    if REMOTE_MODE:
        pytest.skip("s3-front lane is launched locally only")
    (port,) = free_ports(1)
    base, p = _start_nginx(port, minio["port"], MINIO_SK, "s3front",
                           conf_fn=_s3front_conf)
    if p.returncode != 0:
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] nginx rejected the s3-front config: "
                    f"{p.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        err = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] s3-front node never listened: {err}")
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)


def _skeleton_residue(base):
    """Regular files with content left under the node's local export root —
    a diverted resume must leave the skeleton byte-free."""
    residue = []
    for dirpath, _dirs, files in os.walk(os.path.join(base, "root")):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > 0:
                    residue.append(path)
            except OSError:
                pass
    return residue


def _upload_resume_object(node, tmp_path, name, size, timeout=60):
    body = os.urandom(size)
    source = tmp_path / name
    source.write_bytes(body)
    result = _xrdcp(str(source), _root_url(node, name), timeout=timeout)
    if result.returncode != 0:
        attribute_failure(f"{name} PUT (xrdcp) failed: "
                          f"{(result.stderr or result.stdout)[-300:]}")
    return body


def _assert_minio_object(body, name, label, timeout=10):
    result = minio_request("GET", f"/{BUCKET}/{name}", timeout=timeout)
    if result.status_code != 200:
        attribute_failure(f"{label} upload absent from MinIO "
                          f"(direct GET {result.status_code})")
    assert _sha256(result.content) == _sha256(body), \
        f"[brix-machinery] {label} upload corrupted in MinIO"


def _assert_no_incomplete_upload(name):
    result = minio_request("GET", f"/{BUCKET}?uploads=")
    assert result.status_code == 200, \
        "[brix-machinery] could not inspect incomplete multipart uploads"
    assert name.encode() not in result.content, \
        "[brix-machinery] incomplete multipart upload left behind"


class TestStagedWriteResidue:

    def test_resume_divert_upload_lands_in_minio(self, minio,
                                                 brix_stream_resume,
                                                 tmp_path):
        """Success: with brix_upload_resume on, an upload to the staged-only
        backend is transparently diverted through the staged seam — the object
        lands byte-exact in MinIO and NO bytes strand in the local skeleton."""
        body = _upload_resume_object(brix_stream_resume, tmp_path,
                                     "resume_up.bin", 200_000)
        _assert_minio_object(body, "resume_up.bin", "resume-divert")
        residue = _skeleton_residue(brix_stream_resume["base"])
        assert not residue, \
            f"[brix-machinery] resume left byte residue in the local " \
            f"skeleton (divert failed): {residue}"

    def test_mpu_boundary_upload_byte_exact(self, minio, brix_stream_resume,
                                            tmp_path):
        """Error-boundary: a >16MiB upload crosses SD_REMOTE_PART_SIZE, forcing
        the lazy single-PUT buffer to upgrade to a multipart upload mid-stream.
        Byte-exact roundtrip, and no incomplete MPU left behind."""
        body = _upload_resume_object(brix_stream_resume, tmp_path,
                                     "mpu_up.bin", 20 * 1024 * 1024, 120)
        _assert_minio_object(body, "mpu_up.bin", "MPU-boundary", timeout=60)
        _assert_no_incomplete_upload("mpu_up.bin")

    def test_exclusive_create_refuses_overwrite(self, minio, brix_s3front):
        """Security-negative: PutObject with If-None-Match:* (exclusive
        create) must refuse to replace an existing object — noreplace reaches
        sd_remote_staged_commit as a HEAD-before-publish and the original
        bytes survive."""
        first = os.urandom(4096)
        second = os.urandom(4096)
        url = (f"http://{brix_s3front['host']}:{brix_s3front['port']}"
               f"/frontbucket/excl.bin")
        # The MinIO bucket outlives test runs — clear any prior excl.bin so
        # the first exclusive PUT exercises the create path, not the refusal.
        minio_request("DELETE", f"/{BUCKET}/excl.bin")
        r = requests.put(url, data=first,
                         headers={"If-None-Match": "*"}, timeout=30)
        if r.status_code not in (200, 201):
            attribute_failure(f"exclusive first PUT failed: {r.status_code}")
        r = requests.put(url, data=second,
                         headers={"If-None-Match": "*"}, timeout=30)
        assert r.status_code in (409, 412), \
            f"SECURITY: exclusive-create PUT over an existing object " \
            f"returned {r.status_code} (expected 409/412)"
        g = minio_request("GET", f"/{BUCKET}/excl.bin")
        assert g.status_code == 200 and _sha256(g.content) == _sha256(first), \
            "SECURITY: exclusive-create overwrite replaced the object bytes"


