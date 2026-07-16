# brix-remote-ok
"""S3 credential-forwarding to an upstream MinIO backend.

Topology under test::

    client ──HTTP PUT/GET──► brix (WebDAV front, brix_storage_backend s3://minio/bucket,
                                   brix_credential → SigV4)  ──signed S3──► MinIO (docker)

Proves that a user can upload/download THROUGH a brix node against a
known-working S3 backend, with brix signing the upstream requests from its
configured credential (sd_remote driver: signed range-GET reads + staged
whole-object PUT writes).

Fault attribution is explicit and layered — every brix-side assertion first
re-verifies the backend directly, so a failure is reported as either
``[backend]`` (MinIO itself broken — not a brix problem) or
``[brix-machinery]`` (backend proven healthy, the forwarding path is at
fault).  Brix code is never touched by this test.

Modes:
  * local (default): MinIO via ``minio_harness.sh`` (docker, same directory) +
    a private nginx instance; skipped when docker is unavailable.
  * remote (k8s): set TEST_MINIO_HOST/TEST_MINIO_PORT and
    TEST_S3FWD_HOST/TEST_S3FWD_PORT to use the in-cluster ``s3-forward``
    profile (charts/s3-forward) instead of launching anything.
"""

import hashlib
import hmac
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone

import pytest
import requests

from settings import NGINX_BIN, XRDCP_BIN, free_ports

# P80.7: docker-gated tier. The suite self-skips without docker (harness exit
# 3), so --fast/--pr stay clean on docker-less boxes; `serial` keeps the fixed
# MinIO port (29000) and the shared container out of the xdist pool.
pytestmark = pytest.mark.serial

HERE = os.path.dirname(os.path.abspath(__file__))

MINIO_HOST = os.environ.get("TEST_MINIO_HOST", "127.0.0.1")
MINIO_PORT = int(os.environ.get("TEST_MINIO_PORT",
                                os.environ.get("MINIO_PORT", "29000")))
MINIO_AK = os.environ.get("MINIO_ROOT_USER", "minioadmin")
MINIO_SK = os.environ.get("MINIO_ROOT_PASSWORD", "minioadmin")
BUCKET = os.environ.get("TEST_MINIO_BUCKET", "brixfwd")
REGION = "us-east-1"

REMOTE_MODE = "TEST_MINIO_HOST" in os.environ
FWD_HOST = os.environ.get("TEST_S3FWD_HOST", "127.0.0.1")
FWD_PORT_ENV = os.environ.get("TEST_S3FWD_PORT")


# --------------------------------------------------------------------------
# Minimal stdlib SigV4 (path-style) — direct-to-MinIO control plane. Kept
# dependency-free on purpose: boto3/requests_aws4auth are not in the test env.
# --------------------------------------------------------------------------

def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _sigv4_headers(method, host, port, path, payload):
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    host_hdr = f"{host}:{port}"
    uri, _, query = path.partition("?")   # canonical URI vs canonical query
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical = (f"{method}\n{uri}\n{query}\nhost:{host_hdr}\n"
                 f"x-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
                 f"\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}")
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n"
               + hashlib.sha256(canonical.encode()).hexdigest())
    k = _sign(_sign(_sign(_sign(("AWS4" + MINIO_SK).encode(), datestamp),
                          REGION), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Host": host_hdr,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={MINIO_AK}/{scope}, "
                          f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
                          f"Signature={sig}"),
    }


def minio_request(method, path, payload=b"", timeout=10):
    """One signed path-style request straight to MinIO (bypassing brix)."""
    url = f"http://{MINIO_HOST}:{MINIO_PORT}{path}"
    hdrs = _sigv4_headers(method, MINIO_HOST, MINIO_PORT, path, payload)
    return requests.request(method, url, headers=hdrs, data=payload,
                            timeout=timeout)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Fault attribution — the point of this test's design: never blame brix while
# the backend is unproven, never blame the backend once it answered correctly.
# --------------------------------------------------------------------------

def _backend_healthy():
    try:
        r = minio_request("PUT", f"/{BUCKET}/_health_probe", b"probe")
        if r.status_code not in (200, 201):
            return False, f"direct PUT status={r.status_code}"
        r = minio_request("GET", f"/{BUCKET}/_health_probe")
        if r.status_code != 200 or r.content != b"probe":
            return False, f"direct GET status={r.status_code}"
        return True, "ok"
    except requests.RequestException as e:
        return False, f"direct request failed: {e}"


def attribute_failure(what):
    """Fail with an explicit layer verdict after a brix-side check failed."""
    ok, detail = _backend_healthy()
    if ok:
        pytest.fail(f"[brix-machinery] {what} — MinIO re-verified healthy "
                    f"directly, so the fault is in the brix forwarding path "
                    f"(sd_remote / credential plumbing), not the backend")
    pytest.fail(f"[backend] {what} — and MinIO itself is broken ({detail}); "
                f"not a brix problem")


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

def _wait_port(host, port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def minio():
    """A healthy MinIO with the test bucket created. Skips without docker."""
    if not REMOTE_MODE:
        if shutil.which("docker") is None:
            pytest.skip("docker not available for the MinIO backend")
        p = subprocess.run(["bash", os.path.join(HERE, "minio_harness.sh"),
                            "start"],
                           env={**os.environ, "MINIO_PORT": str(MINIO_PORT)},
                           capture_output=True, text=True)
        if p.returncode == 3:
            pytest.skip("docker daemon not usable for the MinIO backend")
        if p.returncode != 0:
            pytest.fail(f"[backend] MinIO container failed to start: "
                        f"{p.stderr[-400:]}")
    if not _wait_port(MINIO_HOST, MINIO_PORT):
        pytest.fail(f"[backend] MinIO not reachable on "
                    f"{MINIO_HOST}:{MINIO_PORT}")
    r = minio_request("PUT", f"/{BUCKET}")          # idempotent bucket create
    if r.status_code not in (200, 409):
        pytest.fail(f"[backend] bucket create failed: {r.status_code} "
                    f"{r.text[:200]}")
    ok, detail = _backend_healthy()
    if not ok:
        pytest.fail(f"[backend] MinIO direct roundtrip failed: {detail}")
    return {"host": MINIO_HOST, "port": MINIO_PORT}


def _fwd_conf(port, minio_port, root, logs, secret_key):
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
            dav_methods PUT DELETE;
            brix_webdav on;
            brix_webdav_auth none;
            brix_export {root};
            brix_storage_backend s3://127.0.0.1:{minio_port}/{BUCKET};
            brix_storage_credential minio;
            brix_allow_write on;
        }}
    }}
}}
"""


def _stream_conf(port, minio_port, root, logs, secret_key):
    """root:// front, same MinIO backend, STATIC brix_storage_credential —
    the exact posture bug 1.1 broke (worker-init credential replay wiped the
    parse-time S3 keys; P80.1 regression lane)."""
    return f"""
daemon on;
error_log {logs}/error.log info;
pid {logs}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential minio {{
        s3_access_key {MINIO_AK};
        s3_secret_key {secret_key};
        s3_region {REGION};
    }}
    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_export {root};
        brix_storage_backend s3://127.0.0.1:{minio_port}/{BUCKET};
        brix_storage_credential minio;
    }}
}}
"""


def _start_nginx(port, minio_port, secret_key, tag, conf_fn=_fwd_conf):
    base = tempfile.mkdtemp(prefix=f"minio_fwd_{tag}.")
    for d in ("root", "logs"):
        os.makedirs(os.path.join(base, d), exist_ok=True)
    conf = os.path.join(base, "nginx.conf")
    with open(conf, "w") as f:
        f.write(conf_fn(port, minio_port, os.path.join(base, "root"),
                        os.path.join(base, "logs"), secret_key))
    p = subprocess.run([NGINX_BIN, "-p", base, "-c", conf],
                       capture_output=True, text=True)
    return base, p


def _stop_nginx(base):
    pidfile = os.path.join(base, "logs", "nginx.pid")
    try:
        with open(pidfile) as f:
            os.kill(int(f.read().strip()), signal.SIGKILL)
    except (OSError, ValueError):
        pass
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture(scope="module")
def brix_fwd(minio):
    """The brix forwarding node (correct credentials)."""
    if REMOTE_MODE:
        if not FWD_PORT_ENV:
            pytest.skip("remote mode: TEST_S3FWD_PORT not set")
        port = int(FWD_PORT_ENV)
        if not _wait_port(FWD_HOST, port):
            pytest.fail(f"[brix-machinery] s3-forward node not reachable on "
                        f"{FWD_HOST}:{port}")
        yield {"host": FWD_HOST, "port": port}
        return
    (port,) = free_ports(1)
    base, p = _start_nginx(port, minio["port"], MINIO_SK, "ok")
    if p.returncode != 0:
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] nginx rejected the s3-forwarding "
                    f"config (directive/parse problem): {p.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        err = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] forwarding node never listened: {err}")
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)


def _tail(path, n=600):
    try:
        with open(path) as f:
            return f.read()[-n:]
    except OSError:
        return "(no error.log)"


def _brix_url(node, key):
    return f"http://{node['host']}:{node['port']}/{key}"


# --------------------------------------------------------------------------
# Tests — success (both directions), error, security-negative
# --------------------------------------------------------------------------

class TestMinioS3Forward:

    def test_backend_direct_roundtrip(self, minio):
        """Leg 0: the backend is known-working, proven without brix."""
        body = os.urandom(2048)
        r = minio_request("PUT", f"/{BUCKET}/direct.bin", body)
        assert r.status_code == 200, f"[backend] direct PUT {r.status_code}"
        r = minio_request("GET", f"/{BUCKET}/direct.bin")
        assert r.status_code == 200 and r.content == body, \
            "[backend] direct GET roundtrip failed"

    def test_download_through_brix(self, minio, brix_fwd):
        """Object seeded directly into MinIO is served through brix
        (forwarded signed range-GET read)."""
        body = os.urandom(300_000)
        r = minio_request("PUT", f"/{BUCKET}/seeded.bin", body)
        assert r.status_code == 200, f"[backend] seed PUT {r.status_code}"
        r = requests.get(_brix_url(brix_fwd, "seeded.bin"), timeout=30)
        if r.status_code != 200:
            attribute_failure(f"GET through brix returned {r.status_code}")
        if _sha256(r.content) != _sha256(body):
            attribute_failure("GET through brix returned corrupted bytes")

    def test_upload_through_brix(self, minio, brix_fwd):
        """PUT through brix lands in MinIO byte-exact (staged whole-object
        upload signed with the forwarded credential)."""
        body = os.urandom(300_000)
        r = requests.put(_brix_url(brix_fwd, "uploaded.bin"), data=body,
                         timeout=30)
        if r.status_code not in (200, 201, 204):
            attribute_failure(f"PUT through brix returned {r.status_code}")
        r = minio_request("GET", f"/{BUCKET}/uploaded.bin")
        if r.status_code != 200:
            attribute_failure(f"object PUT via brix absent from MinIO "
                              f"(direct GET {r.status_code})")
        if _sha256(r.content) != _sha256(body):
            attribute_failure("object PUT via brix is corrupted in MinIO")

    def test_missing_object_maps_to_404(self, minio, brix_fwd):
        """Error leg: upstream NoSuchKey must surface as 404 (ENOENT
        mapping), not a 5xx machinery error."""
        r = requests.get(_brix_url(brix_fwd, "no-such-object.bin"),
                         timeout=30)
        if r.status_code >= 500:
            attribute_failure(f"missing object returned {r.status_code} "
                              f"instead of 404")
        assert r.status_code == 404, \
            f"expected 404 for a missing object, got {r.status_code}"

    def test_wrong_credentials_are_rejected_upstream(self, minio):
        """Security-negative: with a bad secret the forwarded requests must
        FAIL — proving the SigV4 credential is load-bearing, i.e. brix is
        genuinely authenticating to the backend and not falling back to an
        anonymous or cached path."""
        if REMOTE_MODE:
            pytest.skip("wrong-cred instance is launched locally only")
        (port,) = free_ports(1)
        base, p = _start_nginx(port, MINIO_PORT,
                               "definitely-wrong-secret", "bad")
        if p.returncode != 0:
            _stop_nginx(base)
            pytest.fail(f"[brix-machinery] wrong-cred config rejected at "
                        f"parse time: {p.stderr[-300:]}")
        try:
            assert _wait_port("127.0.0.1", port), \
                "[brix-machinery] wrong-cred node never listened"
            body = os.urandom(4096)
            r = requests.put(f"http://127.0.0.1:{port}/forged.bin",
                             data=body, timeout=30)
            assert r.status_code >= 400, \
                (f"SECURITY: PUT with a wrong backend secret succeeded "
                 f"({r.status_code}) — credential is not being forwarded")
            g = minio_request("GET", f"/{BUCKET}/forged.bin")
            assert g.status_code == 404, \
                "SECURITY: object written to MinIO despite a bad credential"
            r = requests.get(f"http://127.0.0.1:{port}/direct.bin",
                             timeout=30)
            assert r.status_code >= 400, \
                (f"SECURITY: GET with a wrong backend secret succeeded "
                 f"({r.status_code})")
        finally:
            _stop_nginx(base)


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
        body = os.urandom(200_000)
        src = tmp_path / "stream_up.bin"
        src.write_bytes(body)
        p = _xrdcp(str(src), _root_url(brix_stream, "stream_up.bin"))
        if p.returncode != 0:
            attribute_failure(f"stream PUT (xrdcp) failed: "
                              f"{(p.stderr or p.stdout)[-300:]}")
        r = minio_request("GET", f"/{BUCKET}/stream_up.bin")
        if r.status_code != 200:
            attribute_failure(f"stream-uploaded object absent from MinIO "
                              f"(direct GET {r.status_code})")
        assert _sha256(r.content) == _sha256(body), \
            "[brix-machinery] stream upload corrupted in MinIO"

        seed = os.urandom(150_000)
        r = minio_request("PUT", f"/{BUCKET}/stream_seed.bin", seed)
        assert r.status_code == 200, f"[backend] seed PUT {r.status_code}"
        dst = tmp_path / "stream_down.bin"
        p = _xrdcp(_root_url(brix_stream, "stream_seed.bin"), str(dst))
        if p.returncode != 0:
            attribute_failure(f"stream GET (xrdcp) failed: "
                              f"{(p.stderr or p.stdout)[-300:]}")
        assert _sha256(dst.read_bytes()) == _sha256(seed), \
            "[brix-machinery] stream download corrupted"

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
    if REMOTE_MODE:
        pytest.skip("resume-divert lane is launched locally only")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip("xrdcp not available for the stream lane")
    (port,) = free_ports(1)
    base, p = _start_nginx(port, minio["port"], MINIO_SK, "stream_resume",
                           conf_fn=_stream_resume_conf)
    if p.returncode != 0:
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] nginx rejected the resume-on stream s3 "
                    f"config: {p.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        err = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        pytest.fail(f"[brix-machinery] resume-on stream node never listened: "
                    f"{err}")
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


class TestStagedWriteResidue:

    def test_resume_divert_upload_lands_in_minio(self, minio,
                                                 brix_stream_resume,
                                                 tmp_path):
        """Success: with brix_upload_resume on, an upload to the staged-only
        backend is transparently diverted through the staged seam — the object
        lands byte-exact in MinIO and NO bytes strand in the local skeleton."""
        body = os.urandom(200_000)
        src = tmp_path / "resume_up.bin"
        src.write_bytes(body)
        p = _xrdcp(str(src), _root_url(brix_stream_resume, "resume_up.bin"))
        if p.returncode != 0:
            attribute_failure(f"resume-divert PUT (xrdcp) failed: "
                              f"{(p.stderr or p.stdout)[-300:]}")
        r = minio_request("GET", f"/{BUCKET}/resume_up.bin")
        if r.status_code != 200:
            attribute_failure(f"resume-divert upload absent from MinIO "
                              f"(direct GET {r.status_code}) — bytes likely "
                              f"stranded in the local resume skeleton")
        assert _sha256(r.content) == _sha256(body), \
            "[brix-machinery] resume-divert upload corrupted in MinIO"
        residue = _skeleton_residue(brix_stream_resume["base"])
        assert not residue, \
            f"[brix-machinery] resume left byte residue in the local " \
            f"skeleton (divert failed): {residue}"

    def test_mpu_boundary_upload_byte_exact(self, minio, brix_stream_resume,
                                            tmp_path):
        """Error-boundary: a >16MiB upload crosses SD_REMOTE_PART_SIZE, forcing
        the lazy single-PUT buffer to upgrade to a multipart upload mid-stream.
        Byte-exact roundtrip, and no incomplete MPU left behind."""
        body = os.urandom(20 * 1024 * 1024)
        src = tmp_path / "mpu_up.bin"
        src.write_bytes(body)
        p = _xrdcp(str(src), _root_url(brix_stream_resume, "mpu_up.bin"),
                   timeout=120)
        if p.returncode != 0:
            attribute_failure(f"MPU-boundary PUT (xrdcp) failed: "
                              f"{(p.stderr or p.stdout)[-300:]}")
        r = minio_request("GET", f"/{BUCKET}/mpu_up.bin", timeout=60)
        if r.status_code != 200:
            attribute_failure(f"MPU-boundary upload absent from MinIO "
                              f"(direct GET {r.status_code})")
        assert _sha256(r.content) == _sha256(body), \
            "[brix-machinery] MPU-boundary upload corrupted in MinIO"
        r = minio_request("GET", f"/{BUCKET}?uploads=")
        assert r.status_code == 200 and b"mpu_up.bin" not in r.content, \
            "[brix-machinery] incomplete multipart upload left behind"

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


# --------------------------------------------------------------------------
# P80.3 — per-user backend credentials for WRITES + metadata (sd_remote).
# staged_open_cred/stat_cred/unlink_cred registration means an authenticated
# principal's <user>.s3 file signs the staged upload (and its noreplace HEAD),
# never the shared static credential. pwd auth supplies a cheap local
# authenticated principal (identity DN = username → cred key = username).
# --------------------------------------------------------------------------

REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

PWD_ALICE = "alice"
PWD_BOB = "bob"
PWD_PASSWORD = "s3cret-pw"


def _pwd_db_line(user, password):
    salt = os.urandom(8)
    h = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 24)
    return f"{user}:{salt.hex()}:{h.hex()}"


def _pwd_ucred_conf(pwd_file, cred_dir):
    """Conf factory: pwd-authenticated root:// front whose STATIC credential
    is deliberately wrong — only the per-user cred dir can sign correctly."""
    def conf(port, minio_port, root, logs, secret_key):
        return f"""
daemon on;
error_log {logs}/error.log info;
pid {logs}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential minio {{
        s3_access_key {MINIO_AK};
        s3_secret_key {secret_key};
        s3_region {REGION};
    }}
    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_auth pwd;
        brix_pwd_file {pwd_file};
        brix_allow_write on;
        brix_upload_resume off;
        brix_export {root};
        brix_storage_backend s3://127.0.0.1:{minio_port}/{BUCKET};
        brix_storage_credential minio;
        brix_storage_credential_dir {cred_dir};
        brix_storage_credential_fallback deny;
    }}
}}
"""
    return conf


def _xrdcp_pwd(user, src, dst, timeout=60):
    env = {**os.environ,
           "XRDC_PWD": PWD_PASSWORD,
           "XRDC_PWD_USER": user,
           "XRD_CONNECTIONRETRY": "1",
           "XRD_REQUESTTIMEOUT": "30",
           "XRD_STREAMTIMEOUT": "30"}
    env.pop("XrdSecCREDS", None)
    return subprocess.run([NATIVE_XRDCP, "--auth", "pwd", "-f", src, dst],
                          capture_output=True, text=True,
                          timeout=timeout, env=env)


@pytest.fixture(scope="module")
def brix_ucred(minio):
    """pwd-auth root:// front: wrong static secret, per-user cred dir with
    alice.s3 = the real MinIO keys, no bob.s3, fallback deny."""
    if REMOTE_MODE:
        pytest.skip("per-user cred lane is launched locally only")
    if not os.access(NATIVE_XRDCP, os.X_OK):
        pytest.skip("native xrdcp (client/bin/xrdcp) not available")
    aux = tempfile.mkdtemp(prefix="minio_fwd_ucred_aux.")
    pwd_file = os.path.join(aux, "pwd.db")
    with open(pwd_file, "w") as f:
        f.write(_pwd_db_line(PWD_ALICE, PWD_PASSWORD) + "\n")
        f.write(_pwd_db_line(PWD_BOB, PWD_PASSWORD) + "\n")
    cred_dir = os.path.join(aux, "creds")
    os.makedirs(cred_dir, exist_ok=True)
    with open(os.path.join(cred_dir, f"{PWD_ALICE}.s3"), "w") as f:
        f.write(f"{MINIO_AK}\n{MINIO_SK}\n{REGION}\n")
    os.chmod(os.path.join(cred_dir, f"{PWD_ALICE}.s3"), 0o600)

    (port,) = free_ports(1)
    base, p = _start_nginx(port, minio["port"], WRONG_SECRET, "ucred",
                           conf_fn=_pwd_ucred_conf(pwd_file, cred_dir))
    if p.returncode != 0:
        _stop_nginx(base)
        shutil.rmtree(aux, ignore_errors=True)
        pytest.fail(f"[brix-machinery] nginx rejected the per-user-cred "
                    f"config: {p.stderr[-500:]}")
    if not _wait_port("127.0.0.1", port):
        err = _tail(os.path.join(base, "logs", "error.log"))
        _stop_nginx(base)
        shutil.rmtree(aux, ignore_errors=True)
        pytest.fail(f"[brix-machinery] per-user-cred node never listened: "
                    f"{err}")
    yield {"host": "127.0.0.1", "port": port, "base": base}
    _stop_nginx(base)
    shutil.rmtree(aux, ignore_errors=True)


class TestPerUserWriteCredential:

    def test_alice_upload_signed_with_her_credential(self, minio, brix_ucred,
                                                     tmp_path):
        """Success: the static credential is WRONG, so the upload can only
        land if alice's per-user .s3 triple signed the staged write (and its
        noreplace probe). Byte-exact in MinIO proves staged_open_cred ran."""
        body = os.urandom(150_000)
        src = tmp_path / "alice_up.bin"
        src.write_bytes(body)
        p = _xrdcp_pwd(PWD_ALICE, str(src),
                       _root_url(brix_ucred, "alice_up.bin"))
        if p.returncode != 0:
            err = _tail(os.path.join(brix_ucred["base"], "logs", "error.log"))
            attribute_failure(f"alice per-user-cred PUT failed: "
                              f"{(p.stderr or p.stdout)[-300:]} / log: {err}")
        r = minio_request("GET", f"/{BUCKET}/alice_up.bin")
        if r.status_code != 200:
            attribute_failure(f"alice's upload absent from MinIO (direct GET "
                              f"{r.status_code}) — per-user credential did "
                              f"not sign the staged write")
        assert _sha256(r.content) == _sha256(body), \
            "[brix-machinery] alice's per-user-cred upload corrupted in MinIO"

    def test_bob_without_credential_is_refused(self, minio, brix_ucred,
                                               tmp_path):
        """Error: bob authenticates fine but has no bob.s3 and fallback is
        deny — the write must fail and nothing may reach MinIO (the wrong
        static credential must NOT be used as a fallback)."""
        src = tmp_path / "bob_up.bin"
        src.write_bytes(os.urandom(4096))
        p = _xrdcp_pwd(PWD_BOB, str(src), _root_url(brix_ucred, "bob_up.bin"))
        assert p.returncode != 0, \
            "SECURITY: bob's upload succeeded without a per-user credential " \
            "under fallback=deny"
        r = minio_request("GET", f"/{BUCKET}/bob_up.bin")
        assert r.status_code == 404, \
            f"SECURITY: bob's refused upload reached MinIO anyway " \
            f"(GET {r.status_code})"

    def test_deny_is_logged_and_secret_never_leaks(self, brix_ucred):
        """Security-negative: the refusal is an auditable deny (needle from
        vfs_cred.c) and alice's per-user secret never appears in any log."""
        log = _tail(os.path.join(brix_ucred["base"], "logs", "error.log"),
                    n=200_000)
        assert "(fallback=deny) - refusing" in log, \
            "[brix-machinery] per-user deny left no auditable log line"
        assert PWD_BOB in log, \
            "[brix-machinery] deny log does not name the refused principal"
        assert MINIO_SK not in log, \
            "SECURITY: per-user secret key leaked into error.log"
