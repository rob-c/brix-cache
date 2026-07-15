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

from settings import NGINX_BIN, free_ports

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
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical = (f"{method}\n{path}\n\nhost:{host_hdr}\n"
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


def _start_nginx(port, minio_port, secret_key, tag):
    base = tempfile.mkdtemp(prefix=f"minio_fwd_{tag}.")
    for d in ("root", "logs"):
        os.makedirs(os.path.join(base, d), exist_ok=True)
    conf = os.path.join(base, "nginx.conf")
    with open(conf, "w") as f:
        f.write(_fwd_conf(port, minio_port, os.path.join(base, "root"),
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
