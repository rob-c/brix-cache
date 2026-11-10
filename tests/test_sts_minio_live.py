"""Live MinIO STS origin-leg conformance (phase-70 §5.5, MinIO dialect).

The offline unit (sts_units in test_c_auth_units.py) proves the header-auth POST
builder emits byte-stable, correctly-scoped SigV4 over a real crypto/formatter
link. THIS suite closes the loop the unit cannot: it stands up a real MinIO,
drives an AssumeRole exchange through the PRODUCTION brix_s3_sts_assume() code
(flavor=MINIO) via a thin C harness, and then proves the *returned* temporary
credentials actually authenticate an S3 GET at that same MinIO — the exact
end-to-end the AWS-dialect path could never satisfy against MinIO (MinIO speaks
only POST + form-body + header-auth AssumeRole, never GET/presigned).

Ritual:
  success  — AssumeRole returns a usable (ak, sk, session) triple and a
             token-folded GET fetches the seeded object byte-for-byte;
  security — the same GET WITHOUT the session token is rejected (403);
             an AssumeRole signed with a wrong service secret fails closed.

Run (opt-out): uses a local container image or a native MinIO binary and the
configured nginx SDK. Force-skip with STS_MINIO_LIVE=0; select a native binary
explicitly with BRIX_MINIO_BIN. Explicit BRIX_CONTAINER_RUNTIME/BRIX_MINIO_IMAGE
selections remain authoritative and never silently select the native service.
The native service binds only the test host, uses private disposable data and
is stopped through its owned Popen handle. No installed service is changed.
"""

from __future__ import annotations

import datetime as dt
from contextlib import contextmanager
import hashlib
import hmac
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pytest

from cmdscripts.c_auth_units import NGX_SRC, pkg_config
from cmdscripts.compile_run import REPO_ROOT, run
from cmdscripts.container_runtime import container_runtime
from brix_suite.launcher.internal_operations import _port_released
from test_platform_linux_native import native_compile
from settings import HOST         # env-overridable host (the sanctioned idiom)

# `slow`: this lab now actually RUNS wherever a container runtime is present
# (docker OR rootless podman — see cmdscripts.container_runtime); it stands up a
# real MinIO on a fixed port, so it belongs in the nightly/full tier, not the
# minutes-long `-m "not slow"` PR gate. (Before the podman seam it silently
# skipped on the docker-only gate, so no marker was needed.)

def _guard_minio_sts_lab_1():
    if os.environ.get("STS_MINIO_LIVE") == "0":
        pytest.skip("STS_MINIO_LIVE=0 set — skipping the live MinIO STS lab")

def _guard_minio_sts_lab_2(runtime):
    if runtime is None:
        pytest.skip("no working container runtime (docker or rootless podman)")

def _guard_minio_sts_lab_3(image):
    if image is None:
        pytest.skip("no local minio image (expected one of: "
                    + ", ".join(_minio_images()) + ")")

def _guard_minio_sts_lab_5(cid):
    if not cid:
        pytest.skip("failed to launch minio container")

def _check_minio_sts_lab_1(healthy):
    assert healthy, "MinIO never became healthy"

def _check_minio_sts_lab_2(hdr, uri):
    assert _http("PUT", ENDPOINT + uri, hdr, b"")[0] == 200, "bucket create"

def _check_minio_sts_lab_3(hdr, uri):
    assert _http("PUT", ENDPOINT + uri, hdr, BODY)[0] == 200, "object put"


# The module-scoped oracle owns one fixed port and must stay on one worker.
pytestmark = [pytest.mark.timeout(300), pytest.mark.slow,
              pytest.mark.xdist_group("sts-minio")]

# A minio image is present locally under one of these tags (see `docker images`).
MINIO_IMAGES = (
    "quay.io/minio/minio:latest",
    "docker.io/minio/minio:latest",
    "minio/minio:latest",
)
ROOT_USER = "brixroot"
ROOT_PW = "brixrootpw123"
BAD_PW = "wrong-service-secret-xxxxxxxx"
PORT = 19922                      # fixed, high, runtime-direct (no fleet port)
REGION = "us-east-1"
BUCKET = "stsbucket"
KEY = "obj/hello.txt"
BODY = b"phase-70 sts origin leg live proof\n"
ENDPOINT = f"http://{HOST}:{PORT}"

# ---- minimal SigV4 (test-side verifier; independent of the code under test) --

def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = hmac.new(("AWS4" + secret).encode(), datestamp.encode(), hashlib.sha256).digest()
    for part in (region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return k


def _now() -> tuple[str, str]:
    n = dt.datetime.now(dt.timezone.utc)
    return n.strftime("%Y%m%dT%H%M%SZ"), n.strftime("%Y%m%d")


def _http(method: str, url: str, headers: dict, body: bytes | None = None):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _sign_put(ak: str, sk: str, bucket: str, key: str, body: bytes):
    amzdate, datestamp = _now()
    host = f"{HOST}:{PORT}"
    payload = _sha(body)
    uri = f"/{bucket}/{quote(key, safe='/')}" if key else f"/{bucket}"
    signed = "host;x-amz-content-sha256;x-amz-date"
    canon = (f"PUT\n{uri}\n\nhost:{host}\nx-amz-content-sha256:{payload}\n"
             f"x-amz-date:{amzdate}\n\n{signed}\n{payload}")
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{_sha(canon.encode())}"
    sig = hmac.new(_signing_key(sk, datestamp, REGION, "s3"),
                   to_sign.encode(), hashlib.sha256).hexdigest()
    return uri, {
        "Host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}"),
    }


def _sign_get(ak: str, sk: str, session: str | None, bucket: str, key: str):
    """Token-folded GET in the exact sd_s3_sign_ex canonical form: UNSIGNED
    payload, x-amz-security-token folded LAST (after x-amz-date)."""
    amzdate, datestamp = _now()
    host = f"{HOST}:{PORT}"
    payload = "UNSIGNED-PAYLOAD"
    uri = f"/{bucket}/{quote(key, safe='/')}"
    st_canon = f"x-amz-security-token:{session}\n" if session else ""
    st_signed = ";x-amz-security-token" if session else ""
    signed = f"host;x-amz-content-sha256;x-amz-date{st_signed}"
    canon = (f"GET\n{uri}\n\nhost:{host}\nx-amz-content-sha256:{payload}\n"
             f"x-amz-date:{amzdate}\n{st_canon}\n{signed}\n{payload}")
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{_sha(canon.encode())}"
    sig = hmac.new(_signing_key(sk, datestamp, REGION, "s3"),
                   to_sign.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}"),
    }
    if session:
        headers["x-amz-security-token"] = session
    return uri, headers


# ---- lab discovery / lifecycle -------------------------------------------

def _minio_images() -> tuple[str, ...]:
    """An explicit image selection is authoritative, never a fallback hint."""
    requested = os.environ.get("BRIX_MINIO_IMAGE")
    return (requested,) if requested else MINIO_IMAGES


def _pick_image(runtime: str) -> str | None:
    listed = run([runtime, "images", "--format", "{{.Repository}}:{{.Tag}}"],
                 cwd=REPO_ROOT)
    if listed.returncode != 0:
        return None
    tags = set(listed.stdout.split())
    for img in _minio_images():
        if img in tags:
            return img
    return None


def _native_minio_binary() -> str | None:
    """An explicit binary must exist; a bad pin cannot silently use PATH."""
    requested = os.environ.get("BRIX_MINIO_BIN")
    found = shutil.which(requested or "minio")
    if requested and found is None:
        raise RuntimeError("BRIX_MINIO_BIN is not an executable binary")
    return found


@contextmanager
def _native_minio(binary, root, port=PORT):
    """Start only our private child; never stop an existing port occupant."""
    if not _port_released(HOST, port):
        raise RuntimeError("native MinIO test endpoint is already occupied")
    data, certs = root / "data", root / "certs"
    data.mkdir()
    certs.mkdir()
    environment = {**os.environ, "MINIO_ROOT_USER": ROOT_USER,
        "MINIO_ROOT_PASSWORD": ROOT_PW, "MINIO_BROWSER": "off",
        "MINIO_UPDATE": "off"}
    command = [binary, "server", "--address", f"{HOST}:{port}",
               "--certs-dir", str(certs), "--json", "--anonymous", str(data)]
    with (root / "minio.log").open("wb") as log:
        process = subprocess.Popen(command, env=environment, stdout=log, stderr=log)
        try:
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _selected_native_minio():
    """Prefer native availability but never override a container pin."""
    container_pin = any(os.environ.get(key) for key in (
        "BRIX_CONTAINER_RUNTIME", "BRIX_MINIO_IMAGE"))
    if os.environ.get("BRIX_MINIO_BIN") and container_pin:
        raise RuntimeError("select either native MinIO or a container, not both")
    return None if container_pin else _native_minio_binary()


@contextmanager
def _minio_service(root, port=PORT):
    """Use one owned service, preserving explicit selection errors."""
    binary = _selected_native_minio()
    if binary:
        with _native_minio(binary, root, port) as process:
            yield process
        return
    with _container_minio(port):
        yield None


@contextmanager
def _container_minio(port=PORT):
    """Keep the existing local-image oracle when native execution is absent."""
    runtime = container_runtime()
    _guard_minio_sts_lab_2(runtime)
    image = _pick_image(runtime)
    _guard_minio_sts_lab_3(image)
    result = run([runtime, "run", "-d", "--rm", "-p", f"{HOST}:{port}:9000",
        "-e", f"MINIO_ROOT_USER={ROOT_USER}",
        "-e", f"MINIO_ROOT_PASSWORD={ROOT_PW}", image, "server", "/data"], cwd=REPO_ROOT)
    assert result.returncode == 0, "MinIO container launch failed"
    cid = result.stdout.strip()
    _guard_minio_sts_lab_5(cid)
    try:
        yield None
    finally:
        run([runtime, "rm", "-f", cid], cwd=REPO_ROOT)


def _wait_minio(process, endpoint=ENDPOINT):
    """A dead native child cannot borrow an unrelated service's health proof."""
    for _ in range(80):
        if process is not None and process.poll() is not None:
            raise RuntimeError("native MinIO exited during readiness; see minio.log")
        try:
            if _http("GET", f"{endpoint}/minio/health/live", {})[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    _check_minio_sts_lab_1(False)


@pytest.fixture(scope="module")
def sts_harness(native_compile):
    """Compile the real STS and DNS closure; compilation failures are errors."""
    sources = [
        "src/auth/s3/sts.c", "src/auth/s3/sts_sign.c", "src/auth/s3/sts_http.c",
        "src/core/compat/crypto.c", "src/core/compat/sigv4.c",
        "src/net/dns/curl_pin.c", "src/net/dns/resolve.c",
        "src/net/dns/resolve_thread.c", "src/core/compat/net_target_parse.c",
        "src/core/compat/net_target_policy.c",
        "src/core/compat/host_format.c", "tests/c/sts_live_dns_runtime.c",
        str(NGX_SRC / "src/core/ngx_string.c"),
        str(NGX_SRC / "src/core/ngx_inet.c"),
    ]
    libraries = ["openssl", "libcurl", "libxml-2.0"]
    flags = ["-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
             *pkg_config(["--cflags", *libraries]),
             *pkg_config(["--libs", *libraries]), "-pthread"]
    return native_compile(
        "sts-live-assume", (REPO_ROOT / "tests/c/sts_live_assume.c").read_text(),
        sources, flags, include_dirs=pkg_config(["--variable=includedir", "openssl"]),
    )


@pytest.mark.parametrize("url,expected", [
    ("http://localhost:19922/", 0),  # net-literal-allow: hostname must exercise real DNS rather than a literal-address shortcut
    ("http:///", 1),
    ("http://127.0.0.1@untrusted.invalid/", 1),  # net-literal-allow: hostile userinfo must be rejected before resolution
    ("https://[2001:db8::1]@127.0.0.1:19922/private", 1),  # net-literal-allow: bracket/userinfo decoy must never retarget curl to loopback
])
def test_standalone_sts_uses_the_real_dns_pin(sts_harness, url, expected):
    """Real name resolution works; malformed and userinfo URLs are refused."""
    result = subprocess.run([str(sts_harness), "--dns-probe", url],
                            capture_output=True, timeout=15)
    assert result.returncode == expected, result.stderr


@pytest.fixture(scope="module")
def minio_sts_lab(sts_harness, tmp_path_factory):
    _guard_minio_sts_lab_1()
    with _minio_service(tmp_path_factory.mktemp("sts-minio-native")) as process:
        _wait_minio(process)
        uri, hdr = _sign_put(ROOT_USER, ROOT_PW, BUCKET, "", b"")
        _check_minio_sts_lab_2(hdr, uri)
        uri, hdr = _sign_put(ROOT_USER, ROOT_PW, BUCKET, KEY, BODY)
        _check_minio_sts_lab_3(hdr, uri)
        yield sts_harness


def _assume(harness: Path, secret: str) -> subprocess.CompletedProcess:
    return run([str(harness), ENDPOINT, ROOT_USER, secret, REGION],
               cwd=REPO_ROOT, env={"TMPDIR": "/tmp"})


# ---- tests ----------------------------------------------------------------

def test_minio_assume_role_then_token_get(minio_sts_lab):
    """Production brix_s3_sts_assume(flavor=MINIO) yields temp creds that
    actually authenticate an S3 GET of the seeded object, byte-for-byte."""
    proc = _assume(minio_sts_lab, ROOT_PW)
    assert proc.returncode == 0, f"AssumeRole failed: {proc.stdout}{proc.stderr}"
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 3, f"expected ak/sk/session, got: {lines!r}"
    ak, sk, session = lines
    assert ak and sk and session, "empty credential field"
    # MinIO's session token is a JWT — three dot-separated segments.
    assert session.count(".") == 2, "session token is not a JWT"

    uri, hdr = _sign_get(ak, sk, session, BUCKET, KEY)
    status, got = _http("GET", ENDPOINT + uri, hdr)
    assert status == 200, f"token-signed GET rejected: {status} {got[:200]!r}"
    assert got == BODY, "fetched object body mismatch"


def test_minio_temp_cred_requires_session_token(minio_sts_lab):
    """Security-negative: the same temp (ak, sk) WITHOUT the session token must
    be rejected — the token, not the key pair, carries the grant."""
    proc = _assume(minio_sts_lab, ROOT_PW)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    ak, sk, _session = proc.stdout.strip().splitlines()

    uri, hdr = _sign_get(ak, sk, None, BUCKET, KEY)
    status, _ = _http("GET", ENDPOINT + uri, hdr)
    assert status == 403, f"no-token GET must be 403, got {status}"


def test_minio_assume_role_wrong_secret_fails_closed(minio_sts_lab):
    """Security-negative: an AssumeRole signed with the wrong service secret is
    refused by MinIO and the client reports failure (no creds emitted)."""
    proc = _assume(minio_sts_lab, BAD_PW)
    assert proc.returncode != 0, "AssumeRole with a bad secret unexpectedly OK"
    assert "\n" not in proc.stdout.strip().strip("ERR"), \
        "no credential material must leak on failure"
