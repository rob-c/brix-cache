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

Run (opt-out): runs by default whenever a container runtime (docker OR rootless
podman — see cmdscripts.container_runtime) + a minio image are present and the
nginx objects are built; force-skip with STS_MINIO_LIVE=0, or pin the runtime
with $BRIX_CONTAINER_RUNTIME. Runtime-direct (no fleet server), mirroring
test_ceph_live.py — not a TEST_REGISTRY suite.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pytest

from cmdscripts.c_auth_units import NGX_SRC, OBJS, find_obj, pkg_config
from cmdscripts.compile_run import REPO_ROOT, run
from cmdscripts.container_runtime import container_runtime
from settings import HOST         # env-overridable host (the sanctioned idiom)

# `slow`: this lab now actually RUNS wherever a container runtime is present
# (docker OR rootless podman — see cmdscripts.container_runtime); it stands up a
# real MinIO on a fixed port, so it belongs in the nightly/full tier, not the
# minutes-long `-m "not slow"` PR gate. (Before the podman seam it silently
# skipped on the docker-only gate, so no marker was needed.)
pytestmark = [pytest.mark.timeout(300), pytest.mark.slow]

# A minio image is present locally under one of these tags (see `docker images`).
MINIO_IMAGES = (
    "quay.io/minio/minio:latest",
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

# The production TUs the harness links (same objects the module build produced).
STS_OBJS = ["sts.o", "sts_sign.o", "sts_http.o", "crypto.o", "sigv4.o"]


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

def _pick_image(runtime: str) -> str | None:
    listed = run([runtime, "images", "--format", "{{.Repository}}:{{.Tag}}"],
                 cwd=REPO_ROOT)
    tags = set(listed.stdout.split())
    for img in MINIO_IMAGES:
        if img in tags:
            return img
    return None


def _build_harness(dst: Path) -> tuple[Path | None, str]:
    """Compile tests/c/sts_live_assume.c against the prebuilt production objects.
    Returns (binary, "") on success, or (None, reason) to skip."""
    objs = [find_obj(n) for n in STS_OBJS]
    missing = [n for n, o in zip(STS_OBJS, objs) if o is None]
    if missing:
        return None, f"build nginx first (missing {' '.join(missing)})"
    ngx_string = OBJS / "src/core/ngx_string.o"
    if not ngx_string.exists():
        return None, "build nginx first (ngx_string.o)"
    binary = dst / "sts_live_assume"
    cmd = [
        "gcc", "-O", "-Wall",
        "-I", "src",
        "-I", str(NGX_SRC / "src/core"),
        "-I", str(NGX_SRC / "src/event"),
        "-I", str(NGX_SRC / "src/os/unix"),
        "-I", str(OBJS),
        *pkg_config(["--cflags", "libxml-2.0"]),
        "tests/c/sts_live_assume.c",
        *[str(o) for o in objs],
        str(ngx_string),
        *pkg_config(["--libs", "libxml-2.0"], ["-lxml2"]),
        *pkg_config(["--libs", "libcurl"], ["-lcurl"]),
        "-lcrypto",
        "-o", str(binary),
    ]
    built = run(cmd, cwd=REPO_ROOT, env={"TMPDIR": "/tmp"})
    if built.returncode != 0:
        return None, f"harness compile failed: {(built.stderr or built.stdout)[-2000:]}"
    return binary, ""


@pytest.fixture(scope="module")
def minio_sts_lab(tmp_path_factory):
    if os.environ.get("STS_MINIO_LIVE") == "0":
        pytest.skip("STS_MINIO_LIVE=0 set — skipping the live MinIO STS lab")
    runtime = container_runtime()
    if runtime is None:
        pytest.skip("no working container runtime (docker or rootless podman)")
    image = _pick_image(runtime)
    if image is None:
        pytest.skip("no local minio image (expected one of: "
                    + ", ".join(MINIO_IMAGES) + ")")

    harness, reason = _build_harness(tmp_path_factory.mktemp("sts_harness"))
    if harness is None:
        pytest.skip(reason)

    cid = run(
        [runtime, "run", "-d", "--rm", "-p", f"{PORT}:9000",
         "-e", f"MINIO_ROOT_USER={ROOT_USER}",
         "-e", f"MINIO_ROOT_PASSWORD={ROOT_PW}",
         image, "server", "/data"],
        cwd=REPO_ROOT,
    ).stdout.strip()
    if not cid:
        pytest.skip("failed to launch minio container")

    try:
        healthy = False
        for _ in range(80):
            try:
                if _http("GET", f"{ENDPOINT}/minio/health/live", {})[0] == 200:
                    healthy = True
                    break
            except OSError:
                pass
            time.sleep(0.5)
        assert healthy, "MinIO never became healthy"

        uri, hdr = _sign_put(ROOT_USER, ROOT_PW, BUCKET, "", b"")
        assert _http("PUT", ENDPOINT + uri, hdr, b"")[0] == 200, "bucket create"
        uri, hdr = _sign_put(ROOT_USER, ROOT_PW, BUCKET, KEY, BODY)
        assert _http("PUT", ENDPOINT + uri, hdr, BODY)[0] == 200, "object put"

        yield harness
    finally:
        run([runtime, "rm", "-f", cid], cwd=REPO_ROOT)


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
