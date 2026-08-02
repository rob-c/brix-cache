"""End-to-end nginx-runtime S3-STS origin leg (phase-70 §5.5, the runtime "wire").

The offline unit proves the AssumeRole SigV4 builder; test_sts_minio_live proves
the production brix_s3_sts_assume() against a real MinIO in isolation.  THIS suite
closes the last gap named in phase-88-open-work-audit §4: the *runtime invocation*
that carries the STS-minted credential onto the outbound origin connection —
front-door capture -> VFS deleg gate -> sd_remote open — driven through a booted
root:// gateway.

Topology (all live, unprivileged):
  * a real MinIO (docker-direct, mirrors test_sts_minio_live) is BOTH the S3
    object store and the STS endpoint;
  * a booted nginx root:// gateway whose storage backend is that MinIO and whose
    `brix_backend_delegation exchange` mints a per-request origin credential via
    STS AssumeRole (flavor=minio);
  * a WLCG bearer authenticates at the front door (ztn), so the raw JWT is
    captured onto the session and the deleg gate engages.

THE DISCRIMINATOR: the gateway's static `brix_storage_credential` carries a
DELIBERATELY WRONG secret.  A byte-exact read can therefore ONLY be the
STS-minted temporary credential authenticating the origin GET — never the static
fallback.  That makes the positive test a true proof of the runtime STS wire.

Ritual (success + two fail-closed security-negatives):
  * exchange + correct STS service secret  -> read returns the seeded bytes
    (the STS temp cred, not the wrong static cred, authenticated the origin);
  * delegation OFF (select)                -> STS never engages, the wrong static
    cred is all that remains, the origin GET is refused, no bytes (proves the
    discriminator is honest — success above was NOT the static cred);
  * exchange + BROKEN STS service secret   -> AssumeRole is refused by MinIO, the
    EXCHANGE gate denies with no service-cred fallback, no bytes (fail-closed).

Run (opt-out): runs whenever docker + a minio image + the built nginx are
present; force-skip with STS_MINIO_LIVE=0.  Docker-direct (not a TEST_REGISTRY
suite), so serial.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import socket
import struct
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

# Reuse the proven MinIO lab primitives (docker discovery + SigV4 crypto) so the
# seeding path is identical to test_sts_minio_live and shares no drift surface.
from test_sts_minio_live import (
    MINIO_IMAGES,
    REGION,
    ROOT_PW,
    ROOT_USER,
    _have_docker,
    _http,
    _now,
    _pick_image,
    _sha,
    _signing_key,
)
from cmdscripts.compile_run import REPO_ROOT, run

# Adjust import path for the token issuer utility (mirrors test_token_auth.py).
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer

pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-sts-e2e")]

MINIO_PORT = 19924                # fixed high port, distinct from 19922
BUCKET = "stsrtbucket"
KEY = "hello.txt"                 # logical "/hello.txt" -> S3 key "hello.txt"
BODY = b"phase-70 sts runtime origin-leg proof\n"
WRONG_STATIC_SK = "deliberately-wrong-static-secret-not-the-real-one"
BAD_STS_SK = "wrong-sts-service-secret-xxxxxxxxxxxx"

ENDPOINT = f"http://{HOST}:{MINIO_PORT}"

# ---- root:// wire request/response IDs (host byte order) ------------------
kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_open     = 3010
kXR_read     = 3013
kXR_close    = 3003
kXR_ok       = 0
kXR_oksofar  = 4000
kXR_open_read = 0x0010


# ---- MinIO seeding (parametrised SigV4 PUT; endpoint-independent) ---------

def _sign_put_at(host_port: str, ak: str, sk: str, bucket: str, key: str,
                 body: bytes):
    """SigV4 PUT signer parametrised by authority (bucket-create when key='')."""
    amzdate, datestamp = _now()
    payload = _sha(body)
    uri = f"/{bucket}/{key}" if key else f"/{bucket}"
    signed = "host;x-amz-content-sha256;x-amz-date"
    canon = (f"PUT\n{uri}\n\nhost:{host_port}\nx-amz-content-sha256:{payload}\n"
             f"x-amz-date:{amzdate}\n\n{signed}\n{payload}")
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{_sha(canon.encode())}"
    sig = hmac.new(_signing_key(sk, datestamp, REGION, "s3"),
                   to_sign.encode(), hashlib.sha256).hexdigest()
    return uri, {
        "Host": host_port, "x-amz-date": amzdate,
        "x-amz-content-sha256": payload,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}"),
    }


# ---- lab lifecycle --------------------------------------------------------

@pytest.fixture(scope="module")
def minio_store():
    """A live MinIO (S3 + STS) seeded with one object; yields its authority."""
    if os.environ.get("STS_MINIO_LIVE") == "0":
        pytest.skip("STS_MINIO_LIVE=0 set — skipping the live MinIO STS lab")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if not _have_docker():
        pytest.skip("docker not available")
    image = _pick_image()
    if image is None:
        pytest.skip("no local minio image (expected one of: "
                    + ", ".join(MINIO_IMAGES) + ")")

    cid = run(
        ["docker", "run", "-d", "--rm", "-p", f"{MINIO_PORT}:9000",
         "-e", f"MINIO_ROOT_USER={ROOT_USER}",
         "-e", f"MINIO_ROOT_PASSWORD={ROOT_PW}",
         image, "server", "/data"],
        cwd=REPO_ROOT,
    ).stdout.strip()
    if not cid:
        pytest.skip("failed to launch minio container")

    host_port = f"{HOST}:{MINIO_PORT}"
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

        uri, hdr = _sign_put_at(host_port, ROOT_USER, ROOT_PW, BUCKET, "", b"")
        assert _http("PUT", ENDPOINT + uri, hdr, b"")[0] == 200, "bucket create"
        uri, hdr = _sign_put_at(host_port, ROOT_USER, ROOT_PW, BUCKET, KEY, BODY)
        assert _http("PUT", ENDPOINT + uri, hdr, BODY)[0] == 200, "object put"

        yield host_port
    finally:
        run(["docker", "rm", "-f", cid], cwd=REPO_ROOT)


@pytest.fixture(scope="module")
def token(tmp_path_factory):
    """A signed WLCG bearer + its JWKS dir (loaded by the gateway at startup)."""
    tdir = tmp_path_factory.mktemp("sts_e2e_tokens")
    issuer = TokenIssuer(str(tdir))
    issuer.init_keys()
    jwt = issuer.generate(sub="alice", scope="storage.read:/")
    return {"dir": str(tdir), "jwt": jwt}


@contextlib.contextmanager
def _gateway(minio_authority: str, token_dir: str, delegation: str, sts_sk: str):
    """Boot a root:// STS gateway variant; yields its client port."""
    minio_host, minio_port = minio_authority.split(":")
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="root-s3-sts",
        template="nginx_root_s3_sts.conf",
        protocol="root",
        readiness="tcp",
        template_values={
            "BIND_HOST": BIND_HOST,
            "TOKEN_DIR": token_dir,
            "MINIO_HOST": minio_host,
            "MINIO_PORT": minio_port,
            "BUCKET": BUCKET,
            "S3_AK": ROOT_USER,
            "S3_STATIC_SK": WRONG_STATIC_SK,
            "S3_STS_SK": sts_sk,
            "DELEGATION": delegation,
        },
    ))
    try:
        yield endpoint.port
    finally:
        harness.close()


# ---- root:// wire client (ztn bearer + read) ------------------------------

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed mid-response")
        buf.extend(chunk)
    return bytes(buf)


def _resp(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _auth_ztn(sock, token_str):
    tb = token_str.encode() if isinstance(token_str, str) else token_str
    cred_payload = b"ztn\x00" + tb
    req = (struct.pack("!2sH", b"\x00\x03", kXR_auth) + b"\x00" * 12
           + b"ztn\x00" + struct.pack("!I", len(cred_payload)) + cred_payload)
    sock.sendall(req)
    return _resp(sock)


def _login(sock):
    req = struct.pack("!2sHI8sBBBBI", b"\x00\x02", kXR_login,
                      os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _resp(sock)


def _open(sock, path):
    p = path.encode() + b"\x00"
    req = struct.pack("!2sHHH2s6s4sI", b"\x00\x04", kXR_open,
                      0o644, kXR_open_read, b"\x00\x00", b"\x00" * 6,
                      b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _resp(sock)


def _read(sock, fhandle, offset, rlen):
    sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x06", kXR_read, fhandle,
                             offset, rlen, 0))
    return _resp(sock)


def _try_read(port, token_str, path):
    """Full ztn session -> open(path) -> read.  Returns (ok, data): ok=True only
    when the whole chain succeeds and bytes came back."""
    sock = socket.create_connection((HOST, port), timeout=10)
    sock.settimeout(10)
    try:
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        if _resp(sock)[0] != kXR_ok:
            return False, b""
        if _login(sock)[0] != kXR_ok:
            return False, b""
        if _auth_ztn(sock, token_str)[0] != kXR_ok:
            return False, b""
        st, body = _open(sock, path)
        if st != kXR_ok or len(body) < 4:
            return False, b""
        fh = body[:4]
        data = bytearray()
        while True:
            st, chunk = _read(sock, fh, len(data), 65536)
            data.extend(chunk)
            if st == kXR_ok:
                break
            if st != kXR_oksofar:
                return False, bytes(data)
            if not chunk:
                break
        with contextlib.suppress(OSError):
            sock.sendall(struct.pack("!2sH4s12sI", b"\x00\x0e", kXR_close, fh,
                                     b"\x00" * 12, 0))
            _resp(sock)
        return True, bytes(data)
    finally:
        sock.close()


# ---- tests ----------------------------------------------------------------

def test_sts_exchange_mints_origin_cred_and_reads(minio_store, token):
    """Positive: exchange + a correct STS service secret mints a temporary origin
    credential via AssumeRole; the read returns the seeded object byte-exact.
    Since the static credential's secret is WRONG, this can only be the STS temp
    credential authenticating the origin GET — the runtime STS wire, proven."""
    with _gateway(minio_store, token["dir"], "exchange", ROOT_PW) as port:
        ok, data = _try_read(port, token["jwt"], "/" + KEY)
    assert ok, "STS-exchange read failed — expected byte-exact object"
    assert data == BODY, f"origin bytes mismatch: {data[:64]!r}"


def test_delegation_off_falls_to_wrong_static_cred_and_is_refused(minio_store,
                                                                  token):
    """Security-negative / discriminator honesty: with delegation OFF (select),
    STS never engages and only the WRONG static credential remains; the origin
    GET is refused and no bytes come back — proving the positive success above
    was the STS temp cred, not the static fallback."""
    with _gateway(minio_store, token["dir"], "select", ROOT_PW) as port:
        ok, data = _try_read(port, token["jwt"], "/" + KEY)
    assert not (ok and data == BODY), \
        "read unexpectedly succeeded with a deliberately-wrong static credential"


def test_broken_sts_service_secret_fails_closed(minio_store, token):
    """Security-negative: exchange with a BROKEN STS service secret — MinIO
    refuses the AssumeRole, the EXCHANGE gate denies (no service-cred fallback),
    and no bytes are served (fail-closed, never a silent static-cred downgrade)."""
    with _gateway(minio_store, token["dir"], "exchange", BAD_STS_SK) as port:
        ok, data = _try_read(port, token["jwt"], "/" + KEY)
    assert not (ok and data == BODY), \
        "read unexpectedly succeeded despite a broken STS service secret"
