# brix-remote-ok
"""root://+GSI multi-user gateway over MinIO S3 — per-VO backend credentials
and per-user authz, tested purely from the USER's perspective.

Topology under test (charts/s3-gsi, ``./xrd-lab test s3gsi``)::

    xrdcp/xrdfs as bob|alice (VO atlas), tom|jane (VO cms), mallory (no cred)
        │ root://+GSI (proxy certs)
        ▼
    brix  (brix_auth gsi + brix_authdb per-DN default-deny,
           brix_storage_backend s3://minio/brixgsi,
           brix_storage_credential_dir  → per-user .s3 files:
             bob/alice → atlas-svc keys, tom/jane → cms-svc keys)
        │ SigV4
        ▼
    MinIO (atlas-svc scoped to atlas/*, cms-svc scoped to cms/*,
           svc = static service credential, full bucket)

Two lanes over the same backend: TEST_S3GSI_PORT (fallback allow) and
TEST_S3GSI_DENY_PORT (fallback deny).

The suite asserts the DESIRED behaviour of "a normal root:// gateway that
happens to be S3-backed".  Known machinery gaps (predicted from
src/fs/backend/remote/sd_remote.c: no staged_open_cred, no dirlist/mkdir/
rename) are marked xfail with the prediction as reason — an XFAIL confirms
the gap, an XPASS means the machinery grew the capability.  Security
assertions (per-user isolation, credential attribution) are always hard.

Credential ATTRIBUTION is external and unforgeable: MinIO policy scopes each
VO credential, so which credential brix signed with is observable from which
prefixes an op can touch (e.g. the cms/shared canary is readable by cms keys
but not atlas keys; atlas/wprobe/* rejects PutObject for atlas keys but not
for the service credential).

Fault attribution: every brix-side failure first re-probes MinIO directly
with admin credentials and reports ``[backend]`` (MinIO broken — not brix)
vs ``[brix-machinery]`` (backend healthy, gateway at fault).

Remote-only: requires TEST_S3GSI_HOST (set by the s3gsi scenario); skipped
otherwise.
"""

import hashlib
import hmac
import os
import shutil
import stat as statmod
import subprocess
from datetime import datetime, timezone

import pytest
import requests

S3GSI_HOST = os.environ.get("TEST_S3GSI_HOST")
S3GSI_PORT = int(os.environ.get("TEST_S3GSI_PORT", "1094"))
S3GSI_DENY_PORT = int(os.environ.get("TEST_S3GSI_DENY_PORT", "1095"))
MINIO_HOST = os.environ.get("TEST_MINIO_HOST", "127.0.0.1")
MINIO_PORT = int(os.environ.get("TEST_MINIO_PORT", "9000"))
BUCKET = os.environ.get("TEST_S3GSI_BUCKET", "brixgsi")
ADMIN_AK = os.environ.get("MINIO_ROOT_USER", "minioadmin")
ADMIN_SK = os.environ.get("MINIO_ROOT_PASSWORD", "minioadmin")
REGION = "us-east-1"
TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/tr")
PKI_SRC = os.environ.get("PKI_SRC", "/auth/pki")

USERS = ("bob", "alice", "tom", "jane", "mallory")
VO = {"bob": "atlas", "alice": "atlas", "mallory": "atlas",
      "tom": "cms", "jane": "cms"}
# Backend credentials as provisioned by charts/s3-gsi (test-visible so the
# suite can probe the attribution mechanism itself before relying on it).
VO_CREDS = {"atlas": ("atlas-svc", "atlas-secret-1"),
            "cms": ("cms-svc", "cms-secret-1")}

CANARY_PATH = "/cms/shared/canary.dat"
CANARY_BODY = b"cms-canary-payload-v1"

pytestmark = pytest.mark.skipif(
    S3GSI_HOST is None,
    reason="s3gsi scenario env not set (TEST_S3GSI_HOST) — k8s remote-only suite")

XFAIL_WRITE_CRED = ("predicted gap: sd_remote has no staged_open_cred — "
                    "writes are signed with the static service credential")
XFAIL_DENY_WRITE = ("predicted gap: fallback deny refuses writes even with a "
                    "valid .s3 (no staged_open_cred slot to dispatch to)")
XFAIL_NO_DIRLIST = "predicted gap: sd_remote has no opendir/readdir (dirlist)"
XFAIL_NO_MKDIR = "predicted gap: sd_remote has no mkdir slot"
XFAIL_NO_RENAME = "predicted gap: sd_remote has no rename slot"


# --------------------------------------------------------------------------
# Minimal stdlib SigV4 (path-style) — the direct-to-MinIO control plane used
# for ground truth + attribution.  boto3/aws4auth are not in the test env.
# --------------------------------------------------------------------------

def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _sigv4_headers(method, path, payload, ak, sk):
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    host_hdr = f"{MINIO_HOST}:{MINIO_PORT}"
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical = (f"{method}\n{path}\n\nhost:{host_hdr}\n"
                 f"x-amz-content-sha256:{payload_hash}\nx-amz-date:{amzdate}\n"
                 f"\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}")
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = (f"AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n"
               + hashlib.sha256(canonical.encode()).hexdigest())
    k = _sign(_sign(_sign(_sign(("AWS4" + sk).encode(), datestamp),
                          REGION), "s3"), "aws4_request")
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "Host": host_hdr,
        "x-amz-date": amzdate,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                          f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
                          f"Signature={sig}"),
    }


def _s3(method, key, payload=b"", ak=ADMIN_AK, sk=ADMIN_SK, timeout=15):
    """One signed S3 request against MinIO; key is the object key ('' = bucket)."""
    path = f"/{BUCKET}/{key}" if key else f"/{BUCKET}"
    hdrs = _sigv4_headers(method, path, payload, ak, sk)
    url = f"http://{MINIO_HOST}:{MINIO_PORT}{path}"
    return requests.request(method, url, headers=hdrs,
                            data=payload or None, timeout=timeout)


def _backend_healthy():
    try:
        r = requests.get(
            f"http://{MINIO_HOST}:{MINIO_PORT}/minio/health/ready", timeout=5)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _attr(msg):
    """Attribute a brix-side failure: [backend] if MinIO itself is sick."""
    if not _backend_healthy():
        return f"[backend] MinIO unhealthy — not a brix fault: {msg}"
    return f"[brix-machinery] backend healthy, gateway at fault: {msg}"


def _object_key(path):
    """Wire path /atlas/bob/f -> expected object key atlas/bob/f."""
    return path.lstrip("/")


def _obj_get(path, **kw):
    return _s3("GET", _object_key(path), **kw)


def _obj_put(path, body, **kw):
    return _s3("PUT", _object_key(path), payload=body, **kw)


# --------------------------------------------------------------------------
# GSI client plumbing — per-user proxies from the s3gsi-pki secret.
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gsi(tmp_path_factory):
    """Copy per-user proxies out of the (0644) secret mount with 0400 perms
    and return an env factory: gsi(user) -> subprocess env dict."""
    ca_dir = os.path.join(TEST_ROOT, "pki", "ca")
    assert os.path.isfile(os.path.join(ca_dir, "ca.pem")), \
        f"client-pki-init did not lay out {ca_dir} (clientPki mounts missing?)"
    pdir = tmp_path_factory.mktemp("proxies")
    proxies = {}
    for u in USERS:
        src = os.path.join(PKI_SRC, f"{u}_proxy.pem")
        assert os.path.isfile(src), f"missing {src} in s3gsi-pki secret"
        dst = str(pdir / f"{u}.pem")
        shutil.copyfile(src, dst)
        os.chmod(dst, statmod.S_IRUSR)
        proxies[u] = dst

    def env_for(user):
        env = dict(os.environ)
        for k in ("X509_USER_CERT", "X509_USER_KEY"):
            env.pop(k, None)
        env.update({
            "X509_USER_PROXY": proxies[user],
            "X509_CERT_DIR": ca_dir,
            "XrdSecPROTOCOL": "gsi",
            "XrdSecGSISRVNAMES": "*",
            "XRD_CONNECTIONRETRY": "1",
            "XRD_REQUESTTIMEOUT": "30",
        })
        return env

    return env_for


def _url(path, port=None):
    return f"root://{S3GSI_HOST}:{port or S3GSI_PORT}/{path}"


def _run(cmd, env, timeout=90):
    return subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=timeout)


def _xrdcp_up(env, local, path, port=None):
    return _run(["xrdcp", "-f", local, _url(path, port)], env)


def _xrdcp_down(env, path, local, port=None):
    return _run(["xrdcp", "-f", _url(path, port), local], env)


def _xrdfs(env, port, *args):
    return _run(["xrdfs", f"root://{S3GSI_HOST}:{port or S3GSI_PORT}", *args], env)


def _fail_blob(r):
    return f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}"


# ==========================================================================
# 0. Attribution mechanism sanity — prove the backend-side scoping works
#    before any conclusion is drawn from it.  Pure [backend] tests.
# ==========================================================================

class TestBackendProvisioned:
    def test_bucket_and_canary_present(self):
        assert _backend_healthy(), "[backend] MinIO not ready"
        r = _obj_get(CANARY_PATH)
        assert r.status_code == 200 and r.content == CANARY_BODY, \
            f"[backend] canary missing/corrupt: {r.status_code}"

    def test_atlas_keys_cannot_read_canary(self):
        ak, sk = VO_CREDS["atlas"]
        r = _obj_get(CANARY_PATH, ak=ak, sk=sk)
        assert r.status_code == 403, \
            f"[backend] atlas keys must be denied on cms/*: got {r.status_code}"

    def test_cms_keys_can_read_canary(self):
        ak, sk = VO_CREDS["cms"]
        r = _obj_get(CANARY_PATH, ak=ak, sk=sk)
        assert r.status_code == 200 and r.content == CANARY_BODY, \
            f"[backend] cms keys must read cms/*: got {r.status_code}"

    def test_atlas_keys_denied_on_wprobe(self):
        ak, sk = VO_CREDS["atlas"]
        r = _obj_put("/atlas/wprobe/direct.dat", b"x", ak=ak, sk=sk)
        assert r.status_code == 403, \
            f"[backend] atlas keys must be denied PutObject on atlas/wprobe/*: {r.status_code}"


# ==========================================================================
# 1. Look-and-feel: each user works in their own tree like on a normal
#    root:// gateway.
# ==========================================================================

class TestUserRoundtrip:
    @pytest.mark.parametrize("user", ["bob", "alice", "tom", "jane"])
    def test_write_read_roundtrip(self, gsi, tmp_path, user):
        body = f"payload-{user}-v1".encode() * 1024
        src = tmp_path / f"{user}.src"
        src.write_bytes(body)
        path = f"/{VO[user]}/{user}/roundtrip.dat"

        up = _xrdcp_up(gsi(user), str(src), path)
        assert up.returncode == 0, _attr(f"{user} upload failed: {_fail_blob(up)}")

        # Ground truth: the object landed in MinIO under the expected key.
        g = _obj_get(path)
        assert g.status_code == 200, \
            _attr(f"{user} upload not visible in MinIO at key "
                  f"{_object_key(path)!r}: {g.status_code}")
        assert g.content == body, _attr(f"{user} object bytes differ in MinIO")

        dst = tmp_path / f"{user}.dst"
        down = _xrdcp_down(gsi(user), path, str(dst))
        assert down.returncode == 0, _attr(f"{user} download failed: {_fail_blob(down)}")
        assert dst.read_bytes() == body, _attr(f"{user} downloaded bytes differ")

    def test_stat_own_file(self, gsi):
        body = b"stat-me" * 64
        assert _obj_put("/atlas/bob/statme.dat", body).status_code == 200, \
            "[backend] seed PUT failed"
        r = _xrdfs(gsi("bob"), None, "stat", "/atlas/bob/statme.dat")
        assert r.returncode == 0 and str(len(body)) in r.stdout, \
            _attr(f"stat failed or wrong size: {_fail_blob(r)}")

    def test_rm_own_file(self, gsi):
        assert _obj_put("/atlas/bob/rmme.dat", b"bye").status_code == 200, \
            "[backend] seed PUT failed"
        r = _xrdfs(gsi("bob"), None, "rm", "/atlas/bob/rmme.dat")
        assert r.returncode == 0, _attr(f"rm failed: {_fail_blob(r)}")
        g = _obj_get("/atlas/bob/rmme.dat")
        assert g.status_code == 404, \
            _attr(f"rm reported ok but object still in MinIO: {g.status_code}")

    @pytest.mark.xfail(reason=XFAIL_NO_DIRLIST, strict=False)
    def test_dirlist_own_tree(self, gsi):
        assert _obj_put("/atlas/bob/lsdir/a.dat", b"a").status_code == 200
        r = _xrdfs(gsi("bob"), None, "ls", "/atlas/bob/lsdir")
        assert r.returncode == 0 and "a.dat" in r.stdout, \
            _attr(f"ls failed: {_fail_blob(r)}")

    @pytest.mark.xfail(reason=XFAIL_NO_MKDIR, strict=False)
    def test_mkdir_own_tree(self, gsi):
        r = _xrdfs(gsi("bob"), None, "mkdir", "/atlas/bob/newdir")
        assert r.returncode == 0, _attr(f"mkdir failed: {_fail_blob(r)}")

    @pytest.mark.xfail(reason=XFAIL_NO_RENAME, strict=False)
    def test_mv_own_tree(self, gsi):
        assert _obj_put("/atlas/bob/mvsrc.dat", b"mv").status_code == 200
        r = _xrdfs(gsi("bob"), None, "mv", "/atlas/bob/mvsrc.dat",
                   "/atlas/bob/mvdst.dat")
        assert r.returncode == 0, _attr(f"mv failed: {_fail_blob(r)}")
        assert _obj_get("/atlas/bob/mvdst.dat").status_code == 200, \
            _attr("mv reported ok but destination object missing in MinIO")


# ==========================================================================
# 2. Per-user + per-VO isolation (hard security assertions).
# ==========================================================================

class TestIsolation:
    @pytest.fixture(scope="class", autouse=True)
    def seed(self):
        for p, b in (("/atlas/alice/secret.dat", b"alice-secret"),
                     ("/cms/tom/secret.dat", b"tom-secret")):
            assert _obj_put(p, b).status_code == 200, f"[backend] seed {p} failed"

    def test_bob_cannot_read_alice(self, gsi, tmp_path):
        r = _xrdcp_down(gsi("bob"), "/atlas/alice/secret.dat",
                        str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: bob read alice's file through the gateway"

    def test_bob_cannot_write_alice(self, gsi, tmp_path):
        src = tmp_path / "evil"
        src.write_bytes(b"evil")
        r = _xrdcp_up(gsi("bob"), str(src), "/atlas/alice/planted.dat")
        assert r.returncode != 0, \
            "SECURITY: bob wrote into alice's tree through the gateway"
        g = _obj_get("/atlas/alice/planted.dat")
        assert g.status_code == 404, \
            "SECURITY: bob's denied write still materialized in MinIO"

    def test_bob_cannot_read_cms(self, gsi, tmp_path):
        r = _xrdcp_down(gsi("bob"), "/cms/tom/secret.dat", str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: bob (atlas) read a cms user's file through the gateway"

    def test_unlisted_path_denied(self, gsi, tmp_path):
        src = tmp_path / "stray"
        src.write_bytes(b"stray")
        r = _xrdcp_up(gsi("bob"), str(src), "/elsewhere/stray.dat")
        assert r.returncode != 0, \
            "SECURITY: authdb default-deny did not hold for an unlisted path"

    def test_mallory_cannot_read_bob(self, gsi, tmp_path):
        assert _obj_put("/atlas/bob/seed.dat", b"bob-data").status_code == 200
        r = _xrdcp_down(gsi("mallory"), "/atlas/bob/seed.dat",
                        str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: mallory read bob's file (same-VO isolation broken)"


# ==========================================================================
# 3. Credential attribution — WHICH backend credential did brix sign with?
# ==========================================================================

class TestCredentialAttribution:
    def test_read_uses_users_vo_credential(self, gsi, tmp_path):
        """bob has an authdb read grant on /cms/shared, but his .s3 carries
        ATLAS keys — MinIO must refuse the signed read.  Success here would
        mean brix signed bob's read with someone else's credential."""
        r = _xrdcp_down(gsi("bob"), CANARY_PATH, str(tmp_path / "canary"))
        assert r.returncode != 0, \
            ("ATTRIBUTION: bob's read of the cms canary SUCCEEDED — brix did "
             "not sign the read with bob's atlas credential (service-cred "
             "leak on the read path?)")

    def test_read_same_vo_credential_works(self, gsi, tmp_path):
        """jane (cms keys) reads the same canary through the same gateway —
        proves per-user selection picked HER credential."""
        dst = tmp_path / "canary"
        r = _xrdcp_down(gsi("jane"), CANARY_PATH, str(dst))
        assert r.returncode == 0, \
            _attr(f"jane could not read the cms canary: {_fail_blob(r)}")
        assert dst.read_bytes() == CANARY_BODY, _attr("canary bytes differ")

    @pytest.mark.xfail(reason=XFAIL_WRITE_CRED, strict=False)
    def test_write_uses_users_vo_credential(self, gsi, tmp_path):
        """MinIO denies PutObject on atlas/wprobe/* for ATLAS keys but allows
        it for the service credential.  If bob's write there SUCCEEDS, brix
        signed it with the service credential (the predicted gap); the
        desired behaviour is a rejected write."""
        src = tmp_path / "probe"
        src.write_bytes(b"probe")
        r = _xrdcp_up(gsi("bob"), str(src), "/atlas/wprobe/probe.dat")
        landed = _obj_get("/atlas/wprobe/probe.dat").status_code == 200
        assert r.returncode != 0 and not landed, \
            ("ATTRIBUTION: bob's write to the wprobe prefix went through "
             f"(rc={r.returncode}, landed={landed}) — signed with the SERVICE "
             "credential, not bob's atlas keys")


# ==========================================================================
# 4. Fallback semantics: allow lane (mallory has no .s3) + deny lane.
# ==========================================================================

class TestFallbackLanes:
    def test_allow_lane_nocred_uses_service(self, gsi, tmp_path):
        """fallback allow: mallory (no .s3) transparently rides the service
        credential — documents what 'allow' means operationally."""
        src = tmp_path / "m.src"
        src.write_bytes(b"mallory-data")
        up = _xrdcp_up(gsi("mallory"), str(src), "/atlas/mallory/f.dat")
        assert up.returncode == 0, \
            _attr(f"mallory allow-lane upload failed: {_fail_blob(up)}")
        dst = tmp_path / "m.dst"
        down = _xrdcp_down(gsi("mallory"), "/atlas/mallory/f.dat", str(dst))
        assert down.returncode == 0 and dst.read_bytes() == b"mallory-data", \
            _attr(f"mallory allow-lane download failed: {_fail_blob(down)}")

    def test_deny_lane_nocred_rejected(self, gsi, tmp_path):
        assert _obj_put("/atlas/mallory/denyme.dat", b"x").status_code == 200
        r = _xrdcp_down(gsi("mallory"), "/atlas/mallory/denyme.dat",
                        str(tmp_path / "out"), port=S3GSI_DENY_PORT)
        assert r.returncode != 0, \
            ("SECURITY: deny lane served mallory (no backend credential) — "
             "storage_credential_fallback deny not enforced")

    def test_deny_lane_read_with_cred(self, gsi, tmp_path):
        assert _obj_put("/atlas/bob/denyread.dat", b"deny-read").status_code == 200
        dst = tmp_path / "out"
        r = _xrdcp_down(gsi("bob"), "/atlas/bob/denyread.dat", str(dst),
                        port=S3GSI_DENY_PORT)
        assert r.returncode == 0 and dst.read_bytes() == b"deny-read", \
            _attr(f"deny-lane read with a VALID .s3 failed: {_fail_blob(r)}")

    @pytest.mark.xfail(reason=XFAIL_DENY_WRITE, strict=False)
    def test_deny_lane_write_with_cred(self, gsi, tmp_path):
        src = tmp_path / "w.src"
        src.write_bytes(b"deny-write")
        r = _xrdcp_up(gsi("bob"), str(src), "/atlas/bob/denywrite.dat",
                      port=S3GSI_DENY_PORT)
        assert r.returncode == 0, \
            _attr(f"deny-lane write with a VALID .s3 failed: {_fail_blob(r)}")
