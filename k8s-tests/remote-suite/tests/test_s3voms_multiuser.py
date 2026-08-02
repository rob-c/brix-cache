# brix-remote-ok
"""root://+GSI multi-user gateway over MinIO S3 with ZERO per-user provisioning:
authorization AND backend-credential selection are both driven entirely by the
client's VOMS Attribute Certificate (phase-80 P80.14).

Topology under test (charts/s3-voms, ``./xrd-lab test s3voms``)::

    xrdcp/xrdfs as bob|alice (VOMS vo=atlas), tom|jane (VOMS vo=cms),
                  mallory (valid proxy, NO VOMS AC)
        │ root://+GSI (proxy certs; the AC is carried in the proxy)
        ▼
    brix  (brix_auth gsi + VOMS extraction (brix_vomsdir + brix_voms_cert_dir),
           brix_require_vo /atlas atlas + /cms cms,
           brix_authdb = 'o atlas /atlas a' + 'o cms /cms a' (default-deny),
           brix_storage_backend s3://minio/brixvoms,
           brix_storage_credential_dir → EXACTLY TWO VO-tier files:
             vo-atlas.s3 → atlas-svc keys, vo-cms.s3 → cms-svc keys,
           brix_storage_credential_fallback deny)
        │ SigV4
        ▼
    MinIO (atlas-svc scoped to atlas/*, cms-svc scoped to cms/*,
           svc = static service credential, full bucket)

The distinguishing claim vs. the s3gsi suite: **nothing on the server names a
user**.  There is no gridmap and no per-user credential file — a NEVER-SEEN
user cert bearing a valid atlas VOMS AC immediately reads/writes/deletes under
``/atlas/*`` and is denied everywhere else, and MinIO attributes every one of
its requests to the atlas group key.  The isolation contract is therefore
**per-VO, not per-user**: two atlas members share the ``/atlas`` space by
design (a shared VO tree); the hard boundary is atlas-vs-cms and no-VO.

Credential ATTRIBUTION is external and unforgeable exactly as in s3gsi: MinIO
policy scopes each VO credential, so which credential brix signed with is
observable from which prefixes an op can touch (the cms/shared canary is
readable by cms keys but not atlas keys; atlas/wprobe/* rejects PutObject for
the atlas VO key but not for the service credential, so an atlas write there
succeeding would prove a service-credential leak).

Fault attribution: every brix-side failure first re-probes MinIO directly with
admin credentials and reports ``[backend]`` (MinIO broken — not brix) vs
``[brix-machinery]`` (backend healthy, gateway at fault).

Remote-only: requires TEST_S3VOMS_HOST (set by the s3voms scenario); skipped
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

S3VOMS_HOST = os.environ.get("TEST_S3VOMS_HOST")
S3VOMS_PORT = int(os.environ.get("TEST_S3VOMS_PORT", "1097"))
MINIO_HOST = os.environ.get("TEST_MINIO_HOST", "127.0.0.1")
MINIO_PORT = int(os.environ.get("TEST_MINIO_PORT", "9000"))
BUCKET = os.environ.get("TEST_S3VOMS_BUCKET", "brixvoms")
ADMIN_AK = os.environ.get("MINIO_ROOT_USER", "minioadmin")
ADMIN_SK = os.environ.get("MINIO_ROOT_PASSWORD", "minioadmin")
REGION = "us-east-1"
TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/tr")
PKI_SRC = os.environ.get("PKI_SRC", "/auth/pki")

USERS = ("bob", "alice", "tom", "jane", "mallory")
# VOMS VO carried in each principal's AC (mallory has none).
VO = {"bob": "atlas", "alice": "atlas", "tom": "cms", "jane": "cms"}
# Backend credentials as provisioned by charts/s3-voms (test-visible so the
# suite can probe the attribution mechanism itself before relying on it).
VO_CREDS = {"atlas": ("atlas-svc", "atlas-secret-1"),
            "cms": ("cms-svc", "cms-secret-1")}

CANARY_PATH = "/cms/shared/canary.dat"
CANARY_BODY = b"cms-canary-payload-v1"

pytestmark = pytest.mark.skipif(
    S3VOMS_HOST is None,
    reason="s3voms scenario env not set (TEST_S3VOMS_HOST) — k8s remote-only suite")

# Same sd_remote namespace-op gaps predicted for the s3gsi lane.
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
# GSI client plumbing — per-user VOMS proxies from the s3voms-pki secret.
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gsi(tmp_path_factory):
    """Copy per-user VOMS proxies out of the (0644) secret mount with 0400 perms
    and return an env factory: gsi(user) -> subprocess env dict."""
    ca_dir = os.path.join(TEST_ROOT, "pki", "ca")
    assert os.path.isfile(os.path.join(ca_dir, "ca.pem")), \
        f"client-pki-init did not lay out {ca_dir} (clientPki mounts missing?)"
    pdir = tmp_path_factory.mktemp("proxies")
    proxies = {}
    for u in USERS:
        src = os.path.join(PKI_SRC, f"{u}_proxy.pem")
        assert os.path.isfile(src), f"missing {src} in s3voms-pki secret"
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
    return f"root://{S3VOMS_HOST}:{port or S3VOMS_PORT}/{path}"


def _run(cmd, env, timeout=90):
    return subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=timeout)


def _xrdcp_up(env, local, path, port=None):
    return _run(["xrdcp", "-f", local, _url(path, port)], env)


def _xrdcp_down(env, path, local, port=None):
    return _run(["xrdcp", "-f", _url(path, port), local], env)


def _xrdfs(env, port, *args):
    return _run(["xrdfs", f"root://{S3VOMS_HOST}:{port or S3VOMS_PORT}", *args], env)


def _fail_blob(r):
    return f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}"


def _assert_honest_unsupported(op, r):
    """While the namespace op stays unimplemented on sd_remote, its failure
    mode must be kXR_Unsupported (3013), never a dishonest generic I/O error."""
    if r.returncode == 0:
        return
    blob = _fail_blob(r)
    low = blob.lower()
    assert "3013" in blob or "not supported" in low or "unsupported" in low, \
        _attr(f"[brix-machinery] {op} failed with a dishonest error kind "
              f"(want kXR_Unsupported/3013): {blob}")


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
# 1. Zero-provisioning look-and-feel: a never-seen cert with a valid VOMS AC
#    works immediately in its VO tree like on a normal root:// gateway.
# ==========================================================================

class TestVomsRoundtrip:
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
        _assert_honest_unsupported("ls", r)
        assert r.returncode == 0 and "a.dat" in r.stdout, \
            _attr(f"ls failed: {_fail_blob(r)}")

    @pytest.mark.xfail(reason=XFAIL_NO_MKDIR, strict=False)
    def test_mkdir_own_tree(self, gsi):
        r = _xrdfs(gsi("bob"), None, "mkdir", "/atlas/bob/newdir")
        _assert_honest_unsupported("mkdir", r)
        assert r.returncode == 0, _attr(f"mkdir failed: {_fail_blob(r)}")

    @pytest.mark.xfail(reason=XFAIL_NO_RENAME, strict=False)
    def test_mv_own_tree(self, gsi):
        assert _obj_put("/atlas/bob/mvsrc.dat", b"mv").status_code == 200
        r = _xrdfs(gsi("bob"), None, "mv", "/atlas/bob/mvsrc.dat",
                   "/atlas/bob/mvdst.dat")
        _assert_honest_unsupported("mv", r)
        assert r.returncode == 0, _attr(f"mv failed: {_fail_blob(r)}")
        assert _obj_get("/atlas/bob/mvdst.dat").status_code == 200, \
            _attr("mv reported ok but destination object missing in MinIO")


# ==========================================================================
# 2. Per-VO isolation (hard security assertions).  The grant is org-scoped, so
#    same-VO members SHARE the space by design; the boundary is VO-vs-VO and
#    the no-VO identity.
# ==========================================================================

class TestVoIsolation:
    @pytest.fixture(scope="class", autouse=True)
    def seed(self):
        for p, b in (("/atlas/alice/shared.dat", b"alice-atlas"),
                     ("/cms/tom/secret.dat", b"tom-cms")):
            assert _obj_put(p, b).status_code == 200, f"[backend] seed {p} failed"

    def test_same_vo_members_share_the_space(self, gsi, tmp_path):
        """The intended posture, asserted explicitly: two atlas members share
        /atlas (org grant 'o atlas /atlas a'), so bob reads alice's object.  A
        failure here would mean the VO grant collapsed to per-user."""
        dst = tmp_path / "shared"
        r = _xrdcp_down(gsi("bob"), "/atlas/alice/shared.dat", str(dst))
        assert r.returncode == 0 and dst.read_bytes() == b"alice-atlas", \
            _attr(f"same-VO share broke (bob could not read alice): {_fail_blob(r)}")

    def test_atlas_cannot_read_cms(self, gsi, tmp_path):
        r = _xrdcp_down(gsi("bob"), "/cms/tom/secret.dat", str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: an atlas member read a cms object through the gateway"

    def test_atlas_cannot_write_cms(self, gsi, tmp_path):
        src = tmp_path / "evil"
        src.write_bytes(b"evil")
        r = _xrdcp_up(gsi("bob"), str(src), "/cms/tom/planted.dat")
        assert r.returncode != 0, \
            "SECURITY: an atlas member wrote into the cms tree through the gateway"
        assert _obj_get("/cms/tom/planted.dat").status_code == 404, \
            "SECURITY: the denied cross-VO write still materialized in MinIO"

    def test_cms_cannot_read_atlas(self, gsi, tmp_path):
        r = _xrdcp_down(gsi("tom"), "/atlas/alice/shared.dat",
                        str(tmp_path / "loot"))
        assert r.returncode != 0, \
            "SECURITY: a cms member read an atlas object (VO isolation is symmetric)"

    def test_unlisted_path_denied(self, gsi, tmp_path):
        src = tmp_path / "stray"
        src.write_bytes(b"stray")
        r = _xrdcp_up(gsi("bob"), str(src), "/elsewhere/stray.dat")
        assert r.returncode != 0, \
            "SECURITY: authdb default-deny did not hold for an unlisted prefix"

    def test_no_ac_identity_denied_everywhere(self, gsi, tmp_path):
        """mallory authenticates with a valid proxy but carries NO VOMS AC, so
        the identity has no vorg/VO: denied by both the 'o' rules and
        brix_require_vo, on every governed prefix."""
        src = tmp_path / "m"
        src.write_bytes(b"mallory")
        for space in ("/atlas/mallory/x.dat", "/cms/mallory/x.dat"):
            r = _xrdcp_up(gsi("mallory"), str(src), space)
            assert r.returncode != 0, \
                f"SECURITY: a no-VOMS identity was served on {space}"
            assert _obj_get(space).status_code == 404, \
                f"SECURITY: a no-VOMS denied write still landed at {space}"


# ==========================================================================
# 3. Credential attribution — WHICH backend credential did brix sign with?
#    The credential is VO-DERIVED (P80.12), never per-user, never the service
#    credential (fallback=deny).
# ==========================================================================

class TestCredentialAttribution:
    def test_read_uses_vo_credential(self, gsi, tmp_path):
        """jane (VO cms) reads the cms canary through the gateway — proves the
        VO-tier resolver picked vo-cms.s3 with no per-user file in play."""
        dst = tmp_path / "canary"
        r = _xrdcp_down(gsi("jane"), CANARY_PATH, str(dst))
        assert r.returncode == 0, \
            _attr(f"jane could not read the cms canary: {_fail_blob(r)}")
        assert dst.read_bytes() == CANARY_BODY, _attr("canary bytes differ")

    def test_write_uses_vo_credential_not_service(self, gsi, tmp_path):
        """MinIO denies PutObject on atlas/wprobe/* for the ATLAS key but allows
        it for the service credential.  bob's write there MUST fail: success
        would mean brix signed with the service credential (fallback leak),
        not vo-atlas.s3."""
        src = tmp_path / "probe"
        src.write_bytes(b"probe")
        r = _xrdcp_up(gsi("bob"), str(src), "/atlas/wprobe/probe.dat")
        landed = _obj_get("/atlas/wprobe/probe.dat").status_code == 200
        assert r.returncode != 0 and not landed, \
            ("ATTRIBUTION: bob's write to the wprobe prefix went through "
             f"(rc={r.returncode}, landed={landed}) — signed with the SERVICE "
             "credential, not the atlas VO key (vo-atlas.s3)")
