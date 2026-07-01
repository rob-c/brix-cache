"""
tests/test_frm_owner.py

FINDING-FRM-1 regression: the FRM cancel/evict path must enforce requester
OWNERSHIP — a stage request may only be cancelled/deleted by the principal that
created it.  Before the fix, any caller could cancel another tenant's tape recall
by its guessable monotonic reqid (a cross-VO denial-of-service).

This stands up a self-contained token-auth WebDAV + Tape REST + FRM server (ES256
JWKS, like test_token_es256.py) and drives the WLCG Tape REST API with TWO
distinct authenticated identities (different token "sub"):

  * alice POST /api/v1/stage            -> 201 + requestId         (owner = alice)
  * bob   DELETE /api/v1/stage/{id}     -> 403  (foreign principal denied)  <-- fix
  * bob   POST   /api/v1/stage/{id}/cancel -> 403                            <-- fix
  * alice DELETE /api/v1/stage/{id}     -> 204  (the owner still may)
  * alice DELETE /api/v1/stage/{bogus}  -> 204  (idempotent, no enum oracle)

Fail-open for anonymous callers / owner-less records is covered by the existing
anonymous test_tape_rest.py (which still passes after the fix).
"""

import base64
import json
import os
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    _HAVE_CRYPTO = True
except Exception:                                # pragma: no cover
    _HAVE_CRYPTO = False

STREAM_PORT = int(os.environ.get("TEST_FRM_OWNER_STREAM", "22041"))
HTTP_PORT = int(os.environ.get("TEST_FRM_OWNER_HTTP", "22042"))
KID = "ec-key-frm"
ISSUER = "https://test.example.com"
AUDIENCE = "nginx-xrootd"
SCOPE = "storage.read:/ storage.modify:/ storage.create:/ storage.stage:/"


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


from frm_helpers import xattr_ok as _xattr_ok


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS or not _HAVE_CRYPTO:
        pytest.skip("requests + cryptography required")
    d = tmp_path_factory.mktemp("frmowner")
    if not _xattr_ok(str(d)):
        pytest.skip("filesystem does not support user xattrs")

    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "cadir").mkdir()
    data = d / "data"; data.mkdir()
    queue = d / "frm.queue"

    near = data / "near.dat"
    near.write_bytes(b"")
    os.setxattr(str(near), "user.frm.residency", b"nearline")

    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "EC", "crv": "P-256", "kid": KID, "use": "sig", "alg": "ES256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }]}
    jwks_path = d / "jwks.json"
    jwks_path.write_text(json.dumps(jwks))

    conf = f"""
worker_processes 1;
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{STREAM_PORT};
        xrootd on;
        xrootd_storage_backend posix:{data};
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_frm on;
        xrootd_frm_queue_path {queue};
        xrootd_frm_stagecmd /bin/true;
    }}
}}
http {{
    access_log off;
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t;
    server {{
        listen {BIND_HOST}:{HTTP_PORT};
        location / {{
            xrootd_webdav on;
            xrootd_webdav_storage_backend posix:{data};
            xrootd_webdav_auth required;
            xrootd_webdav_cadir {d}/cadir;
            xrootd_webdav_allow_write on;
            xrootd_webdav_tape_rest on;
            xrootd_webdav_token_jwks {jwks_path};
            xrootd_webdav_token_issuer "{ISSUER}";
            xrootd_webdav_token_audience "{AUDIENCE}";
        }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx rejected config: %s" % chk.stderr.strip()[-300:])
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not _wait_port(HTTP_PORT):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip("frm-owner server did not start: %s" % err[-300:])

    class S:
        pass
    s = S()
    s.key = key
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _token(key, sub):
    now = int(time.time())
    header = {"alg": "ES256", "typ": "JWT", "kid": KID}
    payload = {"iss": ISSUER, "sub": sub, "aud": AUDIENCE,
               "exp": now + 3600, "iat": now, "nbf": now,
               "scope": SCOPE, "wlcg.ver": "1.0"}
    si = (_b64u(json.dumps(header, separators=(",", ":")).encode())
          + "." + _b64u(json.dumps(payload, separators=(",", ":")).encode()))
    der = key.sign(si.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return si + "." + _b64u(raw)


def _hdr(token):
    return {"Authorization": "Bearer %s" % token}


def _stage(token, path="/near.dat"):
    r = requests.post("http://%s:%d/api/v1/stage" % (HOST, HTTP_PORT),
                      headers=_hdr(token), json={"files": [{"path": path}]},
                      timeout=10)
    rid = None
    try:
        rid = r.json().get("requestId")
    except Exception:
        pass
    return r.status_code, rid


def _delete(token, rid):
    return requests.delete("http://%s:%d/api/v1/stage/%s" % (HOST, HTTP_PORT, rid),
                           headers=_hdr(token), timeout=10).status_code


def _cancel(token, rid):
    # body-LESS cancel, as real FTS/gfal2 clients send: the dispatch routes
    # /stage/{id}/cancel before the mandatory body parse, so this must reach the
    # ownership check (not 400).
    return requests.post("http://%s:%d/api/v1/stage/%s/cancel" % (HOST, HTTP_PORT, rid),
                         headers=_hdr(token), timeout=10).status_code


def _alice(srv):
    return _token(srv.key, "alice@example.org")


def _bob(srv):
    return _token(srv.key, "bob@example.org")


def test_owner_can_stage_then_delete(srv):
    st, rid = _stage(_alice(srv))
    assert st == 201 and rid, "alice stage failed: %r (rid=%r)" % (st, rid)
    assert _delete(_alice(srv), rid) == 204, "owner must be able to delete own request"


def test_foreign_principal_cannot_delete(srv):
    st, rid = _stage(_alice(srv))
    assert st == 201 and rid, "alice stage failed: %r" % st
    # THE FIX: bob did not create this request -> 403, and it must NOT be deleted.
    assert _delete(_bob(srv), rid) == 403, \
        "a foreign principal must NOT be able to delete another's stage request"
    # prove it was untouched: the owner can still delete it.
    assert _delete(_alice(srv), rid) == 204, \
        "owner delete after a denied foreign delete must still succeed (record intact)"


def test_foreign_principal_cannot_cancel(srv):
    st, rid = _stage(_alice(srv))
    assert st == 201 and rid, "alice stage failed: %r" % st
    assert _cancel(_bob(srv), rid) == 403, \
        "a foreign principal must NOT be able to cancel another's stage request"
    assert _delete(_alice(srv), rid) == 204, "owner cleanup delete"


def test_owner_bodyless_cancel_reaches_handler(srv):
    # regression for the dispatch gotcha: a body-less POST .../cancel must route
    # to the cancel handler (204 for the owner), not 400 from the body parser.
    st, rid = _stage(_alice(srv))
    assert st == 201 and rid, "alice stage failed: %r" % st
    assert _cancel(_alice(srv), rid) == 204, \
        "owner's body-less cancel must succeed (204), not 400 from the body parser"


def test_unknown_reqid_idempotent_for_owner(srv):
    # an absent record fails open (no enumeration oracle): the owner check passes
    # and the delete is an idempotent no-op.
    assert _delete(_alice(srv), "9999999.1@nohost") == 204, \
        "delete of an unknown reqid should be an idempotent 204, not 403"
