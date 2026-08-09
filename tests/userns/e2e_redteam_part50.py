#!/usr/bin/env python3
"""e2e_redteam.py — full-stack privilege-escalation red-team for phase-40
impersonation.  RUNS AS IN-NS ROOT (launched by userns_exec_launcher inside an
unprivileged user namespace with a subuid range + bind-mounted fake passwd/group).

This is the pseudo-production permissions test: it boots the REAL nginx binary
with `brix_impersonation map` (so the real master spawns the real broker, real
svc-uid workers connect, and the real auth->identity->dispatch->broker->setfsuid
chain runs), then drives it over the network with token-authenticated WebDAV
requests as many identities and tries to break the permissions model.

It asserts the model holds end-to-end: files owned by the MAPPED user (not the
worker/broker), DAC enforced, every escalation/forbidden identity denied,
confinement intact, and no credential leak under concurrency.

argv[1] = work dir (pre-created by the pytest wrapper, holds nothing required —
this script generates keys/tokens/config/export tree itself as in-ns root).
Prints "PASS:"/"FAIL:" per check and "ALL PASSED" + exit 0 on success.
"""

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection   # imported by name: the http() helper below
from urllib.parse import quote           # would otherwise shadow the `http` module

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from settings import BIND_HOST, HOST

WORK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/e2e_redteam"
NGINX = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
# repo root = .../tests/userns/e2e_redteam.py -> up 3.  The native root:// clients
# (built under client/) drive the stream server with a bearer token (BEARER_TOKEN).
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The native CLI binaries are built into client/bin/ (the Makefile's BINDIR), not
# client/ directly — an older layout this path lagged behind.
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
# set in main(): the JWT signing key + the impersonation stream port, so the
# root:// helpers can mint a per-subject token without threading them everywhere.
_jwt_key = None
_stream_port = 0
ISSUER = "https://redteam.example"
AUDIENCE = "nginx-xrootd"
KID = "rt-es256"
WRITE_SCOPE = "storage.create:/ storage.modify:/ storage.read:/"

# S3 SigV4: access_key == the UNIX user the broker maps to (subject = access key).
S3_BUCKET = "testbucket"
S3_REGION = "us-east-1"
S3_SECRET = "rt-s3-secret-0123456789"

# in-ns uids (match the fake /etc/passwd the launcher bind-mounted).
UID_ALICE, UID_BOB, UID_SVC = 1001, 1002, 1500
UID_CAROL, UID_DAVE, UID_ERIN, UID_FRANK = 1003, 1004, 1005, 1006
UID_MANYU, UID_FLOOR, UID_LOW = 1008, 1000, 999
# supplementary groups (match the fake /etc/group): staff={alice,carol},
# research={bob,dave}, shared={alice,bob,carol}, proj={carol,dave,erin}.
GID_STAFF, GID_RESEARCH, GID_SHARED, GID_PROJ = 2001, 2002, 2003, 2004

_pass = _fail = 0


def run_s3_post_form_and_bucketops(key, data, port, s3port):
    """S3 browser POST-form upload + bucket-level ops under impersonation.

    The browser POST Object path (src/protocols/s3/post_object.c) is EXEMPT from the
    dispatch-time header SigV4 (handler.c: `if (!is_post_object_form)`), so the
    impersonation identity for a form upload is whatever auth populated — never a
    privileged fallback.  This batch proves the load-bearing invariant: any object
    a POST form creates is owned by the MAPPED user (alice 1001), NEVER the worker
    (svc 1500) or root (0); a cross-tenant/escape form key is confined+DAC-denied;
    the signed-policy auth gate rejects tampered/forged/expired/missing material;
    and the bucket-level verbs (?location, v1 ListObjects, HEAD/DELETE/PUT bucket,
    ?uploads) neither escalate, destroy the export, nor leak another tenant's
    names.  Distinct from run_s3 / run_s3_extended / run_create_ownership, which
    only cover header-auth PUT/multipart/copy and the v2-list symlink leak.
    """
    if not s3port:
        ok(True, "S3 post-form/bucket-ops skipped (no S3 port)")
        return

    BOB = b"BOB-PRIVATE-SECRET"
    bobread = os.path.join(data, "bob", "readable.txt")

    def uid_of(rel):
        fp = os.path.join(data, rel.lstrip("/"))
        try:
            return os.stat(fp).st_uid if os.path.exists(fp) else -1
        except OSError:
            return -2

    def exists(rel):
        try:
            return os.path.exists(os.path.join(data, rel.lstrip("/")))
        except OSError:
            return False

    def post_form(s3path, ct, body):
        # POST Object carries auth in the form, not the Authorization header.
        return http("POST", f"/{S3_BUCKET}/{s3path}", s3port, data=body,
                    hdrs={"Content-Type": ct})

    # =====================================================================
    # A. POST-FORM OWNERSHIP / ESCALATION  (the central invariant)
    # =====================================================================
    # A1. CONTROL: a correctly-signed POST form (alice cred) targeting alice's own
    #     subtree.  Whether the server honours the form (2xx/303) or refuses it
    #     (the POST path is header-SigV4-exempt, so the broker may see an empty
    #     principal and DENY), the load-bearing rule is the SAME: if a file lands,
    #     it is owned by alice — never svc(1500)/root(0).
    rel1 = "alice/pf_ok.txt"
    if exists(rel1):
        try:
            os.unlink(os.path.join(data, rel1))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", rel1, b"PF-OK-BODY\n")
    st, _ = post_form("", ct, body)
    u1 = uid_of(rel1)
    ok(u1 in (UID_ALICE, -1) and u1 != UID_SVC and u1 != 0,
       f"POST-form upload: created file owned by alice, never worker/root "
       f"(HTTP {st}, uid={u1})")

    # A2. If the form WAS honoured, the object must be confined under alice/ (the
    #     form `key` resolved through the bucket root, not anywhere else) and the
    #     body must round-trip when alice reads it back via header-auth GET.
    if u1 == UID_ALICE:
        stg, gb = s3("GET", rel1, s3port)
        ok(stg == 200 and gb == b"PF-OK-BODY\n",
           f"POST-form object confined to alice/ + body byte-exact (HTTP {stg})")
    else:
        ok(st in (400, 401, 403, 404) and not exists(rel1),
           f"POST-form upload refused fail-closed, no orphan object (HTTP {st})")

    # A3. CROSS-TENANT form key: alice-credentialled form whose key targets BOB's
    #     0755 dir.  The write runs as alice (or an empty principal) -> DAC/broker
    #     denies it; crucially NO file owned by svc/root/bob may appear there.
    relx = "bob/pf_xtenant.txt"
    if exists(relx):
        try:
            os.unlink(os.path.join(data, relx))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relx, b"PF-XTENANT\n")
    st, _ = post_form("", ct, body)
    ux = uid_of(relx)
    ok(not exists(relx) or ux == UID_ALICE,
       f"POST-form into bob's dir: no bob/svc/root-owned file created "
       f"(HTTP {st}, uid={ux})")

    # A4. TAMPERED policy signature -> the signed-policy gate rejects it (403),
    #     and no object is committed.  Proves form auth is actually verified.
    relt = "alice/pf_tampered.txt"
    if exists(relt):
        try:
            os.unlink(os.path.join(data, relt))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relt, b"PF-TAMPER\n", tamper_sig=True)
    st, _ = post_form("", ct, body)
    ok(st in (400, 401, 403) and not exists(relt),
       f"POST-form tampered policy signature REJECTED, no object (HTTP {st})")

    # A5. FORGED credential access key: form claims x-amz-credential=root/...  The
    #     access key must match the configured 'alice' exactly -> InvalidAccessKeyId
    #     (403); no object, and absolutely no root(0)-owned file anywhere it points.
    relr = "alice/pf_rootcred.txt"
    if exists(relr):
        try:
            os.unlink(os.path.join(data, relr))
        except OSError:
            pass
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    ct, body = _s3_post_form(
        "alice", relr, b"PF-ROOTCRED\n",
        cred_override=f"root/{now}/{S3_REGION}/s3/aws4_request")
    st, _ = post_form("", ct, body)
    rr = uid_of(relr)
    ok(st in (400, 401, 403) and (not exists(relr) or rr == UID_ALICE) and rr != 0,
       f"POST-form forged 'root' credential REJECTED, no root-owned object "
       f"(HTTP {st}, uid={rr})")

    # A6. EXPIRED policy: signature is valid but the policy expiration is in the
    #     past -> AccessDenied (403), no object.
    rele = "alice/pf_expired.txt"
    if exists(rele):
        try:
            os.unlink(os.path.join(data, rele))
        except OSError:
            pass
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    ct, body = _s3_post_form("alice", rele, b"PF-EXPIRED\n", when=old,
                             expires_min=1)
    st, _ = post_form("", ct, body)
    ok(st in (400, 401, 403) and not exists(rele),
       f"POST-form expired policy REJECTED, no object (HTTP {st})")

    # A7. ${filename} template + a path-traversal filename.  The server reduces the
    #     filename to its basename before expansion, so the key cannot climb out;
    #     nothing may be written outside the export root.
    outside = os.path.join(os.path.dirname(data), "PF_FN_ESCAPE")
    ct, body = _s3_post_form("alice", "alice/${filename}", b"PF-FN\n",
                             filename="../../../PF_FN_ESCAPE")
    st, _ = post_form("", ct, body)
    ok(not os.path.exists(outside),
       f"POST-form ${{filename}} traversal basename-confined, no escape (HTTP {st})")

    # A8. Explicit traversal in the form `key` itself -> confined, nothing escapes.
    out2 = "/tmp/PF_KEY_ESCAPE"
    try:
        if os.path.exists(out2):
            os.unlink(out2)
    except OSError:
        pass
    ct, body = _s3_post_form("alice", "../../../../tmp/PF_KEY_ESCAPE", b"PF-K\n")
    st, _ = post_form("", ct, body)
    ok(not os.path.exists(out2),
       f"POST-form traversal key created nothing outside the export (HTTP {st})")

    # A9. Missing file part -> 400 (key+file are both required), no object.
    relnf = "alice/pf_nofile.txt"
    if exists(relnf):
        try:
            os.unlink(os.path.join(data, relnf))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relnf, b"", omit_file=True)
    st, _ = post_form("", ct, body)
    ok(st in (400, 403) and not exists(relnf),
       f"POST-form with no file part rejected, no object (HTTP {st})")

    # A10. No policy/signature fields at all (access key IS configured) -> the
    #      missing-fields gate denies it (403); no object.
    relnp = "alice/pf_nopolicy.txt"
    if exists(relnp):
        try:
            os.unlink(os.path.join(data, relnp))
        except OSError:
            pass
    ct, body = _s3_post_form("alice", relnp, b"PF-NP\n", omit_policy=True)
    st, _ = post_form("", ct, body)
    ok(st in (400, 401, 403) and not exists(relnp),
       f"POST-form with no signed policy REJECTED, no object (HTTP {st})")

    # A11. A non-multipart POST to the bucket (wrong Content-Type) must not be
    #      mistaken for a form upload and must not create anything outside its key.
    st, _ = http("POST", f"/{S3_BUCKET}/", s3port, data=b"key=alice/x&file=y",
                 hdrs={"Content-Type": "application/x-www-form-urlencoded"})
    ok(st in (400, 401, 403, 405) and not exists("alice/x"),
       f"non-multipart POST to bucket rejected, no object (HTTP {st})")

    # =====================================================================
    # B. BUCKET-LEVEL VERBS  (escalation / destruction / leak surface)
    # =====================================================================
    # B1. GET /bucket?location (region locator) -> GetBucketLocation: a valid S3
    #     probe answered with the config-supplied region only (LocationConstraint).
    #     It carries NO tenant data — assert it leaks no body content / svc names.
    st, b = s3("GET", "", s3port, params={"location": ""})
    ok(st in (200, 400, 403, 404) and BOB not in (b or b"")
       and b"secret-name.txt" not in (b or b""),
       f"GET /bucket?location no tenant leak (HTTP {st})")

    # B2. GET /bucket with NO list-type (S3 ListObjects v1) -> valid op: the walk is
    #     broker-confined to the mapped user (alice), so it enumerates only entries
    #     alice may traverse and emits keys/size/mtime/synthetic-etag (no file bytes,
    #     no content digest).  bobsecret/ (0700) is fail-closed skipped, so the
    #     listing must contain neither bob's secret BODY nor the cross-tenant
    #     bobsecret name.
    st, b = s3("GET", "", s3port)
    ok(st in (200, 400, 403, 404) and BOB not in (b or b"")
       and b"bobsecret/s.txt" not in (b or b"") and b"bob-only" not in (b or b""),
       f"GET /bucket (ListObjects v1): no cross-tenant CONTENTS leaked — bob's 0700 "
       f"bobsecret/ contents (key 'bobsecret/s.txt' + its 'bob-only' body) are NOT "
       f"enumerated (s3_walk returns 0 on an access-denied dir); a bare prefix name "
       f"is POSIX-visible via readdir of the 0755 export root, like ls (HTTP {st})")

    # B3. HEAD /bucket (empty key) -> HeadBucket: header-only probe (200 + region or
    #     404); either way the response has NO body.
    st, b = s3("HEAD", "", s3port)
    ok(st in (200, 400, 403, 404) and not (b or b""),
       f"HEAD /bucket (HeadBucket) no body (HTTP {st})")

    # B4. DELETE /bucket (empty key) -> rejected, and the export root + alice/ must
    #     SURVIVE (a bucket delete must never rmtree the storage).
    st, _ = s3("DELETE", "", s3port)
    ok(st in (400, 403, 404) and os.path.isdir(os.path.join(data, "alice"))
       and os.path.exists(bobread),
       f"DELETE /bucket rejected, export tree intact (HTTP {st})")

    # B5. PUT /bucket (CreateBucket) -> rejected (empty key); no side effect.
    st, _ = s3("PUT", "", s3port, data=b"")
    ok(st in (400, 403, 404, 411),
       f"PUT /bucket (CreateBucket) rejected (HTTP {st})")

    # B6. GET /bucket?uploads (ListMultipartUploads): initiate an alice MPU first so
    #     there is an in-flight upload, then list.  It must be handled (200/404),
    #     list alice's OWN upload (when 200), and never leak another tenant's
    #     private key names or the svc-only secret.
    st_i, ib = s3("POST", "alice/pf_mpu_list.bin", s3port, params={"uploads": ""})
    upid = None
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", ib or b"")
    if m:
        upid = m.group(1).decode()
    st, b = s3("GET", "", s3port, params={"uploads": ""})
    leaked = (b"secret-name.txt" in (b or b"") or b"bobsecret" in (b or b"")
              or BOB in (b or b"") or b"escape/" in (b or b""))
    ok(st in (200, 404) and not leaked,
       f"GET /bucket?uploads handled, no cross-tenant/secret leak (HTTP {st})")
    if upid:
        # positive control: alice's own in-flight upload key is listable to alice.
        listed = b"pf_mpu_list.bin" in (b or b"")
        ok(st == 404 or listed,
           f"ListMultipartUploads shows alice's own in-flight upload (HTTP {st})")
        s3("DELETE", "alice/pf_mpu_list.bin", s3port, params={"uploadId": upid})
    else:
        ok(True, "ListMultipartUploads control skipped (initiate unsupported)")

    # =====================================================================
    # C. OBJECT-METADATA EDGE BEHAVIOURS  (ownership invariant under odd headers)
    # =====================================================================
    # C1. Content-MD5 that does NOT match the body.  This server verifies only
    #     x-amz-checksum-crc64nvme (not Content-MD5), so the PUT is accepted; the
    #     load-bearing assertion is that the stored object is STILL alice-owned and
    #     never worker/root — a wrong digest must not flip the identity.
    relm = "alice/pf_md5.txt"
    if exists(relm):
        try:
            os.unlink(os.path.join(data, relm))
        except OSError:
            pass
    bad_md5 = base64.b64encode(hashlib.md5(b"DIFFERENT").digest()).decode()
    st, _ = s3("PUT", relm, s3port, data=b"PF-MD5-BODY\n",
               extra_hdrs={"Content-MD5": bad_md5})
    um = uid_of(relm)
    ok((not exists(relm)) or (um == UID_ALICE and um != UID_SVC and um != 0),
       f"PUT with mismatched Content-MD5: object (if stored) owned by alice, "
       f"never worker/root (HTTP {st}, uid={um})")

    # C2. x-amz-storage-class on PUT must not alter ownership or confinement: the
    #     object lands alice-owned under alice/, the requested class is advisory.
    rels = "alice/pf_sc.txt"
    if exists(rels):
        try:
            os.unlink(os.path.join(data, rels))
        except OSError:
            pass
    st, _ = s3("PUT", rels, s3port, data=b"PF-SC-BODY\n",
               extra_hdrs={"x-amz-storage-class": "GLACIER"})
    us = uid_of(rels)
    ok(st in (200, 201) and us == UID_ALICE and us != UID_SVC and us != 0,
       f"PUT x-amz-storage-class=GLACIER: object owned by alice, confined "
       f"(HTTP {st}, uid={us})")

    # =====================================================================
    # D. WORKER SURVIVAL
    # =====================================================================
    # A normal header-auth GET after the whole barrage proves no POST-form /
    # bucket-op sequence wedged or desynced the S3 worker.
    s3("PUT", "alice/pf_alive.txt", s3port, data=b"PF-ALIVE\n")
    st, b = s3("GET", "alice/pf_alive.txt", s3port)
    ok(st == 200 and b == b"PF-ALIVE\n",
       f"S3 worker survived POST-form + bucket-op barrage (HTTP {st})")


