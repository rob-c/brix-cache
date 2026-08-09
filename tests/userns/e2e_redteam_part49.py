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


def run_s3_subresource_fallthrough(key, data, port, s3port):
    """S3 UNHANDLED sub-resource fall-through under per-request impersonation.

    The dispatcher (src/protocols/s3/handler.c) recognizes only a handful of query params
    (delete, key-marker, max-parts, max-uploads, part-number-marker, uploads,
    +partNumber/uploadId pairs).  EVERY other S3 sub-resource (?acl, ?tagging,
    ?versioning, ?policy, ?cors, ?lifecycle, ?retention, ?legal-hold, ...) is
    UNRECOGNIZED and silently falls through to plain object semantics:
        GET  ?acl     -> s3_handle_get    (plain object read)
        PUT  ?tagging -> s3_put_body      (the request body is STORED AS THE OBJECT)
        DELETE ?acl   -> s3_handle_delete (plain object delete)
        POST ?acl     -> 405              (NO fall-through to object PUT)
        bucket-level (empty key) ?acl     -> 400 InvalidURI
    The invariant under attack: an unrecognized sub-resource must never (a) bypass
    impersonation/ownership (an artifact lands owned by the MAPPED user 1001, never
    svc/root, confined in the export), (b) leak another tenant's bytes, or
    (c) mutate another tenant's object / crash the worker.  NEW surface vs
    run_protocol_features_s3 (conditional/metadata/response verbs), run_s3_deep
    (copy/delete-batch/range/list), run_s3_extended (head/multipart/subtree-keys):
    none of those drive the *unrecognized sub-resource parser fall-through* path."""
    if not s3port:
        ok(True, "S3 port not configured — subresource-fallthrough skipped (handled)")
        return

    absp = lambda rel: os.path.join(data, *rel.split("/"))

    def owner_uid(p):
        try:
            return os.stat(p).st_uid if os.path.exists(p) else -1
        except OSError:
            return -1

    def not_worker_root(p):
        u = owner_uid(p)
        return u == -1 or u not in (UID_SVC, 0)

    def confined(p):
        try:
            return os.path.realpath(p).startswith(os.path.realpath(data) + os.sep)
        except OSError:
            return False

    SECRET = b"BOB-PRIVATE-SECRET"
    XML_BODY = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
                b'<Key>injected</Key><Value>SUBRES-FALLTHRU</Value>'
                b'</Tag></TagSet></Tagging>')

    # ============================================================== (A) ===
    # GET ?<subres> on alice's OWN object falls through to a plain object GET:
    # it runs as alice (1001) and returns the byte-exact body — proving the
    # fall-through still honors the mapped principal (no anon/worker read) and
    # never 5xx-crashes the worker.  One representative per param-shape (bare /
    # dashed / camelCase / plain); the same code path serves the rest.
    s3("PUT", "alice/sr_own.txt", s3port, data=b"SR-OWN-BODY\n")
    for sr in ["acl", "tagging", "versioning", "object-lock", "publicAccessBlock", "torrent"]:
        st, b = s3("GET", "alice/sr_own.txt", s3port, params={sr: ""})
        if sr in ("acl", "tagging"):
            # ?acl / ?tagging are now HANDLED ops (GetObjectAcl / GetObjectTagging,
            # src/protocols/s3/tagging.c) — a benign metadata XML response, NOT the object
            # body; still runs as alice, never leaks another tenant.
            ok(st == 200 and b"SR-OWN-BODY" not in (b or b"")
               and (b"<AccessControlPolicy" in (b or b"") or b"<Tagging" in (b or b"")),
               f"S3 GET ?{sr} on own object -> handled canned metadata, not the "
               f"object body (HTTP {st})")
        else:
            ok(st == 200 and b == b"SR-OWN-BODY\n",
               f"S3 GET ?{sr} on own object falls through to plain read as alice (HTTP {st})")

    # ============================================================== (B) ===
    # PUT ?<subres> with an XML body falls through to OBJECT PUT: the XML is
    # stored AS THE OBJECT.  THE KEY OWNERSHIP INVARIANT — any artifact created
    # this way is owned by the MAPPED user (alice=1001), NEVER svc(1500)/root(0),
    # and confined inside the export.  Four distinct param shapes prove the
    # parser-shape never changes the principal the write lands under.
    for sr in ["tagging", "object-lock", "publicAccessBlock", "acl"]:
        rel = f"alice/sr_put_{sr.replace('-', '_')}.txt"
        fp = absp(rel)
        try:
            if os.path.exists(fp):
                os.unlink(fp)
        except OSError:
            pass
        st, _ = s3("PUT", rel, s3port, params={sr: ""}, data=XML_BODY)
        # If the fall-through created the object it MUST be alice's, confined, and
        # contain exactly the XML body (stored-as-object proof).  If the server
        # instead refused the unknown sub-resource, no file is the safe outcome.
        if os.path.exists(fp):
            ok(owner_uid(fp) == UID_ALICE and confined(fp)
               and open(fp, "rb").read() == XML_BODY,
               f"S3 PUT ?{sr} fell through to object PUT: alice-owned, confined, byte-exact (HTTP {st})")
        else:
            ok(not_worker_root(fp),
               f"S3 PUT ?{sr} refused, no object created (HTTP {st})")
        # Regardless of branch: the artifact is NEVER svc/root-owned.
        ok(not_worker_root(fp),
           f"S3 PUT ?{sr} artifact never worker/root-owned")

    # ============================================================== (C) ===
    # CROSS-TENANT READ: alice GET ?<subres> on bob's 0600 private.txt must NOT
    # return bob's bytes.  The fall-through runs s3_handle_get as alice; bob's DAC
    # (0600 owner=1002) denies the open -> 403/404, no SECRET in the body.  This
    # is the leak-via-unhandled-sub-resource probe — the denial must survive the
    # *parser fall-through*, not a recognized verb (distinct from run_s3_deep).
    for sr in ["acl", "tagging", "policy", "versions", "torrent", "attributes"]:
        st, b = s3("GET", "bob/private.txt", s3port, params={sr: ""})
        leaked = SECRET in (b or b"")
        if sr == "acl":
            # GetObjectAcl returns a CANNED ACL templated on the REQUESTER's own
            # identity — it never opens bob's file, so a 200 here discloses NOTHING
            # about bob (no content, no metadata, not even existence).  The security
            # boundary (bob's secret bytes) holds; only the status is a benign 200.
            ok(st == 200 and not leaked,
               f"S3 alice GET ?acl on bob's 0600 -> canned requester-owned ACL, no "
               f"bob secret/data leaked (HTTP {st})")
        else:
            # ?tagging reads the object's tags (DAC-gated) and the rest fall through
            # to s3_handle_get -> bob's 0600 denies the impersonated open -> 403/404.
            ok(st in (403, 404) and not leaked,
               f"S3 alice GET ?{sr} on bob's 0600 DENIED, no secret bytes (HTTP {st})")

    # ============================================================== (D) ===
    # CROSS-TENANT MUTATION: alice PUT ?<subres> on bob's 0600 private.txt must
    # NOT mutate it — the fall-through object-PUT runs as alice and bob's file
    # DAC denies create/truncate.  Snapshot bytes+mode+owner BEFORE and AFTER and
    # assert byte-for-byte identity (a true no-mutation proof, not just a status).
    bpriv = absp("bob/private.txt")
    try:
        before_bytes = open(bpriv, "rb").read()
        before_mode = os.stat(bpriv).st_mode & 0o777
        before_uid = os.stat(bpriv).st_uid
    except OSError:
        before_bytes, before_mode, before_uid = None, -1, -1
    for sr in ["tagging", "acl", "object-lock", "retention", "legal-hold"]:
        st, _ = s3("PUT", "bob/private.txt", s3port, params={sr: ""}, data=XML_BODY)
        try:
            after_bytes = open(bpriv, "rb").read()
            after_mode = os.stat(bpriv).st_mode & 0o777
            after_uid = os.stat(bpriv).st_uid
        except OSError:
            after_bytes, after_mode, after_uid = None, -2, -2
        ok(st not in (200, 201, 204)
           and after_bytes == before_bytes and SECRET in (before_bytes or b"")
           and after_mode == before_mode and after_uid == before_uid == UID_BOB,
           f"S3 alice PUT ?{sr} on bob's 0600 DENIED: bytes+mode+owner unchanged (HTTP {st})")

    # ============================================================== (E) ===
    # CROSS-TENANT DELETE: alice DELETE ?<subres> on bob's world-readable 0644
    # readable.txt falls through to a plain object DELETE running as alice.  bob's
    # dir is 0755 (alice cannot unlink within it) so the file must SURVIVE.
    # Snapshot existence before/after.  Distinct from run_s3_deep's DeleteObjects
    # batch: this is the single-object DELETE verb reached via the sub-res parser.
    bread = absp("bob/readable.txt")
    bread_before = os.path.exists(bread)
    for sr in ["acl", "tagging"]:
        st, _ = s3("DELETE", "bob/readable.txt", s3port, params={sr: ""})
        ok(bread_before and os.path.exists(bread),
           f"S3 alice DELETE ?{sr} on bob's file DENIED: file survives (HTTP {st})")

    # Self-DELETE positive control: alice DELETE ?acl on her OWN object falls
    # through to a real delete and removes it (proves E's survival is per-file DAC,
    # not a blanket reject of sub-resourced DELETEs).
    s3("PUT", "alice/sr_del.txt", s3port, data=b"x\n")
    delp = absp("alice/sr_del.txt")
    st, _ = s3("DELETE", "alice/sr_del.txt", s3port, params={"acl": ""})
    ok(not os.path.exists(delp),
       f"control: S3 alice DELETE ?acl on own object falls through + deletes (HTTP {st})")

    # ============================================================== (F) ===
    # POST ?<subres> on an object key: POST does NOT fall through to object PUT
    # (the dispatcher handles POST only for ?uploads / ?delete / uploadId), so an
    # unhandled POST sub-resource ends at 405 and creates NOTHING — never an
    # object write, never a worker/root artifact.
    for sr in ["acl", "notification", "requestPayment"]:
        rel = f"alice/sr_post_{sr}.txt"
        fp = absp(rel)
        try:
            if os.path.exists(fp):
                os.unlink(fp)
        except OSError:
            pass
        st, _ = s3("POST", rel, s3port, params={sr: ""}, data=XML_BODY)
        ok(st in (405, 400, 403, 501) and not os.path.exists(fp),
           f"S3 POST ?{sr} on object key NOT a write fall-through -> rejected, no artifact (HTTP {st})")

    # ============================================================== (G) ===
    # BUCKET-LEVEL (empty key) unhandled sub-resource: GET/PUT/DELETE /bucket/?acl.
    # The unknown ?acl param is ignored: GET falls through to the broker-confined
    # bucket list (200, no cross-tenant bytes), while PUT/DELETE on an empty key hit
    # the empty-key guard -> 400 InvalidURI.  Either way there is NO object-write
    # fall-through and NO escape/secret leak in the reply.
    for method in ["GET", "PUT", "DELETE"]:
        body = XML_BODY if method == "PUT" else None
        st, b = s3(method, "", s3port, params={"acl": ""}, data=body)
        ok(st in (200, 400, 403, 404, 405, 501)
           and b"escape/" not in (b or b"") and SECRET not in (b or b""),
           f"S3 {method} /bucket/?acl (bucket-level) no object/leak (HTTP {st})")

    # ============================================================== (H) ===
    # WORKER LIVENESS: after the whole adversarial sub-resource sweep the worker is
    # still up — a clean GET of alice's seeded object returns its body (proves no
    # sub-resource path crashed the worker / wedged the connection).
    st, b = s3("GET", "alice/sr_own.txt", s3port)
    ok(st == 200 and b == b"SR-OWN-BODY\n",
       f"S3 worker survived unhandled-sub-resource sweep (follow-up GET OK, HTTP {st})")


