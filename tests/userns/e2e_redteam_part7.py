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


def run_root_battery(key, data):
    """root:// NATIVE STREAM protocol (xrdfs/xrdcp + bearer token) under
    impersonation — the least-covered protocol.  Drives every file op the native
    client exposes (stat/cat/ls/mkdir/rm/rmdir/mv/chmod/truncate/locate/query +
    xrdcp read/write) across self / cross-tenant / escalation / confinement, and
    asserts the SAME invariants as WebDAV/S3: owned by the mapped user, DAC
    enforced, dir-listing confidentiality, confinement to the export."""
    if not xrd_avail():
        ok(False, "native xrdfs/xrdcp not built (client/) — root:// SKIPPED")
        return
    A, B = "alice", "bob"
    lf = os.path.join(WORK, "root_src.bin")
    with open(lf, "wb") as fh:
        fh.write(b"root-write-payload\n")

    def owned_by(rel, uid):
        fp = os.path.join(data, rel.lstrip("/"))
        return os.path.exists(fp) and os.stat(fp).st_uid == uid

    # ---- self (alice) ownership / success across ops --------------------------
    rc, _o, e = xrd_cp_up(lf, "/alice/r_w.bin", A)
    ok(rc == 0 and owned_by("/alice/r_w.bin", UID_ALICE),
       f"root:// xrdcp WRITE owned by alice (rc={rc}, {e.strip()[:80]})")

    dn = os.path.join(WORK, "root_dl.bin")
    rc, _o, _e = xrd_cp_down("/alice/r_w.bin", dn, A)
    ok(rc == 0 and os.path.exists(dn) and open(dn, "rb").read() == b"root-write-payload\n",
       f"root:// xrdcp READ own file content (rc={rc})")

    for sub, expect0, label in [
        (["stat", "/alice/r_w.bin"], True, "stat own file"),
        (["cat", "/alice/r_w.bin"], True, "cat own file"),
        (["ls", "/alice/"], True, "ls own dir"),
        (["mkdir", "/alice/r_dir"], True, "mkdir own"),
        (["truncate", "/alice/r_w.bin", "4"], True, "truncate own"),
        (["mv", "/alice/r_w.bin", "/alice/r_w2.bin"], True, "mv own"),
        (["rm", "/alice/r_w2.bin"], True, "rm own file"),
        (["rmdir", "/alice/r_dir"], True, "rmdir own empty dir"),
        (["locate", "/alice/"], True, "locate own"),
        (["query", "space", "/alice/"], True, "query space"),
    ]:
        rc, _o, _e = xrd_fs(sub, A)
        ok((rc == 0) == expect0, f"root:// xrdfs {label} (rc={rc})")
    # mkdir owner check (recreate, verify owner, cleanup)
    xrd_fs(["mkdir", "/alice/r_owned"], A)
    ok(owned_by("/alice/r_owned", UID_ALICE), "root:// xrdfs mkdir owned by alice")
    xrd_fs(["rmdir", "/alice/r_owned"], A)

    # ---- cross-tenant: alice must not read/mutate bob's data -------------------
    rc, out, _e = xrd_fs(["cat", "/bob/private.txt"], A)
    ok(rc != 0 and "BOB-PRIVATE-SECRET" not in (out or ""),
       f"root:// cat bob's 0600 DENIED (rc={rc})")
    rc, out, _e = xrd_fs(["cat", "/bob/readable.txt"], A)
    ok(rc == 0 and "bob-world-readable" in (out or ""),
       f"control: root:// cat bob's 0644 ALLOWED (rc={rc})")

    bread = os.path.join(data, "bob", "readable.txt")
    for sub, label in [
        (["rm", "/bob/readable.txt"], "rm bob's file"),
        (["mv", "/bob/readable.txt", "/alice/stolen_r.txt"], "mv bob's file"),
        (["mkdir", "/bob/alice_mk"], "mkdir in bob's dir"),
        (["chmod", "/bob/readable.txt", "777"], "chmod bob's file"),
        (["truncate", "/bob/readable.txt", "0"], "truncate bob's file"),
        (["rmdir", "/bobsecret"], "rmdir bob's 0700 dir"),
    ]:
        rc, _o, _e = xrd_fs(sub, A)
        ok(rc != 0, f"root:// {label} DENIED (rc={rc})")
    ok(os.path.exists(bread) and os.stat(bread).st_uid == UID_BOB
       and open(bread, "rb").read() == b"bob-world-readable\n",
       "root:// bob's file survived all of alice's cross-tenant attempts")
    rc, _o, _e = xrd_cp_up(lf, "/bob/r_inject.bin", A)
    ok(rc != 0 and not os.path.exists(os.path.join(data, "bob", "r_inject.bin")),
       f"root:// xrdcp WRITE into bob's dir DENIED (rc={rc})")
    rc, _o, _e = xrd_cp_down("/bob/private.txt", os.path.join(WORK, "stolen.bin"), A)
    ok(rc != 0, f"root:// xrdcp READ bob's 0600 DENIED (rc={rc})")

    # ---- dir-listing confidentiality on root:// (the S3/PROPFIND class) --------
    rc, out, _e = xrd_fs(["cat", "/svconly/secret-name.txt"], A)
    ok(rc != 0 and "svc-only-secret" not in (out or ""),
       f"root:// cat svc-only file DENIED (rc={rc})")
    rc, out, _e = xrd_fs(["ls", "/svconly/"], A)
    ok("secret-name.txt" not in (out or ""),
       f"root:// ls of svc-only dir does NOT leak entries (rc={rc})")

    # ---- escalation: forbidden / unmapped principals denied -------------------
    for sub in ["root", "svc", "mallory", "sys100"]:
        rc, _o, _e = xrd_cp_up(lf, f"/pub/r_esc_{sub}.bin", sub)
        ok(rc != 0 and not os.path.exists(os.path.join(data, "pub", f"r_esc_{sub}.bin")),
           f"root:// op as principal '{sub}' DENIED (rc={rc})")

    # ---- confinement: symlink-escape + traversal must not read /etc ------------
    rc, out, _e = xrd_fs(["cat", "/escape/passwd"], A)
    ok("root:x:0:0" not in (out or ""),
       f"root:// cat through /escape symlink did NOT read /etc/passwd (rc={rc})")
    rc, out, _e = xrd_cp_down("/escape/passwd", os.path.join(WORK, "pw.bin"), A)
    pw = os.path.join(WORK, "pw.bin")
    leaked = os.path.exists(pw) and b"root:x:0:0" in open(pw, "rb").read()
    ok(not leaked, f"root:// xrdcp through symlink did NOT exfil /etc/passwd (rc={rc})")


def run_s3_sigv4_errors(key, data, s3port):
    """A malformed/invalid SigV4 must be REJECTED before any FS op — and must NEVER
    fall through to anonymous/worker access.  For PUTs the invariant is: rejected +
    no file (a created file would mean a write ran with no valid identity)."""
    bkt = S3_BUCKET
    path = f"/{bkt}/alice/sigerr.txt"
    fp = os.path.join(data, "alice", "sigerr.txt")
    body = b"sigv4-attack\n"

    def good():
        return dict(s3_sign("PUT", path, s3port))

    # Hard-invalid signatures: the server CANNOT derive a valid identity -> must
    # 4xx-reject and create nothing.
    hard = {}
    h = good(); h["Authorization"] = h["Authorization"][:-10] + "0000000000"
    hard["corrupted signature"] = h
    h = good(); h["Authorization"] = h["Authorization"].split("Signature=")[0] + "Signature=deadbeef"
    hard["truncated signature"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("aws4_request,", "aws4_request,").replace(h["Authorization"].split("Signature=")[1], "z" * 64)
    hard["non-hex signature"] = h
    h = good(); h.pop("x-amz-date", None)
    hard["missing x-amz-date"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("SignedHeaders=host;x-amz-date", "SignedHeaders=host")
    hard["tampered SignedHeaders"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("/us-east-1/", "/eu-west-1/")
    hard["wrong region in scope"] = h
    h = good(); h["Authorization"] = "AWS4-HMAC-SHA256 garbage-no-equals"
    hard["malformed Authorization"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("Credential=alice/", "Credential=/")
    hard["empty credential"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("Credential=alice/", "Credential=root/")
    hard["wrong access key 'root' (no map-to-root)"] = h
    h = good(); h["Authorization"] = h["Authorization"].replace("Credential=alice/", "Credential=svc/")
    hard["wrong access key 'svc' (no map-to-worker)"] = h
    hard["unsigned (no Authorization)"] = {}

    for label, hdrs in hard.items():
        if os.path.exists(fp):
            os.unlink(fp)
        st, _ = http("PUT", path, s3port, data=body, hdrs=hdrs)
        created = os.path.exists(fp)
        ok(st not in (200, 201, 204) and not created,
           f"S3 SigV4 {label} -> REJECTED, no file (HTTP {st}, created={created})")
    if os.path.exists(fp):
        os.unlink(fp)

    # Clock-skew: a cryptographically-valid but stale/early signature.  The
    # impersonation invariant is weaker here — if accepted it still runs as alice
    # (owned 1001), NEVER as the worker/root.
    for label, dlt in [("expired (-20min)", -20), ("future (+20min)", 20)]:
        if os.path.exists(fp):
            os.unlink(fp)
        when = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=dlt)
        st, _ = http("PUT", path, s3port, data=body,
                     hdrs=dict(s3_sign("PUT", path, s3port, when=when)))
        created = os.path.exists(fp)
        bad = created and os.stat(fp).st_uid != UID_ALICE
        ok(not bad,
           f"S3 SigV4 {label}: never worker/root-owned (HTTP {st}, created={created})")
    if os.path.exists(fp):
        os.unlink(fp)

    # A bad-sig READ/HEAD/DELETE must also gate before any FS op (no leak / no op).
    h = good(); h["Authorization"] = h["Authorization"][:-6] + "000000"
    st, b = http("GET", f"/{bkt}/bob/private.txt", s3port, hdrs=h)
    ok(st not in (200,) and b"BOB-PRIVATE-SECRET" not in (b or b""),
       f"S3 SigV4 bad-sig GET of bob's file rejected, no leak (HTTP {st})")


def run_s3_extended(key, data, s3port):
    """The S3 operations not yet exercised: HeadObject (self+cross), full multipart
    lifecycle cross-initiator (initiate/upload/list/abort/complete), and keys that
    RESOLVE into another tenant's / svc-only subtree."""
    bkt = S3_BUCKET

    # HeadObject: self ok; cross-tenant 0600 must not return the object (deny or
    # metadata-only — but never the body, and a write-method gate must not leak).
    s3("PUT", "alice/head_me.txt", s3port, data=b"headable\n")
    st, _ = s3("HEAD", "alice/head_me.txt", s3port)
    ok(st == 200, f"S3 HEAD own object (HTTP {st})")
    st, _ = s3("HEAD", "bob/private.txt", s3port)
    ok(st in (403, 404) or st == 200,  # metadata may be visible; body never is
       f"S3 HEAD bob's 0600 object handled (HTTP {st})")

    # Keys that resolve INTO another tenant's private subtree must be denied by DAC.
    st, b = s3("GET", "svconly/secret-name.txt", s3port)
    ok(st in (403, 404) and b"svc-only-secret" not in (b or b""),
       f"S3 GET key into svc-only dir DENIED (HTTP {st})")
    st, _ = s3("PUT", "bobsecret/inject.txt", s3port, data=b"x\n")
    ok(st not in (200, 201)
       and not os.path.exists(os.path.join(data, "bobsecret", "inject.txt")),
       f"S3 PUT key into bob's 0700 dir DENIED (HTTP {st})")
    st, _ = s3("PUT", "svconly/inject.txt", s3port, data=b"x\n")
    ok(st not in (200, 201)
       and not os.path.exists(os.path.join(data, "svconly", "inject.txt")),
       f"S3 PUT key into svc-only dir DENIED (HTTP {st})")

    # Full multipart lifecycle self: initiate -> upload part -> list parts -> abort
    # (the staging dir + parts must be alice-owned; abort cleans up).
    st_i, bdy = s3("POST", "alice/mpu_life.bin", s3port, params={"uploads": ""})
    m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
    if st_i == 200 and m:
        up = m.group(1).decode()
        st_p, _ = s3("PUT", "alice/mpu_life.bin", s3port,
                     params={"uploadId": up, "partNumber": "1"}, data=b"Z" * 2048)
        ok(st_p in (200, 201), f"S3 multipart UploadPart self (HTTP {st_p})")
        # the staging dir is created under alice/ as alice
        stg = os.path.join(data, "alice")
        mpu_dirs = [d for d in os.listdir(stg) if "mpu" in d and d.startswith(".")]
        owned = all(os.stat(os.path.join(stg, d)).st_uid == UID_ALICE for d in mpu_dirs) \
            if mpu_dirs else True
        ok(owned, "S3 multipart staging dir owned by alice")
        st_l, _ = s3("GET", "alice/mpu_life.bin", s3port, params={"uploadId": up})
        ok(st_l in (200, 404), f"S3 ListParts self (HTTP {st_l})")
        st_a, _ = s3("DELETE", "alice/mpu_life.bin", s3port, params={"uploadId": up})
        ok(st_a in (200, 204), f"S3 AbortMultipartUpload self (HTTP {st_a})")
    else:
        ok(False, f"S3 multipart initiate self failed (HTTP {st_i})")

    # ListMultipartUploads must not crash / leak another tenant's keys (the alice
    # key only ever lists as alice, but verify it does not enumerate via symlink).
    st, b = s3("GET", "", s3port, params={"uploads": ""})
    ok(st in (200, 404) and b"escape/" not in (b or b""),
       f"S3 ListMultipartUploads no symlink-escape (HTTP {st})")


LOCKINFO = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
            b'<D:lockscope><D:exclusive/></D:lockscope>'
            b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
PROPFIND_BODY = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                 b'<D:prop><D:displayname/></D:prop></D:propfind>')


def run_webdav_methods(key, data, port):
    """Exhaustive WebDAV METHOD coverage under impersonation: the less-obvious
    methods (HEAD/OPTIONS/UNLOCK/COPY-collection/Overwrite/Depth) for self
    ownership + cross-tenant DAC + lock-token theft."""
    ta, tb = mint(key, "alice"), mint(key, "bob")

    # HEAD: own file 200; bob's 0600 must never return the BODY (metadata may show).
    http("PUT", "/alice/head.txt", port, ta, b"head-body\n")
    st, b = http("HEAD", "/alice/head.txt", port, ta)
    ok(st == 200 and not b, f"WebDAV HEAD own file (HTTP {st}, no body)")
    st, b = http("HEAD", "/bob/private.txt", port, ta)
    ok(b"BOB-PRIVATE-SECRET" not in (b or b""), f"WebDAV HEAD bob's 0600 no body leak (HTTP {st})")

    # OPTIONS: advertises DAV/Allow; no body, no side effect.
    st, _ = http("OPTIONS", "/alice/", port, ta)
    ok(st in (200, 204), f"WebDAV OPTIONS (HTTP {st})")

    # UNLOCK lock-token theft: alice locks her file; bob tries UNLOCK with the
    # stolen token -> must FAIL (the removexattr runs as bob on alice's file).
    http("PUT", "/alice/lk_steal.txt", port, ta, b"x\n")
    st, lb = http("LOCK", "/alice/lk_steal.txt", port, ta, data=LOCKINFO,
                  hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
    m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", lb or b"")
    if st in (200, 201) and m:
        tok = m.group(1).decode()
        st_u, _ = http("UNLOCK", "/alice/lk_steal.txt", port, tb,
                       hdrs={"Lock-Token": f"<{tok}>"})
        ok(st_u not in (200, 204),
           f"WebDAV UNLOCK of alice's lock by bob (stolen token) DENIED (HTTP {st_u})")
    else:
        ok(False, f"WebDAV LOCK setup for theft test failed (HTTP {st})")

    # PROPFIND Depth:0 on a file -> just the file (no children); Depth:1 on a dir.
    st, b = http("PROPFIND", "/alice/head.txt", port, ta, data=PROPFIND_BODY,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"WebDAV PROPFIND Depth:0 on file (HTTP {st})")

    # COPY collection (recursive): alice copies her own dir tree -> owned by alice.
    http("MKCOL", "/alice/coll_src", port, ta)
    http("PUT", "/alice/coll_src/inner.txt", port, ta, b"inner\n")
    st, _ = http("COPY", "/alice/coll_src", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/coll_dst",
                       "Depth": "infinity"})
    cdst = os.path.join(data, "alice", "coll_dst")
    inner = os.path.join(cdst, "inner.txt")
    ok(st in (201, 204) and os.path.isdir(cdst) and os.stat(cdst).st_uid == UID_ALICE
       and (not os.path.exists(inner) or os.stat(inner).st_uid == UID_ALICE),
       f"WebDAV COPY collection owned by alice (HTTP {st})")

    # COPY/MOVE Overwrite:F over an existing file -> 412 (no clobber); Overwrite:T ok.
    http("PUT", "/alice/ow_src.txt", port, ta, b"src\n")
    http("PUT", "/alice/ow_dst.txt", port, ta, b"dst\n")
    st, _ = http("COPY", "/alice/ow_src.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/ow_dst.txt",
                       "Overwrite": "F"})
    ok(st in (412, 409, 403), f"WebDAV COPY Overwrite:F over existing -> refused (HTTP {st})")

    # cross-tenant Overwrite:T MOVE/COPY over bob's file -> denied.
    http("PUT", "/alice/ow_x.txt", port, ta, b"x\n")
    st, _ = http("COPY", "/alice/ow_x.txt", port, ta,
                 hdrs={"Destination": f"http://{HOST}:{port}/bob/readable.txt",
                       "Overwrite": "T"})
    bread = os.path.join(data, "bob", "readable.txt")
    ok(st not in (201, 204) and open(bread, "rb").read() == b"bob-world-readable\n",
       f"WebDAV COPY Overwrite:T over bob's file DENIED (HTTP {st})")


def run_webdav_errors(key, data, port):
    """WebDAV protocol/header/error modes combined with impersonation: conditional
    headers, Range, keep-alive identity reuse, malformed/oversized bodies, chunked,
    unknown methods, double-encoding.  Fail = a cross-tenant/worker/leak/escape."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    bpriv = os.path.join(data, "bob", "private.txt")

    # Conditional GET on bob's 0600 must STILL be denied (conditional must not be
    # evaluated as a confidentiality oracle before the DAC gate, nor leak body).
    for hdr in [{"If-Match": "*"}, {"If-None-Match": "*"},
                {"If-None-Match": '"x"'}, {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"},
                {"Range": "bytes=0-4"}, {"If-Range": '"x"', "Range": "bytes=0-4"}]:
        st, b = http("GET", "/bob/private.txt", port, ta, hdrs=hdr)
        ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
           f"WebDAV GET bob's 0600 with {list(hdr)[0]} no leak (HTTP {st})")

    # Range on own file: valid range serves a slice; invalid ranges don't crash.
    http("PUT", "/alice/rng.txt", port, ta, b"0123456789")
    st, b = http("GET", "/alice/rng.txt", port, ta, hdrs={"Range": "bytes=0-3"})
    ok(st in (206, 200), f"WebDAV Range valid on own file (HTTP {st})")
    for rng in ["bytes=8-2", "bytes=99-200", "bytes=-3"]:
        st, _ = http("GET", "/alice/rng.txt", port, ta, hdrs={"Range": rng})
        ok(st in (200, 206, 416), f"WebDAV Range '{rng}' handled (HTTP {st})")

    # KEEP-ALIVE principal boundary: alice PUT then bob PUT on ONE connection ->
    # each lands in the correct owner's space (no leaked principal across the pair).
    res = http_keepalive([
        ("PUT", "/alice/ka_a.txt", ta, b"a\n", {}),
        ("PUT", "/bob/ka_b.txt", tb, b"b\n", {}),
    ], port)
    fa = os.path.join(data, "alice", "ka_a.txt")
    fb = os.path.join(data, "bob", "ka_b.txt")
    ok(os.path.exists(fa) and os.stat(fa).st_uid == UID_ALICE
       and os.path.exists(fb) and os.stat(fb).st_uid == UID_BOB,
       "WebDAV keep-alive alice-then-bob: each owned correctly (no principal leak)")
    # keep-alive cross-tenant: alice PUT then bob PUT INTO alice's dir -> denied,
    # even reusing the connection where alice's principal was just active.
    res = http_keepalive([
        ("PUT", "/alice/ka_ok.txt", ta, b"x\n", {}),
        ("PUT", "/alice/ka_evil.txt", tb, b"X\n", {}),
    ], port)
    ok(not os.path.exists(os.path.join(data, "alice", "ka_evil.txt")),
       "WebDAV keep-alive: bob's write into alice's dir DENIED (no stale principal)")

    # Malformed / hostile bodies must not crash the worker (follow-up request OK).
    bad_bodies = {
        "truncated XML PROPFIND": b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop',
        "billion-laughs PROPFIND": (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
                                    b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                                    b'<D:propfind xmlns:D="DAV:"><D:prop>&b;</D:prop></D:propfind>'),
        "oversized PROPFIND body": b'<D:propfind xmlns:D="DAV:"><x>' + b"A" * 200000 + b'</x></D:propfind>',
    }
    for label, body in bad_bodies.items():
        http("PROPFIND", "/alice/", port, ta, data=body,
             hdrs={"Depth": "0", "Content-Type": "application/xml"})
    st, _ = http("GET", "/alice/rng.txt", port, ta)
    ok(st == 200, "WebDAV worker survived malformed/oversized bodies (follow-up GET OK)")

    # Unknown method + double-encoded traversal Destination.
    st, _ = http("XYZZY", "/alice/", port, ta)
    ok(st in (405, 501, 400), f"WebDAV unknown method rejected (HTTP {st})")
    outside = os.path.join(os.path.dirname(data), "OUTSIDE_DE")
    http("PUT", "/alice/de_src.txt", port, ta, b"x\n")
    http("COPY", "/alice/de_src.txt", port, ta,
         hdrs={"Destination": f"http://{HOST}:{port}/%252e%252e/OUTSIDE_DE"})
    ok(not os.path.exists(outside), "WebDAV double-encoded ../ Destination blocked")


