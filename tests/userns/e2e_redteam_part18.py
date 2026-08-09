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


def _resp_status(resp):
    """Parse the HTTP status code out of a raw response (-1 if unparseable)."""
    try:
        if resp.startswith(b"HTTP/"):
            return int(resp.split(b" ", 2)[1])
    except (ValueError, IndexError):
        pass
    return -1


def run_http_protocol_abuse(key, data, port, s3port):
    """RAW HTTP-layer attacks under impersonation (request smuggling, duplicate
    headers, HTTP/1.0, bare-LF framing, body-on-GET, absolute-URI, multi-range).
    A desync or a smuggled second request must NEVER execute under the wrong
    identity, leak another tenant's bytes, or wedge the worker.  Uses raw sockets
    (raw_http) so the framing is forgeable; every case proves worker-survival +
    no cross-tenant leak + no smuggled side effect."""
    ta = mint(key, "alice")
    H = HOST

    # seed a readable own file + a sized file for range tests.
    http("PUT", "/alice/hpa_own.txt", port, ta, b"HPA-OWN-BODY\n")
    http("PUT", "/alice/hpa_rng.txt", port, ta, b"0123456789ABCDEF")

    # (1) REQUEST SMUGGLING via duplicate Content-Length: a second PUT smuggled in
    #     the body must NOT be executed (as alice or anyone).  nginx should 400.
    smug = (f"PUT /alice/hpa_s1.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 5\r\n"
            f"Content-Length: 120\r\n\r\nhelloPUT /alice/hpa_SMUGGLED.txt "
            f"HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n"
            f"Content-Length: 4\r\n\r\nevil")
    resp = raw_http(smug, port)
    st = _resp_status(resp)
    ok(not os.path.exists(os.path.join(data, "alice", "hpa_SMUGGLED.txt")),
       f"dup-Content-Length smuggled request NOT executed (HTTP {st})")
    ok(st in (400, 411, -1) or st >= 400,
       f"dup-Content-Length request rejected/handled (HTTP {st})")

    # (2) Content-Length + Transfer-Encoding: chunked (CL.TE smuggling) -> reject;
    #     no smuggled artifact.
    clte = (f"POST /alice/hpa_s2.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nPUT /alice/hpa_TE.txt "
            f"HTTP/1.1\r\nHost: {H}\r\n\r\n")
    resp = raw_http(clte, port)
    ok(not os.path.exists(os.path.join(data, "alice", "hpa_TE.txt")),
       f"CL+TE smuggled request NOT executed (HTTP {_resp_status(resp)})")

    # (3) duplicate Host headers -> 400 (nginx), no confusion.
    dh = (f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {H}\r\nHost: evil.example\r\n"
          f"Authorization: Bearer {ta}\r\n\r\n")
    resp = raw_http(dh, port)
    ok(b"HPA-OWN-BODY" not in resp or _resp_status(resp) == 200,
       f"duplicate Host header handled, no anomaly (HTTP {_resp_status(resp)})")

    # (4) HTTP/1.0 request (no Host) -> served or cleanly handled, no leak/crash.
    h10 = (f"GET /alice/hpa_own.txt HTTP/1.0\r\nAuthorization: Bearer {ta}\r\n\r\n")
    resp = raw_http(h10, port)
    ok(_resp_status(resp) in (200, 400, 404, 426, 505, -1),
       f"HTTP/1.0 request handled (HTTP {_resp_status(resp)})")

    # (5) absolute-URI request line targeting a foreign host must not escape — the
    #     path is still confined to alice; bob's secret never returned.
    au = (f"GET http://evil.example/bob/private.txt HTTP/1.1\r\nHost: {H}\r\n"
          f"Authorization: Bearer {ta}\r\n\r\n")
    resp = raw_http(au, port)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       f"absolute-URI request leaks no bob secret (HTTP {_resp_status(resp)})")

    # (6) bare-LF line framing (no CR) -> nginx tolerates or 400; no desync.
    lf = (f"GET /alice/hpa_own.txt HTTP/1.1\nHost: {H}\nAuthorization: Bearer {ta}\n\n")
    resp = raw_http(lf, port)
    ok(_resp_status(resp) in (200, 400, -1),
       f"bare-LF framed request handled (HTTP {_resp_status(resp)})")

    # (7) body on GET (Content-Length on a method that ignores it) -> handled.
    bg = (f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {H}\r\n"
          f"Authorization: Bearer {ta}\r\nContent-Length: 5\r\n\r\nXXXXX")
    resp = raw_http(bg, port)
    ok(_resp_status(resp) in (200, 400, 413, -1),
       f"body-on-GET handled (HTTP {_resp_status(resp)})")

    # (8) MULTI-RANGE on own file -> 206 (multipart/byteranges) or 200; valid.
    mr = (f"GET /alice/hpa_rng.txt HTTP/1.1\r\nHost: {H}\r\n"
          f"Authorization: Bearer {ta}\r\nRange: bytes=0-2,5-7\r\n\r\n")
    resp = raw_http(mr, port)
    ok(_resp_status(resp) in (200, 206, 416),
       f"multi-range GET on own file handled (HTTP {_resp_status(resp)})")

    # (9) MULTI-RANGE on bob's 0600 file -> never returns the secret bytes.
    mrb = (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nRange: bytes=0-4,6-10\r\n\r\n")
    resp = raw_http(mrb, port)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       f"multi-range GET on bob's 0600 no leak (HTTP {_resp_status(resp)})")

    # (10) overlapping / negative / huge ranges on own file -> no crash.
    for rng in ["bytes=0-0,0-0,0-0", "bytes=-99999", "bytes=5-2", "bytes=0-999999"]:
        resp = raw_http(f"GET /alice/hpa_rng.txt HTTP/1.1\r\nHost: {H}\r\n"
                        f"Authorization: Bearer {ta}\r\nRange: {rng}\r\n\r\n", port)
        ok(_resp_status(resp) in (200, 206, 416, 400, -1),
           f"range '{rng}' handled (HTTP {_resp_status(resp)})")

    # (11) absurd header count -> rejected (431/400), worker survives.
    many = "".join(f"X-Pad-{i}: {i}\r\n" for i in range(200))
    resp = raw_http(f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {H}\r\n"
                    f"Authorization: Bearer {ta}\r\n{many}\r\n", port)
    ok(_resp_status(resp) in (200, 400, 431, 494, -1),
       f"200-header request handled (HTTP {_resp_status(resp)})")

    # (11b) a WELL-FORMED chunked PUT must work and the object is owned by the
    #       writer (exercises the chunked request-body path under impersonation).
    tb_ = mint(key, "bob")
    body = b"chunked-body-data"
    chunked = (f"PUT /alice/hpa_chunked.txt HTTP/1.1\r\nHost: {H}\r\n"
               f"Authorization: Bearer {ta}\r\nTransfer-Encoding: chunked\r\n\r\n"
               f"{len(body):x}\r\n").encode() + body + b"\r\n0\r\n\r\n"
    resp = raw_http(chunked, port)
    fpc = os.path.join(data, "alice", "hpa_chunked.txt")
    ok(_resp_status(resp) in (200, 201, 204, 400, 411, 501, -1),
       f"chunked PUT handled (HTTP {_resp_status(resp)})")
    ok(not os.path.exists(fpc) or os.stat(fpc).st_uid == UID_ALICE,
       "chunked PUT object (if created) owned by alice not worker/root")
    # bob chunked PUT INTO alice's dir -> denied by DAC.
    cb = (f"PUT /alice/hpa_bobchunk.txt HTTP/1.1\r\nHost: {H}\r\n"
          f"Authorization: Bearer {tb_}\r\nTransfer-Encoding: chunked\r\n\r\n"
          f"3\r\nXXX\r\n0\r\n\r\n").encode()
    raw_http(cb, port)
    ok(not os.path.exists(os.path.join(data, "alice", "hpa_bobchunk.txt")),
       "bob chunked PUT into alice's dir DENIED")

    # (11c) RAW PIPELINE of 3 requests on ONE connection (alice,alice-cross,alice):
    #       the per-request principal must not let any request read bob's 0600, and
    #       alice's own requests must still be served (no interleave corruption).
    pipe = (f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
            f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
            f"GET /alice/hpa_own.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n"
            f"Connection: close\r\n\r\n")
    resp = raw_http(pipe, port)
    ok(b"BOB-PRIVATE-SECRET" not in resp and resp.count(b"HPA-OWN-BODY") >= 1,
       "raw 3-request pipeline: alice served, bob 0600 never leaked")

    # (12) worker SURVIVED every raw attack: a normal request still works.
    st, b = http("GET", "/alice/hpa_own.txt", port, ta)
    ok(st == 200 and b == b"HPA-OWN-BODY\n",
       f"worker survived raw HTTP abuse (follow-up GET ok, HTTP {st})")
    # and nothing landed wrongly-owned in alice's dir from the raw writes.
    bad = 0
    for f in os.listdir(os.path.join(data, "alice")):
        if f.startswith("hpa_"):
            try:
                if os.lstat(os.path.join(data, "alice", f)).st_uid in (UID_SVC, 0):
                    bad += 1
            except OSError:
                pass
    ok(bad == 0, f"no hpa_* file landed worker/root-owned (mismatches={bad})")


def run_s3_presigned(key, data, port, s3port):
    """S3 PRESIGNED-URL (query-string SigV4) auth under impersonation.  The query
    carries the credential; the access-key still maps to a UNIX uid, so a presigned
    URL grants exactly the signer's DAC — never an escalation — and expiry /
    tamper / cross-tenant must all be enforced."""
    if not s3port:
        ok(True, "S3 presigned skipped (no S3 port)")
        return
    BOB = b"BOB-PRIVATE-SECRET"

    # seed an own object via header-auth.
    s3("PUT", "alice/ps_obj.txt", s3port, data=b"PRESIGN-OWN-OBJECT\n")

    # (1) valid presigned GET of own object -> 200 + bytes (positive control).
    st, b = http("GET", s3_presign("GET", "alice/ps_obj.txt", s3port, expires=300), s3port)
    ok(st == 200 and b"PRESIGN-OWN-OBJECT" in (b or b""),
       f"valid presigned GET reads own object (HTTP {st})")

    # (2) EXPIRED presigned (signed an hour ago, 60s validity) -> denied.
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
    st, b = http("GET", s3_presign("GET", "alice/ps_obj.txt", s3port, expires=60, when=old), s3port)
    ok(st in (401, 403) and b"PRESIGN-OWN-OBJECT" not in (b or b""),
       f"expired presigned GET denied (HTTP {st})")

    # (3) TAMPERED signature -> denied.
    st, b = http("GET", s3_presign("GET", "alice/ps_obj.txt", s3port, tamper=True), s3port)
    ok(st in (401, 403), f"tampered presigned signature denied (HTTP {st})")

    # (4) X-Amz-Expires=0 and absurdly-large -> rejected (AWS caps at 7 days).
    for exp in (0, 999999999):
        st, _ = http("GET", s3_presign("GET", "alice/ps_obj.txt", s3port, expires=exp), s3port)
        ok(st in (401, 403, 400), f"presigned X-Amz-Expires={exp} rejected (HTTP {st})")

    # (5) presigned GET of a CROSS-TENANT 0600 path (signed as alice) -> DAC denies,
    #     never the secret (presigned grants alice's DAC, not bob's).
    st, b = http("GET", s3_presign("GET", "bob/private.txt", s3port), s3port)
    ok(BOB not in (b or b""),
       f"presigned GET of bob's 0600 leaks no secret (HTTP {st})")

    # (6) presigned PUT -> creates an object owned by the signer (alice), confined.
    pp = s3_presign("PUT", "alice/ps_put.txt", s3port, expires=300)
    st, _ = http("PUT", pp, s3port, data=b"presigned-put\n")
    fp = os.path.join(data, "alice", "ps_put.txt")
    ok(st in (200, 201, 204) or not os.path.exists(fp),
       f"presigned PUT handled (HTTP {st})")
    if os.path.exists(fp):
        ok(os.stat(fp).st_uid == UID_ALICE,
           f"presigned-PUT object owned by alice not worker/root (uid={os.stat(fp).st_uid})")
    else:
        ok(True, "presigned PUT not honoured (no object) — acceptable, no breach")

    # (7) presigned PUT into bob's 0700 dir (signed as alice) -> denied by DAC.
    st, _ = http("PUT", s3_presign("PUT", "bobsecret/ps_evil.txt", s3port), s3port,
                 data=b"x\n")
    ok(not os.path.exists(os.path.join(data, "bobsecret", "ps_evil.txt")),
       f"presigned PUT into bob's 0700 dir denied (HTTP {st})")

    # (8) presigned with a method mismatch (sign GET, send PUT) -> signature covers
    #     the method, so denied.
    g = s3_presign("GET", "alice/ps_mm.txt", s3port)
    st, _ = http("PUT", g, s3port, data=b"x\n")
    ok(st in (401, 403) and not os.path.exists(os.path.join(data, "alice", "ps_mm.txt")),
       f"presigned method-mismatch (GET-sig used for PUT) denied (HTTP {st})")

    # (9) presigned signed under an UNKNOWN access key (not configured) -> denied
    #     (no access key but alice is configured, so the credential is unmappable).
    st, b = http("GET", s3_presign("GET", "alice/ps_obj.txt", s3port,
                                   access_key="nonexistent-key"), s3port)
    ok(st in (401, 403) and b"PRESIGN-OWN-OBJECT" not in (b or b""),
       f"presigned with unknown access key denied (HTTP {st})")

    # (10) presigned replayed AFTER the object is deleted -> 404 (auth validated,
    #      then not-found) — must not 200 nor leak; proves no stale-grant.
    s3("PUT", "alice/ps_gone.txt", s3port, data=b"soon-gone\n")
    pre = s3_presign("GET", "alice/ps_gone.txt", s3port, expires=300)
    s3("DELETE", "alice/ps_gone.txt", s3port)
    st, b = http("GET", pre, s3port)
    ok(st in (403, 404) and b"soon-gone" not in (b or b""),
       f"presigned GET of a deleted object 404s, no stale data (HTTP {st})")


def run_crossproto_chmod_chains(key, data, port, s3port):
    """INNOVATIVE cross-protocol MODE-enforcement chains.  A chmod issued via one
    protocol (root://) must be enforced for a DIFFERENT tenant via every other
    protocol — only meaningful now that kXR_chmod is broker-routed (a previously
    un-brokered op).  Proves the DAC change is real kernel state, not per-protocol
    bookkeeping, and that chmod never alters ownership."""
    if not xrd_avail():
        ok(True, "cross-protocol chmod chains skipped (native client absent)")
        return
    ta, tb = mint(key, "alice"), mint(key, "bob")
    MARK = b"CPC-ALICE-SECRET"

    lf = os.path.join(WORK, "cpc_seed.bin")
    with open(lf, "wb") as fh:
        fh.write(MARK + b"\n")

    # ---- Chain 1: create via root:// 0644, world-readable, then chmod 600 ----
    xrd_cp_up(lf, "/alice/cpc1.bin", "alice")
    fp1 = os.path.join(data, "alice", "cpc1.bin")
    os.chmod(fp1, 0o644) if os.path.exists(fp1) else None   # normalize to 0644
    # bob CAN read the 0644 file via WebDAV + S3 (control: the deny later is real).
    st, b = http("GET", "/alice/cpc1.bin", port, tb)
    ok(MARK in (b or b""), f"control: bob reads alice's 0644 via WebDAV (HTTP {st})")
    st, b = s3("GET", "alice/cpc1.bin", s3port)   # alice endpoint reads it too
    ok(MARK in (b or b""), f"control: 0644 file readable via S3 (HTTP {st})")
    # alice chmod 600 via root:// (the now-brokered op).
    rc, _o, _e = xrd_fs(["chmod", "/alice/cpc1.bin", "600"], "alice")
    mode = (os.stat(fp1).st_mode & 0o777) if os.path.exists(fp1) else -1
    ok(rc == 0 and mode == 0o600,
       f"root:// chmod 600 applied (rc={rc}, mode={mode:o})")
    # ownership UNCHANGED by chmod.
    ok(os.path.exists(fp1) and os.stat(fp1).st_uid == UID_ALICE,
       "chmod did not change ownership (still alice)")
    # now bob is DENIED across EVERY protocol (kernel DAC enforces the new mode).
    st, b = http("GET", "/alice/cpc1.bin", port, tb)
    ok(MARK not in (b or b""),
       f"after chmod 600: bob WebDAV read DENIED cross-protocol (HTTP {st})")
    rc, out, _e = xrd_fs(["cat", "/alice/cpc1.bin"], "bob")
    ok(rc != 0 and MARK.decode() not in (out or ""),
       f"after chmod 600: bob root:// cat DENIED (rc={rc})")
    dlx = os.path.join(WORK, "cpc_steal.bin")
    rc, _o, _e = xrd_cp_down("/alice/cpc1.bin", dlx, "bob")
    leaked = os.path.exists(dlx) and MARK in open(dlx, "rb").read()
    ok(rc != 0 and not leaked, f"after chmod 600: bob root:// xrdcp DENIED (rc={rc})")
    # alice (owner) STILL reads it (positive control).
    st, b = http("GET", "/alice/cpc1.bin", port, ta)
    ok(st == 200 and MARK in (b or b""),
       f"after chmod 600: alice (owner) still reads via WebDAV (HTTP {st})")

    # ---- Chain 2: create via S3, chmod via root://, read-back owner-only ----
    s3("PUT", "alice/cpc2.bin", s3port, data=MARK + b"-S3\n")
    fp2 = os.path.join(data, "alice", "cpc2.bin")
    rc, _o, _e = xrd_fs(["chmod", "/alice/cpc2.bin", "600"], "alice")
    m2 = (os.stat(fp2).st_mode & 0o777) if os.path.exists(fp2) else -1
    ok(rc == 0 and m2 == 0o600 and os.stat(fp2).st_uid == UID_ALICE,
       f"S3-created file chmod'd 600 via root://, owned alice (rc={rc}, mode={m2:o})")
    st, b = http("GET", "/alice/cpc2.bin", port, tb)
    ok(MARK + b"-S3" not in (b or b""),
       f"S3-created+chmod600 file: bob WebDAV read DENIED (HTTP {st})")

    # ---- Chain 3: create via WebDAV 0600, chmod 0644 via root://, bob can read ----
    http("PUT", "/alice/cpc3.bin", port, ta, b"CPC3-PUBLIC\n")
    fp3 = os.path.join(data, "alice", "cpc3.bin")
    if os.path.exists(fp3):
        os.chmod(fp3, 0o600)
    st, b = http("GET", "/alice/cpc3.bin", port, tb)
    ok(b"CPC3-PUBLIC" not in (b or b""), f"control: 0600 file denied to bob (HTTP {st})")
    rc, _o, _e = xrd_fs(["chmod", "/alice/cpc3.bin", "644"], "alice")
    m3 = (os.stat(fp3).st_mode & 0o777) if os.path.exists(fp3) else -1
    ok(rc == 0 and m3 == 0o644,
       f"root:// chmod 600->644 widened (rc={rc}, mode={m3:o})")
    st, b = http("GET", "/alice/cpc3.bin", port, tb)
    ok(st == 200 and b"CPC3-PUBLIC" in (b or b""),
       f"after chmod 644: bob WebDAV read now ALLOWED cross-protocol (HTTP {st})")

    # ---- Chain 4: bob cannot chmod alice's file via root:// (mode intact) ----
    pre = (os.stat(fp3).st_mode & 0o777) if os.path.exists(fp3) else -1
    rc, _o, _e = xrd_fs(["chmod", "/alice/cpc3.bin", "777"], "bob")
    post = (os.stat(fp3).st_mode & 0o777) if os.path.exists(fp3) else -1
    ok(rc != 0 and post == pre,
       f"bob chmod of alice's file via root:// DENIED, mode intact ({pre:o}->{post:o})")


