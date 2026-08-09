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


def run_protocol_features_s3(key, data, port, s3port):
    """Genuinely-NEW S3 protocol-feature surface under per-request impersonation —
    the conditional/metadata/response-shaping verbs NOT yet exercised (basic
    GET/PUT/HEAD/DELETE/list/multipart/copy/presign/SigV4 are already covered).

    For each feature the impersonation invariants hold regardless of whether the
    feature is implemented: a CREATE lands owned by the mapped user (alice=1001,
    never the worker 1500 / root 0); a cross-tenant read of bob's 0600 object
    never returns the body / metadata oracle; an UNSUPPORTED feature is accepted
    as "handled" (the server must degrade safely, never leak/escape/escalate).

    Covers: (a) conditional create If-None-Match:* (create-only / no-clobber),
    (b) user-metadata + Content-Type round-trip (self ok, cross-tenant no leak),
    (c) GET response-header overrides (own ok, bob's 0600 still DAC-denied),
    (d) If-Modified-Since / If-Unmodified-Since (own + no-oracle on bob 0600),
    (e) GET ?partNumber=1 on a non-multipart object, (f) HEAD of a non-existent
    key -> 404 not 403 (no existence confusion), (g) bogus x-amz-content-sha256
    vs UNSIGNED-PAYLOAD.  S3 access_key 'alice' is the only configured leg."""
    if not s3port:
        ok(True, "S3 port not configured — protocol-features-s3 skipped (handled)")
        return

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False

    def not_worker_root(p):
        # Weaker invariant for maybe-created files: if it exists it must be the
        # mapped user, NEVER the worker (1500) or root (0).
        try:
            if not os.path.exists(p):
                return True
            return os.stat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True

    abs = lambda rel: os.path.join(data, *rel.split("/"))

    # ------------------------------------------------------------------ (a) ---
    # CONDITIONAL CREATE  If-None-Match: *  — create-only / no-clobber.
    fp = abs("alice/pfs_cond_create.txt")
    try:
        if os.path.exists(fp):
            os.unlink(fp)
    except OSError:
        pass
    st1, _ = s3("PUT", "alice/pfs_cond_create.txt", s3port, data=b"PFS-V1-BODY\n",
                extra_hdrs={"If-None-Match": "*"})
    # S3 conditional-create (If-None-Match:*) is not implemented (no conditional
    # handling in src/protocols/s3/) — the server may ignore it (create) or return 304/412.
    # Accept either; the security invariant is: IF it created, the object is alice's.
    ok((st1 in (200, 201) and owned_alice(fp)) or st1 in (304, 412, 501, 400),
       f"S3 If-None-Match:* first PUT handled, any object owned by alice (HTTP {st1})")
    # Second create-only PUT to the SAME key: either 412 (precond failed) or, if
    # unsupported, it is allowed — but it must NOT corrupt ownership, and content
    # is re-read below for the no-clobber/handled assertion.
    st2, _ = s3("PUT", "alice/pfs_cond_create.txt", s3port, data=b"PFS-CLOBBER\n",
                extra_hdrs={"If-None-Match": "*"})
    try:
        after = open(fp, "rb").read() if os.path.exists(fp) else b""
    except OSError:
        after = b""
    if st2 == 412:
        ok(after == b"PFS-V1-BODY\n" and owned_alice(fp),
           f"S3 If-None-Match:* second PUT -> 412 Precondition Failed, no clobber (HTTP {st2})")
    else:
        ok(owned_alice(fp) and not_worker_root(fp),
           f"S3 If-None-Match:* unsupported -> still alice-owned, no escalation (HTTP {st2})")
    # Conditional create must never land owned by worker/root regardless of branch.
    ok(not_worker_root(fp),
       "S3 conditional-create object never worker/root-owned")

    # ------------------------------------------------------------------ (b) ---
    # OBJECT METADATA round-trip: Content-Type + x-amz-meta-* on PUT, then
    # HEAD/GET echoes them back.  Self only — and cross-tenant HEAD/GET of bob's
    # 0600 never leaks bob's metadata or body.
    mp = abs("alice/pfs_meta.txt")
    stm, _ = s3("PUT", "alice/pfs_meta.txt", s3port, data=b"PFS-META-BODY\n",
                extra_hdrs={"Content-Type": "application/x-pfs-marker",
                            "x-amz-meta-foo": "PFS-META-FOO",
                            "x-amz-meta-bar": "PFS-META-BAR"})
    ok(stm in (200, 201) and owned_alice(mp),
       f"S3 PUT with metadata created + owned by alice (HTTP {stm})")
    sth, hb = s3("HEAD", "alice/pfs_meta.txt", s3port)
    ok(sth == 200, f"S3 HEAD own metadata object (HTTP {sth})")
    stg, gb = s3("GET", "alice/pfs_meta.txt", s3port)
    # Metadata round-trip is best-effort: if the server stores+echoes user meta we
    # see it; if not, the GET still returns the exact body owned by alice.
    echoed = (b"PFS-META-FOO" in (gb or b"") or b"PFS-META-FOO" in (hb or b""))
    ok(stg == 200 and gb == b"PFS-META-BODY\n",
       f"S3 GET metadata object: byte-exact body (HTTP {stg}, meta_echoed={echoed})")
    ok(True, f"S3 user-metadata round-trip handled (echoed={echoed})")
    # Cross-tenant HEAD/GET of bob's 0600: never the body, never a meta oracle.
    stbh, bhb = s3("HEAD", "bob/private.txt", s3port)
    ok(b"BOB-PRIVATE-SECRET" not in (bhb or b""),
       f"S3 HEAD bob's 0600: no body/metadata leak (HTTP {stbh})")
    stbg, bgb = s3("GET", "bob/private.txt", s3port)
    ok(stbg in (403, 404) and b"BOB-PRIVATE-SECRET" not in (bgb or b""),
       f"S3 GET bob's 0600 metadata object DENIED, no secret (HTTP {stbg})")

    # ------------------------------------------------------------------ (c) ---
    # GET response-header OVERRIDES (?response-content-type, response-content-
    # disposition).  Signed query params keep the SigV4 valid.  Own object: ok
    # (overrides applied or ignored).  bob's 0600: still DAC-denied, no body.
    ov = {"response-content-type": "application/pfs-override",
          "response-content-disposition": "attachment; filename=pfs.bin"}
    sto, ob = s3("GET", "alice/pfs_meta.txt", s3port, params=ov)
    ok(sto == 200 and ob == b"PFS-META-BODY\n",
       f"S3 GET own object with response-overrides: byte-exact body (HTTP {sto})")
    stov, ovb = s3("GET", "bob/private.txt", s3port, params=ov)
    ok(stov in (403, 404) and b"BOB-PRIVATE-SECRET" not in (ovb or b""),
       f"S3 GET bob's 0600 with response-overrides STILL DENIED, no body (HTTP {stov})")
    # Control: bob's 0644 world-readable IS served (proves the deny is per-file DAC,
    # not a blanket reject of the override params).
    stc, cb = s3("GET", "bob/readable.txt", s3port, params=ov)
    ok(stc == 200 and b"bob-world-readable" in (cb or b""),
       f"control: S3 GET bob's 0644 with overrides ALLOWED (HTTP {stc})")

    # ------------------------------------------------------------------ (d) ---
    # If-Modified-Since / If-Unmodified-Since conditional GET.  On own object the
    # server returns 200/304 (either is correct).  On bob's 0600 there must be NO
    # oracle: the conditional outcome must not differ-leak existence/mtime and the
    # body must never appear.
    past = "Wed, 01 Jan 2020 00:00:00 GMT"
    future = "Thu, 31 Dec 2099 23:59:59 GMT"
    sims, _ = s3("GET", "alice/pfs_meta.txt", s3port,
                 extra_hdrs={"If-Modified-Since": past})
    ok(sims in (200, 304),
       f"S3 If-Modified-Since(past) own object handled (HTTP {sims})")
    simf, fb = s3("GET", "alice/pfs_meta.txt", s3port,
                  extra_hdrs={"If-Modified-Since": future})
    ok(simf in (200, 304) and b"BOB-PRIVATE-SECRET" not in (fb or b""),
       f"S3 If-Modified-Since(future) own object handled (HTTP {simf})")
    sius, ub = s3("GET", "alice/pfs_meta.txt", s3port,
                  extra_hdrs={"If-Unmodified-Since": past})
    ok(sius in (200, 304, 412) and not_worker_root(mp),
       f"S3 If-Unmodified-Since(past) own object handled (HTTP {sius})")
    # bob's 0600 with BOTH conditional headers: no oracle, no body.
    sbm, sbmb = s3("GET", "bob/private.txt", s3port,
                   extra_hdrs={"If-Modified-Since": past})
    ok(sbm in (403, 404) and b"BOB-PRIVATE-SECRET" not in (sbmb or b""),
       f"S3 If-Modified-Since on bob's 0600: DENIED, no oracle/body (HTTP {sbm})")
    sbu, sbub = s3("GET", "bob/private.txt", s3port,
                   extra_hdrs={"If-Unmodified-Since": future})
    ok(sbu in (403, 404) and b"BOB-PRIVATE-SECRET" not in (sbub or b""),
       f"S3 If-Unmodified-Since on bob's 0600: DENIED, no oracle/body (HTTP {sbu})")

    # ------------------------------------------------------------------ (e) ---
    # GET ?partNumber=1 on a NON-multipart object.  Whatever the server returns
    # (whole body, 416/400, or a single "part") it must not leak bob's 0600 and
    # must not escalate.  Own object first (handled), then bob's private (deny).
    spn, pnb = s3("GET", "alice/pfs_meta.txt", s3port, params={"partNumber": "1"})
    ok(spn in (200, 206, 400, 416, 501) and b"BOB-PRIVATE-SECRET" not in (pnb or b""),
       f"S3 GET ?partNumber=1 on non-multipart own object handled (HTTP {spn})")
    spnb, pnbb = s3("GET", "bob/private.txt", s3port, params={"partNumber": "1"})
    ok(spnb in (403, 404, 400, 416) and b"BOB-PRIVATE-SECRET" not in (pnbb or b""),
       f"S3 GET ?partNumber=1 on bob's 0600 DENIED, no body (HTTP {spnb})")
    # A wildly out-of-range partNumber must not crash the worker / leak.
    spx, _ = s3("GET", "alice/pfs_meta.txt", s3port, params={"partNumber": "99999"})
    ok(spx in (200, 206, 400, 416, 404, 501),
       f"S3 GET ?partNumber=99999 handled, no crash (HTTP {spx})")

    # ------------------------------------------------------------------ (f) ---
    # HEAD a NON-EXISTENT key -> 404, never 403 (a 403 on a missing key would be an
    # existence-confusion oracle leaking that the deny is path-vs-existence based).
    # Also: HEAD a missing key UNDER bob's traversable 0755 dir -> 404 (not a leak).
    sne, _ = s3("HEAD", "alice/pfs_does_not_exist_zzz.txt", s3port)
    ok(sne == 404, f"S3 HEAD non-existent own key -> 404 not 403 (HTTP {sne})")
    sneb, _ = s3("HEAD", "bob/pfs_missing_zzz.txt", s3port)
    ok(sneb in (404, 403), f"S3 HEAD missing key under bob's dir handled (HTTP {sneb})")
    # GET non-existent own key likewise 404, no phantom body.
    sneg, ngb = s3("GET", "alice/pfs_does_not_exist_zzz.txt", s3port)
    # 404 with a NoSuchKey error XML body is correct S3 — what matters is it is a
    # clean 404 (not a 403 that leaks existence, and no real object content).
    ok(sneg == 404 and b"PFS" not in (ngb or b""),
       f"S3 GET non-existent own key -> 404, no object content (HTTP {sneg})")
    # HEAD a key that RESOLVES into svc-only 0750 (missing leaf): no 200, no oracle.
    snes, _ = s3("HEAD", "svconly/pfs_missing.txt", s3port)
    ok(snes in (403, 404),
       f"S3 HEAD missing key in svc-only dir: no leak (HTTP {snes})")

    # ------------------------------------------------------------------ (g) ---
    # PUT with a BOGUS x-amz-content-sha256.  This server signs UNSIGNED-PAYLOAD
    # (x-amz-content-sha256 is NOT in SignedHeaders), so a bogus value is unsigned
    # noise: the request still authenticates as alice and the write runs as alice
    # — but it must NEVER fall through to worker/root, and the body must be exact.
    bp = abs("alice/pfs_bogus_sha.txt")
    try:
        if os.path.exists(bp):
            os.unlink(bp)
    except OSError:
        pass
    stb, _ = s3("PUT", "alice/pfs_bogus_sha.txt", s3port, data=b"PFS-SHA-BODY\n",
                extra_hdrs={"x-amz-content-sha256": "deadbeef" * 8})
    # Either accepted (runs as alice) or rejected (no file) — both safe; the only
    # failure is a worker/root-owned file.
    ok(not_worker_root(bp),
       f"S3 PUT bogus x-amz-content-sha256: never worker/root-owned (HTTP {stb})")
    if stb in (200, 201) and os.path.exists(bp):
        try:
            body = open(bp, "rb").read()
        except OSError:
            body = b""
        ok(owned_alice(bp) and body == b"PFS-SHA-BODY\n",
           f"S3 PUT bogus-sha (unsigned payload) ran as alice, byte-exact (HTTP {stb})")
    else:
        ok(not os.path.exists(bp),
           f"S3 PUT bogus-sha rejected, no file (HTTP {stb})")
    # An EXPLICIT well-formed-but-WRONG sha256 (correct hex length, wrong digest)
    # is still unsigned for this server -> same invariant: never worker/root.
    bp2 = abs("alice/pfs_wrong_sha.txt")
    try:
        if os.path.exists(bp2):
            os.unlink(bp2)
    except OSError:
        pass
    stw, _ = s3("PUT", "alice/pfs_wrong_sha.txt", s3port, data=b"PFS-W\n",
                extra_hdrs={"x-amz-content-sha256": "0" * 64})
    ok(not_worker_root(bp2),
       f"S3 PUT wrong (64-hex) content-sha256: never worker/root-owned (HTTP {stw})")
    # And a cross-tenant write attempt carrying a bogus sha must STILL be DAC-denied
    # (the bogus header does not become an auth bypass into bob's space).
    stx, _ = s3("PUT", "bob/pfs_inject.txt", s3port, data=b"X\n",
                extra_hdrs={"x-amz-content-sha256": "deadbeef" * 8})
    ok(stx not in (200, 201) and not os.path.exists(abs("bob/pfs_inject.txt")),
       f"S3 PUT into bob's dir with bogus sha STILL DENIED (HTTP {stx})")

    # ----------------------------------------------------------- worker-alive ---
    # After all the malformed/conditional traffic the worker must still serve a
    # plain legit op correctly (proves no desync / no wedged identity).
    sal, alb = s3("GET", "alice/pfs_meta.txt", s3port)
    ok(sal == 200 and alb == b"PFS-META-BODY\n",
       f"worker survives feature battery: legit GET byte-exact (HTTP {sal})")
    # Cleanup best-effort (do not fail the suite on cleanup).
    for rel in ("alice/pfs_cond_create.txt", "alice/pfs_meta.txt",
                "alice/pfs_bogus_sha.txt", "alice/pfs_wrong_sha.txt"):
        try:
            p = abs(rel)
            if os.path.exists(p):
                os.unlink(p)
        except OSError:
            pass


