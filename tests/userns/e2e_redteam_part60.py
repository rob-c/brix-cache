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


def run_header_injection_matrix(key, data, port, s3port):
    """HEADER / CRLF / HOST / DESTINATION / COPY-SOURCE injection matrix under
    impersonation.  Distinct from the malformed/http-abuse/confinement batches: those
    cover encoded-CRLF-in-PATH, NUL-in-header, dup-Host(relative-URI), absolute-URI to a
    foreign host, oversized header VALUE/COUNT, and CLEAN Destination/copy-source DAC
    denials.  HERE the payload lives in the Destination: / x-amz-copy-source: VALUE and
    in the response-header surface: CRLF response-splitting, cross-host + traversal +
    percent-encoded-CRLF in COPY/MOVE/CopyObject (verified byte-for-byte on bob's 0600
    file on disk), Host-header confusion (missing / mismatched-on-absolute-URI / two
    Host on an absolute-URI line), obs-fold continuation, NUL in a header value other
    than the smuggle-classic, oversized request TARGET (not header), Expect:100-continue
    with no body, Connection-header games, and DUPLICATE auth (Bearer + SigV4 together).
    Every case: no response-splitting/reflection, no escape, no cross-tenant mutation,
    worker survives."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    H = "%s:%d" % (HOST, port)
    BOB = b"BOB-PRIVATE-SECRET"
    bpriv = os.path.join(data, "bob", "private.txt")
    outside = os.path.join(os.path.dirname(data), "HIM_ESCAPE_SENTINEL")

    # baseline snapshot of bob's 0600 file (just restored by _reset_fixtures): every
    # Destination/copy-source injection below must leave it byte-identical on disk.
    try:
        bob0 = open(bpriv, "rb").read()
        bst0 = os.stat(bpriv)
    except OSError:
        bob0, bst0 = None, None

    def bob_untouched():
        if bob0 is None:
            return True
        try:
            s = os.stat(bpriv)
            return (open(bpriv, "rb").read() == bob0 and s.st_uid == bst0.st_uid
                    and (s.st_mode & 0o777) == (bst0.st_mode & 0o777))
        except OSError:
            return False

    def no_split(resp):
        # a response must contain at most ONE status line and never reflect our marker
        # as a header (response-splitting / header-injection).
        r = resp or b""
        return (r.count(b"HTTP/1.") <= 1 and b"X-Injected" not in r
                and b"x-injected" not in r and b"HIM-SPLIT" not in r)

    def status(resp):
        m = re.match(rb"HTTP/1\.[01] (\d{3})", resp or b"")
        return int(m.group(1)) if m else -1

    def worker_alive(tag):
        st, b = http("GET", "/alice/him_probe.txt", port, ta)
        # the probe file is (re)created just below; survival = a clean own round-trip.
        ok(st in (200, 201, 204, 404) and b"BOB-PRIVATE-SECRET" not in (b or b""),
           "worker survived %s (follow-up alice GET HTTP %s)" % (tag, st))

    # seed an own file used as a benign COPY/MOVE source (so a "valid source" can't
    # be the reason a copy is refused -- only the malicious Destination is).
    http("PUT", "/alice/him_src.txt", port, ta, b"HIM-COPY-SOURCE-BODY\n")
    http("PUT", "/alice/him_probe.txt", port, ta, b"HIM-PROBE\n")

    # ============================================================ Destination: CRLF ===
    # CRLF injected INTO the Destination header value: must not split the response and
    # must not create a file at the smuggled tail.  raw_http (urllib would reject \r\n).
    dst_crlf = (b"COPY /alice/him_src.txt HTTP/1.1\r\nHost: " + H.encode()
                + b"\r\nAuthorization: Bearer " + ta.encode()
                + b"\r\nDestination: http://" + H.encode()
                + b"/alice/him_crlf.txt\r\nX-Injected: HIM-SPLIT\r\n"
                + b"Connection: close\r\n\r\n")
    resp = raw_http(dst_crlf, port)
    ok(no_split(resp),
       "Destination CRLF: no response-split / no injected header reflected (HTTP %s)"
       % status(resp))

    # percent-encoded CRLF (%0d%0a) inside Destination value -- urllib accepts the
    # literal percents; server must NOT decode them into a real header split, and the
    # weird target must not land outside alice.
    st, _ = http("COPY", "/alice/him_src.txt", port, ta,
                 hdrs={"Destination":
                       "http://%s/alice/him_pe%%0d%%0aX-Injected:%%201.txt" % H})
    ok(not os.path.exists(outside) and bob_untouched(),
       "Destination percent-encoded-CRLF: no escape, bob 0600 untouched (HTTP %s)" % st)

    # ====================================================== Destination: cross-host ===
    # Destination authority pointing at a FOREIGN host (COPY): the server must confine
    # to its own export (treat as same-export path or reject) -- never proxy-write off
    # box and never mutate bob.
    st, _ = http("COPY", "/alice/him_src.txt", port, ta,
                 hdrs={"Destination": "http://evil.example:9999/bob/private.txt"})
    ok(bob_untouched() and not os.path.exists(outside),
       "Destination cross-host authority COPY: bob's 0600 NOT overwritten (HTTP %s)"
       % st)

    # Destination scheme/host pointing at bob's file (same host) via COPY of alice's
    # own readable source -- the WRITE leg runs as alice -> EACCES on bob's dir/file.
    st, _ = http("COPY", "/alice/him_src.txt", port, ta,
                 hdrs={"Destination": "http://%s/bob/private.txt" % H})
    ok(st not in (200, 201, 204) and bob_untouched(),
       "Destination -> bob/private.txt: alice COPY DENIED, secret unchanged (HTTP %s)"
       % st)

    # ====================================================== Destination: traversal ===
    # ../ traversal in the Destination path must not write outside the export root.
    for dval, tag in [
        ("http://%s/../HIM_ESCAPE_SENTINEL" % H, "../-after-host"),
        ("http://%s/alice/../../HIM_ESCAPE_SENTINEL" % H, "deep-../"),
        ("/../HIM_ESCAPE_SENTINEL", "path-only-../"),
    ]:
        st, _ = http("COPY", "/alice/him_src.txt", port, ta, hdrs={"Destination": dval})
        ok(not os.path.exists(outside),
           "Destination traversal (%s) blocked, no file outside export (HTTP %s)"
           % (tag, st))

    # MOVE with a traversal Destination must neither escape NOR consume the source.
    st, _ = http("MOVE", "/alice/him_src.txt", port, ta,
                 hdrs={"Destination": "http://%s/../HIM_ESCAPE_SENTINEL" % H})
    ok(not os.path.exists(outside)
       and os.path.exists(os.path.join(data, "alice", "him_src.txt")),
       "MOVE traversal Destination: no escape, source intact (HTTP %s)" % st)
    worker_alive("destination-injection")

    # =========================================================== Host-header attacks ===
    # (a) MISSING Host on HTTP/1.1 -> 400 (nginx requires it); no leak.
    miss = (b"GET /bob/private.txt HTTP/1.1\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(miss, port)
    ok(BOB not in (resp or b"") and no_split(resp),
       "missing Host (HTTP/1.1): no bob leak, handled (HTTP %s)" % status(resp))

    # (b) absolute-URI request line with a Host header that MISMATCHES the URI
    #     authority -- must still confine to the local export; bob never leaks.
    mism = (b"GET http://evil.example/alice/him_probe.txt HTTP/1.1\r\nHost: "
            + H.encode() + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(mism, port)
    ok(BOB not in (resp or b""),
       "absolute-URI + mismatched Host: no bob leak (HTTP %s)" % status(resp))

    # (c) TWO Host headers on an absolute-URI line -> ambiguous authority must 400 /
    #     not be resolved into a foreign read of bob.
    two = (b"GET http://" + H.encode() + b"/alice/him_probe.txt HTTP/1.1\r\nHost: "
           + H.encode() + b"\r\nHost: evil.example\r\nAuthorization: Bearer "
           + ta.encode() + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(two, port)
    ok(BOB not in (resp or b"") and no_split(resp),
       "two Host headers on absolute-URI: handled, no leak (HTTP %s)" % status(resp))

    # =========================================================== obs-fold continuation ==
    # obsolete line-folding (a header continued on a folded line) is forbidden by
    # RFC7230; nginx must reject (400) or not honour the fold as an Authorization, and
    # certainly must not fold a smuggled Authorization granting bob.
    fold = (b"GET /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nX-Fold: value\r\n\tAuthorization: Bearer " + tb.encode()
            + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(fold, port)
    ok(BOB not in (resp or b"") and no_split(resp),
       "obs-fold header continuation: folded Authorization not honoured, no leak "
       "(HTTP %s)" % status(resp))

    # ============================================================ NUL in header value ===
    # NUL inside the Authorization VALUE (distinct from the X-Evil NUL the malformed
    # batch tests): must not be truncated into a valid bearer that reads bob.
    nul = (b"GET /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nAuthorization: Bearer " + ta.encode()
           + b"\x00 extra\r\nConnection: close\r\n\r\n")
    resp = raw_http(nul, port)
    ok(BOB not in (resp or b""),
       "NUL in Authorization value: not truncated into a granting token (HTTP %s)"
       % status(resp))

    # ============================================================ oversized request TARGET
    # an oversized request TARGET (URI), not a header value (the malformed batch did a
    # 24KB header VALUE; http-abuse did a 200-header COUNT) -> 414 / 400, no crash.
    big_uri = (b"GET /alice/" + b"A" * 18000 + b" HTTP/1.1\r\nHost: " + H.encode()
               + b"\r\nAuthorization: Bearer " + ta.encode()
               + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(big_uri, port)
    ok(status(resp) in (414, 400, 404, 494, -1) or status(resp) >= 400,
       "oversized request TARGET rejected (HTTP %s)" % status(resp))

    # ============================================================ Expect: 100-continue ==
    # Expect:100-continue with NO following body on a PUT: the worker must not hang
    # forever waiting and must not create an alice file from a body that never came.
    exp = (b"PUT /alice/him_expect.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nAuthorization: Bearer " + ta.encode()
           + b"\r\nExpect: 100-continue\r\nContent-Length: 10\r\n"
           + b"Connection: close\r\n\r\n")
    resp = raw_send_steps([(exp, 1.2)], port, read_timeout=3.0)
    expfp = os.path.join(data, "alice", "him_expect.txt")
    expbad = os.path.exists(expfp) and os.stat(expfp).st_uid != UID_ALICE
    ok(not expbad and no_split(resp),
       "Expect:100-continue then no body: no hang/desync, no svc/root file "
       "(HTTP %s)" % status(resp))

    # ============================================================ Connection-header games
    # a Connection header that names a hop-by-hop header to strip (Connection:
    # Authorization) must NOT cause the server to drop Authorization and then serve
    # bob's file unauthenticated.
    conn = (b"GET /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nConnection: Authorization, close\r\n\r\n")
    resp = raw_http(conn, port)
    ok(BOB not in (resp or b""),
       "Connection: Authorization (strip-auth game): no anonymous bob read (HTTP %s)"
       % status(resp))
    worker_alive("host-conn-games")

    # ============================================================ DUPLICATE auth ========
    # Bearer (alice) AND a SigV4 Authorization in ONE WebDAV request: the server must
    # pick ONE scheme deterministically and never both-grant.  Whatever it picks, a
    # read of bob's 0600 must be denied (alice has no DAC; SigV4 here is malformed for
    # the WebDAV endpoint anyway) and bob's file is never mutated.  urllib collapses
    # duplicate header names, so forge BOTH an AWS4 line and a Bearer line on a raw
    # socket to actually present dual auth.
    sig = s3_sign("GET", "/%s/bob/private.txt" % S3_BUCKET, port)["Authorization"]
    dual = (b"GET /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nAuthorization: " + sig.encode()
            + b"\r\nConnection: close\r\n\r\n")
    resp = raw_http(dual, port)
    ok(BOB not in (resp or b""),
       "dual Bearer+SigV4 Authorization (WebDAV): never both-grant, bob denied "
       "(HTTP %s)" % status(resp))
    ok(bob_untouched(),
       "after dual-auth WebDAV probe: bob's 0600 unchanged on disk")

    # ==================================================================== S3 copy-source
    if s3port:
        # x-amz-copy-source with CRLF injected: CopyObject source-read runs as the
        # signer (alice); the CRLF must not split / inject and bob must not be touched.
        st, _ = s3("PUT", "alice/him_cs1.bin", s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/bob/private.txt\r\nX-Injected: HIM-SPLIT"
                               % S3_BUCKET})
        ok(st not in (200, 201) and bob_untouched()
           and not os.path.exists(os.path.join(data, "alice", "him_cs1.bin")),
           "S3 copy-source CRLF: rejected, bob untouched, no alice artifact (HTTP %s)"
           % st)

        # x-amz-copy-source with ../ traversal into /etc -- must not read /etc/passwd
        # nor escape the export.
        st, b = s3("PUT", "alice/him_cs2.bin", s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/../../../../etc/passwd" % S3_BUCKET})
        ok(b"root:x:0:0" not in (b or b"")
           and not os.path.exists(os.path.join(data, "alice", "him_cs2.bin")),
           "S3 copy-source ../etc/passwd traversal: no leak, no artifact (HTTP %s)"
           % st)

        # x-amz-copy-source pointing at a DIFFERENT bucket name (cross-bucket authority)
        # -- with only one bucket configured this must not resolve to a host path.
        st, _ = s3("PUT", "alice/him_cs3.bin", s3port,
                   extra_hdrs={"x-amz-copy-source": "/otherbucket/bob/private.txt"})
        ok(bob_untouched()
           and not os.path.exists(os.path.join(data, "alice", "him_cs3.bin")),
           "S3 copy-source foreign-bucket: no cross-bucket read, bob untouched "
           "(HTTP %s)" % st)

        # DUPLICATE auth on S3: a valid SigV4 line AND a Bearer line -- the S3 endpoint
        # must authenticate via SigV4 only and never let the Bearer escalate; a GET of
        # bob's 0600 stays denied.
        sg = dict(s3_sign("GET", "/%s/bob/private.txt" % S3_BUCKET, s3port))
        sg["X-Bearer-Smuggle"] = "Bearer %s" % tb   # bob bearer as a side header
        st, b = http("GET", "/%s/bob/private.txt" % S3_BUCKET, s3port, hdrs=sg)
        ok(st not in (200,) and BOB not in (b or b""),
           "S3 SigV4(alice) + smuggled bob-bearer: no escalation, bob denied (HTTP %s)"
           % st)
        worker_alive("s3-copy-source")
    else:
        ok(True, "S3 copy-source / dual-auth injection skipped (no s3port)")

    # final: bob's protected file survived the ENTIRE matrix byte-for-byte.
    ok(bob_untouched(),
       "FINAL: bob's 0600 private.txt byte-identical + 0600 after full injection matrix")


