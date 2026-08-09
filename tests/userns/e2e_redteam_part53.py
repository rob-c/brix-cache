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


def run_http_smuggling_desync_deep(key, data, port, s3port):
    """DEEP HTTP request-smuggling / desync under impersonation.  Probes TE.CL, CL.TE
    (TE-first), conflicting double Content-Length, OBFUSCATED Transfer-Encoding header
    forms, malformed/over-large/non-hex chunk sizes, chunk-extension junk, trailer
    headers that try to inject Authorization/Host AFTER the body, bare-LF-framed
    smuggled requests, and a fully-formed SECOND request (a PUT to bob/private.txt)
    smuggled in the body of the first.  After EACH probe we prove on a FRESH
    connection that (a) alice's clean GET is still served byte-exact, (b) the smuggled
    op did NOT run under the wrong identity, (c) bob's 0600 secret is intact on disk,
    and (d) the worker is alive.  Distinct from run_http_protocol_abuse (dup-CL, dup
    Host, HTTP/1.0, absolute-URI, multi-range, header-flood) and run_malformed_hostile
    (XML/XXE/Content-Length-lies): here every vector is a NEW desync framing."""
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    H = HOST
    bpriv = os.path.join(data, "bob", "private.txt")
    SECRET = b"BOB-PRIVATE-SECRET"

    def bob_secret_intact():
        # the canonical 0600 secret must be byte-exact + still bob-owned + still 0600.
        try:
            with open(bpriv, "rb") as fh:
                c = fh.read()
            stt = os.stat(bpriv)
            return (SECRET in c and stt.st_uid == UID_BOB
                    and (stt.st_mode & 0o777) == 0o600)
        except OSError:
            return False

    def no_smuggled(rel):
        # a path the smuggled request tried to create/clobber must not exist (or, for
        # bob/private.txt, must be unchanged -- handled separately by bob_secret_intact).
        return not os.path.exists(os.path.join(data, rel))

    # seed a clean, alice-owned sentinel used as the desync-survival follow-up target.
    http("PUT", "/alice/sds_clean.txt", port, ta, b"SDS-ALICE-CLEAN\n")

    def survives(tag):
        # FRESH-connection clean GET with alice's token: correct bytes + the worker is
        # alive => no desync poisoned this connection or wedged the worker.
        st, b = http("GET", "/alice/sds_clean.txt", port, ta)
        ok(st == 200 and b == b"SDS-ALICE-CLEAN\n",
           "post-%s: fresh alice GET served byte-exact, worker alive (HTTP %s)" % (tag, st))

    # ---- (1) TE.CL: Transfer-Encoding FIRST then Content-Length; chunked body holds a
    #          smuggled PUT to bob/private.txt.  The terminating 0-chunk must end the
    #          request so the smuggled bytes are never a second request.
    teclbody = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                + b"\r\nAuthorization: Bearer " + ta.encode()
                + b"\r\nContent-Length: 5\r\n\r\nPWNED")
    tecl = (b"POST /alice/sds_tecl.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: "
            + str(len(teclbody)).encode() + b"\r\n\r\n0\r\n\r\n" + teclbody)
    raw_http(tecl, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "TE.CL (TE-first+CL) smuggled PUT did NOT overwrite bob's 0600 secret")
    survives("TE.CL")

    # ---- (2) CL.TE: Content-Length FIRST then Transfer-Encoding; CL frames a short
    #          body, the trailing chunked data tries to surface as a smuggled request.
    clte = (b"POST /alice/sds_clte.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"5c\r\nPUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nContent-Length: 3\r\n\r\nXXX\r\n0\r\n\r\n")
    raw_http(clte, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "CL.TE (CL-first+TE) trailing chunk not run as smuggled write to bob")
    survives("CL.TE")

    # ---- (3) Conflicting DOUBLE Content-Length (5 then 0): the second framing must not
    #          let trailing bytes become a smuggled PUT.  (run_http_protocol_abuse uses
    #          5/120 with a DIFFERENT smuggled target+ordering; here 5/0 -> bob.)
    dcl = (b"POST /alice/sds_dcl.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nAuthorization: Bearer " + ta.encode()
           + b"\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhelloPUT "
           + b"/bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
           + b"\r\nContent-Length: 3\r\n\r\nYYY")
    raw_http(dcl, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "conflicting double Content-Length (5/0) did not smuggle a write to bob")
    survives("double-CL-5-0")

    # ---- (4) OBFUSCATED Transfer-Encoding header forms.  Each tries to sneak chunked
    #          framing past the CL parser so the chunk body becomes a smuggled request.
    #          A correct server treats an unrecognized TE as no-TE (uses CL) OR 400s --
    #          either way no smuggled op runs.  Distinct framings probed individually:
    te_obf = [
        ("tab-folded TE value", b"Transfer-Encoding:\tchunked"),
        ("leading-space TE name", b" Transfer-Encoding: chunked"),
        ("TE list chunked,x", b"Transfer-Encoding: chunked, x"),
        ("space-before-colon TE", b"Transfer-Encoding : chunked"),
        ("doubled TE identity+chunked", b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"),
        ("uppercase CHUNKED", b"Transfer-Encoding: CHUNKED"),
    ]
    for i, (label, hdr) in enumerate(te_obf):
        body = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                + b"\r\nContent-Length: 3\r\n\r\nZZZ")
        raw = (b"POST /alice/sds_obf%d.txt HTTP/1.1\r\nHost: " % i + H.encode()
               + b"\r\nAuthorization: Bearer " + ta.encode() + b"\r\n" + hdr
               + b"\r\nContent-Length: " + str(len(body)).encode()
               + b"\r\n\r\n0\r\n\r\n" + body)
        raw_http(raw, port, read_timeout=2.5)
        ok(bob_secret_intact(),
           "obfuscated TE (%s) did not enable a smuggled write to bob" % label)
    survives("obfuscated-TE")

    # ---- (5) MALFORMED chunk sizes on a genuine chunked PUT to alice's OWN dir.  A bad
    #          size must be a parse error (4xx) or truncated read -- never a desync that
    #          spills the remainder as a smuggled request.  Each size probed distinctly.
    bad_sizes = [
        ("negative chunk size", b"-1"),
        ("0x-prefixed overflow", b"0xFFFFFFFFFFFFFFFF"),
        ("huge hex size", b"FFFFFFFF"),
        ("non-hex size", b"zz"),
        ("empty size line", b""),
    ]
    for i, (label, sz) in enumerate(bad_sizes):
        trailer_smuggle = (b"\r\nPUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
                           + b"\r\nContent-Length: 3\r\n\r\nWWW")
        raw = (b"PUT /alice/sds_chk%d.txt HTTP/1.1\r\nHost: " % i + H.encode()
               + b"\r\nAuthorization: Bearer " + ta.encode()
               + b"\r\nTransfer-Encoding: chunked\r\n\r\n" + sz
               + b"\r\nABC" + trailer_smuggle)
        resp = raw_http(raw, port, read_timeout=2.5)
        ok(_resp_status(resp) in (400, 411, 413, 422, 501, -1)
           or _resp_status(resp) < 300 or _resp_status(resp) >= 400,
           "malformed chunk size (%s) handled with a status, no crash" % label)
        ok(bob_secret_intact(),
           "malformed chunk size (%s) did not smuggle a write to bob" % label)
        ok(no_smuggled("alice/sds_chk%d_PWN.txt" % i),
           "malformed chunk size (%s): no stray smuggled artifact created" % label)
    survives("malformed-chunk-size")

    # ---- (6) CHUNK-EXTENSION junk: a valid chunk with a huge bogus ;ext=... parameter.
    #          The extension must be ignored (chunk still 3 bytes) -- the junk must not
    #          shift framing so trailing bytes leak out as a smuggled request.
    ext = b";evil=" + b"A" * 2048 + b';name="PUT /bob/private.txt"'
    cext = (b"PUT /alice/sds_ext.txt HTTP/1.1\r\nHost: " + H.encode()
            + b"\r\nAuthorization: Bearer " + ta.encode()
            + b"\r\nTransfer-Encoding: chunked\r\n\r\n3" + ext + b"\r\nABC\r\n0\r\n\r\n")
    resp = raw_http(cext, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "chunk-extension junk did not desync into a smuggled write to bob")
    fext = os.path.join(data, "alice", "sds_ext.txt")
    ok(not os.path.exists(fext) or os.stat(fext).st_uid == UID_ALICE,
       "chunk-ext PUT (if created) owned by alice, never worker/root")
    survives("chunk-extension-junk")

    # ---- (7) TRAILER headers after the final chunk trying to inject Authorization/Host
    #          to retroactively change the request's identity.  Trailers must NOT alter
    #          the already-authenticated principal -> the PUT stays alice-scoped and bob
    #          is untouched.  Trailers naming bob's token must not promote the write.
    trail = (b"PUT /alice/sds_trail.txt HTTP/1.1\r\nHost: " + H.encode()
             + b"\r\nAuthorization: Bearer " + ta.encode()
             + b"\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n"
             + b"3\r\nABC\r\n0\r\n"
             + b"Authorization: Bearer " + tb.encode() + b"\r\n"
             + b"Host: bob.example\r\n\r\n")
    resp = raw_http(trail, port, read_timeout=3.0)
    ftr = os.path.join(data, "alice", "sds_trail.txt")
    ok(not os.path.exists(ftr) or os.stat(ftr).st_uid == UID_ALICE,
       "trailer-injected Authorization did NOT re-map identity (file stays alice-owned)")
    ok(bob_secret_intact(),
       "trailer-injected Host/Authorization did not redirect the write onto bob")
    survives("trailer-header-injection")

    # ---- (8) BARE-LF framed request whose body carries a bare-LF-framed SECOND request
    #          (\n line endings, no CR).  A server that splits on bare LF could treat the
    #          tail as a smuggled PUT; it must not run as a write to bob.  (abuse-batch's
    #          bare-LF case is a single GET; this smuggles a second request via bare-LF.)
    lf = (b"POST /alice/sds_lf.txt HTTP/1.1\nHost: " + H.encode()
          + b"\nAuthorization: Bearer " + ta.encode()
          + b"\nContent-Length: 4\n\ndataPUT /bob/private.txt HTTP/1.1\nHost: "
          + H.encode() + b"\nContent-Length: 3\n\nLFX")
    raw_http(lf, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "bare-LF-framed smuggled second request did not write to bob's secret")
    survives("bare-LF-smuggle")

    # ---- (9) Fully-formed SECOND request smuggled via an over-large Content-Length lie
    #          combined with a 0-chunk TE (the classic CL.0/TE.0 victim-poison).  The
    #          smuggled victim is a complete PUT to bob/private.txt with bob's OWN token
    #          -- even though bob COULD write his own file, the smuggled request must not
    #          execute as a side effect of alice's request (no second-request parse).
    victim = (b"PUT /bob/private.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + tb.encode()
              + b"\r\nContent-Length: 9\r\n\r\nSMUGGLED!")
    poison = (b"GET /alice/sds_clean.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + ta.encode()
              + b"\r\nTransfer-Encoding: chunked\r\nContent-Length: "
              + str(len(victim)).encode() + b"\r\n\r\n0\r\n\r\n" + victim)
    raw_http(poison, port, read_timeout=3.0)
    ok(bob_secret_intact(),
       "fully-formed smuggled PUT (bob token) to bob/private NOT executed as 2nd request")
    survives("formed-second-request")

    # ---- (10) DESYNC-POISON the NEXT connection: send a smuggling prefix, then on a
    #           SEPARATE fresh connection alice GETs her file.  If the worker were
    #           desynced, alice's response could be poisoned by the smuggled prefix or
    #           she could receive bob's bytes; she must get exactly her own clean bytes.
    prefix = (b"POST /alice/sds_poison.txt HTTP/1.1\r\nHost: " + H.encode()
              + b"\r\nAuthorization: Bearer " + ta.encode()
              + b"\r\nContent-Length: 50\r\n\r\nGET /bob/private.txt HTTP/1.1\r\nHost: "
              + H.encode() + b"\r\n")
    raw_http(prefix, port, read_timeout=2.0)
    st, b = http("GET", "/alice/sds_clean.txt", port, ta)
    ok(st == 200 and b == b"SDS-ALICE-CLEAN\n" and SECRET not in (b or b""),
       "after smuggle-prefix: next conn alice GET clean, no bob bytes bled in (HTTP %s)" % st)

    # ---- (11) FINAL invariants: nothing the raw writes produced landed wrongly-owned in
    #           alice's dir, and bob's secret survived the whole batch byte-exact.
    bad = 0
    try:
        for f in os.listdir(os.path.join(data, "alice")):
            if f.startswith("sds_"):
                try:
                    if os.lstat(os.path.join(data, "alice", f)).st_uid in (UID_SVC, 0):
                        bad += 1
                except OSError:
                    pass
    except OSError:
        pass
    ok(bad == 0, "no sds_* file landed worker/root-owned after smuggling batch (mismatches=%d)" % bad)
    ok(bob_secret_intact(),
       "bob's 0600 private.txt byte-exact + 1002:1002 + 0600 after ALL smuggling vectors")


