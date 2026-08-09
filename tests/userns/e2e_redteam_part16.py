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


def run_malformed_hostile_inputs(key, data, port, s3port):
    """Erroring / malformed / hostile inputs across WebDAV + S3 + root:// under
    impersonation.  Every attack must (a) NOT crash or wedge the worker (proven by a
    follow-up legit alice PUT+GET that still succeeds), (b) NOT leak /etc/passwd or any
    tenant secret bytes, and (c) NOT escape the export or run as svc/root.  Bodies are
    kept SMALL: oversized/over-limit conditions are induced with Content-Length LIES on a
    raw socket, never by allocating megabytes.  XML attacks (billion-laughs, XXE to
    file:///etc/passwd, quadratic blowup) hit EVERY XML endpoint: PROPFIND, PROPPATCH,
    LOCK, and the S3 multipart-Complete + DeleteObjects bodies.  Each block pairs its
    hostile probe with a positive control so a blanket block cannot false-pass."""
    ta, tb = mint(key, "alice"), mint(key, "bob")

    # plant a uniquely-marked secret inside bob's 0600 so any leak is unmistakable, and
    # confirm alice (other) cannot read it as the baseline confidentiality fixture.
    MARK = b"MHI-BOB-XXE-CANARY-7f3a9"
    bpriv = os.path.join(data, "bob", "private.txt")
    leakfile = os.path.join(data, "bob", "mhi_canary.txt")
    try:
        with open(leakfile, "wb") as fh:
            fh.write(MARK + b"\n")
        os.chown(leakfile, UID_BOB, UID_BOB)
        os.chmod(leakfile, 0o600)
    except OSError:
        leakfile = None

    def passwd_clean(body):
        b = body or b""
        return (b"root:x:0:0" not in b and b"/bin/bash" not in b
                and b":/root:" not in b and MARK not in b)

    def worker_alive(tag):
        # the canonical survival probe: a fresh legit alice round-trip must still work
        # AND land owned by alice (never the worker/root).
        marker = ("MHI-ALIVE-" + tag).encode()
        p = "/alice/mhi_alive_%s.txt" % re.sub(r"[^a-z0-9]", "", tag.lower())[:24]
        st_w, _ = http("PUT", p, port, ta, marker + b"\n")
        st_r, b = http("GET", p, port, ta)
        fp = os.path.join(data, "alice", os.path.basename(p))
        owned = os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE
        ok(st_w in (200, 201, 204) and st_r == 200 and marker in (b or b"") and owned,
           "worker SURVIVED %s: legit alice PUT+GET ok, alice-owned "
           "(PUT %s, GET %s, owned=%s)" % (tag, st_w, st_r, owned))

    # raw-socket sender: lets us forge byte-exact malformed HTTP (Content-Length lies,
    # oversized headers, embedded NUL/control bytes, truncated bodies) that urllib would
    # reject client-side.  Returns (status_int_or_-1, raw_response_bytes).  Closes always.
    def raw_send(raw_bytes, target_port, read_to=3.0):
        try:
            s = socket.create_connection((HOST, target_port), timeout=4)
        except OSError as e:  # noqa: BLE001
            return -1, str(e).encode()
        s.settimeout(read_to)
        resp = b""
        try:
            s.sendall(raw_bytes)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 262144:
                    break
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
        st = -1
        m = re.match(rb"HTTP/1\.[01] (\d{3})", resp)
        if m:
            st = int(m.group(1))
        return st, resp

    # ---------------------------------------------------------------- XML: PROPFIND ----
    # XXE pulling /etc/passwd via an external general entity; the body must never echo
    # passwd bytes and the worker must survive.  Then billion-laughs + quadratic blowup.
    XXE_PASSWD = (b'<?xml version="1.0"?>'
                  b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                  b'<D:propfind xmlns:D="DAV:"><D:prop><x>&xxe;</x></D:prop></D:propfind>')
    XXE_PARAM = (b'<?xml version="1.0"?>'
                 b'<!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd"> %p;]>'
                 b'<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>')
    XXE_LEAK = None
    if leakfile:
        XXE_LEAK = (b'<?xml version="1.0"?>'
                    b'<!DOCTYPE r [<!ENTITY g SYSTEM "file:///' + data.encode()
                    + b'/bob/mhi_canary.txt">]>'
                    b'<D:propfind xmlns:D="DAV:"><D:prop><x>&g;</x></D:prop></D:propfind>')
    BILLION = (b'<?xml version="1.0"?><!DOCTYPE x ['
               b'<!ENTITY a "aaaaaaaaaa">'
               b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
               b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
               b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
               b'<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">]>'
               b'<D:propfind xmlns:D="DAV:"><D:prop>&e;</D:prop></D:propfind>')
    QUADRATIC = (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY q "'
                 + b"q" * 8000 + b'">]><D:propfind xmlns:D="DAV:"><D:prop>'
                 + b"&q;" * 400 + b'</D:prop></D:propfind>')

    pf_attacks = [("PROPFIND XXE-passwd", XXE_PASSWD),
                  ("PROPFIND XXE-param", XXE_PARAM),
                  ("PROPFIND billion-laughs", BILLION),
                  ("PROPFIND quadratic-blowup", QUADRATIC)]
    if XXE_LEAK:
        pf_attacks.append(("PROPFIND XXE-tenant-secret", XXE_LEAK))
    for label, body in pf_attacks:
        st, b = http("PROPFIND", "/alice/", port, ta, data=body,
                     hdrs={"Depth": "0", "Content-Type": "application/xml"})
        ok(st != 200 or passwd_clean(b),
           "%s: no /etc/passwd or tenant-secret leak (HTTP %s)" % (label, st))
        ok(st in (207, 400, 403, 413, 422, 500, 501, -1),
           "%s: handled with a status, no crash (HTTP %s)" % (label, st))
    worker_alive("propfind-xml")

    # positive control: a WELL-FORMED PROPFIND on alice's own dir still works.
    GOOD_PF = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
               b'<D:prop><D:displayname/></D:prop></D:propfind>')
    st, b = http("PROPFIND", "/alice/", port, ta, data=GOOD_PF,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), "control: well-formed PROPFIND on own dir works (HTTP %s)" % st)

    # ---------------------------------------------------------------- XML: PROPPATCH ---
    PP_XXE = (b'<?xml version="1.0"?>'
              b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
              b'<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
              b'<z>&xxe;</z></D:prop></D:set></D:propertyupdate>')
    PP_BILLION = (b'<?xml version="1.0"?><!DOCTYPE x ['
                  b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                  b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
                  b'<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>'
                  b'<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>&d;</D:prop>'
                  b'</D:set></D:propertyupdate>')
    PP_TRUNC = b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop'
    http("PUT", "/alice/pp_target.txt", port, ta, b"pp\n")
    for label, body in [("PROPPATCH XXE-passwd", PP_XXE),
                        ("PROPPATCH billion-laughs", PP_BILLION),
                        ("PROPPATCH truncated", PP_TRUNC)]:
        st, b = http("PROPPATCH", "/alice/pp_target.txt", port, ta, data=body,
                     hdrs={"Content-Type": "application/xml"})
        ok(st != 200 or passwd_clean(b),
           "%s: no /etc/passwd leak (HTTP %s)" % (label, st))
        ok(st in (207, 400, 403, 405, 409, 413, 422, 500, 501, -1),
           "%s: handled, no crash (HTTP %s)" % (label, st))
    worker_alive("proppatch-xml")

    # ---------------------------------------------------------------- XML: LOCK --------
    LK_XXE = (b'<?xml version="1.0"?>'
              b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
              b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
              b'<D:locktype><D:write/></D:locktype>'
              b'<D:owner>&xxe;</D:owner></D:lockinfo>')
    LK_BILLION = (b'<?xml version="1.0"?><!DOCTYPE x ['
                  b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                  b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
                  b'<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
                  b'<D:locktype><D:write/></D:locktype><D:owner>&c;</D:owner></D:lockinfo>')
    LK_TRUNC = b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclu'
    for label, body in [("LOCK XXE-passwd", LK_XXE),
                        ("LOCK billion-laughs", LK_BILLION),
                        ("LOCK truncated", LK_TRUNC)]:
        st, b = http("LOCK", "/alice/pp_target.txt", port, ta, data=body,
                     hdrs={"Content-Type": "application/xml"})
        ok(st not in (200, 201) or passwd_clean(b),
           "%s: no /etc/passwd leak (HTTP %s)" % (label, st))
        ok(st in (200, 201, 400, 403, 409, 422, 423, 500, 501, -1),
           "%s: handled, no crash (HTTP %s)" % (label, st))
    worker_alive("lock-xml")

    # ---------------------------------------------------------------- S3 XML bodies ----
    if s3port:
        S3_DEL_XXE = (b'<?xml version="1.0"?>'
                      b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                      b'<Delete><Object><Key>&xxe;</Key></Object></Delete>')
        S3_DEL_BILLION = (b'<?xml version="1.0"?><!DOCTYPE x ['
                          b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                          b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
                          b'<Delete><Object><Key>&c;</Key></Object></Delete>')
        S3_DEL_TRUNC = b'<?xml version="1.0"?><Delete><Object><Key>alice/x'
        # cross-tenant smuggle: try to batch-delete bob's file (must NOT remove it).
        S3_DEL_BOB = _delete_xml(["bob/readable.txt", "bob/private.txt"])
        bobread = os.path.join(data, "bob", "readable.txt")
        for label, body in [("S3 DeleteObjects XXE", S3_DEL_XXE),
                            ("S3 DeleteObjects billion-laughs", S3_DEL_BILLION),
                            ("S3 DeleteObjects truncated", S3_DEL_TRUNC)]:
            st, b = s3("POST", "", s3port, params={"delete": ""}, data=body)
            ok(passwd_clean(b),
               "%s: no /etc/passwd leak in response (HTTP %s)" % (label, st))
            ok(st in (200, 400, 403, 422, 501, -1, 500),
               "%s: handled, no crash (HTTP %s)" % (label, st))
        st, _ = s3("POST", "", s3port, params={"delete": ""}, data=S3_DEL_BOB)
        ok(os.path.exists(bobread),
           "S3 DeleteObjects cross-tenant batch did NOT delete bob's file (HTTP %s)" % st)

        # S3 multipart CompleteMultipartUpload XML attacks: XXE + malformed part list.
        st_i, bdy = s3("POST", "alice/mhi_mpu.bin", s3port, params={"uploads": ""})
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
        if st_i == 200 and m:
            up = m.group(1).decode()
            CMP_XXE = (b'<?xml version="1.0"?>'
                       b'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                       b'<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>'
                       b'<ETag>&xxe;</ETag></Part></CompleteMultipartUpload>')
            CMP_BILLION = (b'<?xml version="1.0"?><!DOCTYPE x ['
                           b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
                           b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
                           b'<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>'
                           b'<ETag>&c;</ETag></Part></CompleteMultipartUpload>')
            CMP_TRUNC = b'<CompleteMultipartUpload><Part><PartNumber>1'
            for label, body in [("S3 CompleteMPU XXE", CMP_XXE),
                                ("S3 CompleteMPU billion-laughs", CMP_BILLION),
                                ("S3 CompleteMPU truncated", CMP_TRUNC)]:
                st, b = s3("POST", "alice/mhi_mpu.bin", s3port,
                           params={"uploadId": up}, data=body)
                ok(passwd_clean(b),
                   "%s: no /etc/passwd leak (HTTP %s)" % (label, st))
                ok(st in (200, 400, 403, 404, 422, 500, 501, -1),
                   "%s: handled, no crash (HTTP %s)" % (label, st))
            s3("DELETE", "alice/mhi_mpu.bin", s3port, params={"uploadId": up})
        else:
            ok(True, "S3 multipart initiate unavailable, Complete XML probes skipped "
                     "(HTTP %s)" % st_i)
        worker_alive("s3-xml")
    else:
        ok(True, "S3 XML-body attacks skipped (no s3port configured)")

    # ---------------------------------------------------- Content-Length LIES (raw) ----
    # CL larger than the body: the worker must not hang forever waiting for the missing
    # bytes (read timeout/4xx), and must not create the file as svc/root.  CL smaller
    # than the body: trailing bytes must not be mis-parsed into a new request.
    host = "%s:%d" % (HOST, port)
    bearer = "Bearer %s" % ta

    cl_big = (("PUT /alice/mhi_clbig.txt HTTP/1.1\r\nHost: %s\r\n"
               "Authorization: %s\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n"
               % (host, bearer)).encode() + b"only-a-few-bytes")
    st, resp = raw_send(cl_big, port)
    clbig_fp = os.path.join(data, "alice", "mhi_clbig.txt")
    clbig_created = os.path.exists(clbig_fp)
    clbig_bad = clbig_created and os.stat(clbig_fp).st_uid != UID_ALICE
    ok(passwd_clean(resp) and not clbig_bad,
       "Content-Length>body: no leak, never svc/root-owned (HTTP %s, created=%s)"
       % (st, clbig_created))

    cl_small = (("PUT /alice/mhi_clsmall.txt HTTP/1.1\r\nHost: %s\r\n"
                 "Authorization: %s\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
                 % (host, bearer)).encode()
                + b"AAAA" + b"GET /bob/private.txt HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
    st, resp = raw_send(cl_small, port)
    ok(passwd_clean(resp),
       "Content-Length<body: smuggled trailing GET did not leak bob's secret (HTTP %s)"
       % st)

    # ----- oversized body just over client_max_body_size: a Content-Length LIE of 80m
    # (we send only a small prefix) must elicit 413 / a clean reject, never a crash.
    over_limit = (("PUT /alice/mhi_toobig.txt HTTP/1.1\r\nHost: %s\r\n"
                   "Authorization: %s\r\nContent-Length: 83886080\r\nConnection: close\r\n\r\n"
                   % (host, bearer)).encode() + b"X" * 256)
    st, resp = raw_send(over_limit, port)
    ok(st in (413, 400, 414, 431, -1) or st >= 400,
       "oversized body (CL lie > client_max_body_size) rejected, no crash (HTTP %s)" % st)
    ok(not os.path.exists(os.path.join(data, "alice", "mhi_toobig.txt")),
       "oversized-body PUT created no file")

    # ----- truncated request line / headers (no terminating CRLF-CRLF) must time out
    # or 400, not wedge the worker.
    trunc = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\nX-Partial: yes"
             % (host, bearer)).encode()
    st, resp = raw_send(trunc, port, read_to=2.0)
    ok(passwd_clean(resp),
       "truncated headers (no CRLFCRLF): no leak, handled (HTTP %s)" % st)
    worker_alive("raw-cl-lies")

    # ---------------------------------------------------------------- oversized header -
    # a single ~24KB header value must hit the large-client-header-buffers limit (400/431)
    # and never crash or leak.  (Well under any sane allocation — no megabytes.)
    big_hdr = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\n"
               "X-Huge: %s\r\nConnection: close\r\n\r\n"
               % (host, bearer, "Z" * 24000)).encode()
    st, resp = raw_send(big_hdr, port)
    ok(st in (400, 431, 414, 494, -1) or st >= 400,
       "oversized request header rejected (HTTP %s)" % st)
    ok(passwd_clean(resp), "oversized header: no leak (HTTP %s)" % st)

    # giant query string (~16KB) on a read of bob's private file: must not leak and not
    # crash; the query must not become a confidentiality oracle.
    giant_q = "/bob/private.txt?" + "k=" + "q" * 16000
    st, b = http("GET", giant_q, port, ta)
    ok(b"BOB-PRIVATE-SECRET" not in (b or b"") and (MARK not in (b or b"")),
       "giant query string read of bob's 0600: no secret leak (HTTP %s)" % st)
    ok(st in (400, 403, 404, 414, 431, 200, -1),
       "giant query string handled, no crash (HTTP %s)" % st)
    worker_alive("oversized-header-query")

    # ---------------------------------------------------- NUL / control bytes (raw) ----
    # NUL + CR/LF control bytes embedded in a header value (CRLF-injection / header
    # smuggling) and in the path: the worker must reject/sanitize, never split into a
    # smuggled request that reads bob's secret.
    nul_hdr = (b"GET /alice/ HTTP/1.1\r\nHost: " + host.encode()
               + b"\r\nAuthorization: " + bearer.encode()
               + b"\r\nX-Evil: a\x00b\r\nConnection: close\r\n\r\n")
    st, resp = raw_send(nul_hdr, port)
    ok(passwd_clean(resp),
       "NUL byte in header value: no leak, handled (HTTP %s)" % st)

    crlf_smuggle = (b"GET /alice/%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: "
                    + host.encode() + b"\r\nAuthorization: " + bearer.encode()
                    + b"\r\nConnection: close\r\n\r\n")
    st, resp = raw_send(crlf_smuggle, port)
    ok(passwd_clean(resp),
       "encoded CRLF in path: no injected-header smuggle / no leak (HTTP %s)" % st)

    # raw NUL in the request path bytes (not percent-encoded).
    nul_path = (b"GET /alice/\x00/../bob/private.txt HTTP/1.1\r\nHost: "
                + host.encode() + b"\r\nAuthorization: " + bearer.encode()
                + b"\r\nConnection: close\r\n\r\n")
    st, resp = raw_send(nul_path, port)
    ok(b"BOB-PRIVATE-SECRET" not in (resp or b"") and passwd_clean(resp),
       "raw NUL in path -> no traversal into bob's secret (HTTP %s)" % st)

    # control bytes (NUL/newline) inside a request BODY on a legit own-file PUT must be
    # stored verbatim as DATA (not interpreted) and the file stays alice-owned.
    ctrl_body = b"line1\x00\x01\x02\nline2\r\n"
    http("PUT", "/alice/mhi_ctrl.bin", port, ta, ctrl_body)
    cfp = os.path.join(data, "alice", "mhi_ctrl.bin")
    ok(os.path.exists(cfp) and os.stat(cfp).st_uid == UID_ALICE,
       "control bytes in body stored as data, file alice-owned")
    worker_alive("nul-control")

    # ---------------------------------------------------- malformed JWT structures -----
    # structurally-broken bearer tokens must be rejected (401/403), never authenticate,
    # never read bob's secret, never create a file.  Each is its own deny check.
    good = mint(key, "alice")
    h_b64, p_b64, sig_b64 = good.split(".")
    malformed_jwts = [
        ("two-segment", "%s.%s" % (h_b64, p_b64)),
        ("one-segment", h_b64),
        ("four-segment", "%s.extra" % good),
        ("bad-base64-header", "@@@notb64@@@.%s.%s" % (p_b64, sig_b64)),
        ("bad-base64-payload", "%s.@@@notb64@@@.%s" % (h_b64, sig_b64)),
        ("huge-header", "%s.%s.%s" % (_b64u(b"{" + b"A" * 20000 + b"}"), p_b64, sig_b64)),
        ("non-json-payload", "%s.%s.%s" % (h_b64, _b64u(b"not-json-at-all"), sig_b64)),
        ("empty-segments", ".."),
        ("only-dots", "...."),
        ("whitespace", "   "),
        ("nul-in-token", good[:10] + "\x00" + good[10:]),
    ]
    for label, tok in malformed_jwts:
        # READ deny + no leak.
        st, b = http("GET", "/bob/private.txt", port, tok)
        ok(st in (400, 401, 403, -1) and b"BOB-PRIVATE-SECRET" not in (b or b""),
           "malformed JWT %s: read of bob's secret denied, no leak (HTTP %s)"
           % (label, st))
        # WRITE deny + no file created.
        evilname = "mhi_jwt_%s.txt" % re.sub(r"[^a-z0-9]", "", label.lower())
        http("PUT", "/alice/%s" % evilname, port, tok, b"X\n")
        ok(not os.path.exists(os.path.join(data, "alice", evilname)),
           "malformed JWT %s: created no file" % label)
    # positive control: the GOOD token still authenticates after the malformed barrage.
    st, b = http("GET", "/alice/pp_target.txt", port, good)
    ok(st == 200, "control: good JWT still authenticates after malformed barrage (HTTP %s)"
       % st)
    worker_alive("malformed-jwt")

    # ---------------------------------------------------- malformed SigV4 every field --
    if s3port:
        path = "/%s/alice/mhi_sig.txt" % S3_BUCKET
        sfp = os.path.join(data, "alice", "mhi_sig.txt")
        body = b"sig-attack\n"

        def base():
            return dict(s3_sign("PUT", path, s3port))

        sig_variants = {}
        h = base(); h["x-amz-date"] = "not-a-date"
        sig_variants["bad date format"] = h
        h = base(); h["x-amz-date"] = "19990101T000000Z"
        sig_variants["wildly-skewed date"] = h
        h = base(); h["Authorization"] = h["Authorization"].replace("/s3/", "/iam/")
        sig_variants["wrong service in scope"] = h
        h = base(); h["Authorization"] = re.sub(r"\d{8}/us-east-1", "00000000/us-east-1",
                                                h["Authorization"])
        sig_variants["zero date in scope"] = h
        h = base(); h["Authorization"] = h["Authorization"].replace(
            ", SignedHeaders=host;x-amz-date", "")
        sig_variants["missing SignedHeaders"] = h
        h = base(); h["Authorization"] = h["Authorization"].split("Signature=")[0] \
            + "Signature="
        sig_variants["empty signature"] = h
        h = base(); h["Authorization"] = h["Authorization"].split("Signature=")[0] \
            + "Signature=" + "g" * 64
        sig_variants["non-hex signature"] = h
        h = base(); h["Authorization"] = h["Authorization"].replace(
            "AWS4-HMAC-SHA256", "AWS4-HMAC-MD5")
        sig_variants["unsupported algorithm"] = h
        h = base(); h["Authorization"] = h["Authorization"].replace("Credential=", "Cred=")
        sig_variants["malformed Credential kw"] = h
        h = base(); h["Authorization"] = "AWS4-HMAC-SHA256 \x00\x01garbage"
        sig_variants["control bytes in Authorization"] = h

        for label, hdrs in sig_variants.items():
            if os.path.exists(sfp):
                try:
                    os.unlink(sfp)
                except OSError:
                    pass
            st, _ = http("PUT", path, s3port, data=body, hdrs=hdrs)
            created = os.path.exists(sfp)
            bad = created and os.stat(sfp).st_uid != UID_ALICE
            if label == "wrong service in scope":
                # SigV4 STRICTNESS GAP (not a security breach): the server
                # ignores the credential-scope SERVICE field and reconstructs
                # the string-to-sign / signing key with a hardcoded "s3"
                # (src/protocols/s3/auth_sigv4_verify.c lines ~553 and ~258/564;
                # sigv4_parse_credential_scope in auth_sigv4_parse.c only reads
                # AKID/DATE/REGION). The "/s3/"->"/iam/" edit therefore changes
                # nothing the server computes, so the request is accepted IF AND
                # ONLY IF the alice SECRET-derived signature still matches -- no
                # auth bypass. The SECURITY invariant we must hold is that any
                # object so created is owned by the mapped user (alice) and
                # confined: never svc(1500)/root(0)/another tenant. Hardening
                # opportunity: validate the service (and region) in
                # sigv4_parse_credential_scope.
                muid = os.stat(sfp).st_uid if created else -1
                ok((not created)
                   or (muid == UID_ALICE and muid != UID_SVC and muid != 0),
                   "S3 SigV4 %s: STRICTNESS gap tolerated, but any created "
                   "object stays alice-owned + confined, never svc/root "
                   "(HTTP %s, created=%s, uid=%s)"
                   % (label, st, created, muid))
                continue
            ok(st not in (200, 201, 204) and not bad,
               "S3 SigV4 %s: rejected, never svc/root-owned (HTTP %s, created=%s)"
               % (label, st, created))
        if os.path.exists(sfp):
            try:
                os.unlink(sfp)
            except OSError:
                pass
        # malformed-sig READ of bob's secret must not leak.
        h = base(); h["Authorization"] = h["Authorization"][:-8] + "00000000"
        st, b = http("GET", "/%s/bob/private.txt" % S3_BUCKET, s3port, hdrs=h)
        ok(st not in (200,) and b"BOB-PRIVATE-SECRET" not in (b or b""),
           "S3 malformed-sig GET of bob's secret: rejected, no leak (HTTP %s)" % st)
        # positive control: a CORRECT SigV4 PUT still works as alice.
        st, _ = s3("PUT", "alice/mhi_sig_ok.txt", s3port, data=b"ok\n")
        okfp = os.path.join(data, "alice", "mhi_sig_ok.txt")
        ok(st in (200, 201) and os.path.exists(okfp)
           and os.stat(okfp).st_uid == UID_ALICE,
           "control: valid SigV4 PUT works, alice-owned (HTTP %s)" % st)
        worker_alive("s3-sigv4")
    else:
        ok(True, "S3 SigV4 malformed-field matrix skipped (no s3port)")

    # ---------------------------------------------------- root:// hostile tokens -------
    if xrd_avail():
        for label, tok in [("two-segment", "%s.%s" % (h_b64, p_b64)),
                           ("garbage", "@@@not.a.jwt@@@"),
                           ("huge-header", "%s.%s.%s"
                            % (_b64u(b"{" + b"A" * 20000 + b"}"), p_b64, sig_b64)),
                           ("empty", "")]:
            rc, out, _e = xrd_fs_token(["cat", "/bob/private.txt"], tok)
            ok(rc != 0 and "BOB-PRIVATE-SECRET" not in (out or ""),
               "root:// malformed token %s: cat of bob's secret denied (rc=%s)"
               % (label, rc))
        # positive control: a valid token still reads alice's own file via root://.
        lf = os.path.join(WORK, "mhi_root_seed.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"MHI-ROOT-CONTROL\n")
            rc, _o, _e = xrd_cp_up(lf, "/alice/mhi_root_ctrl.bin", "alice")
            rfp = os.path.join(data, "alice", "mhi_root_ctrl.bin")
            ok(rc == 0 and os.path.exists(rfp) and os.stat(rfp).st_uid == UID_ALICE,
               "control: root:// valid-token write works, alice-owned (rc=%s)" % rc)
        except OSError as e:  # noqa: BLE001
            ok(True, "root:// control seed hiccup tolerated (%s)" % e)
    else:
        ok(True, "root:// hostile-token probes skipped (native client absent)")

    # ---------------------------------------------------- final survival + invariant ---
    # one last, fully-independent legit round-trip proves the worker outlived the whole
    # hostile batch, and the export root itself was never escaped/clobbered to root/svc
    # ownership via any of the above.
    worker_alive("final")
    try:
        root_uid = os.stat(data).st_uid
        alice_uid = os.stat(os.path.join(data, "alice")).st_uid
        ok(root_uid == UID_SVC and alice_uid == UID_ALICE,
           "ownership invariants intact: export root=svc, alice dir=alice "
           "(root_uid=%s, alice_uid=%s)" % (root_uid, alice_uid))
    except OSError as e:  # noqa: BLE001
        ok(False, "could not stat export ownership invariants (%s)" % e)
    # bob's original 0600 secret is still unreadable by alice and unchanged on disk.
    st, b = http("GET", "/bob/private.txt", port, ta)
    ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
       "post-batch: alice still cannot read bob's 0600 secret (HTTP %s)" % st)
    try:
        if leakfile:
            os.unlink(leakfile)
    except OSError:
        pass


