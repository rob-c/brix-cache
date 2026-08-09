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


def run_resource_dos_limits(key, data, port, s3port):
    """RESOURCE / DoS-LIMIT exhaustion under per-request impersonation.  Bounded
    (host-load-safe: tiny bodies, <=6 concurrent xrd_fs, <=8 threads, no megabytes)
    stressors that each probe a DISTINCT capacity ceiling the broker/worker must
    bound GRACEFULLY rather than crash, hang, leak, or run as svc/root: (1) a single
    PATH_MAX-scale path SEGMENT (~4000 chars) -> clean 4xx; (2) a 40-deep MKCOL chain
    then a PUT at the bottom -> bottom dir AND file owned by alice (broker openat2
    survives the depth); (3) many concurrent root:// handle opens via a few xrd_fs
    invocations -> bounded, no fd leak / crash; (4) huge header COUNT (200 headers)
    and one near-64KiB single header forged on a raw socket -> bounded 4xx, worker
    survives; (5) a PROPPATCH carrying 60 dead props -> xattr COUNT bounded, file
    stays alice-owned; (6) a very long S3 key + very long S3 query string -> 4xx not
    crash; (7) bounded slow partial sends via raw_send_steps -> client-timeout / no
    worker wedge.  After EACH stressor a clean alice GET /alice/hello.txt returns 200
    with the exact bytes we anchored (proves no DoS/wedge), and a final sweep proves
    no svc/root-owned artifact was left behind.  Distinct from the broker / malformed
    batches (see overlap_notes)."""
    T = "rdl_"
    ta = mint(key, "alice")
    adir = os.path.join(data, "alice")
    host = "%s:%d" % (HOST, port)
    bearer = "Bearer %s" % ta

    # ---- recovery anchor: write a KNOWN body to /alice/hello.txt as alice up front so
    # every post-stressor GET can assert exact bytes back regardless of prior batches.
    ANCHOR = b"RDL-ANCHOR-hi-from-alice\n"
    http("PUT", "/alice/hello.txt", port, ta, ANCHOR)

    def recover(label, n=[0]):
        """Clean alice GET /alice/hello.txt -> 200 with the exact anchored bytes.  A
        wedged worker or broker (hung on a prior stressor) would stall or fail this."""
        n[0] += 1
        t0 = time.time()
        st, b = http("GET", "/alice/hello.txt", port, ta)
        dt = time.time() - t0
        ok(st == 200 and b == ANCHOR and dt < 5.0,
           "recovery after %s: alice GET /alice/hello.txt -> 200 exact bytes, fast "
           "(HTTP %s, %.2fs)" % (label, st, dt))

    recover("baseline")

    # =====================================================================
    # 1) Single PATH_MAX-scale SEGMENT (~4000 chars, near PATH_MAX 4096).  Unlike a
    #    NAME_MAX-scale (~245) name or a many-component long path, ONE oversized
    #    component stresses the broker's path buffer at the PATH_MAX boundary; must
    #    yield a clean 4xx (or 507), never crash, never create a file, never escape.
    # =====================================================================
    seg = T + ("Z" * 4000)
    st, _ = http("PUT", "/alice/%s" % seg, port, ta, b"pmax\n")
    pmax_fp = os.path.join(adir, seg)
    pmax_created = os.path.exists(pmax_fp)
    ok(st in (400, 403, 404, 414, 500, 507, -1) and not pmax_created,
       "PATH_MAX-scale single segment (~4000): rejected cleanly, no file "
       "(HTTP %s, created=%s)" % (st, pmax_created))
    # a root:// stat on the same oversized segment must also bound, not hang.
    if xrd_avail():
        t0 = time.time()
        rc, _o, _e = xrd_fs(["stat", "/alice/%s" % seg], "alice")
        ok(time.time() - t0 < 12.0 and rc != 0,
           "root:// stat on PATH_MAX-scale segment bounded + denied, no hang (rc=%s)"
           % rc)
    recover("PATH_MAX segment")

    # =====================================================================
    # 2) 40-deep MKCOL chain then a PUT at the very bottom.  Proves the broker's
    #    openat2 / RESOLVE_BENEATH walk survives real namespace depth AND that the
    #    deepest directory and the leaf file both land owned by alice (no owner drift
    #    to svc/root as depth grows).  Goes materially deeper than any nearby batch.
    # =====================================================================
    DEPTH = 40
    cur = "/alice/%sdeep40" % T
    made = 0
    for _i in range(DEPTH):
        st, _ = http("MKCOL", cur, port, ta)
        if st in (200, 201):
            made += 1
            cur = cur + "/d"
        else:
            break
    top = os.path.join(adir, "%sdeep40" % T)
    ok(made >= 20 and os.path.isdir(top) and os.stat(top).st_uid == UID_ALICE,
       "40-deep MKCOL chain: %s levels created, top dir alice-owned" % made)
    # the DEEPEST directory the chain reached must itself be alice-owned (depth-walk
    # ownership invariant, distinct from only checking the top level).
    deepest_dir = cur.rsplit("/d", 1)[0]
    deepest_fs = os.path.join(data, deepest_dir.lstrip("/"))
    deep_owned = os.path.isdir(deepest_fs) and os.stat(deepest_fs).st_uid == UID_ALICE
    ok(made == 0 or deep_owned,
       "deepest directory of the chain owned by alice (no owner drift at depth %s)"
       % made)
    # a PUT at the bottom: broker must resolve the deep path and create alice-owned.
    if made >= 1:
        leaf = deepest_dir + "/leaf.txt"
        st, _ = http("PUT", leaf, port, ta, b"deepleaf\n")
        leaf_fs = os.path.join(data, leaf.lstrip("/"))
        leaf_owned = os.path.exists(leaf_fs) and os.stat(leaf_fs).st_uid == UID_ALICE
        ok((st in (200, 201, 204) and leaf_owned)
           or st in (403, 404, 409, 414, 500, 507),
           "PUT at bottom of 40-deep tree: alice-owned if created, else clean reject "
           "(HTTP %s)" % st)
    recover("40-deep MKCOL+PUT")

    # =====================================================================
    # 3) Concurrent root:// HANDLE pressure: a few (<=6) parallel xrd_fs invocations,
    #    each opening/reading several files, exercising the broker handle path + the
    #    nginx fd table under impersonation.  Must stay BOUNDED -> every alice probe
    #    succeeds (rc 0) and no leaked fd / crash wedges a follow-up.  (No nearby batch
    #    fans out concurrent native-client subprocesses.)
    # =====================================================================
    if xrd_avail():
        # seed a handful of small alice files to open repeatedly.
        for i in range(5):
            http("PUT", "/alice/%shandle_%d.txt" % (T, i), port, ta,
                 ("H%d\n" % i).encode())
        results = {}

        def opener(idx):
            # one xrd_fs process doing several stat+cat reads = several broker opens.
            args = ["cat", "/alice/%shandle_%d.txt" % (T, idx % 5)]
            rc, out, _e = xrd_fs(args, "alice")
            results[idx] = (rc, out or "")

        threads = [threading.Thread(target=opener, args=(i,)) for i in range(6)]
        t0 = time.time()
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        elapsed = time.time() - t0
        good = sum(1 for rc, _o in results.values() if rc == 0)
        ok(good >= 5 and elapsed < 25.0,
           "6 concurrent root:// handle openers: %d/6 succeeded, bounded "
           "(%.1fs, no wedge)" % (good, elapsed))
        # content correctness for one of them -> no cross-handle body bleed.
        rc0, out0 = results.get(0, (1, ""))
        ok(rc0 == 0 and "H0" in out0,
           "concurrent root:// open returned the OWN file's body (no handle bleed)")
        recover("concurrent root:// handles")
    else:
        ok(True, "concurrent root:// handle pressure skipped (native client absent)")

    # =====================================================================
    # 4a) Huge header COUNT: 200 distinct small headers forged on a raw socket.  This
    #     stresses large_client_header_buffers COUNT (not a single oversized value, as
    #     the malformed batch did) -> the worker must bound it (400/431) or absorb it,
    #     never crash, never leak, never create anything.
    # =====================================================================
    many = "".join("X-Rdl-%d: v%d\r\n" % (i, i) for i in range(200))
    raw_many = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\n%s"
                "Connection: close\r\n\r\n" % (host, bearer, many)).encode()
    resp = raw_http(raw_many, port)
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp or b"")
    st = int(m.group(1)) if m else -1
    ok(b"BOB-PRIVATE-SECRET" not in (resp or b"") and b"root:x:0:0" not in (resp or b""),
       "200-header request: no tenant/passwd leak (HTTP %s)" % st)
    ok(st in (200, 400, 414, 431, 494, -1) or st >= 400,
       "200-header COUNT request bounded with a status, no crash (HTTP %s)" % st)
    recover("200-header count")

    # 4b) One near-64KiB SINGLE header value (capped at 64KiB per the host-safe limit;
    #     larger than the malformed batch's ~24KB probe) -> must hit the header-buffer
    #     SIZE ceiling (400/431/494) cleanly, worker survives, nothing created/leaked.
    big_val = "Q" * 63000
    raw_big = ("GET /alice/ HTTP/1.1\r\nHost: %s\r\nAuthorization: %s\r\n"
               "X-Rdl-Big: %s\r\nConnection: close\r\n\r\n"
               % (host, bearer, big_val)).encode()
    resp = raw_http(raw_big, port)
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp or b"")
    st = int(m.group(1)) if m else -1
    ok(st in (400, 431, 414, 494, -1) or st >= 400,
       "near-64KiB single header value: rejected at the buffer ceiling (HTTP %s)" % st)
    ok(b"root:x:0:0" not in (resp or b""),
       "near-64KiB single header: no /etc/passwd leak (HTTP %s)" % st)
    recover("64KiB single header")

    # =====================================================================
    # 5) PROPPATCH with 60 dead properties in ONE request.  WebDAV dead props persist
    #    as user.* xattrs; a flood must be xattr-COUNT bounded gracefully (not OOM /
    #    not crash), and the target file must stay alice-owned with no setuid/setgid
    #    bit gained.  (The broker batch probed xattr NAMESPACE prefixes, not COUNT;
    #    the malformed batch did XXE/billion-laughs, not a many-prop flood.)
    # =====================================================================
    http("PUT", "/alice/%spp.txt" % T, port, ta, b"pp target\n")
    pp_fp = os.path.join(adir, "%spp.txt" % T)
    sets = "".join("<Z:p%d>v%d</Z:p%d>" % (i, i, i) for i in range(60))
    pp_body = ('<?xml version="1.0"?>'
               '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:rdl">'
               '<D:set><D:prop>%s</D:prop></D:set></D:propertyupdate>' % sets).encode()
    st, _ = http("PROPPATCH", "/alice/%spp.txt" % T, port, ta, data=pp_body,
                 hdrs={"Content-Type": "application/xml"})
    ok(st in (200, 207, 400, 403, 409, 413, 422, 500, 501),
       "PROPPATCH with 60 dead props: bounded with a status, no crash (HTTP %s)" % st)
    ok(os.path.exists(pp_fp) and os.stat(pp_fp).st_uid == UID_ALICE,
       "60-dead-prop target still owned by alice after the prop flood")
    pp_st = os.stat(pp_fp)
    ok(not (pp_st.st_mode & 0o6000),
       "60-dead-prop target gained no setuid/setgid bit")
    # xattr count is bounded: the inode did not accrue an unbounded number of xattrs.
    try:
        nxattr = len(os.listxattr(pp_fp))
    except OSError:
        nxattr = -1
    ok(nxattr < 0 or nxattr <= 200,
       "dead-prop xattr count bounded on the inode (count=%s)" % nxattr)
    recover("60 dead props")

    # =====================================================================
    # 6) Very long S3 KEY + very long S3 query string -> 4xx, not crash.  Distinct
    #    from the malformed batch's 16KB query on a WebDAV read (a leak oracle): here
    #    the S3 handler's key/query length bounding is the target, and no svc/root
    #    object may be created.
    # =====================================================================
    if s3port:
        longkey = "alice/" + (T + "k") * 600          # ~ 3.6KB key, bounded
        st, _ = s3("PUT", longkey, s3port, data=b"longkey\n")
        lk_fs = os.path.join(data, longkey)
        lk_created = os.path.exists(lk_fs)
        lk_bad = lk_created and os.stat(lk_fs).st_uid != UID_ALICE
        ok(st in (400, 403, 404, 414, 500, 501, -1) or (st in (200, 201) and not lk_bad),
           "very long S3 key: rejected, or created alice-owned; never svc/root "
           "(HTTP %s, created=%s)" % (st, lk_created))
        # very long S3 QUERY string on a GET -> bounded 4xx, no crash, no leak.
        st, b = s3("GET", "alice/hello.txt", s3port,
                   params={"x": (T + "q") * 1500})   # ~ 9KB query value
        ok(st in (200, 400, 403, 404, 414, 431, -1),
           "very long S3 query string: bounded with a status, no crash (HTTP %s)" % st)
        ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
           "very long S3 query string leaked no tenant secret (HTTP %s)" % st)
        recover("long S3 key/query")
    else:
        ok(True, "long S3 key/query stressor skipped (no s3port configured)")

    # =====================================================================
    # 7) Bounded SLOW partial sends (slowloris-shaped) via raw_send_steps.  Drip the
    #    request line + headers across small pauses and never finish the header block:
    #    the worker must apply its client-header timeout (close / 408 / -1) and NOT
    #    wedge the single worker thread.  No nearby batch exercises raw_send_steps
    #    timed partial sends.  Bounded: total pause budget < ~4s.
    # =====================================================================
    slow_steps = [
        ("GET /alice/hello.txt HTTP/1.1\r\n", 1.0),
        ("Host: %s\r\n" % host, 1.0),
        ("Authorization: %s\r\n" % bearer, 1.0),
        ("X-Rdl-Partial: still-typing", 0.5),   # NOTE: no terminating CRLFCRLF
    ]
    t0 = time.time()
    resp = raw_send_steps(slow_steps, port, read_timeout=3.0)
    dt = time.time() - t0
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp or b"")
    st = int(m.group(1)) if m else -1
    ok(dt < 12.0 and (st in (-1, 400, 408, 414, 431) or st >= 400 or st == -1),
       "slow partial send (never-completed headers): client-timeout / clean reject, "
       "no worker wedge (HTTP %s, %.1fs)" % (st, dt))
    ok(b"hi-from-alice" not in (resp or b"") and ANCHOR not in (resp or b""),
       "slow partial send returned no body (request never completed)")
    # the crucial proof: RIGHT AFTER the slow attack, a normal alice GET is still fast.
    recover("slow partial send")

    # A second slow-send variant that DOES complete after pauses -> must succeed and
    # serve the anchored bytes (proves the timeout doesn't false-trip a slow-but-valid
    # client, and the worker handled the paced delivery without identity drift).
    ok_steps = [
        ("GET /alice/hello.txt HTTP/1.1\r\n", 0.4),
        ("Host: %s\r\n" % host, 0.4),
        ("Authorization: %s\r\n" % bearer, 0.4),
        ("Connection: close\r\n\r\n", 0.0),
    ]
    resp = raw_send_steps(ok_steps, port, read_timeout=4.0)
    served = ANCHOR in (resp or b"")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", resp or b"")
    st = int(m.group(1)) if m else -1
    ok(st == 200 and served,
       "paced-but-complete slow request served the anchored alice body (HTTP %s)" % st)
    recover("paced complete request")

    # =====================================================================
    # 8) FINAL invariant sweep: every file THIS batch created under alice/ is owned by
    #    alice (never svc(1500)/root(0)) -> no stressor laundered an artifact to a
    #    privileged owner, and nothing escaped the export.
    # =====================================================================
    drift = 0
    scanned = 0
    try:
        for nm in os.listdir(adir):
            if not nm.startswith(T):
                continue
            fp = os.path.join(adir, nm)
            try:
                if os.path.islink(fp):
                    continue
                u = os.stat(fp, follow_symlinks=False).st_uid
            except OSError:
                continue
            scanned += 1
            if u == UID_SVC or u == 0:
                drift += 1
    except OSError:
        pass
    ok(scanned > 0 and drift == 0,
       "ownership invariant: of %s rdl_ artifacts, NONE owned by svc(1500)/root(0) "
       "(drift=%s)" % (scanned, drift))
    # nothing escaped the export root via any oversized/deep path attempt.
    outside = os.path.dirname(os.path.dirname(os.path.abspath(data)))
    ok(not os.path.exists(os.path.join(outside, "%sescaped" % T)),
       "no rdl_ artifact escaped the export root")
    recover("full DoS-limit battery")


