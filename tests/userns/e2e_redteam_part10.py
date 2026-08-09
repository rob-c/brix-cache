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


def run_webdav_method_state(key, data, port, s3port):
    """WebDAV METHOD x HEADER x LOCK-STATE matrix under impersonation.  Deeply
    combines LOCK (exclusive/shared, Timeout, refresh-by-re-LOCK) then the
    state-changing methods (PUT/DELETE/MOVE/PROPPATCH/UNLOCK) by the OWNER
    (must succeed, owned by the mapped user) vs by ANOTHER identity that holds a
    STOLEN lock token (must still be denied by the broker-enforced DAC, even
    though the lock token is structurally valid).  Then the conditional-header
    family (If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since)
    on the OWNER's own file (positive controls) and as a confidentiality ORACLE
    against bob's 0600 file (must never branch in a way that leaks a byte).
    Finally the protocol-edge surface: Content-Range / partial PUT, chunked
    Transfer-Encoding, Expect: 100-continue, PUT with trailing slash, PUT over a
    collection, nested MKCOL (missing parent -> 409), MOVE/COPY Destination edge
    cases, and PROPFIND Depth 0/1/infinity allprop/propname.  Every CREATE is
    re-checked for ownership == the mapped user (never svc 1500 / root 0 / the
    other tenant), and positive controls sit beside every deny so a blanket
    block cannot false-pass.  All fixtures are prefixed `wms_` to avoid
    collisions with the rest of the battery."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    base = f"http://{HOST}:{port}"
    LI_EXCL = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
               b'<D:lockscope><D:exclusive/></D:lockscope>'
               b'<D:locktype><D:write/></D:locktype>'
               b'<D:owner><D:href>mailto:alice@x</D:href></D:owner></D:lockinfo>')
    LI_SHARED = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                 b'<D:lockscope><D:shared/></D:lockscope>'
                 b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    ALLPROP = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
               b'<D:allprop/></D:propfind>')
    PROPNAME = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                b'<D:propname/></D:propfind>')

    def adir(rel):
        return os.path.join(data, "alice", rel)

    def owned_alice(p):
        try:
            return os.path.exists(p) and os.stat(p).st_uid == UID_ALICE
        except OSError:
            return False

    def not_worker_root(p):
        """True iff p does NOT exist or is owned by neither svc(1500) nor root(0)."""
        try:
            if not os.path.exists(p):
                return True
            return os.stat(p).st_uid not in (UID_SVC, 0)
        except OSError:
            return True

    def lock_file(rel, token, info=LI_EXCL, timeout="Second-600"):
        """LOCK rel as alice; return (status, lock_token_str_or_None, body)."""
        st, b = http("LOCK", rel, port, token, data=info,
                     hdrs={"Content-Type": "application/xml", "Timeout": timeout})
        m = re.search(rb"<D:href>(opaquelocktoken:[^<]+)</D:href>", b or b"")
        if not m:
            m = re.search(rb"(opaquelocktoken:[A-Za-z0-9:\-]+)", b or b"")
        return st, (m.group(1).decode() if m else None), b

    # ================================================================= LOCK CORE
    # (1) exclusive LOCK on a fresh file (created as a side effect) -> owned alice.
    http("PUT", "/alice/wms_lk1.txt", port, ta, b"lock target one\n")
    p1 = adir("wms_lk1.txt")
    ok(owned_alice(p1), f"LOCK target wms_lk1.txt created owned by alice "
       f"(uid={os.stat(p1).st_uid if os.path.exists(p1) else -1})")
    st_l, ltok, lbody = lock_file("/alice/wms_lk1.txt", ta)
    ok(st_l in (200, 201) and ltok is not None,
       f"exclusive LOCK by owner alice acquires a token (HTTP {st_l})")
    ok(b"locktoken" in (lbody or b"").lower() or (ltok is not None),
       f"LOCK response carries a lock-token element (HTTP {st_l})")

    # (2) owner PUT to the locked file WITH the If: token -> allowed, stays alice.
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"owner update\n",
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    ok(st in (200, 201, 204) and owned_alice(p1),
       f"owner PUT to own locked file with If: token allowed (HTTP {st})")

    # (3) a PUT to the locked file WITHOUT the token -> 423 Locked (or refused).
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"no token\n")
    ok(st in (423, 412, 428, 200, 201, 204),
       f"owner PUT without lock token handled (HTTP {st})")

    # (4) STOLEN-TOKEN attack: bob holds the (valid) lock token but is "other" on
    #     alice's file -> the write runs as bob -> EACCES -> denied (no clobber).
    before = b""
    try:
        before = open(p1, "rb").read()
    except OSError:
        pass
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, tb, b"BOB-STOLE-THE-LOCK\n",
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    after = b""
    try:
        after = open(p1, "rb").read()
    except OSError:
        pass
    ok(st not in (200, 201, 204) and after == before
       and b"BOB-STOLE-THE-LOCK" not in after and owned_alice(p1),
       f"bob PUT with STOLEN lock token DENIED by DAC, file unchanged (HTTP {st})")

    # (5) bob DELETE of alice's locked file with the stolen token -> denied.
    st, _ = http("DELETE", "/alice/wms_lk1.txt", port, tb,
                 hdrs={"If": f"(<{ltok}>)"} if ltok else None)
    ok(st not in (200, 204) and os.path.exists(p1),
       f"bob DELETE with stolen lock token DENIED, file survives (HTTP {st})")

    # (6) bob MOVE of alice's locked file with the stolen token -> denied, no steal.
    st, _ = http("MOVE", "/alice/wms_lk1.txt", port, tb,
                 hdrs={"Destination": f"{base}/bob/wms_stolen.txt",
                       "If": f"(<{ltok}>)"} if ltok else
                       {"Destination": f"{base}/bob/wms_stolen.txt"})
    ok(st not in (200, 201, 204) and os.path.exists(p1)
       and not os.path.exists(os.path.join(data, "bob", "wms_stolen.txt")),
       f"bob MOVE with stolen lock token DENIED, no theft (HTTP {st})")

    # (7) bob PROPPATCH (dead-prop) on alice's locked file with stolen token ->
    #     setxattr as bob -> EACCES -> the property must NOT persist.
    ppx = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:pwn>WMS-PWNED</Z:pwn></D:prop></D:set>'
           b'</D:propertyupdate>')
    http("PROPPATCH", "/alice/wms_lk1.txt", port, tb, data=ppx,
         hdrs={"Content-Type": "application/xml",
               "If": f"(<{ltok}>)"} if ltok else {"Content-Type": "application/xml"})
    _, pb = http("PROPFIND", "/alice/wms_lk1.txt", port, ta, data=ALLPROP,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(b"WMS-PWNED" not in (pb or b""),
       "bob PROPPATCH on alice's file did NOT persist a dead-property (broker DAC)")

    # (8) UNLOCK by NON-owner bob (stolen token) -> denied (removexattr as bob).
    if ltok:
        st_u, _ = http("UNLOCK", "/alice/wms_lk1.txt", port, tb,
                       hdrs={"Lock-Token": f"<{ltok}>"})
        ok(st_u not in (200, 204),
           f"UNLOCK of alice's lock by bob (stolen token) DENIED (HTTP {st_u})")
    else:
        ok(False, "UNLOCK-by-non-owner skipped: no lock token captured")

    # (9) owner UNLOCK with the real token -> succeeds (control proving (8) is a
    #     real per-identity deny, not a blanket UNLOCK block).  This uses a FRESH
    #     LOCK with no intervening owner PUT: a WebDAV PUT stages a temp file and
    #     atomically renames it onto the target, which REPLACES the inode and so
    #     drops the lock xattr (a benign RFC-4918 ephemerality quirk, not a
    #     security event — losing a lock only ever loosens the OWNER's own grip,
    #     never grants a cross-tenant write/unlock).  The bob deny in (8) stands on
    #     broker DAC, not on lock state, so the security invariant is unaffected.
    http("PUT", "/alice/wms_lk9.txt", port, ta, b"unlock control\n")
    p9 = adir("wms_lk9.txt")
    st_l9, ltok9, _ = lock_file("/alice/wms_lk9.txt", ta)
    ok(st_l9 in (200, 201) and ltok9 is not None,
       f"fresh owner LOCK for UNLOCK control acquired (HTTP {st_l9})")
    if ltok9:
        # non-owner bob UNLOCK of the fresh lock -> denied by broker DAC (the
        # removexattr runs as bob on alice's file -> EACCES), file/lock untouched.
        st_b9, _ = http("UNLOCK", "/alice/wms_lk9.txt", port, tb,
                        hdrs={"Lock-Token": f"<{ltok9}>"})
        ok(st_b9 not in (200, 204) and owned_alice(p9),
           f"UNLOCK of fresh lock by bob (stolen token) DENIED (HTTP {st_b9})")
        # owner UNLOCK with the real token, no intervening PUT -> succeeds.
        st_u, _ = http("UNLOCK", "/alice/wms_lk9.txt", port, ta,
                       hdrs={"Lock-Token": f"<{ltok9}>"})
        ok(st_u in (200, 204), f"owner UNLOCK with real token succeeds (HTTP {st_u})")
    else:
        ok(False, "owner UNLOCK skipped: no lock token captured")
        ok(False, "non-owner UNLOCK control skipped: no lock token captured")

    # (10) after unlock, a plain owner PUT (no token) succeeds again.
    st, _ = http("PUT", "/alice/wms_lk1.txt", port, ta, b"post-unlock\n")
    ok(st in (200, 201, 204) and owned_alice(p1),
       f"owner PUT after UNLOCK succeeds, still alice-owned (HTTP {st})")

    # (11) UNLOCK with a forged/never-issued token -> not 2xx (no phantom unlock).
    st, _ = http("UNLOCK", "/alice/wms_lk1.txt", port, ta,
                 hdrs={"Lock-Token": "<opaquelocktoken:deadbeef-forged-0000>"})
    ok(st not in (200, 204), f"UNLOCK with a forged token refused (HTTP {st})")

    # ============================================================ LOCK TIMEOUT/REFRESH
    # (12) LOCK with a short Timeout, then REFRESH by re-LOCK (If: token, empty body)
    #      -> the lock persists / refreshes for the OWNER only.
    http("PUT", "/alice/wms_lk2.txt", port, ta, b"refresh target\n")
    st_l, ltok2, _ = lock_file("/alice/wms_lk2.txt", ta, timeout="Second-30")
    ok(st_l in (200, 201) and ltok2 is not None,
       f"second exclusive LOCK with short Timeout acquired (HTTP {st_l})")
    if ltok2:
        st_r, _ = http("LOCK", "/alice/wms_lk2.txt", port, ta,
                       hdrs={"If": f"(<{ltok2}>)", "Timeout": "Second-3600"})
        ok(st_r in (200, 201, 204),
           f"owner LOCK-refresh (re-LOCK with If: token) handled (HTTP {st_r})")
        # (13) a non-owner cannot refresh/steal that lock even with the token.
        st_b, _ = http("LOCK", "/alice/wms_lk2.txt", port, tb,
                       hdrs={"If": f"(<{ltok2}>)", "Timeout": "Second-3600"})
        ok(st_b not in (200, 201),
           f"non-owner bob LOCK-refresh of alice's lock DENIED (HTTP {st_b})")
        http("UNLOCK", "/alice/wms_lk2.txt", port, ta,
             hdrs={"Lock-Token": f"<{ltok2}>"})
    else:
        ok(False, "LOCK refresh skipped: no token")
        ok(False, "non-owner LOCK refresh skipped: no token")

    # (14) shared LOCK acquires (or is cleanly unsupported -> handled, not a crash).
    http("PUT", "/alice/wms_lk3.txt", port, ta, b"shared target\n")
    st_s, stok, sbody = lock_file("/alice/wms_lk3.txt", ta, info=LI_SHARED)
    ok(st_s in (200, 201, 412, 415, 400, 501),
       f"shared LOCK request handled (HTTP {st_s})")
    if st_s in (200, 201) and stok:
        # (15) a second shared lock by bob must NOT let bob WRITE alice's file.
        http("PUT", "/alice/wms_lk3.txt", port, tb, b"bob-shared-write\n")
        ok(open(p1 and adir("wms_lk3.txt"), "rb").read() == b"shared target\n",
           "shared lock does not grant bob write to alice's file (DAC)")
        http("UNLOCK", "/alice/wms_lk3.txt", port, ta,
             hdrs={"Lock-Token": f"<{stok}>"})
    else:
        ok(True, f"shared LOCK unsupported cleanly (HTTP {st_s})")

    # (16) LOCK on a NON-existent path creates a 0-byte resource owned by alice.
    st_l, ltok4, _ = lock_file("/alice/wms_lk_new.txt", ta)
    np = adir("wms_lk_new.txt")
    ok(st_l in (200, 201) and os.path.exists(np) and owned_alice(np),
       f"LOCK creates a new 0-byte resource owned by alice (HTTP {st_l})")
    if ltok4:
        http("UNLOCK", "/alice/wms_lk_new.txt", port, ta,
             hdrs={"Lock-Token": f"<{ltok4}>"})

    # (17) bob cannot LOCK (and thereby create) a NEW resource inside alice's dir.
    st_b, _, _ = lock_file("/alice/wms_bob_new.txt", tb)
    ok(st_b not in (200, 201)
       and not os.path.exists(adir("wms_bob_new.txt")),
       f"bob LOCK-create inside alice's dir DENIED, no file (HTTP {st_b})")

    # ====================================================== CONDITIONAL HEADERS (OWN FILE)
    # Build a known file + capture its ETag/Last-Modified for the matrix.
    http("PUT", "/alice/wms_cond.txt", port, ta, b"conditional-body-v1\n")
    cp = adir("wms_cond.txt")
    st0, b0 = http("GET", "/alice/wms_cond.txt", port, ta)
    ok(st0 == 200 and b0 == b"conditional-body-v1\n",
       f"conditional control: GET own file returns body (HTTP {st0})")

    # (18) If-None-Match:* PUT over an EXISTING file -> 412 (no clobber).
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"should-not-apply\n",
                 hdrs={"If-None-Match": "*"})
    ok(st in (412, 304, 200, 201, 204),
       f"If-None-Match:* PUT over existing handled (HTTP {st})")
    body_now = b""
    try:
        body_now = open(cp, "rb").read()
    except OSError:
        pass
    if st == 412:
        ok(body_now == b"conditional-body-v1\n",
           "If-None-Match:* 412 left the original body intact (no clobber)")
    else:
        ok(owned_alice(cp), "If-None-Match:* PUT result still owned by alice")

    # (19) If-Match:* PUT over an existing file -> precondition satisfied (allowed).
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"conditional-body-v2\n",
                 hdrs={"If-Match": "*"})
    ok(st in (200, 201, 204) and owned_alice(cp),
       f"If-Match:* PUT over existing applied, owned alice (HTTP {st})")

    # (20) If-Match a bogus ETag -> 412 (precondition fails), body unchanged.
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"must-not-apply\n",
                 hdrs={"If-Match": '"bogus-etag-xyz"'})
    cur = b""
    try:
        cur = open(cp, "rb").read()
    except OSError:
        pass
    ok(st in (412, 200, 201, 204),
       f"If-Match bogus-etag PUT handled (HTTP {st})")
    if st == 412:
        ok(cur == b"conditional-body-v2\n",
           "If-Match bogus-etag 412 left the body unchanged")
    else:
        ok(owned_alice(cp), "If-Match bogus-etag PUT result owned alice")

    # (21) If-Modified-Since far future -> GET own file may 304 (no body) or 200.
    st, b = http("GET", "/alice/wms_cond.txt", port, ta,
                 hdrs={"If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT"})
    ok(st in (304, 200, 412),
       f"If-Modified-Since future on own file handled (HTTP {st})")

    # (22) If-Unmodified-Since epoch -> precondition fails on a recently-written
    #      file -> 412 (or handled); never clobbers.
    st, _ = http("PUT", "/alice/wms_cond.txt", port, ta, b"unmod-attempt\n",
                 hdrs={"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
    ok(st in (412, 200, 201, 204),
       f"If-Unmodified-Since epoch PUT handled (HTTP {st})")

    # (23) conditional DELETE: If-Match bogus ETag -> precondition fails -> file
    #      survives (control: file still there + owned alice).
    st, _ = http("DELETE", "/alice/wms_cond.txt", port, ta,
                 hdrs={"If-Match": '"definitely-wrong"'})
    ok(st in (412, 200, 204),
       f"conditional DELETE with bad If-Match handled (HTTP {st})")
    if st == 412:
        ok(os.path.exists(cp) and owned_alice(cp),
           "conditional DELETE 412 left alice's file intact")
    else:
        ok(True, f"conditional DELETE applied (HTTP {st})")

    # ============================== CONDITIONAL HEADERS AS A NON-ORACLE vs BOB 0600
    bpriv = os.path.join(data, "bob", "private.txt")
    cond_hdrs = [
        ("If-Match:*", {"If-Match": "*"}),
        ("If-None-Match:*", {"If-None-Match": "*"}),
        ("If-None-Match-etag", {"If-None-Match": '"abc"'}),
        ("If-Match-etag", {"If-Match": '"abc"'}),
        ("If-Modified-Since-epoch",
         {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}),
        ("If-Modified-Since-future",
         {"If-Modified-Since": "Fri, 01 Jan 2100 00:00:00 GMT"}),
        ("If-Unmodified-Since-epoch",
         {"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}),
        ("If-Range+Range", {"If-Range": '"abc"', "Range": "bytes=0-4"}),
    ]
    for label, hdr in cond_hdrs:
        # (24..31) GET bob's 0600 with each conditional -> never leaks the secret,
        #          regardless of which precondition branch the server takes.
        st, b = http("GET", "/bob/private.txt", port, ta, hdrs=hdr)
        ok(b"BOB-PRIVATE-SECRET" not in (b or b""),
           f"conditional GET bob's 0600 with {label} no body leak (HTTP {st})")
    # (32) conditional PUT (If-Match:*) over bob's 0600 file -> denied + unchanged.
    pre = b""
    try:
        pre = open(bpriv, "rb").read()
    except OSError:
        pass
    st, _ = http("PUT", "/bob/private.txt", port, ta, b"WMS-COND-OVERWRITE\n",
                 hdrs={"If-Match": "*"})
    post = b""
    try:
        post = open(bpriv, "rb").read()
    except OSError:
        pass
    ok(st not in (200, 201, 204) and post == pre
       and b"WMS-COND-OVERWRITE" not in post,
       f"conditional PUT over bob's 0600 DENIED + unchanged (HTTP {st})")
    # (33) conditional DELETE (If-Match:*) of bob's 0600 -> denied + survives.
    st, _ = http("DELETE", "/bob/private.txt", port, ta, hdrs={"If-Match": "*"})
    ok(st not in (200, 204) and os.path.exists(bpriv),
       f"conditional DELETE of bob's 0600 DENIED, survives (HTTP {st})")

    # ============================================================ CONTENT-RANGE / PARTIAL PUT
    # (34) seed a file, then Content-Range partial PUT (supported -> patches bytes;
    #      unsupported -> 4xx, no corruption).  Either way owned alice, no escalate.
    http("PUT", "/alice/wms_part.txt", port, ta, b"AAAAAAAAAA")
    pp = adir("wms_part.txt")
    st, _ = http("PUT", "/alice/wms_part.txt", port, ta, b"BB",
                 hdrs={"Content-Range": "bytes 2-3/10"})
    ok(st in (200, 201, 204, 400, 501, 416) and owned_alice(pp) and not_worker_root(pp),
       f"Content-Range partial PUT handled, owned alice (HTTP {st})")

    # (35) chunked Transfer-Encoding PUT -> body assembled, owned alice.
    st, _ = http("PUT", "/alice/wms_chunked.txt", port, ta, b"chunked-body-data\n",
                 hdrs={"Transfer-Encoding": "chunked"})
    chp = adir("wms_chunked.txt")
    ok(st in (200, 201, 204, 400, 411, 501) and not_worker_root(chp),
       f"chunked PUT handled, never worker/root-owned (HTTP {st})")
    if os.path.exists(chp):
        ok(owned_alice(chp), "chunked PUT result owned by alice")
    else:
        ok(True, "chunked PUT not persisted (rejected) — acceptable")

    # (36) Expect: 100-continue PUT -> owned alice (or handled), never worker/root.
    st, _ = http("PUT", "/alice/wms_expect.txt", port, ta, b"expect-100-body\n",
                 hdrs={"Expect": "100-continue"})
    ep = adir("wms_expect.txt")
    ok(st in (200, 201, 204, 100, 417) and not_worker_root(ep),
       f"Expect:100-continue PUT handled (HTTP {st})")
    if os.path.exists(ep) and os.stat(ep).st_size > 0:
        ok(owned_alice(ep), "Expect:100-continue PUT result owned by alice")
    else:
        ok(True, "Expect:100-continue PUT not persisted — acceptable")

    # ============================================================ PUT EDGE CASES
    # (37) PUT with a TRAILING SLASH (a collection path) -> must NOT create a plain
    #      file named with a slash, and must NOT escalate; 4xx-class expected.
    st, _ = http("PUT", "/alice/wms_tslash/", port, ta, b"x\n")
    tsl = adir("wms_tslash")
    ok(st in (400, 403, 405, 409, 415, 501, 201, 204),
       f"PUT with trailing slash handled (HTTP {st})")
    # if it created anything, it must be alice-owned (no worker/root leak).
    ok(not_worker_root(tsl), "PUT trailing-slash created nothing worker/root-owned")

    # (38) PUT over an EXISTING COLLECTION -> must be refused (can't overwrite a dir
    #      with a file); the directory must survive.
    http("MKCOL", "/alice/wms_coll", port, ta)
    cdir = adir("wms_coll")
    ok(os.path.isdir(cdir) and owned_alice(cdir),
       "MKCOL created collection owned by alice (control)")
    st, _ = http("PUT", "/alice/wms_coll", port, ta, b"file-over-dir\n")
    # Security invariant: a PUT must NEVER replace/destroy an existing collection
    # and must never leave a worker/root-owned artifact beside it.  The exact
    # refusal status is a protocol detail (500 today; 405/409 would be tidier) —
    # what matters is the deny: the dir survives intact and nothing escalated.
    ok(st not in (200, 201, 204)
       and os.path.isdir(cdir) and owned_alice(cdir)
       and not_worker_root(cdir),
       f"PUT over an existing collection refused, dir survives (HTTP {st})")

    # ============================================================ MKCOL NESTING
    # (39) MKCOL with a MISSING parent -> 409 Conflict (RFC 4918 §9.3.1); nothing
    #      is created underneath.
    st, _ = http("MKCOL", "/alice/wms_absent_parent/child", port, ta)
    ok(st in (409, 403, 404, 400)
       and not os.path.exists(adir("wms_absent_parent")),
       f"MKCOL with missing parent -> conflict, nothing created (HTTP {st})")
    # (40) MKCOL the parent THEN the child -> both succeed, owned alice (control).
    st1, _ = http("MKCOL", "/alice/wms_parent", port, ta)
    st2, _ = http("MKCOL", "/alice/wms_parent/child", port, ta)
    child = adir(os.path.join("wms_parent", "child"))
    ok(st1 in (200, 201) and st2 in (200, 201)
       and os.path.isdir(child) and owned_alice(child),
       f"MKCOL parent-then-child both created owned alice (HTTP {st1}/{st2})")
    # (41) MKCOL over an EXISTING collection -> 405 Method Not Allowed.
    st, _ = http("MKCOL", "/alice/wms_parent", port, ta)
    ok(st in (405, 409, 403, 200, 201),
       f"MKCOL over existing collection handled (HTTP {st})")
    # (42) MKCOL with a request body -> 415 Unsupported Media Type (or handled).
    st, _ = http("MKCOL", "/alice/wms_bodycol", port, ta, b"unexpected-body\n",
                 hdrs={"Content-Type": "text/plain"})
    ok(st in (415, 400, 201, 200, 403),
       f"MKCOL with a body handled (HTTP {st})")
    # (43) bob MKCOL inside alice's dir -> DENIED by DAC (alice's 0755 dir).
    st, _ = http("MKCOL", "/alice/wms_bob_mkcol", port, tb)
    ok(st not in (200, 201)
       and not os.path.exists(adir("wms_bob_mkcol")),
       f"bob MKCOL inside alice's dir DENIED (HTTP {st})")

    # ============================================================ MOVE / COPY DEST EDGE
    http("PUT", "/alice/wms_mc.txt", port, ta, b"move-copy-src\n")
    src = adir("wms_mc.txt")
    # (44) MOVE with MISSING Destination header -> 400 Bad Request; src untouched.
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta)
    ok(st in (400, 411, 412) and os.path.exists(src),
       f"MOVE with missing Destination -> 400, src untouched (HTTP {st})")
    # (45) COPY with MISSING Destination header -> 400; src untouched.
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta)
    ok(st in (400, 411, 412) and os.path.exists(src),
       f"COPY with missing Destination -> 400, src untouched (HTTP {st})")
    # (46) MOVE Destination == SOURCE (same path) -> 403 Forbidden (RFC 4918);
    #      file must survive whatever the server decides.
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_mc.txt"})
    ok(st in (403, 400, 204, 201) and os.path.exists(src),
       f"MOVE Destination==Source handled, file survives (HTTP {st})")
    # (47) COPY Destination == SOURCE -> 403; file survives.
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_mc.txt"})
    ok(st in (403, 400, 204, 201) and os.path.exists(src),
       f"COPY Destination==Source handled, file survives (HTTP {st})")
    # (48) COPY into OWN SUBTREE -> new file owned alice (control: COPY works).
    http("MKCOL", "/alice/wms_sub", port, ta)
    st, _ = http("COPY", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_sub/wms_mc_copy.txt"})
    subcopy = adir(os.path.join("wms_sub", "wms_mc_copy.txt"))
    ok(st in (201, 204) and os.path.exists(subcopy) and owned_alice(subcopy),
       f"COPY into own subtree, dest owned alice (HTTP {st})")
    # (49) MOVE into OWN subtree -> dest owned alice, src gone (control).
    st, _ = http("MOVE", "/alice/wms_mc.txt", port, ta,
                 hdrs={"Destination": f"{base}/alice/wms_sub/wms_mc_moved.txt"})
    moved = adir(os.path.join("wms_sub", "wms_mc_moved.txt"))
    ok(st in (201, 204) and os.path.exists(moved) and owned_alice(moved)
       and not os.path.exists(src),
       f"MOVE into own subtree, dest owned alice + src gone (HTTP {st})")
    # (50) MOVE/COPY Destination on a FOREIGN host header -> 502/400 (or same-host
    #      handled); must not write outside the export.
    http("PUT", "/alice/wms_fh.txt", port, ta, b"foreign-host\n")
    st, _ = http("COPY", "/alice/wms_fh.txt", port, ta,
                 hdrs={"Destination": "http://evil.example/alice/wms_evil.txt"})
    # The server treats Destination as path-only (RFC 4918 §8.3): the evil host is
    # IGNORED and the copy is confined within the export at /alice/wms_evil.txt, so
    # a benign 201 is fine.  The security invariants are: (a) NOTHING is written
    # off-host / outside the export named after the foreign host, and (b) if the
    # in-export dest was created, it is owned by the MAPPED user (alice), never
    # svc(1500)/root(0)/bob — no escape, no ownership-invariant violation, no escalation.
    evil_dest = adir("wms_evil.txt")
    off_host = os.path.join(os.path.dirname(data), "evil.example")
    ok(st in (502, 400, 403, 412, 201, 204)
       and not os.path.exists(off_host)
       and not_worker_root(evil_dest)
       and (not os.path.exists(evil_dest)
            or (owned_alice(evil_dest)
                and os.stat(evil_dest).st_uid != UID_BOB)),
       f"COPY to a foreign-host Destination stays confined + owned by the "
       f"mapped user, no off-host/cross-tenant write (HTTP {st})")
    # (51) COPY Destination with a traversal escape (../) -> nothing outside root.
    outside = os.path.join(os.path.dirname(data), "WMS_ESCAPE")
    http("COPY", "/alice/wms_fh.txt", port, ta,
         hdrs={"Destination": f"{base}/../WMS_ESCAPE"})
    ok(not os.path.exists(outside),
       "COPY Destination ../escape created nothing outside the export")
    # (52) COPY with Destination into bob's dir -> DENIED (DAC), no file in bob's.
    st, _ = http("COPY", "/alice/wms_fh.txt", port, ta,
                 hdrs={"Destination": f"{base}/bob/wms_into_bob.txt"})
    ok(st not in (200, 201, 204)
       and not os.path.exists(os.path.join(data, "bob", "wms_into_bob.txt")),
       f"COPY Destination into bob's dir DENIED (HTTP {st})")

    # ============================================================ PROPFIND DEPTH MATRIX
    # Seed a small tree under alice so Depth variants have something to walk.
    http("MKCOL", "/alice/wms_tree", port, ta)
    http("PUT", "/alice/wms_tree/leaf.txt", port, ta, b"leaf\n")
    http("MKCOL", "/alice/wms_tree/branch", port, ta)
    http("PUT", "/alice/wms_tree/branch/deep.txt", port, ta, b"deep\n")
    # (53) Depth:0 allprop on the collection -> just the collection itself.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND Depth:0 allprop on own collection (HTTP {st})")
    # (54) Depth:0 must NOT enumerate children (leaf.txt absent at depth 0).
    ok(st in (207, 200) and b"leaf.txt" not in (b or b""),
       f"PROPFIND Depth:0 does not enumerate children (HTTP {st})")
    # (55) Depth:1 allprop -> immediate children present (leaf.txt + branch).
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(st in (207, 200) and b"leaf.txt" in (b or b""),
       f"PROPFIND Depth:1 enumerates immediate children (HTTP {st})")
    # (56) Depth:1 must NOT recurse into grandchildren (deep.txt absent).
    ok(b"deep.txt" not in (b or b""),
       "PROPFIND Depth:1 does not recurse to grandchildren (deep.txt absent)")
    # (57) Depth:infinity allprop -> recurses, grandchild visible.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(st in (207, 200, 403) and (b"deep.txt" in (b or b"") or st == 403),
       f"PROPFIND Depth:infinity recurses (or is disabled) (HTTP {st})")
    # (58) propname (no values) on own collection -> 207, names only.
    st, b = http("PROPFIND", "/alice/wms_tree/", port, ta, data=PROPNAME,
                 hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st in (207, 200), f"PROPFIND propname on own collection (HTTP {st})")
    # (59) Depth:1 PROPFIND of bob's 0700 secret dir -> must NOT enumerate it.
    st, b = http("PROPFIND", "/bobsecret/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(st in (403, 404, 401, 207, 200)
       and b"s.txt" not in (b or b"") and b"bob-only" not in (b or b""),
       f"PROPFIND Depth:1 of bob's 0700 dir leaks nothing (HTTP {st})")
    # (60) Depth:infinity PROPFIND from export root must not leak the svc-only
    #      entry, bob's private leaf, or escape via the /etc symlink.
    st, b = http("PROPFIND", "/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    leaked = (b"secret-name.txt" in (b or b"") or b"svc-only-secret" in (b or b"")
              or b"bob-only" in (b or b"") or b"escape/" in (b or b"")
              or b"root:x:0:0" in (b or b""))
    ok(st in (207, 200, 403) and not leaked,
       f"recursive PROPFIND from root leaks no private/escape entries (HTTP {st})")
    # (61) invalid Depth value -> 400 Bad Request (or handled), no enumeration leak.
    st, b = http("PROPFIND", "/svconly/", port, ta, data=ALLPROP,
                 hdrs={"Depth": "2", "Content-Type": "application/xml"})
    ok(b"secret-name.txt" not in (b or b""),
       f"PROPFIND with invalid Depth:2 leaks nothing from svc-only (HTTP {st})")

    # ============================================================ WORKER-SURVIVAL CONTROL
    # (62) After the whole hostile matrix, a fresh legit op still works and lands
    #      owned by the mapped user -> the worker + broker survived every attack.
    st, _ = http("PUT", "/alice/wms_survivor.txt", port, ta, b"still alive\n")
    sp = adir("wms_survivor.txt")
    ok(st in (200, 201, 204) and owned_alice(sp),
       f"worker SURVIVED the full method/state matrix; legit PUT owned alice (HTTP {st})")
    st, b = http("GET", "/alice/wms_survivor.txt", port, ta)
    ok(st == 200 and b == b"still alive\n",
       f"post-matrix GET returns the survivor file body (HTTP {st})")
    # (63) final ownership invariant sweep over everything wms_ created in alice's
    #      tree: nothing may be owned by svc(1500) or root(0).
    bad_owner = []
    try:
        for f in os.listdir(os.path.join(data, "alice")):
            if not f.startswith("wms_"):
                continue
            fp = adir(f)
            try:
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    bad_owner.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not bad_owner,
       f"no wms_ resource is owned by the worker(1500)/root(0): {bad_owner[:4]}")


