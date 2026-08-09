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


def run_concurrency_state_race(key, data, port, s3port):
    """CONCURRENCY / ORDERING / STATE-CONFUSION races against the per-worker, process-
    global impersonation principal.  Every storm below tries to make an op execute
    under a STALE or LEAKED principal (alice's setfsuid bleeding into bob's request or
    vice-versa), then proves it did not by: (a) the op landing in the correct owner's
    space, (b) the created/mutated file's st_uid matching the DRIVING identity (never
    the worker svc=1500, never root=0, never the other tenant), (c) the worker
    SURVIVING (a follow-up legit op still works), and (d) a full os.lstat scan of both
    user dirs finding zero wrong-owner regular files after the storm.  Each deny carries
    a nearby positive control so a blanket block cannot false-pass."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    TAG = "csr_"            # fixture/file prefix to avoid collisions with other batteries

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def apath(name):
        return os.path.join(data, "alice", name)

    def bpath(name):
        return os.path.join(data, "bob", name)

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    def scan_misowned():
        """Count regular files in alice/ + bob/ that belong to the WRONG uid (the
        other tenant), to svc(1500), or to root(0).  Only judges our TAG files plus
        any svc/root-owned file (a svc/root-owned data file is always a leak signal)."""
        bad = []
        for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB)):
            d = os.path.join(data, sub)
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for f in names:
                p = os.path.join(d, f)
                try:
                    stx = os.lstat(p)
                except OSError:
                    continue
                if not (stx.st_mode & 0o170000) == 0o100000:   # skip non-regular
                    continue
                u = stx.st_uid
                if u in (UID_SVC, 0):
                    bad.append((sub, f, u))
                elif f.startswith(TAG) and u != want:
                    bad.append((sub, f, u))
        return bad

    # ============================================================================
    # A) KEEP-ALIVE INTERLEAVE — a,b,a,b... on ONE TCP connection.  If the principal
    #    is reused stale, alice's PUT could create bob-owned files or land in bob/.
    # ============================================================================
    inter = []
    for i in range(8):
        a_name, b_name = f"{TAG}ka_a_{i}.txt", f"{TAG}ka_b_{i}.txt"
        inter.append(("PUT", f"/alice/{a_name}", ta, b"A-keepalive\n", None))
        inter.append(("PUT", f"/bob/{b_name}", tb, b"B-keepalive\n", None))
    res = http_keepalive(inter, port)
    ok(len(res) == 16, f"keep-alive interleave: all 16 requests answered on one conn "
       f"(got {len(res)})")
    ka_ok = sum(1 for (s, _b) in res if s in (200, 201, 204))
    ok(ka_ok == 16, f"keep-alive interleave: every PUT accepted (2xx={ka_ok}/16)")
    a_mis = b_mis = 0
    for i in range(8):
        ap, bp = apath(f"{TAG}ka_a_{i}.txt"), bpath(f"{TAG}ka_b_{i}.txt")
        if not (os.path.exists(ap) and st_uid(ap) == UID_ALICE):
            a_mis += 1
        if not (os.path.exists(bp) and st_uid(bp) == UID_BOB):
            b_mis += 1
    ok(a_mis == 0, f"keep-alive: all 8 alice files owned alice, none stale-principal "
       f"(mismatch={a_mis})")
    ok(b_mis == 0, f"keep-alive: all 8 bob files owned bob, none stale-principal "
       f"(mismatch={b_mis})")
    # no alice file leaked into bob's dir or vice-versa (path landed under wrong owner)
    cross = 0
    for i in range(8):
        if os.path.exists(bpath(f"{TAG}ka_a_{i}.txt")):
            cross += 1
        if os.path.exists(apath(f"{TAG}ka_b_{i}.txt")):
            cross += 1
    ok(cross == 0, f"keep-alive: no request landed in the other tenant's dir (cross={cross})")

    # ============================================================================
    # B) BURST ORDERING — aaaa...bbbb...aaaa on one connection (run of same identity
    #    then a flip).  A flip without re-establishing the principal would write the
    #    first post-flip request under the previous identity.
    # ============================================================================
    burst = []
    order = (["a"] * 5) + (["b"] * 5) + (["a"] * 5) + (["b"] * 5)
    for i, who in enumerate(order):
        if who == "a":
            burst.append(("PUT", f"/alice/{TAG}burst_{i}.txt", ta, b"a\n", None))
        else:
            burst.append(("PUT", f"/bob/{TAG}burst_{i}.txt", tb, b"b\n", None))
    bres = http_keepalive(burst, port)
    ok(sum(1 for (s, _b) in bres if s in (200, 201, 204)) == 20,
       f"burst-order: all 20 PUTs accepted ({sum(1 for (s,_b) in bres if s in (200,201,204))}/20)")
    flip_bad = 0
    for i, who in enumerate(order):
        want = UID_ALICE if who == "a" else UID_BOB
        d = "alice" if who == "a" else "bob"
        fp = os.path.join(data, d, f"{TAG}burst_{i}.txt")
        if not (os.path.exists(fp) and st_uid(fp) == want):
            flip_bad += 1
    ok(flip_bad == 0, f"burst-order: every post-flip request used the CORRECT principal "
       f"(no stale carry-over; bad={flip_bad})")

    # ============================================================================
    # C) PIPELINED PUTs same path, alternating identities — last writer wins but the
    #    file must end up owned by WHOEVER actually wrote it, never svc/root, and the
    #    body must match an identity that was allowed to write (alice owns alice/).
    # ============================================================================
    shared = f"{TAG}pipe_shared.txt"
    pipe = []
    for i in range(6):
        tok = ta if i % 2 == 0 else tb
        body = b"alice-wins\n" if i % 2 == 0 else b"bob-attempt\n"
        # both target /alice/<shared>: alice writes succeed, bob writes must be denied
        pipe.append(("PUT", f"/alice/{shared}", tok, body, None))
    http_keepalive(pipe, port)
    sp = apath(shared)
    # alice's dir is 0755 alice-owned: bob (other) cannot create/replace here.
    final_uid = st_uid(sp)
    ok(os.path.exists(sp) and final_uid == UID_ALICE,
       f"pipelined same-path: final file owned alice, never bob/svc/root (uid={final_uid})")
    try:
        fb = open(sp, "rb").read()
    except OSError:
        fb = b""
    ok(b"bob-attempt" not in fb,
       "pipelined same-path: bob's interleaved write did NOT overwrite alice's file body")

    # ============================================================================
    # D) SIMULTANEOUS SAME-PATH CREATE by alice & bob (true threads) into a world-
    #    writable shared dir.  Whoever wins, the file must be owned by a REAL mapped
    #    user (1001 or 1002) — never svc/root — and must not be a torn mix.
    # ============================================================================
    pub_shared = f"{TAG}pub_race.txt"
    pp = os.path.join(data, "pub", pub_shared)
    rm_quiet(pp)
    race_status = {}

    def create_pub(who):
        tok = ta if who == "alice" else tb
        s, _b = http("PUT", f"/pub/{pub_shared}", port, tok,
                     (who + "-pub\n").encode())
        race_status[who] = s

    for _round in range(6):       # repeat to widen the race window
        rm_quiet(pp)
        ths = [threading.Thread(target=create_pub, args=(w,))
               for w in ("alice", "bob", "alice", "bob")]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
    winner = st_uid(pp)
    ok(os.path.exists(pp) and winner in (UID_ALICE, UID_BOB),
       f"same-path race in /pub: winner is a real mapped user, not svc/root "
       f"(uid={winner})")
    ok(winner != UID_SVC and winner != 0,
       f"same-path race: created file NEVER owned by worker(1500)/root(0) (uid={winner})")
    rm_quiet(pp)

    # ============================================================================
    # E) OPEN-AS-A then immediately OP-AS-B referencing A's just-created private file.
    #    alice creates a 0600 file; bob (driving on the SAME worker right after) must
    #    NOT be able to read it (no principal carry-over from the create).
    # ============================================================================
    SECRET = b"ALICE-OPEN-RACE-MARKER-7731\n"
    arace = f"{TAG}open_race.txt"
    http("PUT", f"/alice/{arace}", port, ta, SECRET)
    fp = apath(arace)
    try:
        os.chmod(fp, 0o600)
    except OSError:
        pass
    ok(os.path.exists(fp) and st_uid(fp) == UID_ALICE and (os.lstat(fp).st_mode & 0o077) == 0,
       f"open-race setup: alice's 0600 marker file in place (uid={st_uid(fp)})")
    # bob immediately reads it via keep-alive right after an alice op on the same conn
    seq = [("GET", f"/alice/{arace}", ta, None, None),   # alice reads own (control)
           ("GET", f"/alice/{arace}", tb, None, None)]   # bob reads alice's 0600 (deny)
    sres = http_keepalive(seq, port)
    a_st, a_body = sres[0] if len(sres) > 0 else (-1, b"")
    b_st, b_body = sres[1] if len(sres) > 1 else (-1, b"")
    ok(a_st == 200 and SECRET in (a_body or b""),
       f"control: alice reads her own 0600 file on the shared conn (HTTP {a_st})")
    ok(b_st in (401, 403, 404) and SECRET not in (b_body or b""),
       f"open-race: bob CANNOT read alice's 0600 file via principal carry-over "
       f"(HTTP {b_st})")

    # ============================================================================
    # F) MANY CONCURRENT COLLECTION COPYs (true threads).  COPY of a collection runs
    #    inline (recursive walk + per-child create) — a long op that holds the
    #    principal; many in flight stress for desync.  Each alice COPY's destination
    #    tree must be wholly alice-owned; bob's must be bob-owned; broker must not wedge.
    # ============================================================================
    # seed a small collection for each user
    for who, tok, d in (("alice", ta, "alice"), ("bob", tb, "bob")):
        http("MKCOL", f"/{d}/{TAG}coll_src", port, tok)
        for j in range(3):
            http("PUT", f"/{d}/{TAG}coll_src/f{j}.txt", port, tok,
                 (who + f"-{j}\n").encode())
    copy_bad = []

    def coll_copy(idx):
        who = "alice" if idx % 2 == 0 else "bob"
        tok = ta if who == "alice" else tb
        d = who
        dst = f"/{d}/{TAG}coll_dst_{idx}"
        s, _b = http("COPY", f"/{d}/{TAG}coll_src", port, tok,
                     hdrs={"Destination": f"http://{HOST}:{port}{dst}",
                           "Depth": "infinity"})
        if s not in (200, 201, 204, 207):
            copy_bad.append((who, idx, s))

    cths = [threading.Thread(target=coll_copy, args=(i,)) for i in range(12)]
    for t in cths:
        t.start()
    for t in cths:
        t.join()
    ok(len(copy_bad) <= 12 and all(b[2] not in (-1,) for b in copy_bad),
       f"concurrent collection COPY: no broker hang/connection-death "
       f"(failures={copy_bad[:3]})")
    # every copied tree must be owned by the DRIVING user only (no desync cross-owner)
    coll_mis = 0
    coll_seen = 0
    for idx in range(12):
        who = "alice" if idx % 2 == 0 else "bob"
        want = UID_ALICE if who == "alice" else UID_BOB
        dstdir = os.path.join(data, who, f"{TAG}coll_dst_{idx}")
        if not os.path.isdir(dstdir):
            continue
        for root_, dirs, files in os.walk(dstdir):
            for name in list(dirs) + list(files):
                pth = os.path.join(root_, name)
                u = st_uid(pth)
                coll_seen += 1
                if u != want:
                    coll_mis += 1
    ok(coll_seen > 0, f"concurrent COPY: at least one destination tree materialised "
       f"(entries seen={coll_seen})")
    ok(coll_mis == 0, f"concurrent COPY: every copied entry owned by the DRIVING user "
       f"(no broker principal desync; cross-owner={coll_mis})")
    # broker survives: a follow-up legit op still works after the COPY storm
    st, _ = http("PUT", f"/alice/{TAG}post_copy.txt", port, ta, b"survived\n")
    pcp = apath(f"{TAG}post_copy.txt")
    ok(st in (200, 201, 204) and os.path.exists(pcp) and st_uid(pcp) == UID_ALICE,
       f"broker SURVIVES the COPY storm: follow-up alice PUT owned alice (HTTP {st})")

    # ============================================================================
    # G) LOCK-TOKEN THEFT RACE — alice LOCKs her file; bob (concurrently, same worker)
    #    tries to mutate it presenting alice's lock token in If:.  The lock token is
    #    NOT an authorization grant — bob is still "other" on alice's 0644 file and the
    #    broker must deny his write.
    # ============================================================================
    lk = f"{TAG}lock_target.txt"
    http("PUT", f"/alice/{lk}", port, ta, b"lock-race-body\n")
    try:
        os.chmod(apath(lk), 0o644)
    except OSError:
        pass
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    lst, lbody = http("LOCK", f"/alice/{lk}", port, ta, data=li,
                      hdrs={"Content-Type": "application/xml", "Timeout": "Second-600"})
    m = re.search(rb"<[^>]*locktoken[^>]*>\s*<[^>]*href[^>]*>\s*([^<\s]+)",
                  lbody or b"", re.I)
    if not m:
        m = re.search(rb"(urn:uuid:[0-9a-fA-F-]+|opaquelocktoken:[^<\s]+)", lbody or b"")
    token_uri = m.group(1).decode() if m else "urn:uuid:00000000-0000-0000-0000-000000000000"
    ok(lst in (200, 201), f"lock-token theft setup: alice LOCK acquired (HTTP {lst})")
    # bob replays alice's stolen lock token to PUT over her file
    bst, _ = http("PUT", f"/alice/{lk}", port, tb, b"BOB-STOLE-LOCK\n",
                  hdrs={"If": f"(<{token_uri}>)"})
    body_now = b""
    try:
        body_now = open(apath(lk), "rb").read()
    except OSError:
        pass
    ok(bst not in (200, 201, 204) and b"BOB-STOLE-LOCK" not in body_now,
       f"lock-token theft: bob replaying alice's lock token did NOT overwrite her file "
       f"(HTTP {bst})")
    ok(st_uid(apath(lk)) == UID_ALICE,
       "lock-token theft: alice's locked file remained alice-owned")
    # control: alice WITH her own lock token can still write her own file
    ast, _ = http("PUT", f"/alice/{lk}", port, ta, b"alice-rewrite\n",
                  hdrs={"If": f"(<{token_uri}>)"})
    ok(ast in (200, 201, 204),
       f"control: alice with her own lock token writes her own file (HTTP {ast})")

    # ============================================================================
    # H) MULTIPART CROSS-IDENTITY DRIVE (S3) — alice initiates an uploadId, bob drives
    #    the part/complete with a BOB-signed request.  Parts + final object must map by
    #    the DRIVING identity (the key lives under alice/, where bob is denied): bob
    #    must NOT be able to complete an alice-initiated upload into alice's space.
    # ============================================================================
    if s3port:
        mk = f"alice/{TAG}mpu_cross.bin"
        st_i, ibody = s3("POST", mk, s3port, params={"uploads": ""}, access_key="alice")
        um = re.search(rb"<UploadId>([^<]+)</UploadId>", ibody or b"")
        ok(st_i == 200 and um is not None,
           f"multipart cross-identity setup: alice initiated uploadId (HTTP {st_i})")
        if um:
            upid = um.group(1).decode()
            # bob signs the part upload (only access_key 'alice' is configured, so a
            # bob-signed request is also an INVALID signature -> must be rejected).
            st_pb, _ = s3("PUT", mk, s3port,
                          params={"uploadId": upid, "partNumber": "1"},
                          data=b"Q" * 4096, access_key="bob")
            ok(st_pb not in (200, 201, 204),
               f"multipart cross-identity: bob-signed UploadPart REJECTED (HTTP {st_pb})")
            # alice legitimately uploads + completes (control: the upload still works)
            st_pa, pbody = s3("PUT", mk, s3port,
                              params={"uploadId": upid, "partNumber": "1"},
                              data=b"Q" * 4096, access_key="alice")
            et = re.search(rb'ETag>\\?"?([^"<\\]+)', pbody or b"")
            etag = et.group(1).decode() if et else "etag"
            comp = (f"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                    f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>").encode()
            st_cb, _ = s3("POST", mk, s3port, params={"uploadId": upid},
                          data=comp, access_key="bob")
            ok(st_cb not in (200, 201),
               f"multipart cross-identity: bob-signed Complete REJECTED (HTTP {st_cb})")
            st_ca, _ = s3("POST", mk, s3port, params={"uploadId": upid},
                          data=comp, access_key="alice")
            mfp = os.path.join(data, mk)
            muid = st_uid(mfp)
            ok(st_ca in (200, 201) and os.path.exists(mfp) and muid == UID_ALICE,
               f"control: alice completes her OWN upload, object owned alice "
               f"(HTTP {st_ca}, uid={muid})")
            rm_quiet(mfp)
    else:
        ok(True, "S3 multipart cross-identity skipped (S3 port not up)")

    # ============================================================================
    # I) CONCURRENT MIXED PROTOCOL/OP STORM (true threads) with embedded cross-tenant
    #    attacks — alice PUT, bob PUT, alice MKCOL, bob DELETE-own, alice->bob PUT
    #    (deny), bob->alice MKCOL (deny).  Hunts a race window where a leaked principal
    #    lets a cross-tenant op slip through.
    # ============================================================================
    storm_bad = []
    NSTORM = 36

    def storm(i):
        try:
            kind = i % 6
            if kind == 0:
                http("PUT", f"/alice/{TAG}st_a_{i}.txt", port, ta, b"a\n")
            elif kind == 1:
                http("PUT", f"/bob/{TAG}st_b_{i}.txt", port, tb, b"b\n")
            elif kind == 2:
                http("MKCOL", f"/alice/{TAG}st_dir_{i}", port, ta)
            elif kind == 3:
                http("PUT", f"/bob/{TAG}st_bd_{i}.txt", port, tb, b"d\n")
                http("DELETE", f"/bob/{TAG}st_bd_{i}.txt", port, tb)
            elif kind == 4:                                   # alice -> bob (deny)
                s, _b = http("PUT", f"/bob/{TAG}st_x_{i}.txt", port, ta, b"X\n")
                xp = bpath(f"{TAG}st_x_{i}.txt")
                if s in (200, 201, 204) or os.path.exists(xp):
                    storm_bad.append(("a->b-put", i, s))
            else:                                             # bob -> alice (deny)
                s, _b = http("MKCOL", f"/alice/{TAG}st_y_{i}", port, tb)
                yp = apath(f"{TAG}st_y_{i}")
                if s in (200, 201) or os.path.isdir(yp):
                    storm_bad.append(("b->a-mkcol", i, s))
        except Exception as e:  # noqa: BLE001
            storm_bad.append(("exc", i, repr(e)))

    sths = [threading.Thread(target=storm, args=(i,)) for i in range(NSTORM)]
    for t in sths:
        t.start()
    for t in sths:
        t.join()
    ok(not storm_bad,
       f"mixed protocol/op storm: no cross-tenant op slipped through a race window "
       f"(breaches={storm_bad[:4]})")

    # ============================================================================
    # J) POST-STORM GLOBAL OWNERSHIP SCAN — after EVERY storm above, scan both user
    #    dirs and assert zero wrong-owner regular files (the decisive principal-leak
    #    detector: a single svc/root/cross-tenant owned data file fails the battery).
    # ============================================================================
    misowned = scan_misowned()
    ok(not misowned,
       f"post-storm scan: zero wrong-owner regular files in alice/ + bob/ "
       f"(leaks={misowned[:4]})")
    # explicit svc/root sweep across pub/ too (created files there must be 1001/1002)
    pub_bad = []
    try:
        for f in os.listdir(os.path.join(data, "pub")):
            pth = os.path.join(data, "pub", f)
            stx = os.lstat(pth)
            if (stx.st_mode & 0o170000) == 0o100000 and stx.st_uid in (UID_SVC, 0):
                pub_bad.append((f, stx.st_uid))
    except OSError:
        pass
    ok(not pub_bad,
       f"post-storm scan: no svc/root-owned file in the shared /pub dir (leaks={pub_bad[:4]})")

    # ============================================================================
    # K) FINAL LIVENESS — after all the storms, both identities still work correctly
    #    and independently on a fresh keep-alive connection (broker not wedged, no
    #    sticky principal left behind by the last op).
    # ============================================================================
    fin = [("PUT", f"/alice/{TAG}final_a.txt", ta, b"final-a\n", None),
           ("PUT", f"/bob/{TAG}final_b.txt", tb, b"final-b\n", None),
           ("GET", f"/alice/{TAG}final_a.txt", ta, None, None),
           ("GET", f"/bob/{TAG}final_b.txt", tb, None, None)]
    fres = http_keepalive(fin, port)
    fa, fb_ = apath(f"{TAG}final_a.txt"), bpath(f"{TAG}final_b.txt")
    ok(len(fres) == 4 and fres[0][0] in (200, 201, 204) and fres[1][0] in (200, 201, 204),
       f"final liveness: both identities still write after all storms "
       f"(a={fres[0][0] if fres else '?'}, b={fres[1][0] if len(fres) > 1 else '?'})")
    ok(os.path.exists(fa) and st_uid(fa) == UID_ALICE,
       "final liveness: alice's last file owned alice (no sticky principal)")
    ok(os.path.exists(fb_) and st_uid(fb_) == UID_BOB,
       "final liveness: bob's last file owned bob (no sticky principal)")
    ok(len(fres) == 4 and fres[2][0] == 200 and b"final-a" in (fres[2][1] or b""),
       "final liveness: alice reads her own final file back")
    ok(len(fres) == 4 and fres[3][0] == 200 and b"final-b" in (fres[3][1] or b""),
       "final liveness: bob reads his own final file back")


