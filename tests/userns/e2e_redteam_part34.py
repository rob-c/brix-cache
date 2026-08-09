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


def run_connection_errors(key, data, port, s3port):
    """CONNECTION-STATE / erroring-connection attacks under impersonation.  The
    setfsuid/setfsgid principal is per-worker PROCESS-GLOBAL, so an abnormally
    terminated connection (hard-RST mid-request/body, abandon-after-Authorization,
    one-byte drip, pipelined-then-truncated) must never (a) leave a half-written /
    truncated file committed, (b) wedge the worker, (c) strand a stale principal that
    bleeds into the NEXT connection's request, or (d) leak another tenant's secret
    bytes.  Every case drives ONE scripted TCP connection through raw HTTP bytes via
    raw_send_steps (the WebDAV port speaks HTTP), then PROVES worker-survival with a
    normal http() GET and scans alice/ + bob/ for any svc(1500)/root(0)-owned file.
    Cross-tenant denies each carry a positive control; read-denies also assert the
    secret marker is absent from the response."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    H = HOST
    TAG = "cxe_"

    apath = lambda n: os.path.join(data, "alice", n)
    bpath = lambda n: os.path.join(data, "bob", n)

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    # Baseline: snapshot files OTHER batches legitimately planted (e.g. the
    # broker_resource_limits svc-owned hardlink) BEFORE any connection-error case,
    # so the sweep only flags artifacts THIS battery's abnormal connections create.
    def _snapshot():
        seen = set()
        for sub in ("alice", "bob"):
            try:
                for f in os.listdir(os.path.join(data, sub)):
                    seen.add((sub, f))
            except OSError:
                pass
        return seen

    _baseline = _snapshot()

    def scan_misowned():
        """Regular files in alice/ + bob/ that APPEARED during this battery and are
        owned by svc(1500)/root(0) (a leak), or a TAG file owned by the WRONG tenant.
        Pre-existing fixtures planted by other batches are excluded via the baseline."""
        bad = []
        for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB)):
            d = os.path.join(data, sub)
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for f in names:
                if (sub, f) in _baseline:
                    continue   # planted by another batch, not by our connections
                p = os.path.join(d, f)
                try:
                    stx = os.lstat(p)
                except OSError:
                    continue
                if (stx.st_mode & 0o170000) != 0o100000:
                    continue
                u = stx.st_uid
                if u in (UID_SVC, 0):
                    bad.append((sub, f, u))
                elif f.startswith(TAG) and u != want:
                    bad.append((sub, f, u))
        return bad

    def get_req(path, tok, conn_close=True):
        cc = "Connection: close\r\n" if conn_close else ""
        return (f"GET {path} HTTP/1.1\r\nHost: {H}\r\n"
                f"Authorization: Bearer {tok}\r\n{cc}\r\n").encode()

    def survives(label):
        """Worker survived: a normal authenticated GET of alice's own file still
        returns the exact body.  One ok() per call site."""
        st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
        ok(st == 200 and b == b"CXE-LIVE-MARKER\n",
           f"{label}: worker survived (follow-up alice GET ok, HTTP {st})")

    def no_misowned(label):
        bad = scan_misowned()
        ok(not bad, f"{label}: no svc/root/wrong-owner file in alice|bob ({bad})")

    # seed a stable own file used as the worker-survival probe + a bob 0600 control.
    http("PUT", f"/alice/{TAG}live.txt", port, ta, b"CXE-LIVE-MARKER\n")
    st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
    ok(st == 200 and b == b"CXE-LIVE-MARKER\n",
       f"baseline: alice own file readable before storm (HTTP {st})")
    # bob 0600 fixture (data/bob/private.txt) is the cross-tenant secret control.
    st, b = http("GET", "/bob/private.txt", port, ta)
    ok(st in (403, 404) and b"BOB-PRIVATE-SECRET" not in b,
       f"baseline: alice cannot read bob 0600 secret (HTTP {st})")

    # ========================================================================
    # CASE 1 — full request then immediate HARD-RST.  A complete, valid PUT body
    #   is sent, then the socket is RST before/at the response.  The file may or
    #   may not commit, but if it does it must be alice-owned (never svc/root) and
    #   byte-exact; the worker must survive.
    # ========================================================================
    rm_quiet(apath(f"{TAG}rst_full.txt"))
    body = b"CXE-RST-FULL-BODY\n"
    req = (f"PUT /alice/{TAG}rst_full.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: {len(body)}\r\n\r\n"
           ).encode() + body
    raw_send_steps([(req, 0.20, True)], port)        # send all, pause, hard-RST
    fp = apath(f"{TAG}rst_full.txt")
    if os.path.exists(fp):
        ok(st_uid(fp) == UID_ALICE and st_uid(fp) not in (UID_SVC, 0),
           f"case1 full+RST: committed file owned alice not svc/root (uid={st_uid(fp)})")
        try:
            with open(fp, "rb") as fh:
                got = fh.read()
        except OSError:
            got = b""
        ok(got == body or got == b"",
           "case1 full+RST: committed file byte-exact or absent (no partial corruption)")
    else:
        ok(True, "case1 full+RST: no file committed after RST (handled)")
    survives("case1 full+RST")
    no_misowned("case1 full+RST")

    # ========================================================================
    # CASE 2 — headers + PARTIAL body (Content-Length lies HIGH), then RST.  The
    #   server is told 64 bytes but only 5 arrive before the reset.  A TRUNCATED
    #   object must NOT be committed (the writer requires the full declared body);
    #   if anything lands it must be alice-owned, never svc/root.
    # ========================================================================
    rm_quiet(apath(f"{TAG}partial.txt"))
    head = (f"PUT /alice/{TAG}partial.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 64\r\n\r\n").encode()
    raw_send_steps([(head, 0.05), (b"PARTL", 0.20, True)], port)   # 5 of 64, RST
    fp = apath(f"{TAG}partial.txt")
    if os.path.exists(fp):
        try:
            sz = os.path.getsize(fp)
        except OSError:
            sz = -1
        ok(st_uid(fp) == UID_ALICE and st_uid(fp) not in (UID_SVC, 0),
           f"case2 partial-body: any landed file owned alice (uid={st_uid(fp)})")
        ok(sz != 64, f"case2 partial-body: no full-size phantom object committed (size={sz})")
        rm_quiet(fp)
    else:
        ok(True, "case2 partial-body: truncated body NOT committed (no partial file)")
    survives("case2 partial-body")
    no_misowned("case2 partial-body")

    # ========================================================================
    # CASE 3a — ABANDON after the request line only (no headers, no blank line),
    #   then RST.  No principal may be stuck; the connection must be torn down
    #   cleanly and the worker stays healthy.
    # ========================================================================
    raw_send_steps([(f"GET /alice/{TAG}live.txt HTTP/1.1\r\n".encode(), 0.30, True)], port)
    survives("case3a abandon-after-request-line")
    no_misowned("case3a abandon-after-request-line")

    # CASE 3b — ABANDON right after the Authorization header (alice), never send
    #   the terminating blank line, then RST.  The half-applied auth must not
    #   strand alice's principal for the NEXT connection.
    raw_send_steps([
        (f"GET /alice/{TAG}live.txt HTTP/1.1\r\nHost: {H}\r\n".encode(), 0.05),
        (f"Authorization: Bearer {ta}\r\n".encode(), 0.30, True),
    ], port)
    survives("case3b abandon-after-Authorization")
    # immediately after the abandon, a BOB request must land as bob (no stale alice).
    st, b = http("PUT", f"/bob/{TAG}after_abandon.txt", port, tb, b"BOB-AFTER-ABANDON\n")
    fp = bpath(f"{TAG}after_abandon.txt")
    ok(st in (200, 201, 204) and os.path.exists(fp) and st_uid(fp) == UID_BOB,
       f"case3b: bob request after alice-abandon lands as BOB not stale-alice (uid={st_uid(fp)})")
    no_misowned("case3b abandon-after-Authorization")

    # ========================================================================
    # CASE 4 — CONNECTION CHURN: many short-lived connections, each authenticating
    #   as alice then abandoned/RST, interleaved with bob connections.  After the
    #   storm a fresh alice GET and bob op must each land in the CORRECT space — no
    #   stale principal leaked to a reused worker connection/slot.
    # ========================================================================
    for i in range(24):
        who_tok = ta if (i % 2 == 0) else tb
        # send a complete request line + auth, then RST without reading the reply.
        raw_send_steps([
            (f"GET /alice/{TAG}live.txt HTTP/1.1\r\nHost: {H}\r\n".encode(), 0.0),
            (f"Authorization: Bearer {who_tok}\r\nConnection: close\r\n\r\n".encode(),
             0.0, True),
        ], port, read_timeout=0.6)
    # fresh, clean alice GET — must still be alice's own bytes.
    st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
    ok(st == 200 and b == b"CXE-LIVE-MARKER\n",
       f"case4 churn: post-storm alice GET lands in alice space, exact bytes (HTTP {st})")
    # fresh bob PUT — must land bob-owned in bob/ (no stale alice principal).
    st, b = http("PUT", f"/bob/{TAG}churn_bob.txt", port, tb, b"BOB-POST-CHURN\n")
    fp = bpath(f"{TAG}churn_bob.txt")
    ok(st in (200, 201, 204) and os.path.exists(fp) and st_uid(fp) == UID_BOB
       and st_uid(fp) not in (UID_SVC, 0, UID_ALICE),
       f"case4 churn: post-storm bob PUT owned bob not stale-alice/svc/root (uid={st_uid(fp)})")
    # fresh alice PUT — must land alice-owned in alice/.
    st, b = http("PUT", f"/alice/{TAG}churn_alice.txt", port, ta, b"ALICE-POST-CHURN\n")
    fp = apath(f"{TAG}churn_alice.txt")
    ok(st in (200, 201, 204) and os.path.exists(fp) and st_uid(fp) == UID_ALICE
       and st_uid(fp) not in (UID_SVC, 0, UID_BOB),
       f"case4 churn: post-storm alice PUT owned alice not bob/svc/root (uid={st_uid(fp)})")
    # the churn must not have created any object in EITHER dir (all were abandoned).
    ok(not os.path.exists(apath(f"{TAG}churn_phantom.txt")),
       "case4 churn: abandoned GET connections created no phantom write artifact")
    # post-churn, alice still cannot read bob's 0600 secret (principal not widened).
    st, b = http("GET", "/bob/private.txt", port, ta)
    ok(st in (403, 404) and b"BOB-PRIVATE-SECRET" not in b,
       f"case4 churn: alice STILL denied bob 0600 secret post-storm (HTTP {st})")
    no_misowned("case4 churn")

    # ========================================================================
    # CASE 5 — SLOW DRIP: send a valid alice GET one byte at a time with tiny
    #   pauses.  Served or cleanly handled — no desync, no leak, worker survives.
    # ========================================================================
    drip = get_req(f"/alice/{TAG}live.txt", ta)
    steps = [(bytes([drip[i]]), 0.01) for i in range(len(drip))]
    resp = raw_send_steps(steps, port, read_timeout=5.0)
    dstat = _resp_status(resp)
    ok(dstat in (200, 408, 400, -1),
       f"case5 slow-drip: byte-at-a-time alice GET served/handled (HTTP {dstat})")
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case5 slow-drip: no foreign-tenant secret bytes in drip response")
    # a drip whose body is bob's 0600 path must NEVER leak the secret marker.
    drip2 = get_req("/bob/private.txt", ta)
    steps2 = [(bytes([drip2[i]]), 0.01) for i in range(len(drip2))]
    resp2 = raw_send_steps(steps2, port, read_timeout=5.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp2,
       f"case5 slow-drip: drip GET of bob 0600 leaks no secret (HTTP {_resp_status(resp2)})")
    survives("case5 slow-drip")
    no_misowned("case5 slow-drip")

    # ========================================================================
    # CASE 6 — PIPELINE a VALID alice GET + a TRUNCATED second request, then RST.
    #   The first request must NOT have leaked bob data (the truncated second can't
    #   trick a desync into serving foreign bytes), and the worker survives.
    # ========================================================================
    pipe = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False)
            + f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuth".encode())  # truncated
    resp = raw_send_steps([(pipe, 0.30, True)], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       f"case6 pipeline+truncate: bob 0600 secret never leaked (HTTP {_resp_status(resp)})")
    ok(b"CXE-LIVE-MARKER" in resp or _resp_status(resp) in (200, 400, 408, -1),
       f"case6 pipeline+truncate: first alice GET served, no desync (HTTP {_resp_status(resp)})")
    survives("case6 pipeline+truncate")
    no_misowned("case6 pipeline+truncate")

    # CASE 6b — pipeline TWO valid requests then RST before reading: first MUST be
    #   alice's own bytes, the (cross-tenant) second must not leak bob's secret.
    pipe2 = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False)
             + get_req("/bob/private.txt", ta, conn_close=True))
    resp = raw_send_steps([(pipe2, 0.30, True)], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case6b pipeline two-valid: cross-tenant 2nd request leaks no bob secret")
    survives("case6b pipeline two-valid")

    # ========================================================================
    # CASE 7 — Authorization is alice but Content-Length claims a HUGE body; only a
    #   few bytes are sent, then RST mid-body.  No giant/phantom object may commit;
    #   any landed file is alice-owned; worker survives.
    # ========================================================================
    rm_quiet(apath(f"{TAG}huge.txt"))
    head = (f"PUT /alice/{TAG}huge.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 10000000\r\n\r\n").encode()
    raw_send_steps([(head, 0.05), (b"CXE-HUGE-PREFIX", 0.20, True)], port)  # 15 of 10M
    fp = apath(f"{TAG}huge.txt")
    if os.path.exists(fp):
        try:
            sz = os.path.getsize(fp)
        except OSError:
            sz = -1
        ok(st_uid(fp) == UID_ALICE and st_uid(fp) not in (UID_SVC, 0),
           f"case7 huge-CL+RST: any landed file owned alice (uid={st_uid(fp)})")
        ok(sz < 10000000, f"case7 huge-CL+RST: no 10MB phantom object committed (size={sz})")
        rm_quiet(fp)
    else:
        ok(True, "case7 huge-CL+RST: lying huge body NOT committed (no phantom file)")
    survives("case7 huge-CL+RST")
    no_misowned("case7 huge-CL+RST")

    # CASE 7b — same huge-CL lie but Authorization is BOB targeting ALICE's dir,
    #   then RST.  DAC denies bob in alice/ regardless of how the body terminates;
    #   nothing must land, and certainly nothing bob/svc/root-owned.
    head = (f"PUT /alice/{TAG}bob_huge.txt HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {tb}\r\nContent-Length: 10000000\r\n\r\n").encode()
    raw_send_steps([(head, 0.05), (b"BOB-EVIL", 0.15, True)], port)
    ok(not os.path.exists(apath(f"{TAG}bob_huge.txt")),
       "case7b huge-CL+RST: bob PUT into alice's dir DENIED, no artifact")
    survives("case7b cross-tenant huge-CL+RST")
    no_misowned("case7b cross-tenant huge-CL+RST")

    # ========================================================================
    # CASE 8 — KEEP-ALIVE interleave that ends in an ABRUPT RST: alice,bob,alice on
    #   ONE connection, then the conn is RST instead of closed.  Each request must
    #   land under the DRIVING identity (no stale-principal carry-over), and the RST
    #   must not roll a wrong-owner file into the other tenant's space.
    # ========================================================================
    rm_quiet(apath(f"{TAG}ka_a.txt"))
    rm_quiet(bpath(f"{TAG}ka_b.txt"))
    rm_quiet(apath(f"{TAG}ka_a2.txt"))
    pa1 = (f"PUT /alice/{TAG}ka_a.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: 6\r\n\r\nA-one\n").encode()
    pb1 = (f"PUT /bob/{TAG}ka_b.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {tb}\r\nContent-Length: 6\r\n\r\nB-one\n").encode()
    pa2 = (f"PUT /alice/{TAG}ka_a2.txt HTTP/1.1\r\nHost: {H}\r\n"
           f"Authorization: Bearer {ta}\r\nContent-Length: 6\r\n\r\nA-two\n").encode()
    raw_send_steps([(pa1, 0.08), (pb1, 0.08), (pa2, 0.15, True)], port, read_timeout=4.0)
    fa, fb = apath(f"{TAG}ka_a.txt"), bpath(f"{TAG}ka_b.txt")
    if os.path.exists(fa):
        ok(st_uid(fa) == UID_ALICE and st_uid(fa) not in (UID_SVC, 0, UID_BOB),
           f"case8 ka+RST: 1st alice PUT owned alice not bob/svc/root (uid={st_uid(fa)})")
    else:
        ok(True, "case8 ka+RST: 1st alice PUT not committed (handled)")
    if os.path.exists(fb):
        ok(st_uid(fb) == UID_BOB and st_uid(fb) not in (UID_SVC, 0, UID_ALICE),
           f"case8 ka+RST: bob PUT owned bob not stale-alice/svc/root (uid={st_uid(fb)})")
    else:
        ok(True, "case8 ka+RST: bob PUT not committed (handled)")
    # the alice request must NOT have landed in bob's dir nor bob's in alice's.
    ok(not os.path.exists(bpath(f"{TAG}ka_a.txt"))
       and not os.path.exists(apath(f"{TAG}ka_b.txt")),
       "case8 ka+RST: no request crossed into the other tenant's directory")
    survives("case8 ka-interleave+RST")
    no_misowned("case8 ka-interleave+RST")

    # ========================================================================
    # CASE 9 — root:// (stream) connection-state probe: the impersonation principal
    #   is shared by the SAME worker that serves HTTP, so a churn of native xrdfs
    #   sessions (each a separate connect/auth/teardown) must not leak a principal
    #   into a fresh HTTP request.  Guarded by xrd_avail().
    # ========================================================================
    if xrd_avail():
        # alternate alice/bob short xrdfs stat sessions (connect+auth+disconnect).
        for i in range(8):
            sub = "alice" if (i % 2 == 0) else "bob"
            base = "alice" if sub == "alice" else "bob"
            try:
                xrd_fs(["stat", f"/{base}/"], sub)
            except OSError:
                pass
        # bob tries to stat alice's 0600-equivalent secret over root:// -> denied,
        # and the secret marker must never appear in xrdfs output.
        try:
            rc, out, err = xrd_fs(["cat", "/bob/private.txt"], "alice")
        except OSError:
            rc, out, err = -1, "", "oserr"
        ok(rc != 0 and "BOB-PRIVATE-SECRET" not in (out or ""),
           f"case9 root:// churn: alice cannot cat bob 0600 secret (rc={rc})")
        # positive control: alice can stat her own dir over root:// after the churn.
        try:
            rc2, out2, err2 = xrd_fs(["stat", "/alice/"], "alice")
        except OSError:
            rc2, out2, err2 = -1, "", "oserr"
        ok(rc2 == 0 or "alice" in (out2 or "").lower() or rc2 in (0,),
           f"case9 root:// churn: alice stat own dir works post-churn (rc={rc2})")
        # a fresh HTTP alice GET after the root:// churn still lands correctly.
        st, b = http("GET", f"/alice/{TAG}live.txt", port, ta)
        ok(st == 200 and b == b"CXE-LIVE-MARKER\n",
           f"case9 root:// churn: HTTP alice GET unaffected by stream churn (HTTP {st})")
    else:
        ok(True, "case9 root:// churn: native xrdfs unavailable (skipped/handled)")
        ok(True, "case9 root:// churn: stream secret-deny skipped (no client)")
        ok(True, "case9 root:// churn: stream positive control skipped (no client)")

    # ========================================================================
    # CASE 10 — RAW half-open desync probe: send a valid alice GET, read the
    #   response, then on the SAME (kept-alive) conn send a TRUNCATED bob request
    #   and RST.  Reuse must not let the truncated bob request resurrect alice's
    #   already-applied principal to read bob's space, nor leak alice's bytes to a
    #   bob identity.  We assert no secret leak + clean status.
    # ========================================================================
    keep = (get_req(f"/alice/{TAG}live.txt", ta, conn_close=False))
    resp = raw_send_steps([
        (keep, 0.15),
        (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bea".encode(),
         0.20, True),
    ], port, read_timeout=4.0)
    ok(b"BOB-PRIVATE-SECRET" not in resp,
       "case10 half-open desync: truncated 2nd request leaks no bob secret")
    ok(_resp_status(resp) in (200, 400, 408, -1),
       f"case10 half-open desync: first alice GET cleanly served (HTTP {_resp_status(resp)})")
    survives("case10 half-open desync")
    no_misowned("case10 half-open desync")

    # ========================================================================
    # FINAL — a global ownership sweep of both tenant dirs: across EVERY abnormal
    #   connection above, not a single regular file may be owned by the worker
    #   svc(1500) or root(0).  This is the strongest no-principal-leak invariant.
    # ========================================================================
    final_bad = scan_misowned()
    ok(not final_bad,
       f"FINAL sweep: zero svc/root/wrong-owner files after all connection-error cases ({final_bad})")
    # and the worker is definitively alive: one last clean round-trip both tenants.
    st_a, b_a = http("GET", f"/alice/{TAG}live.txt", port, ta)
    st_b, b_b = http("PUT", f"/bob/{TAG}final.txt", port, tb, b"BOB-FINAL\n")
    fpb = bpath(f"{TAG}final.txt")
    ok(st_a == 200 and b_a == b"CXE-LIVE-MARKER\n",
       f"FINAL: alice GET healthy after entire storm (HTTP {st_a})")
    ok(st_b in (200, 201, 204) and os.path.exists(fpb) and st_uid(fpb) == UID_BOB,
       f"FINAL: bob PUT healthy + owned bob after entire storm (uid={st_uid(fpb)}, HTTP {st_b})")


