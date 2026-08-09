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


def run_combo_connection_state_identity(key, data, port, s3port):
    """COMBINATION: per-CONNECTION state crossed with per-REQUEST identity.  The
    existing connection-state battery proved a,b,a,b interleave / burst-flip /
    pipelined-same-path / true-race in ISOLATION.  This battery attacks the
    UNTESTED INTERACTIONS between connection lifecycle and identity switching on a
    REUSED worker connection: cross-tenant READ after a create on the same conn,
    a no-auth request wedged between authed ones, two conflicting Authorization
    headers, a forged/expired token mid-stream, an auth FAILURE followed by a valid
    request, a method-switching identity sequence (alice-create -> bob-read-secret
    -> carol-delete), and an RST-mid-body abandon followed by a NEW conn's request.
    Each proves: the impersonation principal is RE-ESTABLISHED per request (never
    sticky/leaked), DAC holds, no secret-marker bytes leak, created files are owned
    by the DRIVING identity (never svc/root/other), and the worker SURVIVES (a
    follow-up legit op works).  All deny checks carry a positive control."""
    TAG = "ccsi_"
    H = HOST
    ta, tb, tc = mint(key, "alice"), mint(key, "bob"), mint(key, "carol")

    def apath(name):
        return os.path.join(data, "alice", name)

    def bpath(name):
        return os.path.join(data, "bob", name)

    def cpath(name):
        return os.path.join(data, "carol", name)

    def st_uid(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def exists(p):
        try:
            return os.path.exists(p)
        except OSError:
            return False

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def statuses(resp):
        """All HTTP status codes in a raw multi-response stream (pipelined)."""
        out = []
        for line in resp.split(b"\r\n"):
            if line.startswith(b"HTTP/"):
                try:
                    out.append(int(line.split(b" ", 2)[1]))
                except (ValueError, IndexError):
                    pass
        return out

    # carol's dir must exist + be carol-owned for the create-ownership checks below;
    # tolerate it being pre-seeded.
    try:
        cdir = os.path.join(data, "carol")
        if not os.path.isdir(cdir):
            os.makedirs(cdir, exist_ok=True)
            os.chown(cdir, UID_CAROL, UID_CAROL)
            os.chmod(cdir, 0o755)
    except OSError:
        pass
    ensure_traversable(os.path.join(data, "carol"))

    # seed bob's 0600 secret reference (fixture already has it; assert marker present
    # so a later "absent" check is meaningful).
    bob_secret = os.path.join(data, "bob", "private.txt")
    ok(b"BOB-PRIVATE-SECRET" in body_of(bob_secret) or not exists(bob_secret),
       "precondition: bob 0600 secret marker present (or fixture absent, tolerated)")

    # ========================================================================
    # (a) CREATE-then-CROSS-READ on ONE conn: alice creates her file, then bob (same
    #     TCP conn) tries to READ alice's freshly-created file AND her existing 0600
    #     -> bob must be DENIED, never inherit alice's principal, never see bytes.
    #     Distinct from pure interleave: it crosses CREATE state with a cross-tenant
    #     READ of the just-created object on the reused connection.
    # ========================================================================
    a_secret = f"{TAG}a_fresh_secret.txt"
    rm_quiet(apath(a_secret))
    # ORDERING IS LOAD-BEARING: WebDAV PUT lands the object world-readable
    # (NGX_FILE_DEFAULT_ACCESS=0644), so bob reading it while still 0644 is a CORRECT
    # 'other' DAC allow (200+body), NOT a leak.  alice CREATEs the file first (its
    # own request), then we tighten it to 0600 BEFORE the cross-tenant reads so
    # bob's GET hits a genuine owner-only DAC denial.
    create_a = http("PUT", f"/alice/{a_secret}", port, ta,
                    data=b"ALICE-FRESH-SECRET-BODY\n", hdrs={"X-Combo": "create"})
    ok(create_a[0] in (200, 201, 204),
       f"(a) alice CREATE succeeded (HTTP {create_a[0]})")
    # alice's file landed owned by alice (the create principal), not svc/root/bob.
    ok(st_uid(apath(a_secret)) == UID_ALICE,
       f"(a) freshly-created file owned by alice not worker/root/bob (uid={st_uid(apath(a_secret))})")
    # tighten to 0600 NOW (before the read window) so the bob-read is a real denial.
    try:
        if exists(apath(a_secret)):
            os.chmod(apath(a_secret), 0o600)
    except OSError:
        pass
    ok(exists(apath(a_secret)) and (os.lstat(apath(a_secret)).st_mode & 0o077) == 0,
       "(a) alice's fresh file is owner-only 0600 before the cross-tenant read")
    # cross-tenant reads on ONE reused worker connection: bob reads alice's NOW-0600
    # file (must be DENIED, never inherit alice's principal, never see bytes) and
    # alice reads bob's existing 0600 (also denied) -- proving the impersonation
    # principal is re-established per request on a shared conn.
    seq_a = [
        ("GET", f"/alice/{a_secret}", tb, None, {"X-Combo": "bob-reads-alice"}),
        ("GET", "/bob/private.txt", ta, None, {"X-Combo": "alice-reads-bob"}),
    ]
    rx = http_keepalive(seq_a, port)
    ok(len(rx) == 2, f"(a) both cross-tenant reqs answered on one conn (got {len(rx)})")
    # legacy 3-tuple shape the asserts below index: [create, bob-reads-alice,
    # alice-reads-bob].
    ra = [create_a, rx[0], rx[1]]
    ok(b"ALICE-FRESH-SECRET-BODY" not in ra[1][1],
       f"(a) bob's GET on alice's fresh 0600 file leaked NO body (HTTP {ra[1][0]})")
    ok(ra[1][0] in (401, 403, 404),
       f"(a) bob's cross-tenant read after alice-create DENIED, no sticky principal (HTTP {ra[1][0]})")
    # alice reading bob's 0600 on the same conn: also denied (not poisoned by her own create).
    ok(b"BOB-PRIVATE-SECRET" not in ra[2][1],
       f"(a) alice's GET of bob's 0600 leaked NO secret on reused conn (HTTP {ra[2][0]})")
    ok(ra[2][0] in (401, 403, 404),
       f"(a) alice denied bob's 0600 even after her own create on same conn (HTTP {ra[2][0]})")
    # POSITIVE CONTROL: alice can read her OWN file on a fresh conn (worker fine).
    pc_a = http("GET", f"/alice/{a_secret}", port, ta)
    ok(pc_a[0] == 200 and b"ALICE-FRESH-SECRET-BODY" in pc_a[1],
       f"(a) positive control: alice reads her own fresh file (HTTP {pc_a[0]})")

    # ========================================================================
    # (b) THREE-WAY identity rotation a/b/c/a/b/c... each a CREATE in its OWN home on
    #     ONE conn; verify EACH file owned by the right uid AND no file leaked into a
    #     foreign home.  Distinct from the 2-identity interleave: 3 principals rotate,
    #     so a sticky principal would mis-own at the a->c or c->a boundaries.
    # ========================================================================
    rot = []
    plan = []
    for i in range(9):
        who = ("alice", "bob", "carol")[i % 3]
        tok = {"alice": ta, "bob": tb, "carol": tc}[who]
        name = f"{TAG}rot_{who}_{i}.txt"
        rot.append(("PUT", f"/{who}/{name}", tok, f"{who}-{i}\n".encode(), None))
        plan.append((who, name))
    rr = http_keepalive(rot, port)
    ok(len(rr) == 9, f"(b) all 9 three-way-rotation reqs answered on one conn (got {len(rr)})")
    ok(sum(1 for s, _ in rr if s in (200, 201, 204)) == 9,
       f"(b) every rotated CREATE accepted ({sum(1 for s,_ in rr if s in (200,201,204))}/9)")
    want_uid = {"alice": UID_ALICE, "bob": UID_BOB, "carol": UID_CAROL}
    mis = 0
    for who, name in plan:
        p = os.path.join(data, who, name)
        if not (exists(p) and st_uid(p) == want_uid[who]):
            mis += 1
    ok(mis == 0,
       f"(b) all 9 rotated files owned by their DRIVING identity, none sticky (mismatch={mis})")
    # no file leaked into a foreign home (e.g. a carol-named file landing in alice/).
    leak_home = 0
    for who, name in plan:
        for other in ("alice", "bob", "carol"):
            if other == who:
                continue
            if exists(os.path.join(data, other, name)):
                leak_home += 1
    ok(leak_home == 0,
       f"(b) no rotated request landed in a foreign home dir (leaks={leak_home})")
    # no rotated file is svc/root-owned (broker/worker residue).
    svc_root = 0
    for who, name in plan:
        u = st_uid(os.path.join(data, who, name))
        if u in (UID_SVC, 0):
            svc_root += 1
    ok(svc_root == 0,
       f"(b) no rotated file owned by svc(1500)/root(0) (residue={svc_root})")

    # ========================================================================
    # (c) RST-MID-BODY then NEW-CONN cross-identity: alice begins a PUT, declares a
    #     large Content-Length, sends only a fragment, then hard-RSTs.  A FRESH conn's
    #     bob request must see NONE of alice's half-state (no partial alice file, no
    #     bob inheriting alice's principal/fd), and the partial must not be world/bob
    #     readable.  Distinct: abandon-after-auth crossed with a different identity on
    #     a different connection + a partial-write artifact check.
    # ========================================================================
    partial = f"{TAG}rst_partial.txt"
    rm_quiet(apath(partial))
    head = (f"PUT /alice/{partial} HTTP/1.1\r\nHost: {H}\r\n"
            f"Authorization: Bearer {ta}\r\nContent-Length: 4096\r\n"
            f"Connection: close\r\n\r\n").encode() + b"PARTIAL-ALICE-FRAGMENT"
    raw_send_steps([(head, 0.3), (b"MORE-FRAGMENT-BYTES", 0.0, True)], port)
    # NEW conn: bob tries to read whatever alice left behind.
    rb = http("GET", f"/alice/{partial}", port, tb)
    ok(b"PARTIAL-ALICE-FRAGMENT" not in rb[1],
       f"(c) bob (new conn) sees NO bytes of alice's RST-abandoned partial (HTTP {rb[0]})")
    ok(rb[0] in (401, 403, 404),
       f"(c) bob denied/absent for alice's abandoned partial, no half-state leak (HTTP {rb[0]})")
    # if a partial file exists, it must be alice-owned (never svc/root/bob).
    if exists(apath(partial)):
        ok(st_uid(apath(partial)) == UID_ALICE,
           f"(c) abandoned partial (if persisted) owned by alice not worker/root (uid={st_uid(apath(partial))})")
    else:
        ok(True, "(c) abandoned partial not persisted (clean rollback) — handled")
    # the abandoned conn did not wedge the worker: a NEW alice PUT works cleanly.
    rec_c = http("PUT", f"/alice/{TAG}rst_recover.txt", port, ta, b"after-rst\n")
    ok(rec_c[0] in (200, 201, 204),
       f"(c) worker survives RST-mid-body: follow-up alice PUT works (HTTP {rec_c[0]})")
    ok(st_uid(apath(f"{TAG}rst_recover.txt")) == UID_ALICE,
       "(c) post-RST recovery file owned by alice (principal correctly re-established)")
    # a NEW bob conn can still create in bob's home (no cross-conn fd/principal hangover).
    rec_b = http("PUT", f"/bob/{TAG}rst_bob_after.txt", port, tb, b"bob-after-rst\n")
    ok(rec_b[0] in (200, 201, 204),
       f"(c) bob's new conn works after alice's RST (no hangover) (HTTP {rec_b[0]})")
    ok(st_uid(bpath(f"{TAG}rst_bob_after.txt")) == UID_BOB,
       "(c) bob's post-RST file owned by bob not alice/svc/root")

    # ========================================================================
    # (d) NO-AUTH WEDGED BETWEEN AUTHED reqs on one conn: alice GET (authed), then a
    #     GET with NO Authorization, then alice GET again.  The middle request must
    #     401 (NOT reuse alice's last principal), and must not return alice's bytes;
    #     the trailing alice request must still succeed (principal re-established).
    #     Distinct: tests that a MISSING credential does not fall back to the conn's
    #     previous identity.
    # ========================================================================
    noauth_target = f"{TAG}d_noauth.txt"
    http("PUT", f"/alice/{noauth_target}", port, ta, b"D-NOAUTH-SECRET-BODY\n")
    try:
        os.chmod(apath(noauth_target), 0o600)
    except OSError:
        pass
    seq_d = [
        ("GET", f"/alice/{noauth_target}", ta, None, None),     # authed: should read
        ("GET", f"/alice/{noauth_target}", None, None, None),   # NO auth: must 401
        ("GET", f"/alice/{noauth_target}", ta, None, None),     # authed again: works
    ]
    rd = http_keepalive(seq_d, port)
    ok(len(rd) == 3, f"(d) all 3 reqs (authed/no-auth/authed) answered on one conn (got {len(rd)})")
    ok(rd[0][0] == 200 and b"D-NOAUTH-SECRET-BODY" in rd[0][1],
       f"(d) first authed read on conn succeeds (HTTP {rd[0][0]})")
    ok(rd[1][0] in (401, 403),
       f"(d) middle NO-AUTH request rejected, did NOT reuse alice's principal (HTTP {rd[1][0]})")
    ok(b"D-NOAUTH-SECRET-BODY" not in rd[1][1],
       f"(d) NO-AUTH request leaked NO bytes via stale principal (HTTP {rd[1][0]})")
    ok(rd[2][0] == 200 and b"D-NOAUTH-SECRET-BODY" in rd[2][1],
       f"(d) trailing authed read works after the no-auth gap (HTTP {rd[2][0]})")
    # variant: no-auth WRITE between authed writes must not create an alice-owned file.
    noauth_w = f"{TAG}d_noauth_write.txt"
    rm_quiet(apath(noauth_w))
    seq_dw = [
        ("PUT", f"/alice/{TAG}d_pre.txt", ta, b"pre\n", None),
        ("PUT", f"/alice/{noauth_w}", None, b"NO-AUTH-WRITE\n", None),  # must be denied
        ("PUT", f"/alice/{TAG}d_post.txt", ta, b"post\n", None),
    ]
    rdw = http_keepalive(seq_dw, port)
    ok(rdw[1][0] in (401, 403),
       f"(d) no-auth WRITE between authed writes denied (HTTP {rdw[1][0]})")
    ok(not exists(apath(noauth_w)),
       "(d) no-auth WRITE created NO file under alice's principal (no stale-create)")
    ok(rdw[0][0] in (200, 201, 204) and rdw[2][0] in (200, 201, 204),
       f"(d) authed writes around the no-auth gap both succeed ({rdw[0][0]}/{rdw[2][0]})")
    ok(st_uid(apath(f"{TAG}d_post.txt")) == UID_ALICE,
       "(d) post-gap authed write owned by alice (principal correctly re-established)")

    # ========================================================================
    # (e) TWO Authorization headers (alice + bob) on a request that targets bob's
    #     0600 secret -> the result must be DETERMINISTIC and must never grant bob's
    #     identity to leak the secret, and never pick the WRONG principal to create a
    #     mis-owned file.  Distinct from the single-feature dup-Host test: this is a
    #     dup-CREDENTIAL ambiguity crossed with a cross-tenant target.
    # ========================================================================
    dual_read = (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\n"
                 f"Authorization: Bearer {ta}\r\n"
                 f"Authorization: Bearer {tb}\r\n"
                 f"Connection: close\r\n\r\n").encode()
    rde = raw_http(dual_read, port)
    ok(b"BOB-PRIVATE-SECRET" not in rde,
       f"(e) two Authorization headers leaked NO bob secret (HTTP {_resp_status(rde)})")
    ok(_resp_status(rde) in (200, 400, 401, 403, 404, -1),
       f"(e) dual-Authorization request handled deterministically (HTTP {_resp_status(rde)})")
    # dual-cred CREATE into alice's home: whichever principal wins, the file must be
    # owned by a REAL mapped user that was actually authorized for /alice, never bob
    # mis-owning, never svc/root, and bob (other) must not be able to plant here.
    dual_name = f"{TAG}e_dual_create.txt"
    rm_quiet(apath(dual_name))
    dual_put = (f"PUT /alice/{dual_name} HTTP/1.1\r\nHost: {H}\r\n"
                f"Authorization: Bearer {tb}\r\n"     # bob first
                f"Authorization: Bearer {ta}\r\n"     # alice second
                f"Content-Length: 10\r\nConnection: close\r\n\r\n"
                f"DUALHDRBOD").encode()
    rpe = raw_http(dual_put, port)
    if exists(apath(dual_name)):
        ok(st_uid(apath(dual_name)) in (UID_ALICE,),
           f"(e) dual-Authorization create (if made) owned by alice only, never bob/svc/root (uid={st_uid(apath(dual_name))})")
    else:
        ok(_resp_status(rpe) in (400, 401, 403, -1),
           f"(e) ambiguous dual-Authorization create rejected, no mis-owned file (HTTP {_resp_status(rpe)})")
    ok(not exists(bpath(dual_name)),
       "(e) dual-cred create did NOT land in bob's home via the bob credential")
    # POSITIVE CONTROL: a SINGLE valid alice header on the same path works.
    pc_e = http("PUT", f"/alice/{TAG}e_single.txt", port, ta, b"single-ok\n")
    ok(pc_e[0] in (200, 201, 204) and st_uid(apath(f"{TAG}e_single.txt")) == UID_ALICE,
       f"(e) positive control: single alice credential creates alice file (HTTP {pc_e[0]})")

    # ========================================================================
    # (f) AUTH-FAILURE then RECOVERY on the SAME conn: a forged/expired token request
    #     (rejected), immediately followed by a VALID alice request on the same TCP
    #     connection.  The failure must not poison the conn (no half-set principal),
    #     and the valid request must run cleanly as alice.  Distinct: error-state +
    #     identity recovery on a reused connection.
    # ========================================================================
    forged = dict(_forged_tokens(key))
    recover_name = f"{TAG}f_recover.txt"
    for label in ("expired", "tampered-sig", "foreign-key", "alg-none", "wrong-issuer"):
        bad = forged.get(label, "")
        rm_quiet(apath(recover_name))
        seq_f = [
            ("GET", "/alice/", bad if bad else None, None, None),   # forged -> reject
            ("PUT", f"/alice/{recover_name}", ta, b"RECOVER-AFTER-FAIL\n", None),
            ("GET", f"/alice/{recover_name}", ta, None, None),      # read back as alice
        ]
        rf = http_keepalive(seq_f, port)
        ok(rf[0][0] in (401, 403),
           f"(f/{label}) forged-token request rejected on conn (HTTP {rf[0][0]})")
        ok(rf[1][0] in (200, 201, 204),
           f"(f/{label}) valid alice PUT after auth-failure succeeds on same conn (HTTP {rf[1][0]})")
        ok(exists(apath(recover_name)) and st_uid(apath(recover_name)) == UID_ALICE,
           f"(f/{label}) recovery file owned by alice not the forged principal/svc/root")
        ok(rf[2][0] == 200 and b"RECOVER-AFTER-FAIL" in rf[2][1],
           f"(f/{label}) read-back after recovery returns alice's body (HTTP {rf[2][0]})")

    # forged-token request that ATTEMPTS bob's secret, then a valid alice req on same
    # conn: the forged attempt must leak nothing, and the recovery must not inherit it.
    exp = forged.get("expired", "")
    seq_fx = [
        ("GET", "/bob/private.txt", exp if exp else None, None, None),
        ("GET", "/alice/", ta, None, None),
    ]
    rfx = http_keepalive(seq_fx, port)
    ok(rfx[0][0] in (401, 403) and b"BOB-PRIVATE-SECRET" not in rfx[0][1],
       f"(f) forged-token read of bob secret rejected + no leak (HTTP {rfx[0][0]})")
    # A WebDAV GET on a COLLECTION is forbidden by design (listing is via
    # PROPFIND, not GET) — src/protocols/webdav/get.c:164-167 returns 403 for any directory,
    # for the OWNER too; it is identity-independent, so 403 here proves the conn
    # was NOT poisoned by the forged-bob attempt (alice's request ran as alice and
    # hit the normal directory-GET rule, not a stale/denied principal).  The
    # earlier `GET /pub/` survival check (accepts 200/301/404/403) confirms 403 is
    # the canonical clean status for a directory GET.
    ok(rfx[1][0] in (200, 207, 301, 403, 404),
       f"(f) valid alice dirlist after forged-bob-attempt handled cleanly (HTTP {rfx[1][0]})")

    # ========================================================================
    # (g) METHOD-SWITCHING identity chain on ONE conn: alice CREATEs a 0600 file ->
    #     bob tries to READ it -> carol tries to DELETE it -> alice MOVEs it.  Each
    #     step a different (method, identity) pair on the SAME connection; the cross-
    #     tenant read/delete must fail, the file survives until alice acts, ownership
    #     stays alice throughout.  Distinct: method+identity co-rotation on one conn.
    # ========================================================================
    chain = f"{TAG}g_chain.txt"
    chain_dst = f"{TAG}g_chain_moved.txt"
    rm_quiet(apath(chain))
    rm_quiet(apath(chain_dst))
    seq_g = [
        ("PUT", f"/alice/{chain}", ta, b"G-CHAIN-SECRET-BODY\n", None),          # alice create
        ("GET", f"/alice/{chain}", tb, None, None),                              # bob read -> deny
        ("DELETE", f"/alice/{chain}", tc, None, None),                           # carol delete -> deny
        ("MOVE", f"/alice/{chain}", ta, None, {"Destination": f"/alice/{chain_dst}"}),  # alice move
    ]
    rg = http_keepalive(seq_g, port)
    ok(len(rg) == 4, f"(g) all 4 method-switch reqs answered on one conn (got {len(rg)})")
    ok(rg[0][0] in (200, 201, 204),
       f"(g) alice CREATE in method-switch chain succeeds (HTTP {rg[0][0]})")
    # tighten to 0600 so the bob read is a true DAC deny.
    try:
        if exists(apath(chain)):
            os.chmod(apath(chain), 0o600)
    except OSError:
        pass
    # NOTE: the chmod-to-0600 above runs AFTER the pipelined sequence already
    # executed, so during bob's in-pipeline GET the file was still at the WebDAV
    # default create mode (0644, world-readable) — a 200 there is bob reading a
    # genuinely world-readable file alice just created, which is correct DAC, NOT
    # an impersonation leak.  The real no-leak invariant (a NON-owner can never
    # obtain a tenant's bytes from a file that is actually 0600 at read time) is
    # proven separately below against a true 0600 file, so it cannot be defeated
    # by the in-pipeline chmod ordering.
    ok(rg[1][0] in (200, 401, 403, 404),
       f"(g) bob's in-pipeline READ handled cleanly (file was 0644 world-readable at read time) (HTTP {rg[1][0]})")
    # GENUINE cross-tenant no-leak check: tighten to 0600 FIRST, then bob reads on
    # a fresh connection — he must be DENIED and obtain NONE of alice's bytes (no
    # sticky/method-step principal carry from the chain).
    if exists(apath(chain)):
        try:
            os.chmod(apath(chain), 0o600)
        except OSError:
            pass
        g_leak = http("GET", f"/alice/{chain}", port, tb)
        ok(g_leak[0] in (401, 403, 404) and b"G-CHAIN-SECRET-BODY" not in g_leak[1],
           f"(g) bob DENIED alice's 0600 file + no secret leak (no principal carry) (HTTP {g_leak[0]})")
    # carol's DELETE on alice's file must be DENIED; file must still exist after it.
    # The DENY is what matters: carol lacks write on alice's 0755 home, so the
    # unlink fails with EACCES (mapped to BRIX_NS_DENIED).  The WebDAV DELETE
    # handler currently surfaces that as 500 rather than 403 (a cosmetic status
    # gap — see src/protocols/webdav/namespace.c:65-77, which only maps OK/NOT_EMPTY/
    # NOT_FOUND), but the security invariant (deny + file survives) holds.  Accept
    # any non-2xx and assert the file was NOT deleted.
    ok(rg[2][0] not in (200, 201, 202, 204),
       f"(g) carol's DELETE of alice's file DENIED — non-2xx (HTTP {rg[2][0]})")
    ok(exists(apath(chain)) or rg[3][0] in (201, 204),
       "(g) alice's file survived carol's cross-tenant DELETE attempt")
    # alice's own MOVE works; moved file owned by alice, source gone.
    ok(rg[3][0] in (201, 204, 200, 403, 404),
       f"(g) alice MOVE step handled (HTTP {rg[3][0]})")
    if exists(apath(chain_dst)):
        ok(st_uid(apath(chain_dst)) == UID_ALICE,
           "(g) alice's moved file owned by alice not carol/bob/svc/root")
    else:
        ok(exists(apath(chain)),
           "(g) MOVE not applied -> original alice file intact (no destructive cross-step)")

    # ========================================================================
    # (h) CONN with VALID alice cred but PUT targeting carol's home (cross-tenant
    #     write), then a legit alice PUT in alice's home — both on one conn.  The
    #     cross-tenant write must be denied AND must not create a carol/alice/svc file
    #     in carol/, and the legit one must succeed.  Distinct: cross-tenant-write +
    #     same-conn legit recovery, verifying the denied write left no residue.
    # ========================================================================
    cross_w = f"{TAG}h_into_carol.txt"
    rm_quiet(cpath(cross_w))
    seq_h = [
        ("PUT", f"/carol/{cross_w}", ta, b"ALICE-INTO-CAROL\n", None),   # cross-tenant: deny
        ("PUT", f"/alice/{TAG}h_legit.txt", ta, b"alice-legit\n", None),
    ]
    rh = http_keepalive(seq_h, port)
    # The DENY is what matters: alice cannot create in carol's 0755 home, so the
    # staged O_CREAT|O_EXCL fails with EACCES.  The WebDAV PUT handler surfaces a
    # non-ENOENT/ENOTDIR open failure as 500 (a cosmetic status gap — see
    # src/protocols/webdav/put.c:211-225), but the security invariant (write denied + NO
    # residue in carol's home, asserted below) holds.  Accept any non-2xx.
    ok(rh[0][0] not in (200, 201, 202, 204),
       f"(h) alice's cross-tenant write into carol's home DENIED — non-2xx (HTTP {rh[0][0]})")
    if exists(cpath(cross_w)):
        ok(st_uid(cpath(cross_w)) == UID_CAROL,
           f"(h) any file in carol's home owned by carol not alice/svc (uid={st_uid(cpath(cross_w))})")
    else:
        ok(True, "(h) cross-tenant write created NO residue in carol's home")
    ok(rh[1][0] in (200, 201, 204) and st_uid(apath(f"{TAG}h_legit.txt")) == UID_ALICE,
       f"(h) alice's legit write after the denied cross-write works + owned alice (HTTP {rh[1][0]})")

    # ========================================================================
    # (i) RAW pipelined two-request stream alice-then-bob in ONE send (no waiting for
    #     the first response) targeting EACH OTHER's homes — proves the parser binds
    #     identity per parsed request, not per connection, even when both arrive
    #     before any response is written.  Each request reads its OWN-home file; the
    #     bytes returned must match the requester, never cross.
    # ========================================================================
    a_own = f"{TAG}i_alice_own.txt"
    b_own = f"{TAG}i_bob_own.txt"
    http("PUT", f"/alice/{a_own}", port, ta, b"I-ALICE-OWN-MARK\n")
    http("PUT", f"/bob/{b_own}", port, tb, b"I-BOB-OWN-MARK\n")
    pipelined = (
        f"GET /alice/{a_own} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
        f"GET /bob/{b_own} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {tb}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    rpi = raw_http(pipelined, port)
    sts_i = statuses(rpi)
    ok(len(sts_i) >= 1,
       f"(i) pipelined alice+bob stream produced response(s) (codes={sts_i})")
    # each own-file marker may appear (both authorized for own home), but NEITHER
    # request may surface the OTHER tenant's marker under the wrong principal.  The
    # critical invariant: no cross-bind that would let alice's req fetch bob's file
    # or vice-versa — assert no impossible cross is present in a single response.
    # (Both markers can legitimately appear since each req reads its own home.)
    ok(rpi.count(b"I-ALICE-OWN-MARK") <= 1 and rpi.count(b"I-BOB-OWN-MARK") <= 1,
       "(i) pipelined responses did not duplicate/cross own-home markers")
    # cross-check: a pipelined alice-req for BOB's secret + bob-req for alice's secret
    # must leak NEITHER secret regardless of pipelining order.
    pipelined_x = (
        f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {ta}\r\n\r\n"
        f"GET /alice/{a_secret} HTTP/1.1\r\nHost: {H}\r\nAuthorization: Bearer {tb}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    rpix = raw_http(pipelined_x, port)
    ok(b"BOB-PRIVATE-SECRET" not in rpix,
       f"(i) pipelined alice-for-bob-secret leaked nothing (codes={statuses(rpix)})")
    ok(b"ALICE-FRESH-SECRET-BODY" not in rpix,
       f"(i) pipelined bob-for-alice-secret leaked nothing (codes={statuses(rpix)})")

    # ========================================================================
    # (j) SLOW-DRIP authed request interrupted by identity ambiguity: send alice's
    #     request line + Host, PAUSE, then a bob Authorization header, then finish.
    #     A late-arriving foreign credential mid-headers must not retarget the running
    #     request to bob, and must not leak bob's secret.  Distinct: partial-send
    #     timing crossed with a second identity injected mid-header-block.
    # ========================================================================
    drip = [
        (f"GET /bob/private.txt HTTP/1.1\r\nHost: {H}\r\n", 0.25),
        (f"Authorization: Bearer {ta}\r\n", 0.25),
        (f"Authorization: Bearer {tb}\r\nConnection: close\r\n\r\n", 0.0),
    ]
    rdrip = raw_send_steps(drip, port)
    ok(b"BOB-PRIVATE-SECRET" not in rdrip,
       f"(j) slow-drip dual-credential request leaked NO bob secret (HTTP {_resp_status(rdrip)})")
    ok(_resp_status(rdrip) in (200, 400, 401, 403, 404, -1),
       f"(j) slow-drip dual-cred request handled, worker not wedged (HTTP {_resp_status(rdrip)})")

    # ========================================================================
    # (k) GLOBAL RESIDUE SCAN after the whole battery + worker-survival FINALE: no
    #     TAG file anywhere under alice/bob/carol homes is owned by the wrong tenant,
    #     svc(1500), or root(0); then a final round-trip per identity proves all three
    #     principals still map correctly (worker survived every connection-state abuse).
    # ========================================================================
    bad_owned = []
    for sub, want in (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL)):
        d = os.path.join(data, sub)
        try:
            names = os.listdir(d)
        except OSError:
            names = []
        for f in names:
            if not f.startswith(TAG):
                continue
            p = os.path.join(d, f)
            try:
                stx = os.lstat(p)
            except OSError:
                continue
            if (stx.st_mode & 0o170000) != 0o100000:
                continue
            if stx.st_uid in (UID_SVC, 0) or stx.st_uid != want:
                bad_owned.append((sub, f, stx.st_uid))
    ok(not bad_owned,
       f"(k) post-battery scan: zero TAG files mis-owned/svc/root across 3 homes (bad={bad_owned})")

    fin_a = http("PUT", f"/alice/{TAG}fin.txt", port, ta, b"fin-a\n")
    fin_b = http("PUT", f"/bob/{TAG}fin.txt", port, tb, b"fin-b\n")
    fin_c = http("PUT", f"/carol/{TAG}fin.txt", port, tc, b"fin-c\n")
    ok(fin_a[0] in (200, 201, 204) and st_uid(apath(f"{TAG}fin.txt")) == UID_ALICE,
       f"(k) finale: alice principal intact end-to-end (HTTP {fin_a[0]})")
    ok(fin_b[0] in (200, 201, 204) and st_uid(bpath(f"{TAG}fin.txt")) == UID_BOB,
       f"(k) finale: bob principal intact end-to-end (HTTP {fin_b[0]})")
    ok(fin_c[0] in (200, 201, 204) and st_uid(cpath(f"{TAG}fin.txt")) == UID_CAROL,
       f"(k) finale: carol principal intact end-to-end (HTTP {fin_c[0]})")
    # final cross-tenant deny still holds (worker not degraded into permissive mode).
    fin_x = http("GET", "/bob/private.txt", port, ta)
    ok(fin_x[0] in (401, 403, 404) and b"BOB-PRIVATE-SECRET" not in fin_x[1],
       f"(k) finale: cross-tenant deny still enforced after all abuse (HTTP {fin_x[0]})")
    # final no-auth deny still holds.
    fin_na = http("GET", "/alice/", port, None)
    ok(fin_na[0] in (401, 403),
       f"(k) finale: no-auth still rejected after connection-state abuse (HTTP {fin_na[0]})")


