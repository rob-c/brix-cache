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


def run_broker_internals_stress(key, data, port, s3port):
    """Stress the broker's IDENTITY-CACHE + principal-string parser + per-request
    impersonation switch.  Proves: (1) a stale identity cache NEVER serves the
    wrong uid when alice/bob/carol/dave rotate through the SAME export; (2) hostile
    token-`sub` edge strings (1-4KB overlong, embedded ws, unicode/homoglyph, NUL,
    numeric, reserved names) map DETERMINISTICALLY to the same local id every time or
    are DENIED -- and NEVER to root/svc/system; (3) rapid legit identity switching on
    ONE kept-alive connection serves each request as its true identity (no principal
    leak across pipelined requests); (4) <=8 concurrent distinct identities each
    create a file owned by exactly their own uid (zero owner cross).

    Writes go into the world-writable /pub (0777 svc) because only alice/ and bob/
    have provisioned home dirs -- /pub lets ANY mapped identity create, so the file's
    OWNER is purely the broker's mapped uid (exactly the property under test) and any
    misowned residue is a real idmap breach.  All files are bis_-tagged and removed."""
    T = "bis_"
    pubdir = os.path.join(data, "pub")        # 0777 svc -> only idmap sets the owner

    # Subjects that MUST map to a fixed legit uid.
    LEGIT = [("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL),
             ("dave", UID_DAVE), ("erin", UID_ERIN), ("frank", UID_FRANK)]
    LEGIT_TOK = {s: mint(key, s) for s, _ in LEGIT}
    WANT = dict(LEGIT)

    def pub_path(name):
        return os.path.join(pubdir, name)

    def rm(name):
        p = pub_path(name)
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass

    # =====================================================================
    # (1) IDENTITY-CACHE TTL / CORRECTNESS: rotate alice->bob->carol->dave...
    #     repeatedly through the SAME server into the SAME /pub dir.  If the broker
    #     caches the mapped identity and a stale entry survives the switch, a later
    #     request will create a file owned by the WRONG (previously-cached) uid.
    #     Every created file MUST be owned by exactly the requesting subject's uid.
    # =====================================================================
    ROT = ["alice", "bob", "carol", "alice", "carol", "bob",
           "alice", "dave", "frank", "carol", "alice", "erin"]
    rot_bad = []          # (round, sub, expected_uid, actual_uid)
    for rnd, sub in enumerate(ROT):
        name = f"{T}rot_{rnd}.txt"
        st, _ = http("PUT", f"/pub/{name}", port, LEGIT_TOK[sub],
                     f"{sub}-rot-{rnd}\n".encode())
        fp = pub_path(name)
        made = os.path.exists(fp)
        actual = os.stat(fp).st_uid if made else -1
        if not (st in (200, 201, 204) and made and actual == WANT[sub]):
            rot_bad.append((rnd, sub, WANT[sub], actual))
        rm(name)
    ok(not rot_bad,
       f"identity-cache rotation alice/bob/carol/dave/erin/frank x{len(ROT)}: every "
       f"file owned by the CURRENT subject's uid, no stale-cache cross "
       f"(bad={rot_bad[:3]})")

    # Read-back arm: write+GET as alice immediately AFTER a bob mapping, repeatedly;
    # alice must read HER bytes and the file must own 1001 (bob's just-used identity
    # did not bleed into alice's open).
    rb_bad = 0
    for i in range(6):
        bn = f"{T}rb_b_{i}.txt"
        an = f"{T}rb_a_{i}.txt"
        http("PUT", f"/pub/{bn}", port, LEGIT_TOK["bob"], f"bob-{i}\n".encode())
        ap = f"alice-rb-{i}\n".encode()
        http("PUT", f"/pub/{an}", port, LEGIT_TOK["alice"], ap)
        st, gb = http("GET", f"/pub/{an}", port, LEGIT_TOK["alice"])
        fp = pub_path(an)
        bfp = pub_path(bn)
        bob_owned = os.path.exists(bfp) and os.stat(bfp).st_uid == UID_BOB
        if not (st == 200 and gb == ap and os.path.exists(fp)
                and os.stat(fp).st_uid == UID_ALICE and bob_owned):
            rb_bad += 1
        rm(bn)
        rm(an)
    ok(rb_bad == 0,
       f"bob-then-alice interleave x6: bob file owns 1002, alice reads her own bytes "
       f"& owns 1001 right after -- no cache bleed (mismatches={rb_bad})")

    # =====================================================================
    # (2) PRINCIPAL-STRING EDGE CASES via the token sub claim.  Each hostile sub
    #     must EITHER deny (no file) OR map deterministically to a legit (>=1000,
    #     non-svc) uid -- never to root/svc/system -- AND the SAME edge string must
    #     yield the SAME outcome on a repeat (no steerable nondeterminism).
    # =====================================================================
    NUL = "alice" + chr(0) + "x"
    HOMO = "al" + chr(0x456) + "ce"          # cyrillic-i homoglyph of "alice"
    WIDE = chr(0xFF41) + "lice"              # fullwidth 'a' + "lice"
    edges = [
        ("overlong-1k", "z" * 1024),
        ("overlong-4k", "q" * 4096),
        ("embedded-newline", "ali\nce"),
        ("embedded-tab", "ali\tce"),
        ("embedded-space", "al ice"),
        ("leading-space", " alice"),
        ("trailing-space", "alice "),
        ("homoglyph-cyrillic", HOMO),
        ("fullwidth-unicode", WIDE),
        ("embedded-nul", NUL),
        ("numeric-1001", "1001"),
        ("numeric-zero", "0"),
        ("name-root", "root"),
        ("name-svc", "svc"),
        ("uppercase-ALICE", "ALICE"),
        ("dotdot-alice", "alice/.."),
    ]

    def edge_attempt(sub, tag):
        rel = f"{T}edge_{tag}.txt"
        st, _ = http("PUT", f"/pub/{rel}", port, mint(key, sub), b"edge\n")
        fp = pub_path(rel)
        made = os.path.exists(fp)
        uid = os.stat(fp).st_uid if made else -1
        return st, made, uid, fp

    for tag, sub in edges:
        st1, made1, uid1, fp1 = edge_attempt(sub, tag + "_a")
        st2, made2, uid2, fp2 = edge_attempt(sub, tag + "_b")
        # Core safety: nothing privileged/system, ever.
        priv = (made1 and uid1 < 1000) or (made2 and uid2 < 1000)
        svc = (made1 and uid1 == UID_SVC) or (made2 and uid2 == UID_SVC)
        ok(not priv and not svc,
           f"edge sub {tag}: never mapped to a reserved(<1000)/svc uid "
           f"(uids={uid1},{uid2})")
        # Determinism: SAME edge string -> SAME outcome class.
        ok((made1 == made2) and (uid1 == uid2),
           f"edge sub {tag}: deterministic -- repeat yields identical outcome "
           f"(made={made1}/{made2}, uid={uid1}/{uid2})")
        for f in (fp1, fp2):
            try:
                if os.path.exists(f):
                    os.remove(f)
            except OSError:
                pass

    # A homoglyph/unicode/whitespace/case variant of "alice" must NOT silently
    # resolve to the REAL alice uid (1001) -- impersonation by visual/whitespace/case
    # collision would be an escalation.  Either denied, or mapped to some OTHER id,
    # but not aliased onto 1001 as if it were her.
    for tag, sub in (("homoglyph-cyrillic", HOMO), ("fullwidth-unicode", WIDE),
                     ("leading-space", " alice"), ("trailing-space", "alice "),
                     ("uppercase-ALICE", "ALICE")):
        rel = f"{T}collide_{tag}.txt"
        st, _ = http("PUT", f"/pub/{rel}", port, mint(key, sub), b"x\n")
        fp = pub_path(rel)
        made = os.path.exists(fp)
        uid = os.stat(fp).st_uid if made else -1
        ok(not made or uid != UID_ALICE,
           f"alice-collision sub {tag}: not aliased onto the REAL alice uid 1001 "
           f"(made={made}, uid={uid})")
        rm(rel)

    # =====================================================================
    # (3) RAPID IDENTITY SWITCHING on ONE kept-alive connection.  Pipeline a
    #     rotation alice,bob,alice,carol,dave,alice,bob,carol on a SINGLE TCP
    #     connection; each PUT must be owned by the actor's uid -- proving the
    #     per-request principal is reset on the worker between pipelined requests
    #     and never leaks from the previous request.
    # =====================================================================
    SWITCH = ["alice", "bob", "alice", "carol", "dave", "alice", "bob", "carol"]
    seq = []
    for i, sub in enumerate(SWITCH):
        seq.append(("PUT", f"/pub/{T}ka_{i}.txt", LEGIT_TOK[sub],
                    f"{sub}-ka-{i}\n".encode(), None))
    res = http_keepalive(seq, port)
    ka_owner_bad = []
    all_ok_status = True
    for i, sub in enumerate(SWITCH):
        st = res[i][0] if i < len(res) else -1
        if st not in (200, 201, 204):
            all_ok_status = False
        fp = pub_path(f"{T}ka_{i}.txt")
        made = os.path.exists(fp)
        uid = os.stat(fp).st_uid if made else -1
        if not (made and uid == WANT[sub]):
            ka_owner_bad.append((i, sub, WANT[sub], uid))
        rm(f"{T}ka_{i}.txt")
    ok(all_ok_status,
       f"keep-alive identity switch: every pipelined request served (statuses "
       f"{[r[0] for r in res[:len(SWITCH)]]})")
    ok(not ka_owner_bad,
       f"keep-alive identity switch alice/bob/carol/dave on ONE conn: each file "
       f"owned by ITS actor's uid, no cross-request principal leak "
       f"(bad={ka_owner_bad[:3]})")

    # Read-back arm on a kept-alive conn: bob writes his own file, THEN carol on the
    # SAME socket must be DENIED bob's 0600 private.txt (no leftover bob auth on the
    # worker after bob's request) and must NOT see bob's secret bytes.
    BOB_SECRET = b"BOB-PRIVATE-SECRET"
    seq2 = [
        ("PUT", f"/pub/{T}kapriv.txt", LEGIT_TOK["bob"], b"bob-owns-this\n", None),
        ("GET", "/bob/private.txt", LEGIT_TOK["carol"], None, None),
    ]
    res2 = http_keepalive(seq2, port)
    bp = pub_path(f"{T}kapriv.txt")
    bob_made = os.path.exists(bp) and os.stat(bp).st_uid == UID_BOB
    ok(res2[0][0] in (200, 201, 204) and bob_made,
       f"keep-alive: bob's own write lands owned 1002 first (HTTP {res2[0][0]})")
    ok(res2[1][0] != 200 and BOB_SECRET not in (res2[1][1] or b""),
       f"keep-alive: carol after bob on SAME conn DENIED bob's 0600 private.txt, "
       f"no secret leak from the prior bob request (HTTP {res2[1][0]})")
    rm(f"{T}kapriv.txt")

    # =====================================================================
    # (4) <=8 CONCURRENT DISTINCT IDENTITIES each create a file in /pub.  Under
    #     true concurrency the broker must keep per-request identities separate --
    #     zero files may end up owned by the wrong subject's uid (6 threads < cap).
    # =====================================================================
    conc_bad = []
    conc_lock = threading.Lock()

    def conc_job(sub, want):
        name = f"{T}conc_{sub}.txt"
        try:
            st, _ = http("PUT", f"/pub/{name}", port, LEGIT_TOK[sub],
                         f"{sub}-conc\n".encode())
            fp = pub_path(name)
            made = os.path.exists(fp)
            uid = os.stat(fp).st_uid if made else -1
            if not (st in (200, 201, 204) and made and uid == want):
                with conc_lock:
                    conc_bad.append((sub, want, uid))
        except Exception as e:  # noqa: BLE001
            with conc_lock:
                conc_bad.append((sub, want, repr(e)))

    threads = [threading.Thread(target=conc_job, args=(s, u)) for s, u in LEGIT]
    for t in threads:        # exactly 6 distinct identities, under the <=8 cap
        t.start()
    for t in threads:
        t.join()
    ok(not conc_bad,
       f"<=8 concurrent distinct identities each own their /pub file by exactly "
       f"their uid -- zero owner cross under concurrency (bad={conc_bad[:3]})")
    for sub, _u in LEGIT:
        rm(f"{T}conc_{sub}.txt")

    # Liveness: the worker AND broker survived the cache rotation + edge-string
    # parsing + concurrency, and still map a clean alice op correctly.
    st, _ = http("PUT", f"/pub/{T}final.txt", port, LEGIT_TOK["alice"], b"ok\n")
    fp = pub_path(f"{T}final.txt")
    final_ok = (st in (200, 201, 204) and os.path.exists(fp)
                and os.stat(fp).st_uid == UID_ALICE)
    ok(final_ok,
       f"post-stress: broker still maps alice->1001 cleanly, worker not wedged "
       f"(HTTP {st})")
    rm(f"{T}final.txt")


