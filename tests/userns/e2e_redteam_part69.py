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


def run_broker_dos_resilience(key, data, port, s3port):
    """BROKER DoS / RESILIENCE under SUSTAINED MIXED legit+denied load.  The single
    per-worker broker is a shared chokepoint; this battery proves it does not
    misown, starve, desync, head-of-line-block, or crash under bounded pressure --
    and stays ALIVE afterwards (run_broker_failclosed tears it down LAST, so we must
    NOT kill it).  Novel axes vs run_combo_broker_pressure / run_concurrency_state_race:
      (a) FIVE distinct mapped identities (alice/bob/carol/dave/erin) churned rapidly
          via threads+keep-alive into the world-writable /pub dir -> every file owned
          by the RIGHT driving uid, body matches, no principal leak under contention;
      (b) rapid identity-SWITCH alice,bob,carol,dave,erin x2 on ONE keep-alive conn ->
          each create owned correctly, each read returns own bytes, no carry-over;
      (c) FAIRNESS: a flood of broker-DENIED ops (mallory/lowu/root) interleaved
          concurrently with the 5 legit identities -> the denials neither get created
          nor STARVE/DESYNC the legit ops (all legit succeed & own correctly);
      (d) HEAD-OF-LINE: one large (64KiB) in-flight GET concurrent with many small
          metadata ops as distinct identities -> no small op wedges, errors, or
          misowns behind the big read;
      (e) POST-PRESSURE HEALTH: a clean alice PUT+GET round-trips and /pub holds no
          svc/root/denied residue.  Bounded: <=8 threads/wave, <=64KiB bodies, no MB,
          broker left alive."""
    T = "bdr_"                                       # tag prefixes every fixture
    pubdir = os.path.join(data, "pub")               # svc:svc 0777 -> only idmap gates
    adir = os.path.join(data, "alice")
    # five mapped identities -> their expected st_uid after an impersonated create.
    IDENT = [("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL),
             ("dave", UID_DAVE), ("erin", UID_ERIN)]
    TOK = {s: mint(key, s) for s, _u in IDENT}
    UID_OF = {s: u for s, u in IDENT}
    # principals the broker idmap MUST refuse (each holds a VALID write token, so only
    # the idmap guard -- not authz -- can stop them): unmapped / sub-floor / root.
    DENIED = ["mallory", "lowu", "root"]
    DTOK = {s: mint(key, s) for s in DENIED}

    def uid_of_path(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def rm_quiet(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    created = []                                     # /pub files we must clean up

    def recover(label, n=[0]):
        """Legit alice PUT+GET roundtrip in her OWN dir -- a wedged/crashed broker
        would make the impersonated create fail, hang, or own wrong."""
        n[0] += 1
        rel = f"/alice/{T}rec_{n[0]}.txt"
        body = f"rec-{n[0]}-{label[:10]}".encode()
        stp, _ = http("PUT", rel, port, TOK["alice"], body)
        stg, gb = http("GET", rel, port, TOK["alice"])
        fp = os.path.join(adir, f"{T}rec_{n[0]}.txt")
        owned = os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE
        ok(stp in (200, 201, 204) and stg == 200 and gb == body and owned,
           f"recovery after {label}: alice PUT+GET roundtrips, owned 1001, broker "
           f"not wedged (PUT {stp}, GET {stg})")

    recover("baseline")

    # =====================================================================
    # A) FIVE-IDENTITY CHURN.  24 short-lived jobs (run in waves of <=8 live
    #    threads) each open a fresh keep-alive conn and PUT+GET a UNIQUE-marker
    #    file into /pub as one of the five identities, round-robin.  Under this
    #    contention the per-worker process-global principal could bleed one
    #    tenant's setfsuid into another's create.  Assert per-job: file exists,
    #    owned by the DRIVING uid (never svc/root/another tenant), and the GET
    #    returned that job's OWN marker (no crossed reply).
    # =====================================================================
    churn_bad = []          # (job, reason, detail) -- any ownership/content cross
    churn_served = [0]      # count of jobs whose create+read both succeeded

    def churn_job(i):
        sub, want = IDENT[i % 5]
        rel = f"{T}churn_{sub}_{i}.txt"
        marker = f"CHURN-{sub}-{i}-MARK\n".encode()
        seq = [("PUT", f"/pub/{rel}", TOK[sub], marker, None),
               ("GET", f"/pub/{rel}", TOK[sub], None, None)]
        try:
            res = http_keepalive(seq, port)
        except Exception as e:  # noqa: BLE001
            churn_bad.append((i, "exc", repr(e)))
            return
        fp = os.path.join(pubdir, rel)
        created.append(fp)
        if not (res and res[0][0] in (200, 201, 204)):
            churn_bad.append((i, "put-status", res[0][0] if res else -1))
            return
        u = uid_of_path(fp)
        if u != want:
            churn_bad.append((i, "owner", (sub, u, want)))
        if u in (UID_SVC, 0):
            churn_bad.append((i, "reserved-owner", (sub, u)))
        # the read on the SAME conn must return THIS job's own marker, not a
        # neighbour's crossed reply.
        if not (len(res) > 1 and res[1][0] == 200 and res[1][1] == marker):
            churn_bad.append((i, "crossed-read",
                              (sub, res[1][0] if len(res) > 1 else -1)))
        else:
            churn_served[0] += 1

    threads = [threading.Thread(target=churn_job, args=(i,)) for i in range(24)]
    for base in range(0, len(threads), 8):           # waves of <=8 live threads
        wave = threads[base:base + 8]
        for t in wave:
            t.start()
        for t in wave:
            t.join()
    ok(not churn_bad,
       f"5-identity churn (24 jobs): every file owned by its DRIVING identity, no "
       f"principal leak / crossed read under contention (bad={churn_bad[:3]})")
    ok(churn_served[0] == 24,
       f"5-identity churn: all 24 jobs SERVED (broker stayed responsive, none "
       f"dropped/wedged) (served={churn_served[0]}/24)")
    # cross-tenant ownership audit: count distinct correct owners actually observed
    # (proves the broker really switched principal per identity, not a fixed uid).
    owners_seen = set()
    for sub, want in IDENT:
        for i in range(24):
            if i % 5 == [s for s, _ in IDENT].index(sub):
                fp = os.path.join(pubdir, f"{T}churn_{sub}_{i}.txt")
                if uid_of_path(fp) == want:
                    owners_seen.add(want)
                    break
    ok(owners_seen == {u for _s, u in IDENT},
       f"5-identity churn: all five distinct uids (1001..1005) observed as real "
       f"owners -- broker per-request remap proven (seen={sorted(owners_seen)})")
    recover("five-identity churn")

    # =====================================================================
    # B) RAPID IDENTITY-SWITCH on ONE keep-alive connection: alice,bob,carol,
    #    dave,erin,alice,bob,carol,dave,erin -- each PUT+GET pair on the SAME
    #    socket.  A stale process-global principal would make the request right
    #    after a switch create/own/read under the PREVIOUS identity.
    # =====================================================================
    seq = []
    order = [s for s, _ in IDENT] * 2                # 10 switches on one conn
    for j, sub in enumerate(order):
        rel = f"{T}sw_{sub}_{j}.txt"
        body = f"SW-{sub}-{j}\n".encode()
        seq.append(("PUT", f"/pub/{rel}", TOK[sub], body, None))
        seq.append(("GET", f"/pub/{rel}", TOK[sub], None, None))
        created.append(os.path.join(pubdir, rel))
    sres = http_keepalive(seq, port)
    sw_owner_bad = sw_read_bad = 0
    for j, sub in enumerate(order):
        rel = f"{T}sw_{sub}_{j}.txt"
        body = f"SW-{sub}-{j}\n".encode()
        fp = os.path.join(pubdir, rel)
        if uid_of_path(fp) != UID_OF[sub]:
            sw_owner_bad += 1
        gi = j * 2 + 1
        if not (gi < len(sres) and sres[gi][0] == 200 and sres[gi][1] == body):
            sw_read_bad += 1
    ok(sw_owner_bad == 0,
       f"rapid switch x10 on one conn: every create owned by the post-switch "
       f"identity, no stale carry-over (bad={sw_owner_bad})")
    ok(sw_read_bad == 0,
       f"rapid switch x10 on one conn: every read returned the requester's OWN "
       f"bytes, no crossed reply across the switch (bad={sw_read_bad})")
    recover("rapid identity-switch")

    # =====================================================================
    # C) FAIRNESS: sustained MIXED legit+denied load.  Concurrently (waves of
    #    <=8) fire (i) broker-DENIED PUTs (mallory/lowu/root -> /pub) that must
    #    be refused, and (ii) legit 5-identity PUTs that must succeed & own
    #    correctly.  The denials must NOT starve or desync the legit ops: every
    #    legit op completes with the right owner, and no denied file appears.
    # =====================================================================
    fair_denied_created = []     # any denied principal that got a /pub file
    fair_legit_bad = []          # legit op that failed/misowned under the flood
    fair_legit_done = [0]
    fair_exc = []

    def fair_job(i):
        try:
            if i % 2 == 0:                            # DENIED flood
                sub = DENIED[(i // 2) % len(DENIED)]
                rel = f"{T}fair_d_{sub}_{i}.txt"
                st, _ = http("PUT", f"/pub/{rel}", port, DTOK[sub],
                             f"{sub.upper()}-DENY-{i}\n".encode())
                fp = os.path.join(pubdir, rel)
                created.append(fp)
                u = uid_of_path(fp)
                if st in (200, 201, 204) or os.path.exists(fp):
                    fair_denied_created.append((sub, i, st, u))
            else:                                     # LEGIT op
                sub, want = IDENT[(i // 2) % 5]
                rel = f"{T}fair_l_{sub}_{i}.txt"
                body = f"LEGIT-{sub}-{i}\n".encode()
                st, _ = http("PUT", f"/pub/{rel}", port, TOK[sub], body)
                fp = os.path.join(pubdir, rel)
                created.append(fp)
                if not (st in (200, 201, 204)
                        and os.path.exists(fp) and uid_of_path(fp) == want):
                    fair_legit_bad.append((sub, i, st, uid_of_path(fp)))
                else:
                    fair_legit_done[0] += 1
        except Exception as e:  # noqa: BLE001
            fair_exc.append((i, repr(e)))

    fthreads = [threading.Thread(target=fair_job, args=(i,)) for i in range(24)]
    for base in range(0, len(fthreads), 8):
        wave = fthreads[base:base + 8]
        for t in wave:
            t.start()
        for t in wave:
            t.join()
    ok(not fair_denied_created,
       f"fairness flood: NO denied principal (mallory/lowu/root) ever created a "
       f"/pub file even mixed with legit load (created={fair_denied_created[:3]})")
    ok(not fair_legit_bad,
       f"fairness flood: every legit 5-identity op succeeded & owned correctly -- "
       f"denials did NOT starve/misown them (bad={fair_legit_bad[:3]})")
    ok(fair_legit_done[0] == 12,
       f"fairness flood: all 12 legit ops completed under the deny storm (no "
       f"starvation) (done={fair_legit_done[0]}/12)")
    ok(not fair_exc,
       f"fairness flood: no exception/crash mixing denied+legit concurrently "
       f"(exc={fair_exc[:2]})")
    recover("mixed legit+denied flood")

    # =====================================================================
    # D) HEAD-OF-LINE BLOCKING.  Stage a large (64KiB, the body cap) alice file,
    #    then run ONE big GET of it concurrently with SMALL metadata ops driven
    #    by distinct identities (PROPFIND/stat).  A serialized broker that wedged
    #    the small ops behind the big read would make them slow, error, or worse,
    #    misown.  Assert the small ops all returned promptly & correctly while the
    #    big read was in flight.  <=6 concurrent small ops + 1 big = <=8 threads.
    # =====================================================================
    BIG = b"H" * (64 * 1024)                          # 64KiB == body cap
    bigrel = f"/alice/{T}big.bin"
    stp, _ = http("PUT", bigrel, port, TOK["alice"], BIG)
    bigfp = os.path.join(adir, f"{T}big.bin")
    ok(stp in (200, 201, 204) and os.path.exists(bigfp)
       and os.stat(bigfp).st_uid == UID_ALICE and os.path.getsize(bigfp) == len(BIG),
       f"head-of-line setup: alice's 64KiB file staged, owned 1001 (PUT {stp})")

    hol = {}                 # ident -> (status, ok_bool, elapsed)
    big_result = {}

    def big_read():
        t0 = time.time()
        st, b = http("GET", bigrel, port, TOK["alice"])
        big_result["r"] = (st, len(b or b""), time.time() - t0)

    PF = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
          b'<D:displayname/></D:prop></D:propfind>')

    def small_op(sub):
        # each identity probes its OWN namespace via a cheap metadata op; alice
        # PROPFINDs her own staged file (must see it), the rest PROPFIND /pub
        # (world-listable) -- all must return promptly, none wedged behind the big
        # read.  We record status + whether it returned in a sane time.
        t0 = time.time()
        if sub == "alice":
            st, b = http("PROPFIND", bigrel, port, TOK[sub],
                         hdrs={"Depth": "0", "Content-Type": "application/xml"},
                         data=PF)
            good = st in (207, 200)
        else:
            st, b = http("PROPFIND", "/pub", port, TOK[sub],
                         hdrs={"Depth": "0", "Content-Type": "application/xml"},
                         data=PF)
            good = st in (207, 200)
        hol[sub] = (st, good, time.time() - t0)

    bt = threading.Thread(target=big_read)
    sts = [threading.Thread(target=small_op, args=(s,))
           for s, _u in IDENT]                       # 5 small ops
    bt.start()
    for t in sts:                                    # 1 big + 5 small = 6 threads
        t.start()
    bt.join()
    for t in sts:
        t.join()
    br = big_result.get("r", (-1, 0, 99.0))
    ok(br[0] == 200 and br[1] == len(BIG),
       f"head-of-line: the big 64KiB GET itself returned all bytes (HTTP {br[0]}, "
       f"{br[1]}B)")
    small_ok = all(v[1] for v in hol.values())
    ok(len(hol) == 5 and small_ok,
       f"head-of-line: every small metadata op (5 identities) returned correctly "
       f"WHILE the big read was in flight -- no wedge ({sorted((s, v[0]) for s, v in hol.items())})")
    slowest = max((v[2] for v in hol.values()), default=99.0)
    ok(slowest < 6.0,
       f"head-of-line: no small op was blocked behind the big read (slowest "
       f"{slowest:.2f}s)")
    # alice's own PROPFIND must have seen HER file (right identity, not crossed).
    a_hol = hol.get("alice", (-1, False, 0))
    ok(a_hol[1],
       f"head-of-line: alice's PROPFIND on her own file succeeded concurrently "
       f"(right identity under load, HTTP {a_hol[0]})")
    recover("head-of-line big-vs-small")

    # =====================================================================
    # E) POST-PRESSURE HEALTH + CLEANUP.  Prove the broker fully survived: a clean
    #    alice PUT+GET round-trips, and the world-writable /pub holds NO file owned
    #    by svc(1500)/root(0)/a denied principal across everything we did (any such
    #    residue is a true idmap-guard breach).  Then clean up our /pub fixtures so
    #    we leave the broker AND the export tidy for run_broker_failclosed.
    # =====================================================================
    # post-pressure clean roundtrip in alice's own dir.
    final_rel = f"/alice/{T}final.txt"
    final_body = b"BROKER-SURVIVED-PRESSURE\n"
    sp, _ = http("PUT", final_rel, port, TOK["alice"], final_body)
    sg, gb = http("GET", final_rel, port, TOK["alice"])
    ffp = os.path.join(adir, f"{T}final.txt")
    ok(sp in (200, 201, 204) and sg == 200 and gb == final_body
       and os.path.exists(ffp) and os.stat(ffp).st_uid == UID_ALICE,
       f"post-pressure: clean alice PUT+GET round-trips, owned 1001 -- broker ALIVE "
       f"and correctly mapping after all DoS pressure (PUT {sp}, GET {sg})")
    # a fresh CAROL op too -- proves the broker can still remap a SECOND identity
    # after the storm (not just stuck on alice).
    crel = f"/pub/{T}final_carol.txt"
    csp, _ = http("PUT", crel, port, TOK["carol"], b"carol-after\n")
    cfp = os.path.join(pubdir, f"{T}final_carol.txt")
    created.append(cfp)
    ok(csp in (200, 201, 204) and uid_of_path(cfp) == UID_CAROL,
       f"post-pressure: carol op still remaps to 1003 (broker not stuck on one "
       f"principal) (HTTP {csp}, uid={uid_of_path(cfp)})")
    # residue audit BEFORE we delete anything: any bdr_ file in /pub owned by a
    # reserved/denied uid is a breach.
    residue = []
    try:
        for f in os.listdir(pubdir):
            if not f.startswith(T):
                continue
            p = os.path.join(pubdir, f)
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                u = os.lstat(p).st_uid
            except OSError:
                continue
            if u < 1000 or u == UID_SVC:             # reserved / svc / denied sub-floor
                residue.append((f, u))
    except OSError:
        pass
    ok(not residue,
       f"FINAL: no bdr_ file in world-writable /pub owned by svc/root/sub-floor -- "
       f"every denied mapping refused at the broker (residue={residue[:4]})")
    # clean up our /pub fixtures (leave the export tidy; broker stays ALIVE).
    for p in set(created):
        rm_quiet(p)
    recover("post-pressure final sanity")


