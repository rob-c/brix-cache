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


def run_samefile_contention(key, data, port, s3port):
    """Same PHYSICAL file, multiple identities CONTENDING concurrently.  Distinct
    from the existing different-file concurrency: here every writer targets ONE
    path, stressing the per-worker impersonation principal under true contention.
    Whoever wins, the file must be owned by an actual mapped writer (never svc/root)
    and the content must be a whole value from one writer (no torn/mixed write)."""
    ta, tb = mint(key, "alice"), mint(key, "bob")

    # (1) N threads alternate alice/bob PUT to the SAME /pub/contend.txt (0777 dir).
    N = 24
    bodies = {"alice": b"AAAAAAAA-ALICE-WHOLE-VALUE\n",
              "bob":   b"BBBBBBBB-BOB-WHOLE-VALUE\n"}
    err = []

    def putter(i):
        sub = "alice" if i % 2 == 0 else "bob"
        tok = ta if sub == "alice" else tb
        try:
            http("PUT", "/pub/contend.txt", port, tok, bodies[sub])
        except Exception as e:  # noqa: BLE001
            err.append(repr(e))

    threads = [threading.Thread(target=putter, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    cf = os.path.join(data, "pub", "contend.txt")
    if os.path.exists(cf):
        owner = os.stat(cf).st_uid
        content = open(cf, "rb").read()
        ok(owner in (UID_ALICE, UID_BOB),
           f"contended file owned by a real writer not worker/root (uid={owner})")
        ok(content in bodies.values(),
           "contended file content is one writer's WHOLE value (no torn/mixed write)")
    else:
        ok(False, "contended file missing after the storm")
    ok(not err, f"no exceptions during same-file contention ({err[:2]})")

    # (2) two identities, ONE keep-alive connection is NOT used here; instead two
    #     threads racing a create of the SAME fresh path each loop iteration.
    mism = 0
    for r in range(8):
        rp = f"/pub/race_{r}.txt"
        res = []

        def race(sub):
            tok = ta if sub == "alice" else tb
            http("PUT", rp, port, tok, f"{sub}\n".encode())
            res.append(sub)

        t1 = threading.Thread(target=race, args=("alice",))
        t2 = threading.Thread(target=race, args=("bob",))
        t1.start(); t2.start(); t1.join(); t2.join()
        fp = os.path.join(data, "pub", f"race_{r}.txt")
        if os.path.exists(fp) and os.stat(fp).st_uid not in (UID_ALICE, UID_BOB):
            mism += 1
    ok(mism == 0, f"alice/bob same-path race: never worker/root-owned (mismatches={mism})")

    # (3) rapid create->delete->recreate of one path by alice: always alice-owned,
    #     never a stale principal leaking svc/root.
    leak = 0
    for r in range(12):
        http("PUT", "/alice/churn.txt", port, ta, f"churn{r}\n".encode())
        cp = os.path.join(data, "alice", "churn.txt")
        if os.path.exists(cp) and os.stat(cp).st_uid != UID_ALICE:
            leak += 1
        http("DELETE", "/alice/churn.txt", port, ta)
    ok(leak == 0, f"rapid churn of one path stays alice-owned (leaks={leak})")

    # (4) alice creates /pub/h.txt, bob OVERWRITES it (both can write 0777 pub) ->
    #     after bob's write the file is BOB-owned (the staged write re-creates the
    #     inode as the writer), never svc/root; no cross-principal residue.
    http("PUT", "/pub/handover.txt", port, ta, b"alice-first\n")
    http("PUT", "/pub/handover.txt", port, tb, b"bob-second\n")
    hp = os.path.join(data, "pub", "handover.txt")
    if os.path.exists(hp):
        ok(os.stat(hp).st_uid in (UID_ALICE, UID_BOB) and os.stat(hp).st_uid != UID_SVC,
           f"shared-dir handover file owned by a real writer (uid={os.stat(hp).st_uid})")
    else:
        ok(False, "handover file missing")


def run_group_read_dac(key, data, port, s3port):
    """GROUP-based read DAC through the real protocols — exercises the broker's
    setgroups() (a mapped user's SUPPLEMENTARY groups), the core impersonation
    mechanism never before tested end-to-end.  staff={alice,carol}, bob NOT in
    staff.  A 0640 group=staff file: alice (owner) + carol (group member) may read,
    bob (other) may not.  Tested over WebDAV AND root://; S3 only has alice's key
    so it covers the owner leg."""
    GR = "/grp"
    SR = b"STAFF-GROUP-READABLE"
    RR = b"RESEARCH-GROUP-READABLE"

    # (1) staff_r.txt 0640 alice:staff — owner alice reads.
    st, b = http("GET", f"{GR}/staff_r.txt", port, mint(key, "alice"))
    ok(st == 200 and SR in (b or b""), f"owner alice reads 0640 staff file (HTTP {st})")
    # (2) carol is in staff (supplementary) -> group-read ALLOWED (proves setgroups).
    st, b = http("GET", f"{GR}/staff_r.txt", port, mint(key, "carol"))
    ok(st == 200 and SR in (b or b""),
       f"carol (staff group member) reads 0640 staff file via group DAC (HTTP {st})")
    # (3) bob is NOT in staff -> other bits = 0 -> DENIED + no leak.
    st, b = http("GET", f"{GR}/staff_r.txt", port, mint(key, "bob"))
    ok(SR not in (b or b""),
       f"bob (NOT in staff) denied 0640 staff file, no leak (HTTP {st})")
    # (4) dave is not in staff -> denied (second non-member control).
    st, b = http("GET", f"{GR}/staff_r.txt", port, mint(key, "dave"))
    ok(SR not in (b or b""),
       f"dave (NOT in staff) denied 0640 staff file (HTTP {st})")

    # (5) same group-read leg via root:// (different protocol, same DAC).
    if xrd_avail():
        rc, out, _e = xrd_fs(["cat", f"{GR}/staff_r.txt"], "carol")
        ok(rc == 0 and SR.decode() in (out or ""),
           f"carol reads 0640 staff file via root:// group DAC (rc={rc})")
        rc, out, _e = xrd_fs(["cat", f"{GR}/staff_r.txt"], "bob")
        ok(rc != 0 and SR.decode() not in (out or ""),
           f"bob denied 0640 staff file via root:// (rc={rc})")

    # (6) staff_none.txt 0600 alice:staff — even carol (group member) is DENIED
    #     (no group-read bit) — proves the group GRANT in (2) is bit-driven.
    st, b = http("GET", f"{GR}/staff_none.txt", port, mint(key, "carol"))
    ok(b"STAFF-OWNER-ONLY" not in (b or b""),
       f"carol denied 0600 staff file (no group-read bit) (HTTP {st})")
    st, b = http("GET", f"{GR}/staff_none.txt", port, mint(key, "alice"))
    ok(st == 200 and b"STAFF-OWNER-ONLY" in (b or b""),
       f"owner alice reads her own 0600 file (HTTP {st})")

    # (7) world_r.txt 0644 — bob (other) CAN read (other-read bit set).
    st, b = http("GET", f"{GR}/world_r.txt", port, mint(key, "bob"))
    ok(st == 200 and b"WORLD-READABLE" in (b or b""),
       f"bob reads 0644 world-readable file (other bit) (HTTP {st})")

    # (8) research_r.txt 0640 bob:research — dave (in research) reads; alice/carol
    #     (NOT in research) denied — a SECOND independent group proves it's not a
    #     blanket 'any group' grant.
    st, b = http("GET", f"{GR}/research_r.txt", port, mint(key, "dave"))
    ok(st == 200 and RR in (b or b""),
       f"dave (research member) reads 0640 research file (HTTP {st})")
    st, b = http("GET", f"{GR}/research_r.txt", port, mint(key, "alice"))
    ok(RR not in (b or b""),
       f"alice (NOT in research) denied 0640 research file (HTTP {st})")
    st, b = http("GET", f"{GR}/research_r.txt", port, mint(key, "carol"))
    ok(RR not in (b or b""),
       f"carol (NOT in research) denied 0640 research file (HTTP {st})")

    # (9) bob IS the owner of research_r.txt -> owner read.
    st, b = http("GET", f"{GR}/research_r.txt", port, mint(key, "bob"))
    ok(st == 200 and RR in (b or b""),
       f"owner bob reads his own research file (HTTP {st})")


def run_group_write_dac(key, data, port, s3port):
    """GROUP-based WRITE DAC.  A 0660 group-writable file: a group member may
    overwrite it (WebDAV PUT replaces via staged write in the parent dir, so this
    also needs dir write — we use group-writable dirs); a non-member may not.
    Distinct from group-read: exercises setgroups on the WRITE path."""
    GR = "/grp"

    # shareddir is 0770 alice:shared (alice,bob,carol). A member creates a file in
    # it -> allowed + owned by the creator with the dir's group (setgid? no, 0770
    # not setgid -> file gets creator's primary group).  Non-member (dave) denied.
    for sub, uid in (("alice", UID_ALICE), ("bob", UID_BOB), ("carol", UID_CAROL)):
        st, _ = http("PUT", f"/shareddir/{sub}_made.txt", port, mint(key, sub),
                     f"{sub}-in-shared\n".encode())
        fp = os.path.join(data, "shareddir", f"{sub}_made.txt")
        ok(st in (200, 201, 204) and os.path.exists(fp)
           and os.stat(fp).st_uid == uid,
           f"{sub} (shared-group member) creates in 0770 shared dir, owned {sub} (HTTP {st})")
    # dave is NOT in shared -> cannot enter/write the 0770 dir.
    st, _ = http("PUT", "/shareddir/dave_evil.txt", port, mint(key, "dave"), b"x\n")
    ok(not os.path.exists(os.path.join(data, "shareddir", "dave_evil.txt")),
       f"dave (NOT in shared) cannot write the 0770 shared dir (HTTP {st})")

    # staffdir is 0770 alice:staff. carol (staff) creates; bob (not) denied.
    st, _ = http("PUT", "/staffdir/carol_made.txt", port, mint(key, "carol"), b"c\n")
    ok(os.path.exists(os.path.join(data, "staffdir", "carol_made.txt")),
       f"carol (staff) creates in 0770 staff dir (HTTP {st})")
    st, _ = http("PUT", "/staffdir/bob_evil.txt", port, mint(key, "bob"), b"x\n")
    ok(not os.path.exists(os.path.join(data, "staffdir", "bob_evil.txt")),
       f"bob (NOT staff) cannot write the 0770 staff dir (HTTP {st})")

    # a group member DELETE in a group-writable dir: carol deletes the file she
    # made in staffdir -> allowed (dir write via group); bob cannot.
    st, _ = http("DELETE", "/staffdir/carol_made.txt", port, mint(key, "carol"))
    ok(not os.path.exists(os.path.join(data, "staffdir", "carol_made.txt")),
       f"carol deletes her own file in the staff dir (HTTP {st})")

    # carol (staff) overwrites the staff-group inside.txt? inside.txt is 0640 (no
    # group WRITE), in a 0770 dir.  A staged PUT replaces the file via the DIR
    # (carol has dir write through staff) -> allowed; the new file is carol-owned.
    st, _ = http("PUT", "/staffdir/inside.txt", port, mint(key, "carol"),
                 b"carol-rewrote\n")
    ip = os.path.join(data, "staffdir", "inside.txt")
    ok(st in (200, 201, 204) and os.path.exists(ip),
       f"carol rewrites a file in the group-writable staff dir (HTTP {st})")
    # bob (not staff) cannot rewrite it (no dir write).
    st, _ = http("PUT", "/staffdir/inside.txt", port, mint(key, "bob"), b"bob-pwn\n")
    ok(b"bob-pwn" not in open(ip, "rb").read() if os.path.exists(ip) else True,
       f"bob cannot rewrite a file in the staff dir (HTTP {st})")


def run_permission_matrix(key, data, port, s3port):
    """The DEFINITIVE POSIX read-DAC matrix through the gateway: one file
    (grp/matrix.txt, owner alice:staff, marker MATRIX-SECRET-BODY) cycled through a
    spread of modes; for each, READ is attempted by alice (OWNER bits), carol (GROUP
    staff member -> GROUP bits) and bob (OTHER bits).  The gateway's allow/deny MUST
    exactly track the UNIX bits the impersonated user is subject to — proving the
    broker enforces full owner/group/other DAC, not merely owner bits."""
    fp = os.path.join(data, "grp", "matrix.txt")
    MARK = b"MATRIX-SECRET-BODY"
    path = "/grp/matrix.txt"

    accessors = (("alice", 0o400), ("carol", 0o040), ("bob", 0o004))
    modes = [0o000, 0o400, 0o040, 0o004, 0o440, 0o444, 0o600,
             0o640, 0o644, 0o604, 0o660, 0o006]
    for mode in modes:
        try:
            os.chown(fp, UID_ALICE, GID_STAFF)
            os.chmod(fp, mode)
        except OSError:
            pass
        for sub, bit in accessors:
            allowed = bool(mode & bit)
            st, b = http("GET", path, port, mint(key, sub))
            got = MARK in (b or b"")
            ok(got == allowed,
               f"mode {mode:04o} read by {sub} ({'allow' if allowed else 'deny'}): "
               f"gateway {'served' if got else 'withheld'} (HTTP {st})")
    # restore to owner-only.
    try:
        os.chmod(fp, 0o600)
    except OSError:
        pass

    # the same matrix spot-checked over root:// for the GROUP leg (carol), proving
    # the group DAC is protocol-independent kernel state, not WebDAV bookkeeping.
    if xrd_avail():
        for mode in (0o040, 0o000, 0o640):
            try:
                os.chmod(fp, mode)
            except OSError:
                pass
            allowed = bool(mode & 0o040)
            rc, out, _e = xrd_fs(["cat", path], "carol")
            got = MARK.decode() in (out or "")
            ok(got == allowed,
               f"root:// mode {mode:04o} group-read by carol "
               f"({'allow' if allowed else 'deny'}) rc={rc}")
        try:
            os.chmod(fp, 0o600)
        except OSError:
            pass


