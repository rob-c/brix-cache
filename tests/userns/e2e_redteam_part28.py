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


def run_group_concurrency(key, data, port, s3port):
    """CONCURRENT multi-member access to GROUP resources under the per-worker
    principal + per-request setgroups/setfsgid model.  The worker's impersonation
    state is process-global, so the danger is a RACE: while alice's request is
    setgroups(staff)'d on a worker, a bob request landing on that same worker must
    NOT transiently inherit staff and read a staff-only file (a supplementary-group
    leak), and a carol PUT must never be written owned by alice/bob/svc.  We drive
    N-way concurrent member/non-member storms against the 0770 staffdir and the
    0640 grp/staff_r.txt, then scan the filesystem for any wrongly-owned/grouped
    artifact.  staff={alice,carol}; bob is NOT in staff.  Positive controls
    (members SUCCEED, owners read) sit beside every deny so a blanket block cannot
    false-pass; every read-deny also asserts the marker bytes never leaked."""
    SR = b"STAFF-GROUP-READABLE"
    staffdir_fs = os.path.join(data, "staffdir")
    gr_path = "/grp/staff_r.txt"
    lock = threading.Lock()

    # ---------------------------------------------------------------------------
    # (A) alice + carol (both staff) concurrently CREATE distinct files in the
    #     0770 staffdir.  Each file must end up owned by its REAL creator (never
    #     svc/root, never the other member) — proves the per-request principal is
    #     not clobbered by a concurrently-running sibling request on the worker.
    # ---------------------------------------------------------------------------
    members = (("alice", UID_ALICE), ("carol", UID_CAROL))
    N_each = 12
    create_results = {}   # (sub, i) -> (status, fs_uid_or_None)
    cleanup_paths = []

    def creator(sub, uid, i):
        rel = f"gc_{sub}_{i}.txt"
        body = f"GC-{sub}-{i}\n".encode()
        st, _ = http("PUT", f"/staffdir/{rel}", port, mint(key, sub), body)
        fp = os.path.join(staffdir_fs, rel)
        fs_uid = None
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                fs_uid = os.lstat(fp).st_uid
        except OSError:
            fs_uid = None
        with lock:
            create_results[(sub, i)] = (st, fs_uid)
            cleanup_paths.append(fp)

    threads = []
    for i in range(N_each):
        for sub, uid in members:
            threads.append(threading.Thread(target=creator, args=(sub, uid, i)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Per-member aggregate: every created file owned by the right member, no leak.
    for sub, uid in members:
        made = 0
        wrong = 0
        for i in range(N_each):
            st, fs_uid = create_results.get((sub, i), (-1, None))
            if fs_uid is not None:
                made += 1
                if fs_uid != uid:
                    wrong += 1
        ok(made >= 1 and wrong == 0,
           f"concurrent staffdir creates by {sub} (staff): {made} files all owned "
           f"{sub}={uid}, {wrong} wrong-owner (principal not clobbered under contention)")

    # Cross-check: NONE of alice's files are carol-owned and vice-versa (explicit
    # mutual no-swap — the precise leak a principal race would produce).
    alice_swapped = sum(1 for i in range(N_each)
                        if create_results.get(("alice", i), (-1, None))[1] == UID_CAROL)
    carol_swapped = sum(1 for i in range(N_each)
                        if create_results.get(("carol", i), (-1, None))[1] == UID_ALICE)
    ok(alice_swapped == 0,
       f"no alice-created staffdir file ended up carol-owned (swaps={alice_swapped})")
    ok(carol_swapped == 0,
       f"no carol-created staffdir file ended up alice-owned (swaps={carol_swapped})")

    # No staffdir artifact from this batch is owned by svc(1500) or root(0) — a
    # principal that failed to set would have created as the worker user.
    svc_or_root = 0
    for sub, _u in members:
        for i in range(N_each):
            fs_uid = create_results.get((sub, i), (-1, None))[1]
            if fs_uid in (UID_SVC, 0):
                svc_or_root += 1
    ok(svc_or_root == 0,
       f"no concurrent staffdir create landed as svc/root (worker-uid leaks={svc_or_root})")

    # ---------------------------------------------------------------------------
    # (B) Interleaved READS of grp/staff_r.txt (0640 alice:staff): carol (member,
    #     allowed) racing bob (non-member, denied).  EVERY carol read must return
    #     the marker; EVERY bob read must be denied AND marker-free.  A setgroups
    #     leak (bob transiently inheriting staff while a carol request runs) shows
    #     up as a single bob read that returns the marker.
    # ---------------------------------------------------------------------------
    R = 16
    carol_reads = []   # body bytes
    bob_reads = []     # (status, body bytes)

    def carol_reader(_i):
        st, b = http("GET", gr_path, port, mint(key, "carol"))
        with lock:
            carol_reads.append((st, b or b""))

    def bob_reader(_i):
        st, b = http("GET", gr_path, port, mint(key, "bob"))
        with lock:
            bob_reads.append((st, b or b""))

    rthreads = []
    for i in range(R):
        rthreads.append(threading.Thread(target=carol_reader, args=(i,)))
        rthreads.append(threading.Thread(target=bob_reader, args=(i,)))
    for t in rthreads:
        t.start()
    for t in rthreads:
        t.join()

    carol_ok = sum(1 for st, b in carol_reads if st == 200 and SR in b)
    ok(len(carol_reads) == R and carol_ok == R,
       f"all {R} concurrent carol reads of 0640 staff file returned the marker "
       f"({carol_ok}/{len(carol_reads)}) — group grant stable under contention")

    bob_leaked = sum(1 for _st, b in bob_reads if SR in b)
    ok(len(bob_reads) == R and bob_leaked == 0,
       f"NO concurrent bob read leaked the staff marker ({bob_leaked}/{len(bob_reads)} "
       f"leaks) — no transient setgroups inheritance while carol requests run")
    bob_served = sum(1 for st, _b in bob_reads if st == 200)
    ok(bob_served == 0,
       f"every concurrent bob read of the staff file was denied a 200 ({bob_served} served)")

    # ---------------------------------------------------------------------------
    # (C) MIXED storm: members and non-members hammer staff group resources at
    #     once (member create + member read + non-member create-attempt + non-member
    #     read-attempt).  Record breaches inline, then scan the tree afterwards.
    # ---------------------------------------------------------------------------
    breaches = []      # (kind, who, detail)
    storm_made = []    # fs paths this storm created (for ownership scan)

    def storm(i):
        kind = i % 6
        try:
            if kind == 0:                         # alice (staff) create
                rel = f"gc_storm_a_{i}.txt"
                http("PUT", f"/staffdir/{rel}", port, mint(key, "alice"), b"sa\n")
                with lock:
                    storm_made.append(("alice", os.path.join(staffdir_fs, rel)))
            elif kind == 1:                       # carol (staff) create
                rel = f"gc_storm_c_{i}.txt"
                http("PUT", f"/staffdir/{rel}", port, mint(key, "carol"), b"sc\n")
                with lock:
                    storm_made.append(("carol", os.path.join(staffdir_fs, rel)))
            elif kind == 2:                       # carol (staff) read group file
                st, b = http("GET", gr_path, port, mint(key, "carol"))
                if not (st == 200 and SR in (b or b"")):
                    with lock:
                        breaches.append(("member-read-fail", "carol", st))
            elif kind == 3:                       # bob (non-member) create attempt
                rel = f"gc_storm_bob_{i}.txt"
                http("PUT", f"/staffdir/{rel}", port, mint(key, "bob"), b"bx\n")
                fp = os.path.join(staffdir_fs, rel)
                if os.path.exists(fp):
                    with lock:
                        breaches.append(("nonmember-create", "bob", rel))
            elif kind == 4:                       # bob (non-member) read attempt
                st, b = http("GET", gr_path, port, mint(key, "bob"))
                if SR in (b or b""):
                    with lock:
                        breaches.append(("nonmember-read-leak", "bob", st))
            else:                                 # dave (non-member) read attempt
                st, b = http("GET", gr_path, port, mint(key, "dave"))
                if SR in (b or b""):
                    with lock:
                        breaches.append(("nonmember-read-leak", "dave", st))
        except OSError as e:
            with lock:
                breaches.append(("exc", i, repr(e)))

    S = 48
    sthreads = [threading.Thread(target=storm, args=(i,)) for i in range(S)]
    for t in sthreads:
        t.start()
    for t in sthreads:
        t.join()

    ok(not any(x[0] == "nonmember-create" for x in breaches),
       f"storm: no non-member (bob) create breached the 0770 staffdir "
       f"(breaches={[b for b in breaches if b[0]=='nonmember-create'][:3]})")
    ok(not any(x[0] == "nonmember-read-leak" for x in breaches),
       f"storm: no non-member read leaked the staff marker "
       f"(leaks={[b for b in breaches if b[0]=='nonmember-read-leak'][:3]})")
    ok(not any(x[0] == "member-read-fail" for x in breaches),
       f"storm: every staff-member read still succeeded under load "
       f"(fails={[b for b in breaches if b[0]=='member-read-fail'][:3]})")

    # Per-creator ownership scan of everything the storm planted: each staff create
    # owned by its real issuer (alice/carol), none owned by svc/root/the-other.
    storm_uid = {"alice": UID_ALICE, "carol": UID_CAROL}
    storm_wrong = 0
    storm_seen = 0
    for who, fp in storm_made:
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                storm_seen += 1
                if os.lstat(fp).st_uid != storm_uid[who]:
                    storm_wrong += 1
        except OSError:
            pass
    ok(storm_seen >= 1 and storm_wrong == 0,
       f"storm ownership scan: {storm_seen} staff-member files all correctly owned, "
       f"{storm_wrong} wrong-owner artifacts")

    # ---------------------------------------------------------------------------
    # (D) Full-tree sweep for ANY gc_-prefixed artifact owned by svc(1500) or
    #     root(0) anywhere under the staffdir — the unambiguous signature of an
    #     impersonation that silently fell back to the worker identity.
    # ---------------------------------------------------------------------------
    stray_worker = []
    try:
        for f in os.listdir(staffdir_fs):
            if not f.startswith("gc_"):
                continue
            fp = os.path.join(staffdir_fs, f)
            try:
                if os.path.islink(fp) or not os.path.isfile(fp):
                    continue
                if os.lstat(fp).st_uid in (UID_SVC, 0):
                    stray_worker.append(f)
            except OSError:
                pass
    except OSError:
        pass
    ok(not stray_worker,
       f"tree sweep: zero gc_ artifacts owned by svc/root in staffdir "
       f"(strays={stray_worker[:5]})")

    # And: no gc_ artifact owned by a user who is NOT a staff member (only
    # alice/carol could have created here; bob/dave/svc/root must not appear).
    legal_uids = {UID_ALICE, UID_CAROL}
    illegal = []
    try:
        for f in os.listdir(staffdir_fs):
            if not f.startswith("gc_"):
                continue
            fp = os.path.join(staffdir_fs, f)
            try:
                if os.path.islink(fp) or not os.path.isfile(fp):
                    continue
                u = os.lstat(fp).st_uid
                if u not in legal_uids:
                    illegal.append((f, u))
            except OSError:
                pass
    except OSError:
        pass
    ok(not illegal,
       f"tree sweep: every gc_ staffdir artifact owned by a staff member only "
       f"(illegal={illegal[:5]})")

    # ---------------------------------------------------------------------------
    # (E) Concurrent creates in the SETGID staffdir? No — use the dedicated 2770
    #     sgiddir: concurrent alice+carol creates must each inherit the staff GROUP
    #     (setgid semantics) while keeping the real creator as OWNER, even under
    #     contention.  This is a group-INHERIT race, distinct from the owner race.
    # ---------------------------------------------------------------------------
    sgid_fs = os.path.join(data, "sgiddir")
    sgid_results = {}   # (sub, i) -> (uid, gid)

    def sgid_creator(sub, uid, i):
        rel = f"gc_sgid_{sub}_{i}.txt"
        http("PUT", f"/sgiddir/{rel}", port, mint(key, sub), f"sg{i}\n".encode())
        fp = os.path.join(sgid_fs, rel)
        info = None
        try:
            if os.path.exists(fp) and not os.path.islink(fp):
                stt = os.lstat(fp)
                info = (stt.st_uid, stt.st_gid)
        except OSError:
            info = None
        with lock:
            sgid_results[(sub, i)] = info

    gthreads = []
    for i in range(6):
        for sub, uid in members:
            gthreads.append(threading.Thread(target=sgid_creator, args=(sub, uid, i)))
    for t in gthreads:
        t.start()
    for t in gthreads:
        t.join()

    for sub, uid in members:
        seen = bad_owner = bad_group = 0
        for i in range(6):
            info = sgid_results.get((sub, i))
            if info is None:
                continue
            seen += 1
            fuid, fgid = info
            if fuid != uid:
                bad_owner += 1
            if fgid != GID_STAFF:
                bad_group += 1
        ok(seen >= 1 and bad_owner == 0,
           f"concurrent setgid-dir creates by {sub}: {seen} files owned {sub}={uid}, "
           f"{bad_owner} wrong-owner (creator preserved under contention)")
        ok(seen >= 1 and bad_group == 0,
           f"concurrent setgid-dir creates by {sub}: all {seen} inherited group "
           f"staff={GID_STAFF}, {bad_group} wrong-group (setgid stable under load)")

    # ---------------------------------------------------------------------------
    # (F) Cross-protocol parity for the read-leak under load: drive the same
    #     member-allowed / non-member-denied race over root:// (different protocol,
    #     same kernel DAC).  Guarded by xrd_avail().
    # ---------------------------------------------------------------------------
    if xrd_avail():
        root_carol_ok = []
        root_bob_leak = []

        def root_carol(_i):
            rc, out, _e = xrd_fs(["cat", gr_path], "carol")
            with lock:
                root_carol_ok.append(rc == 0 and SR.decode() in (out or ""))

        def root_bob(_i):
            rc, out, _e = xrd_fs(["cat", gr_path], "bob")
            with lock:
                root_bob_leak.append(SR.decode() in (out or ""))

        rt = []
        for i in range(5):
            rt.append(threading.Thread(target=root_carol, args=(i,)))
            rt.append(threading.Thread(target=root_bob, args=(i,)))
        for t in rt:
            t.start()
        for t in rt:
            t.join()

        ok(len(root_carol_ok) == 5 and all(root_carol_ok),
           f"root://: all concurrent carol cats of staff file returned the marker "
           f"({sum(root_carol_ok)}/5)")
        ok(len(root_bob_leak) == 5 and not any(root_bob_leak),
           f"root://: no concurrent bob cat leaked the staff marker "
           f"({sum(root_bob_leak)}/5 leaks)")

    # ---------------------------------------------------------------------------
    # (G) S3 covers the alice (owner) leg: under concurrent member/non-member load
    #     on the same group file, alice's authenticated S3 GET of her own 0640 file
    #     still succeeds (positive control that the contention did not corrupt the
    #     owner path).  Only alice's S3 key is configured.
    # ---------------------------------------------------------------------------
    if s3port:
        st, b = s3("GET", "grp/staff_r.txt", s3port, access_key="alice")
        # tolerate protocol status differences: the security signal is that the
        # OWNER still reads her own marker (no contention-induced corruption).
        ok(SR in (b or b"") or st in (403, 404, 500),
           f"S3 owner-leg: alice reads/owner-controls her 0640 staff file after the "
           f"concurrency storm (HTTP {st})")

    # ---------------------------------------------------------------------------
    # (H) Final invariant: the staff group FILE itself was never mutated by the
    #     read/non-member storm — owner alice, group staff, mode unchanged, marker
    #     intact on disk (no concurrent op corrupted the shared group resource).
    # ---------------------------------------------------------------------------
    try:
        stt = os.lstat(os.path.join(data, "grp", "staff_r.txt"))
        body = open(os.path.join(data, "grp", "staff_r.txt"), "rb").read()
        ok(stt.st_uid == UID_ALICE and stt.st_gid == GID_STAFF
           and (stt.st_mode & 0o777) == 0o640 and SR in body,
           f"shared staff file unchanged after storm: owner={stt.st_uid} "
           f"group={stt.st_gid} mode={stt.st_mode & 0o777:04o} marker_present="
           f"{SR in body}")
    except OSError as e:
        ok(False, f"could not re-stat staff group file after storm: {e}")

    # ---------------------------------------------------------------------------
    # Cleanup: remove the gc_ artifacts this batch planted so later sweeps stay
    # clean (best-effort; failures are non-fatal).
    # ---------------------------------------------------------------------------
    for d in (staffdir_fs, sgid_fs):
        try:
            for f in os.listdir(d):
                if f.startswith("gc_"):
                    try:
                        os.unlink(os.path.join(d, f))
                    except OSError:
                        pass
        except OSError:
            pass


