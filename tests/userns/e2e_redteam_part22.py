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


def run_sticky_bit_dac(key, data, port, s3port):
    """STICKY-BIT (1777) world-writable directory DAC under impersonation, modelled
    on /tmp.  stickytmp/ is 1777 svc:svc — every tenant may CREATE a file in it
    (owned by the *creator*, never the worker/root), but the sticky bit means a
    DIFFERENT non-owner user may NOT unlink or rename another user's file even
    though the directory itself is world-writable; only the FILE's owner (or the
    dir owner, who here is the unprivileged worker svc, NOT a tenant) may
    delete/rename it.  This exercises the broker's setfsuid/setfsgid against the
    kernel's VFS sticky-protection (inode_permission + check_sticky), a dimension
    the owner/group read+write DAC suites never touch.  Each leg is run across
    WebDAV DELETE/MOVE and the native root:// rm/mv so it is proven protocol-wide,
    and every create is checked to be owned by the real principal."""
    SD = "/stickytmp"
    sdir = os.path.join(data, "stickytmp")
    AOWN = os.path.join(sdir, "alice_owned.txt")        # 0644 owned alice (fixture)
    AMARK = b"alice-sticky"

    # ----------------------------------------------------------------- invariants
    # (0) the directory itself must really be sticky + world-writable, else the
    #     whole test is meaningless (a blanket-deny gateway would otherwise pass).
    try:
        dm = os.stat(sdir).st_mode
    except OSError:
        dm = 0
    ok(bool(dm & 0o1000) and (dm & 0o777) == 0o777 and (dm & 0o2),
       f"stickytmp is sticky + world-writable (mode {dm & 0o7777:04o})")
    ok(os.stat(sdir).st_uid == UID_SVC,
       f"stickytmp owned by the worker svc (uid {os.stat(sdir).st_uid}), not a tenant")
    # (0b) the pre-seeded alice_owned.txt is genuinely alice's (the victim file).
    ok(os.path.exists(AOWN) and os.stat(AOWN).st_uid == UID_ALICE,
       "fixture alice_owned.txt is owned by alice (the sticky-protected victim)")

    # ----------------------------------------------- CREATE leg (world-writable)
    # Anyone may create in a 1777 dir; each new file is owned by its real creator,
    # never the worker (svc/1500) or root (0).  Cover several distinct tenants.
    for sub, uid in (("alice", UID_ALICE), ("bob", UID_BOB),
                     ("carol", UID_CAROL), ("dave", UID_DAVE)):
        fn = f"{SD}/sb_{sub}.txt"
        fp = os.path.join(sdir, f"sb_{sub}.txt")
        st, _ = http("PUT", fn, port, mint(key, sub), f"{sub}-made-here\n".encode())
        created = os.path.exists(fp)
        owned = created and os.stat(fp).st_uid == uid
        ok(st in (200, 201, 204) and created and owned,
           f"{sub} CREATEs in 1777 sticky dir, owned by {sub} not svc/root (HTTP {st})")

    # bob's file is the canonical victim for the cross-user delete/move legs below.
    bob_fp = os.path.join(sdir, "sb_bob.txt")
    BOBMARK = b"bob-made-here"

    # ============================================================ WebDAV DELETE
    # (1) carol (a DIFFERENT non-owner) tries to DELETE bob's file -> sticky DENY;
    #     the file must SURVIVE unchanged and still owned by bob (no leak/clobber).
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "carol"))
    survived = os.path.exists(bob_fp) and os.stat(bob_fp).st_uid == UID_BOB
    still_body = (open(bob_fp, "rb").read() if os.path.exists(bob_fp) else b"")
    ok(st not in (200, 204) and survived and BOBMARK in still_body,
       f"sticky: carol DENIED DELETE of bob's file, it survives owned by bob (HTTP {st})")
    # (1b) dave (yet another non-owner) likewise DENIED -> not a carol-specific fluke.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "dave"))
    ok(st not in (200, 204) and os.path.exists(bob_fp)
       and os.stat(bob_fp).st_uid == UID_BOB,
       f"sticky: dave DENIED DELETE of bob's file (HTTP {st})")
    # (1c) alice (non-owner, but a *staff* peer) ALSO cannot delete bob's file —
    #      sticky protection is per-FILE-owner, group membership is irrelevant.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "alice"))
    ok(st not in (200, 204) and os.path.exists(bob_fp),
       f"sticky: alice (non-owner) DENIED DELETE of bob's file (HTTP {st})")
    # (1-POS) POSITIVE CONTROL: bob (the OWNER) DELETEs his own file -> allowed.
    st, _ = http("DELETE", f"{SD}/sb_bob.txt", port, mint(key, "bob"))
    ok(st in (200, 204) and not os.path.exists(bob_fp),
       f"sticky POSITIVE: bob deletes his OWN file in the sticky dir (HTTP {st})")

    # ============================================================== WebDAV MOVE
    # (2) carol tries to MOVE (rename) alice's pre-seeded file out of the sticky
    #     dir -> sticky DENY (rename of a non-owned file is blocked); the source
    #     must remain in place, owned by alice, and NO copy may appear at the dest.
    dest_carol = os.path.join(data, "carol", "stolen_alice.txt")
    try:
        chown_dir(os.path.join(data, "carol"), UID_CAROL, UID_CAROL, 0o755)
    except OSError:
        pass
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "carol"),
                 hdrs={"Destination": f"http://{HOST}:{port}/carol/stolen_alice.txt"})
    src_ok = os.path.exists(AOWN) and os.stat(AOWN).st_uid == UID_ALICE
    ok(st not in (200, 201, 204) and src_ok and not os.path.exists(dest_carol),
       f"sticky: carol DENIED MOVE of alice's file, source intact, no dest (HTTP {st})")
    # (2b) dave likewise cannot rename alice's file even WITHIN the sticky dir.
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "dave"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/dave_grab.txt"})
    ok(st not in (200, 201, 204) and os.path.exists(AOWN)
       and not os.path.exists(os.path.join(sdir, "dave_grab.txt")),
       f"sticky: dave DENIED MOVE/rename of alice's file inside the dir (HTTP {st})")
    # (2c) the secret bytes of alice's file must NOT have leaked to any dest (a MOVE
    #      that secretly copied-then-failed would expose them).  Re-seed marker then
    #      re-assert no stray copy carries it.
    try:
        with open(AOWN, "wb") as fh:
            fh.write(AMARK + b"\n")
        os.chown(AOWN, UID_ALICE, UID_ALICE)
        os.chmod(AOWN, 0o644)
    except OSError:
        pass
    leaked = (os.path.exists(dest_carol) and AMARK in open(dest_carol, "rb").read())
    ok(not leaked, "sticky: alice's marker bytes did not leak to a denied MOVE dest")
    # (2-POS) POSITIVE CONTROL: alice (the OWNER) MOVEs her own file within the dir.
    moved = os.path.join(sdir, "alice_moved.txt")
    st, _ = http("MOVE", f"{SD}/alice_owned.txt", port, mint(key, "alice"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/alice_moved.txt"})
    ok(st in (200, 201, 204) and os.path.exists(moved)
       and os.stat(moved).st_uid == UID_ALICE,
       f"sticky POSITIVE: alice renames her OWN file in the sticky dir (HTTP {st})")
    # restore the canonical victim file name + ownership for the root:// leg below.
    try:
        if os.path.exists(moved) and not os.path.exists(AOWN):
            os.rename(moved, AOWN)
        os.chown(AOWN, UID_ALICE, UID_ALICE)
        os.chmod(AOWN, 0o644)
    except OSError:
        pass

    # ===================================================== cross-user CLOBBER
    # (3) sticky does NOT block creating a NEW name, but it MUST block overwriting
    #     (via rename-onto) another user's file.  carol re-creates her own file,
    #     then a non-owner (bob) trying to MOVE-rename ONTO carol's file is denied;
    #     carol's file keeps her ownership + body (no clobber, no owner takeover).
    carol_fp = os.path.join(sdir, "sb_carol_v.txt")
    st, _ = http("PUT", f"{SD}/sb_carol_v.txt", port, mint(key, "carol"),
                 b"carol-victim\n")
    ok(os.path.exists(carol_fp) and os.stat(carol_fp).st_uid == UID_CAROL,
       f"setup: carol re-creates her sticky victim file owned by carol (HTTP {st})")
    st, _ = http("PUT", f"{SD}/sb_bob_v.txt", port, mint(key, "bob"), b"bob-src\n")
    st, _ = http("MOVE", f"{SD}/sb_bob_v.txt", port, mint(key, "bob"),
                 hdrs={"Destination": f"http://{HOST}:{port}{SD}/sb_carol_v.txt"})
    not_clobbered = (os.path.exists(carol_fp)
                     and os.stat(carol_fp).st_uid == UID_CAROL
                     and b"carol-victim" in open(carol_fp, "rb").read())
    ok(st not in (200, 201, 204) and not_clobbered,
       f"sticky: bob DENIED rename-clobber onto carol's file (HTTP {st})")

    # ============================================================== root:// leg
    # The SAME sticky semantics through the native stream client (different
    # protocol, same kernel VFS state) — proves it is not WebDAV bookkeeping.
    if xrd_avail():
        # erin creates her own file in the sticky dir, owned by erin.
        lf = os.path.join(WORK, "sb_erin_src.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"erin-root-made\n")
        except OSError:
            pass
        rc, _o, _e = xrd_cp_up(lf, f"{SD}/sb_erin.bin", "erin")
        erin_fp = os.path.join(sdir, "sb_erin.bin")
        ok(rc == 0 and os.path.exists(erin_fp)
           and os.stat(erin_fp).st_uid == UID_ERIN,
           f"root:// sticky: erin creates her file owned by erin (rc={rc})")
        # (4) frank (non-owner) tries to rm erin's file -> sticky DENY, survives.
        rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "frank")
        ok(rc != 0 and os.path.exists(erin_fp)
           and os.stat(erin_fp).st_uid == UID_ERIN,
           f"root:// sticky: frank DENIED rm of erin's file, it survives (rc={rc})")
        # (4b) frank tries to mv erin's file out -> sticky DENY, source intact, no dest.
        rc, _o, _e = xrd_fs(["mv", f"{SD}/sb_erin.bin", "/pub/frank_grab.bin"], "frank")
        ok(rc != 0 and os.path.exists(erin_fp)
           and not os.path.exists(os.path.join(data, "pub", "frank_grab.bin")),
           f"root:// sticky: frank DENIED mv of erin's file (rc={rc})")
        # (4c) carol (different non-owner) also DENIED rm of erin's file.
        rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "carol")
        ok(rc != 0 and os.path.exists(erin_fp),
           f"root:// sticky: carol DENIED rm of erin's file (rc={rc})")
        # (4-POS) POSITIVE CONTROL: erin (owner) rm's her own file -> allowed.
        rc, _o, _e = xrd_fs(["rm", f"{SD}/sb_erin.bin"], "erin")
        ok(rc == 0 and not os.path.exists(erin_fp),
           f"root:// sticky POSITIVE: erin rm's her OWN file (rc={rc})")

        # (5) cross-user rm/mv of the pre-seeded alice_owned.txt via root://.
        rc, _o, _e = xrd_fs(["rm", f"{SD}/alice_owned.txt"], "bob")
        ok(rc != 0 and os.path.exists(AOWN) and os.stat(AOWN).st_uid == UID_ALICE,
           f"root:// sticky: bob DENIED rm of alice's file (rc={rc})")
        rc, _o, _e = xrd_fs(["mv", f"{SD}/alice_owned.txt",
                             "/alice/sb_root_moved.txt"], "bob")
        ok(rc != 0 and os.path.exists(AOWN)
           and not os.path.exists(os.path.join(data, "alice", "sb_root_moved.txt")),
           f"root:// sticky: bob DENIED mv of alice's file (rc={rc})")
        # (5-POS) POSITIVE CONTROL: alice (owner) mv's her own file within the dir.
        rc, _o, _e = xrd_fs(["mv", f"{SD}/alice_owned.txt",
                             f"{SD}/alice_root_moved.txt"], "alice")
        ramoved = os.path.join(sdir, "alice_root_moved.txt")
        ok(rc == 0 and os.path.exists(ramoved)
           and os.stat(ramoved).st_uid == UID_ALICE,
           f"root:// sticky POSITIVE: alice mv's her OWN file (rc={rc})")
        # restore canonical fixture for any later batches.
        try:
            if os.path.exists(ramoved) and not os.path.exists(AOWN):
                os.rename(ramoved, AOWN)
            with open(AOWN, "wb") as fh:
                fh.write(AMARK + b"\n")
            os.chown(AOWN, UID_ALICE, UID_ALICE)
            os.chmod(AOWN, 0o644)
        except OSError:
            pass
    else:
        ok(True, "root:// sticky leg SKIPPED (native xrdfs/xrdcp not built)")

    # ===================================================== S3 (alice leg only)
    # Only alice's S3 key is configured.  alice may DELETE her OWN object in the
    # sticky dir (owner), but a cross-user clobber via S3 is impossible to express
    # as a non-alice principal, so S3 covers the OWNER-success leg.  First plant a
    # bob-owned file directly (fixture) and confirm alice's S3 DELETE of it FAILS
    # closed (alice is not bob, sticky + DAC both bite), then alice deletes her own.
    if s3port:
        bobx = os.path.join(sdir, "sb_s3_bobvictim.txt")
        try:
            with open(bobx, "wb") as fh:
                fh.write(b"s3-bob-victim\n")
            os.chown(bobx, UID_BOB, UID_BOB)
            os.chmod(bobx, 0o644)
        except OSError:
            pass
        st, _ = s3("DELETE", "stickytmp/sb_s3_bobvictim.txt", s3port)
        ok(st not in (200, 204) and os.path.exists(bobx)
           and os.stat(bobx).st_uid == UID_BOB,
           f"S3 sticky: alice DENIED DELETE of bob's file, survives owned by bob (HTTP {st})")
        # POSITIVE CONTROL: alice creates then DELETEs her OWN object -> allowed.
        st, _ = s3("PUT", "stickytmp/sb_s3_alice.txt", s3port, data=b"s3-alice\n")
        ax = os.path.join(sdir, "sb_s3_alice.txt")
        ok(st in (200, 201) and os.path.exists(ax)
           and os.stat(ax).st_uid == UID_ALICE,
           f"S3 sticky POSITIVE: alice creates her own object owned by alice (HTTP {st})")
        st, _ = s3("DELETE", "stickytmp/sb_s3_alice.txt", s3port)
        ok(st in (200, 204) and not os.path.exists(ax),
           f"S3 sticky POSITIVE: alice deletes her OWN object (HTTP {st})")
    else:
        ok(True, "S3 sticky leg SKIPPED (no s3 port)")

    # ===================================================== final no-clobber sweep
    # After all the denied cross-user ops, NO file this batch created may have
    # flipped to the worker (svc/1500) or root (0): a wrong-uid file is a leak.
    bad_owner = []
    try:
        for f in os.listdir(sdir):
            p = os.path.join(sdir, f)
            if not f.startswith(("sb_", "alice")) or os.path.islink(p) \
                    or not os.path.isfile(p):
                continue
            u = os.lstat(p).st_uid
            if u in (UID_SVC, 0):
                bad_owner.append((f, u))
    except OSError:
        pass
    ok(not bad_owner,
       f"sticky: no tenant file flipped to worker/root ownership (offenders={bad_owner[:3]})")
    # and the directory itself never lost its sticky bit during the storm.
    try:
        dm2 = os.stat(sdir).st_mode
    except OSError:
        dm2 = 0
    ok(bool(dm2 & 0o1000) and os.stat(sdir).st_uid == UID_SVC,
       f"sticky: stickytmp retains its sticky bit + svc ownership post-test "
       f"(mode {dm2 & 0o7777:04o})")
    # worker survived the whole battery (a fresh request still serves).
    st, _ = http("GET", "/grp/world_r.txt", port, mint(key, "alice"))
    ok(st == 200, f"worker survived the sticky-bit battery (HTTP {st})")


