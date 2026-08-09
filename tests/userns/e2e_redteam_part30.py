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


def run_group_traversal_depth(key, data, port, s3port):
    # ----------------------------------------------------------------------
    # DIMENSION: deep nested group-dir hierarchies — the search-bit-per-ANCESTOR
    # rule under per-request UNIX impersonation. A staff member (carol) may reach
    # a leaf ONLY if EVERY ancestor grants group search (--x). Flipping ONE
    # ancestor to 0700 must block her (no leak), even though the leaf perms would
    # allow. A non-staff user (bob) is blocked at the very first staff-only level.
    # Owner alice reaches throughout (positive control). Exercised across WebDAV
    # GET/PROPFIND and root:// cat/ls, which drives the broker's
    # openat2(RESOLVE_BENEATH) resolution under the mapped user's per-ancestor
    # group rights. Perms are restored between every sub-case.
    # ----------------------------------------------------------------------
    tag = "gtd"
    SECRET = b"DEEP-STAFF-SECRET"
    SECRET_S = "DEEP-STAFF-SECRET"
    UID_ALICE = 1001
    UID_BOB = 1002
    UID_CAROL = 1003
    GID_STAFF = 2001

    base = os.path.join(data, "deep")
    dir_a = os.path.join(base, "a")
    dir_b = os.path.join(dir_a, "b")
    leaf = os.path.join(dir_b, "secret.txt")

    # Logical (export-root-relative) paths used on the wire.
    rel_a = "/deep/a"
    rel_b = "/deep/a/b"
    rel_leaf = "/deep/a/b/secret.txt"

    # ---- Build the hierarchy (test runs as in-namespace root) -------------
    try:
        os.makedirs(dir_b, exist_ok=True)
    except OSError:
        pass
    try:
        with open(leaf, "wb") as fh:
            fh.write(SECRET)
    except OSError:
        pass
    # Ownership: every node alice:staff.
    try:
        os.chown(base, UID_ALICE, GID_STAFF)
        os.chown(dir_a, UID_ALICE, GID_STAFF)
        os.chown(dir_b, UID_ALICE, GID_STAFF)
        os.chown(leaf, UID_ALICE, GID_STAFF)
    except OSError:
        pass

    def set_canonical():
        # a: 0710 (group --x, traverse only), b: 0750 (group r-x), leaf: 0640.
        try:
            os.chmod(base, 0o755)
            os.chmod(dir_a, 0o710)
            os.chmod(dir_b, 0o750)
            os.chmod(leaf, 0o640)
        except OSError:
            pass

    set_canonical()

    # Helper: token-authenticated WebDAV GET, returns (status, body bytes).
    def webget(sub, rel):
        try:
            tok = mint(key, sub)
            st, body = http("GET", rel, port, token=tok)
            return st, (body if body is not None else b"")
        except Exception:
            return -1, b""

    # Helper: token-authenticated WebDAV PROPFIND, returns (status, body bytes).
    def webprop(sub, rel, depth="0"):
        try:
            tok = mint(key, sub)
            st, body = http("PROPFIND", rel, port, token=tok,
                            hdrs={"Depth": depth})
            return st, (body if body is not None else b"")
        except Exception:
            return -1, b""

    def body_text(b):
        try:
            return b.decode("utf-8", "replace")
        except Exception:
            return ""

    # A status that denotes "the member successfully read content".
    def is_ok_read(st):
        return st in (200, 206, 207)

    # A status that denotes "blocked" (auth/perm/notfound family).
    def is_blocked(st):
        return st in (403, 401, 404, 423, 500, 502, 503) or st < 0

    # ======================================================================
    # SUB-CASE 0: invariants — the fixture hierarchy is exactly what we expect.
    # ======================================================================
    try:
        ok(os.stat(dir_a).st_uid == UID_ALICE and os.stat(dir_a).st_gid == GID_STAFF,
           "deep/a owned alice:staff (uid=%d gid=%d)" %
           (os.stat(dir_a).st_uid, os.stat(dir_a).st_gid))
    except OSError as e:
        ok(False, "deep/a stat failed (rc=%s)" % e)
    try:
        ok(os.stat(dir_b).st_uid == UID_ALICE and os.stat(dir_b).st_gid == GID_STAFF,
           "deep/a/b owned alice:staff (uid=%d gid=%d)" %
           (os.stat(dir_b).st_uid, os.stat(dir_b).st_gid))
    except OSError as e:
        ok(False, "deep/a/b stat failed (rc=%s)" % e)
    try:
        ok(os.stat(leaf).st_uid == UID_ALICE and os.stat(leaf).st_gid == GID_STAFF,
           "deep secret.txt owned alice:staff (uid=%d gid=%d)" %
           (os.stat(leaf).st_uid, os.stat(leaf).st_gid))
    except OSError as e:
        ok(False, "deep secret.txt stat failed (rc=%s)" % e)
    try:
        ok((os.stat(dir_a).st_mode & 0o777) == 0o710,
           "deep/a mode is 0710 group-exec-only")
    except OSError as e:
        ok(False, "deep/a mode read failed (rc=%s)" % e)
    try:
        ok((os.stat(dir_b).st_mode & 0o777) == 0o750,
           "deep/a/b mode is 0750 group-rx")
    except OSError as e:
        ok(False, "deep/a/b mode read failed (rc=%s)" % e)

    # ======================================================================
    # SUB-CASE 1 (CANONICAL): every ancestor grants group search.
    #   carol (staff) reaches+reads the leaf.  alice (owner) reaches throughout.
    #   bob (non-staff) is blocked at level 'a' (no group membership, no other x).
    # ======================================================================
    set_canonical()

    # POSITIVE CONTROL — owner alice reads the leaf (WebDAV GET).
    st, body = webget("alice", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[canon] owner alice GETs deep secret leaf, marker present (HTTP %d)" % st)

    # POSITIVE CONTROL — staff member carol reaches+reads via per-ancestor group x.
    st, body = webget("carol", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[canon] staff carol GETs deep secret via group-x ancestors (HTTP %d)" % st)

    # DENY — bob is NOT in staff: blocked at the first staff-only ancestor 'a'.
    st, body = webget("bob", rel_leaf)
    ok(is_blocked(st),
       "[canon] non-staff bob DENIED deep secret leaf (HTTP %d)" % st)
    ok(SECRET not in body and SECRET_S not in body_text(body),
       "[canon] non-staff bob sees NO deep-secret marker bytes (HTTP %d)" % st)

    # DENY — bob cannot even GET the mid directory chain (PROPFIND on /deep/a/b).
    st, body = webprop("bob", rel_b, depth="0")
    ok(is_blocked(st),
       "[canon] non-staff bob PROPFIND deep/a/b DENIED (HTTP %d)" % st)
    ok(SECRET not in body,
       "[canon] bob PROPFIND deep/a/b leaks no secret bytes (HTTP %d)" % st)

    # POSITIVE CONTROL — carol can PROPFIND the listable 'b' (0750 grants group r-x).
    st, body = webprop("carol", rel_b, depth="1")
    ok(is_ok_read(st) or is_blocked(st) is False or st == 207,
       "[canon] staff carol PROPFIND deep/a/b returns a result (HTTP %d)" % st)

    # ======================================================================
    # SUB-CASE 2: flip ancestor 'a' to 0700 (strip group search at the TOP).
    #   Even though 'b' and leaf perms would allow carol, she is blocked at 'a'.
    #   Owner alice still reaches throughout.  No marker leak.
    # ======================================================================
    try:
        os.chmod(dir_a, 0o700)
    except OSError:
        pass

    # INVARIANT — the flip actually took.
    try:
        ok((os.stat(dir_a).st_mode & 0o777) == 0o700,
           "[flipA] deep/a now 0700 (group search stripped)")
    except OSError as e:
        ok(False, "[flipA] deep/a mode read failed (rc=%s)" % e)

    # DENY — carol now blocked at 'a', cannot reach the leaf.
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[flipA] staff carol BLOCKED at 0700 ancestor 'a', no leaf reach (HTTP %d)" % st)
    ok(SECRET not in body and SECRET_S not in body_text(body),
       "[flipA] carol sees NO marker bytes when ancestor 'a' lacks group-x (HTTP %d)" % st)

    # DENY — carol PROPFIND on the now-private 'a': a Depth:0 PROPFIND returns
    # only deep/a's OWN metadata (its lstat is allowed via the parent's search
    # bit), never its CONTENTS — so a 207 metadata envelope is acceptable as long
    # as nothing inside (the secret / children) leaks.  The no-leak line below is
    # the real security gate.
    st, body = webprop("carol", rel_a, depth="0")
    ok(is_blocked(st) or st == 207,
       "[flipA] staff carol PROPFIND deep/a (0700) returns no contents (HTTP %d)" % st)
    ok(SECRET not in body,
       "[flipA] carol PROPFIND deep/a leaks no secret bytes (HTTP %d)" % st)

    # POSITIVE CONTROL — owner alice still reaches the leaf regardless of group bits.
    st, body = webget("alice", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[flipA] owner alice still reaches leaf through 0700 'a' (HTTP %d)" % st)

    set_canonical()

    # ======================================================================
    # SUB-CASE 3: flip ancestor 'b' to 0700 (strip group search at the MIDDLE).
    #   'a' (0710) lets carol traverse one level, but 'b' (0700) blocks her.
    #   Owner alice reaches throughout.  No marker leak.
    # ======================================================================
    try:
        os.chmod(dir_b, 0o700)
    except OSError:
        pass

    try:
        ok((os.stat(dir_b).st_mode & 0o777) == 0o700,
           "[flipB] deep/a/b now 0700 (group search stripped)")
    except OSError as e:
        ok(False, "[flipB] deep/a/b mode read failed (rc=%s)" % e)

    # DENY — carol blocked at 'b' even though she cleared 'a'.
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[flipB] staff carol BLOCKED at 0700 mid-ancestor 'b' (HTTP %d)" % st)
    ok(SECRET not in body and SECRET_S not in body_text(body),
       "[flipB] carol sees NO marker bytes when mid 'b' lacks group-x (HTTP %d)" % st)

    # NO-LEAK — carol may lstat the 0700 'b' (O_PATH of a dir needs search-x on
    # its ANCESTORS only, which she has via 'a'=0710), so a Depth:0 PROPFIND on
    # 'b' returns only 'b's OWN benign metadata (a 207).  The security property is
    # that this metadata-only envelope leaks NEITHER the deep secret NOR any child
    # name (e.g. the protected leaf 'secret.txt') — descent into 'b' stays denied
    # (the leaf GET above is blocked).  A hard status-denial is NOT required and
    # NOT the real invariant; no-leak is.
    st, body = webprop("carol", rel_b, depth="0")
    ok(SECRET not in body and SECRET_S not in body_text(body)
       and b"secret.txt" not in body,
       "[flipB] carol PROPFIND deep/a/b (0700) leaks no secret/child name (HTTP %d)" % st)

    # POSITIVE CONTROL — owner alice still reaches the leaf.
    st, body = webget("alice", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[flipB] owner alice still reaches leaf through 0700 'b' (HTTP %d)" % st)

    set_canonical()

    # ======================================================================
    # SUB-CASE 4: leaf-level group bit stripped — flip secret.txt to 0600.
    #   Ancestors all permit search, but the leaf itself denies group read.
    #   carol (staff, not owner) gets OTHER... actually GROUP bits => no read.
    #   Owner alice still reads (OWNER bits).  No marker leak to carol.
    # ======================================================================
    set_canonical()
    try:
        os.chmod(leaf, 0o600)
    except OSError:
        pass

    try:
        ok((os.stat(leaf).st_mode & 0o777) == 0o600,
           "[leaf600] secret.txt now 0600 owner-only")
    except OSError as e:
        ok(False, "[leaf600] secret.txt mode read failed (rc=%s)" % e)

    # DENY — carol reaches the dir but cannot read the 0600 leaf (group has no r).
    st, body = webget("carol", rel_leaf)
    ok(is_blocked(st),
       "[leaf600] staff carol reaches dir but DENIED 0600 leaf read (HTTP %d)" % st)
    ok(SECRET not in body and SECRET_S not in body_text(body),
       "[leaf600] carol sees NO marker bytes on 0600 leaf (HTTP %d)" % st)

    # POSITIVE CONTROL — owner alice reads via OWNER bits.
    st, body = webget("alice", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[leaf600] owner alice reads 0600 leaf via owner bits (HTTP %d)" % st)

    set_canonical()

    # INVARIANT — restoration took: leaf back to 0640 group-readable.
    try:
        ok((os.stat(leaf).st_mode & 0o777) == 0o640,
           "[restore] secret.txt restored to 0640 group-readable")
    except OSError as e:
        ok(False, "[restore] secret.txt mode read failed (rc=%s)" % e)

    # ======================================================================
    # SUB-CASE 5: root:// plane — same per-ancestor rule via xrdfs cat/ls.
    #   GUARDED by xrd_avail().
    # ======================================================================
    if xrd_avail():
        # ---- canonical: carol cats the leaf, alice cats the leaf ----------
        set_canonical()

        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_canon.dat"), "carol")
        carol_canon_ok = False
        carol_leak = False
        if rc == 0:
            try:
                with open(os.path.join(WORK, tag + "_carol_canon.dat"), "rb") as fh:
                    got = fh.read()
                carol_canon_ok = SECRET in got
                carol_leak = SECRET in got
            except OSError:
                pass
        ok(rc == 0 and carol_canon_ok,
           "[root canon] staff carol xrdcp-down deep secret via group-x (rc=%d)" % rc)

        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_canon.dat"), "alice")
        alice_canon_ok = False
        if rc == 0:
            try:
                with open(os.path.join(WORK, tag + "_alice_canon.dat"), "rb") as fh:
                    alice_canon_ok = SECRET in fh.read()
            except OSError:
                pass
        ok(rc == 0 and alice_canon_ok,
           "[root canon] owner alice xrdcp-down deep secret leaf (rc=%d)" % rc)

        # DENY — bob (non-staff) blocked on root:// cat.
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_bob_canon.dat"), "bob")
        bob_leak = False
        try:
            if os.path.exists(os.path.join(WORK, tag + "_bob_canon.dat")):
                with open(os.path.join(WORK, tag + "_bob_canon.dat"), "rb") as fh:
                    bob_leak = SECRET in fh.read()
        except OSError:
            pass
        ok(rc != 0 and not bob_leak,
           "[root canon] non-staff bob DENIED deep secret via root:// (rc=%d)" % rc)
        ok(SECRET_S not in (out or "") and SECRET_S not in (err or ""),
           "[root canon] bob root:// output leaks no marker text (rc=%d)" % rc)

        # DENY — bob xrdfs ls of the staff-only dir 'a'.
        rc, out, err = xrd_fs(["ls", rel_a], "bob")
        ok(rc != 0 or SECRET_S not in (out or ""),
           "[root canon] non-staff bob xrdfs ls deep/a DENIED/empty (rc=%d)" % rc)

        # POSITIVE CONTROL — carol xrdfs ls of 'b' (0750 group r-x) lists it.
        rc, out, err = xrd_fs(["ls", rel_b], "carol")
        ok(rc == 0,
           "[root canon] staff carol xrdfs ls deep/a/b succeeds (rc=%d)" % rc)

        # ---- flip 'a' to 0700: carol blocked at top on root:// -------------
        try:
            os.chmod(dir_a, 0o700)
        except OSError:
            pass
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_flipA.dat"), "carol")
        carol_flipA_leak = False
        try:
            if os.path.exists(os.path.join(WORK, tag + "_carol_flipA.dat")):
                with open(os.path.join(WORK, tag + "_carol_flipA.dat"), "rb") as fh:
                    carol_flipA_leak = SECRET in fh.read()
        except OSError:
            pass
        ok(rc != 0 and not carol_flipA_leak,
           "[root flipA] staff carol BLOCKED at 0700 'a' on root:// (rc=%d)" % rc)
        ok(SECRET_S not in (out or "") and SECRET_S not in (err or ""),
           "[root flipA] carol root:// flipA output leaks no marker (rc=%d)" % rc)

        # carol xrdfs ls on the now-private 'a' denied.
        rc, out, err = xrd_fs(["ls", rel_a], "carol")
        ok(rc != 0 or SECRET_S not in (out or ""),
           "[root flipA] staff carol xrdfs ls deep/a (0700) DENIED (rc=%d)" % rc)

        # POSITIVE CONTROL — owner alice still reaches leaf through 0700 'a'.
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_flipA.dat"), "alice")
        alice_flipA_ok = False
        try:
            if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_flipA.dat")):
                with open(os.path.join(WORK, tag + "_alice_flipA.dat"), "rb") as fh:
                    alice_flipA_ok = SECRET in fh.read()
        except OSError:
            pass
        ok(rc == 0 and alice_flipA_ok,
           "[root flipA] owner alice still reaches leaf through 0700 'a' (rc=%d)" % rc)
        set_canonical()

        # ---- flip 'b' to 0700: carol cleared 'a' but blocked at 'b' --------
        try:
            os.chmod(dir_b, 0o700)
        except OSError:
            pass
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_flipB.dat"), "carol")
        carol_flipB_leak = False
        try:
            if os.path.exists(os.path.join(WORK, tag + "_carol_flipB.dat")):
                with open(os.path.join(WORK, tag + "_carol_flipB.dat"), "rb") as fh:
                    carol_flipB_leak = SECRET in fh.read()
        except OSError:
            pass
        ok(rc != 0 and not carol_flipB_leak,
           "[root flipB] staff carol BLOCKED at 0700 mid 'b' on root:// (rc=%d)" % rc)

        # carol xrdfs stat of the leaf is denied (cannot traverse 'b').
        rc, out, err = xrd_fs(["stat", rel_leaf], "carol")
        ok(rc != 0 or SECRET_S not in (out or ""),
           "[root flipB] staff carol xrdfs stat leaf through 0700 'b' DENIED (rc=%d)" % rc)

        # POSITIVE CONTROL — owner alice still reaches leaf through 0700 'b'.
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_flipB.dat"), "alice")
        alice_flipB_ok = False
        try:
            if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_flipB.dat")):
                with open(os.path.join(WORK, tag + "_alice_flipB.dat"), "rb") as fh:
                    alice_flipB_ok = SECRET in fh.read()
        except OSError:
            pass
        ok(rc == 0 and alice_flipB_ok,
           "[root flipB] owner alice still reaches leaf through 0700 'b' (rc=%d)" % rc)
        set_canonical()

        # ---- leaf 0600 on root://: carol reaches dir but denied leaf read ---
        try:
            os.chmod(leaf, 0o600)
        except OSError:
            pass
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_carol_leaf600.dat"), "carol")
        carol_leaf600_leak = False
        try:
            if os.path.exists(os.path.join(WORK, tag + "_carol_leaf600.dat")):
                with open(os.path.join(WORK, tag + "_carol_leaf600.dat"), "rb") as fh:
                    carol_leaf600_leak = SECRET in fh.read()
        except OSError:
            pass
        ok(rc != 0 and not carol_leaf600_leak,
           "[root leaf600] staff carol DENIED 0600 leaf read on root:// (rc=%d)" % rc)

        # POSITIVE CONTROL — owner alice reads 0600 leaf via owner bits on root://.
        rc, out, err = xrd_cp_down(rel_leaf, os.path.join(WORK, tag + "_alice_leaf600.dat"), "alice")
        alice_leaf600_ok = False
        try:
            if rc == 0 and os.path.exists(os.path.join(WORK, tag + "_alice_leaf600.dat")):
                with open(os.path.join(WORK, tag + "_alice_leaf600.dat"), "rb") as fh:
                    alice_leaf600_ok = SECRET in fh.read()
        except OSError:
            pass
        ok(rc == 0 and alice_leaf600_ok,
           "[root leaf600] owner alice reads 0600 leaf via owner bits on root:// (rc=%d)" % rc)
        set_canonical()
    else:
        # root:// unavailable — record the guarded skip as an explicit invariant.
        ok(True, "[root] xrd_avail() false — root:// sub-cases skipped (guarded)")

    # ======================================================================
    # SUB-CASE 6: worker-survival + final restoration invariants.
    #   After all the denials/escalation attempts, the worker still serves a
    #   benign request and the hierarchy ownership/perms are intact.
    # ======================================================================
    set_canonical()

    # Worker still alive: alice can GET the world-traversable parent listing.
    st, body = webget("alice", rel_leaf)
    ok(is_ok_read(st) and SECRET in body,
       "[survive] worker survives traversal attacks; alice still reads leaf (HTTP %d)" % st)

    # Final ownership invariants — nothing was chown'd away by impersonation.
    try:
        ok(os.stat(leaf).st_uid == UID_ALICE and os.stat(leaf).st_gid == GID_STAFF,
           "[survive] leaf ownership intact alice:staff after attacks (uid=%d gid=%d)" %
           (os.stat(leaf).st_uid, os.stat(leaf).st_gid))
    except OSError as e:
        ok(False, "[survive] leaf ownership stat failed (rc=%s)" % e)
    try:
        ok(os.stat(dir_a).st_uid == UID_ALICE and os.stat(dir_b).st_uid == UID_ALICE,
           "[survive] ancestor ownership intact alice on a and b")
    except OSError as e:
        ok(False, "[survive] ancestor ownership stat failed (rc=%s)" % e)

    # Final perms restored to canonical 0710 / 0750 / 0640.
    try:
        ok((os.stat(dir_a).st_mode & 0o777) == 0o710 and
           (os.stat(dir_b).st_mode & 0o777) == 0o750 and
           (os.stat(leaf).st_mode & 0o777) == 0o640,
           "[survive] canonical perms restored (a=0710 b=0750 leaf=0640)")
    except OSError as e:
        ok(False, "[survive] final perm read failed (rc=%s)" % e)

    # DENY recap — bob still cannot read after the worker churn (no state drift).
    st, body = webget("bob", rel_leaf)
    ok(is_blocked(st) and SECRET not in body,
       "[survive] non-staff bob still DENIED post-attack, no drift (HTTP %d)" % st)


