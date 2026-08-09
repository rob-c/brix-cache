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


def run_root_protocol_depth(key, data, port, s3port):
    """root:// STREAM protocol DEPTH under impersonation — combinatorial xrdfs/xrdcp
    matrix that goes deeper than run_root_battery / run_root_deep.  Exhaustively
    drives open modes (new / update / truncate-shrink / re-write / read-only) and
    their resulting ownership, query checksum/config/space/xattr (self vs bob 0600,
    no body leak), locate, stat self vs cross-tenant, nested mkdir + per-level
    ownership, rmdir non-empty-vs-empty (self + bob), mv within-tenant /
    cross-tenant-source / into-svconly, chmod own (mode actually changes) vs bob
    (denied, mode intact), truncate own vs bob, pub/ (0777 shared) write owned by
    the WRITER, read-then-delete, query xattr of user.* on own file, and a burst of
    sequential small files all owned by the mapping user.  Every mutating op has a
    self-success POSITIVE CONTROL beside its cross-tenant/escalation DENY so a
    blanket block cannot false-pass.  GUARDED by xrd_avail()."""
    if not xrd_avail():
        ok(True, "root:// protocol-depth skipped (native xrdfs/xrdcp absent)")
        return

    A, B = "alice", "bob"
    MARK_BOB = b"BOB-PRIVATE-SECRET"          # planted in data/bob/private.txt (0600)
    MARK_SVC = b"svc-only-secret"             # planted in data/svconly/secret-name.txt

    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))

    def uid_of(rel):
        fp = realp(rel)
        try:
            return os.stat(fp).st_uid if os.path.exists(fp) else -1
        except OSError:
            return -1

    def mode_of(rel):
        fp = realp(rel)
        try:
            return (os.stat(fp).st_mode & 0o777) if os.path.exists(fp) else -1
        except OSError:
            return -1

    def size_of(rel):
        fp = realp(rel)
        try:
            return os.path.getsize(fp) if os.path.exists(fp) else -1
        except OSError:
            return -1

    def local(name, content=b""):
        lp = os.path.join(WORK, "rpd_" + name)
        try:
            with open(lp, "wb") as fh:
                fh.write(content)
        except OSError:
            pass
        return lp

    # ---- seed local payloads of distinct sizes (open-mode matrix) ---------------
    BIG = b"RPD-OPEN-MODE-PAYLOAD-0123456789\n" * 64     # ~2 KiB
    SMALL = b"rpd-small\n"
    lf_big = local("big.bin", BIG)
    lf_small = local("small.bin", SMALL)

    # =====================================================================
    # (A) OPEN-MODE / OWNERSHIP MATRIX  (new file -> update -> shrink -> regrow)
    # =====================================================================
    # (A1) NEW FILE create via data plane -> owned by alice, byte-exact size.
    rc, _o, e = xrd_cp_up(lf_big, "/alice/rpd_om.bin", A)
    ok(rc == 0 and uid_of("/alice/rpd_om.bin") == UID_ALICE
       and size_of("/alice/rpd_om.bin") == len(BIG),
       f"root:// open(new) write owned by alice, full size (rc={rc}, "
       f"uid={uid_of('/alice/rpd_om.bin')}, sz={size_of('/alice/rpd_om.bin')})")

    # (A2) UPDATE/OVERWRITE existing with a SMALLER payload (-f forces truncate-on-
    #      open).  Same file, still owned by alice, new (smaller) size — proves the
    #      update/truncate open mode re-establishes the principal, not the worker.
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_om.bin", A)
    ok(rc == 0 and uid_of("/alice/rpd_om.bin") == UID_ALICE
       and size_of("/alice/rpd_om.bin") == len(SMALL),
       f"root:// open(update/truncate) overwrite still alice-owned, shrunk "
       f"(rc={rc}, sz={size_of('/alice/rpd_om.bin')})")

    # (A3) explicit truncate-SHRINK via xrdfs truncate on own file (mutation).
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_om.bin", "4"], A)
    ok(rc == 0 and size_of("/alice/rpd_om.bin") == 4
       and uid_of("/alice/rpd_om.bin") == UID_ALICE,
       f"root:// truncate-shrink own file to 4 bytes (rc={rc}, "
       f"sz={size_of('/alice/rpd_om.bin')})")

    # (A4) truncate-GROW (sparse) own file — size grows, ownership unchanged.
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_om.bin", "4096"], A)
    ok(rc == 0 and size_of("/alice/rpd_om.bin") == 4096
       and uid_of("/alice/rpd_om.bin") == UID_ALICE,
       f"root:// truncate-grow own file to 4096 (rc={rc}, "
       f"sz={size_of('/alice/rpd_om.bin')})")

    # (A5) READ-ONLY open: download own file byte-exact (read path as alice).
    rc, _o, _e = xrd_cp_up(lf_big, "/alice/rpd_rd.bin", A)
    dl = os.path.join(WORK, "rpd_rd_dl.bin")
    rc2, _o2, _e2 = xrd_cp_down("/alice/rpd_rd.bin", dl, A)
    got = b""
    try:
        got = open(dl, "rb").read() if os.path.exists(dl) else b""
    except OSError:
        got = b""
    ok(rc == 0 and rc2 == 0 and got == BIG,
       f"root:// open(read-only) own file byte-exact (up={rc}, down={rc2})")

    # (A6) bob writes his OWN new file -> owned by BOB, not alice/svc (control that
    #      the open path maps the *token* identity, not a sticky last-principal).
    rc, _o, _e = xrd_cp_up(lf_small, "/bob/rpd_bom.bin", B)
    ok(rc == 0 and uid_of("/bob/rpd_bom.bin") == UID_BOB,
       f"root:// bob's open(new) write owned by bob (rc={rc}, "
       f"uid={uid_of('/bob/rpd_bom.bin')})")

    # =====================================================================
    # (B) QUERY MATRIX — checksum / config / space / xattr  (self vs bob no-leak)
    # =====================================================================
    # (B1) query checksum of OWN file succeeds.
    rc, out, _e = xrd_fs(["query", "checksum", "/alice/rpd_rd.bin"], A)
    ok(rc == 0, f"root:// query checksum own file (rc={rc})")

    # (B2) query checksum of bob's 0600 file: DENIED, and the body must not carry the
    #      secret marker (checksum could leak content/derived data).
    rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], A)
    ok(rc != 0 and MARK_BOB.decode() not in (out or ""),
       f"root:// query checksum of bob's 0600 DENIED + no leak (rc={rc})")

    # (B3) query checksum of svc-only file: DENIED + no svc secret marker.
    rc, out, _e = xrd_fs(["query", "checksum", "/svconly/secret-name.txt"], A)
    ok(rc != 0 and MARK_SVC.decode() not in (out or ""),
       f"root:// query checksum of svc-only file DENIED + no leak (rc={rc})")

    # (B4) query config of a benign server key works (no path -> no DAC) and does
    #      NOT echo any planted secret.
    rc, out, _e = xrd_fs(["query", "config", "version"], A)
    ok(MARK_BOB.decode() not in (out or "")
       and MARK_SVC.decode() not in (out or ""),
       f"root:// query config does not leak any tenant secret (rc={rc})")

    # (B5) query space of own dir works; of bob's 0600 file must not leak content.
    rc, _o, _e = xrd_fs(["query", "space", "/alice/"], A)
    ok(rc == 0, f"root:// query space own dir (rc={rc})")
    rc, out, _e = xrd_fs(["query", "space", "/bob/private.txt"], A)
    ok(MARK_BOB.decode() not in (out or ""),
       f"root:// query space of bob's 0600 leaks no content (rc={rc})")

    # (B6) query xattr (user.* / XrdCks.*) on OWN file — optional feature: accept
    #      unsupported (rc!=0) as handled, but a SUCCESS must carry no foreign secret.
    rc, out, _e = xrd_fs(["query", "xattr", "/alice/rpd_rd.bin"], A)
    ok(MARK_BOB.decode() not in (out or "")
       and MARK_SVC.decode() not in (out or ""),
       f"root:// query xattr own file leaks no foreign secret (rc={rc})")

    # (B7) query xattr on bob's 0600 file — DENIED or unsupported, never the secret.
    rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt"], A)
    ok(MARK_BOB.decode() not in (out or ""),
       f"root:// query xattr of bob's 0600 leaks no content (rc={rc})")

    # =====================================================================
    # (C) STAT / STATX / LOCATE  — self vs cross-tenant
    # =====================================================================
    # (C1) stat own file succeeds.
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_rd.bin"], A)
    ok(rc == 0, f"root:// stat own file (rc={rc})")

    # (C2) stat bob's world-readable 0644 file: metadata is not secret -> may succeed,
    #      but the stat output must not leak the PRIVATE file's secret bytes.
    rc, out, _e = xrd_fs(["stat", "/bob/readable.txt"], A)
    ok(MARK_BOB.decode() not in (out or ""),
       f"root:// stat bob's 0644 file leaks no private content (rc={rc})")

    # (C3) stat a NON-EXISTENT path -> error (no phantom success / no escape).
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_does_not_exist_xyz"], A)
    ok(rc != 0, f"root:// stat of missing file errors cleanly (rc={rc})")

    # (C4) locate own dir works (positive control for the namespace walk).
    rc, _o, _e = xrd_fs(["locate", "/alice/"], A)
    ok(rc == 0, f"root:// locate own dir (rc={rc})")

    # (C5) locate of bob's secret 0700 dir entry must not leak its protected child.
    rc, out, _e = xrd_fs(["locate", "/bobsecret/s.txt"], A)
    ok("bob-only" not in (out or ""),
       f"root:// locate of bob's 0700 file leaks no content (rc={rc})")

    # =====================================================================
    # (D) NESTED MKDIR + PER-LEVEL OWNERSHIP  (self) and cross-tenant DENY
    # =====================================================================
    # (D1) create a parent then a child; each level owned by alice.
    rc1, _o, _e = xrd_fs(["mkdir", "/alice/rpd_nest"], A)
    rc2, _o, _e = xrd_fs(["mkdir", "/alice/rpd_nest/child"], A)
    ok(rc1 == 0 and rc2 == 0
       and uid_of("/alice/rpd_nest") == UID_ALICE
       and uid_of("/alice/rpd_nest/child") == UID_ALICE,
       f"root:// nested mkdir: every level owned by alice (rc={rc1}/{rc2})")

    # (D2) a file inside the nested dir is owned by alice too (write into own subtree).
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_nest/child/leaf.bin", A)
    ok(rc == 0 and uid_of("/alice/rpd_nest/child/leaf.bin") == UID_ALICE,
       f"root:// file in nested own dir owned by alice (rc={rc})")

    # (D3) mkdir into bob's 0700 dir -> DENIED, nothing created.
    rc, _o, _e = xrd_fs(["mkdir", "/bobsecret/rpd_intrude"], A)
    ok(rc != 0 and not os.path.exists(realp("/bobsecret/rpd_intrude")),
       f"root:// mkdir into bob's 0700 dir DENIED (rc={rc})")

    # (D4) mkdir into svc-only 0750 dir -> DENIED (alice is other, no write).
    rc, _o, _e = xrd_fs(["mkdir", "/svconly/rpd_intrude"], A)
    ok(rc != 0 and not os.path.exists(realp("/svconly/rpd_intrude")),
       f"root:// mkdir into svc-only 0750 dir DENIED (rc={rc})")

    # =====================================================================
    # (E) RMDIR non-empty vs empty  (self) and cross-tenant DENY
    # =====================================================================
    # (E1) rmdir a NON-EMPTY own dir must FAIL (ENOTEMPTY), dir + child survive.
    rc, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest"], A)
    ok(rc != 0 and os.path.isdir(realp("/alice/rpd_nest/child")),
       f"root:// rmdir non-empty own dir refused (ENOTEMPTY) (rc={rc})")

    # (E2) empty the subtree leaf-first, then rmdir EMPTY own dirs succeeds.
    xrd_fs(["rm", "/alice/rpd_nest/child/leaf.bin"], A)
    rcA, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest/child"], A)
    rcB, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest"], A)
    ok(rcA == 0 and rcB == 0 and not os.path.exists(realp("/alice/rpd_nest")),
       f"root:// rmdir empty own dirs succeeds, tree gone (rc={rcA}/{rcB})")

    # (E3) rmdir bob's secret 0700 dir -> DENIED, dir + secret child intact.
    rc, _o, _e = xrd_fs(["rmdir", "/bobsecret"], A)
    ok(rc != 0 and os.path.isdir(realp("/bobsecret"))
       and os.path.exists(realp("/bobsecret/s.txt")),
       f"root:// rmdir bob's 0700 dir DENIED, intact (rc={rc})")

    # =====================================================================
    # (F) MV  — within-tenant OK / cross-tenant-source DENY / into-svconly DENY
    # =====================================================================
    # (F1) within-tenant rename: src disappears, dst owned by alice, content kept.
    xrd_fs(["rm", "/alice/rpd_mv_src.bin"], A)   # idempotent cleanup
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_mv_src.bin", A)
    rc2, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_src.bin", "/alice/rpd_mv_dst.bin"], A)
    ok(rc == 0 and rc2 == 0 and uid_of("/alice/rpd_mv_dst.bin") == UID_ALICE
       and not os.path.exists(realp("/alice/rpd_mv_src.bin"))
       and size_of("/alice/rpd_mv_dst.bin") == len(SMALL),
       f"root:// mv within alice's tenant OK, dst alice-owned (rc={rc2})")

    # (F2) cross-tenant SOURCE: mv bob's 0644 file into alice's dir -> DENIED.  The
    #      source removal needs write on bob's dir; bob's file stays put, no copy.
    before_uid = uid_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["mv", "/bob/readable.txt", "/alice/rpd_stolen.bin"], A)
    ok(rc != 0 and os.path.exists(realp("/bob/readable.txt"))
       and uid_of("/bob/readable.txt") == before_uid
       and not os.path.exists(realp("/alice/rpd_stolen.bin")),
       f"root:// mv of bob's file (cross-tenant source) DENIED (rc={rc})")

    # (F3) mv own file INTO svc-only 0750 dir as DEST -> DENIED (no write on svconly);
    #      the source file must survive in alice's dir (atomic refusal, no loss).
    rc, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_dst.bin", "/svconly/rpd_planted.bin"], A)
    ok(rc != 0 and os.path.exists(realp("/alice/rpd_mv_dst.bin"))
       and not os.path.exists(realp("/svconly/rpd_planted.bin")),
       f"root:// mv own file INTO svc-only dest DENIED, src kept (rc={rc})")

    # (F4) mv own file into the world-writable pub/ 0777 dir -> OK, owner preserved
    #      (control proving F3's deny is the DEST dir's DAC, not a blanket mv block).
    rc, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_dst.bin", "/pub/rpd_pubmoved.bin"], A)
    ok(rc == 0 and uid_of("/pub/rpd_pubmoved.bin") == UID_ALICE
       and not os.path.exists(realp("/alice/rpd_mv_dst.bin")),
       f"root:// mv own file into pub/ (0777) OK, still alice-owned (rc={rc})")

    # =====================================================================
    # (G) CHMOD  — own (mode actually changes) vs bob (DENIED, mode intact)
    # =====================================================================
    # (G1) chmod own file changes the mode (and to a DIFFERENT value than before).
    xrd_cp_up(lf_small, "/alice/rpd_chmod.bin", A)
    pre = mode_of("/alice/rpd_chmod.bin")
    target = 0o640 if pre != 0o640 else 0o600
    rc, _o, _e = xrd_fs(["chmod", "/alice/rpd_chmod.bin", oct(target)[2:]], A)
    post = mode_of("/alice/rpd_chmod.bin")
    ok(rc == 0 and post == target and post != pre,
       f"root:// chmod own file changes mode {pre:o}->{post:o} (rc={rc})")

    # (G2) chmod bob's PRIVATE 0600 file -> DENIED, mode unchanged (no DAC widening).
    pre_b = mode_of("/bob/private.txt")
    rc, _o, _e = xrd_fs(["chmod", "/bob/private.txt", "666"], A)
    ok(rc != 0 and mode_of("/bob/private.txt") == pre_b and pre_b == 0o600,
       f"root:// chmod bob's 0600 file DENIED, mode intact ({pre_b:o}, rc={rc})")

    # (G3) chmod bob's 0644 file -> DENIED too (alice is not the owner).
    pre_r = mode_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["chmod", "/bob/readable.txt", "600"], A)
    ok(rc != 0 and mode_of("/bob/readable.txt") == pre_r,
       f"root:// chmod bob's 0644 file DENIED, mode intact ({pre_r:o}, rc={rc})")

    # =====================================================================
    # (H) TRUNCATE  — own (shrinks) vs bob (DENIED, size intact)
    # =====================================================================
    # (H1) truncate own file to 0 succeeds.
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_chmod.bin", "0"], A)
    ok(rc == 0 and size_of("/alice/rpd_chmod.bin") == 0,
       f"root:// truncate own file to 0 (rc={rc})")

    # (H2) truncate bob's 0600 PRIVATE file -> DENIED, size unchanged.
    sz_b = size_of("/bob/private.txt")
    rc, _o, _e = xrd_fs(["truncate", "/bob/private.txt", "0"], A)
    ok(rc != 0 and size_of("/bob/private.txt") == sz_b and sz_b > 0,
       f"root:// truncate bob's 0600 file DENIED, size intact ({sz_b}, rc={rc})")

    # (H3) truncate bob's 0644 file -> DENIED (no write perm on other's file).
    sz_r = size_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["truncate", "/bob/readable.txt", "0"], A)
    ok(rc != 0 and size_of("/bob/readable.txt") == sz_r,
       f"root:// truncate bob's 0644 file DENIED, size intact ({sz_r}, rc={rc})")

    # =====================================================================
    # (I) PUB/ (0777 shared) — write owned by the WRITER (alice vs bob distinct)
    # =====================================================================
    rc, _o, _e = xrd_cp_up(lf_small, "/pub/rpd_alice_pub.bin", A)
    ok(rc == 0 and uid_of("/pub/rpd_alice_pub.bin") == UID_ALICE,
       f"root:// write into pub/ owned by alice the writer (rc={rc})")
    rc, _o, _e = xrd_cp_up(lf_small, "/pub/rpd_bob_pub.bin", B)
    ok(rc == 0 and uid_of("/pub/rpd_bob_pub.bin") == UID_BOB,
       f"root:// write into pub/ owned by bob the writer (rc={rc})")
    # invariant: NEITHER shared-dir file is owned by svc(1500) or root(0).
    ua = uid_of("/pub/rpd_alice_pub.bin")
    ub = uid_of("/pub/rpd_bob_pub.bin")
    ok(ua >= 1000 and ub >= 1000 and ua != UID_SVC and ub != UID_SVC
       and ua != 0 and ub != 0 and ua != ub,
       f"root:// pub/ files owned by distinct mapped users, never svc/root "
       f"(alice={ua}, bob={ub})")

    # =====================================================================
    # (J) READ-then-DELETE lifecycle (own file)
    # =====================================================================
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_rmlife.bin", A)
    dl2 = os.path.join(WORK, "rpd_rmlife_dl.bin")
    rcd, _o, _e = xrd_cp_down("/alice/rpd_rmlife.bin", dl2, A)
    got2 = b""
    try:
        got2 = open(dl2, "rb").read() if os.path.exists(dl2) else b""
    except OSError:
        got2 = b""
    rcrm, _o, _e = xrd_fs(["rm", "/alice/rpd_rmlife.bin"], A)
    ok(rc == 0 and rcd == 0 and got2 == SMALL and rcrm == 0
       and not os.path.exists(realp("/alice/rpd_rmlife.bin")),
       f"root:// read-then-delete own file lifecycle (up={rc}, down={rcd}, "
       f"rm={rcrm})")

    # alice must NOT be able to rm bob's file (delete needs write on bob's dir).
    rc, _o, _e = xrd_fs(["rm", "/bob/readable.txt"], A)
    ok(rc != 0 and os.path.exists(realp("/bob/readable.txt")),
       f"root:// rm bob's file DENIED, file intact (rc={rc})")

    # =====================================================================
    # (K) ESCALATION via the STREAM data plane — forbidden / unmapped principals
    # =====================================================================
    for sub in ["root", "svc", "sys100", "dockerite", "mallory"]:
        fp_rel = f"/pub/rpd_esc_{sub}.bin"
        rc, _o, _e = xrd_cp_up(lf_small, fp_rel, sub)
        created = os.path.exists(realp(fp_rel))
        bad_owner = created and uid_of(fp_rel) < 1000
        ok(rc != 0 and not created and not bad_owner,
           f"root:// data-plane write as principal '{sub}' DENIED, no file "
           f"(rc={rc}, created={created})")

    # =====================================================================
    # (L) CONFINEMENT via the stream protocol — symlink escape + traversal
    # =====================================================================
    rc, out, _e = xrd_fs(["cat", "/escape/passwd"], A)
    ok("root:x:0:0" not in (out or ""),
       f"root:// cat through /escape symlink did NOT read /etc/passwd (rc={rc})")
    pw = os.path.join(WORK, "rpd_pw.bin")
    rc, _o, _e = xrd_cp_down("/escape/passwd", pw, A)
    leaked_pw = False
    try:
        leaked_pw = os.path.exists(pw) and b"root:x:0:0" in open(pw, "rb").read()
    except OSError:
        leaked_pw = False
    ok(not leaked_pw, f"root:// xrdcp through symlink did NOT exfil /etc/passwd (rc={rc})")
    # traversal in the wire path must not escape (no OUTSIDE sentinel created).
    sentinel = os.path.join(os.path.dirname(data.rstrip("/")), "RPD_OUTSIDE")
    try:
        if os.path.exists(sentinel):
            os.remove(sentinel)
    except OSError:
        pass
    xrd_cp_up(lf_small, "/../RPD_OUTSIDE", A)
    xrd_fs(["mkdir", "/../RPD_OUTSIDE_DIR"], A)
    ok(not os.path.exists(sentinel)
       and not os.path.exists(os.path.join(os.path.dirname(data.rstrip("/")),
                                            "RPD_OUTSIDE_DIR")),
       "root:// traversal (../) did not escape the export root")

    # =====================================================================
    # (M) SEQUENTIAL many-small-files burst — every file owned by the mapping user
    #     (no setfsuid principal drift across back-to-back ops on one worker).
    # =====================================================================
    N = 16
    bad = 0
    for i in range(N):
        rel = f"/alice/rpd_seq_{i}.bin"
        rc, _o, _e = xrd_cp_up(lf_small, rel, A)
        if not (rc == 0 and uid_of(rel) == UID_ALICE):
            bad += 1
    ok(bad == 0,
       f"root:// {N} sequential alice writes all owned by alice (mismatches={bad})")

    # interleave a single bob write in the middle of alice's burst and re-verify a
    # FRESH alice write still lands as alice (principal not stuck on bob).
    xrd_cp_up(lf_small, "/bob/rpd_seq_bob.bin", B)
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_seq_after_bob.bin", A)
    ok(rc == 0 and uid_of("/alice/rpd_seq_after_bob.bin") == UID_ALICE
       and uid_of("/bob/rpd_seq_bob.bin") == UID_BOB,
       f"root:// alice write after an interleaved bob write stays alice-owned "
       f"(rc={rc})")

    # =====================================================================
    # (N) SECOND-IDENTITY SELF-MATRIX (bob) — full ownership/DAC parity, and the
    #     reverse cross-tenant deny (bob must not touch ALICE's data).
    # =====================================================================
    # (N1) bob creates a private file -> owned by bob.
    rc, _o, _e = xrd_cp_up(lf_small, "/bob/rpd_bself.bin", B)
    ok(rc == 0 and uid_of("/bob/rpd_bself.bin") == UID_BOB,
       f"root:// bob self-write owned by bob (rc={rc})")
    # (N2) bob chmod own file works.
    rc, _o, _e = xrd_fs(["chmod", "/bob/rpd_bself.bin", "600"], B)
    ok(rc == 0 and mode_of("/bob/rpd_bself.bin") == 0o600,
       f"root:// bob chmod own file (rc={rc})")
    # (N3) seed an alice 0600 secret, then prove BOB cannot read/mutate it.
    rcseed, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_asecret.bin", A)
    xrd_fs(["chmod", "/alice/rpd_asecret.bin", "600"], A)
    rc, out, _e = xrd_fs(["cat", "/alice/rpd_asecret.bin"], B)
    ok(rc != 0 and "rpd-small" not in (out or ""),
       f"root:// bob cat alice's 0600 file DENIED + no leak (rc={rc})")
    pre_m = mode_of("/alice/rpd_asecret.bin")
    rc, _o, _e = xrd_fs(["chmod", "/alice/rpd_asecret.bin", "777"], B)
    ok(rc != 0 and mode_of("/alice/rpd_asecret.bin") == pre_m,
       f"root:// bob chmod alice's file DENIED, mode intact ({pre_m:o}, rc={rc})")
    rc, _o, _e = xrd_fs(["rm", "/alice/rpd_asecret.bin"], B)
    ok(rc != 0 and os.path.exists(realp("/alice/rpd_asecret.bin")),
       f"root:// bob rm alice's file DENIED, intact (rc={rc})")

    # =====================================================================
    # (O) FORGED / INVALID raw tokens over the stream protocol — none may map to a
    #     UNIX identity or create a file in the shared pub/ dir.
    # =====================================================================
    for label, tok in _forged_tokens(key):
        rel = f"/pub/rpd_forge.bin"
        try:
            if os.path.exists(realp(rel)):
                os.remove(realp(rel))
        except OSError:
            pass
        rc, _o, _e = xrd_fs_token(["stat", "/alice/"], tok)
        ok(rc != 0,
           f"root:// forged token '{label}' rejected for stat (rc={rc})")

    # =====================================================================
    # (P) WORKER SURVIVES — after all the abuse, a legit alice op still succeeds
    #     (the broker / worker were not wedged by any of the above attacks).
    # =====================================================================
    rc, _o, e = xrd_cp_up(lf_small, "/alice/rpd_survive.bin", A)
    ok(rc == 0 and uid_of("/alice/rpd_survive.bin") == UID_ALICE,
       f"root:// worker SURVIVES the battery; legit alice op still works "
       f"(rc={rc}, {e.strip()[:60]})")
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_survive.bin"], A)
    ok(rc == 0, f"root:// follow-up stat after survival write OK (rc={rc})")


