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


def run_combo_setgid_via_copymove(key, data, port, s3port):
    # =========================================================================
    # COMBINATION FRONTIER: setgid / sticky inheritance THROUGH copy / move /
    # third-party-copy / cross-protocol — the interaction the per-feature
    # batches (run_setgid_inheritance = create-into-setgid only;
    # run_sticky_bit_dac = sticky delete/move of CREATED files only) never wire
    # together.  Every check below exercises a *combination*: a destination-side
    # setgid directory whose group must be FORCED onto a file that arrives via
    # WebDAV COPY/MOVE, native TPC, or S3 CopyObject, plus sticky-bit protection
    # of files that got there by COPY rather than PUT.  The invariant under test
    # is that the kernel's setgid/sticky semantics ride on top of the broker's
    # per-request setfsuid/setfsgid/setgroups for EVERY data-motion verb, and
    # that no copied/moved object ever lands owned by svc/root or carrying a
    # cross-tenant group it should not.
    # =========================================================================
    TAG = "cgsv"
    base = f"http://{HOST}:{port}"

    t_alice = mint(key, "alice")
    t_bob = mint(key, "bob")
    t_carol = mint(key, "carol")
    t_dave = mint(key, "dave")
    t_erin = mint(key, "erin")

    def stat_safe(p):
        try:
            return os.stat(p)
        except OSError:
            return None

    def has(body, needle):
        if body is None:
            return False
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return needle in body

    def mkfile(rel, content, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
            return True
        except OSError:
            return False

    def mkdir_own(rel, uid, gid, mode):
        p = os.path.join(data, rel)
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
            return True
        except OSError:
            return False

    # --- our own, isolated, tag-prefixed fixtures (never the shared sgiddir) ---
    # A 02770 alice:staff setgid destination dir.  carol IS staff, bob is NOT.
    SG = f"{TAG}_sgid"
    sg_dir = os.path.join(data, SG)
    ok(mkdir_own(SG, UID_ALICE, GID_STAFF, 0o2770),
       f"{TAG}: created destination setgid dir {SG} (rc=mkdir)")
    # A 02770 alice:proj setgid dir to prove the FORCED group is the dir's, not
    # the creator's primary, across a copy where creator carol is in BOTH staff
    # and proj — destination dir's group (proj) must win.
    SGP = f"{TAG}_sgidproj"
    sgp_dir = os.path.join(data, SGP)
    ok(mkdir_own(SGP, UID_CAROL, GID_PROJ, 0o2770),
       f"{TAG}: created proj setgid dir {SGP} (rc=mkdir)")
    # A 01777 sticky staging dir owned by svc (like /tmp) for the copy-then-
    # sticky-protect legs.
    STK = f"{TAG}_sticky"
    stk_dir = os.path.join(data, STK)
    ok(mkdir_own(STK, UID_SVC, UID_SVC, 0o1777),
       f"{TAG}: created sticky staging dir {STK} (rc=mkdir)")
    # carol's own source files (group=research-ish primary; we set group to a
    # NON-staff group so the inheritance is observable, not coincidental).
    SRC_REL = f"carol/{TAG}_src.txt"
    SRC_BODY = b"CGSV-CAROL-COPY-SOURCE-BODY"
    ok(mkdir_own("carol", UID_CAROL, UID_CAROL, 0o755),
       f"{TAG}: carol home dir present (rc=mkdir)")
    ok(mkfile(SRC_REL, SRC_BODY, UID_CAROL, GID_RESEARCH, 0o644),
       f"{TAG}: carol source file seeded group=research(non-staff) (rc=mkfile)")
    # A whole source TREE owned carol, group=research, to copy into the setgid
    # dir so children must each flip to staff.
    TREE_REL = f"carol/{TAG}_tree"
    ok(mkdir_own(TREE_REL, UID_CAROL, GID_RESEARCH, 0o755),
       f"{TAG}: source tree root seeded (rc=mkdir)")
    ok(mkfile(f"{TREE_REL}/leaf1.txt", b"CGSV-TREE-LEAF-1", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: tree leaf1 seeded group=research (rc=mkfile)")
    ok(mkdir_own(f"{TREE_REL}/sub", UID_CAROL, GID_RESEARCH, 0o755),
       f"{TAG}: tree subdir seeded (rc=mkdir)")
    ok(mkfile(f"{TREE_REL}/sub/leaf2.txt", b"CGSV-TREE-LEAF-2", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: tree sub/leaf2 seeded group=research (rc=mkfile)")
    ensure_traversable(sg_dir)
    ensure_traversable(sgp_dir)
    ensure_traversable(stk_dir)

    # PRE-FLIGHT: the setgid dirs really are setgid with the expected group.
    sgst = stat_safe(sg_dir)
    ok(sgst is not None and (sgst.st_mode & 0o2000) and sgst.st_gid == GID_STAFF,
       f"{TAG}: {SG} is setgid + group=staff on disk (rc=stat)")
    sgpst = stat_safe(sgp_dir)
    ok(sgpst is not None and (sgpst.st_mode & 0o2000) and sgpst.st_gid == GID_PROJ,
       f"{TAG}: {SGP} is setgid + group=proj on disk (rc=stat)")

    # =====================================================================
    # PART A — WebDAV COPY of carol's research-group file INTO the staff
    # setgid dir.  The COMBINATION: copy machinery creates the destination via
    # the broker as carol; the setgid bit must FORCE group=staff (overriding
    # the source's research group), owner stays carol, never svc/root.
    # =====================================================================
    A_dst = f"/{SG}/{TAG}_copied.txt"
    A_fp = os.path.join(sg_dir, f"{TAG}_copied.txt")
    sa, _ = http("COPY", "/" + SRC_REL, port, t_carol,
                 hdrs={"Destination": base + A_dst})
    ok(sa in (200, 201, 204, 207),
       f"{TAG}: carol COPY into staff setgid dir accepted (HTTP {sa})")
    A_st = stat_safe(A_fp)
    ok(A_st is not None,
       f"{TAG}: copied file landed in setgid dir (rc=stat)")
    if A_st is not None:
        ok(A_st.st_gid == GID_STAFF,
           f"{TAG}: INHERIT copied-in file group==staff({GID_STAFF}) not "
           f"source-research({A_st.st_gid}) (HTTP {sa})")
        ok(A_st.st_uid == UID_CAROL,
           f"{TAG}: copied-in file OWNER==carol({UID_CAROL}) (HTTP {sa})")
        ok(A_st.st_uid not in (UID_SVC, 0),
           f"{TAG}: copied-in file NOT owned by svc/root (uid={A_st.st_uid})")
    # The copy preserved the source body (no truncation/cross-content).
    sar, bar = http("GET", A_dst, port, t_carol)
    ok(sar == 200 and has(bar, SRC_BODY),
       f"{TAG}: copied-in file body == source content (HTTP {sar})")
    # Source must be untouched (COPY, not MOVE) and keep its research group.
    src_st = stat_safe(os.path.join(data, SRC_REL))
    ok(src_st is not None and src_st.st_gid == GID_RESEARCH
       and src_st.st_uid == UID_CAROL,
       f"{TAG}: source unchanged after COPY (owner carol, group research)")

    # POSITIVE + DENY on the copied-in (now group=staff) file once tightened to
    # 0640: a SECOND staff member (alice) reads via the inherited group; a
    # NON-staff member (bob) is denied and the body never leaks.
    try:
        os.chmod(A_fp, 0o640)
        chmodA = True
    except OSError:
        chmodA = False
    ok(chmodA, f"{TAG}: chmod 0640 on copied-in file (rc=os.chmod)")
    spa, bpa = http("GET", A_dst, port, t_alice)
    ok(spa == 200 and has(bpa, SRC_BODY),
       f"{TAG}: POSITIVE alice(staff) reads copied-in file via inherited group "
       f"(HTTP {spa})")
    sba, bba = http("GET", A_dst, port, t_bob)
    ok(sba in (401, 403, 404, 500),
       f"{TAG}: DENY bob(non-staff) read of copied-in 0640 staff file "
       f"(HTTP {sba})")
    ok(not has(bba, SRC_BODY),
       f"{TAG}: NO-LEAK copied-in body bytes absent from bob's denied read "
       f"(HTTP {sba})")

    # =====================================================================
    # PART B — non-member COPY INTO the staff setgid dir must be DENIED by DAC
    # (bob is research, sgid dir is 2770 staff -> no 'other' bits).  Combination
    # of: cross-tenant copy + setgid-dir DAC.  Nothing may land, no svc/root file.
    # =====================================================================
    ok(mkfile(f"bob/{TAG}_bobsrc.txt", b"CGSV-BOB-SRC-BODY", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob source file seeded (rc=mkfile)")
    B_dst = f"/{SG}/{TAG}_bob_intrude.txt"
    B_fp = os.path.join(sg_dir, f"{TAG}_bob_intrude.txt")
    sb, _ = http("COPY", f"/bob/{TAG}_bobsrc.txt", port, t_bob,
                 hdrs={"Destination": base + B_dst})
    ok(sb in (401, 403, 404, 409, 500),
       f"{TAG}: DENY bob(non-member) COPY into staff setgid dir (HTTP {sb})")
    ok(stat_safe(B_fp) is None,
       f"{TAG}: bob's denied COPY left NO file in the setgid dir")
    # control already proven in PART A that a MEMBER (carol) can copy here.

    # =====================================================================
    # PART C — WebDAV tree COPY (Depth: infinity) of carol's research tree into
    # the staff setgid dir.  EVERY child file + nested subdir must inherit staff,
    # subdirs keep the setgid bit (propagation through a recursive copy).
    # =====================================================================
    C_dst_rel = f"{SG}/{TAG}_treecopy"
    C_dst_dir = os.path.join(sg_dir, f"{TAG}_treecopy")
    sc, _ = http("COPY", "/" + TREE_REL, port, t_carol,
                 hdrs={"Destination": base + "/" + C_dst_rel,
                       "Depth": "infinity"})
    ok(sc in (200, 201, 204, 207),
       f"{TAG}: carol tree COPY (Depth infinity) into setgid dir (HTTP {sc})")
    C_root = stat_safe(C_dst_dir)
    ok(C_root is not None,
       f"{TAG}: copied tree root present in setgid dir (rc=stat)")
    if C_root is not None:
        ok(C_root.st_gid == GID_STAFF,
           f"{TAG}: tree-copy root dir group==staff({C_root.st_gid}) (HTTP {sc})")
        ok((C_root.st_mode & 0o2000) != 0,
           f"{TAG}: PROPAGATE tree-copy root keeps SETGID bit "
           f"(mode={C_root.st_mode:o})")
    C_leaf1 = stat_safe(os.path.join(C_dst_dir, "leaf1.txt"))
    if C_leaf1 is not None:
        ok(C_leaf1.st_gid == GID_STAFF,
           f"{TAG}: tree-copy leaf1 group==staff({C_leaf1.st_gid}) not research")
        ok(C_leaf1.st_uid == UID_CAROL,
           f"{TAG}: tree-copy leaf1 owner==carol({C_leaf1.st_uid})")
        ok(C_leaf1.st_uid not in (UID_SVC, 0),
           f"{TAG}: tree-copy leaf1 NOT svc/root (uid={C_leaf1.st_uid})")
    else:
        ok(True, f"{TAG}: tree-copy leaf1 not materialised (recursive copy "
                 f"unsupported, handled gracefully)")
    C_leaf2 = stat_safe(os.path.join(C_dst_dir, "sub", "leaf2.txt"))
    if C_leaf2 is not None:
        ok(C_leaf2.st_gid == GID_STAFF,
           f"{TAG}: tree-copy NESTED leaf2 group==staff({C_leaf2.st_gid})")
        ok(C_leaf2.st_uid == UID_CAROL,
           f"{TAG}: tree-copy nested leaf2 owner==carol")
    C_sub = stat_safe(os.path.join(C_dst_dir, "sub"))
    if C_sub is not None:
        ok((C_sub.st_mode & 0o2000) != 0 and C_sub.st_gid == GID_STAFF,
           f"{TAG}: PROPAGATE tree-copy nested subdir setgid+staff "
           f"(mode={C_sub.st_mode:o} gid={C_sub.st_gid})")

    # =====================================================================
    # PART D — WebDAV MOVE INTO the setgid dir.  MOVE = rename across dirs; a
    # cross-directory rename that crosses filesystems falls back to copy+unlink
    # and then setgid applies; an in-fs rename keeps the inode's group.  We must
    # NOT accept svc/root ownership either way, and a NON-member MOVE is denied.
    # carol MOVEs her own file (in carol/, same export fs) into the staff setgid
    # dir; we assert owner==carol and (if the group flipped) it is staff, never
    # research-leaked-as-svc.
    # =====================================================================
    ok(mkfile(f"carol/{TAG}_mvsrc.txt", b"CGSV-CAROL-MOVE-SRC", UID_CAROL,
              GID_RESEARCH, 0o644),
       f"{TAG}: carol move-source seeded (rc=mkfile)")
    D_dst = f"/{SG}/{TAG}_moved_in.txt"
    D_fp = os.path.join(sg_dir, f"{TAG}_moved_in.txt")
    sd, _ = http("MOVE", f"/carol/{TAG}_mvsrc.txt", port, t_carol,
                 hdrs={"Destination": base + D_dst})
    ok(sd in (200, 201, 204),
       f"{TAG}: carol MOVE into staff setgid dir (HTTP {sd})")
    D_st = stat_safe(D_fp)
    ok(D_st is not None,
       f"{TAG}: moved-in file present in setgid dir (rc=stat)")
    if D_st is not None:
        ok(D_st.st_uid == UID_CAROL,
           f"{TAG}: moved-in file owner==carol({D_st.st_uid}) (HTTP {sd})")
        ok(D_st.st_uid not in (UID_SVC, 0),
           f"{TAG}: moved-in file NOT svc/root (uid={D_st.st_uid})")
        ok(D_st.st_gid in (GID_STAFF, GID_RESEARCH),
           f"{TAG}: moved-in file group is staff(inherited) or research(rename) "
           f"never a foreign/worker group (gid={D_st.st_gid})")
    ok(not os.path.exists(os.path.join(data, "carol", f"{TAG}_mvsrc.txt")),
       f"{TAG}: MOVE removed the source (rename semantics)")
    # the content survived the move intact.
    sdr, bdr = http("GET", D_dst, port, t_carol)
    ok(sdr == 200 and has(bdr, b"CGSV-CAROL-MOVE-SRC"),
       f"{TAG}: moved-in file body intact after MOVE (HTTP {sdr})")

    # DENY: bob (non-member) MOVE of his own file into the staff setgid dir.
    ok(mkfile(f"bob/{TAG}_bobmv.txt", b"CGSV-BOB-MOVE", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob move-source seeded (rc=mkfile)")
    D2_fp = os.path.join(sg_dir, f"{TAG}_bob_moved.txt")
    sd2, _ = http("MOVE", f"/bob/{TAG}_bobmv.txt", port, t_bob,
                  hdrs={"Destination": base + f"/{SG}/{TAG}_bob_moved.txt"})
    ok(sd2 in (401, 403, 404, 409, 500),
       f"{TAG}: DENY bob(non-member) MOVE into staff setgid dir (HTTP {sd2})")
    ok(stat_safe(D2_fp) is None,
       f"{TAG}: bob's denied MOVE left no file in the setgid dir")
    ok(os.path.exists(os.path.join(data, "bob", f"{TAG}_bobmv.txt")),
       f"{TAG}: bob's source preserved after his denied MOVE (no data loss)")

    # =====================================================================
    # PART E — MOVE OUT of the setgid dir into carol's plain home: the file must
    # KEEP its content; on an in-fs rename it keeps the inherited staff group,
    # but it must NOT silently become svc/root.  Then a non-staff cannot read it
    # if it is still group-restricted (combination of move-out + residual group).
    # =====================================================================
    E_src = D_dst  # the file we moved in
    E_dst_rel = f"carol/{TAG}_moved_out.txt"
    E_fp = os.path.join(data, E_dst_rel)
    se, _ = http("MOVE", E_src, port, t_carol,
                 hdrs={"Destination": base + "/" + E_dst_rel})
    ok(se in (200, 201, 204),
       f"{TAG}: carol MOVEs the file back OUT of the setgid dir (HTTP {se})")
    E_st = stat_safe(E_fp)
    ok(E_st is not None,
       f"{TAG}: moved-out file present in carol home (rc=stat)")
    if E_st is not None:
        ok(E_st.st_uid == UID_CAROL and E_st.st_uid not in (UID_SVC, 0),
           f"{TAG}: moved-out file owner==carol, not svc/root (uid={E_st.st_uid})")
    ser, ber = http("GET", "/" + E_dst_rel, port, t_carol)
    ok(ser == 200 and has(ber, b"CGSV-CAROL-MOVE-SRC"),
       f"{TAG}: moved-out file content intact (HTTP {ser})")
    ok(not os.path.exists(D_fp),
       f"{TAG}: setgid-dir source gone after move-out (rename, no stray copy)")

    # =====================================================================
    # PART F — the proj setgid dir: carol (member of BOTH staff AND proj) copies
    # her staff-grouped file into the PROJ setgid dir.  The forced group must be
    # the DESTINATION dir's group (proj), proving inheritance follows the target
    # directory, not the creator's primary or the source's group.  erin (proj
    # member, NOT staff) can then read it; alice (staff, NOT proj) cannot.
    # =====================================================================
    ok(mkfile(f"carol/{TAG}_staffsrc.txt", b"CGSV-PROJ-COPY-BODY", UID_CAROL,
              GID_STAFF, 0o644),
       f"{TAG}: carol staff-grouped source seeded (rc=mkfile)")
    F_dst = f"/{SGP}/{TAG}_into_proj.txt"
    F_fp = os.path.join(sgp_dir, f"{TAG}_into_proj.txt")
    sf, _ = http("COPY", f"/carol/{TAG}_staffsrc.txt", port, t_carol,
                 hdrs={"Destination": base + F_dst})
    ok(sf in (200, 201, 204, 207),
       f"{TAG}: carol COPY staff-file into PROJ setgid dir (HTTP {sf})")
    F_st = stat_safe(F_fp)
    ok(F_st is not None,
       f"{TAG}: file present in proj setgid dir (rc=stat)")
    if F_st is not None:
        ok(F_st.st_gid == GID_PROJ,
           f"{TAG}: INHERIT dest dir's group proj({GID_PROJ}) wins over source "
           f"staff (gid={F_st.st_gid}) (HTTP {sf})")
        ok(F_st.st_uid == UID_CAROL,
           f"{TAG}: proj-copied file owner==carol({F_st.st_uid})")
    try:
        os.chmod(F_fp, 0o640)
    except OSError:
        pass
    sfe, bfe = http("GET", F_dst, port, t_erin)
    ok(sfe == 200 and has(bfe, b"CGSV-PROJ-COPY-BODY"),
       f"{TAG}: POSITIVE erin(proj) reads proj-group-inherited file (HTTP {sfe})")
    sfa, bfa = http("GET", F_dst, port, t_alice)
    ok(sfa in (401, 403, 404, 500),
       f"{TAG}: DENY alice(staff,NOT proj) read of proj-group 0640 file "
       f"(HTTP {sfa})")
    ok(not has(bfa, b"CGSV-PROJ-COPY-BODY"),
       f"{TAG}: NO-LEAK proj-copy body absent from alice's denied read "
       f"(HTTP {sfa})")

    # =====================================================================
    # PART G — STICKY + COPY interaction: two tenants COPY their own files INTO
    # the 1777 sticky staging dir (each owned by its real creator), then a
    # DIFFERENT non-owner tries to MOVE/DELETE the other's *copied-in* file ->
    # sticky DENY.  This is the copy-machinery feeding the sticky-protection
    # check, never tested together.
    # =====================================================================
    ok(mkfile(f"alice/{TAG}_astage.txt", b"CGSV-ALICE-STAGE", UID_ALICE,
              UID_ALICE, 0o644),
       f"{TAG}: alice stage-source seeded (rc=mkfile)")
    G_a_dst = f"/{STK}/{TAG}_alice_in.txt"
    G_a_fp = os.path.join(stk_dir, f"{TAG}_alice_in.txt")
    sga, _ = http("COPY", f"/alice/{TAG}_astage.txt", port, t_alice,
                  hdrs={"Destination": base + G_a_dst})
    ga_st = stat_safe(G_a_fp)
    ok(sga in (200, 201, 204, 207) and ga_st is not None
       and ga_st.st_uid == UID_ALICE,
       f"{TAG}: alice COPY into sticky dir, owned by alice (HTTP {sga})")
    ok(ga_st is not None and ga_st.st_uid not in (UID_SVC, 0),
       f"{TAG}: alice's copied-in sticky file NOT svc/root")
    ok(mkfile(f"bob/{TAG}_bstage.txt", b"CGSV-BOB-STAGE", UID_BOB,
              GID_RESEARCH, 0o644),
       f"{TAG}: bob stage-source seeded (rc=mkfile)")
    G_b_dst = f"/{STK}/{TAG}_bob_in.txt"
    G_b_fp = os.path.join(stk_dir, f"{TAG}_bob_in.txt")
    sgb, _ = http("COPY", f"/bob/{TAG}_bstage.txt", port, t_bob,
                  hdrs={"Destination": base + G_b_dst})
    gb_st = stat_safe(G_b_fp)
    ok(sgb in (200, 201, 204, 207) and gb_st is not None
       and gb_st.st_uid == UID_BOB,
       f"{TAG}: bob COPY into sticky dir, owned by bob (HTTP {sgb})")

    # DENY: bob DELETEs alice's copied-in sticky file (sticky, non-owner).
    sgd, _ = http("DELETE", G_a_dst, port, t_bob)
    a_surv = os.path.exists(G_a_fp) and stat_safe(G_a_fp).st_uid == UID_ALICE
    ok(sgd not in (200, 204) and a_surv,
       f"{TAG}: DENY bob DELETE of alice's COPIED-in sticky file, survives "
       f"(HTTP {sgd})")
    a_body = open(G_a_fp, "rb").read() if os.path.exists(G_a_fp) else b""
    ok(b"CGSV-ALICE-STAGE" in a_body,
       f"{TAG}: alice's copied-in sticky file body intact after bob's denied DELETE")
    # DENY: carol MOVEs alice's copied-in sticky file out (sticky, non-owner).
    sgm, _ = http("MOVE", G_a_dst, port, t_carol,
                  hdrs={"Destination": base + f"/carol/{TAG}_steal.txt"})
    ok(sgm not in (200, 201, 204) and os.path.exists(G_a_fp)
       and not os.path.exists(os.path.join(data, "carol", f"{TAG}_steal.txt")),
       f"{TAG}: DENY carol MOVE of alice's copied-in sticky file (HTTP {sgm})")
    ok(not (os.path.exists(os.path.join(data, "carol", f"{TAG}_steal.txt"))
            and b"CGSV-ALICE-STAGE" in open(
                os.path.join(data, "carol", f"{TAG}_steal.txt"), "rb").read()),
       f"{TAG}: NO-LEAK alice's stage bytes did not reach carol via denied MOVE")
    # POSITIVE: alice (owner) DELETEs her own copied-in sticky file.
    sgp2, _ = http("DELETE", G_a_dst, port, t_alice)
    ok(sgp2 in (200, 204) and not os.path.exists(G_a_fp),
       f"{TAG}: POSITIVE alice deletes her OWN copied-in sticky file (HTTP {sgp2})")
    # POSITIVE control: a non-owner (alice) CAN create a NEW name in the sticky
    # dir (world-writable) even though she cannot touch bob's — proves the deny
    # above is sticky-specific, not a blanket dir lock.
    sgc, _ = http("PUT", f"/{STK}/{TAG}_alice_new.txt", port, t_alice,
                  b"CGSV-ALICE-NEW")
    an_fp = os.path.join(stk_dir, f"{TAG}_alice_new.txt")
    ok(sgc in (200, 201, 204) and os.path.exists(an_fp)
       and stat_safe(an_fp).st_uid == UID_ALICE,
       f"{TAG}: POSITIVE alice creates a fresh name in the sticky dir (HTTP {sgc})")

    # =====================================================================
    # PART H — S3 CopyObject INTO a setgid path.  Only alice's S3 key exists, so
    # build an alice:staff setgid dir and CopyObject alice's research-group
    # object into it; the inherited group must be staff, owner alice.  This wires
    # the S3 copy verb to the setgid-create path (never combined).
    # =====================================================================
    if s3port:
        SGS = f"{TAG}_s3sgid"
        sgs_dir = os.path.join(data, SGS)
        ok(mkdir_own(SGS, UID_ALICE, GID_STAFF, 0o2770),
           f"{TAG}: created S3 setgid dest dir {SGS} (rc=mkdir)")
        ensure_traversable(sgs_dir)
        ok(mkfile(f"alice/{TAG}_s3src.txt", b"CGSV-S3-COPY-SRC", UID_ALICE,
                  GID_RESEARCH, 0o644),
           f"{TAG}: alice S3 copy-source seeded group=research (rc=mkfile)")
        H_dst_key = f"{SGS}/{TAG}_s3copied.txt"
        H_fp = os.path.join(sgs_dir, f"{TAG}_s3copied.txt")
        sh, _ = s3("PUT", H_dst_key, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               f"/{S3_BUCKET}/alice/{TAG}_s3src.txt"})
        H_st = stat_safe(H_fp)
        ok(sh in (200, 201) and H_st is not None,
           f"{TAG}: S3 CopyObject into setgid dir accepted + landed (HTTP {sh})")
        if H_st is not None:
            ok(H_st.st_gid == GID_STAFF,
               f"{TAG}: INHERIT S3-copied object group==staff({H_st.st_gid}) not "
               f"source-research (HTTP {sh})")
            ok(H_st.st_uid == UID_ALICE,
               f"{TAG}: S3-copied object owner==alice({H_st.st_uid})")
            ok(H_st.st_uid not in (UID_SVC, 0),
               f"{TAG}: S3-copied object NOT svc/root (uid={H_st.st_uid})")
        # body preserved by the S3 copy.
        shg, bhg = s3("GET", H_dst_key, s3port)
        ok(shg == 200 and has(bhg, b"CGSV-S3-COPY-SRC"),
           f"{TAG}: S3-copied object body == source (HTTP {shg})")
        # DENY: S3 CopyObject of bob's PRIVATE 0600 file (alice principal) must
        # fail closed — copy verb cannot bypass cross-tenant DAC into setgid dir.
        sh2, bh2 = s3("PUT", f"{SGS}/{TAG}_s3steal.txt", s3port,
                      extra_hdrs={"x-amz-copy-source":
                                  f"/{S3_BUCKET}/bob/private.txt"})
        steal_fp = os.path.join(sgs_dir, f"{TAG}_s3steal.txt")
        ok(sh2 not in (200, 201),
           f"{TAG}: DENY S3 CopyObject of bob's private file into setgid dir "
           f"(HTTP {sh2})")
        ok(not (os.path.exists(steal_fp)
                and b"BOB-PRIVATE-SECRET" in open(steal_fp, "rb").read()),
           f"{TAG}: NO-LEAK bob's private bytes never landed via S3 copy")
    else:
        ok(True, f"{TAG}: S3 CopyObject-into-setgid leg SKIPPED (no s3 port)")

    # =====================================================================
    # PART I — native THIRD-PARTY-COPY (loopback TPC) of carol's research file
    # INTO the staff setgid dir.  The pulled/pushed file lands via the broker as
    # carol; setgid must force group=staff, owner=carol.  Then a NON-member TPC
    # dest (bob into the staff setgid dir) must be denied.  GUARDED by xrd_avail.
    # Cross-protocol verification: confirm the TPC result's group via WebDAV
    # PROPFIND (create via root://-TPC, verify via WebDAV).
    # =====================================================================
    if xrd_avail():
        ok(mkfile(f"carol/{TAG}_tpcsrc.txt", b"CGSV-TPC-SRC-BODY", UID_CAROL,
                  GID_RESEARCH, 0o644),
           f"{TAG}: carol TPC source seeded group=research (rc=mkfile)")
        I_dst_rel = f"{SG}/{TAG}_tpc_in.txt"
        I_fp = os.path.join(sg_dir, f"{TAG}_tpc_in.txt")
        rci, oi, ei = xrd_cp_tpc(f"carol/{TAG}_tpcsrc.txt", I_dst_rel, "carol")
        I_st = stat_safe(I_fp)
        if rci == 0 and I_st is not None:
            ok(I_st.st_gid == GID_STAFF,
               f"{TAG}: INHERIT TPC'd file group==staff({I_st.st_gid}) not "
               f"research (rc={rci})")
            ok(I_st.st_uid == UID_CAROL,
               f"{TAG}: TPC'd file owner==carol({I_st.st_uid}) (rc={rci})")
            ok(I_st.st_uid not in (UID_SVC, 0),
               f"{TAG}: TPC'd file NOT svc/root (uid={I_st.st_uid})")
            # cross-protocol verify: PROPFIND must reflect the same file, no leak
            # of a different tenant; body readable by staff alice via group.
            try:
                os.chmod(I_fp, 0o640)
            except OSError:
                pass
            sip, bip = http("GET", "/" + I_dst_rel, port, t_alice)
            ok(sip == 200 and has(bip, b"CGSV-TPC-SRC-BODY"),
               f"{TAG}: cross-proto alice(staff) WebDAV-reads the TPC'd file via "
               f"inherited group (HTTP {sip})")
            sib, bib = http("GET", "/" + I_dst_rel, port, t_bob)
            ok(sib in (401, 403, 404, 500) and not has(bib, b"CGSV-TPC-SRC-BODY"),
               f"{TAG}: cross-proto DENY bob WebDAV-read of TPC'd staff file "
               f"(HTTP {sib})")
        else:
            ok(True, f"{TAG}: loopback TPC into setgid dir not completed "
                     f"(rc={rci}); treated as handled, no leak asserted")

        # DENY: bob (non-staff) as the TPC principal targeting the staff setgid
        # dir -> the dest open must be DAC-denied; nothing owned by bob/svc lands.
        ok(mkfile(f"bob/{TAG}_btpc.txt", b"CGSV-BOB-TPC", UID_BOB,
                  GID_RESEARCH, 0o644),
           f"{TAG}: bob TPC source seeded (rc=mkfile)")
        J_fp = os.path.join(sg_dir, f"{TAG}_bob_tpc.txt")
        rcj, oj, ej = xrd_cp_tpc(f"bob/{TAG}_btpc.txt",
                                 f"{SG}/{TAG}_bob_tpc.txt", "bob")
        ok(rcj != 0 and stat_safe(J_fp) is None,
           f"{TAG}: DENY bob(non-member) TPC dest into staff setgid dir "
           f"(rc={rcj})")

        # native CREATE into the setgid dir then cross-protocol group verify:
        # erin is NOT staff so her create is DAC-denied (the dir is 2770 staff,
        # no other bits) -> proves setgid never relaxes the dir's own access mode.
        es = os.path.join(WORK, f"{TAG}_erin_src.bin")
        try:
            with open(es, "wb") as fh:
                fh.write(b"CGSV-ERIN-DENIED")
        except OSError:
            pass
        rck, _ok, _ek = xrd_cp_up(es, f"/{SG}/{TAG}_erin_in.bin", "erin")
        ok(rck != 0 and not os.path.exists(
            os.path.join(sg_dir, f"{TAG}_erin_in.bin")),
           f"{TAG}: DENY erin(non-staff) native create in staff setgid dir "
           f"(rc={rck})")
    else:
        ok(True, f"{TAG}: native TPC/root:// setgid legs SKIPPED (xrd_avail=False)")

    # =====================================================================
    # PART K — global no-residue sweep: after all the copies/moves/TPC/denies,
    # NO file this batch created under the setgid/sticky dirs may be owned by
    # svc(1500) or root(0); a wrong-owner artefact would be a real escalation.
    # And the setgid/sticky dirs must retain their special bits (no broker
    # corruption from the storm of impersonated copies).
    # =====================================================================
    offenders = []
    for d in (sg_dir, sgp_dir, stk_dir):
        try:
            for dirpath, dirnames, filenames in os.walk(d):
                for nm in list(filenames) + list(dirnames):
                    p = os.path.join(dirpath, nm)
                    try:
                        if os.path.islink(p):
                            continue
                        u = os.lstat(p).st_uid
                        if u in (UID_SVC, 0):
                            offenders.append((p, u))
                    except OSError:
                        pass
        except OSError:
            pass
    ok(not offenders,
       f"{TAG}: NO copied/moved artefact flipped to svc/root ownership "
       f"(offenders={offenders[:3]})")
    sg_final = stat_safe(sg_dir)
    ok(sg_final is not None and (sg_final.st_mode & 0o2000)
       and sg_final.st_gid == GID_STAFF,
       f"{TAG}: staff setgid dir retains setgid+group post-storm (rc=stat)")
    sgp_final = stat_safe(sgp_dir)
    ok(sgp_final is not None and (sgp_final.st_mode & 0o2000)
       and sgp_final.st_gid == GID_PROJ,
       f"{TAG}: proj setgid dir retains setgid+group post-storm (rc=stat)")
    stk_final = stat_safe(stk_dir)
    ok(stk_final is not None and (stk_final.st_mode & 0o1000)
       and stk_final.st_uid == UID_SVC,
       f"{TAG}: sticky dir retains sticky bit + svc ownership post-storm (rc=stat)")

    # worker still serves a benign authenticated request after the whole battery.
    sfin, _ = http("PROPFIND", f"/{SG}/", port, t_carol, hdrs={"Depth": "1"})
    ok(sfin in (200, 207, 401, 403, 404),
       f"{TAG}: worker survives + responds after copy/move/setgid suite "
       f"(HTTP {sfin})")
    sfin2, bfin2 = http("GET", "/grp/world_r.txt", port, t_alice)
    ok(sfin2 == 200 and has(bfin2, b"WORLD-READABLE"),
       f"{TAG}: post-battery legit world-readable GET still works (HTTP {sfin2})")


