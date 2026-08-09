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


def run_combo_concurrent_crossproto(key, data, port, s3port):
    """CONCURRENT cross-PROTOCOL access to the SAME physical resource.  Concurrency
    and cross-protocol are each covered in isolation by earlier batches; the COMBO
    here is the two together: while one protocol mutates an inode, ANOTHER protocol
    (different code path, different worker code, possibly a still-open data-plane fd)
    touches the SAME inode under a possibly-DIFFERENT identity.  Every check asserts
    a real property of that interleaving: (i) a reader sees a CONSISTENT whole value
    (old-or-new, never torn/half/cross), (ii) the surviving inode is owned by a REAL
    mapped writer (never svc 1500 / root 0 / the wrong tenant), and (iii) per-identity
    byte patterns prove the per-worker principal + already-open fd never aliases one
    tenant's bytes onto another's request.  <=8 threads, payloads <=64 KiB."""
    TAG = "ccxp"
    ta, tb = mint(key, "alice"), mint(key, "bob")
    have_s3 = bool(s3port)
    have_root = xrd_avail()

    def rel(*parts):
        return os.path.join(data, *parts)

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def gid_of(p):
        try:
            return os.stat(p).st_gid
        except OSError:
            return -1

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def real_writer(p):
        """Inode owned by an actual mapped writer, never worker/root."""
        u = uid_of(p)
        return os.path.exists(p) and u in (UID_ALICE, UID_BOB) and u not in (UID_SVC, 0)

    # Detectable per-identity byte patterns: a whole body is a single repeated tag,
    # so a torn/spliced read is detectable as a mix of two distinct tag bytes.
    def whole(tag, n):
        unit = (tag + "-CCXP-WHOLE|").encode()
        return (unit * ((n // len(unit)) + 1))[:n]

    SZ = 48 * 1024                                   # <=64 KiB payload
    A_OLD = whole("AAAA-OLD", SZ)
    A_NEW = whole("AAAA-NEW", SZ)
    B_VAL = whole("BBBB-BOB", SZ)

    def is_whole(buf, *candidates):
        """buf is byte-identical to ONE candidate whole value (never torn/mixed)."""
        return any(buf == c for c in candidates)

    def torn_markers(buf):
        """Count how many distinct identity tags appear -> >1 means a torn/cross read."""
        seen = set()
        for tag in (b"AAAA-OLD", b"AAAA-NEW", b"BBBB-BOB"):
            if tag in buf:
                seen.add(tag)
        return seen

    # ===================================================================
    # (a) alice WebDAV-PUTs X while bob root://-reads X (X starts 0644).
    #     bob must see a CONSISTENT whole version (old or new), X stays
    #     owned by its owner, and no torn/cross bytes ever surface.
    # ===================================================================
    relx = "alice/%s_a_x.txt" % TAG
    fpx = rel("alice", "%s_a_x.txt" % TAG)
    # seed the file with the OLD whole value, mode 0644 (group/other readable so a
    # cross-protocol reader is a real read, not a DAC deny masking the race).
    st, _ = http("PUT", "/" + relx, port, ta, A_OLD)
    try:
        if os.path.exists(fpx):
            os.chmod(fpx, 0o644)
    except OSError:
        pass
    ok(st in (200, 201, 204) and uid_of(fpx) == UID_ALICE,
       "(a) seed alice/X 0644 owned by alice before cross-proto race (HTTP %s, uid=%s)"
       % (st, uid_of(fpx)))

    if have_root:
        reads = []          # whole buffers bob's root:// reads observed
        rerr = []
        torn = []

        def a_writer():
            for _ in range(4):
                try:
                    http("PUT", "/" + relx, port, ta, A_NEW)
                    http("PUT", "/" + relx, port, ta, A_OLD)
                except Exception as e:        # noqa: BLE001
                    rerr.append(repr(e))

        def a_reader(i):
            dl = os.path.join(WORK, "%s_a_dl_%d.bin" % (TAG, i))
            try:
                if os.path.exists(dl):
                    os.unlink(dl)
            except OSError:
                pass
            rc, _o, _e = xrd_cp_down("/" + relx, dl, "bob")
            if rc == 0:
                b = body_of(dl)
                reads.append(b)
                if len(torn_markers(b)) > 1:
                    torn.append(len(b))

        threads = [threading.Thread(target=a_writer)]
        threads += [threading.Thread(target=a_reader, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok(not torn,
           "(a) bob root:// read during alice WebDAV-PUT never torn/mixed (torn=%s)"
           % torn[:2])
        ok(all(is_whole(b, A_OLD, A_NEW) for b in reads),
           "(a) every successful bob read is a CONSISTENT whole version (n=%d)"
           % len(reads))
        ok(uid_of(fpx) == UID_ALICE and uid_of(fpx) not in (UID_SVC, 0),
           "(a) X stays owned by alice after concurrent cross-proto race (uid=%s)"
           % uid_of(fpx))
        ok(is_whole(body_of(fpx), A_OLD, A_NEW),
           "(a) X on disk is a whole writer value after the race (no half-write)")
    else:
        ok(True, "(a) root:// reader skipped (native client absent)")
        ok(True, "(a) consistency skipped (native client absent)")
        ok(True, "(a) ownership skipped (native client absent)")
        ok(True, "(a) disk-whole skipped (native client absent)")

    # cross-tenant twist on (a): while alice rewrites X, bob WebDAV-GET of a 0600
    # sibling secret must still be denied (the concurrent benign read must not open a
    # window that leaks a sibling secret under the racing principal).
    rels = "alice/%s_a_secret.txt" % TAG
    fps = rel("alice", "%s_a_secret.txt" % TAG)
    SECRET = b"CCXP-A-SIBLING-SECRET-" + b"S" * 256
    http("PUT", "/" + rels, port, ta, SECRET)
    try:
        if os.path.exists(fps):
            os.chmod(fps, 0o600)
    except OSError:
        pass
    leaked_a = []

    def a_secret_probe():
        for _ in range(6):
            stp, bp = http("GET", "/" + rels, port, tb)
            if stp == 200 or SECRET in (bp or b""):
                leaked_a.append(stp)

    def a_noise():
        for _ in range(6):
            http("PUT", "/" + relx, port, ta, A_NEW)

    t1 = threading.Thread(target=a_secret_probe)
    t2 = threading.Thread(target=a_noise)
    t1.start(); t2.start(); t1.join(); t2.join()
    ok(not leaked_a,
       "(a) bob's 0600-secret GET stays denied under concurrent alice write-noise")
    ok(SECRET[:24] not in body_of(fpx),
       "(a) sibling secret bytes never bleed into the raced file X")

    # ===================================================================
    # (b) alice S3-PUTs an object while alice WebDAV-GETs it: SAME identity,
    #     TWO protocols, ONE inode -> no torn read, ownership stays alice.
    # ===================================================================
    if have_s3:
        relb = "alice/%s_b_obj.txt" % TAG
        fpb = rel("alice", "%s_b_obj.txt" % TAG)
        s3("PUT", relb, s3port, data=A_OLD)         # seed
        gtorn = []
        greads = []
        gerr = []

        def b_s3_writer():
            for _ in range(4):
                try:
                    s3("PUT", relb, s3port, data=A_NEW)
                    s3("PUT", relb, s3port, data=A_OLD)
                except Exception as e:    # noqa: BLE001
                    gerr.append(repr(e))

        def b_wd_reader(i):
            stg, bg = http("GET", "/" + relb, port, ta)
            if stg == 200 and bg:
                greads.append(bg)
                if len(torn_markers(bg)) > 1:
                    gtorn.append(len(bg))

        threads = [threading.Thread(target=b_s3_writer)]
        threads += [threading.Thread(target=b_wd_reader, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok(not gtorn,
           "(b) alice WebDAV-GET during alice S3-PUT never torn (torn=%s)" % gtorn[:2])
        ok(all(is_whole(b, A_OLD, A_NEW) for b in greads),
           "(b) every WebDAV read of the S3-written object is whole (n=%d)" % len(greads))
        ok(uid_of(fpb) == UID_ALICE and uid_of(fpb) not in (UID_SVC, 0),
           "(b) cross-proto same-identity object stays alice-owned (uid=%s)"
           % uid_of(fpb))
        ok(is_whole(body_of(fpb), A_OLD, A_NEW),
           "(b) S3/WebDAV-raced object on disk is a whole value (no torn S3 write)")
        ok(not gerr, "(b) no exceptions during S3-write/WebDAV-read race (%s)" % gerr[:2])
    else:
        for _m in ("torn", "whole", "owner", "disk", "noerr"):
            ok(True, "(b) S3/WebDAV cross-proto race skipped (%s; S3 down)" % _m)

    # ===================================================================
    # (c) root:// WRITE + S3 READ on the SAME path concurrently by the SAME
    #     identity (alice) -> data consistent, no fd aliasing (a still-open
    #     root data-plane fd must not feed the S3 reader stale/foreign bytes).
    # ===================================================================
    if have_root and have_s3:
        relc = "alice/%s_c_path.bin" % TAG
        fpc = rel("alice", "%s_c_path.bin" % TAG)
        s3("PUT", relc, s3port, data=A_OLD)         # seed via S3
        lf_new = os.path.join(WORK, "%s_c_new.bin" % TAG)
        lf_old = os.path.join(WORK, "%s_c_old.bin" % TAG)
        try:
            with open(lf_new, "wb") as fh:
                fh.write(A_NEW)
            with open(lf_old, "wb") as fh:
                fh.write(A_OLD)
        except OSError:
            pass
        ctorn = []
        creads = []

        def c_root_writer():
            for _ in range(4):
                xrd_cp_up(lf_new, "/" + relc, "alice")
                xrd_cp_up(lf_old, "/" + relc, "alice")

        def c_s3_reader(i):
            stc, bc = s3("GET", relc, s3port, access_key="alice")
            if stc == 200 and bc:
                creads.append(bc)
                if len(torn_markers(bc)) > 1:
                    ctorn.append(len(bc))

        threads = [threading.Thread(target=c_root_writer)]
        threads += [threading.Thread(target=c_s3_reader, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok(not ctorn,
           "(c) S3 read during root:// write never torn/fd-aliased (torn=%s)"
           % ctorn[:2])
        ok(all(is_whole(b, A_OLD, A_NEW) for b in creads),
           "(c) every S3 read of root-written path is a whole value (n=%d)"
           % len(creads))
        ok(B_VAL not in b"".join(creads),
           "(c) no foreign-tenant bytes ever fed to the S3 reader (no fd aliasing)")
        ok(uid_of(fpc) == UID_ALICE and uid_of(fpc) not in (UID_SVC, 0),
           "(c) root-write/S3-read same path stays alice-owned (uid=%s)" % uid_of(fpc))
        ok(is_whole(body_of(fpc), A_OLD, A_NEW),
           "(c) final inode is a whole writer value (root data-plane fd not torn)")
    else:
        for _m in ("torn", "whole", "noforeign", "owner", "disk"):
            ok(True, "(c) root-write/S3-read race skipped (%s; deps down)" % _m)

    # ===================================================================
    # (d) alice writes /pub/shared via WebDAV while bob writes it via root://
    #     (pub is 0777) -> final file owned by ONE real writer (never svc/root),
    #     content is exactly one writer's WHOLE value (no interleaved bytes).
    # ===================================================================
    reld = "pub/%s_d_shared.bin" % TAG
    fpd = rel("pub", "%s_d_shared.bin" % TAG)
    lf_bob = os.path.join(WORK, "%s_d_bob.bin" % TAG)
    if have_root:
        try:
            with open(lf_bob, "wb") as fh:
                fh.write(B_VAL)
        except OSError:
            pass
    derr = []

    def d_wd_alice():
        for _ in range(5):
            try:
                http("PUT", "/" + reld, port, ta, A_NEW)
            except Exception as e:        # noqa: BLE001
                derr.append(repr(e))

    def d_root_bob():
        for _ in range(5):
            xrd_cp_up(lf_bob, "/" + reld, "bob")

    dthreads = [threading.Thread(target=d_wd_alice)]
    if have_root:
        dthreads.append(threading.Thread(target=d_root_bob))
    for t in dthreads:
        t.start()
    for t in dthreads:
        t.join()

    if os.path.exists(fpd):
        du = uid_of(fpd)
        db = body_of(fpd)
        ok(du in (UID_ALICE, UID_BOB) and du not in (UID_SVC, 0),
           "(d) pub/shared raced by two protocols owned by ONE real writer (uid=%s)" % du)
        cands = [A_NEW] + ([B_VAL] if have_root else [])
        ok(is_whole(db, *cands),
           "(d) pub/shared content is exactly one writer's WHOLE value (no interleave)")
        ok(len(torn_markers(db)) <= 1,
           "(d) pub/shared never carries two writers' bytes spliced together")
        # owner must MATCH the winning content (no svc inode wearing a writer's bytes).
        if db == A_NEW:
            ok(du == UID_ALICE, "(d) winner=alice content -> alice-owned (uid=%s)" % du)
        elif have_root and db == B_VAL:
            ok(du == UID_BOB, "(d) winner=bob content -> bob-owned (uid=%s)" % du)
        else:
            ok(False, "(d) pub/shared content is not a recognized whole writer value")
    else:
        ok(False, "(d) pub/shared file missing after two-protocol storm")
        ok(False, "(d) content skipped (missing)")
        ok(False, "(d) splice skipped (missing)")
        ok(False, "(d) owner-content-match skipped (missing)")
    ok(not derr, "(d) no exceptions during WebDAV/root pub/shared race (%s)" % derr[:2])

    # ===================================================================
    # (e) concurrent reads of DIFFERENT tenants' files via DIFFERENT protocols:
    #     each thread must get ITS OWN tenant's bytes, ZERO cross-contamination.
    #     This is the core impersonation isolation property under cross-proto load.
    # ===================================================================
    # plant alice/bob 0644 files with per-tenant whole bodies.
    rel_ae = "alice/%s_e_alice.txt" % TAG
    rel_be = "bob/%s_e_bob.txt" % TAG
    fp_ae, fp_be = rel("alice", "%s_e_alice.txt" % TAG), rel("bob", "%s_e_bob.txt" % TAG)
    http("PUT", "/" + rel_ae, port, ta, A_NEW)
    http("PUT", "/" + rel_be, port, tb, B_VAL)
    for fp in (fp_ae, fp_be):
        try:
            if os.path.exists(fp):
                os.chmod(fp, 0o644)
        except OSError:
            pass
    ok(uid_of(fp_ae) == UID_ALICE and uid_of(fp_be) == UID_BOB,
       "(e) per-tenant fixtures owned correctly before cross-read storm")

    cross = []          # records (who, wrong-bytes-seen)
    mism = []           # records (who, status, len)

    def e_wd_alice():
        for _ in range(4):
            ste, be = http("GET", "/" + rel_ae, port, ta)
            if ste == 200:
                if be != A_NEW:
                    mism.append(("wd-alice", ste, len(be or b"")))
                if B_VAL[:16] in (be or b""):
                    cross.append(("wd-alice", "saw-bob"))

    def e_s3_alice():
        if not have_s3:
            return
        for _ in range(4):
            ste, be = s3("GET", rel_ae.replace("alice/", "alice/"), s3port,
                         access_key="alice")
            if ste == 200:
                if be != A_NEW:
                    mism.append(("s3-alice", ste, len(be or b"")))
                if B_VAL[:16] in (be or b""):
                    cross.append(("s3-alice", "saw-bob"))

    def e_wd_bob():
        for _ in range(4):
            ste, be = http("GET", "/" + rel_be, port, tb)
            if ste == 200:
                if be != B_VAL:
                    mism.append(("wd-bob", ste, len(be or b"")))
                if A_NEW[:16] in (be or b""):
                    cross.append(("wd-bob", "saw-alice"))

    def e_root_bob():
        if not have_root:
            return
        for i in range(3):
            dl = os.path.join(WORK, "%s_e_root_%d.bin" % (TAG, i))
            try:
                if os.path.exists(dl):
                    os.unlink(dl)
            except OSError:
                pass
            rc, _o, _e = xrd_cp_down("/" + rel_be, dl, "bob")
            if rc == 0:
                be = body_of(dl)
                if be != B_VAL:
                    mism.append(("root-bob", rc, len(be)))
                if A_NEW[:16] in be:
                    cross.append(("root-bob", "saw-alice"))

    ethreads = [
        threading.Thread(target=e_wd_alice),
        threading.Thread(target=e_wd_bob),
        threading.Thread(target=e_s3_alice),
        threading.Thread(target=e_root_bob),
    ]
    for t in ethreads:
        t.start()
    for t in ethreads:
        t.join()

    ok(not cross,
       "(e) cross-protocol concurrent reads: ZERO cross-tenant contamination (%s)"
       % cross[:3])
    ok(not mism,
       "(e) every reader got exactly ITS OWN tenant's whole bytes (mismatch=%s)"
       % mism[:3])
    # explicit per-leg controls so a blanket failure cannot false-pass.
    ste, be = http("GET", "/" + rel_ae, port, ta)
    ok(ste == 200 and be == A_NEW and B_VAL[:16] not in be,
       "(e) WebDAV alice read = alice bytes, no bob bytes (HTTP %s)" % ste)
    ste, be = http("GET", "/" + rel_be, port, tb)
    ok(ste == 200 and be == B_VAL and A_NEW[:16] not in be,
       "(e) WebDAV bob read = bob bytes, no alice bytes (HTTP %s)" % ste)
    if have_s3:
        ste, be = s3("GET", rel_ae, s3port, access_key="alice")
        ok(ste == 200 and be == A_NEW and B_VAL[:16] not in be,
           "(e) S3 alice read = alice bytes, no bob bytes (HTTP %s)" % ste)
    else:
        ok(True, "(e) S3 alice-read control skipped (S3 down)")
    if have_root:
        dl = os.path.join(WORK, "%s_e_ctrl.bin" % TAG)
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + rel_be, dl, "bob")
        ok(rc == 0 and body_of(dl) == B_VAL and A_NEW[:16] not in body_of(dl),
           "(e) root:// bob read = bob bytes, no alice bytes (rc=%s)" % rc)
    else:
        ok(True, "(e) root:// bob-read control skipped (native client absent)")

    # cross-tenant DENY under the same concurrent storm: bob reading alice's 0600
    # secret via WebDAV while the (e) storm runs must STILL be denied (isolation is
    # not just "right bytes" but also "no access where DAC forbids it").
    http("PUT", "/" + rels, port, ta, SECRET)
    try:
        if os.path.exists(fps):
            os.chmod(fps, 0o600)
    except OSError:
        pass
    eleak = []

    def e_storm_noise():
        for _ in range(6):
            http("GET", "/" + rel_ae, port, ta)
            if have_s3:
                s3("GET", rel_be.replace("bob/", "bob/"), s3port, access_key="alice")

    def e_secret_probe():
        for _ in range(6):
            stp, bp = http("GET", "/" + rels, port, tb)
            if stp == 200 or SECRET[:24] in (bp or b""):
                eleak.append(stp)

    t1 = threading.Thread(target=e_storm_noise)
    t2 = threading.Thread(target=e_secret_probe)
    t1.start(); t2.start(); t1.join(); t2.join()
    ok(not eleak,
       "(e) bob's 0600-secret stays denied under concurrent cross-proto read storm")

    # positive control for the deny: alice CAN read her own secret (the deny above is
    # a real DAC deny, not a server-wide outage that would false-pass the negative).
    sta, ba = http("GET", "/" + rels, port, ta)
    ok(sta == 200 and SECRET[:24] in (ba or b""),
       "(e) control: alice reads her own secret post-storm (HTTP %s)" % sta)

    # ===================================================================
    # (f) WORKER-SURVIVAL after all the cross-proto concurrency: a follow-up legit
    #     op across each protocol still works AND lands with correct ownership (the
    #     per-worker principal was fully reset; no stale fd/identity wedged a worker).
    # ===================================================================
    relf = "alice/%s_f_after.txt" % TAG
    fpf = rel("alice", "%s_f_after.txt" % TAG)
    stf, _ = http("PUT", "/" + relf, port, ta, b"CCXP-AFTER-WEBDAV\n")
    ok(stf in (200, 201, 204) and uid_of(fpf) == UID_ALICE,
       "(f) survival: WebDAV PUT works + alice-owned after the storm (HTTP %s, uid=%s)"
       % (stf, uid_of(fpf)))
    stf, bf = http("GET", "/" + relf, port, ta)
    ok(stf == 200 and bf == b"CCXP-AFTER-WEBDAV\n",
       "(f) survival: WebDAV GET returns correct whole bytes (HTTP %s)" % stf)

    if have_s3:
        stf, _ = s3("PUT", "alice/%s_f_s3.txt" % TAG, s3port, data=b"CCXP-AFTER-S3\n")
        fpf3 = rel("alice", "%s_f_s3.txt" % TAG)
        ok(stf in (200, 201) and uid_of(fpf3) == UID_ALICE,
           "(f) survival: S3 PUT works + alice-owned after the storm (HTTP %s, uid=%s)"
           % (stf, uid_of(fpf3)))
    else:
        ok(True, "(f) survival S3 skipped (S3 down)")

    if have_root:
        rc, out, _e = xrd_fs(["stat", "/" + relf], "alice")
        ok(rc == 0, "(f) survival: root:// stat works after the storm (rc=%s)" % rc)
        # and a fresh root write is alice-owned (principal fully reset).
        lf = os.path.join(WORK, "%s_f_root.bin" % TAG)
        try:
            with open(lf, "wb") as fh:
                fh.write(b"CCXP-AFTER-ROOT\n")
        except OSError:
            pass
        rc, _o, _e = xrd_cp_up(lf, "/alice/%s_f_root.bin" % TAG, "alice")
        fpr = rel("alice", "%s_f_root.bin" % TAG)
        ok(rc == 0 and uid_of(fpr) == UID_ALICE and uid_of(fpr) not in (UID_SVC, 0),
           "(f) survival: root:// write works + alice-owned (rc=%s, uid=%s)"
           % (rc, uid_of(fpr)))
    else:
        ok(True, "(f) survival root:// stat skipped (native client absent)")
        ok(True, "(f) survival root:// write skipped (native client absent)")

    # final cross-tenant invariant: none of the storm created any tenant-crossed
    # residue — alice's tree carries no bob-owned files and vice-versa, and no svc
    # residue under the alice/bob trees from a leaked worker principal.
    svc_residue = []
    for base, want in (("alice", UID_ALICE), ("bob", UID_BOB)):
        d = rel(base)
        try:
            for nm in os.listdir(d):
                if not nm.startswith(TAG):
                    continue
                fp = os.path.join(d, nm)
                u = uid_of(fp)
                if u in (UID_SVC, 0):
                    svc_residue.append((base, nm, u))
        except OSError:
            pass
    ok(not svc_residue,
       "(f) no svc/root-owned residue under tenant trees after cross-proto storm (%s)"
       % svc_residue[:3])


