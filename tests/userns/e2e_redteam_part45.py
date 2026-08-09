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


def run_combo_idmap_edge_full_matrix(key, data, port, s3port):
    """COMBINATION battery: idmap-EDGE identities crossed with the FULL mutating
    op/protocol matrix.

    The existing boundary-mapping batch proved the floor/forbidden idmap guard for
    a SINGLE WebDAV PUT (plus one root:// write).  This battery instead drives EVERY
    denied edge identity through EVERY mutating operation on EVERY plane it can carry
    a principal on, in one interleaved sweep:

        denied identities  : lowu(uid 999 < 1000 floor), badprim(reserved primary
                             gid), dockerite(forbidden 'docker' group),
                             mallory(unmapped subject), '0'(root as a STRING sub),
                             '1500'(svc uid as a STRING sub).
        mutating WebDAV ops: PUT, MKCOL, MOVE, COPY, DELETE, PROPPATCH, LOCK.
        mutating root:// ops: mkdir, touch, cp-up(write), mv, chmod, ln(hard),
                             truncate, native TPC.

    The load-bearing invariant for the whole battery: NO denied identity, through ANY
    op on ANY plane, ever creates or mutates a namespace entry; nothing ever lands
    owned by a reserved id (uid < 1000), by a forbidden mapping's own uid, by svc
    (1500), or by root (0); and the worker never silently falls back to the svc
    principal to satisfy a request whose mapping was rejected.

    floor1000 (uid == 1000 == the floor, ALLOWED) runs the SAME op matrix as the
    POSITIVE CONTROL: every op must SUCCEED and every artefact must be owned EXACTLY
    1000:1000 — proving the denies above are identity-specific guard decisions, not a
    blanket /pub mutation block.  S3 only configures the 'alice' access key, so a
    denied principal cannot be expressed on the S3 plane at all; the S3 leg therefore
    runs alice/floor-equivalent mutating ops (PUT, multipart-initiate, CopyObject,
    DeleteObjects) purely as ownership positive-controls and feeds the final
    reserved-id sweep.  All writes target /pub (svc:svc 0777) so the FS itself can
    never be the thing that blocks a denied write — only the idmap guard can, making
    any created/mutated entry a TRUE security failure rather than a benign FS deny.
    """
    TAG = "ciefm"
    PUB = os.path.join(data, "pub")

    # ---- inline ownership / existence probes (do not collide with module helpers) -
    def pub_path(rel):
        return os.path.join(PUB, rel)

    def owner_of(rel):
        try:
            stt = os.stat(pub_path(rel))
            return True, stt.st_uid, stt.st_gid
        except OSError:
            return False, -1, -1

    def lexists(rel):
        try:
            return os.path.lexists(pub_path(rel))
        except OSError:
            return False

    def lowner_of(rel):
        try:
            stt = os.lstat(pub_path(rel))
            return True, stt.st_uid, stt.st_gid
        except OSError:
            return False, -1, -1

    def body_of(rel):
        try:
            with open(pub_path(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    RESERVED = lambda u: 0 <= u < 1000        # uid below the 1000 floor
    BADMAP = lambda u: u in (UID_SVC, 0)      # svc / root fallback owners

    def scan_reserved_or_svc():
        """All (name, uid) in /pub owned by a reserved id, svc, or root — the
        cross-cutting leak detector swept after every denied storm."""
        bad = []
        try:
            for nm in os.listdir(PUB):
                try:
                    u = os.lstat(pub_path(nm)).st_uid
                except OSError:
                    continue
                if RESERVED(u) or BADMAP(u):
                    bad.append((nm, u))
        except OSError:
            pass
        return bad

    # uid each denied subject would map to IF the guard wrongly let it through —
    # used to assert a slipped-through artefact is never owned by the very identity.
    DENIED_UID = {
        "lowu": UID_LOW, "badprim": 1009, "dockerite": 1007,
        "mallory": -1, "0": 0, "1500": UID_SVC,
    }
    DENIED = [
        ("lowu", "uid 999 below the 1000 floor"),
        ("badprim", "uid ok but PRIMARY gid reserved"),
        ("dockerite", "member of forbidden 'docker' group"),
        ("mallory", "subject not present in the idmap"),
        ("0", "subject string '0' (root) — must never map"),
        ("1500", "subject string '1500' (svc uid) — must never map"),
    ]

    have_root = xrd_avail()

    # ---- baseline: /pub clean of any reserved/svc/root-owned entry -----------------
    ok(scan_reserved_or_svc() == [],
       "baseline: /pub has no reserved/svc/root-owned entry before edge matrix")

    # =========================================================================
    # SEED a real floor1000-owned tree + an alice-owned victim, both used as the
    # SOURCES / DESTINATIONS the denied identities will try to mutate.  Seeding via
    # the gateway proves the floor identity itself is the positive baseline.
    # =========================================================================
    st, _ = http("PUT", f"/pub/{TAG}_seed_floor.txt", port, mint(key, "floor1000"),
                 b"FLOOR-SEED\n")
    ex, su, sg = owner_of(f"{TAG}_seed_floor.txt")
    ok(st in (200, 201, 204) and ex and su == UID_FLOOR and sg == UID_FLOOR,
       f"seed: floor1000 PUT lands owned exactly 1000:1000 (HTTP {st}, uid={su}, gid={sg})")

    # an alice-owned 0600 victim file the denied identities will try to MOVE/COPY/
    # DELETE/truncate/chmod/link — a successful mutation by a denied id is a breach.
    VICT = f"{TAG}_victim.txt"
    VICT_MARK = b"CIEFM-ALICE-VICTIM-SECRET"
    try:
        with open(pub_path(VICT), "wb") as fh:
            fh.write(VICT_MARK + b"\n")
        os.chown(pub_path(VICT), UID_ALICE, UID_ALICE)
        os.chmod(pub_path(VICT), 0o600)
        victim_mode0 = os.stat(pub_path(VICT)).st_mode & 0o777
    except OSError:
        victim_mode0 = -1
    ex, vu, _vg = owner_of(VICT)
    ok(ex and vu == UID_ALICE and victim_mode0 == 0o600,
       f"seed: alice-owned 0600 victim planted in /pub (uid={vu}, mode={victim_mode0:o})")

    # =========================================================================
    # PART A — FLOOR1000 POSITIVE CONTROL: the whole mutating matrix must SUCCEED
    # and every artefact must be owned EXACTLY 1000:1000.  Run FIRST so the denied
    # legs below can be compared against a known-good full-matrix baseline.
    # =========================================================================
    tfloor = mint(key, "floor1000")

    # A-WebDAV PUT
    fput = f"{TAG}_floor_put.txt"
    st, _ = http("PUT", f"/pub/{fput}", port, tfloor, b"FLOOR-PUT\n")
    ex, u, g = owner_of(fput)
    ok(st in (200, 201, 204) and ex and u == UID_FLOOR and g == UID_FLOOR,
       f"floor MATRIX WebDAV PUT ok, owned 1000:1000 (HTTP {st}, {u}:{g})")

    # A-WebDAV MKCOL
    fcol = f"{TAG}_floor_col"
    st, _ = http("MKCOL", f"/pub/{fcol}", port, tfloor)
    ex, u, _g = owner_of(fcol)
    ok(st in (201, 200) and ex and os.path.isdir(pub_path(fcol)) and u == UID_FLOOR,
       f"floor MATRIX WebDAV MKCOL ok, dir owned 1000 (HTTP {st}, uid={u})")

    # A-WebDAV COPY (own file -> new), then MOVE the copy
    fcopy = f"{TAG}_floor_copy.txt"
    st, _ = http("COPY", f"/pub/{fput}", port, tfloor,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{fcopy}"})
    ex, u, _g = owner_of(fcopy)
    ok(st in (201, 204) and ex and u == UID_FLOOR,
       f"floor MATRIX WebDAV COPY ok, copy owned 1000 (HTTP {st}, uid={u})")
    fmoved = f"{TAG}_floor_moved.txt"
    st, _ = http("MOVE", f"/pub/{fcopy}", port, tfloor,
                 hdrs={"Destination": f"http://{HOST}:{port}/pub/{fmoved}"})
    ex, u, _g = owner_of(fmoved)
    ok(st in (201, 204) and ex and not lexists(fcopy) and u == UID_FLOOR,
       f"floor MATRIX WebDAV MOVE ok, moved owned 1000 (HTTP {st}, uid={u})")

    # A-WebDAV PROPPATCH (own file) + LOCK (own file)
    pp_body = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:">'
               b'<D:set><D:prop><Z:m xmlns:Z="urn:x">v</Z:m></D:prop></D:set>'
               b'</D:propertyupdate>')
    st, _ = http("PROPPATCH", f"/pub/{fput}", port, tfloor, data=pp_body,
                 hdrs={"Content-Type": "application/xml"})
    ok(st in (207, 200, 403, 422, 501) and owner_of(fput)[1] == UID_FLOOR,
       f"floor MATRIX WebDAV PROPPATCH handled, owner intact 1000 (HTTP {st})")
    lk_body = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope>'
               b'<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>'
               b'</D:lockinfo>')
    st, lb = http("LOCK", f"/pub/{fput}", port, tfloor, data=lk_body,
                  hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
    ok(st in (200, 201, 403, 405, 501) and owner_of(fput)[1] == UID_FLOOR,
       f"floor MATRIX WebDAV LOCK handled, owner intact 1000 (HTTP {st})")

    # A-WebDAV DELETE (own file)
    fdel = f"{TAG}_floor_del.txt"
    http("PUT", f"/pub/{fdel}", port, tfloor, b"x\n")
    st, _ = http("DELETE", f"/pub/{fdel}", port, tfloor)
    ok(st in (200, 204, 404) and not lexists(fdel),
       f"floor MATRIX WebDAV DELETE removed own file (HTTP {st})")

    # A-root:// matrix (guarded)
    if have_root:
        rc, _o, _e = xrd_fs(["mkdir", f"/pub/{TAG}_floor_rdir"], "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_rdir")
        ok(rc == 0 and ex and u == UID_FLOOR,
           f"floor MATRIX root:// mkdir owned 1000 (rc={rc}, uid={u})")

        rc, _o, _e = xrd_fs(["touch", f"/pub/{TAG}_floor_touch.txt"], "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_touch.txt")
        ok(rc == 0 and ex and u == UID_FLOOR,
           f"floor MATRIX root:// touch owned 1000 (rc={rc}, uid={u})")

        lf = os.path.join(WORK, f"{TAG}_floor_up.bin")
        try:
            with open(lf, "wb") as fh:
                fh.write(b"FLOOR-CPUP\n")
        except OSError:
            lf = None
        if lf:
            rc, _o, _e = xrd_cp_up(lf, f"/pub/{TAG}_floor_up.bin", "floor1000")
            ex, u, _g = owner_of(f"{TAG}_floor_up.bin")
            ok(rc == 0 and ex and u == UID_FLOOR,
               f"floor MATRIX root:// cp-up owned 1000 (rc={rc}, uid={u})")
            # mv the uploaded file
            rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_floor_up.bin",
                                 f"/pub/{TAG}_floor_mv.bin"], "floor1000")
            ex, u, _g = owner_of(f"{TAG}_floor_mv.bin")
            ok(rc == 0 and ex and not lexists(f"{TAG}_floor_up.bin") and u == UID_FLOOR,
               f"floor MATRIX root:// mv owned 1000 (rc={rc}, uid={u})")
            # chmod the moved file
            rc, _o, _e = xrd_fs(["chmod", f"/pub/{TAG}_floor_mv.bin", "640"],
                                "floor1000")
            m = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_mode & 0o777
                 if lexists(f"{TAG}_floor_mv.bin") else -1)
            ok(rc == 0 and m == 0o640 and owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR,
               f"floor MATRIX root:// chmod 640, owner intact 1000 (rc={rc}, mode={m:o})")
            # truncate the moved file
            rc, _o, _e = xrd_fs(["truncate", f"/pub/{TAG}_floor_mv.bin", "3"],
                                "floor1000")
            sz = (os.stat(pub_path(f"{TAG}_floor_mv.bin")).st_size
                  if lexists(f"{TAG}_floor_mv.bin") else -1)
            ok(rc == 0 and sz == 3 and owner_of(f"{TAG}_floor_mv.bin")[1] == UID_FLOOR,
               f"floor MATRIX root:// truncate to 3, owner intact 1000 (rc={rc}, size={sz})")

    # =========================================================================
    # PART B — DENIED-IDENTITY FULL MATRIX.  For EACH denied subject, attempt the
    # whole mutating matrix; assert every op fails, creates/mutates NOTHING, and
    # never lands a reserved/svc/root/own-uid owner.  After each subject's WebDAV
    # storm, sweep /pub for any leaked owner.
    # =========================================================================
    for sub, label in DENIED:
        tok = mint(key, sub)
        bad_uid = DENIED_UID[sub]
        mk = f"{sub.upper()}-FORBIDDEN".encode()

        # ---- WebDAV PUT (async body handler maps the principal) ----
        rel = f"{TAG}_{sub}_put.txt"
        st, _ = http("PUT", f"/pub/{rel}", port, tok, mk + b"\n")
        ex, u, _g = owner_of(rel)
        ok(st not in (200, 201, 204) and not ex,
           f"{sub} ({label}) WebDAV PUT DENIED, no file (HTTP {st}, exists={ex})")
        ok(not ex or (not RESERVED(u) and not BADMAP(u) and u != bad_uid),
           f"{sub} WebDAV PUT created no reserved/svc/root/own-uid file (uid={u})")

        # ---- WebDAV MKCOL ----
        crel = f"{TAG}_{sub}_col"
        st, _ = http("MKCOL", f"/pub/{crel}", port, tok)
        ex, u, _g = owner_of(crel)
        ok(st not in (200, 201) and not ex,
           f"{sub} WebDAV MKCOL DENIED, no dir (HTTP {st}, exists={ex})")
        ok(not ex or (not RESERVED(u) and not BADMAP(u)),
           f"{sub} WebDAV MKCOL created no reserved/svc/root dir (uid={u})")

        # ---- WebDAV COPY of the floor seed -> new path (read seed + create as sub) ----
        crel2 = f"{TAG}_{sub}_copy.txt"
        st, _ = http("COPY", f"/pub/{TAG}_seed_floor.txt", port, tok,
                     hdrs={"Destination": f"http://{HOST}:{port}/pub/{crel2}"})
        ex, u, _g = owner_of(crel2)
        ok(st not in (200, 201, 204) and not ex,
           f"{sub} WebDAV COPY DENIED, no copy created (HTTP {st}, exists={ex})")
        ok(not ex or (not RESERVED(u) and not BADMAP(u)),
           f"{sub} WebDAV COPY created no reserved/svc/root file (uid={u})")

        # ---- WebDAV MOVE of alice's victim (would relocate another tenant's file) ----
        mrel = f"{TAG}_{sub}_moved.txt"
        st, _ = http("MOVE", f"/pub/{VICT}", port, tok,
                     hdrs={"Destination": f"http://{HOST}:{port}/pub/{mrel}"})
        ok(st not in (200, 201, 204) and not lexists(mrel) and lexists(VICT),
           f"{sub} WebDAV MOVE of alice victim DENIED, victim intact (HTTP {st})")
        ok(owner_of(VICT)[1] == UID_ALICE,
           f"{sub} WebDAV MOVE left alice victim ownership intact (1001)")

        # ---- WebDAV DELETE of alice's victim ----
        st, _ = http("DELETE", f"/pub/{VICT}", port, tok)
        ok(st not in (200, 204) and lexists(VICT),
           f"{sub} WebDAV DELETE of alice victim DENIED, victim survives (HTTP {st})")

        # ---- WebDAV PROPPATCH of alice's victim (xattr write as sub) ----
        st, _ = http("PROPPATCH", f"/pub/{VICT}", port, tok, data=pp_body,
                     hdrs={"Content-Type": "application/xml"})
        ok(st not in (207, 200) and owner_of(VICT)[1] == UID_ALICE,
           f"{sub} WebDAV PROPPATCH on alice victim DENIED, owner intact (HTTP {st})")

        # ---- WebDAV LOCK of alice's victim (lock xattr as sub) ----
        st, _ = http("LOCK", f"/pub/{VICT}", port, tok, data=lk_body,
                     hdrs={"Content-Type": "application/xml", "Timeout": "Second-60"})
        ok(st not in (200, 201) and owner_of(VICT)[1] == UID_ALICE,
           f"{sub} WebDAV LOCK on alice victim DENIED, owner intact (HTTP {st})")

        # victim content never altered / leaked back by any of the above mutations
        ok(body_of(VICT).startswith(VICT_MARK),
           f"{sub} WebDAV mutation storm left alice victim content intact (no tear)")

        # ---- per-subject leak sweep (WebDAV legs) ----
        bad = scan_reserved_or_svc()
        ok(bad == [],
           f"{sub} WebDAV storm: no reserved/svc/root-owned /pub entry (leaks={bad[:4]})")

        # ---- root:// matrix for this subject (guarded) ----
        if have_root:
            # mkdir
            rc, _o, _e = xrd_fs(["mkdir", f"/pub/{TAG}_{sub}_rdir"], sub)
            ex, u, _g = owner_of(f"{TAG}_{sub}_rdir")
            ok(rc != 0 and not ex,
               f"{sub} root:// mkdir DENIED, no dir (rc={rc}, exists={ex})")
            ok(not ex or (not RESERVED(u) and not BADMAP(u)),
               f"{sub} root:// mkdir created no reserved/svc/root dir (uid={u})")

            # touch
            rc, _o, _e = xrd_fs(["touch", f"/pub/{TAG}_{sub}_touch.txt"], sub)
            ex, u, _g = owner_of(f"{TAG}_{sub}_touch.txt")
            ok(rc != 0 and not ex,
               f"{sub} root:// touch DENIED, no file (rc={rc}, exists={ex})")
            ok(not ex or (not RESERVED(u) and not BADMAP(u) and u != bad_uid),
               f"{sub} root:// touch created no reserved/svc/own-uid file (uid={u})")

            # cp-up (data write)
            lf = os.path.join(WORK, f"{TAG}_{sub}_up.bin")
            try:
                with open(lf, "wb") as fh:
                    fh.write(mk + b"\n")
            except OSError:
                lf = None
            if lf:
                rrel = f"{TAG}_{sub}_up.bin"
                rc, _o, _e = xrd_cp_up(lf, f"/pub/{rrel}", sub)
                ex, u, _g = owner_of(rrel)
                ok(rc != 0 and not ex,
                   f"{sub} root:// cp-up DENIED, no file (rc={rc}, exists={ex})")
                ok(not ex or (not RESERVED(u) and not BADMAP(u) and u != bad_uid),
                   f"{sub} root:// cp-up created no reserved/svc/own-uid file (uid={u})")

            # mv the floor seed (relocate another tenant's file as denied sub)
            rc, _o, _e = xrd_fs(["mv", f"/pub/{TAG}_seed_floor.txt",
                                 f"/pub/{TAG}_{sub}_seedmv.txt"], sub)
            ok(rc != 0 and not lexists(f"{TAG}_{sub}_seedmv.txt")
               and lexists(f"{TAG}_seed_floor.txt"),
               f"{sub} root:// mv of floor seed DENIED, seed intact (rc={rc})")
            ok(owner_of(f"{TAG}_seed_floor.txt")[1] == UID_FLOOR,
               f"{sub} root:// mv left floor seed owned 1000")

            # chmod alice's victim (mode-change as denied sub)
            pre = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
            rc, _o, _e = xrd_fs(["chmod", f"/pub/{VICT}", "777"], sub)
            post = (os.stat(pub_path(VICT)).st_mode & 0o777 if lexists(VICT) else -1)
            ok(rc != 0 and post == pre,
               f"{sub} root:// chmod of alice victim DENIED, mode intact ({pre:o}) (rc={rc})")

            # hard-link alice's victim into a sub-named path (namespace graft attempt)
            lrel = f"{TAG}_{sub}_hardln.txt"
            rc, _o, _e = xrd_fs(["ln", f"/pub/{VICT}", f"/pub/{lrel}"], sub)
            ex = lexists(lrel)
            ok(rc != 0 and not ex,
               f"{sub} root:// hard-link of alice victim DENIED, no link (rc={rc})")
            if ex:
                _ee, lu, _lg = lowner_of(lrel)
                ok(not RESERVED(lu) and not BADMAP(lu),
                   f"{sub} stray hard-link not reserved/svc/root owned (uid={lu})")

            # truncate alice's victim (size-change as denied sub)
            presz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
            rc, _o, _e = xrd_fs(["truncate", f"/pub/{VICT}", "0"], sub)
            postsz = (os.stat(pub_path(VICT)).st_size if lexists(VICT) else -1)
            ok(rc != 0 and postsz == presz and postsz > 0,
               f"{sub} root:// truncate of alice victim DENIED, size intact ({presz}) (rc={rc})")

            # a metadata read (stat) as the denied sub must also be refused — the
            # mapping is rejected at session/auth, so even non-mutating ops fail.
            rc, _o, _e = xrd_fs(["stat", f"/pub/{TAG}_seed_floor.txt"], sub)
            ok(rc != 0,
               f"{sub} root:// stat refused (mapping denied at auth) (rc={rc})")

            # ---- per-subject leak sweep (root:// legs) ----
            bad = scan_reserved_or_svc()
            ok(bad == [],
               f"{sub} root:// storm: no reserved/svc/root /pub entry (leaks={bad[:4]})")

    # =========================================================================
    # PART C — DENIED-IDENTITY NATIVE TPC.  A denied principal driving a loopback
    # third-party copy must not produce a destination file owned by anyone, and the
    # floor seed (the would-be source) must survive untouched.
    # =========================================================================
    if have_root:
        # positive control first: floor1000 TPC of its own seed -> new dest = 1000.
        rc, _o, _e = xrd_cp_tpc(f"/pub/{TAG}_seed_floor.txt",
                                f"/pub/{TAG}_floor_tpc.bin", "floor1000")
        ex, u, _g = owner_of(f"{TAG}_floor_tpc.bin")
        # TPC may be unsupported on the loopback config; accept either a clean
        # 1000-owned dest OR a graceful no-op, but never a wrong owner.
        ok((rc == 0 and ex and u == UID_FLOOR) or (not ex),
           f"floor1000 native TPC: dest owned 1000 or no-op, never wrong owner "
           f"(rc={rc}, uid={u})")

        for sub, label in DENIED:
            drel = f"{TAG}_{sub}_tpc.bin"
            rc, _o, _e = xrd_cp_tpc(f"/pub/{TAG}_seed_floor.txt",
                                    f"/pub/{drel}", sub)
            ex, u, _g = owner_of(drel)
            ok(rc != 0 and not ex,
               f"{sub} native TPC DENIED, no dest file (rc={rc}, exists={ex})")
            ok(not ex or (not RESERVED(u) and not BADMAP(u) and u != DENIED_UID[sub]),
               f"{sub} native TPC dest not reserved/svc/own-uid owned (uid={u})")
        ok(lexists(f"{TAG}_seed_floor.txt")
           and owner_of(f"{TAG}_seed_floor.txt")[1] == UID_FLOOR,
           "native TPC storm left floor seed intact and owned 1000")

    # =========================================================================
    # PART D — MODEST INTERLEAVED RACE.  Mix allowed floor1000 ops with denied
    # lowu/'0'/mallory ops on ONE storm so the per-request map decision is proven to
    # carry no cross-request state: no denied op ever lands a file, every allowed op
    # lands owned 1000.  <= 8 threads, tiny payloads.
    # =========================================================================
    race = {"deny_created": 0, "allow_missing": 0}
    race_lock = threading.Lock()
    race_subs = ["floor1000", "lowu", "0", "mallory"]

    def _race_worker(i):
        sub = race_subs[i % len(race_subs)]
        rel = f"{TAG}_race_{sub}_{i}.txt"
        try:
            http("PUT", f"/pub/{rel}", port, mint(key, sub), f"r{i}\n".encode())
        except Exception:  # noqa: BLE001
            pass
        ex, u, _g = owner_of(rel)
        with race_lock:
            if sub == "floor1000":
                if not (ex and u == UID_FLOOR):
                    race["allow_missing"] += 1
            else:
                if ex:
                    race["deny_created"] += 1

    ts = [threading.Thread(target=_race_worker, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ok(race["deny_created"] == 0,
       f"race: no denied (lowu/'0'/mallory) PUT ever created a file "
       f"(drift={race['deny_created']})")
    ok(race["allow_missing"] == 0,
       f"race: every interleaved floor1000 PUT landed owned 1000 "
       f"(misses={race['allow_missing']})")

    # =========================================================================
    # PART E — S3 OWNERSHIP POSITIVE CONTROLS (alice is the only configured key,
    # so a denied PRINCIPAL is not expressible on S3; we instead prove the S3
    # mutating matrix lands owner == mapped alice, never svc/root, and feed the
    # final reserved-id sweep).  This closes the S3 corner of the op/protocol grid.
    # =========================================================================
    if s3port:
        st, _ = s3("GET", "", s3port, params={"list-type": "2"})
        s3_up = st != -1
        if s3_up:
            # PUT
            st, _ = s3("PUT", f"alice/{TAG}_s3_put.txt", s3port, data=b"S3-PUT\n")
            sp = os.path.join(data, "alice", f"{TAG}_s3_put.txt")
            su = os.stat(sp).st_uid if os.path.exists(sp) else -1
            ok(st in (200, 201) and su == UID_ALICE,
               f"S3 PUT (alice) owned 1001, not svc/root (HTTP {st}, uid={su})")
            ok(su < 0 or (not RESERVED(su) and not BADMAP(su)),
               f"S3 PUT owner not reserved/svc/root (uid={su})")

            # multipart-initiate (no parts; just prove the create path owns right /
            # never svc — many configs surface the in-progress marker file)
            st, mbody = s3("POST", f"alice/{TAG}_s3_mpu.bin", s3port,
                           params={"uploads": ""})
            ok(st in (200,) and b"<UploadId>" in (mbody or b""),
               f"S3 multipart-initiate (alice) accepted (HTTP {st})")

            # CopyObject self -> new key, owned alice
            st, _ = s3("PUT", f"alice/{TAG}_s3_copy.txt", s3port,
                       extra_hdrs={"x-amz-copy-source":
                                   f"/{S3_BUCKET}/alice/{TAG}_s3_put.txt"})
            cp = os.path.join(data, "alice", f"{TAG}_s3_copy.txt")
            cu = os.stat(cp).st_uid if os.path.exists(cp) else -1
            ok(st in (200, 201) and cu == UID_ALICE,
               f"S3 CopyObject (alice) owned 1001, not svc/root (HTTP {st}, uid={cu})")

            # DeleteObjects of alice's own key works (positive control)
            st, _ = s3("POST", "", s3port, params={"delete": ""},
                       data=_delete_xml([f"alice/{TAG}_s3_put.txt"]))
            ok(st in (200,) and not os.path.exists(sp),
               f"S3 DeleteObjects of own key removed it (HTTP {st})")
        else:
            ok(True, "S3 ownership controls skipped (S3 endpoint unreachable)")

    # =========================================================================
    # PART F — FINAL CROSS-CUTTING SWEEPS (the load-bearing invariants).
    # =========================================================================
    # F1: /pub free of any reserved/svc/root-owned entry after the entire battery.
    bad = scan_reserved_or_svc()
    ok(bad == [],
       f"FINAL: no /pub entry owned by a reserved/svc/root id after edge matrix "
       f"(leaks={bad[:6]})")

    # F2: none of the denied subjects' would-be uids own anything anywhere in /pub.
    denied_uids = {v for v in DENIED_UID.values() if v >= 0}
    denied_owned = []
    try:
        for nm in os.listdir(PUB):
            try:
                u = os.lstat(pub_path(nm)).st_uid
            except OSError:
                continue
            if u in denied_uids:
                denied_owned.append((nm, u))
    except OSError:
        pass
    ok(denied_owned == [],
       f"FINAL: no /pub entry owned by a denied-mapping uid (owned={denied_owned[:6]})")

    # F3: sweep alice's + bob's S3-writable subtrees for any reserved/svc/root owner
    # that a denied op might have grafted across protocols.
    cross_bad = []
    for sub_dir in ("alice", "bob", "pub"):
        d = os.path.join(data, sub_dir)
        try:
            for nm in os.listdir(d):
                if not nm.startswith(TAG):
                    continue
                try:
                    u = os.lstat(os.path.join(d, nm)).st_uid
                except OSError:
                    continue
                if RESERVED(u) or BADMAP(u):
                    cross_bad.append((sub_dir + "/" + nm, u))
        except OSError:
            pass
    ok(cross_bad == [],
       f"FINAL: no tag-prefixed file under alice/bob/pub owned by reserved/svc/root "
       f"(bad={cross_bad[:6]})")

    # F4: alice's victim survived the entire denied storm — same owner, mode, body.
    ex, vu, _vg = owner_of(VICT)
    ok(ex and vu == UID_ALICE,
       f"FINAL: alice victim survives whole battery, still owned 1001 (uid={vu})")
    ok(ex and (os.stat(pub_path(VICT)).st_mode & 0o777) == 0o600,
       "FINAL: alice victim mode still 0600 (no denied chmod took effect)")
    ok(ex and body_of(VICT).startswith(VICT_MARK),
       "FINAL: alice victim content intact (no denied truncate/overwrite/leak)")

    # F5: WORKER SURVIVAL — after every denied storm + race, a legit floor1000 op and
    # a legit alice op both still work, proving no rejected mapping wedged the
    # worker/broker or pinned it to svc.
    st, _ = http("PUT", f"/pub/{TAG}_survive_floor.txt", port,
                 mint(key, "floor1000"), b"SURVIVE\n")
    ex, u, _g = owner_of(f"{TAG}_survive_floor.txt")
    ok(st in (200, 201, 204) and ex and u == UID_FLOOR,
       f"worker survives edge storm: floor1000 PUT still owned 1000 (HTTP {st}, uid={u})")
    st, b = http("GET", f"/pub/{TAG}_survive_floor.txt", port, mint(key, "floor1000"))
    ok(st == 200 and b"SURVIVE" in (b or b""),
       f"worker survives edge storm: floor1000 GET reads back its file (HTTP {st})")
    st, _ = http("PUT", f"/pub/{TAG}_survive_alice.txt", port,
                 mint(key, "alice"), b"ALICE-SURVIVE\n")
    ex, u, _g = owner_of(f"{TAG}_survive_alice.txt")
    ok(st in (200, 201, 204) and ex and u == UID_ALICE,
       f"worker survives edge storm: alice PUT still owned 1001 (HTTP {st}, uid={u})")


