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


def run_combo_encoding_group_targets(key, data, port, s3port):
    """COMBINATION FRONTIER: traversal/ENCODING crossed with GROUP / SETGID / STICKY
    / CROSS-TENANT targets (the existing encoding battery only ever aimed encodings
    at /etc and at outside-the-export markers; the group/setgid/sticky batteries
    only used CLEAN logical paths).  Here every encoding variant (../, %2e%2e,
    %252e, ..%2f, ....//, ..;/, %00, %0d%0a, double-encoded, unicode-dot, absolute,
    backslash) is fired at a target the *group DAC* protects, so the question is:
    can an encoded path sneak a NON-MEMBER past a group-restricted directory, climb
    OUT of a setgid/sticky dir into a sibling tenant, escape a 0700 dir to /etc, or
    NORMALIZE into another tenant's tree?  bob is NOT in staff (staffdir/sgiddir/
    execonly are alice:staff 0770/2770/0710); alice is NOT in research (bob owns
    bobsecret 0700).  Each deny asserts the protected secret bytes never appear and
    that nothing was created in a forbidden/cross-tenant/outside location; each
    cluster carries a POSITIVE CONTROL proving the path machinery still resolves a
    legit in-tenant / in-group nested path (so a blanket block cannot false-pass).
    The worker must survive (a follow-up legit op works)."""
    tag = "cegt"
    tb = mint(key, "bob")        # bob: NOT in staff (staffdir/sgiddir/execonly closed)
    ta = mint(key, "alice")      # alice: NOT in research (bobsecret closed); IS staff
    tc = mint(key, "carol")      # carol: IN staff (group control for the staff dirs)

    PW = b"root:x:"                       # /etc/passwd signature
    STAFF = b"INSIDE-STAFF-DIR"           # staffdir/inside.txt body (group-only)
    EXEC = b"EXECONLY-KNOWN"              # execonly/known.txt body (group --x only)
    BOB = b"BOB-PRIVATE-SECRET"           # bob/private.txt (0600) body
    BOBS = b"bob-only"                    # bobsecret/s.txt (0700 dir) body
    SVC = b"svc-only-secret"              # svconly/secret-name.txt body

    export_abs = os.path.abspath(data)
    parent1 = os.path.dirname(export_abs)
    parent2 = os.path.dirname(parent1)

    def clean_body(b):
        """No protected/secret marker of ANY target leaked into this response."""
        x = b or b""
        return (PW not in x and b"daemon:x:" not in x and STAFF not in x
                and EXEC not in x and BOB not in x and BOBS not in x and SVC not in x)

    def no_create(*paths):
        """True iff NONE of the candidate forbidden landing paths exist."""
        for p in paths:
            try:
                if os.path.exists(p):
                    return False
            except OSError:
                pass
        return True

    def mode_of(p):
        try:
            return os.stat(p).st_mode & 0o7777
        except OSError:
            return -1

    def owner_of(p):
        try:
            st = os.stat(p)
            return (st.st_uid, st.st_gid)
        except OSError:
            return (-1, -1)

    # A unique sibling-tenant target the escapes try to OVERWRITE / read into:
    # carol owns a private file; escapes out of setgid/sticky dirs aim here so a
    # successful climb would either leak CAROL-SECRET or clobber it.
    CAROL_SECRET = b"CAROL-PRIVATE-CEGT"
    carol_priv = os.path.join(data, "carol", "cegt_priv.txt")
    try:
        os.makedirs(os.path.join(data, "carol"), exist_ok=True)
        os.chown(os.path.join(data, "carol"), UID_CAROL, UID_CAROL)
        os.chmod(os.path.join(data, "carol"), 0o755)
        with open(carol_priv, "wb") as fh:
            fh.write(CAROL_SECRET + b"\n")
        os.chown(carol_priv, UID_CAROL, UID_CAROL)
        os.chmod(carol_priv, 0o600)
    except OSError:
        carol_priv = None

    # A 0700 alice-only dir (NOT group-shared) used for the "climb out of a private
    # dir to /etc" leg — distinct from bobsecret so cleanup stays local.
    priv700 = os.path.join(data, f"{tag}_priv700")
    priv700_secret = os.path.join(priv700, "inner.txt")
    try:
        os.makedirs(priv700, exist_ok=True)
        os.chown(priv700, UID_ALICE, UID_ALICE)
        os.chmod(priv700, 0o700)
        with open(priv700_secret, "wb") as fh:
            fh.write(b"PRIV700-INNER-CEGT\n")
        os.chown(priv700_secret, UID_ALICE, UID_ALICE)
        os.chmod(priv700_secret, 0o600)
    except OSError:
        pass

    # =====================================================================
    # POSITIVE CONTROL CLUSTER — the path/encoding/group machinery WORKS for
    # legitimate cases, so every deny below is meaningful (not a blanket block).
    # =====================================================================
    # (PC1) carol IS staff: a normalizing dot-segment INTO the group dir resolves
    #       and returns the group-only body — proves group-DAC GRANT + dot handling.
    st, b = http("GET", "/staffdir/./inside.txt", port, tc)
    # carol IS staff: group/owner DAC GRANTS the read and the dot-segment must
    # normalize back inside the dir -> HTTP 200.  The body itself is a SHARED
    # fixture an earlier batch (run_group_write_dac) legitimately rewrites
    # (carol re-PUTs staffdir/inside.txt; _reset_fixtures restores the dir but not
    # this child's content), so assert the GRANT (200 + a real body carol may see)
    # without pinning the stale canonical marker, and require no OTHER-tenant
    # secret leaked into the response.
    ok(st == 200 and bool(b)
       and PW not in (b or b"") and BOB not in (b or b"")
       and BOBS not in (b or b"") and SVC not in (b or b""),
       f"control: carol (staff) reads staffdir via dot-segment, group GRANT "
       f"+ normalize works (HTTP {st})")
    # (PC2) carol reaches the group dir through an encoded but in-bounds segment.
    st, b = http("GET", "/staffdir/%2e/inside.txt", port, tc)
    ok(st in (200, 404) and clean_body(b) or _has(b, STAFF),
       f"control: carol staffdir via %2e segment handled (HTTP {st})")
    # (PC3) alice (owner) writes a nested file under the setgid dir — inherits the
    #       staff gid — proves setgid path resolution is functional for a member.
    st, _ = http("PUT", "/sgiddir/cegt_ok.txt", port, ta, b"SGID-OK\n")
    sgf = os.path.join(data, "sgiddir", "cegt_ok.txt")
    ok(st in (200, 201, 204) and os.path.exists(sgf)
       and owner_of(sgf) == (UID_ALICE, GID_STAFF),
       f"control: alice PUT in setgid dir -> file group inherits staff (HTTP {st})")
    # (PC4) bob writes into the world-writable sticky dir (legit, allowed) and the
    #       file is owned by BOB — sticky lets him create his own file.
    st, _ = http("PUT", "/stickytmp/cegt_bob.txt", port, tb, b"STICKY-BOB\n")
    skb = os.path.join(data, "stickytmp", "cegt_bob.txt")
    ok(st in (200, 201, 204) and os.path.exists(skb)
       and owner_of(skb)[0] == UID_BOB,
       f"control: bob PUT into sticky 1777 dir owned by bob (HTTP {st})")

    # =====================================================================
    # (A) ENCODING vs a GROUP-restricted dir the identity is NOT in.
    #     bob is NOT staff: staffdir(0770)/sgiddir(2770)/execonly(0710) are closed
    #     to him by group DAC.  Can an encoded path sneak bob past the group bit?
    #     Every variant must DENY and never leak STAFF/EXEC bytes.
    # =====================================================================
    grp_enc_reads = [
        "/staffdir/inside.txt",                         # plain (group deny baseline)
        "/staffdir%2finside.txt",                       # encoded slash into the dir
        "/%73taffdir/inside.txt",                       # %73 = 's' (encoded dirname)
        "/staffdir/%2e/inside.txt",                     # dot-segment inside
        "/staffdir/../staffdir/inside.txt",             # normalizes back in
        "/staffdir/..%2fstaffdir/inside.txt",           # encoded normalize-back-in
        "/alice/../staffdir/inside.txt",                # via sibling tenant
        "/alice/..%2fstaffdir/inside.txt",
        "/alice/....//staffdir/inside.txt",             # quad-dot collapse
        "/staffdir/./%69nside.txt",                     # %69 = 'i' (encoded leaf)
        "/sgiddir/../staffdir/inside.txt",              # hop via setgid sibling
        "/execonly/known.txt",                          # group --x dir, no group read
        "/execonly/%6bnown.txt",                        # %6b = 'k'
        "/execonly/../execonly/known.txt",
        "/sgiddir/inside.txt",                          # setgid dir, bob not member
    ]
    for p in grp_enc_reads:
        st, b = http("GET", p, port, tb)
        ok(st in (403, 401, 404) and clean_body(b),
           f"(A) bob(non-staff) encoded GET {p[:34]!r} group-DAC deny, no staff/exec "
           f"leak (HTTP {st})")

    # bob PROPFIND the group dir via encoding — must not enumerate the member-only
    # child name or body.
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
          b'<D:prop><D:displayname/></D:prop></D:propfind>')
    for p in ["/staffdir/", "/staffdir%2f", "/alice/../staffdir/",
              "/sgiddir/", "/execonly/"]:
        st, b = http("PROPFIND", p, port, tb, data=pf,
                     hdrs={"Depth": "1", "Content-Type": "application/xml"})
        ok(clean_body(b) and not _has(b, b"inside.txt"),
           f"(A) bob PROPFIND {p!r} no member-only enumeration/body (HTTP {st})")

    # bob WRITE via encoding INTO the group dir he's not a member of — must create
    # nothing there (the group --w bit is closed to a non-member).
    grp_enc_writes = [
        "/staffdir/cegt_intrude.txt",
        "/staffdir%2fcegt_intrude2.txt",
        "/alice/..%2fstaffdir/cegt_intrude3.txt",
        "/sgiddir/cegt_intrude4.txt",
        "/sgiddir/..%2fsgiddir/cegt_intrude5.txt",
    ]
    for p in grp_enc_writes:
        http("PUT", p, port, tb, b"intrude\n")
    ok(no_create(
        os.path.join(data, "staffdir", "cegt_intrude.txt"),
        os.path.join(data, "staffdir", "cegt_intrude2.txt"),
        os.path.join(data, "staffdir", "cegt_intrude3.txt"),
        os.path.join(data, "sgiddir", "cegt_intrude4.txt"),
        os.path.join(data, "sgiddir", "cegt_intrude5.txt")),
       "(A) bob encoded WRITE into staff/setgid group dir created nothing")
    # control: carol (member) CAN write into the staff dir via a normalizing path.
    st, _ = http("PUT", "/staffdir/../staffdir/cegt_carol.txt", port, tc,
                 b"CAROL-IN-STAFF\n")
    ccf = os.path.join(data, "staffdir", "cegt_carol.txt")
    ok(st in (200, 201, 204) and os.path.exists(ccf)
       and owner_of(ccf)[0] == UID_CAROL,
       f"control: carol(staff) encoded WRITE into staffdir OK, owned carol "
       f"(HTTP {st})")

    # =====================================================================
    # (B) ESCAPE from a SETGID / STICKY dir OUT to a sibling tenant's dir.
    #     Fire ".." escapes whose path STARTS inside sgiddir/stickytmp and aims at
    #     carol's private file / bob's private file.  No sibling secret may leak;
    #     nothing may be created in / clobber the sibling tenant.
    # =====================================================================
    # Every target here is owned by CAROL (a true sibling tenant of bob): bob is a
    # NON-owner, NON-group accessor, so any appearance of CAROL_SECRET is a real
    # cross-tenant leak.  Targets bob OWNS (bob/private.txt, bobsecret/s.txt) were
    # removed on purpose: a normalizing `../` stays in-export and resolves back to
    # bob's OWN files, so a 200 + his own bytes there is CORRECT (owner read), not a
    # sibling-tenant leak -- asserting `not _has(b, BOB/BOBS)` against bob's own
    # tree was the test bug here.
    escape_reads = [
        "/sgiddir/../carol/cegt_priv.txt",
        "/sgiddir/..%2fcarol%2fcegt_priv.txt",
        "/sgiddir/....//carol/cegt_priv.txt",
        "/stickytmp/../carol/cegt_priv.txt",
        "/stickytmp/..%2f..%2fcarol/cegt_priv.txt",
        "/stickytmp/..%2fcarol%2fcegt_priv.txt",
        "/sgiddir/..%2f..%2fcarol/cegt_priv.txt",
        "/sgiddir/..;/carol/cegt_priv.txt",
        "/stickytmp/%2e%2e/carol/cegt_priv.txt",
        "/stickytmp/%2e%2e%2fcarol%2fcegt_priv.txt",
    ]
    for p in escape_reads:
        st, b = http("GET", p, port, tb)
        # Sibling-tenant (carol) secret must never leak to bob; the deny must also
        # not surface any other protected marker (/etc, staff, exec, svc, bob/bobs).
        ok(not _has(b, CAROL_SECRET) and clean_body(b),
           f"(B) bob escape-out-of-setgid/sticky GET {p[:36]!r} no sibling-tenant "
           f"secret leak (HTTP {st})")

    # ESCAPE-WRITE out of the sticky/setgid dir to clobber carol's private file or
    # plant a file in carol's tree — must NOT modify carol's file nor create there.
    # All write escapes aim at CAROL's tree (a sibling tenant bob has no access to).
    # The old "/stickytmp/../bob/cegt_plant3.txt" leg was dropped: it normalizes to
    # bob's OWN /bob/ dir (0755, bob-owned), where bob CAN legitimately create a
    # file -- that is correct ownership, not a sibling-tenant plant, so asserting
    # no_create on bob/cegt_plant3.txt false-failed.
    escape_writes = [
        ("/stickytmp/../carol/cegt_priv.txt", b"CLOBBERED\n"),
        ("/stickytmp/..%2fcarol%2fcegt_priv.txt", b"CLOBBERED\n"),
        ("/sgiddir/../carol/cegt_plant.txt", b"PLANT\n"),
        ("/sgiddir/..%2fcarol%2fcegt_plant2.txt", b"PLANT\n"),
        ("/stickytmp/..%2f..%2fcarol%2fcegt_plant3.txt", b"PLANT\n"),
    ]
    for p, d in escape_writes:
        http("PUT", p, port, tb, d)
    # carol's secret intact (not clobbered through the escape)?
    if carol_priv:
        try:
            still = open(carol_priv, "rb").read()
            ok(CAROL_SECRET in still and owner_of(carol_priv)[0] == UID_CAROL,
               "(B) carol's private file intact + still carol-owned after escape "
               "writes (no setgid/sticky clobber)")
        except OSError:
            ok(False, "(B) carol private file unreadable after escape writes")
    ok(no_create(os.path.join(data, "carol", "cegt_plant.txt"),
                 os.path.join(data, "carol", "cegt_plant2.txt"),
                 os.path.join(data, "carol", "cegt_plant3.txt")),
       "(B) escape-write out of setgid/sticky planted nothing in sibling tenant")
    # control: bob deleting HIS OWN sticky file is allowed (sticky lets owner rm).
    st, _ = http("DELETE", "/stickytmp/cegt_bob.txt", port, tb)
    ok(st in (200, 204, 404)
       and not os.path.exists(os.path.join(data, "stickytmp", "cegt_bob.txt")),
       f"control: bob DELETEs his OWN sticky file (sticky owner-rm allowed) "
       f"(HTTP {st})")
    # sticky NEGATIVE: bob may NOT delete alice's file in the sticky dir, even via
    # a normalizing path (sticky bit: only file/dir owner removes).
    st, _ = http("DELETE", "/stickytmp/../stickytmp/alice_owned.txt", port, tb)
    apath = os.path.join(data, "stickytmp", "alice_owned.txt")
    ok(os.path.exists(apath) and owner_of(apath)[0] == UID_ALICE,
       f"(B) bob CANNOT delete alice's file in sticky dir via normalizing path "
       f"(sticky enforced) (HTTP {st})")

    # =====================================================================
    # (C) CLIMB from a 0700 dir OUT to /etc/passwd.  Path begins inside a private
    #     dir (alice's 0700 / bob's 0700 bobsecret) and climbs out with encoding.
    #     /etc/passwd must never be read; bobsecret body must never leak to alice.
    # =====================================================================
    climb_reads_alice = [
        f"/{tag}_priv700/../../../../etc/passwd",
        f"/{tag}_priv700/..%2f..%2f..%2f..%2fetc%2fpasswd",
        f"/{tag}_priv700/....//....//....//etc/passwd",
        f"/{tag}_priv700/..;/..;/..;/etc/passwd",
        f"/{tag}_priv700/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        f"/{tag}_priv700/inner.txt%00/../../../etc/passwd",
    ]
    for p in climb_reads_alice:
        st, b = http("GET", p, port, ta)
        ok(clean_body(b),
           f"(C) alice climb out of own 0700 dir {p[:34]!r} no /etc leak (HTTP {st})")
    # alice climbs out of HER 0700 dir aiming at bob's 0700 bobsecret -> denied.
    climb_cross = [
        f"/{tag}_priv700/../bobsecret/s.txt",
        f"/{tag}_priv700/..%2fbobsecret%2fs.txt",
        "/bobsecret/../bobsecret/s.txt",                # normalize within bob's 0700
        "/bobsecret/%2e%2e/bobsecret/s.txt",
        "/alice/../bobsecret/s.txt",
    ]
    for p in climb_cross:
        st, b = http("GET", p, port, ta)
        ok(not _has(b, BOBS) and clean_body(b),
           f"(C) alice climb into bob's 0700 dir {p[:34]!r} no bob-secret leak "
           f"(HTTP {st})")
    # control: alice reads her OWN file inside her 0700 dir via a normalizing path.
    st, b = http("GET", f"/{tag}_priv700/../{tag}_priv700/inner.txt", port, ta)
    ok(st in (200, 404) and not _has(b, BOBS) and PW not in (b or b""),
       f"control: alice reads own 0700-dir file via normalize (owner allowed) "
       f"(HTTP {st})")

    # =====================================================================
    # (D) NORMALIZE INTO ANOTHER TENANT'S TREE: a path that, after collapsing,
    #     points at a sibling tenant's PRIVATE file — across protocols.  The
    #     normalization must not become an authorization bypass; per-file/dir DAC
    #     still applies under the MAPPED identity.
    # =====================================================================
    normalize_into = [
        "/alice/foo/../../bob/private.txt",
        "/alice/a/b/../../../bob/private.txt",
        "/alice/%2e%2e/bob/private.txt",
        "/alice/..%2fbob%2fprivate.txt",
        "/alice/./../bob/private.txt",
        "/staffdir/../bob/private.txt",
        "/sgiddir/../bobsecret/s.txt",
        "/alice/x/..%2f..%2fcarol/cegt_priv.txt",
        "/alice/foo/../../svconly/secret-name.txt",
    ]
    for p in normalize_into:
        st, b = http("GET", p, port, ta)
        ok(not _has(b, BOB) and not _has(b, BOBS) and not _has(b, CAROL_SECRET)
           and not _has(b, SVC) and PW not in (b or b""),
           f"(D) alice normalize-into-sibling GET {p[:34]!r} no cross-tenant/svc "
           f"leak (HTTP {st})")
    # control: bob (the OWNER) reads bob/private.txt via the SAME normalizing shape
    #          -> proves the normalize itself resolves; the deny above was DAC, not
    #          a path-rejection.
    st, b = http("GET", "/bob/foo/../../bob/private.txt", port, tb)
    ok(st in (200, 404) and (st == 404 or _has(b, BOB)),
       f"control: bob reads own private.txt via normalizing path (owner DAC) "
       f"(HTTP {st})")

    # WebDAV MOVE/COPY Destination that normalizes into a group/sibling target:
    # bob tries to MOVE his own file so it lands inside the staff group dir or in
    # carol's tree — must not land there.
    http("PUT", "/bob/cegt_movesrc.txt", port, tb, b"MOVE-SRC-CEGT\n")
    dest_norm = [
        f"http://{HOST}:{port}/bob/../staffdir/cegt_moved.txt",
        f"http://{HOST}:{port}/bob/..%2fstaffdir%2fcegt_moved2.txt",
        f"http://{HOST}:{port}/bob/../carol/cegt_moved3.txt",
        f"http://{HOST}:{port}/sgiddir/cegt_moved4.txt",
    ]
    for d in dest_norm:
        http("COPY", "/bob/cegt_movesrc.txt", port, tb, hdrs={"Destination": d})
    ok(no_create(os.path.join(data, "staffdir", "cegt_moved.txt"),
                 os.path.join(data, "staffdir", "cegt_moved2.txt"),
                 os.path.join(data, "carol", "cegt_moved3.txt"),
                 os.path.join(data, "sgiddir", "cegt_moved4.txt")),
       "(D) bob COPY Destination normalizing into staff/carol/setgid created "
       "nothing there")
    # control: in-tenant COPY for bob still works + owned by bob.
    st, _ = http("COPY", "/bob/cegt_movesrc.txt", port, tb,
                 hdrs={"Destination": f"http://{HOST}:{port}/bob/cegt_copyok.txt"})
    cpok = os.path.join(data, "bob", "cegt_copyok.txt")
    ok(st in (200, 201, 204) and os.path.exists(cpok)
       and owner_of(cpok)[0] == UID_BOB,
       f"control: bob in-tenant COPY OK, owned bob (HTTP {st})")

    # =====================================================================
    # (E) S3 key + copy-source ENCODING vs group/sticky/cross-tenant targets
    #     (signed as alice; alice is staff so use a target alice's group does NOT
    #     reach — research/bob — and the svc-only dir).
    # =====================================================================
    if s3port:
        s3_grp_keys = [
            "staffdir/inside.txt",                       # alice IS staff -> may read
            "execonly/known.txt",                        # group --x: dir not readable
            "bobsecret/s.txt",                           # bob 0700: deny
            "bobsecret%2fs.txt",
            "alice/../bobsecret/s.txt",
            "sgiddir/../bobsecret/s.txt",
            "..%2f..%2f..%2fetc%2fpasswd",
            "stickytmp/../carol/cegt_priv.txt",
            "stickytmp/..%2fcarol%2fcegt_priv.txt",
            "sgiddir/..%2fbob%2fprivate.txt",
        ]
        for k in s3_grp_keys:
            st, b = s3("GET", k, s3port)
            # NOTE: the S3 access key is alice (uid 1001).  alice IS staff, so
            # staffdir/inside.txt MAY legitimately return; and alice OWNS
            # execonly/known.txt (0640 alice:staff, owner-read), so reading EXEC for
            # THAT key is an owner read, NOT a leak.  The invariant is "no FORBIDDEN
            # secret of a NON-reachable target leaks" — a cross-tenant/group-non-member
            # secret (bob/carol/svc/etc) or EXEC surfacing through an ENCODED ESCAPE
            # into the alice-owned file from some other dir.
            owns_exec = (k == "execonly/known.txt")   # alice owns this 0640 file
            forbidden_leak = (_has(b, BOBS) or _has(b, BOB) or _has(b, CAROL_SECRET)
                              or _has(b, SVC) or PW in (b or b"")
                              or (not owns_exec and _has(b, EXEC)))
            ok(not forbidden_leak,
               f"(E) S3 GET enc key {k[:30]!r} no forbidden group/tenant/svc leak "
               f"(HTTP {st})")

        # S3 PUT encoded keys aimed at the group/sticky/cross-tenant dirs as alice —
        # the ones alice's identity may NOT write (bob's tree, svconly) create
        # nothing; nothing escapes the export.
        s3_put_keys = [
            "bobsecret/cegt_s3.txt",
            "bob/..%2fbob%2fcegt_s3b.txt",
            "svconly/cegt_s3c.txt",
            "..%2f..%2fCEGT_S3_OUT.txt",
            "carol/..%2fcarol%2fcegt_s3d.txt",
        ]
        for k in s3_put_keys:
            s3("PUT", k, s3port, data=b"s3-intrude\n")
        ok(no_create(
            os.path.join(data, "bobsecret", "cegt_s3.txt"),
            os.path.join(data, "svconly", "cegt_s3c.txt"),
            os.path.join(parent1, "CEGT_S3_OUT.txt"),
            os.path.join(parent2, "CEGT_S3_OUT.txt")),
           "(E) S3 encoded PUT into bob-0700/svconly/outside created nothing "
           "forbidden")

        # S3 CopyObject copy-source ENCODING that climbs out of one dir into a
        # group/sibling secret — the destination must not contain the secret bytes.
        cs_variants = [
            f"/{S3_BUCKET}/sgiddir/..%2fbobsecret%2fs.txt",
            f"/{S3_BUCKET}/stickytmp/../carol/cegt_priv.txt",
            f"/{S3_BUCKET}/alice/..%2fbob%2fprivate.txt",
            f"/{S3_BUCKET}/execonly/known.txt",
            f"/{S3_BUCKET}/..%2f..%2f..%2fetc%2fpasswd",
        ]
        for i, cs in enumerate(cs_variants):
            dstkey = f"alice/cegt_cs_{i}.bin"
            st, _ = s3("PUT", dstkey, s3port,
                       extra_hdrs={"x-amz-copy-source": cs})
            dpath = os.path.join(data, "alice", f"cegt_cs_{i}.bin")
            # The signer is alice (uid 1001).  copy-source execonly/known.txt is
            # alice's OWN 0640 file (owner-read), so copying EXEC from THAT clean
            # source into alice's own tree is a legit owner copy, NOT exfil.  EXEC is
            # only a violation if it lands via an ENCODED ESCAPE source (a ..%2f climb
            # out of another dir) rather than the direct owner key.
            owns_src = (cs == f"/{S3_BUCKET}/execonly/known.txt")
            leaked = False
            try:
                if os.path.exists(dpath):
                    c = open(dpath, "rb").read()
                    leaked = (BOBS in c or BOB in c or CAROL_SECRET in c or PW in c
                              or (not owns_src and EXEC in c))
            except OSError:
                leaked = False
            ok(not leaked,
               f"(E) S3 CopyObject enc src {cs[len(S3_BUCKET)+2:][:24]!r} did not "
               f"exfil group/tenant secret (HTTP {st})")

        # S3 control: alice's OWN nested encoded key round-trips + owned by alice.
        st, _ = s3("PUT", "alice/cegt_s3ok.txt", s3port, data=b"S3-CEGT-OK\n")
        st2, b = s3("GET", "alice/cegt_s3ok.txt", s3port)
        ok(st in (200, 201) and st2 == 200 and _has(b, b"S3-CEGT-OK"),
           f"control: S3 alice own key round-trips (HTTP {st}/{st2})")
        okp = os.path.join(data, "alice", "cegt_s3ok.txt")
        ok(os.path.exists(okp) and owner_of(okp)[0] == UID_ALICE,
           "control: S3-created object owned by alice")

    # =====================================================================
    # (F) root:// (stream) stat/cat/mkdir ENCODING vs group/setgid/sticky/sibling.
    # =====================================================================
    if not xrd_avail():
        ok(True, "(F) root:// combo-encoding skipped (native client absent)")
    else:
        # bob (non-staff) stat/cat the staff group dir via normalizing paths -> deny,
        # no staff body.
        root_grp = [
            "/staffdir/inside.txt",
            "/staffdir/../staffdir/inside.txt",
            "/sgiddir/../staffdir/inside.txt",
            "/execonly/known.txt",
            "/alice/../staffdir/inside.txt",
        ]
        for p in root_grp:
            rc, out, _e = xrd_fs(["cat", p], "bob")
            ok(rc != 0 and "INSIDE-STAFF-DIR" not in (out or "")
               and "EXECONLY-KNOWN" not in (out or ""),
               f"(F) root:// bob(non-staff) cat {p[:30]!r} group-DAC deny, no "
               f"staff/exec leak (rc={rc})")

        # alice climbs out of setgid/sticky into bob's 0700 + /etc -> deny.
        root_climb = [
            "/sgiddir/../bobsecret/s.txt",
            "/stickytmp/../bob/private.txt",
            f"/{tag}_priv700/../../../../etc/passwd",
            "/sgiddir/..%2f..%2f..%2fetc%2fpasswd",
        ]
        for p in root_climb:
            rc, out, _e = xrd_fs(["cat", p], "alice")
            ok(rc != 0 and "bob-only" not in (out or "")
               and "BOB-PRIVATE-SECRET" not in (out or "")
               and "root:x:" not in (out or ""),
               f"(F) root:// alice climb-out {p[:30]!r} deny, no bob/etc leak "
               f"(rc={rc})")

        # bob mkdir via normalize INTO the staff group dir -> creates nothing.
        xrd_fs(["mkdir", "/staffdir/../staffdir/cegt_rootdir"], "bob")
        xrd_fs(["mkdir", "/sgiddir/cegt_rootdir2"], "bob")
        ok(no_create(os.path.join(data, "staffdir", "cegt_rootdir"),
                     os.path.join(data, "sgiddir", "cegt_rootdir2")),
           "(F) root:// bob mkdir into staff/setgid group dir created nothing")

        # root:// stat a sibling tenant's private file via normalize -> deny, but
        # the path itself is valid (control proves owner can stat it).
        rc, _o, _e = xrd_fs(["stat", "/alice/../bobsecret/s.txt"], "alice")
        ok(rc != 0,
           f"(F) root:// alice stat into bob's 0700 via normalize denied (rc={rc})")
        rc, _o, _e = xrd_fs(["stat", "/bobsecret/s.txt"], "bob")
        ok(rc == 0,
           f"control: root:// bob (owner) stats own bobsecret file (rc={rc})")

        # root:// control: alice mkdir + write under HER setgid-member dir works and
        # the new dir inherits the staff gid (setgid + member, encoded-normalize).
        rc, _o, _e = xrd_fs(["mkdir", "/sgiddir/../sgiddir/cegt_member"], "alice")
        memd = os.path.join(data, "sgiddir", "cegt_member")
        ok(rc == 0 and os.path.isdir(memd) and owner_of(memd)[1] == GID_STAFF,
           f"control: root:// alice(staff) mkdir under setgid dir inherits staff gid "
           f"(rc={rc})")

    # =====================================================================
    # (G) GRAND INVARIANTS — nothing landed in any forbidden/outside location, the
    #     protected fixtures are byte-intact + correctly owned, worker SURVIVES.
    # =====================================================================
    ok(no_create(
        os.path.join(parent1, "CEGT_S3_OUT.txt"),
        os.path.join(parent2, "CEGT_S3_OUT.txt"),
        "/etc/CEGT_S3_OUT.txt"),
       "(G) GRAND INVARIANT: no attack file landed outside the export root")
    # staff group dir still owned alice:staff at mode 0770 (no encoding flipped it).
    ok(owner_of(os.path.join(data, "staffdir")) == (UID_ALICE, GID_STAFF)
       and mode_of(os.path.join(data, "staffdir")) == 0o770,
       "(G) staffdir still alice:staff 0770 after the encoding battery")
    # setgid bit still set on sgiddir (no op stripped it).
    ok(mode_of(os.path.join(data, "sgiddir")) == 0o2770,
       "(G) sgiddir setgid bit (02770) intact after the battery")
    # sticky bit still set on stickytmp.
    ok(mode_of(os.path.join(data, "stickytmp")) == 0o1777,
       "(G) stickytmp sticky bit (01777) intact after the battery")
    # bob's private file untouched + still owned bob.
    bpriv = os.path.join(data, "bob", "private.txt")
    try:
        ok(open(bpriv, "rb").read() == b"BOB-PRIVATE-SECRET\n"
           and owner_of(bpriv)[0] == UID_BOB,
           "(G) bob/private.txt byte-intact + still bob-owned (no encoded write hit "
           "it)")
    except OSError:
        ok(False, "(G) bob/private.txt unreadable post-battery")
    # carol's private file untouched.
    if carol_priv:
        try:
            ok(open(carol_priv, "rb").read() == CAROL_SECRET + b"\n",
               "(G) carol private file byte-intact (no setgid/sticky escape clobber)")
        except OSError:
            ok(False, "(G) carol private file unreadable post-battery")

    # Worker SURVIVES the whole combination battery: a fresh legit op still works
    # and lands owned by the mapped user (no crash / no principal corruption).
    st, _ = http("PUT", "/alice/cegt_survive.txt", port, ta, b"CEGT-SURVIVE\n")
    sp = os.path.join(data, "alice", "cegt_survive.txt")
    ok(st in (200, 201, 204) and os.path.exists(sp)
       and owner_of(sp)[0] == UID_ALICE,
       f"(G) worker SURVIVES battery: legit alice PUT owned by alice (HTTP {st})")
    st, b = http("GET", "/alice/cegt_survive.txt", port, ta)
    ok(st == 200 and _has(b, b"CEGT-SURVIVE"),
       f"(G) worker SURVIVES battery: legit GET round-trips (HTTP {st})")
    # and a group-DAC GRANT still works post-battery (carol reads staffdir).
    # staffdir/inside.txt is a SHARED fixture an earlier batch legitimately
    # rewrites (carol re-PUT), and _reset_fixtures restores the dir but not this
    # child's content -> assert the GRANT (carol still gets 200 + a real body)
    # without pinning the stale canonical marker, and no OTHER-tenant secret leaks.
    st, b = http("GET", "/staffdir/inside.txt", port, tc)
    ok(st == 200 and bool(b)
       and PW not in (b or b"") and BOB not in (b or b"")
       and BOBS not in (b or b"") and SVC not in (b or b""),
       f"(G) post-battery group GRANT still works: carol reads staffdir (HTTP {st})")

    # Cleanup the local fixtures we planted so later batteries see a clean tree.
    for p in (priv700_secret, os.path.join(priv700, "x")):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    try:
        if os.path.isdir(priv700):
            os.rmdir(priv700)
    except OSError:
        pass


