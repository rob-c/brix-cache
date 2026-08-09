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


def run_combo_authfail_resource_state(key, data, port, s3port):
    # ---------------------------------------------------------------------
    # WHAT: AUTH-FAILURE crossed with RESOURCE-STATE — the error-path
    #       info-leak frontier.  For an EXPIRED / wrong-aud / forged /
    #       alg-none / unmapped-sub bearer (and a tampered/forged S3 sig)
    #       we hit resources in DIFFERENT existence/DAC/lock states: a
    #       LOCKED file, a GROUP-restricted file the token's identity could
    #       not reach anyway, a 0700 dir's child, a NON-existent path, and a
    #       path inside a setgid/sticky dir.
    # WHY:  The auth gate must fire BEFORE any resource/DAC/existence check.
    #       So a bad credential must yield a UNIFORM rejection regardless of
    #       whether the target is locked/unlocked, exists/absent,
    #       forbidden-by-group, or inside a special-mode dir — otherwise the
    #       status/body becomes an existence / lock-state / metadata oracle
    #       that a forged token could mine without ever authenticating.
    # HOW:  Build forbidden-existing, forbidden-absent, locked, group-only,
    #       0700-child, setgid-child and sticky-child fixtures, then drive
    #       each forged credential at them and assert: never 2xx, never the
    #       secret bytes, and the per-credential status is the SAME across
    #       all resource states (no oracle).  Positive control: the correct
    #       identity + a valid credential succeeds.  WebDAV + S3 + root.
    # ---------------------------------------------------------------------
    TAG = "combo_authfail_resstate"
    now = int(time.time())

    def safe_chown(p, uid, gid):
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass

    def safe_chmod(p, mode):
        try:
            os.chmod(p, mode)
        except OSError:
            pass

    def safe_mkdir(p, mode, uid, gid):
        try:
            os.makedirs(p, exist_ok=True)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)

    def safe_write(p, content, mode, uid, gid):
        try:
            with open(p, "wb") as fh:
                fh.write(content)
        except OSError:
            pass
        safe_chown(p, uid, gid)
        safe_chmod(p, mode)

    def safe_exists(p):
        try:
            return os.path.exists(p)
        except OSError:
            return False

    def file_owner(p):
        try:
            st = os.stat(p)
            return (st.st_uid, st.st_gid)
        except OSError:
            return (None, None)

    def is_2xx(st):
        return 200 <= st < 300

    def no_marker(body, marker):
        return marker not in (body or b"")

    # ----- FIXTURES (all under the combo tag namespace) -------------------
    EX_SECRET = b"COMBO-AF-EXISTING-SECRET"
    LK_SECRET = b"COMBO-AF-LOCKED-SECRET"
    GRP_SECRET = b"COMBO-AF-STAFFGRP-SECRET"
    P700_SECRET = b"COMBO-AF-0700CHILD-SECRET"
    SGID_SECRET = b"COMBO-AF-SETGID-SECRET"
    STK_SECRET = b"COMBO-AF-STICKY-SECRET"

    root_dir = os.path.join(data, f"{TAG}_root")
    safe_mkdir(root_dir, 0o755, UID_SVC, UID_SVC)
    ensure_traversable(root_dir)

    # (a) a forbidden-but-EXISTING file owned by bob, 0600.
    bob_dir = os.path.join(root_dir, "bob")
    safe_mkdir(bob_dir, 0o755, UID_BOB, UID_BOB)
    ex_file = os.path.join(bob_dir, "existing_secret.txt")
    safe_write(ex_file, EX_SECRET + b"\n", 0o600, UID_BOB, UID_BOB)

    # a LOCKED file (WebDAV LOCK by its owner alice) — same dir, sibling of absent.
    alice_dir = os.path.join(root_dir, "alice")
    safe_mkdir(alice_dir, 0o755, UID_ALICE, UID_ALICE)
    lk_file = os.path.join(alice_dir, "locked.txt")
    safe_write(lk_file, LK_SECRET + b"\n", 0o600, UID_ALICE, UID_ALICE)
    unlk_file = os.path.join(alice_dir, "unlocked.txt")
    safe_write(unlk_file, LK_SECRET + b"\n", 0o600, UID_ALICE, UID_ALICE)

    # (b) a GROUP-restricted file 0640 alice:staff — bob (not staff) could never
    #     reach it even WITH a valid bob token, so auth-fail must look identical to
    #     the forbidden-existing case (no group/existence distinction leaks).
    grp_file = os.path.join(alice_dir, "staffonly.txt")
    safe_write(grp_file, GRP_SECRET + b"\n", 0o640, UID_ALICE, GID_STAFF)

    # (c) a 0700 dir owned by carol with a child secret — child existence must NOT
    #     be confirmable through an auth-failed request (no dir-listing/timing leak).
    p700_dir = os.path.join(root_dir, "carol700")
    safe_mkdir(p700_dir, 0o700, UID_CAROL, UID_CAROL)
    p700_child = os.path.join(p700_dir, "inside.txt")
    safe_write(p700_child, P700_SECRET + b"\n", 0o600, UID_CAROL, UID_CAROL)

    # (e) setgid dir (02770 alice:staff) child + sticky dir (01777) child.
    sgid_dir = os.path.join(root_dir, "sgid")
    safe_mkdir(sgid_dir, 0o2770, UID_ALICE, GID_STAFF)
    sgid_child = os.path.join(sgid_dir, "sgkid.txt")
    safe_write(sgid_child, SGID_SECRET + b"\n", 0o640, UID_ALICE, GID_STAFF)
    stk_dir = os.path.join(root_dir, "sticky")
    safe_mkdir(stk_dir, 0o1777, UID_SVC, UID_SVC)
    stk_child = os.path.join(stk_dir, "stkkid.txt")
    safe_write(stk_child, STK_SECRET + b"\n", 0o600, UID_BOB, UID_BOB)

    # a world-readable positive-control file owned by alice (valid-token success).
    pc_file = os.path.join(alice_dir, "pc_ok.txt")
    safe_write(pc_file, b"COMBO-AF-PC-OK\n", 0o644, UID_ALICE, UID_ALICE)

    # URL bases (relative to export root).
    base = f"/{TAG}_root"
    P_EXISTING = f"{base}/bob/existing_secret.txt"
    P_ABSENT = f"{base}/bob/this_does_not_exist_zzz.txt"   # forbidden-NONexistent
    P_LOCKED = f"{base}/alice/locked.txt"
    P_UNLOCKED = f"{base}/alice/unlocked.txt"
    P_GRP = f"{base}/alice/staffonly.txt"
    P_700CHILD = f"{base}/carol700/inside.txt"
    P_700ABSENT = f"{base}/carol700/nope_zzz.txt"
    P_SGIDCHILD = f"{base}/sgid/sgkid.txt"
    P_SGIDABSENT = f"{base}/sgid/nope_zzz.txt"
    P_STKCHILD = f"{base}/sticky/stkkid.txt"
    P_PC = f"{base}/alice/pc_ok.txt"

    # forged / failing bearer credentials (each MUST fail auth).
    bad = [
        ("expired", mint(key, "alice", exp=now - 120, iat=now - 240)),
        ("wrong-aud", mint(key, "alice", aud="https://wrong.aud/")),
        ("wrong-iss", mint(key, "alice", iss="https://evil.example/")),
        ("not-yet-valid", mint(key, "alice", nbf=now + 99999)),
        ("alg-none", (_b64u(json.dumps({"alg": "none", "typ": "JWT", "kid": KID},
                                       separators=(",", ":")).encode()) + "."
                      + _b64u(json.dumps({"iss": ISSUER, "sub": "alice",
                                          "aud": AUDIENCE, "exp": now + 3600,
                                          "iat": now, "nbf": now,
                                          "scope": WRITE_SCOPE},
                                         separators=(",", ":")).encode()) + ".")),
        ("foreign-key", mint(ec.generate_private_key(ec.SECP256R1()), "alice")),
        ("unmapped-sub", mint(key, "mallory")),   # well-signed but no uid mapping
        ("garbage", "not.a.jwt"),
    ]

    # =====================================================================
    # SECTION 1: WebDAV — per-credential UNIFORMITY across resource states.
    #   For each bad credential, GET the same forbidden-existing, the
    #   forbidden-absent, the locked, the group-only, the 0700-child, the
    #   setgid-child and the sticky-child.  Collect statuses; assert none is
    #   2xx, no secret leaks, AND all statuses are identical (no oracle).
    # =====================================================================
    targets = [
        ("existing", P_EXISTING, EX_SECRET),
        ("absent", P_ABSENT, None),
        ("locked", P_LOCKED, LK_SECRET),
        ("group-only", P_GRP, GRP_SECRET),
        ("0700-child", P_700CHILD, P700_SECRET),
        ("0700-absent", P_700ABSENT, None),
        ("setgid-child", P_SGIDCHILD, SGID_SECRET),
        ("sticky-child", P_STKCHILD, STK_SECRET),
    ]

    for label, tok in bad:
        statuses = {}
        for tname, tpath, secret in targets:
            st, b = http("GET", tpath, port, tok)
            statuses[tname] = st
            ok(not is_2xx(st),
               f"{TAG}: WebDAV {label} GET {tname} not authenticated, "
               f"not 2xx (HTTP {st})")
            if secret is not None:
                ok(no_marker(b, secret),
                   f"{TAG}: WebDAV {label} GET {tname} leaks no secret bytes "
                   f"(HTTP {st})")
        # existence oracle: forbidden-EXISTING vs forbidden-ABSENT must match.
        ok(statuses["existing"] == statuses["absent"],
           f"{TAG}: WebDAV {label} — existing vs absent SAME status "
           f"(no existence oracle: {statuses['existing']} vs {statuses['absent']})")
        ok(statuses["0700-child"] == statuses["0700-absent"],
           f"{TAG}: WebDAV {label} — 0700 child vs absent-in-0700 SAME status "
           f"(no child-existence oracle: {statuses['0700-child']} vs "
           f"{statuses['0700-absent']})")
        # lock-state oracle: locked vs unlocked sibling must match for bad cred.
        st_unl, b_unl = http("GET", P_UNLOCKED, port, tok)
        ok(statuses["locked"] == st_unl,
           f"{TAG}: WebDAV {label} — locked vs unlocked SAME status "
           f"(no lock-state oracle: {statuses['locked']} vs {st_unl})")
        ok(no_marker(b_unl, LK_SECRET),
           f"{TAG}: WebDAV {label} GET unlocked sibling leaks no secret (HTTP {st_unl})")
        # group-only target must look like any other forbidden target (auth-first).
        ok(statuses["group-only"] == statuses["existing"],
           f"{TAG}: WebDAV {label} — group-only vs forbidden-existing SAME status "
           f"(auth fires before DAC: {statuses['group-only']} vs "
           f"{statuses['existing']})")
        # whole-set uniformity: a bad credential yields ONE status everywhere.
        ok(len(set(statuses.values())) == 1,
           f"{TAG}: WebDAV {label} — uniform status across ALL resource states "
           f"(no resource-state oracle: {sorted(set(statuses.values()))})")

    # Bad-credential WRITE/metadata verbs must also not betray resource state and
    # must create/lock nothing.  PROPFIND (metadata) and LOCK (lock-state) on the
    # forbidden-existing vs absent must match per bad cred.
    for label, tok in bad[:4]:
        st_pe, _ = http("PROPFIND", P_EXISTING, port, tok, hdrs={"Depth": "0"})
        st_pa, _ = http("PROPFIND", P_ABSENT, port, tok, hdrs={"Depth": "0"})
        ok(not is_2xx(st_pe) and st_pe == st_pa,
           f"{TAG}: WebDAV {label} PROPFIND existing==absent, not 2xx "
           f"(no metadata oracle: {st_pe} vs {st_pa})")
        st_le, _ = http("LOCK", P_EXISTING, port, tok,
                        data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                             b'<D:lockscope><D:exclusive/></D:lockscope>'
                             b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                        hdrs={"Content-Type": "application/xml"})
        st_la, _ = http("LOCK", P_ABSENT, port, tok,
                        data=b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                             b'<D:lockscope><D:exclusive/></D:lockscope>'
                             b'<D:locktype><D:write/></D:locktype></D:lockinfo>',
                        hdrs={"Content-Type": "application/xml"})
        ok(not is_2xx(st_le) and st_le == st_la,
           f"{TAG}: WebDAV {label} LOCK existing==absent, not 2xx "
           f"(no lock-creation via bad cred: {st_le} vs {st_la})")
        new_path = os.path.join(bob_dir, f"af_{label}.txt")
        http("PUT", f"{base}/bob/af_{label}.txt", port, tok, data=b"x\n")
        ok(not safe_exists(new_path),
           f"{TAG}: WebDAV {label} PUT into bob's dir created nothing")

    # =====================================================================
    # SECTION 2: WebDAV positive controls — auth fires, but a VALID token at
    #   the correct identity gets the RIGHT answer for each resource state.
    #   (proves the uniform deny above isn't a blanket reject of everything.)
    # =====================================================================
    ta, tb, tc = mint(key, "alice"), mint(key, "bob"), mint(key, "carol")
    st, b = http("GET", P_PC, port, ta)
    ok(st == 200 and b"COMBO-AF-PC-OK" in (b or b""),
       f"{TAG}: PC valid alice reads her own world-readable file (HTTP {st})")
    # valid bob: existing_secret.txt is BOB's OWN 0600 file (owner=UID_BOB), so
    # with a valid bob token DAC grants owner-read -> 200 + his own bytes.  This
    # is the positive control proving the bad-cred uniform-deny above was AUTH,
    # not a broken path.  The security property is that bob gets ONLY his own
    # data (no OTHER tenant's secret) and the file stays bob-owned.  absent ->
    # 404-class (existence distinction allowed once DAC has run for the owner).
    st_e, b_e = http("GET", P_EXISTING, port, tb)
    ok(st_e == 200 and EX_SECRET in (b_e or b"")
       and no_marker(b_e, GRP_SECRET) and no_marker(b_e, LK_SECRET)
       and no_marker(b_e, P700_SECRET),
       f"{TAG}: PC valid bob (owner) reads his own 0600 file, no other-tenant "
       f"leak (HTTP {st_e})")
    ok(file_owner(ex_file) == (UID_BOB, UID_BOB),
       f"{TAG}: PC valid bob owner-read left existing_secret.txt bob-owned")
    st_a, _ = http("GET", P_ABSENT, port, tb)
    ok(not is_2xx(st_a),
       f"{TAG}: PC valid bob on absent path not 2xx (HTTP {st_a})")
    # carol owns the 0700 dir -> she CAN read its child (control that the bad-cred
    # deny above was auth, not a broken path).
    st_c, b_c = http("GET", P_700CHILD, port, tc)
    ok(st_c == 200 and P700_SECRET in (b_c or b""),
       f"{TAG}: PC valid carol (owner) reads her 0700-dir child (HTTP {st_c})")
    # alice (in staff) reads the group-only file -> proves it's reachable for the
    # right identity, so the bad-cred uniform-deny was about AUTH not reachability.
    st_g, b_g = http("GET", P_GRP, port, ta)
    ok(st_g == 200 and GRP_SECRET in (b_g or b""),
       f"{TAG}: PC valid alice reads her 0640 staff group file (HTTP {st_g})")
    # nothing the forged creds did left residue: ownerships unchanged.
    ok(file_owner(ex_file) == (UID_BOB, UID_BOB),
       f"{TAG}: forbidden-existing file still bob-owned after forged-cred storm")
    ok(file_owner(grp_file) == (UID_ALICE, GID_STAFF),
       f"{TAG}: group-only file still alice:staff after forged-cred storm")

    # =====================================================================
    # SECTION 3: S3 — forged/tampered SigV4 + bearer-on-S3 against the SAME
    #   resource-state spread.  Only "alice" key is configured, so we attack
    #   with (i) a TAMPERED presign, (ii) a bearer token on the S3 port
    #   (wrong scheme), (iii) a backdated/expired presign.  Each must be a
    #   uniform non-2xx with no secret leak across existing/absent/locked/
    #   group/0700-child/setgid-child — no resource-state oracle on S3.
    # =====================================================================
    if s3port:
        s3_keys = [
            ("existing", f"{TAG}_root/bob/existing_secret.txt", EX_SECRET),
            ("absent", f"{TAG}_root/bob/nope_zzz.txt", None),
            ("group-only", f"{TAG}_root/alice/staffonly.txt", GRP_SECRET),
            ("0700-child", f"{TAG}_root/carol700/inside.txt", P700_SECRET),
            ("setgid-child", f"{TAG}_root/sgid/sgkid.txt", SGID_SECRET),
            ("locked", f"{TAG}_root/alice/locked.txt", LK_SECRET),
        ]

        # (i) tampered presigned URL (signature forged) — auth must fail uniformly.
        tamper_stat = {}
        for kname, kkey, secret in s3_keys:
            ppath = s3_presign("GET", kkey, s3port, tamper=True)
            st, b = http("GET", ppath, s3port)
            tamper_stat[kname] = st
            ok(not is_2xx(st),
               f"{TAG}: S3 tampered-presign GET {kname} not 2xx (HTTP {st})")
            if secret is not None:
                ok(no_marker(b, secret),
                   f"{TAG}: S3 tampered-presign GET {kname} no secret leak (HTTP {st})")
        ok(tamper_stat["existing"] == tamper_stat["absent"],
           f"{TAG}: S3 tampered-presign existing==absent "
           f"(no existence oracle: {tamper_stat['existing']} vs "
           f"{tamper_stat['absent']})")
        ok(len(set(tamper_stat.values())) == 1,
           f"{TAG}: S3 tampered-presign uniform across resource states "
           f"(no oracle: {sorted(set(tamper_stat.values()))})")

        # (ii) bearer token on the S3 port (wrong auth scheme) — same spread.
        bearer_stat = {}
        for kname, kkey, secret in s3_keys:
            st, b = http("GET", f"/{S3_BUCKET}/{kkey}", s3port,
                         hdrs={"Authorization": f"Bearer {mint(key, 'alice')}"})
            bearer_stat[kname] = st
            ok(not is_2xx(st),
               f"{TAG}: S3 bearer-on-S3 GET {kname} not 2xx (HTTP {st})")
            if secret is not None:
                ok(no_marker(b, secret),
                   f"{TAG}: S3 bearer-on-S3 GET {kname} no secret leak (HTTP {st})")
        ok(bearer_stat["existing"] == bearer_stat["absent"],
           f"{TAG}: S3 bearer-on-S3 existing==absent "
           f"(no existence oracle: {bearer_stat['existing']} vs "
           f"{bearer_stat['absent']})")
        ok(len(set(bearer_stat.values())) == 1,
           f"{TAG}: S3 bearer-on-S3 uniform across resource states "
           f"(no oracle: {sorted(set(bearer_stat.values()))})")

        # (iii) backdated/expired presign — same spread, must be uniform deny.
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
        exp_stat = {}
        for kname, kkey, secret in s3_keys:
            ppath = s3_presign("GET", kkey, s3port, expires=60, when=old)
            st, b = http("GET", ppath, s3port)
            exp_stat[kname] = st
            ok(not is_2xx(st),
               f"{TAG}: S3 expired-presign GET {kname} not 2xx (HTTP {st})")
            if secret is not None:
                ok(no_marker(b, secret),
                   f"{TAG}: S3 expired-presign GET {kname} no secret leak (HTTP {st})")
        ok(exp_stat["existing"] == exp_stat["absent"],
           f"{TAG}: S3 expired-presign existing==absent "
           f"(no existence oracle: {exp_stat['existing']} vs {exp_stat['absent']})")
        ok(len(set(exp_stat.values())) == 1,
           f"{TAG}: S3 expired-presign uniform across resource states "
           f"(no oracle: {sorted(set(exp_stat.values()))})")

        # S3 positive control: alice (valid SigV4) reads her own world-readable
        # control file (so the uniform deny isn't a dead endpoint).
        safe_write(os.path.join(alice_dir, "s3pc.txt"),
                   b"COMBO-AF-S3PC\n", 0o644, UID_ALICE, UID_ALICE)
        st, b = s3("GET", f"{TAG}_root/alice/s3pc.txt", s3port)
        ok(st == 200 and b"COMBO-AF-S3PC" in (b or b""),
           f"{TAG}: S3 PC valid alice reads her own file (HTTP {st})")
        # and valid alice on bob's 0600 existing -> denied (DAC), no leak: proves
        # the bad-cred denies above were AUTH, this one is DAC, both no-leak.
        st, b = s3("GET", f"{TAG}_root/bob/existing_secret.txt", s3port)
        ok(not is_2xx(st) and no_marker(b, EX_SECRET),
           f"{TAG}: S3 PC valid alice denied bob's 0600 (DAC), no leak (HTTP {st})")

    # =====================================================================
    # SECTION 4: root:// — forged-token resource-state oracle.  Drive native
    #   xrdfs with forged tokens at stat/cat across existing/absent/locked/
    #   group/0700-child/setgid-child.  rc must be non-zero everywhere, no
    #   secret bytes, and the forged-token outcome must not distinguish
    #   existing from absent (no existence oracle on the stream plane).
    # =====================================================================
    if xrd_avail():
        root_targets = [
            ("existing", f"/{TAG}_root/bob/existing_secret.txt", EX_SECRET),
            ("absent", f"/{TAG}_root/bob/nope_zzz.txt", None),
            ("group-only", f"/{TAG}_root/alice/staffonly.txt", GRP_SECRET),
            ("0700-child", f"/{TAG}_root/carol700/inside.txt", P700_SECRET),
            ("setgid-child", f"/{TAG}_root/sgid/sgkid.txt", SGID_SECRET),
            ("locked", f"/{TAG}_root/alice/locked.txt", LK_SECRET),
        ]
        for flabel, ftok in _forged_tokens(key):
            rcs = {}
            for tname, tpath, secret in root_targets:
                rc, out, _e = xrd_fs_token(["cat", tpath], ftok)
                rcs[tname] = (rc == 0)
                ok(rc != 0,
                   f"{TAG}: root:// forged[{flabel}] cat {tname} rejected (rc={rc})")
                if secret is not None:
                    ok(secret.decode() not in (out or ""),
                       f"{TAG}: root:// forged[{flabel}] cat {tname} no secret leak")
            # stat existing vs absent under forged token: neither must succeed
            # (a succeeding stat on existing-only would be an existence oracle).
            rc_se, _o, _e = xrd_fs_token(
                ["stat", f"/{TAG}_root/bob/existing_secret.txt"], ftok)
            rc_sa, _o, _e = xrd_fs_token(
                ["stat", f"/{TAG}_root/bob/nope_zzz.txt"], ftok)
            ok(rc_se != 0 and rc_sa != 0,
               f"{TAG}: root:// forged[{flabel}] stat existing & absent BOTH "
               f"rejected (no existence oracle: {rc_se}/{rc_sa})")
            ok(not any(rcs.values()),
               f"{TAG}: root:// forged[{flabel}] every cat failed uniformly "
               f"(no resource-state success leak)")

        # root:// positive controls: valid carol cats her own 0700-dir child;
        # valid bob denied alice's group file & no leak.
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/carol700/inside.txt"], "carol")
        ok(rc == 0 and P700_SECRET.decode() in (out or ""),
           f"{TAG}: root:// PC valid carol reads her 0700-dir child (rc={rc})")
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/alice/staffonly.txt"], "bob")
        ok(rc != 0 and GRP_SECRET.decode() not in (out or ""),
           f"{TAG}: root:// PC valid bob denied alice's staff file, no leak (rc={rc})")
        rc, out, _e = xrd_fs(["cat", f"/{TAG}_root/alice/staffonly.txt"], "alice")
        ok(rc == 0 and GRP_SECRET.decode() in (out or ""),
           f"{TAG}: root:// PC owner alice reads her staff group file (rc={rc})")

    # =====================================================================
    # SECTION 5: worker survival + no-residue after the forged-credential
    #   storm — a follow-up LEGIT op must still work, and nothing the bad
    #   credentials touched produced a svc/root/wrong-owner artifact.
    # =====================================================================
    st, b = http("GET", P_PC, port, ta)
    ok(st == 200 and b"COMBO-AF-PC-OK" in (b or b""),
       f"{TAG}: worker survived forged-credential storm (follow-up GET OK, HTTP {st})")
    # the 0700 dir must still be carol-owned & mode-0700 (no broker leak created a
    # svc/root-owned child or relaxed the dir during the auth-failure barrage).
    ok(file_owner(p700_dir) == (UID_CAROL, UID_CAROL),
       f"{TAG}: carol's 0700 dir still carol-owned after storm")
    try:
        children = set(os.listdir(p700_dir))
    except OSError:
        children = set()
    ok(children == {"inside.txt"},
       f"{TAG}: no forged-cred artifact appeared in carol's 0700 dir ({sorted(children)})")
    # sticky/setgid dirs unchanged, no svc/root residue in bob's dir.
    ok(file_owner(sgid_dir)[1] == GID_STAFF,
       f"{TAG}: setgid dir kept its alice:staff group after storm")
    try:
        bobkids = os.listdir(bob_dir)
    except OSError:
        bobkids = []
    residue = [k for k in bobkids
               if file_owner(os.path.join(bob_dir, k))[0] in (UID_SVC, 0)]
    ok(not residue,
       f"{TAG}: no svc/root-owned residue in bob's dir after storm ({residue})")


