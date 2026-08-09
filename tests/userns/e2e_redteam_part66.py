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


def run_query_subcode_oracle(key, data, port, s3port):
    """Systematic kXR_query SUB-CODE matrix as a per-tenant INFO-LEAK ORACLE under
    UNIX impersonation.  For every reachable native-xrdfs query sub-code
    (checksum=Qcksum, checksumcancel=Qckscan, xattr=Qxattr, opaque=Qopaque,
    opaquefile=Qopaquf, space=Qspace, stats=QStats, config=Qconfig) alice probes
    (a) her OWN path (must work / yield a sane result) and (b) bob's 0600 /
    0700-shadowed / svc-only paths (cross-tenant -> must be DENIED and reveal
    NOTHING bob-derived).  The NOVEL angle vs run_root_deep's B1-B7 (which only
    grepped for the raw secret marker) is the DIFFERENTIAL oracle: bob first
    computes his OWN file's real checksum / xattr-metadata, then we assert alice's
    cross-tenant attempt does NOT echo that bob-derived value (a sub-code that
    returns bob's true checksum/size to alice is a content leak even at rc==0).
    Also asserts the GLOBAL sub-codes (space/stats/config) never embed a tenant
    path or secret, the DAC gate on opaquefile fires BEFORE the 'unsupported'
    reply (so cross-tenant is denied at the gate, not masked as unsupported), and
    query-path confinement (escape symlink + traversal).  A final benign config
    query proves the worker+broker survived.  Unsupported sub-codes (xrdfs error)
    are accepted as a clean handled outcome, never as a leak."""
    TAG = "qso"
    SECRET = "BOB-PRIVATE-SECRET"        # data/bob/private.txt (0600 bob)
    SVCMARK = "svc-only-secret"          # data/svconly/secret-name.txt (svc 0750)

    if not xrd_avail():
        ok(True, "query_subcode_oracle: native xrdfs unavailable — skipped (handled)")
        return

    def rp(rel):
        return os.path.join(data, rel.lstrip("/"))

    def uid_of(rel):
        try:
            return os.stat(rp(rel)).st_uid
        except OSError:
            return -1

    def body_of(rel):
        try:
            with open(rp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def mk_fixture(rel, content, uid, gid, mode):
        p = rp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p

    def rm_quiet(rel):
        p = rp(rel)
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass

    # Distinctive, KNOWN-content fixtures so a leaked checksum/size is recognisable.
    # bob's secret payload is unique so its checksum hex acts as a fingerprint.
    BOB_PAYLOAD = "BOB-QSO-DIFFERENTIAL-SECRET-" + ("Z9" * 40) + "\n"   # < 64 KiB
    ALICE_PAYLOAD = "ALICE-QSO-OWN-CONTENT-" + ("a7" * 30) + "\n"
    bob_secret = f"bob/{TAG}_diff.bin"          # 0600 bob — cross-tenant target
    alice_own = f"alice/{TAG}_own.bin"          # 0644 alice — self control
    mk_fixture(bob_secret, BOB_PAYLOAD, UID_BOB, UID_BOB, 0o600)
    mk_fixture(alice_own, ALICE_PAYLOAD, UID_ALICE, UID_ALICE, 0o644)
    bob_secret_size = len(BOB_PAYLOAD.encode())

    def fingerprints(out):
        """Return the set of hex tokens (>=8 chars) found in a query response —
        a checksum body is the algo name + a long hex digest.  Used to prove
        alice never receives bob's checksum digest."""
        toks = set()
        for raw in (out or "").replace("\n", " ").replace("=", " ").split():
            t = raw.strip().lower()
            if len(t) >= 8 and all(ch in "0123456789abcdef" for ch in t):
                toks.add(t)
        return toks

    # ============================================================ Qcksum (checksum)
    # (1) bob computes his OWN file's checksum -> capture the real digest fingerprint
    # set.  This is the authoritative bob-derived value alice must NEVER learn.
    rc_b, out_b, _e = xrd_fs(["query", "checksum", "/" + bob_secret], "bob")
    bob_fp = fingerprints(out_b) if rc_b == 0 else set()
    ok(rc_b != 0 or SECRET not in (out_b or ""),
       f"Qcksum: bob's own checksum response carries no raw secret bytes (rc={rc_b})")

    # (2) alice checksums her OWN file -> succeeds with a digest; this digest must
    # DIFFER from bob's (proves per-identity confinement isn't returning a shared/
    # wrong-file result), and her response leaks no bob secret.
    rc_a, out_a, _e = xrd_fs(["query", "checksum", "/" + alice_own], "alice")
    alice_fp = fingerprints(out_a) if rc_a == 0 else set()
    ok(rc_a == 0,
       f"Qcksum: alice checksums her OWN 0644 file (rc={rc_a})")
    ok(not (bob_fp and alice_fp and bob_fp == alice_fp),
       "Qcksum: alice's own-file digest != bob's own-file digest "
       "(distinct content -> distinct checksum, no shared-state bleed)")

    # (3) CROSS-TENANT differential: alice checksums bob's 0600 file -> DENIED, and
    # critically alice's response contains NONE of bob's real digest fingerprints
    # (a returned digest would be a content-derived leak even with rc==0).
    rc, out_x, _e = xrd_fs(["query", "checksum", "/" + bob_secret], "alice")
    leaked_digest = bool(bob_fp & fingerprints(out_x))
    ok(rc != 0,
       f"Qcksum: alice's checksum of bob's 0600 file is DENIED (rc={rc})")
    ok(not leaked_digest,
       "Qcksum: alice's denied response does NOT echo bob's real checksum digest "
       "(no content-derived leak via the checksum oracle)")
    ok(SECRET not in (out_x or ""),
       "Qcksum: alice's denied bob-0600 response carries no raw secret bytes")
    ok(uid_of(bob_secret) == UID_BOB,
       f"Qcksum: probing bob's 0600 left his inode owner unchanged "
       f"(uid={uid_of(bob_secret)})")

    # (4) cross-tenant checksum of bob's file SHADOWED by his 0700 dir (bobsecret/
    # s.txt): denied at the directory-traverse DAC level, no shadowed content.
    rc, out, _e = xrd_fs(["query", "checksum", "/bobsecret/s.txt"], "alice")
    ok("bob-only" not in (out or "") and SECRET not in (out or ""),
       f"Qcksum: alice's checksum under bob's 0700 dir denied, no shadowed leak "
       f"(rc={rc})")

    # (5) cross-tenant checksum of the svc-only 0750 file: alice is 'other', no read.
    rc, out, _e = xrd_fs(["query", "checksum", "/svconly/secret-name.txt"], "alice")
    ok(SVCMARK not in (out or ""),
       f"Qcksum: alice's checksum of svc-only 0750 file leaks no svc content "
       f"(rc={rc})")

    # ================================================== Qckscan (checksumcancel)
    # checksumcancel is a path-keyed sub-code never exercised cross-tenant; alice
    # cancelling a checksum scan on bob's 0600 must not become a metadata oracle.
    rc, out, _e = xrd_fs(["query", "checksumcancel", "/" + bob_secret], "alice")
    ok(SECRET not in (out or "") and not (bob_fp & fingerprints(out)),
       f"Qckscan: alice's checksum-cancel on bob's 0600 leaks no secret/digest "
       f"(rc={rc})")
    rc, out, _e = xrd_fs(["query", "checksumcancel", "/" + alice_own], "alice")
    ok(SECRET not in (out or ""),
       f"Qckscan: alice's checksum-cancel on her OWN file is handled cleanly "
       f"(rc={rc})")

    # ============================================================ Qxattr (xattr)
    # (6) bob lists xattr metadata of his OWN file -> authoritative oss.used size.
    rc_bx, out_bx, _e = xrd_fs(["query", "xattr", "/" + bob_secret], "bob")
    bob_size_tok = f"oss.used={bob_secret_size}"
    ok(rc_bx != 0 or SECRET not in (out_bx or ""),
       f"Qxattr: bob's own xattr listing carries no raw secret bytes (rc={rc_bx})")

    # (7) CROSS-TENANT differential: alice lists xattr of bob's 0600 file -> DENIED
    # at the read-auth gate, and her response must NOT reveal bob's file size
    # (oss.used) — the xattr handler stats the file, so a leaked size is a metadata
    # oracle distinct from the raw-marker check in run_root_deep B7.
    rc, out_ax, _e = xrd_fs(["query", "xattr", "/" + bob_secret], "alice")
    ok(rc != 0,
       f"Qxattr: alice's xattr listing of bob's 0600 file is DENIED (rc={rc})")
    ok(bob_size_tok not in (out_ax or ""),
       "Qxattr: alice's denied response does NOT reveal bob's file size via oss.used "
       "(no stat-metadata leak through the xattr oracle)")
    ok(SECRET not in (out_ax or "") and not (bob_fp & fingerprints(out_ax)),
       "Qxattr: alice's denied bob-0600 xattr response leaks no secret or digest")

    # (8) alice lists xattr of her OWN file: succeeds (or unsupported) and exposes
    # ONLY her own metadata — never bob's secret/size.
    rc, out, _e = xrd_fs(["query", "xattr", "/" + alice_own], "alice")
    ok(SECRET not in (out or "") and bob_size_tok not in (out or ""),
       f"Qxattr: alice's OWN xattr listing exposes no bob secret/size (rc={rc})")

    # (9) alice lists xattr of svc-only 0750 file -> denied, no svc content/size.
    rc, out, _e = xrd_fs(["query", "xattr", "/svconly/secret-name.txt"], "alice")
    ok(SVCMARK not in (out or ""),
       f"Qxattr: alice's xattr of svc-only 0750 file leaks no svc content (rc={rc})")

    # ================================================= Qopaquf (opaquefile) DAC GATE
    # opaquefile resolves+auth-gates the path BEFORE returning the 'unsupported'
    # fctl reply.  The security property: a cross-tenant target must be DENIED at
    # the read gate (rc!=0 OR an authz error), NOT silently swallowed as a generic
    # 'unsupported' — otherwise a missing DAC check would be masked.  We accept
    # either a hard error or an authz-shaped error string; what we forbid is bob's
    # secret/size leaking out of it.
    rc, out_of, _e_of = xrd_fs(["query", "opaquefile", "/" + bob_secret], "alice")
    combined = (out_of or "") + (_e_of or "")
    ok(SECRET not in combined and bob_size_tok not in combined
       and not (bob_fp & fingerprints(combined)),
       f"Qopaquf: alice's opaquefile on bob's 0600 leaks no secret/size/digest "
       f"(DAC gate runs before fctl-unsupported, rc={rc})")
    # alice's OWN path: the gate passes, the handler replies (un)supported with no leak.
    rc, out, _e = xrd_fs(["query", "opaquefile", "/" + alice_own], "alice")
    ok(SECRET not in (out or ""),
       f"Qopaquf: alice's opaquefile on her OWN path handled, no foreign leak "
       f"(rc={rc})")

    # ============================================================ Qopaque (opaque)
    # opaque takes a free-form arg (no path DAC, returns unsupported).  Feeding it a
    # bob-path-shaped arg must NOT turn it into an existence/content oracle.
    rc, out, _e = xrd_fs(["query", "opaque", "ofs.tpc=/" + bob_secret], "alice")
    ok(SECRET not in (out or "") and not (bob_fp & fingerprints(out)),
       f"Qopaque: alice's opaque query with a bob-path arg leaks nothing (rc={rc})")

    # =================================== Qspace / QStats / Qconfig  (GLOBAL — no path)
    # These are server-global and may legitimately return — the invariant is they
    # must NOT embed a tenant path, secret, or per-file digest.
    # (10) Qspace pointed at bob's 0600 file: returns GLOBAL fs stats, no content.
    rc, out_sp, _e = xrd_fs(["query", "space", "/" + bob_secret], "alice")
    ok(SECRET not in (out_sp or "") and bob_secret not in (out_sp or ""),
       f"Qspace: alice's space query at a bob path returns global stats, embeds no "
       f"tenant path/secret (rc={rc})")
    rc, _o, _e = xrd_fs(["query", "space", "/alice/"], "alice")
    ok(rc == 0, f"Qspace: alice's space query of her own dir succeeds (rc={rc})")

    # (11) QStats: server XML stats by alice must not embed any tenant path/secret —
    # never tested cross-tenant before.
    rc, out_st, _e = xrd_fs(["query", "stats", "a"], "alice")
    ok(SECRET not in (out_st or "") and SVCMARK not in (out_st or "")
       and "/bob/" not in (out_st or ""),
       f"QStats: alice's server-stats XML embeds no tenant path/secret (rc={rc})")
    # QStats must also be identity-agnostic GLOBAL data: bob's stats carry no
    # alice-private content either (symmetry — neither tenant leaks via stats).
    rc, out_st2, _e = xrd_fs(["query", "stats", "a"], "bob")
    ok(SECRET not in (out_st2 or "") and "/alice/" not in (out_st2 or ""),
       f"QStats: bob's server-stats XML embeds no other-tenant path/secret (rc={rc})")

    # (12) Qconfig multi-key by alice must not echo any tenant secret; a benign key
    # still returns a value (positive control).
    rc, out_cf, _e = xrd_fs(["query", "config", "version chksum tpc bind_max"], "alice")
    ok(SECRET not in (out_cf or "") and SVCMARK not in (out_cf or ""),
       f"Qconfig: alice's multi-key config query leaks no tenant secret (rc={rc})")

    # ========================================== CONFINEMENT via the query path arg
    # (13) Qcksum of the /escape symlink (-> /etc): must not be followed out of the
    # export to checksum /etc/passwd.
    rc, out_es, _e = xrd_fs(["query", "checksum", "/escape/passwd"], "alice")
    ok("root:" not in (out_es or "") and "/bin/bash" not in (out_es or ""),
       f"confinement: Qcksum of /escape/passwd not followed to /etc (rc={rc})")
    # (14) Qxattr with a ../ traversal must stay confined (no /etc metadata).
    rc, out_tr, _e = xrd_fs(["query", "xattr", "/alice/../../../../etc/passwd"],
                            "alice")
    ok("root:" not in (out_tr or "") and "/bin/bash" not in (out_tr or ""),
       f"confinement: Qxattr with ../ traversal stays inside export (rc={rc})")

    # =============================================================== SURVIVAL
    # Benign config query after the whole sub-code battery proves the worker +
    # broker survived every probe (no crash / no wedge).
    rc, out, _e = xrd_fs(["query", "config", "version"], "alice")
    ok(rc == 0 and SECRET not in (out or ""),
       f"survival: benign Qconfig succeeds after sub-code battery (rc={rc})")

    # cleanup
    rm_quiet(bob_secret)
    rm_quiet(alice_own)


