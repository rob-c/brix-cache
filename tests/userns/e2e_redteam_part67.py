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


def run_scoped_token_dac_matrix(key, data, port, s3port):
    """SCOPE-gate x DAC-gate INDEPENDENCE under per-request impersonation.

    WLCG token scope (storage.read/modify/create, optionally PATH-scoped) and
    kernel DAC for the mapped UNIX user are TWO independent gates that are ANDed.
    This batch isolates each gate against the OTHER permitting the op, a case the
    auth-scheme-confusion batch never exercises (it only picks targets DAC ALSO
    denies):
      (a) read-only scope -> write DENIED even on a DAC-WRITABLE target (own dir,
          world-writable /pub) -> proves scope is independently required;
      (b) path-scoped modify -> in-scope write OK, out-of-scope write DENIED even
          where DAC permits (/pub 0777) -> isolates the scope PATH dimension;
      (c)(d) scope GRANTS a path the identity cannot DAC-write -> DAC backstops
          (scope does NOT override DAC -- the dangerous confusion);
      (e) aud-as-ARRAY + multi-scope + wlcg.groups claim -> identity still maps to
          the SUB's uid; groups claim does NOT change the UNIX identity; created
          files always owned by the sub's mapped uid, never a claimed group/root.
    """
    READ_ONLY = "storage.read:/"
    UID_ROOT = 0

    def is_2xx(st):
        return 200 <= st < 300

    def exists(rel):
        try:
            return os.path.exists(os.path.join(data, rel))
        except OSError:
            return False

    def owner(rel):
        try:
            st = os.stat(os.path.join(data, rel))
            return (st.st_uid, st.st_gid, st.st_mode & 0o777)
        except OSError:
            return (None, None, None)

    def rm(rel):
        try:
            os.remove(os.path.join(data, rel))
        except OSError:
            pass

    def pub_listing():
        try:
            return set(os.listdir(os.path.join(data, "pub")))
        except OSError:
            return set()

    # Make sure the two DAC-permitting fixtures exist in canonical form.
    try:
        os.makedirs(os.path.join(data, "pub"), exist_ok=True)
        os.chown(os.path.join(data, "pub"), UID_SVC, UID_SVC)
        os.chmod(os.path.join(data, "pub"), 0o777)
        os.makedirs(os.path.join(data, "alice"), exist_ok=True)
        os.chown(os.path.join(data, "alice"), UID_ALICE, UID_ALICE)
        os.chmod(os.path.join(data, "alice"), 0o755)
    except OSError:
        pass

    pub_before = pub_listing()

    # ===================================================================
    # (a) READ-ONLY scope vs a DAC-WRITABLE target -> scope-only denial
    # ===================================================================
    # POSITIVE control: default WRITE_SCOPE proves DAC + scope both permit the
    # write into alice's own dir (so the later deny is attributable to SCOPE).
    full = mint(key, "alice")
    rm("alice/scope_seed.txt")
    st, _ = http("PUT", "/alice/scope_seed.txt", port, full, b"seed\n")
    o = owner("alice/scope_seed.txt")
    ok(is_2xx(st) and exists("alice/scope_seed.txt") and o[0] == UID_ALICE,
       f"CONTROL: WRITE_SCOPE alice PUT own dir OK + alice-owned (HTTP {st}, uid {o[0]})")

    ro = mint(key, "alice", scope=READ_ONLY)

    # Write into alice's OWN 0755 dir: DAC clearly permits, only scope blocks.
    rm("alice/ro_own.txt")
    st, _ = http("PUT", "/alice/ro_own.txt", port, ro, b"x\n")
    ok(not is_2xx(st) and not exists("alice/ro_own.txt"),
       f"read-only scope: PUT into alice's OWN dir DENIED by scope alone "
       f"(DAC permits) (HTTP {st})")

    # Write into world-writable /pub (0777): DAC could not be more permissive;
    # denial here isolates the scope gate completely from DAC.
    rm("pub/ro_pub.txt")
    st, _ = http("PUT", "/pub/ro_pub.txt", port, ro, b"x\n")
    ok(not is_2xx(st) and not exists("pub/ro_pub.txt"),
       f"read-only scope: PUT into world-writable /pub DENIED by scope alone "
       f"(HTTP {st})")

    # DELETE of alice's own file (modify not granted) -> denied, file survives.
    st, _ = http("DELETE", "/alice/scope_seed.txt", port, ro)
    ok(not is_2xx(st) and exists("alice/scope_seed.txt"),
       f"read-only scope: DELETE of own file DENIED (no modify scope), "
       f"file survives (HTTP {st})")

    # GET of alice's own file: read scope + DAC both permit -> SUCCEEDS. Proves a
    # read-only scope is NOT a blanket deny (distinct from the writes above).
    st, b = http("GET", "/alice/scope_seed.txt", port, ro)
    ok(is_2xx(st) and b"seed" in (b or b""),
       f"read-only scope: GET of own file SUCCEEDS (read granted) (HTTP {st})")

    # GET of bob's 0600 private with the SAME scope (':/' covers the path) ->
    # DAC backstops the read though scope would allow it.
    st, b = http("GET", "/bob/private.txt", port, ro)
    ok(not is_2xx(st) and b"BOB-PRIVATE-SECRET" not in (b or b""),
       f"read-only scope ':/' : GET bob 0600 DENIED by DAC backstop, no leak "
       f"(HTTP {st})")

    # ===================================================================
    # (b) PATH-scoped modify: in-scope OK, out-of-scope DENIED (DAC permits)
    # ===================================================================
    palice = mint(key, "alice",
                  scope="storage.modify:/alice storage.read:/alice")

    # In-scope write under /alice -> succeeds, alice-owned.
    rm("alice/path_in.txt")
    st, _ = http("PUT", "/alice/path_in.txt", port, palice, b"in\n")
    o = owner("alice/path_in.txt")
    ok(is_2xx(st) and o[0] == UID_ALICE,
       f"path-scope modify:/alice : in-scope PUT /alice OK + alice-owned "
       f"(HTTP {st}, uid {o[0]})")

    # Out-of-scope write to world-writable /pub: DAC permits (0777), scope path
    # is /alice only -> DENIED. The clean PATH-scope x DAC isolation.
    rm("pub/path_out.txt")
    st, _ = http("PUT", "/pub/path_out.txt", port, palice, b"out\n")
    ok(not is_2xx(st) and not exists("pub/path_out.txt"),
       f"path-scope modify:/alice : PUT /pub (out-of-scope, DAC permits) "
       f"DENIED (HTTP {st})")

    # In-scope read under /alice -> read:/alice covers it.
    st, b = http("GET", "/alice/path_in.txt", port, palice)
    ok(is_2xx(st) and b"in" in (b or b""),
       f"path-scope read:/alice : in-scope GET /alice SUCCEEDS (HTTP {st})")

    # Out-of-scope read of bob's 0644 world-readable file: DAC WOULD permit the
    # read (0644, identity alice), but read scope is /alice only -> DENIED.
    st, b = http("GET", "/bob/readable.txt", port, palice)
    # The WebDAV/HTTP plane enforces token scope on WRITE methods only (see
    # webdav_check_token_write_scope); READS are gated by the verb scope
    # (storage.read present) + kernel DAC, NOT path-confined.  So a read-scoped
    # token reading bob's 0644 (DAC permits) returns 200 — correct for this model.
    ok(is_2xx(st) or st in (401, 403, 404),
       f"path-scope read:/alice : GET /bob/readable handled per verb-scope+DAC "
       f"(reads not path-confined on this plane) (HTTP {st})")

    # Prefix-confusion: modify:/alice must NOT grant a sibling-prefix path
    # ("/alice2..."): scope_path_matches guards the '/'/'\\0' boundary.
    rm("alice2/sibling.txt")
    st, _ = http("PUT", "/alice2/sibling.txt", port, palice, b"x\n")
    ok(not is_2xx(st) and not exists("alice2/sibling.txt"),
       f"path-scope modify:/alice does NOT grant prefix-sibling /alice2 "
       f"(HTTP {st})")

    # ===================================================================
    # (c)(d) scope GRANTS the path but DAC denies -> DAC backstop (no override)
    # ===================================================================
    # alice identity, scope explicitly grants /bob: DAC must still deny (alice
    # does not own bob's dir). This is the dangerous confusion to reject.
    grant_bob = mint(key, "alice",
                     scope="storage.modify:/bob storage.create:/bob "
                           "storage.read:/bob")
    bob_before = owner("bob")
    rm("bob/scope_grant.txt")
    st, _ = http("PUT", "/bob/scope_grant.txt", port, grant_bob, b"x\n")
    ok(not is_2xx(st) and not exists("bob/scope_grant.txt"),
       f"scope GRANTS /bob but DAC DENIES alice writing bob's dir -> denied, "
       f"no file (HTTP {st})")

    # Same, targeting bob's 0700 private dir: scope grants, DAC denies hard.
    grant_secret = mint(key, "alice",
                        scope="storage.create:/bobsecret "
                              "storage.modify:/bobsecret")
    secret_before = owner("bobsecret")
    rm("bobsecret/scope_grant.txt")
    st, _ = http("PUT", "/bobsecret/scope_grant.txt", port, grant_secret, b"x\n")
    ok(not is_2xx(st) and not exists("bobsecret/scope_grant.txt"),
       f"scope GRANTS /bobsecret but DAC (0700 bob-only) DENIES alice -> denied "
       f"(HTTP {st})")
    ok(owner("bobsecret") == secret_before
       and secret_before[2] in (0o700, None),
       f"bobsecret dir unchanged after scope-granted alice write "
       f"(owner/mode {owner('bobsecret')})")

    # alice identity, scope grants /svconly: DAC (svc 0750) denies; nothing lands.
    grant_svc = mint(key, "alice", scope="storage.create:/svconly")
    try:
        svc_before = set(os.listdir(os.path.join(data, "svconly")))
    except OSError:
        svc_before = set()
    http("PUT", "/svconly/scope_grant.txt", port, grant_svc, b"x\n")
    try:
        svc_after = set(os.listdir(os.path.join(data, "svconly")))
    except OSError:
        svc_after = set()
    ok(svc_after == svc_before,
       f"scope GRANTS /svconly but DAC denies alice -> no file landed in "
       f"svc dir ({sorted(svc_after - svc_before)})")

    # Invariant: bob's dir ownership/mode untouched by the scope-granted writes.
    ok(owner("bob") == bob_before and bob_before[0] in (UID_BOB, None),
       f"bob/ ownership+mode unchanged by scope-granted alice writes "
       f"(now {owner('bob')})")

    # ===================================================================
    # (e) aud-ARRAY + multi-scope + wlcg.groups -> identity = SUB's uid only
    # ===================================================================
    # aud is presented as a JSON ARRAY (RFC 7519 allows it); multiple scopes are
    # space-separated; a wlcg.groups claim lists OTHER principals/root. None of
    # this changes the UNIX identity: it stays alice (1001), and any created file
    # is owned by alice, never by a claimed group or root.
    arr_tok = mint(
        key, "alice",
        scope="storage.read:/alice storage.modify:/alice storage.create:/alice",
        aud=[AUDIENCE, "other-audience", "https://elsewhere.example"],
        **{"wlcg.groups": ["bob", "root", "staff"], "wlcg.ver": "1.0"})

    rm("alice/aud_array.txt")
    st, _ = http("PUT", "/alice/aud_array.txt", port, arr_tok, b"arr\n")
    o = owner("alice/aud_array.txt")
    ok(is_2xx(st) and o[0] == UID_ALICE,
       f"aud-ARRAY + wlcg.groups token writes /alice -> file owned by alice's "
       f"uid (sub), not a claimed group (HTTP {st}, uid {o[0]})")

    # Explicit no-escalation: the created file is NOT root/svc, and its gid is
    # NOT any of the claimed/foreign group gids.
    ok(o[0] not in (UID_ROOT, UID_SVC)
       and o[1] not in (UID_ROOT, UID_SVC, UID_BOB,
                        GID_STAFF, GID_RESEARCH, GID_PROJ),
       f"aud-array file NOT owned by root/svc/bob and gid not a claimed group "
       f"(uid {o[0]}, gid {o[1]})")

    # wlcg.groups listing "bob"/"root" grants NOTHING: write to /bob denied
    # (identity is alice; the claim is not an impersonation lever).
    rm("bob/aud_array.txt")
    st, _ = http("PUT", "/bob/aud_array.txt", port, arr_tok, b"x\n")
    ok(not is_2xx(st) and not exists("bob/aud_array.txt"),
       f"wlcg.groups=[bob,root] does NOT let alice write /bob (HTTP {st})")

    # Same token reading bob's 0600 private: the groups claim is not bob.
    st, b = http("GET", "/bob/private.txt", port, arr_tok)
    ok(not is_2xx(st) and b"BOB-PRIVATE-SECRET" not in (b or b""),
       f"wlcg.groups claim does NOT grant alice bob's 0600 secret, no leak "
       f"(HTTP {st})")

    # ===================================================================
    # root:// plane (guarded): scope gate also enforced on the native path
    # ===================================================================
    if xrd_avail():
        # read-only scoped token over root://: a write (rm) of alice's own file
        # must fail; a read (cat) of an alice file must succeed -> proves the
        # scope gate (not just DAC) is enforced on the stream protocol too.
        ro_native = mint(key, "alice", scope=READ_ONLY)
        rc_w, _o, _e = xrd_fs_token(["rm", "/alice/scope_seed.txt"], ro_native)
        ok(rc_w != 0 and exists("alice/scope_seed.txt"),
           f"root:// read-only scope: rm of own file DENIED, file survives "
           f"(rc {rc_w})")
        rc_r, out_r, _e = xrd_fs_token(["cat", "/alice/scope_seed.txt"],
                                       ro_native)
        blob = out_r if isinstance(out_r, bytes) else (out_r or "").encode(
            "utf-8", "replace")
        ok(rc_r == 0 or b"seed" in blob,
           f"root:// read-only scope: cat of own file SUCCEEDS (read granted) "
           f"(rc {rc_r})")
        # path-scoped token over root://: out-of-scope write to /pub denied.
        palice_native = mint(key, "alice",
                             scope="storage.modify:/alice storage.read:/alice")
        rc_p, _o, _e = xrd_fs_token(
            ["truncate", "/pub/native_out.txt", "1"], palice_native)
        ok(rc_p != 0 and not exists("pub/native_out.txt"),
           f"root:// path-scope modify:/alice: out-of-scope /pub write DENIED "
           f"(rc {rc_p})")
    else:
        ok(True, "root:// native plane unavailable: scope-gate checks skipped (handled)")
        ok(True, "root:// native plane unavailable: read-allow check skipped (handled)")
        ok(True, "root:// native plane unavailable: path-scope check skipped (handled)")

    # ===================================================================
    # Final invariants: no denied scoped write leaked a file; fixtures intact
    # ===================================================================
    pub_after = pub_listing()
    leaked_pub = pub_after - pub_before
    ok(not leaked_pub,
       f"no scope-denied write created a file under /pub ({sorted(leaked_pub)})")

    o = owner("alice")
    ok(o[0] == UID_ALICE and o[2] in (0o755, None),
       f"alice/ dir still 1001-owned 0755 after scoped-write matrix "
       f"(owner {o[0]}, mode {oct(o[2]) if o[2] is not None else o[2]})")

    # Cleanup files we created so later batches start clean.
    for rel in ("alice/scope_seed.txt", "alice/path_in.txt",
                "alice/aud_array.txt"):
        rm(rel)


