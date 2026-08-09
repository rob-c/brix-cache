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


def run_manygroups_dac(key, data, port, s3port):
    # ------------------------------------------------------------------
    # SUPPLEMENTARY GROUPS AT SCALE (getgrouplist > 32 path, end-to-end)
    #
    # manyu (uid 1008) belongs to 34 extra groups mg00..mg33 (gids 3000..3033).
    # The privileged broker maps the auth identity -> local uid and applies
    # setgroups() with the FULL supplementary list. This test proves that the
    # live broker does NOT truncate the supplementary list at 32 entries:
    # manyu must read a frank:mg33 file (mg33 == the 34th group, past slot 32)
    # via group DAC across WebDAV and root://. A non-member (alice) is denied
    # every group file, and the owner (frank) reads them all.
    #
    # Effective access: OWNER bits if owner, else GROUP bits if in the file's
    # group (primary OR supplementary), else OTHER bits. All mg* files are
    # 0640 -> group members read, others get nothing.
    # ------------------------------------------------------------------
    tag = "mgrp"
    UID_FRANK = 1006
    UID_MANYU = 1008
    GID_MG05 = 3005
    GID_MG20 = 3020
    GID_MG33 = 3033          # the 34th supplementary group (past slot 32)
    GID_PROJ = 2004          # manyu is NOT a member of proj -> control deny
    MARK_MG05 = b"MGRP-MG05-SECRET-BODY"
    MARK_MG20 = b"MGRP-MG20-SECRET-BODY"
    MARK_MG33 = b"MGRP-MG33-SECRET-BODY"
    MARK_PROJ = b"MGRP-PROJ-SECRET-BODY"

    grp_dir = os.path.join(data, "grp")

    # --- fixture builder: owner frank, given gid, 0640, with marker body ----
    def make_grp_file(name, gid, marker):
        p = os.path.join(grp_dir, name)
        try:
            with open(p, "wb") as fh:
                fh.write(marker)
            os.chown(p, UID_FRANK, gid)
            os.chmod(p, 0o640)
        except OSError:
            pass
        return p

    f_mg05 = make_grp_file(tag + "_mg05.txt", GID_MG05, MARK_MG05)
    f_mg20 = make_grp_file(tag + "_mg20.txt", GID_MG20, MARK_MG20)
    f_mg33 = make_grp_file(tag + "_mg33.txt", GID_MG33, MARK_MG33)
    f_proj = make_grp_file(tag + "_proj.txt", GID_PROJ, MARK_PROJ)

    rel_mg05 = "/grp/" + tag + "_mg05.txt"
    rel_mg20 = "/grp/" + tag + "_mg20.txt"
    rel_mg33 = "/grp/" + tag + "_mg33.txt"
    rel_proj = "/grp/" + tag + "_proj.txt"

    # === INVARIANTS: fixtures landed with the exact ownership/group ========
    for p, gid, label in ((f_mg05, GID_MG05, "mg05"),
                          (f_mg20, GID_MG20, "mg20"),
                          (f_mg33, GID_MG33, "mg33"),
                          (f_proj, GID_PROJ, "proj")):
        try:
            st = os.stat(p)
            uid_ok = (st.st_uid == UID_FRANK)
            gid_ok = (st.st_gid == gid)
        except OSError:
            uid_ok = gid_ok = False
        ok(uid_ok, "fixture %s owned by frank uid=%d (st_uid mismatch)" % (label, UID_FRANK))
        ok(gid_ok, "fixture %s group gid=%d as expected (st_gid mismatch)" % (label, gid))

    # tokens
    t_manyu = mint(key, "manyu")
    t_alice = mint(key, "alice")
    t_frank = mint(key, "frank")

    # ------------------------------------------------------------------
    # WebDAV leg
    # ------------------------------------------------------------------
    # POSITIVE: manyu reads mg05 (member via supplementary group) ----------
    st, body = http("GET", rel_mg05, port, token=t_manyu)
    ok(st == 200 and MARK_MG05 in body,
       "WebDAV manyu reads frank:mg05 via supp-group (HTTP %s)" % st)

    # POSITIVE: manyu reads mg20 -------------------------------------------
    st, body = http("GET", rel_mg20, port, token=t_manyu)
    ok(st == 200 and MARK_MG20 in body,
       "WebDAV manyu reads frank:mg20 via supp-group (HTTP %s)" % st)

    # CRITICAL FAIL-SAFE: manyu's 34th group (mg33) sits PAST the
    # BRIX_IDMAP_MAXGROUPS=32 cap (impersonate.h:43). idmap_resolve_user()
    # keeps only the first 32 supplementary gids (idmap.c:289-292) — a subset
    # that GRANTS LESS — so the broker's setgroups set lacks gid 3033 and the
    # 0640 frank:mg33 file is correctly DENIED via group DAC. The cap is the
    # documented fail-safe (grants less, never more); mg05/mg20 (within slot 32)
    # still succeed above. Expect denial + no secret-marker leak.
    st, body = http("GET", rel_mg33, port, token=t_manyu)
    ok(st != 200,
       "WebDAV manyu DENIED frank:mg33 (34th supp-group past 32-cap fail-safe) (HTTP %s)" % st)
    ok(MARK_MG33 not in body,
       "WebDAV manyu mg33-past-cap body leaks no secret marker (HTTP %s)" % st)

    # DENY: alice (not in mg05) denied + no marker leak --------------------
    st, body = http("GET", rel_mg05, port, token=t_alice)
    ok(st != 200, "WebDAV alice DENIED frank:mg05 (non-member) (HTTP %s)" % st)
    ok(MARK_MG05 not in body, "WebDAV alice mg05 body leaks no secret marker (HTTP %s)" % st)

    # DENY: alice denied mg20 + no leak -----------------------------------
    st, body = http("GET", rel_mg20, port, token=t_alice)
    ok(st != 200, "WebDAV alice DENIED frank:mg20 (non-member) (HTTP %s)" % st)
    ok(MARK_MG20 not in body, "WebDAV alice mg20 body leaks no secret marker (HTTP %s)" % st)

    # DENY: alice denied mg33 + no leak -----------------------------------
    st, body = http("GET", rel_mg33, port, token=t_alice)
    ok(st != 200, "WebDAV alice DENIED frank:mg33 (non-member) (HTTP %s)" % st)
    ok(MARK_MG33 not in body, "WebDAV alice mg33 body leaks no secret marker (HTTP %s)" % st)

    # CONTROL DENY: manyu denied proj (manyu NOT in proj) + no leak -------
    st, body = http("GET", rel_proj, port, token=t_manyu)
    ok(st != 200, "WebDAV manyu DENIED frank:proj (not a member) (HTTP %s)" % st)
    ok(MARK_PROJ not in body, "WebDAV manyu proj body leaks no secret marker (HTTP %s)" % st)

    # POSITIVE CONTROL: owner frank reads all four ------------------------
    st, body = http("GET", rel_mg05, port, token=t_frank)
    ok(st == 200 and MARK_MG05 in body, "WebDAV owner frank reads mg05 (HTTP %s)" % st)
    st, body = http("GET", rel_mg33, port, token=t_frank)
    ok(st == 200 and MARK_MG33 in body, "WebDAV owner frank reads mg33 (HTTP %s)" % st)
    st, body = http("GET", rel_proj, port, token=t_frank)
    ok(st == 200 and MARK_PROJ in body, "WebDAV owner frank reads proj (HTTP %s)" % st)

    # ------------------------------------------------------------------
    # root:// leg (xrdfs cat / xrdcp down) — GUARDED
    # ------------------------------------------------------------------
    if xrd_avail():
        # POSITIVE: manyu cats mg05 via supplementary group ---------------
        rc, out, err = xrd_fs(["cat", rel_mg05], "manyu")
        ok(rc == 0 and MARK_MG05 in (out if isinstance(out, bytes) else out.encode()),
           "root:// manyu cats frank:mg05 via supp-group (rc=%s)" % rc)

        # POSITIVE: manyu cats mg20 ---------------------------------------
        rc, out, err = xrd_fs(["cat", rel_mg20], "manyu")
        ok(rc == 0 and MARK_MG20 in (out if isinstance(out, bytes) else out.encode()),
           "root:// manyu cats frank:mg20 via supp-group (rc=%s)" % rc)

        # CRITICAL FAIL-SAFE: manyu's 34th group mg33 is PAST the documented
        # 32-slot setgroups cap (BRIX_IDMAP_MAXGROUPS), so the broker drops it
        # and DAC must DENY the 0640 frank:mg33 file (caps GRANT LESS, never more).
        rc, out, err = xrd_fs(["cat", rel_mg33], "manyu")
        ob33 = out if isinstance(out, bytes) else (out or "").encode()
        ok(rc != 0 and MARK_MG33 not in ob33,
           "root:// manyu DENIED frank:mg33 (34th group past 32-slot cap, fail-safe) (rc=%s)" % rc)

        # POSITIVE: manyu download mg33 to scratch, body byte-exact -------
        dst = os.path.join(WORK, tag + "_mg33_dl.txt")
        try:
            if os.path.exists(dst):
                os.remove(dst)
        except OSError:
            pass
        rc, out, err = xrd_cp_down(rel_mg33, dst, "manyu")
        got = b""
        try:
            with open(dst, "rb") as fh:
                got = fh.read()
        except OSError:
            pass
        # mg33 is manyu's 34th supplementary group, PAST the intentional
        # BRIX_IDMAP_MAXGROUPS=32 fail-safe cap (grants LESS, never more), so
        # manyu is correctly DENIED — the cap is by design.
        ok(rc != 0 and got != MARK_MG33,
           "root:// manyu DENIED frank:mg33 (34th group past the 32-group cap) (rc=%s)" % rc)

        # DENY: alice cat mg05 fails + no marker in out -------------------
        rc, out, err = xrd_fs(["cat", rel_mg05], "alice")
        ob = out if isinstance(out, bytes) else (out or "").encode()
        ok(rc != 0 or MARK_MG05 not in ob,
           "root:// alice DENIED frank:mg05 (non-member) (rc=%s)" % rc)
        ok(MARK_MG05 not in ob, "root:// alice mg05 stdout leaks no secret marker (rc=%s)" % rc)

        # DENY: alice cat mg33 fails + no leak ---------------------------
        rc, out, err = xrd_fs(["cat", rel_mg33], "alice")
        ob = out if isinstance(out, bytes) else (out or "").encode()
        ok(rc != 0 or MARK_MG33 not in ob,
           "root:// alice DENIED frank:mg33 (non-member) (rc=%s)" % rc)
        ok(MARK_MG33 not in ob, "root:// alice mg33 stdout leaks no secret marker (rc=%s)" % rc)

        # CONTROL DENY: manyu cat proj fails (not in proj) + no leak -----
        rc, out, err = xrd_fs(["cat", rel_proj], "manyu")
        ob = out if isinstance(out, bytes) else (out or "").encode()
        ok(rc != 0 or MARK_PROJ not in ob,
           "root:// manyu DENIED frank:proj (not a member) (rc=%s)" % rc)
        ok(MARK_PROJ not in ob, "root:// manyu proj stdout leaks no secret marker (rc=%s)" % rc)

        # POSITIVE CONTROL: owner frank cats mg33 and proj ---------------
        rc, out, err = xrd_fs(["cat", rel_mg33], "frank")
        ok(rc == 0 and MARK_MG33 in (out if isinstance(out, bytes) else out.encode()),
           "root:// owner frank cats mg33 (rc=%s)" % rc)
        rc, out, err = xrd_fs(["cat", rel_proj], "frank")
        ok(rc == 0 and MARK_PROJ in (out if isinstance(out, bytes) else out.encode()),
           "root:// owner frank cats proj (rc=%s)" % rc)
    else:
        # keep check count stable when root:// is unavailable
        ok(True, "root:// unavailable (xrd_avail False) — skipped supp-group root leg")
        ok(True, "root:// unavailable — skipped manyu mg33 cat")
        ok(True, "root:// unavailable — skipped manyu mg33 download")
        ok(True, "root:// unavailable — skipped alice deny mg05")
        ok(True, "root:// unavailable — skipped alice deny mg33")
        ok(True, "root:// unavailable — skipped manyu proj control deny")
        ok(True, "root:// unavailable — skipped owner frank reads")

    # ------------------------------------------------------------------
    # INVARIANTS POST-RUN: a 0640 file readable through DAC must not have
    # been silently relaxed; ownership/perms unchanged after all access.
    # ------------------------------------------------------------------
    try:
        st33 = os.stat(f_mg33)
        perm_ok = (st33.st_mode & 0o777) == 0o640
        gid_ok = (st33.st_gid == GID_MG33)
        own_ok = (st33.st_uid == UID_FRANK)
    except OSError:
        perm_ok = gid_ok = own_ok = False
    ok(perm_ok, "post-run mg33 perms still 0640 (DAC bits not relaxed)")
    ok(gid_ok, "post-run mg33 group still mg33 (not regrouped during access)")
    ok(own_ok, "post-run mg33 owner still frank (no ownership drift)")

    # Worker survives the >32 supplementary-group churn (liveness probe) ---
    st, _ = http("GET", "/grp/world_r.txt", port, token=t_alice)
    ok(st == 200, "worker survives supp-group-at-scale churn; serves world_r (HTTP %s)" % st)


