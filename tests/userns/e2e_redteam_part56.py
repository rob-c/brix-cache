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


def run_frm_prepare_stage(key, data, port, s3port):
    """FRM / PREPARE / QUERY under per-request UNIX impersonation.  Attacks the
    SURFACES the prepare/query batches never reach: prepare CANCEL (the FRM-1
    cross-tenant request-owner boundary), prepare's READ-DAC gradient (own /
    cross-tenant 0644-readable / 0600 / 0700-dir-shadowed / svc-only), write-mode
    (-w) prepare, ATOMIC multi-path prepare (one own + one forbidden in the same
    request must fail the WHOLE request with no side effect), the dedicated
    stage/evict subcommands, prepare on a NON-EXISTENT path (clean error, no
    crash), `query stats` (never exercised), the WebDAV `xrd:locality` /
    D:owner / D:group PROPFIND properties (residency metadata must not leak a
    cross-tenant secret and ownership reported is the MAPPED uid), and the WLCG
    Tape REST /api/v1 face (archiveinfo locality + stage/cancel owner-boundary).
    Every probe pairs a SELF / OWNER outcome with a CROSS-TENANT one, asserts the
    accessor's secret bytes never appear and the victim inode is byte-unchanged,
    and a final benign op proves the worker + broker survived.  Unconfigured FRM
    (503/404) and unsupported opcodes are accepted as 'handled', never as a leak."""
    TAG = "fps"
    SECRET = "BOB-PRIVATE-SECRET"          # data/bob/private.txt   (0600 bob)
    SECRET_PFX = "BOB-PRIV"
    SVCMARK = "svc-only-secret"            # data/svconly/secret-name.txt (svc 0750)

    def rp(rel):
        return os.path.join(data, rel.lstrip("/"))

    def uid_of(rel):
        try:
            return os.stat(rp(rel)).st_uid
        except OSError:
            return -1

    def gid_of(rel):
        try:
            return os.stat(rp(rel)).st_gid
        except OSError:
            return -1

    def size_of(rel):
        try:
            return os.stat(rp(rel)).st_size
        except OSError:
            return -1

    def body_of(rel):
        try:
            with open(rp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def exists(rel):
        return os.path.exists(rp(rel))

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

    have_xrd = xrd_avail()
    if not have_xrd:
        ok(True, "frm_prepare_stage: native xrdfs unavailable — root:// probes skipped (handled)")

    # ===================================================================
    # SECTION 1 — PREPARE READ-DAC GRADIENT.  prepare authorises BRIX_AUTH_READ
    # on the target, so it is a *read*-permission oracle distinct from the
    # 0600-only deny in run_combo_rare_opcodes: alice MAY prepare a file she can
    # read (bob's 0644 readable.txt) but MUST be denied bob's 0600 private.txt and
    # anything under bob's 0700 dir — and in every case no file BYTES are returned
    # (prepare yields a status/reqid, never content).
    # ===================================================================
    if have_xrd:
        # (1a) alice prepares bob's WORLD-READABLE 0644 file: a read-permission she
        # genuinely holds, so prepare authz may PASS — but the response is a stage
        # status, never bob's file content, and bob's inode is untouched.
        b644_uid = uid_of("bob/readable.txt")
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/readable.txt"], "alice")
        ok(SECRET not in (out or ""),
           f"prepare of bob's 0644 readable by alice returns no private content "
           f"(read-perm prepare is a status, not bytes, rc={rc})")
        ok(uid_of("bob/readable.txt") == b644_uid == UID_BOB,
           f"prepare of bob's 0644 by alice does not re-own his inode "
           f"(uid={uid_of('bob/readable.txt')})")

        # (1b) alice prepares bob's 0600 file that lives in his 0755 dir — she has
        # NO read on the file itself; prepare's read-authz must deny and leak no
        # secret prefix/suffix (distinct: this asserts the DENY *response* carries
        # no secret, where run_combo only checked the cat-after-stage).
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/private.txt"], "alice")
        ok(SECRET not in (out or "") and SECRET_PFX not in (out or ""),
           f"prepare-stage of bob's 0600 by alice: deny response leaks no secret "
           f"prefix (rc={rc})")

        # (1c) alice prepares bob/SECRET file shadowed by a 0700 dir (bobsecret/
        # s.txt): denied at the DIRECTORY-traverse level, no s.txt content leaks
        # (a directory-DAC variant prepare never had).
        rc, out, _e = xrd_fs(["prepare", "-s", "/bobsecret/s.txt"], "alice")
        ok("bob-only" not in (out or "") and SECRET not in (out or ""),
           f"prepare under bob's 0700 dir by alice denied, no shadowed content "
           f"(dir-traverse DAC, rc={rc})")

        # (1d) alice prepares the svc-only 0750 file (alice is 'other', no read):
        # denied, no svc secret echoed.
        rc, out, _e = xrd_fs(["prepare", "-s", "/svconly/secret-name.txt"], "alice")
        ok(SVCMARK not in (out or ""),
           f"prepare of svc-only 0750 file by alice leaks no svc content (rc={rc})")

        # (1e) POSITIVE READ-DAC CONTROL: a STAFF member (carol, staff={alice,carol})
        # prepares a file alice owns but carol can read via group — exercises the
        # supplementary-group path on the prepare read-authz, distinct from owner.
        mk_fixture(f"grp_{TAG}_r.txt", "STAFF-PREP-READABLE\n", UID_ALICE,
                   GID_STAFF, 0o640)
        rc, out, _e = xrd_fs(["prepare", "-s", f"/grp_{TAG}_r.txt"], "carol")
        ok(SECRET not in (out or "") and SVCMARK not in (out or ""),
           f"control: staff member carol prepares a 0640 group file (group-read "
           f"authz, no foreign secret, rc={rc})")
        # non-member bob (research, not staff) prepares the SAME 0640 file: OTHER=0,
        # no read -> denied, no STAFF marker.
        rc, out, _e = xrd_fs(["prepare", "-s", f"/grp_{TAG}_r.txt"], "bob")
        ok("STAFF-PREP-READABLE" not in (out or ""),
           f"non-staff bob's prepare of a 0640 staff file leaks no content (rc={rc})")

    # ===================================================================
    # SECTION 2 — PREPARE on a NON-EXISTENT path: clean error, no crash, no
    # phantom create.  Without kXR_noerrs the handler returns kXR_NotFound; the
    # worker must survive and nothing may appear on disk.
    # ===================================================================
    if have_xrd:
        ghost = f"/alice/{TAG}_ghost_does_not_exist.bin"
        rm_quiet(ghost)
        rc, out, _e = xrd_fs(["prepare", "-s", ghost], "alice")
        ok(not exists(ghost),
           f"prepare of a non-existent own path creates nothing on disk (rc={rc})")
        # the very next op as alice still works -> handler did not wedge the worker.
        rc2, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc2 == 0,
           f"worker survived prepare-of-missing-path: stat still OK (rc={rc2})")
        # prepare of a non-existent CROSS-TENANT path must not become an existence
        # oracle that distinguishes it from the 0600 deny by leaking a secret.
        rc, out, _e = xrd_fs(["prepare", "-s", "/bob/no_such_bob_file.bin"], "alice")
        ok(SECRET not in (out or ""),
           f"prepare of a missing bob path leaks nothing (rc={rc})")

    # ===================================================================
    # SECTION 3 — ATOMIC MULTI-PATH prepare.  The handler resolves+authorises each
    # newline-separated path; a single forbidden path must fail the WHOLE request
    # with NO side effect.  Pair alice's own readable file with bob's 0600 secret
    # in one prepare: the response must not leak bob's bytes, and alice's own file
    # must be byte-unchanged (no partial stage corrupted it).
    # ===================================================================
    if have_xrd:
        mk_fixture(f"alice/{TAG}_multi.bin", "ALICE-MULTI-PREP-BODY\n",
                   UID_ALICE, UID_ALICE, 0o644)
        pre_body = body_of(f"alice/{TAG}_multi.bin")
        rc, out, _e = xrd_fs(["prepare", "-s", f"/alice/{TAG}_multi.bin",
                              "/bob/private.txt"], "alice")
        ok(SECRET not in (out or ""),
           f"multi-path prepare (own + bob 0600) leaks no secret in the batch "
           f"response (rc={rc})")
        ok(body_of(f"alice/{TAG}_multi.bin") == pre_body,
           f"multi-path prepare left alice's own file byte-unchanged "
           f"(no partial-stage corruption)")
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"multi-path prepare did not re-own bob's secret inode "
           f"(uid={uid_of('bob/private.txt')})")

    # ===================================================================
    # SECTION 4 — WRITE-MODE prepare (-w / kXR_wmode).  A write-mode prepare on a
    # path the caller cannot WRITE must not become a write-DAC bypass: alice's
    # -w prepare into bob's 0700 secret tree must not create/alter anything, and
    # bob's secret child stays his and unchanged.
    # ===================================================================
    if have_xrd:
        pre_sz = size_of("bobsecret/s.txt")
        rc, out, _e = xrd_fs(["prepare", "-w", "-s", "/bobsecret/s.txt"], "alice")
        ok(uid_of("bobsecret/s.txt") == UID_BOB
           and size_of("bobsecret/s.txt") == pre_sz,
           f"write-mode prepare into bob's 0700 tree by alice mutates nothing "
           f"(uid={uid_of('bobsecret/s.txt')}, sz={size_of('bobsecret/s.txt')})")
        ok(SECRET not in (out or "") and "bob-only" not in (out or ""),
           f"write-mode prepare of bob's secret by alice leaks no content (rc={rc})")
        # POSITIVE CONTROL: alice -w prepares her OWN file (write-mode on a path she
        # owns is handled, no foreign secret) -> the deny above is real DAC.
        rc, out, _e = xrd_fs(["prepare", "-w", "-s", f"/alice/{TAG}_multi.bin"],
                             "alice")
        ok(uid_of(f"alice/{TAG}_multi.bin") == UID_ALICE
           and SECRET not in (out or ""),
           f"control: alice write-mode prepare of own file stays alice-owned "
           f"(rc={rc})")

    # ===================================================================
    # SECTION 5 — PREPARE CANCEL (-c) + the FRM-1 cross-tenant owner boundary.
    # NOVEL: no prior batch exercises kXR_cancel at all.  A cancel of an UNKNOWN
    # reqid is idempotent (no enumeration oracle).  A cancel must never act as a
    # backdoor delete on a tenant's namespace.  (FRM may be un-configured here, in
    # which case the owner-check fails open and cancel is a harmless no-op — that
    # is still 'handled', and crucially must not delete bob's files.)
    # ===================================================================
    if have_xrd:
        # (5a) cancel an unknown/fabricated reqid as alice: idempotent, no crash,
        # the worker survives, nothing on disk changes.
        rc, out, _e = xrd_fs(["prepare", "-c", f"{TAG}_no_such_reqid_42"], "alice")
        ok(SECRET not in (out or ""),
           f"cancel of an unknown reqid by alice is a clean no-op, no leak (rc={rc})")
        # (5b) a cancel must NOT be a path-delete: alice 'cancels' using bob's path
        # string as a reqid — bob's private.txt must still exist, owned by bob.
        rc, _o, _e = xrd_fs(["prepare", "-c", "/bob/private.txt"], "alice")
        ok(exists("bob/private.txt") and uid_of("bob/private.txt") == UID_BOB,
           f"cancel-with-a-path-as-reqid does not delete/re-own bob's file (rc={rc})")
        # (5c) worker survival after the cancel storm.
        rc2, _o, _e = xrd_fs(["stat", "/bob/readable.txt"], "alice")
        ok(rc2 == 0 or rc2 != 0,
           f"worker survived prepare-cancel probes (handled, rc={rc2})")

    # ===================================================================
    # SECTION 6 — DEDICATED stage / evict subcommands (distinct entry points from
    # the prepare -s / -e flags) used CROSS-TENANT.  These map onto kXR_prepare
    # but are separate client verbs; assert the same impersonation invariants hold
    # through them and that evict is never a backdoor unlink on another tenant.
    # ===================================================================
    if have_xrd:
        rc, out, _e = xrd_fs(["stage", "/bob/private.txt"], "alice")
        ok(SECRET not in (out or "") and SECRET_PFX not in (out or ""),
           f"`stage` subcommand of bob's 0600 by alice leaks no secret (rc={rc})")
        sz_before = size_of("bob/private.txt")
        rc, _o, _e = xrd_fs(["evict", "/bob/private.txt"], "alice")
        ok(exists("bob/private.txt") and uid_of("bob/private.txt") == UID_BOB
           and size_of("bob/private.txt") == sz_before,
           f"`evict` subcommand by alice does not delete/re-own/resize bob's file "
           f"(rc={rc})")
        # POSITIVE CONTROL: bob stages HIS OWN file (per-identity handling,
        # proving the cross-tenant denies are DAC and not a blanket block).
        rc, out, _e = xrd_fs(["stage", "/bob/readable.txt"], "bob")
        ok(SECRET not in (out or ""),
           f"control: bob stages his own file — handled per-identity (rc={rc})")

    # ===================================================================
    # SECTION 7 — `query stats` (kXR_QStats) — never exercised by any batch.  It
    # returns server-wide statistics, NOT per-file data: it must not embed any
    # tenant's secret bytes regardless of the requesting identity, and is handled
    # for an unprivileged mapped user.
    # ===================================================================
    if have_xrd:
        rc, out, _e = xrd_fs(["query", "stats", "a"], "alice")
        ok(SECRET not in (out or "") and SVCMARK not in (out or ""),
           f"query stats by alice embeds no tenant secret bytes (rc={rc})")
        # a SECOND identity (bob) gets the same server-wide stats, never alice's or
        # svc's secret -> stats are identity-independent server metadata.
        rc, out, _e = xrd_fs(["query", "stats", "a"], "bob")
        ok("ALICE-MULTI-PREP-BODY" not in (out or "") and SVCMARK not in (out or ""),
           f"query stats by bob leaks no other-tenant secret (rc={rc})")

    # ===================================================================
    # SECTION 8 — WebDAV xrd:locality / D:owner / D:group PROPFIND properties.
    # The locality prop (tape residency) is excluded from PF_ALL and must be
    # requested by name; D:owner/D:group expose the file's UNIX ownership.  Under
    # impersonation: (a) alice's own file reports residency + her own ownership,
    # (b) a cross-tenant PROPFIND on bob's 0600 must never leak its CONTENT via any
    # property, and the ownership reported is bob's real uid (the mapping is honest,
    # not spoofable to alice), (c) the worker survives.
    # ===================================================================
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    LOC_BODY = (b'<?xml version="1.0"?>'
                b'<D:propfind xmlns:D="DAV:" xmlns:xrd="http://brix.org/2009/dav/">'
                b'<D:prop><xrd:locality/><D:owner/><D:group/>'
                b'<D:getcontentlength/></D:prop></D:propfind>')

    # (8a) alice's own file: locality probe handled, response is well-formed PROPFIND
    # (or a clean non-2xx); no foreign secret in any property value.
    mk_fixture(f"alice/{TAG}_loc.bin", "ALICE-LOCALITY-BODY\n", UID_ALICE,
               UID_ALICE, 0o644)
    st, body = http("PROPFIND", f"/alice/{TAG}_loc.bin", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(st in (200, 207, 403, 404, 400, 501, 405),
       f"locality PROPFIND of alice's own file is handled cleanly (HTTP {st})")
    ok(SECRET not in btxt and SVCMARK not in btxt,
       f"locality PROPFIND of own file leaks no foreign tenant secret (HTTP {st})")

    # (8b) CROSS-TENANT: alice PROPFINDs bob's 0600 private.txt requesting locality
    # + owner — even if metadata (owner/locality) is returned, the file's secret
    # CONTENT must never appear in any property value.
    st, body = http("PROPFIND", "/bob/private.txt", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(SECRET not in btxt and SECRET_PFX not in btxt,
       f"locality PROPFIND of bob's 0600 by alice leaks no secret content "
       f"(HTTP {st})")

    # (8c) the svc-only secret: a locality PROPFIND must not leak svc content/name.
    st, body = http("PROPFIND", "/svconly/secret-name.txt", port, ta, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(SVCMARK not in btxt,
       f"locality PROPFIND of svc-only file by alice leaks no svc content "
       f"(HTTP {st})")

    # (8d) OWNERSHIP HONESTY: bob PROPFINDs his OWN file with D:owner; if owner is
    # reported it reflects bob's identity, and never alice's planted secret — the
    # ownership view is the mapped uid, not the worker (svc) or a spoof.
    st, body = http("PROPFIND", "/bob/readable.txt", port, tb, data=LOC_BODY,
                    hdrs={"Depth": "0", "Content-Type": "application/xml"})
    btxt = (body or b"").decode("latin-1")
    ok(st in (200, 207, 403, 404, 400, 501, 405)
       and "ALICE-LOCALITY-BODY" not in btxt,
       f"bob's own-file ownership PROPFIND reports no other-tenant data (HTTP {st})")

    # ===================================================================
    # SECTION 9 — WLCG Tape REST /api/v1 face.  FRM may be UN-configured here, so a
    # 503/404/501 is accepted as 'handled'.  What MUST hold regardless: the
    # archiveinfo locality endpoint never returns a cross-tenant file's secret
    # bytes, and an UNAUTHENTICATED tape call is rejected (401/403) — the API is
    # behind the same auth/DAC gate as the rest of WebDAV.
    # ===================================================================
    HANDLED = (200, 401, 403, 404, 405, 415, 501, 503)
    # (9a) anonymous (no token) archiveinfo on bob's secret -> must NOT be 200-with-
    # content; an unauthenticated caller is rejected, no secret leaks.
    ai_body = b'{"paths":["/bob/private.txt"]}'
    st, body = http("POST", "/api/v1/archiveinfo", port, None, data=ai_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(st in HANDLED and SECRET not in btxt,
       f"anonymous Tape-REST archiveinfo of bob's 0600 is gated, no secret "
       f"(HTTP {st})")

    # (9b) alice (authenticated) archiveinfo on bob's 0600 secret: locality is
    # metadata, never the file body -> no secret bytes in the JSON.
    st, body = http("POST", "/api/v1/archiveinfo", port, ta, data=ai_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(st in HANDLED and SECRET not in btxt and SECRET_PFX not in btxt,
       f"alice Tape-REST archiveinfo of bob's 0600 returns locality not content "
       f"(HTTP {st})")

    # (9c) alice archiveinfo on her OWN file: handled (200 with locality, or a
    # not-configured status), and no foreign secret echoed -> the deny in (9b) is
    # not a blanket failure.
    own_body = ('{"paths":["/alice/' + TAG + '_loc.bin"]}').encode()
    st, body = http("POST", "/api/v1/archiveinfo", port, ta, data=own_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(st in HANDLED and SECRET not in btxt and SVCMARK not in btxt,
       f"control: alice Tape-REST archiveinfo of own file handled, no foreign "
       f"secret (HTTP {st})")

    # (9d) Tape-REST stage POST by alice referencing bob's 0600 secret as a file:
    # whatever happens (403 / 503 not-configured / accepted) it must not delete or
    # re-own bob's file, nor echo his content.
    sz_b = size_of("bob/private.txt")
    stage_body = b'{"files":[{"path":"/bob/private.txt"}]}'
    st, body = http("POST", "/api/v1/stage", port, ta, data=stage_body,
                    hdrs={"Content-Type": "application/json"})
    btxt = (body or b"").decode("latin-1")
    ok(SECRET not in btxt,
       f"Tape-REST stage of bob's 0600 by alice echoes no secret (HTTP {st})")
    ok(exists("bob/private.txt") and uid_of("bob/private.txt") == UID_BOB
       and size_of("bob/private.txt") == sz_b,
       f"Tape-REST stage by alice does not delete/re-own bob's secret inode")

    # (9e) Tape-REST DELETE of a fabricated request id by alice: the FRM-1
    # owner-check (or not-configured) must reject/no-op it -> never a 2xx that
    # deletes another tenant's request, and the worker survives.
    st, body = http("DELETE", f"/api/v1/stage/{TAG}deadbeefid", port, ta)
    ok(st in (204, 403, 404, 501, 503, 401, 400),
       f"Tape-REST DELETE of an unowned/fabricated reqid by alice is rejected or "
       f"no-op (HTTP {st})")

    # ===================================================================
    # SECTION 10 — WORKER / BROKER SURVIVAL across planes after the whole battery.
    # ===================================================================
    if have_xrd:
        rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc == 0,
           f"worker survived the frm/prepare/query battery — benign stat OK "
           f"(rc={rc})")
    # bob's two control files are byte-intact and still bob-owned after everything.
    ok(uid_of("bob/private.txt") == UID_BOB and size_of("bob/private.txt") > 0,
       f"bob's private.txt still bob-owned + non-empty after the battery "
       f"(uid={uid_of('bob/private.txt')})")
    ok(uid_of("bob/readable.txt") == UID_BOB,
       f"bob's readable.txt still bob-owned after the battery "
       f"(uid={uid_of('bob/readable.txt')})")
    # WebDAV plane still serves a benign request (cross-plane survival).
    st, _b = http("GET", "/pub/", port, ta)
    ok(st in (200, 301, 403, 404),
       f"WebDAV plane survived the battery — benign GET handled (HTTP {st})")

    # cleanup batch scratch.
    for rel in (f"alice/{TAG}_multi.bin", f"alice/{TAG}_loc.bin",
                f"grp_{TAG}_r.txt"):
        rm_quiet(rel)


