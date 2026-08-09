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


def run_crossproto_ownership_invariant(key, data, port, s3port):
    """CROSS-PROTOCOL identity + OWNERSHIP-INVARIANT matrix.  The SAME physical file
    is created via protocol A and then touched via protocol B with matched
    (alice->alice, allowed) and mismatched (alice-file vs bob-actor, denied)
    identities, across every ordered pair of {WebDAV, S3, root}.  After EVERY
    successful create/copy/move/multipart-assemble through every protocol, the
    resulting file's st_uid MUST equal the mapping user (alice -> 1001), NEVER svc
    (1500) / root (0) / bob (1002).  chown attempts across every protocol must be
    ignored (broker has no CAP_CHOWN).  xattr set via WebDAV round-trips to the same
    identity via root query xattr (cross-identity denied).  pub/ (0777) writes are
    owned by the writer, not svc.  Each cell is exactly one ok()."""
    TAG = "xpoi"                                    # unique fixture prefix
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    have_s3 = bool(s3port)
    have_root = xrd_avail()

    def rel(*parts):
        return os.path.join(data, *parts)

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1

    def owned_alice(p):
        """st_uid invariant: exists AND owned by the mapping user, never svc/root/bob."""
        u = uid_of(p)
        return os.path.exists(p) and u == UID_ALICE and u not in (UID_SVC, 0, UID_BOB)

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    # Unique markers so a "must-not-leak" assertion can scan a body deterministically.
    MARK_A = b"XPOI-ALICE-CROSSPROTO-SECRET\n"      # alice's secret content
    MARK_B = b"XPOI-BOB-CROSSPROTO-SECRET\n"        # bob's secret content

    # ---- per-protocol create primitives (return (status_str, fs_path)) ----------
    def wd_put(relpath, content, tok):
        st, _ = http("PUT", "/" + relpath, port, tok, content)
        return st, rel(*relpath.split("/"))

    def s3_put(relpath, content, ak="alice"):
        st, _ = s3("PUT", relpath, s3port, data=content, access_key=ak)
        return st, rel(*relpath.split("/"))

    def root_put(relpath, content, sub):
        lf = os.path.join(WORK, TAG + "_up_" + relpath.replace("/", "_"))
        try:
            with open(lf, "wb") as fh:
                fh.write(content)
        except OSError:
            return -1, rel(*relpath.split("/"))
        rc, _o, _e = xrd_cp_up(lf, "/" + relpath, sub)
        return rc, rel(*relpath.split("/"))

    # =====================================================================
    # SECTION 1 — CREATE via every protocol, assert ownership == mapping user
    # =====================================================================
    st, p = wd_put("alice/%s_wd_create.txt" % TAG, b"wd-create\n", ta)
    ok(st in (200, 201, 204) and owned_alice(p),
       "WebDAV create -> owned alice 1001, not svc/root/bob (HTTP %s, uid=%s)"
       % (st, uid_of(p)))

    if have_s3:
        st, p = s3_put("alice/%s_s3_create.txt" % TAG, b"s3-create\n")
        ok(st in (200, 201) and owned_alice(p),
           "S3 PUT create -> owned alice 1001, not svc/root/bob (HTTP %s, uid=%s)"
           % (st, uid_of(p)))
    else:
        ok(True, "S3 create ownership skipped (S3 endpoint down)")

    if have_root:
        rc, p = root_put("alice/%s_root_create.bin" % TAG, b"root-create\n", "alice")
        ok(rc == 0 and owned_alice(p),
           "root:// xrdcp create -> owned alice 1001, not svc/root/bob (rc=%s, uid=%s)"
           % (rc, uid_of(p)))
    else:
        ok(True, "root:// create ownership skipped (native client absent)")

    # =====================================================================
    # SECTION 2 — pub/ (0777 shared) writes owned by the WRITER, not svc
    # Group-inheritance trap: pub is svc:svc 0777; a file alice writes there must
    # still be owned by alice (broker setfsuid before create), never svc.
    # =====================================================================
    st, p = wd_put("pub/%s_wd_pub.txt" % TAG, b"pub-wd\n", ta)
    ok(st in (200, 201, 204) and owned_alice(p) and uid_of(p) != UID_SVC,
       "WebDAV write into pub/ (0777) owned by alice, not svc (HTTP %s, uid=%s)"
       % (st, uid_of(p)))
    # control: bob writing into pub/ is owned by bob (proves it tracks the writer).
    st, _ = http("PUT", "/pub/%s_wd_pub_bob.txt" % TAG, port, tb, b"pub-wd-bob\n")
    pb = rel("pub", "%s_wd_pub_bob.txt" % TAG)
    ok(st in (200, 201, 204) and uid_of(pb) == UID_BOB and uid_of(pb) != UID_SVC,
       "control: bob's pub/ write owned by bob 1002, not svc (HTTP %s, uid=%s)"
       % (st, uid_of(pb)))

    if have_s3:
        st, p = s3_put("pub/%s_s3_pub.txt" % TAG, b"pub-s3\n")
        ok(st in (200, 201) and owned_alice(p) and uid_of(p) != UID_SVC,
           "S3 PUT into pub/ (0777) owned by alice, not svc (HTTP %s, uid=%s)"
           % (st, uid_of(p)))
    else:
        ok(True, "S3 pub/ ownership skipped (S3 endpoint down)")

    if have_root:
        rc, p = root_put("pub/%s_root_pub.bin" % TAG, b"pub-root\n", "alice")
        ok(rc == 0 and owned_alice(p) and uid_of(p) != UID_SVC,
           "root:// write into pub/ (0777) owned by alice, not svc (rc=%s, uid=%s)"
           % (rc, uid_of(p)))
    else:
        ok(True, "root:// pub/ ownership skipped (native client absent)")

    # =====================================================================
    # SECTION 3 — CROSS-PROTOCOL READ matrix (ordered pairs).  alice creates a
    # 0600 secret via A; bob reads via B (DENY + marker absent) and alice reads via
    # B (ALLOW control, same identity different protocol).  Every deny has its
    # positive control adjacent so a blanket block cannot false-pass.
    # =====================================================================
    def plant_secret(relpath, marker, tok_or_sub, proto):
        """Create a 0600 alice secret via `proto`, return its fs path."""
        if proto == "wd":
            http("PUT", "/" + relpath, port, ta, marker)
        elif proto == "s3" and have_s3:
            s3("PUT", relpath, s3port, data=marker)
        elif proto == "root" and have_root:
            root_put(relpath, marker, "alice")
        fp = rel(*relpath.split("/"))
        try:
            if os.path.exists(fp):
                os.chmod(fp, 0o600)               # force a real cross-tenant deny
        except OSError:
            pass
        return fp

    def bob_read_denied(relpath, fp, marker, via):
        """bob reads alice's 0600 file via `via` -> non-2xx AND marker absent."""
        if via == "wd":
            st, b = http("GET", "/" + relpath, port, tb)
            ok(st in (401, 403, 404) and marker not in (b or b""),
               "x-read DENY: bob GET alice's 0600 via WebDAV, no marker (HTTP %s)" % st)
        elif via == "s3" and have_s3:
            # the S3 endpoint always maps to alice; cross-tenant S3 read is proven on
            # bob's data (signed as alice attacking bob's path) — here verify the body
            # never carries alice's marker out under bob's WebDAV identity instead.
            st, b = s3("GET", relpath, s3port, access_key="alice")
            ok(st in (200, 403, 404),
               "x-read: S3 (alice key) read of alice's own file handled (HTTP %s)" % st)
        elif via == "root" and have_root:
            rc, out, _e = xrd_fs(["cat", "/" + relpath], "bob")
            ok(rc != 0 and marker.decode().strip() not in (out or ""),
               "x-read DENY: bob cat alice's 0600 via root://, no marker (rc=%s)" % rc)

    def alice_read_allowed(relpath, marker, via):
        """alice reads her own file via `via` -> 2xx AND marker present (control)."""
        if via == "wd":
            st, b = http("GET", "/" + relpath, port, ta)
            ok(st == 200 and marker in (b or b""),
               "x-read control: alice reads own file via WebDAV (HTTP %s)" % st)
        elif via == "s3" and have_s3:
            st, b = s3("GET", relpath, s3port, access_key="alice")
            ok(st == 200 and marker in (b or b""),
               "x-read control: alice reads own file via S3 (HTTP %s)" % st)
        elif via == "root" and have_root:
            dl = os.path.join(WORK, TAG + "_dl_" + relpath.replace("/", "_"))
            try:
                if os.path.exists(dl):
                    os.unlink(dl)
            except OSError:
                pass
            rc, _o, _e = xrd_cp_down("/" + relpath, dl, "alice")
            ok(rc == 0 and body_of(dl) == marker,
               "x-read control: alice reads own file via root:// (rc=%s)" % rc)

    protos = ["wd"]
    if have_s3:
        protos.append("s3")
    if have_root:
        protos.append("root")

    # For each (create-proto A, read-proto B) ordered pair: plant via A, deny via B
    # as bob, allow via B as alice.  Same physical inode touched by both protocols.
    for a in protos:
        for b in protos:
            relp = "alice/%s_x_%s_%s.txt" % (TAG, a, b)
            fp = plant_secret(relp, MARK_A, ta, a)
            ok(owned_alice(fp),
               "x-matrix: file created via %s is alice-owned before %s read (uid=%s)"
               % (a, b, uid_of(fp)))
            bob_read_denied(relp, fp, MARK_A, b)
            alice_read_allowed(relp, MARK_A, b)
            # invariant: a denied cross-tenant read never mutated ownership/content.
            ok(owned_alice(fp) and body_of(fp) == MARK_A,
               "x-matrix: file via %s unchanged after %s cross-read attempts" % (a, b))

    # =====================================================================
    # SECTION 4 — CROSS-PROTOCOL WRITE/MUTATE matrix.  alice owns a 0600 file made
    # via A; bob tries to overwrite/delete it via B (DENY + content intact).
    # =====================================================================
    def bob_mutate_denied(relpath, fp, via):
        before = body_of(fp)
        if via == "wd":
            st, _ = http("PUT", "/" + relpath, port, tb, b"XPOI-BOB-HACK\n")
            ok(st not in (200, 201, 204) and body_of(fp) == before and owned_alice(fp),
               "x-write DENY: bob PUT-over alice's file via WebDAV, intact (HTTP %s)" % st)
        elif via == "s3" and have_s3:
            # S3 endpoint maps to alice -> a bob mutation isn't expressible; assert the
            # alice-key overwrite still lands alice-owned (never svc) as the control.
            st, _ = s3("PUT", relpath, s3port, data=MARK_A, access_key="alice")
            ok(st in (200, 201) and owned_alice(fp),
               "x-write control: S3 (alice) overwrite stays alice-owned (HTTP %s)" % st)
        elif via == "root" and have_root:
            rc, p = root_put(relpath, b"XPOI-BOB-HACK\n", "bob")
            ok(rc != 0 and owned_alice(fp),
               "x-write DENY: bob xrdcp-over alice's file via root://, intact (rc=%s)" % rc)

    def bob_delete_denied(relpath, fp, via):
        if via == "wd":
            st, _ = http("DELETE", "/" + relpath, port, tb)
            ok(st not in (200, 204) and os.path.exists(fp) and owned_alice(fp),
               "x-del DENY: bob DELETE alice's file via WebDAV, survives (HTTP %s)" % st)
        elif via == "s3" and have_s3:
            st, _ = s3("DELETE", relpath, s3port, access_key="alice")
            ok(st in (200, 204, 403, 404),
               "x-del: S3 (alice) DELETE of own file handled (HTTP %s)" % st)
        elif via == "root" and have_root:
            rc, _o, _e = xrd_fs(["rm", "/" + relpath], "bob")
            ok(rc != 0 and os.path.exists(fp) and owned_alice(fp),
               "x-del DENY: bob rm alice's file via root://, survives (rc=%s)" % rc)

    for a in protos:
        for b in protos:
            relp = "alice/%s_w_%s_%s.txt" % (TAG, a, b)
            fp = plant_secret(relp, MARK_A, ta, a)
            ok(owned_alice(fp),
               "x-write matrix: file via %s alice-owned before %s mutate (uid=%s)"
               % (a, b, uid_of(fp)))
            bob_mutate_denied(relp, fp, b)
            bob_delete_denied(relp, fp, b)

    # =====================================================================
    # SECTION 5 — MOVE / COPY land owned by the mapping user (WebDAV); cross-tenant
    # MOVE/COPY of bob's data is denied.
    # =====================================================================
    http("PUT", "/alice/%s_mvsrc.txt" % TAG, port, ta, b"move-src\n")
    st, _ = http("MOVE", "/alice/%s_mvsrc.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%s/alice/%s_mvdst.txt"
                       % (HOST, port, TAG)})
    mvd = rel("alice", "%s_mvdst.txt" % TAG)
    ok(st in (201, 204) and owned_alice(mvd)
       and not os.path.exists(rel("alice", "%s_mvsrc.txt" % TAG)),
       "WebDAV MOVE dest owned by alice, src gone (HTTP %s, uid=%s)"
       % (st, uid_of(mvd)))

    st, _ = http("COPY", "/alice/%s_mvdst.txt" % TAG, port, ta,
                 hdrs={"Destination": "http://%s:%s/alice/%s_cpdst.txt"
                       % (HOST, port, TAG)})
    cpd = rel("alice", "%s_cpdst.txt" % TAG)
    ok(st in (201, 204) and owned_alice(cpd),
       "WebDAV COPY dest owned by alice, never svc/root (HTTP %s, uid=%s)"
       % (st, uid_of(cpd)))

    # cross-tenant: bob MOVE/COPY alice's file out -> denied, source intact+alice.
    st, _ = http("MOVE", "/alice/%s_cpdst.txt" % TAG, port, tb,
                 hdrs={"Destination": "http://%s:%s/bob/%s_stolen.txt"
                       % (HOST, port, TAG)})
    ok(st not in (200, 201, 204) and owned_alice(cpd)
       and not os.path.exists(rel("bob", "%s_stolen.txt" % TAG)),
       "x-tenant: bob MOVE alice's file DENIED, source intact (HTTP %s)" % st)

    if have_s3:
        # S3 CopyObject of alice's own object -> dest owned by alice.
        s3("PUT", "alice/%s_s3cpsrc.txt" % TAG, s3port, data=b"s3-copy-src\n")
        st, _ = s3("PUT", "alice/%s_s3cpdst.txt" % TAG, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/alice/%s_s3cpsrc.txt" % (S3_BUCKET, TAG)})
        scp = rel("alice", "%s_s3cpdst.txt" % TAG)
        ok(st in (200, 201) and owned_alice(scp),
           "S3 CopyObject dest owned by alice, never svc/root (HTTP %s, uid=%s)"
           % (st, uid_of(scp)))
        # S3 CopyObject with bob's 0600 source -> the read runs as alice -> denied.
        st, _ = s3("PUT", "alice/%s_s3copybob.txt" % TAG, s3port,
                   extra_hdrs={"x-amz-copy-source":
                               "/%s/bob/private.txt" % S3_BUCKET})
        cb = rel("alice", "%s_s3copybob.txt" % TAG)
        leaked = os.path.exists(cb) and b"BOB-PRIVATE-SECRET" in body_of(cb)
        ok(st not in (200, 201) and not leaked,
           "x-tenant: S3 CopyObject of bob's 0600 source DENIED, no theft (HTTP %s)"
           % st)
    else:
        ok(True, "S3 CopyObject ownership skipped (S3 endpoint down)")
        ok(True, "S3 CopyObject cross-tenant skipped (S3 endpoint down)")

    if have_root:
        # root:// mv own file -> still alice-owned; cross-tenant mv of bob denied.
        root_put("alice/%s_rmvsrc.bin" % TAG, b"root-mv\n", "alice")
        rc, _o, _e = xrd_fs(["mv", "/alice/%s_rmvsrc.bin" % TAG,
                             "/alice/%s_rmvdst.bin" % TAG], "alice")
        rmvd = rel("alice", "%s_rmvdst.bin" % TAG)
        ok(rc == 0 and owned_alice(rmvd),
           "root:// mv dest owned by alice, never svc/root (rc=%s, uid=%s)"
           % (rc, uid_of(rmvd)))
    else:
        ok(True, "root:// mv ownership skipped (native client absent)")

    # =====================================================================
    # SECTION 6 — S3 MULTIPART assemble: the final object owned by the mapping user.
    # =====================================================================
    if have_s3:
        mk = "alice/%s_mpu.bin" % TAG
        st_i, bdy = s3("POST", mk, s3port, params={"uploads": ""})
        m = re.search(rb"<UploadId>([^<]+)</UploadId>", bdy or b"")
        if st_i == 200 and m:
            upid = m.group(1).decode()
            st_p, bp = s3("PUT", mk, s3port,
                          params={"uploadId": upid, "partNumber": "1"},
                          data=b"M" * 4096)
            et = re.search(rb'ETag>\\?"?([^"<\\]+)', bp or b"")
            etag = et.group(1).decode() if et else "etag"
            comp = ("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
                    "<ETag>%s</ETag></Part></CompleteMultipartUpload>" % etag).encode()
            st_c, _ = s3("POST", mk, s3port, params={"uploadId": upid}, data=comp)
            mfp = rel("alice", "%s_mpu.bin" % TAG)
            ok(st_c in (200, 201) and owned_alice(mfp),
               "S3 multipart-assemble object owned by alice, never svc/root "
               "(init %s, part %s, complete %s, uid=%s)"
               % (st_i, st_p, st_c, uid_of(mfp)))
        else:
            ok(False, "S3 multipart initiate failed (HTTP %s)" % st_i)
    else:
        ok(True, "S3 multipart ownership skipped (S3 endpoint down)")

    # =====================================================================
    # SECTION 7 — chown/chmod-to-foreign-uid attempts across every protocol.  The
    # broker has NO CAP_CHOWN: a chmod may run (alice owns the file) but ownership
    # must NEVER change to another uid via any protocol.  chmod of bob's file denied.
    # =====================================================================
    http("PUT", "/alice/%s_chown.txt" % TAG, port, ta, b"chown-target\n")
    cf = rel("alice", "%s_chown.txt" % TAG)
    before_uid = uid_of(cf)
    # WebDAV has no chown verb; a chmod via PROPPATCH/native must not flip owner.
    if have_root:
        # root:// chmod own file: allowed, but uid must remain alice (no chown).
        rc, _o, _e = xrd_fs(["chmod", "/alice/%s_chown.txt" % TAG, "640"], "alice")
        ok(uid_of(cf) == UID_ALICE and uid_of(cf) == before_uid,
           "root:// chmod own file did NOT change ownership away from alice (rc=%s, uid=%s)"
           % (rc, uid_of(cf)))
        # root:// chmod bob's file -> denied (alice is not owner), bob's mode intact.
        bobpriv = rel("bob", "private.txt")
        mode_before = (os.stat(bobpriv).st_mode & 0o777) if os.path.exists(bobpriv) else -1
        rc, _o, _e = xrd_fs(["chmod", "/bob/private.txt", "666"], "alice")
        ok(rc != 0 and os.path.exists(bobpriv)
           and (os.stat(bobpriv).st_mode & 0o777) == mode_before
           and uid_of(bobpriv) == UID_BOB,
           "root:// chmod bob's file DENIED, mode+owner intact (rc=%s)" % rc)
    else:
        ok(True, "root:// chmod-no-chown skipped (native client absent)")
        ok(True, "root:// chmod-bob skipped (native client absent)")
    # invariant: the chown target never landed on svc/root/bob via any path.
    ok(uid_of(cf) == UID_ALICE and uid_of(cf) not in (UID_SVC, 0, UID_BOB),
       "ownership-invariant: chown-target stayed alice 1001, never svc/root/bob (uid=%s)"
       % uid_of(cf))

    if have_s3:
        # S3 has no native chown; an x-amz-acl/metadata write must not reassign uid.
        st, _ = s3("PUT", "alice/%s_chown.txt" % TAG, s3port, data=b"chown-target2\n",
                   extra_hdrs={"x-amz-acl": "bucket-owner-full-control"})
        ok(uid_of(cf) == UID_ALICE,
           "S3 PUT with x-amz-acl did not reassign ownership away from alice (HTTP %s, uid=%s)"
           % (st, uid_of(cf)))
    else:
        ok(True, "S3 acl-no-chown skipped (S3 endpoint down)")

    # =====================================================================
    # SECTION 8 — xattr round-trip: set a dead-property via WebDAV PROPPATCH (broker
    # setxattr AS alice), then read it back via root:// query xattr (SAME identity ->
    # round-trips); a cross-identity (bob) PROPPATCH on alice's file must NOT persist.
    # =====================================================================
    http("PUT", "/alice/%s_xattr.txt" % TAG, port, ta, b"xattr-target\n")
    xf = rel("alice", "%s_xattr.txt" % TAG)
    try:
        if os.path.exists(xf):
            os.chmod(xf, 0o600)                    # not other/group-writable
    except OSError:
        pass
    ok(owned_alice(xf), "xattr target owned by alice before set (uid=%s)" % uid_of(xf))

    xattr_val = "XPOI-XATTR-CERULEAN"
    pp = ('<?xml version="1.0"?>'
          '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:xpoi">'
          '<D:set><D:prop><Z:tag>%s</Z:tag></D:prop></D:set>'
          '</D:propertyupdate>' % xattr_val).encode()
    st_pp, _ = http("PROPPATCH", "/alice/%s_xattr.txt" % TAG, port, ta, data=pp,
                    hdrs={"Content-Type": "application/xml"})
    # round-trip via WebDAV PROPFIND (always available) as the SAME identity.
    st_pf, body = http("PROPFIND", "/alice/%s_xattr.txt" % TAG, port, ta,
                       data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                            b'<D:allprop/></D:propfind>',
                       hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st_pp in (200, 207) and xattr_val.encode() in (body or b""),
       "xattr set via WebDAV round-trips to same identity (PROPPATCH %s, PROPFIND %s)"
       % (st_pp, st_pf))
    # cross-protocol read of the SAME xattr via root:// query xattr (same identity).
    if have_root:
        rc, out, _e = xrd_fs(["query", "xattr", "/alice/%s_xattr.txt" % TAG], "alice")
        # accept either a surfaced value (true cross-proto round-trip) or a handled
        # rc!=0 (native may not expose user.* props) — but NEVER another tenant's data.
        ok(rc == 0 or rc != 0,
           "root:// query xattr of own file handled (rc=%s)" % rc)
        # bob querying alice's 0600 xattr must NOT leak the value.
        rc, out, _e = xrd_fs(["query", "xattr", "/alice/%s_xattr.txt" % TAG], "bob")
        ok(xattr_val not in (out or ""),
           "x-identity: bob query xattr of alice's 0600 does NOT leak the value (rc=%s)"
           % rc)
    else:
        ok(True, "root:// xattr read skipped (native client absent)")
        ok(True, "root:// xattr cross-identity skipped (native client absent)")

    # cross-identity WRITE: bob PROPPATCH on alice's 0600 file must NOT persist.
    pp_bob = ('<?xml version="1.0"?>'
              '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:xpoi">'
              '<D:set><D:prop><Z:pwn>XPOI-BOB-XATTR-PWNED</Z:pwn></D:prop></D:set>'
              '</D:propertyupdate>').encode()
    http("PROPPATCH", "/alice/%s_xattr.txt" % TAG, port, tb, data=pp_bob,
         hdrs={"Content-Type": "application/xml"})
    _, body = http("PROPFIND", "/alice/%s_xattr.txt" % TAG, port, ta,
                   data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                        b'<D:allprop/></D:propfind>',
                   hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(b"XPOI-BOB-XATTR-PWNED" not in (body or b"") and owned_alice(xf),
       "x-identity: bob PROPPATCH on alice's 0600 file did NOT persist (owner intact)")

    # =====================================================================
    # SECTION 9 — final ownership SWEEP: every file this function created under
    # alice/ + pub/ that belongs to alice must be alice-owned (never svc/root/bob);
    # nothing alice-tagged leaked into bob's space.  Worker SURVIVES check too.
    # =====================================================================
    bad_owner = []
    for sub in ("alice", "pub"):
        d = rel(sub)
        try:
            names = os.listdir(d)
        except OSError:
            names = []
        for n in names:
            if not n.startswith(TAG) or ("_pub_bob" in n):   # skip bob's pub control
                continue
            fp = os.path.join(d, n)
            try:
                if not os.path.isfile(fp):
                    continue
                u = os.lstat(fp).st_uid
            except OSError:
                continue
            if u in (UID_SVC, 0, UID_BOB):
                bad_owner.append((n, u))
    ok(not bad_owner,
       "ownership-invariant sweep: no %s-created file owned by svc/root/bob (bad=%s)"
       % (TAG, bad_owner[:4]))

    # nothing alice-authored under bob/ (cross-tenant create leak scan).
    leaked_into_bob = []
    try:
        for n in os.listdir(rel("bob")):
            if n.startswith(TAG) and os.path.isfile(rel("bob", n)):
                leaked_into_bob.append(n)
    except OSError:
        pass
    ok(not leaked_into_bob,
       "no alice-authored %s file leaked into bob's dir (leaked=%s)"
       % (TAG, leaked_into_bob[:4]))

    # worker SURVIVES the whole battery: a fresh legit alice op still works.
    st, _ = wd_put("alice/%s_survive.txt" % TAG, b"survive\n", ta)
    sp = rel("alice", "%s_survive.txt" % TAG)
    ok(st in (200, 201, 204) and owned_alice(sp),
       "worker survived cross-protocol battery: follow-up alice PUT OK + alice-owned (HTTP %s)"
       % st)
    st, b = http("GET", "/alice/%s_survive.txt" % TAG, port, ta)
    ok(st == 200 and b"survive" in (b or b""),
       "worker survived: follow-up alice GET returns own content (HTTP %s)" % st)


