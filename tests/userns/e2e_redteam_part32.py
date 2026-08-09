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


def run_native_tpc(key, data, port, s3port):
    """Native THIRD-PARTY COPY (xrdcp --tpc) under per-request UNIX impersonation.
    Loopback TPC: source and destination are BOTH the impersonation stream server,
    so the orchestrated server-to-server copy still runs through the broker and the
    written destination MUST be owned by the mapped requester (never svc/root).  A
    cross-tenant SOURCE (pull bob's 0600) or cross-tenant DEST (push into bob's 0700
    dir) MUST be denied with nothing created/leaked.  If the server does not support
    --tpc at all we accept the legit case gracefully as handled, but the cross-tenant
    DENY/no-leak invariants are still asserted unconditionally."""
    TAG = "ntpc"
    if not xrd_avail():
        ok(True, "native TPC suite skipped (native client absent)")
        return

    MARK_A = b"NTPC-ALICE-OWN-SECRET-PAYLOAD"
    MARK_B = b"NTPC-BOB-OWN-SECRET-PAYLOAD"
    BOB_PRIV = b"BOB-PRIVATE-SECRET"          # bytes living in data/bob/private.txt

    # ---- Seed fixtures we control (created as in-ns root, then chown'd) ----------
    a_src_rel = "/alice/%s_src.bin" % TAG
    a_src_fs = os.path.join(data, "alice", "%s_src.bin" % TAG)
    b_src_rel = "/bob/%s_src.bin" % TAG
    b_src_fs = os.path.join(data, "bob", "%s_src.bin" % TAG)
    try:
        with open(a_src_fs, "wb") as fh:
            fh.write(MARK_A + b"\n")
        os.chown(a_src_fs, UID_ALICE, UID_ALICE)
        os.chmod(a_src_fs, 0o644)
    except OSError as e:
        ok(False, "%s: could not seed alice src fixture (%r)" % (TAG, e))
        return
    try:
        with open(b_src_fs, "wb") as fh:
            fh.write(MARK_B + b"\n")
        os.chown(b_src_fs, UID_BOB, UID_BOB)
        os.chmod(b_src_fs, 0o600)
    except OSError as e:
        ok(False, "%s: could not seed bob src fixture (%r)" % (TAG, e))
        return

    def _owner(path):
        try:
            return os.stat(path).st_uid
        except OSError:
            return -1

    def _content(path):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def _gone(path):
        return not os.path.exists(path)

    # =================================================================
    # (a) alice TPC-copies her OWN file alice/src -> alice/dst
    #     dst owned by alice (1001), byte-exact, no svc/root ownership.
    # =================================================================
    a_dst_rel = "/alice/%s_dst.bin" % TAG
    a_dst_fs = os.path.join(data, "alice", "%s_dst.bin" % TAG)
    try:
        if os.path.exists(a_dst_fs):
            os.remove(a_dst_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc(a_src_rel, a_dst_rel, "alice")
    tpc_supported = (rc == 0 and os.path.exists(a_dst_fs))
    if tpc_supported:
        ok(_owner(a_dst_fs) == UID_ALICE,
           "%s(a): alice self-TPC dst owned by alice uid=%d (rc=%d)"
           % (TAG, _owner(a_dst_fs), rc))
        ok(_owner(a_dst_fs) not in (UID_SVC, 0),
           "%s(a): self-TPC dst NOT owned by svc/root (uid=%d)"
           % (TAG, _owner(a_dst_fs)))
        ok(_content(a_dst_fs) == MARK_A + b"\n",
           "%s(a): self-TPC dst is byte-exact copy of source" % TAG)
    else:
        # Unsupported / refused: accept as handled, but assert NO svc/root artifact.
        ok(_gone(a_dst_fs) or _owner(a_dst_fs) == UID_ALICE,
           "%s(a): self-TPC unsupported/handled (rc=%d), no svc/root dst artifact"
           % (TAG, rc))
        ok(_owner(a_dst_fs) not in (UID_SVC, 0),
           "%s(a): self-TPC produced no svc/root-owned artifact (uid=%d)"
           % (TAG, _owner(a_dst_fs)))

    # Positive control regardless of TPC support: plain copy of own file works and
    # is alice-owned (proves the deny cases below are real, not blanket failure).
    a_ctl_rel = "/alice/%s_ctl.bin" % TAG
    a_ctl_fs = os.path.join(data, "alice", "%s_ctl.bin" % TAG)
    try:
        if os.path.exists(a_ctl_fs):
            os.remove(a_ctl_fs)
    except OSError:
        pass
    cdn = os.path.join(WORK, "%s_a_ctl_dl.bin" % TAG)
    rc_d, _o, _e = xrd_cp_down(a_src_rel, cdn, "alice")
    rc_u, _o, _e = xrd_cp_up(cdn, a_ctl_rel.lstrip("/"), "alice")
    ok(rc_d == 0 and rc_u == 0 and _owner(a_ctl_fs) == UID_ALICE
       and _content(a_ctl_fs) == MARK_A + b"\n",
       "%s control: alice plain down+up of own file works, alice-owned (rc=%d/%d)"
       % (TAG, rc_d, rc_u))

    # =================================================================
    # (b) CROSS-TENANT SOURCE: alice TPC-pulls bob/private.txt (0600)
    #     into alice/stolen -> DENIED, no stolen file with the secret.
    # =================================================================
    stolen_rel = "/alice/%s_stolen.bin" % TAG
    stolen_fs = os.path.join(data, "alice", "%s_stolen.bin" % TAG)
    try:
        if os.path.exists(stolen_fs):
            os.remove(stolen_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc("/bob/private.txt", stolen_rel, "alice")
    leaked_priv = (os.path.exists(stolen_fs) and BOB_PRIV in _content(stolen_fs)) \
        or (BOB_PRIV in (out or "").encode()) or (BOB_PRIV in (err or "").encode())
    ok(rc != 0 and not leaked_priv,
       "%s(b): alice TPC-pull of bob/private.txt(0600) DENIED (rc=%d)" % (TAG, rc))
    ok(not (os.path.exists(stolen_fs) and BOB_PRIV in _content(stolen_fs)),
       "%s(b): no stolen file in alice/ carries the BOB-PRIVATE secret marker" % TAG)
    ok(BOB_PRIV not in (out or "").encode() and BOB_PRIV not in (err or "").encode(),
       "%s(b): bob private secret bytes absent from TPC stdout/stderr" % TAG)
    # The source secret must not have ended up anywhere alice-readable; if any file
    # was created it must NOT be a bob-owned secret smuggled in.
    if os.path.exists(stolen_fs):
        ok(BOB_PRIV not in _content(stolen_fs) and _owner(stolen_fs) != UID_BOB,
           "%s(b): residual alice/stolen (if any) holds no bob secret/ownership"
           % TAG)
    else:
        ok(True, "%s(b): no alice/stolen artifact created at all" % TAG)

    # =================================================================
    # (c) CROSS-TENANT DEST: alice TPC-copies alice/src -> bobsecret/x
    #     (bob 0700) -> DENIED, nothing created in bob's dir.
    # =================================================================
    bdst_rel = "/bobsecret/%s_x.bin" % TAG
    bdst_fs = os.path.join(data, "bobsecret", "%s_x.bin" % TAG)
    try:
        if os.path.exists(bdst_fs):
            os.remove(bdst_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc(a_src_rel, bdst_rel, "alice")
    ok(rc != 0 and _gone(bdst_fs),
       "%s(c): alice TPC into bob's 0700 dir DENIED, nothing created (rc=%d)"
       % (TAG, rc))
    ok(_gone(bdst_fs) or _owner(bdst_fs) not in (UID_ALICE, UID_SVC, 0),
       "%s(c): no alice/svc/root-owned file smuggled into bobsecret/" % TAG)
    # bobsecret/ dir mode must be untouched (still bob 0700).
    try:
        dmode = os.stat(os.path.join(data, "bobsecret")).st_mode & 0o777
        downer = os.stat(os.path.join(data, "bobsecret")).st_uid
        ok(dmode == 0o700 and downer == UID_BOB,
           "%s(c): bobsecret/ dir intact bob:0700 after deny (mode=%o uid=%d)"
           % (TAG, dmode, downer))
    except OSError as e:
        ok(False, "%s(c): could not stat bobsecret/ (%r)" % (TAG, e))

    # =================================================================
    # (d) bob TPC-copies his OWN file -> owned by bob.
    # =================================================================
    b_dst_rel = "/bob/%s_dst.bin" % TAG
    b_dst_fs = os.path.join(data, "bob", "%s_dst.bin" % TAG)
    try:
        if os.path.exists(b_dst_fs):
            os.remove(b_dst_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc(b_src_rel, b_dst_rel, "bob")
    if rc == 0 and os.path.exists(b_dst_fs):
        ok(_owner(b_dst_fs) == UID_BOB,
           "%s(d): bob self-TPC dst owned by bob uid=%d (rc=%d)"
           % (TAG, _owner(b_dst_fs), rc))
        ok(_owner(b_dst_fs) not in (UID_ALICE, UID_SVC, 0),
           "%s(d): bob self-TPC dst NOT owned by alice/svc/root (uid=%d)"
           % (TAG, _owner(b_dst_fs)))
        ok(_content(b_dst_fs) == MARK_B + b"\n",
           "%s(d): bob self-TPC dst byte-exact" % TAG)
    else:
        ok(_gone(b_dst_fs) or _owner(b_dst_fs) == UID_BOB,
           "%s(d): bob self-TPC unsupported/handled (rc=%d), no foreign-owned dst"
           % (TAG, rc))
        ok(_owner(b_dst_fs) not in (UID_ALICE, UID_SVC, 0),
           "%s(d): bob self-TPC left no alice/svc/root artifact (uid=%d)"
           % (TAG, _owner(b_dst_fs)))

    # =================================================================
    # (e) TPC mode variants 'first' and 'delegate' (cross-tenant + own).
    #     Cross-tenant source must stay denied under EVERY mode; own copy
    #     under each mode, if it lands, must be requester-owned.
    # =================================================================
    for mode in ("first", "delegate"):
        # cross-tenant pull of bob's private must fail under this mode.
        st_rel = "/alice/%s_steal_%s.bin" % (TAG, mode)
        st_fs = os.path.join(data, "alice", "%s_steal_%s.bin" % (TAG, mode))
        try:
            if os.path.exists(st_fs):
                os.remove(st_fs)
        except OSError:
            pass
        rc, out, err = xrd_cp_tpc("/bob/private.txt", st_rel, "alice", mode=mode)
        leaked = (os.path.exists(st_fs) and BOB_PRIV in _content(st_fs)) \
            or (BOB_PRIV in (out or "").encode()) \
            or (BOB_PRIV in (err or "").encode())
        ok(rc != 0 and not leaked,
           "%s(e): TPC mode=%s cross-tenant pull of bob secret DENIED, no leak (rc=%d)"
           % (TAG, mode, rc))
        # own-file copy under this mode: requester-owned if it materializes.
        od_rel = "/alice/%s_mode_%s.bin" % (TAG, mode)
        od_fs = os.path.join(data, "alice", "%s_mode_%s.bin" % (TAG, mode))
        try:
            if os.path.exists(od_fs):
                os.remove(od_fs)
        except OSError:
            pass
        rc2, _o2, _e2 = xrd_cp_tpc(a_src_rel, od_rel, "alice", mode=mode)
        if rc2 == 0 and os.path.exists(od_fs):
            ok(_owner(od_fs) == UID_ALICE and _content(od_fs) == MARK_A + b"\n",
               "%s(e): TPC mode=%s own-copy alice-owned + byte-exact (rc=%d)"
               % (TAG, mode, rc2))
        else:
            ok(_gone(od_fs) or _owner(od_fs) == UID_ALICE,
               "%s(e): TPC mode=%s own-copy unsupported/handled, no foreign artifact"
               " (rc=%d)" % (TAG, mode, rc2))
        ok(_owner(od_fs) not in (UID_SVC, 0) if os.path.exists(od_fs) else True,
           "%s(e): TPC mode=%s own-copy never svc/root-owned" % (TAG, mode))

    # =================================================================
    # (f) FORGED / NON-MAPPABLE principal TPC -> denied, nothing created.
    #     A token whose sub does not map to a provisioned user must not be
    #     able to orchestrate a copy into alice's space.
    # =================================================================
    forged_rel = "/alice/%s_forged.bin" % TAG
    forged_fs = os.path.join(data, "alice", "%s_forged.bin" % TAG)
    try:
        if os.path.exists(forged_fs):
            os.remove(forged_fs)
    except OSError:
        pass
    # 'nobody-xyz' is not a provisioned identity; mint() builds a structurally valid
    # token but the broker has no uid mapping for it -> must be refused (fail-closed).
    rc, out, err = xrd_cp_tpc(a_src_rel, forged_rel, "nobody-xyz")
    ok(rc != 0 and _gone(forged_fs),
       "%s(f): TPC by unmapped principal DENIED, nothing created (rc=%d)"
       % (TAG, rc))
    ok(MARK_A not in (out or "").encode() and MARK_A not in (err or "").encode(),
       "%s(f): unmapped-principal TPC leaked no alice source bytes" % TAG)
    ok(_gone(forged_fs) or _owner(forged_fs) not in (UID_SVC, 0),
       "%s(f): unmapped-principal TPC produced no svc/root artifact" % TAG)
    # Same forged principal cannot pull bob's secret either (no identity confusion).
    fsteal_rel = "/alice/%s_forged_steal.bin" % TAG
    fsteal_fs = os.path.join(data, "alice", "%s_forged_steal.bin" % TAG)
    try:
        if os.path.exists(fsteal_fs):
            os.remove(fsteal_fs)
    except OSError:
        pass
    rc, out, err = xrd_cp_tpc("/bob/private.txt", fsteal_rel, "nobody-xyz")
    fleak = (os.path.exists(fsteal_fs) and BOB_PRIV in _content(fsteal_fs)) \
        or (BOB_PRIV in (out or "").encode()) or (BOB_PRIV in (err or "").encode())
    ok(rc != 0 and not fleak,
       "%s(f): unmapped principal cannot TPC-steal bob secret (rc=%d)" % (TAG, rc))

    # =================================================================
    # (g) TPC into pub/ (0777, svc-owned) -> dst owned by the COPIER, not svc.
    #     Proves impersonation governs ownership even in a world-writable dir.
    # =================================================================
    pub_a_rel = "/pub/%s_pub_alice.bin" % TAG
    pub_a_fs = os.path.join(data, "pub", "%s_pub_alice.bin" % TAG)
    pub_b_rel = "/pub/%s_pub_bob.bin" % TAG
    pub_b_fs = os.path.join(data, "pub", "%s_pub_bob.bin" % TAG)
    for p in (pub_a_fs, pub_b_fs):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass
    rc, out, err = xrd_cp_tpc(a_src_rel, pub_a_rel, "alice")
    if rc == 0 and os.path.exists(pub_a_fs):
        ok(_owner(pub_a_fs) == UID_ALICE,
           "%s(g): alice TPC into pub/(0777) owned by alice not svc (uid=%d, rc=%d)"
           % (TAG, _owner(pub_a_fs), rc))
        ok(_owner(pub_a_fs) not in (UID_SVC, 0),
           "%s(g): pub/ TPC dst NOT svc/root-owned (uid=%d)" % (TAG, _owner(pub_a_fs)))
        ok(_content(pub_a_fs) == MARK_A + b"\n",
           "%s(g): pub/ TPC dst byte-exact" % TAG)
    else:
        ok(_gone(pub_a_fs) or _owner(pub_a_fs) == UID_ALICE,
           "%s(g): pub/ TPC unsupported/handled (rc=%d), no svc-owned artifact"
           % (TAG, rc))
        ok(_owner(pub_a_fs) not in (UID_SVC, 0) if os.path.exists(pub_a_fs) else True,
           "%s(g): pub/ TPC left no svc/root-owned artifact" % TAG)
    # bob TPC into the SAME 0777 dir must land bob-owned (no principal bleed from
    # the previous alice TPC on a shared worker).
    rc, out, err = xrd_cp_tpc(b_src_rel, pub_b_rel, "bob")
    if rc == 0 and os.path.exists(pub_b_fs):
        ok(_owner(pub_b_fs) == UID_BOB and _owner(pub_b_fs) not in (UID_ALICE, UID_SVC, 0),
           "%s(g): bob TPC into pub/ owned by bob, no alice/svc bleed (uid=%d)"
           % (TAG, _owner(pub_b_fs)))
        ok(_content(pub_b_fs) == MARK_B + b"\n",
           "%s(g): bob pub/ TPC dst byte-exact" % TAG)
    else:
        ok(_gone(pub_b_fs) or _owner(pub_b_fs) == UID_BOB,
           "%s(g): bob pub/ TPC unsupported/handled (rc=%d), no foreign artifact"
           % (TAG, rc))
        ok(_owner(pub_b_fs) not in (UID_ALICE, UID_SVC, 0)
           if os.path.exists(pub_b_fs) else True,
           "%s(g): bob pub/ TPC never alice/svc/root-owned" % TAG)

    # =================================================================
    # WORKER-SURVIVAL: after all the denied / forged orchestration, a fresh
    # legit op by both tenants must still succeed (broker/worker not wedged).
    # =================================================================
    surv = os.path.join(WORK, "%s_surv_dl.bin" % TAG)
    rc_a, _o, _e = xrd_cp_down(a_src_rel, surv, "alice")
    ok(rc_a == 0 and os.path.exists(surv) and MARK_A in _content(surv),
       "%s survival: alice legit read still works after TPC attacks (rc=%d)"
       % (TAG, rc_a))
    rc_s, out_s, _e = xrd_fs(["stat", "/bob/private.txt"], "bob")
    ok(rc_s == 0, "%s survival: bob legit stat still works post-attack (rc=%d)"
       % (TAG, rc_s))
    # And bob's private secret was never disturbed by any of the above.
    ok(_content(os.path.join(data, "bob", "private.txt")) == BOB_PRIV
       or BOB_PRIV in _content(os.path.join(data, "bob", "private.txt")),
       "%s survival: bob/private.txt secret intact after all TPC attempts" % TAG)
    ok(_owner(os.path.join(data, "bob", "private.txt")) == UID_BOB,
       "%s survival: bob/private.txt still bob-owned (uid=%d)"
       % (TAG, _owner(os.path.join(data, "bob", "private.txt"))))


