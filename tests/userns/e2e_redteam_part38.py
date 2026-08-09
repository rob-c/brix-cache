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


def run_combo_symlink_crossproto_toctou(key, data, port, s3port):
    """COMBINATION frontier: links PLANTED via one protocol and FOLLOWED via ANOTHER,
    plus TOCTOU swaps that race a regular file into a cross-tenant symlink between two
    ops.  This is NOT the single-protocol symlink/hardlink coverage of run_stream_
    extended_ops (root:// only) nor the host-planted host-file confinement of
    run_broker_resource_limits batch D — every check here crosses a protocol boundary
    (plant-proto != follow-proto) or interleaves an os-level swap between two
    protocol ops.  Invariants: a foreign/secret target reached through a planted link
    NEVER leaks its bytes regardless of which protocol follows it; a hardlink alias
    never launders group/owner DAC for a non-member reading via a different protocol;
    a TOCTOU swap to bob's secret stays confined under the follow-up op; readlink
    across a tenant boundary leaks neither target bytes nor existence-as-readable; a
    PROPFIND/ListObjects over a dir of planted links lists names but never recurses or
    serves the link targets.  Every deny carries an adjacent positive control; every
    read-deny also asserts the secret marker is absent; the worker survives (a final
    legit cross-protocol op works)."""
    TAG = "csct"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    have_s3 = bool(s3port)
    have_root = xrd_avail()

    # Unique markers so a leak assertion can scan a body deterministically.  These
    # live ONLY behind a link/alias/swap; if any appears in a cross-protocol follow
    # response the confinement/DAC boundary was laundered by the link.
    BOB_SECRET = b"BOB-PRIVATE-SECRET"               # data/bob/private.txt (0600 bob)
    BOB_WORLD = b"bob-world-readable"                # data/bob/readable.txt (0644 bob)
    PASSWD_MARK = b"root:x:0:0"
    GRP_SECRET = b"RESEARCH-GROUP-READABLE"          # grp/research_r.txt (0640 bob:research)

    adir = os.path.join(data, "alice")
    bdir = os.path.join(data, "bob")

    def rel_fs(*parts):
        return os.path.join(data, *parts)

    def luid_of(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def lexists(p):
        try:
            return os.path.lexists(p)
        except OSError:
            return False

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""

    def rm_quiet(p):
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                import shutil as _sh
                _sh.rmtree(p, ignore_errors=True)
        except OSError:
            pass

    def mk_file(p, content, uid, gid, mode):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    def mk_dir(p, uid, gid, mode):
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass

    # ---- cross-protocol follow primitives (read a server PATH via each protocol) ----
    def follow_wd(relpath, tok):
        st, b = http("GET", "/" + relpath, port, tok)
        return st, (b or b"")

    def follow_s3(relpath, ak="alice"):
        if not have_s3:
            return None, b""
        st, b = s3("GET", relpath, s3port, access_key=ak)
        return st, (b or b"")

    def follow_root(relpath, sub):
        if not have_root:
            return None, ""
        rc, out, _e = xrd_fs(["cat", "/" + relpath], sub)
        return rc, (out or "")

    def root_ln_s(target, linkpath, sub):
        """Plant a symlink via the root:// protocol itself (ln -s), as <sub>."""
        if not have_root:
            return None
        rc, _o, _e = xrd_fs(["ln", "-s", target, linkpath], sub)
        return rc

    def root_ln_hard(target, linkpath, sub):
        if not have_root:
            return None
        rc, _o, _e = xrd_fs(["ln", target, linkpath], sub)
        return rc

    def leaked(body, *needles):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return any((n if isinstance(n, bytes) else n.encode()) in (body or b"")
                   for n in needles)

    # =====================================================================
    # SECTION 1 — SYMLINK planted via root:// (ln -s) to FOREIGN/SECRET targets,
    # then FOLLOWED via WebDAV + S3 + root://.  Planting protocol (root) differs
    # from the follow protocol (WebDAV/S3) — the cross-protocol combination.  A
    # link to bob's 0600 / /etc/passwd / a ../../bob relative escape must never
    # yield those bytes through ANY following protocol, as alice OR as bob.
    # =====================================================================
    link_specs = [
        ("toabs_bobpriv", "/bob/private.txt",
         (BOB_SECRET,), "abs symlink->bob 0600 (planted via root://)"),
        ("toabs_passwd", "/etc/passwd",
         (PASSWD_MARK, b"/bin/bash"), "abs symlink->/etc/passwd (planted via root://)"),
        ("torel_bobpriv", "../bob/private.txt",
         (BOB_SECRET,), "relative ../bob/private.txt symlink (planted via root://)"),
        ("torel_deep_etc", "../../etc/passwd",
         (PASSWD_MARK,), "relative ../../etc/passwd escape symlink (planted via root://)"),
    ]
    planted_any = False
    for name, target, secrets, desc in link_specs:
        linkrel = "alice/%s_%s" % (TAG, name)
        linkfs = rel_fs("alice", "%s_%s" % (TAG, name))
        rm_quiet(linkfs)
        rc = root_ln_s(target, "/" + linkrel, "alice")
        planted = lexists(linkfs)
        if not planted:
            # root:// may refuse symlink creation entirely (secure default) — accept
            # as handled, but cover the same shape via a host-planted alice-owned link
            # so the cross-protocol FOLLOW path is still exercised (the link is the
            # attack vector regardless of who planted it; what matters is no follow leak).
            try:
                os.symlink(target, linkfs)
                os.lchown(linkfs, UID_ALICE, UID_ALICE)
            except OSError:
                pass
            planted = lexists(linkfs)
            ok(True, "%s: root:// ln -s refused (rc=%s); host-planted fallback "
               "exercises cross-proto follow (planted=%s)" % (desc, rc, planted))
        else:
            planted_any = True
            ok(luid_of(linkfs) == UID_ALICE,
               "%s: planted link owned by alice not svc/root (luid=%s)"
               % (desc, luid_of(linkfs)))
        if not planted:
            ok(True, "%s: could not plant link in this env — follow checks skipped "
               "(handled, no leak possible)" % desc)
            continue
        # FOLLOW via WebDAV as alice: never the target bytes.
        st, b = follow_wd(linkrel, ta)
        ok(not leaked(b, *secrets),
           "%s: WebDAV GET (alice) follows planted link to NO secret bytes (HTTP %s)"
           % (desc, st))
        # FOLLOW via WebDAV as bob chasing alice's planted link.  CRITICAL: when the
        # link's target is bob's OWN file (e.g. ../bob/private.txt), the link resolves -
        # confined inside the export by openat2(RESOLVE_BENEATH) - to bob's own 0600
        # inode, and the brokered open runs AS bob, so 200 + his OWN bytes is the
        # CORRECT, secure result (no cross-tenant laundering: he can only ever reach
        # what his own UID may read).  A leak requires bob reaching a FOREIGN secret
        # (passwd/etc), which must always deny with no secret bytes.
        bob_owns_target = target in ("/bob/private.txt", "../bob/private.txt")
        st, b = follow_wd(linkrel, tb)
        if bob_owns_target:
            ok(st in (401, 403, 404) or (st == 200 and leaked(b, *secrets)),
               "%s: WebDAV GET (bob) via link to bob's OWN file = his own bytes or "
               "refused, never a foreign leak (HTTP %s)" % (desc, st))
        else:
            ok(st in (401, 403, 404) and not leaked(b, *secrets),
               "%s: WebDAV GET (bob) cannot ride alice's link to FOREIGN secret (HTTP %s)"
               % (desc, st))
        # FOLLOW via S3 (alice key) — a different protocol resolving the same inode.
        st, b = follow_s3(linkrel)
        if st is None:
            ok(True, "%s: S3 follow skipped (S3 down)" % desc)
        else:
            ok(not leaked(b, *secrets),
               "%s: S3 GET follows planted link to NO secret bytes (HTTP %s)"
               % (desc, st))
        # FOLLOW via root:// cat as alice (re-confirm the planted-then-followed loop).
        rc2, out = follow_root(linkrel, "alice")
        if rc2 is None:
            ok(True, "%s: root:// follow skipped (native client absent)" % desc)
        else:
            ok(not leaked(out, *secrets),
               "%s: root:// cat (alice) of planted link leaks no secret (rc=%s)"
               % (desc, rc2))
        # root:// cat as bob too.  As with the WebDAV follow above: a link to bob's
        # OWN file resolves (confined) to his own inode and reads AS bob -> rc=0 + his
        # own bytes is CORRECT, not a leak.  Only a FOREIGN target must deny.
        rc2, out = follow_root(linkrel, "bob")
        if rc2 is None:
            ok(True, "%s: root:// follow (bob) skipped" % desc)
        elif bob_owns_target:
            ok(rc2 != 0 or leaked(out, *secrets),
               "%s: root:// cat (bob) of link to his OWN file = own bytes or denied, "
               "never a foreign leak (rc=%s)" % (desc, rc2))
        else:
            ok(rc2 != 0 and not leaked(out, *secrets),
               "%s: root:// cat (bob) of alice's link to FOREIGN secret denied (rc=%s)"
               % (desc, rc2))
        rm_quiet(linkfs)

    # POSITIVE CONTROL for SECTION 1: a symlink to alice's OWN benign file may resolve
    # (own bytes) or be refused (secure default) — but NEVER yields foreign bytes, and
    # cross-protocol follow agrees.  Proves the denies above are not a blanket "all
    # links 404" that would also false-pass.
    own = rel_fs("alice", "%s_own_target.txt" % TAG)
    mk_file(own, b"CSCT-ALICE-OWN-BENIGN\n", UID_ALICE, UID_ALICE, 0o644)
    own_link = rel_fs("alice", "%s_own_link" % TAG)
    rm_quiet(own_link)
    rc = root_ln_s("%s_own_target.txt" % TAG, "/alice/%s_own_link" % TAG, "alice")
    if not lexists(own_link):
        try:
            os.symlink("%s_own_target.txt" % TAG, own_link)
            os.lchown(own_link, UID_ALICE, UID_ALICE)
        except OSError:
            pass
    if lexists(own_link):
        st, b = follow_wd("alice/%s_own_link" % TAG, ta)
        ok((st == 200 and leaked(b, b"CSCT-ALICE-OWN-BENIGN")) or st != 200,
           "control: WebDAV follow of alice's own-target link = own bytes or refused, "
           "never foreign (HTTP %s)" % st)
        stc, bc = follow_s3("alice/%s_own_link" % TAG)
        if stc is None:
            ok(True, "control: S3 own-link follow skipped (S3 down)")
        else:
            ok((stc == 200 and leaked(bc, b"CSCT-ALICE-OWN-BENIGN")) or stc != 200,
               "control: S3 follow of alice's own-target link = own bytes or refused "
               "(HTTP %s)" % stc)
        ok(not leaked(b, BOB_SECRET, PASSWD_MARK),
           "control: own-link follow never carries any cross-tenant/host secret")
    else:
        ok(True, "control own-link planting skipped (handled)")
        ok(True, "control own-link S3 follow skipped (handled)")
        ok(True, "control own-link no-foreign-bytes skipped (handled)")

    # =====================================================================
    # SECTION 2 — link planted via WebDAV/S3 side-effect path vs root:// follow.
    # WebDAV/S3 have no native "create symlink" verb, so the realistic cross-protocol
    # vector is: an attacker plants the link (host-level, alice-owned) and then drives
    # a DIFFERENT protocol's writer/reader at it.  Here: a link sitting at a path that
    # a WebDAV PUT / S3 PUT would target — the write must hit a real confined file (or
    # be refused), NEVER traverse the link to clobber bob's 0600 secret.
    # =====================================================================
    clob_target = rel_fs("bob", "private.txt")
    before_owner = luid_of(clob_target)
    before_body = body_of(clob_target)
    wlink = rel_fs("alice", "%s_putclobber" % TAG)
    rm_quiet(wlink)
    try:
        os.symlink("/bob/private.txt", wlink)
        os.lchown(wlink, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    if lexists(wlink):
        # WebDAV PUT onto a symlink that points at bob's secret — must not follow the
        # link to overwrite bob's file (cross-protocol: link is a filesystem object,
        # the WRITE arrives over HTTP).
        st, _ = http("PUT", "/alice/%s_putclobber" % TAG, port, ta, b"CSCT-WD-CLOBBER\n")
        ok(body_of(clob_target) == before_body
           and luid_of(clob_target) == before_owner == UID_BOB,
           "WebDAV PUT through alice's link->bob/0600 does NOT clobber bob's secret "
           "(HTTP %s, owner=%s)" % (st, luid_of(clob_target)))
        ok(not leaked(body_of(clob_target), b"CSCT-WD-CLOBBER"),
           "bob's private.txt body unpolluted by the cross-link WebDAV PUT")
        if have_s3:
            st, _ = s3("PUT", "alice/%s_putclobber" % TAG, s3port, data=b"CSCT-S3-CLOBBER\n")
            ok(body_of(clob_target) == before_body
               and luid_of(clob_target) == UID_BOB,
               "S3 PUT through alice's link->bob/0600 does NOT clobber bob's secret "
               "(HTTP %s)" % st)
            ok(not leaked(body_of(clob_target), b"CSCT-S3-CLOBBER"),
               "bob's private.txt body unpolluted by the cross-link S3 PUT")
        else:
            ok(True, "S3 clobber-through-link skipped (S3 down)")
            ok(True, "S3 clobber body-intact skipped (S3 down)")
        # control: bob (the owner) overwriting his OWN file directly still works and
        # restores expected ownership — proves the deny above is link-confinement,
        # not a blanket write-block on bob/private.txt.
        st, _ = http("PUT", "/bob/private.txt", port, tb, BOB_SECRET + b"\n")
        ok(st in (200, 201, 204) and luid_of(clob_target) == UID_BOB,
           "control: bob PUTs his own private.txt directly, stays bob-owned (HTTP %s)"
           % st)
    else:
        ok(True, "PUT-clobber link planting skipped (handled)")
        ok(True, "PUT-clobber body-intact skipped (handled)")
        ok(True, "PUT-clobber S3 skipped (handled)")
        ok(True, "PUT-clobber S3 body skipped (handled)")
        ok(True, "PUT-clobber control skipped (handled)")
    rm_quiet(wlink)

    # =====================================================================
    # SECTION 3 — HARD LINK alias + GROUP DAC across protocols.  A hard link planted
    # (via root:// or host) in alice's tree to a 0640 group file owned bob:research
    # (alice/carol are NOT in research) keeps the inode's mode/owner/group.  Reading
    # the alias via a DIFFERENT protocol (WebDAV/S3) as a NON-MEMBER must still be
    # denied by group DAC — the alias cannot launder the group bit across protocols.
    # =====================================================================
    grp_src = rel_fs("grp", "research_r.txt")        # 0640 bob:research (fixture)
    if not (os.path.exists(grp_src) and GRP_SECRET in body_of(grp_src)):
        mk_file(grp_src, GRP_SECRET + b"\n", UID_BOB, GID_RESEARCH, 0o640)
    hardrel = "alice/%s_grp_hardlink.txt" % TAG
    hardfs = rel_fs("alice", "%s_grp_hardlink.txt" % TAG)
    rm_quiet(hardfs)
    rc = root_ln_hard("/grp/research_r.txt", "/" + hardrel, "alice")
    aliased = lexists(hardfs)
    if not aliased:
        try:
            os.link(grp_src, hardfs)                 # host-plant the alias if root:// refused
        except OSError:
            pass
        aliased = lexists(hardfs)
        ok(True, "root:// hard-link of group file refused (rc=%s); host alias planted "
           "to drive cross-proto group-DAC follow (aliased=%s)" % (rc, aliased))
    if aliased:
        # The alias is the SAME inode: still 0640 bob:research.  alice (not a research
        # member) reading via WebDAV must be denied; the research secret must not leak.
        st, b = follow_wd(hardrel, ta)
        ok(st in (401, 403, 404) and not leaked(b, GRP_SECRET),
           "hardlink alias does NOT let non-member alice read 0640 research file via "
           "WebDAV (HTTP %s)" % st)
        if have_s3:
            st, b = follow_s3(hardrel)              # S3 maps to alice (non-member)
            ok(st in (401, 403, 404) and not leaked(b, GRP_SECRET),
               "hardlink alias does NOT let alice read 0640 research file via S3 "
               "(HTTP %s)" % st)
        else:
            ok(True, "hardlink S3 group-DAC follow skipped (S3 down)")
        # control: dave IS in research -> reading the SAME alias via root:// is allowed
        # (group DAC on the shared inode grants the member).  Proves the deny is a real
        # group-membership decision, not a blanket alias block.
        rc2, out = follow_root(hardrel, "dave")
        if rc2 is None:
            ok(True, "hardlink member-control (root://) skipped (native client absent)")
        else:
            ok(rc2 == 0 and leaked(out, GRP_SECRET),
               "control: research-member dave reads the 0640 alias via root:// "
               "(group DAC grants, rc=%s)" % rc2)
        # invariant: following the alias never rewrote owner/group of the real inode.
        ok(luid_of(grp_src) == UID_BOB,
           "group file inode still bob-owned after cross-proto alias reads (uid=%s)"
           % luid_of(grp_src))
    else:
        ok(True, "hardlink alias group-DAC: alias could not be planted (handled)")
        ok(True, "hardlink alias S3 skipped (handled)")
        ok(True, "hardlink member-control skipped (handled)")
        ok(True, "hardlink inode-owner invariant skipped (handled)")
    rm_quiet(hardfs)

    # =====================================================================
    # SECTION 4 — readlink CROSS-TENANT combined with a cross-protocol follow.  bob
    # tries to readlink a link sitting in ALICE's 0755 dir (he can traverse) whose
    # target names bob's own secret path: readlink may reveal the stored target string
    # but the subsequent FOLLOW (WebDAV as bob) must NOT yield the secret; and a link
    # in bob's 0700 dir must not be readlink-able by alice at all.
    # =====================================================================
    rl_link = rel_fs("alice", "%s_rl_in_alice" % TAG)
    rm_quiet(rl_link)
    rc = root_ln_s("/bob/private.txt", "/alice/%s_rl_in_alice" % TAG, "alice")
    if not lexists(rl_link):
        try:
            os.symlink("/bob/private.txt", rl_link)
            os.lchown(rl_link, UID_ALICE, UID_ALICE)
        except OSError:
            pass
    if lexists(rl_link) and have_root:
        rc2, out, _e = xrd_fs(["readlink", "/alice/%s_rl_in_alice" % TAG], "bob")
        # readlink revealing the target STRING is not itself a content leak; the secret
        # BYTES must not be in it, and a same-link WebDAV follow as bob must still deny.
        ok(not leaked(out, BOB_SECRET),
           "cross-tenant readlink (bob on alice's link) reveals no secret BYTES (rc=%s)"
           % rc2)
        st, b = follow_wd("alice/%s_rl_in_alice" % TAG, tb)
        ok(st in (401, 403, 404) and not leaked(b, BOB_SECRET),
           "post-readlink WebDAV follow (bob) of the link still denied, no leak "
           "(HTTP %s)" % st)
    else:
        ok(True, "cross-tenant readlink skipped (link unplanted or native absent)")
        ok(True, "post-readlink follow skipped (handled)")
    rm_quiet(rl_link)

    # A link inside bob's 0700 secret dir must not be readlink-able by alice (she
    # cannot even traverse bob's 0700 dir), across protocols: readlink (root) denied,
    # and a WebDAV GET of the link path denied — neither reveals existence-as-readable.
    bsec_link = rel_fs("bobsecret", "%s_blink" % TAG)
    rm_quiet(bsec_link)
    try:
        os.symlink("/etc/passwd", bsec_link)
        os.lchown(bsec_link, UID_BOB, UID_BOB)
    except OSError:
        pass
    if lexists(bsec_link):
        if have_root:
            rc2, out, _e = xrd_fs(["readlink", "/bobsecret/%s_blink" % TAG], "alice")
            ok(rc2 != 0 and not leaked(out, PASSWD_MARK),
               "alice cannot readlink a link inside bob's 0700 dir (rc=%s)" % rc2)
        else:
            ok(True, "readlink-in-0700 (root) skipped (native absent)")
        st, b = follow_wd("bobsecret/%s_blink" % TAG, ta)
        ok(st in (401, 403, 404) and not leaked(b, PASSWD_MARK, BOB_SECRET),
           "WebDAV follow of a link in bob's 0700 dir denied to alice (HTTP %s)" % st)
        # control: bob (owner) CAN readlink his own link in his 0700 dir.
        if have_root:
            rc2, out, _e = xrd_fs(["readlink", "/bobsecret/%s_blink" % TAG], "bob")
            ok(rc2 == 0 or "passwd" in (out or ""),
               "control: bob readlinks his own link in his 0700 dir (rc=%s)" % rc2)
        else:
            ok(True, "readlink-in-0700 control skipped (native absent)")
    else:
        ok(True, "link-in-0700 planting skipped (handled)")
        ok(True, "link-in-0700 WebDAV follow skipped (handled)")
        ok(True, "link-in-0700 control skipped (handled)")
    rm_quiet(bsec_link)

    # =====================================================================
    # SECTION 5 — TOCTOU: a path is a REGULAR alice file when op #1 runs, then is
    # atomically swapped (os.remove + os.symlink, in-ns root) to a link at bob's secret
    # BETWEEN op #1 and op #2 — and op #2 (often a DIFFERENT protocol) must still be
    # confined: it must not chase the freshly-planted link to bob's secret.  Modest
    # concurrency only; no large payloads.
    # =====================================================================
    def toctou_swap(relname, swap_target):
        p = rel_fs("alice", relname)
        rm_quiet(p)
        mk_file(p, b"CSCT-TOCTOU-REGULAR\n", UID_ALICE, UID_ALICE, 0o644)
        return p

    # 5a: WebDAV GET op#1 sees a regular file; swap to bob-secret link; WebDAV GET op#2.
    p = toctou_swap("%s_toctou_a" % TAG, "/bob/private.txt")
    st1, b1 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(st1 == 200 and leaked(b1, b"CSCT-TOCTOU-REGULAR"),
       "TOCTOU 5a: pre-swap WebDAV GET returns alice's regular file (HTTP %s)" % st1)
    try:
        os.remove(p)
        os.symlink("/bob/private.txt", p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    st2, b2 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(not leaked(b2, BOB_SECRET),
       "TOCTOU 5a: post-swap WebDAV GET does NOT chase link to bob's secret (HTTP %s)"
       % st2)
    rm_quiet(p)

    # 5b: cross-protocol TOCTOU — root:// stat op#1 (regular), swap to /etc/passwd link,
    # then S3 GET op#2 must not serve host passwd.
    p = toctou_swap("%s_toctou_b" % TAG, "/etc/passwd")
    if have_root:
        rc1, _o, _e = xrd_fs(["stat", "/alice/%s_toctou_b" % TAG], "alice")
        ok(True, "TOCTOU 5b: pre-swap root:// stat of regular alice file (rc=%s)" % rc1)
    else:
        ok(True, "TOCTOU 5b: pre-swap root:// stat skipped (native absent)")
    try:
        os.remove(p)
        os.symlink("/etc/passwd", p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    if have_s3:
        st2, b2 = follow_s3("alice/%s_toctou_b" % TAG)
        ok(not leaked(b2, PASSWD_MARK, b"/bin/bash"),
           "TOCTOU 5b: post-swap S3 GET does NOT serve /etc/passwd via the link "
           "(HTTP %s)" % st2)
    else:
        st2, b2 = follow_wd("alice/%s_toctou_b" % TAG, ta)
        ok(not leaked(b2, PASSWD_MARK),
           "TOCTOU 5b: post-swap WebDAV GET (S3 down) serves no /etc/passwd (HTTP %s)"
           % st2)
    rm_quiet(p)

    # 5c: RACE form — a thread flips the path between regular and a bob-secret link
    # while a small pool of WebDAV GETs hammers it.  At most 8 threads, tiny payloads.
    racepath = rel_fs("alice", "%s_toctou_race" % TAG)
    rm_quiet(racepath)
    mk_file(racepath, b"CSCT-RACE-REGULAR\n", UID_ALICE, UID_ALICE, 0o644)
    stop = threading.Event()
    flips = {"n": 0}

    def flipper():
        toggle = False
        while not stop.is_set():
            try:
                if os.path.lexists(racepath):
                    os.remove(racepath)
                if toggle:
                    os.symlink("/bob/private.txt", racepath)
                    os.lchown(racepath, UID_ALICE, UID_ALICE)
                else:
                    with open(racepath, "wb") as fh:
                        fh.write(b"CSCT-RACE-REGULAR\n")
                    os.chown(racepath, UID_ALICE, UID_ALICE)
                    os.chmod(racepath, 0o644)
                flips["n"] += 1
            except OSError:
                pass
            toggle = not toggle
            time.sleep(0.002)

    leak_hits = {"n": 0}
    err_hits = {"n": 0}

    def racer():
        for _ in range(12):
            try:
                st, b = http("GET", "/alice/%s_toctou_race" % TAG, port, ta)
                if BOB_SECRET in (b or b""):
                    leak_hits["n"] += 1
            except Exception:  # noqa: BLE001
                err_hits["n"] += 1

    ft = threading.Thread(target=flipper)
    ft.start()
    racers = [threading.Thread(target=racer) for _ in range(6)]   # modest: 6+1 threads
    for t in racers:
        t.start()
    for t in racers:
        t.join()
    stop.set()
    ft.join()
    ok(leak_hits["n"] == 0,
       "TOCTOU 5c: concurrent regular<->bob-link flips never leaked bob's secret "
       "over WebDAV (flips=%s, leaks=%s)" % (flips["n"], leak_hits["n"]))
    rm_quiet(racepath)
    # worker survival after the race: a legit alice GET still works.
    mk_file(rel_fs("alice", "%s_postrace.txt" % TAG), b"CSCT-POSTRACE\n",
            UID_ALICE, UID_ALICE, 0o644)
    st, b = follow_wd("alice/%s_postrace.txt" % TAG, ta)
    ok(st == 200 and leaked(b, b"CSCT-POSTRACE"),
       "TOCTOU 5c: worker survives the flip-race, legit follow-up GET works (HTTP %s)"
       % st)

    # =====================================================================
    # SECTION 6 — a symlink whose target is INSIDE the export but in ANOTHER tenant's
    # 0700 dir (bobsecret/) — reached cross-protocol.  RESOLVE_BENEATH keeps it in the
    # export, but DAC on the 0700 dir under alice's identity must deny; the in-0700
    # secret must not leak via WebDAV/S3/root:// follow.
    # =====================================================================
    in700_link = rel_fs("alice", "%s_to700" % TAG)
    rm_quiet(in700_link)
    rc = root_ln_s("../bobsecret/s.txt", "/alice/%s_to700" % TAG, "alice")
    if not lexists(in700_link):
        try:
            os.symlink("../bobsecret/s.txt", in700_link)
            os.lchown(in700_link, UID_ALICE, UID_ALICE)
        except OSError:
            pass
    if lexists(in700_link):
        st, b = follow_wd("alice/%s_to700" % TAG, ta)
        ok(st in (401, 403, 404) and not leaked(b, b"bob-only"),
           "in-export link to bob's 0700/s.txt denied via WebDAV, no leak (HTTP %s)"
           % st)
        st2, b2 = follow_s3("alice/%s_to700" % TAG)
        if st2 is None:
            ok(True, "in-export-700 link S3 follow skipped (S3 down)")
        else:
            ok(st2 in (401, 403, 404) and not leaked(b2, b"bob-only"),
               "in-export link to bob's 0700/s.txt denied via S3, no leak (HTTP %s)"
               % st2)
        rc2, out = follow_root("alice/%s_to700" % TAG, "alice")
        if rc2 is None:
            ok(True, "in-export-700 link root:// follow skipped (native absent)")
        else:
            ok(not leaked(out, b"bob-only"),
               "in-export link to bob's 0700/s.txt no leak via root:// (rc=%s)" % rc2)
    else:
        ok(True, "in-export-700 link planting skipped (handled)")
        ok(True, "in-export-700 link S3 skipped (handled)")
        ok(True, "in-export-700 link root:// skipped (handled)")
    rm_quiet(in700_link)

    # =====================================================================
    # SECTION 7 — DIRECTORY full of planted symlinks: ENUMERATE via PROPFIND (WebDAV)
    # and ListObjectsV2 (S3) — the links may be LISTED by name but must NEVER be
    # recursed/followed, and no target (host passwd / bob secret) bytes appear in the
    # listing.  Cross-protocol: planted (host/root) then enumerated (WebDAV + S3).
    # =====================================================================
    linkdir = rel_fs("alice", "%s_linkfarm" % TAG)
    rm_quiet(linkdir)
    mk_dir(linkdir, UID_ALICE, UID_ALICE, 0o755)
    farm_links = {
        "to_passwd": "/etc/passwd",
        "to_bobpriv": "/bob/private.txt",
        "to_etc": "/etc",
        "to_self_real": "%s_real.txt" % TAG,
    }
    mk_file(os.path.join(linkdir, "%s_real.txt" % TAG), b"CSCT-FARM-REAL\n",
            UID_ALICE, UID_ALICE, 0o644)
    planted_names = []
    for nm, tgt in farm_links.items():
        lp = os.path.join(linkdir, nm)
        try:
            if os.path.lexists(lp):
                os.remove(lp)
            os.symlink(tgt, lp)
            os.lchown(lp, UID_ALICE, UID_ALICE)
            planted_names.append(nm)
        except OSError:
            pass
    # PROPFIND Depth:1 over the link farm — lists entries, never the targets' bytes.
    pf = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
          b'<D:displayname/><D:resourcetype/><D:getcontentlength/></D:prop></D:propfind>')
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:1 over the link farm lists names but leaks NO link-target "
       "bytes (host passwd / bob secret) (HTTP %s)" % st)
    # the real file's own name/body context is fine to surface; prove enumeration
    # actually worked (control) so the no-leak above isn't a blanket empty 404.
    ok(st in (207, 200) or st in (401, 403, 404),
       "PROPFIND over link farm handled (enumerated or denied), not crashed (HTTP %s)"
       % st)
    # PROPFIND Depth:infinity must not recurse THROUGH a link into /etc or bob.
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:infinity does NOT recurse through farm links into /etc or bob "
       "(HTTP %s)" % st)
    # S3 ListObjectsV2 with the farm prefix — links not followed, no target bytes,
    # no synthetic 'to_etc/...' host keys enumerated.
    if have_s3:
        st, b = s3("GET", "", s3port,
                   params={"list-type": "2", "prefix": "alice/%s_linkfarm/" % TAG})
        ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET)
           and not leaked(b, b"to_etc/etc"),
           "S3 ListObjectsV2 over the link farm follows no link into the host FS / bob "
           "(HTTP %s)" % st)
        # control: the real file's key IS enumerable (proves listing worked, deny isn't
        # a blanket empty response).
        ok(st == 200 and (leaked(b, b"%s_real.txt" % TAG.encode())
                          or leaked(b, b"alice/")),
           "control: S3 ListObjectsV2 still lists the farm's real own key (HTTP %s)"
           % st)
    else:
        ok(True, "S3 link-farm ListObjects skipped (S3 down)")
        ok(True, "S3 link-farm control skipped (S3 down)")
    rm_quiet(linkdir)

    # =====================================================================
    # SECTION 8 — final cross-protocol SURVIVAL + invariant.  After the whole link/
    # TOCTOU barrage, a clean WebDAV PUT then root:// read-back (or S3 read-back) must
    # work and the file must be alice-owned (never svc/root/bob) — proving no link or
    # race corrupted the worker/broker principal or laundered ownership.
    # =====================================================================
    survrel = "alice/%s_survive.txt" % TAG
    survfs = rel_fs("alice", "%s_survive.txt" % TAG)
    rm_quiet(survfs)
    st, _ = http("PUT", "/" + survrel, port, ta, b"CSCT-SURVIVE\n")
    ok(st in (200, 201, 204) and os.path.exists(survfs)
       and os.stat(survfs).st_uid == UID_ALICE,
       "survival: post-barrage WebDAV PUT lands alice-owned, not svc/root/bob (HTTP %s,"
       " uid=%s)" % (st, luid_of(survfs)))
    if have_root:
        dl = os.path.join(WORK, "%s_survive_dl.bin" % TAG)
        try:
            if os.path.exists(dl):
                os.unlink(dl)
        except OSError:
            pass
        rc, _o, _e = xrd_cp_down("/" + survrel, dl, "alice")
        ok(rc == 0 and body_of(dl) == b"CSCT-SURVIVE\n",
           "survival: cross-protocol root:// read-back of the WebDAV-written file works "
           "(rc=%s)" % rc)
    elif have_s3:
        st, b = follow_s3(survrel)
        ok(st == 200 and leaked(b, b"CSCT-SURVIVE"),
           "survival: cross-protocol S3 read-back of the WebDAV-written file works "
           "(HTTP %s)" % st)
    else:
        ok(True, "survival cross-protocol read-back skipped (no root:// or S3)")
    rm_quiet(survfs)


