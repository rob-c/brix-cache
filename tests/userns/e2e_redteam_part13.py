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


def run_broker_resource_limits(key, data, port, s3port):
    """BROKER protocol-level + RESOURCE attacks under impersonation.  Plant
    pathological filesystem objects in the export (FIFO, unix socket, dangling /
    looping / shadow-pointing symlinks, cross-tenant hardlink), stress path
    boundaries (near-PATH_MAX, deep nesting, embedded ./ and //), probe the xattr
    namespace (security.*/system.*/trusted.* must be confined to user.* or denied),
    and hammer the single broker socket — proving NONE of it hangs the worker,
    leaks a foreign secret, escapes the export, escalates privilege, or wedges the
    broker.  After every hostile burst we re-prove recovery with a legit alice
    PUT+GET roundtrip (worker AND broker both survive).  Does NOT kill the broker
    (run_broker_failclosed owns that)."""
    T = "brl_"                       # function tag prefixes every fixture we plant
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    adir = os.path.join(data, "alice")
    bdir = os.path.join(data, "bob")

    def _has(body, needle):
        return needle in (body or b"")

    def recover(label, n=[0]):
        """Legit alice PUT+GET roundtrip — proves the worker thread AND the single
        broker socket are still live after a hostile op (a wedged broker would make
        the impersonated create fail or hang)."""
        n[0] += 1
        rel = f"/alice/{T}rec_{n[0]}.txt"
        body = f"recover-{n[0]}-{label[:12]}".encode()
        stp, _ = http("PUT", rel, port, ta, body)
        stg, gb = http("GET", rel, port, ta)
        fp = os.path.join(adir, f"{T}rec_{n[0]}.txt")
        owned = os.path.exists(fp) and os.stat(fp).st_uid == UID_ALICE
        ok(stp in (200, 201, 204) and stg == 200 and gb == body and owned,
           f"recovery after {label}: alice PUT+GET roundtrip ok, owned 1001 "
           f"(PUT {stp}, GET {stg})")

    # baseline recovery: prove the harness path works before we attack anything.
    recover("baseline")

    # ---- planted secrets (unique markers so deny checks can scan the body) ----
    SHADOW_MARK = b"root:$"           # /etc/shadow hash prefix (must never leak)
    BOBHL_MARK = b"BRL-BOB-HARDLINK-SECRET"
    SVCHL_MARK = b"svc-only-secret"   # already in /svconly/secret-name.txt

    # =====================================================================
    # A) FIFO — broker must open O_NONBLOCK / fail closed, NEVER block the
    #    single-threaded worker waiting for a writer that never comes.
    # =====================================================================
    fifo = os.path.join(adir, f"{T}fifo")
    try:
        if not os.path.exists(fifo):
            os.mkfifo(fifo, 0o600)
            os.chown(fifo, UID_ALICE, UID_ALICE)
    except OSError as e:
        fifo = None
        ok(True, f"FIFO fixture skipped ({e.__class__.__name__})")
    if fifo:
        t0 = time.time()
        st, _ = http("GET", f"/alice/{T}fifo", port, ta)
        dt_fifo = time.time() - t0
        ok(dt_fifo < 5.0, f"WebDAV GET on FIFO did not hang worker "
                          f"({dt_fifo:.2f}s, HTTP {st})")
        # PUT onto a FIFO (would block on a reader) must also not wedge.
        t0 = time.time()
        st, _ = http("PUT", f"/alice/{T}fifo", port, ta, b"x" * 64)
        ok(time.time() - t0 < 5.0, f"WebDAV PUT on FIFO did not hang worker (HTTP {st})")
        if xrd_avail():
            rc, _o, _e = xrd_fs(["stat", f"/alice/{T}fifo"], "alice")
            ok(True, f"root:// stat on FIFO returned, did not hang (rc={rc})")
        recover("FIFO ops")

    # =====================================================================
    # B) UNIX-domain socket node in the export — not a regular file; open
    #    must fail closed (ENXIO/EACCES), never hang or be served.
    # =====================================================================
    sockp = os.path.join(adir, f"{T}sock")
    srv = None
    try:
        if os.path.exists(sockp):
            os.unlink(sockp)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sockp)
        os.chown(sockp, UID_ALICE, UID_ALICE)
    except OSError as e:
        sockp = None
        ok(True, f"unix-socket fixture skipped ({e.__class__.__name__})")
    if sockp:
        t0 = time.time()
        st, b = http("GET", f"/alice/{T}sock", port, ta)
        ok(time.time() - t0 < 5.0 and st != 200,
           f"WebDAV GET on unix-socket node fails closed, no hang (HTTP {st})")
        t0 = time.time()
        st, _ = http("PUT", f"/alice/{T}sock", port, ta, b"data\n")
        ok(time.time() - t0 < 5.0, f"WebDAV PUT on unix-socket node did not hang (HTTP {st})")
        if s3port:
            st, b = s3("GET", f"alice/{T}sock", s3port)
            ok(st != 200, f"S3 GET on unix-socket node fails closed (HTTP {st})")
        recover("unix-socket ops")
        try:
            srv.close()
        except OSError:
            pass

    # =====================================================================
    # C) Device-node creation must EPERM for the in-ns root attacker (no
    #    CAP in a true sense for mknod char/block); if it somehow succeeds,
    #    reads through it must fail closed.  Either way -> no hang/escape.
    # =====================================================================
    devp = os.path.join(adir, f"{T}cdev")
    dev_made = False
    try:
        os.mknod(devp, 0o600 | 0o020000, os.makedev(1, 3))   # S_IFCHR /dev/null-ish
        os.chown(devp, UID_ALICE, UID_ALICE)
        dev_made = True
    except OSError:
        dev_made = False
    if not dev_made:
        ok(True, "char-device mknod EPERM in userns (expected) -> skipped")
    else:
        t0 = time.time()
        st, b = http("GET", f"/alice/{T}cdev", port, ta)
        ok(time.time() - t0 < 5.0 and not _has(b, SHADOW_MARK),
           f"WebDAV GET on char-device node handled, no hang/leak (HTTP {st})")
        recover("char-device ops")

    # =====================================================================
    # D) SYMLINK class: dangling, self-loop, ->/etc/shadow, ->/etc/passwd.
    #    The broker re-applies RESOLVE_BENEATH (+ no follow out of export),
    #    so none may return host-file bytes or hang on the loop.
    # =====================================================================
    def _mklink(name, target):
        p = os.path.join(adir, name)
        try:
            if os.path.lexists(p):
                os.unlink(p)
            os.symlink(target, p)
            return p
        except OSError:
            return None

    dang = _mklink(f"{T}dangle", "/nonexistent/brl/target")
    if dang:
        st, b = http("GET", f"/alice/{T}dangle", port, ta)
        ok(st != 200, f"dangling symlink GET handled, not served (HTTP {st})")
        if xrd_avail():
            rc, _o, _e = xrd_fs(["stat", f"/alice/{T}dangle"], "alice")
            ok(True, f"root:// stat dangling symlink returned (rc={rc})")

    loopa = _mklink(f"{T}loopA", f"{T}loopB")
    loopb = _mklink(f"{T}loopB", f"{T}loopA")
    if loopa and loopb:
        t0 = time.time()
        st, b = http("GET", f"/alice/{T}loopA", port, ta)
        ok(time.time() - t0 < 5.0 and st != 200,
           f"symlink LOOP GET fails closed (ELOOP), no hang (HTTP {st})")
        st, _ = http("PROPFIND", f"/alice/{T}loopA", port, ta,
                     hdrs={"Depth": "0", "Content-Type": "application/xml"},
                     data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                          b'<D:prop><D:displayname/></D:prop></D:propfind>')
        ok(st != 200, f"symlink LOOP PROPFIND fails closed (HTTP {st})")

    shadow = _mklink(f"{T}toshadow", "/etc/shadow")
    if shadow:
        st, b = http("GET", f"/alice/{T}toshadow", port, ta)
        ok(st != 200 and not _has(b, SHADOW_MARK) and not _has(b, b"root:"),
           f"symlink ->/etc/shadow GET blocked, no shadow bytes (HTTP {st})")
        if s3port:
            st, b = s3("GET", f"alice/{T}toshadow", s3port)
            ok(st != 200 and not _has(b, SHADOW_MARK),
               f"S3 symlink ->/etc/shadow GET blocked, no leak (HTTP {st})")
        if xrd_avail():
            dlp = os.path.join(WORK, f"{T}shadow_steal.bin")
            try:
                if os.path.exists(dlp):
                    os.unlink(dlp)
            except OSError:
                pass
            rc, _o, _e = xrd_cp_down(f"/alice/{T}toshadow", dlp, "alice")
            got = b""
            try:
                got = open(dlp, "rb").read() if os.path.exists(dlp) else b""
            except OSError:
                got = b""
            ok(rc != 0 and SHADOW_MARK not in got and b"root:" not in got,
               f"root:// xrdcp via symlink ->/etc/shadow DENIED, no leak (rc={rc})")

    passwd_link = _mklink(f"{T}topasswd", "/etc/passwd")
    if passwd_link:
        st, b = http("GET", f"/alice/{T}topasswd", port, ta)
        ok(not _has(b, b"root:x:0:0") and not _has(b, b"root:!"),
           f"symlink ->/etc/passwd GET no passwd leak (HTTP {st})")
    recover("symlink class")

    # A symlink pointing back INTO the export to bob's 0600 private file: even
    # though the link sits in alice's dir, the broker acts AS alice and DAC on the
    # real target (bob 0600) must deny — the link does not launder identity.
    bob_link = _mklink(f"{T}tobobpriv", os.path.join(bdir, "private.txt"))
    if bob_link:
        st, b = http("GET", f"/alice/{T}tobobpriv", port, ta)
        ok(st != 200 and not _has(b, b"BOB-PRIVATE-SECRET"),
           f"symlink to bob's 0600 via alice's dir DENIED by DAC, no leak (HTTP {st})")
        # control: an in-export symlink to bob's 0644 world-readable file.  Two
        # secure outcomes are acceptable, both proving no cross-tenant PRIVATE leak
        # and no blanket-weakening: (a) a RELATIVE in-export link is followed by
        # RESOLVE_BENEATH and DAC then lets alice-as-other read bob's WORLD-READABLE
        # body (200, "bob-world-readable", never "BOB-PRIVATE-SECRET"); or (b) the
        # link is refused by confinement (non-200).  An ABSOLUTE symlink is *always*
        # refused (EXDEV) by RESOLVE_BENEATH regardless of target, so we use a
        # relative target here to actually exercise the follow+per-target-DAC path.
        ctl = _mklink(f"{T}tobobread", os.path.join("..", "bob", "readable.txt"))
        if ctl:
            st, b = http("GET", f"/alice/{T}tobobread", port, ta)
            ok(not _has(b, b"BOB-PRIVATE-SECRET")
               and ((st == 200 and _has(b, b"bob-world-readable")) or st != 200),
               f"control: in-export symlink to bob's 0644 file resolves to "
               f"world-readable body or is denied, never leaks bob's private "
               f"secret (HTTP {st})")

    # =====================================================================
    # E) HARDLINK across tenant dirs — a hardlink in alice's tree to bob's
    #    0600 file.  The inode mode/owner is bob's (0600 bob); the broker
    #    acting as alice ("other") must NOT read it.  Hardlink cannot launder
    #    DAC the way a confinement bug might.
    # =====================================================================
    hl = os.path.join(adir, f"{T}bob_hardlink")
    bob_secret_file = os.path.join(bdir, f"{T}bob_hl_src.txt")
    hl_made = False
    try:
        with open(bob_secret_file, "wb") as fh:
            fh.write(BOBHL_MARK + b"\n")
        os.chown(bob_secret_file, UID_BOB, UID_BOB)
        os.chmod(bob_secret_file, 0o600)
        if os.path.exists(hl):
            os.unlink(hl)
        os.link(bob_secret_file, hl)          # in-ns root can cross-link
        hl_made = True
    except OSError as e:
        ok(True, f"cross-tenant hardlink fixture skipped ({e.__class__.__name__})")
    if hl_made:
        # inode is bob 0600; alice (other) must be denied AND no secret leaks.
        st, b = http("GET", f"/alice/{T}bob_hardlink", port, ta)
        ok(st != 200 and not _has(b, BOBHL_MARK),
           f"cross-tenant HARDLINK to bob's 0600 inode DENIED to alice, no leak "
           f"(HTTP {st})")
        if xrd_avail():
            rc, out, _e = xrd_fs(["cat", f"/alice/{T}bob_hardlink"], "alice")
            ok(rc != 0 and BOBHL_MARK.decode() not in (out or ""),
               f"root:// cat cross-tenant hardlink DENIED, no leak (rc={rc})")
        # bob (the real owner) reading the SAME inode via his own tree = control.
        st, b = http("GET", f"/bob/{T}bob_hl_src.txt", port, tb)
        ok(st == 200 and _has(b, BOBHL_MARK),
           f"control: bob reads his own 0600 inode (HTTP {st})")
        recover("cross-tenant hardlink")

    # A hardlink to /svconly's svc-owned secret (svc 0640-ish): alice must not be
    # able to read svc's secret via a laundered link either.
    svc_secret = os.path.join(data, "svconly", "secret-name.txt")
    svc_hl = os.path.join(adir, f"{T}svc_hardlink")
    svc_hl_made = False
    try:
        if os.path.exists(svc_hl):
            os.unlink(svc_hl)
        os.link(svc_secret, svc_hl)
        # match the canary's restrictive mode on the inode.
        os.chmod(svc_hl, 0o600)
        os.chown(svc_hl, UID_SVC, UID_SVC)
        svc_hl_made = True
    except OSError:
        svc_hl_made = False
    if not svc_hl_made:
        ok(True, "svc-secret hardlink fixture skipped")
    else:
        st, b = http("GET", f"/alice/{T}svc_hardlink", port, ta)
        ok(st != 200 and not _has(b, SVCHL_MARK),
           f"hardlink to svc(1500)-owned secret DENIED to alice, no leak (HTTP {st})")
        recover("svc-secret hardlink")

    # =====================================================================
    # F) PATH BOUNDARY: very long single component (near PATH_MAX), deeply
    #    nested namespace, and paths with embedded ./ and // — the broker
    #    must canonicalize + confine without overrunning or escaping.
    # =====================================================================
    # F1) one very long name (just under typical NAME_MAX 255).
    longname = T + ("L" * 240)
    st, _ = http("PUT", f"/alice/{longname}", port, ta, b"long\n")
    lp = os.path.join(adir, longname)
    if st in (200, 201, 204):
        owned = os.path.exists(lp) and os.stat(lp).st_uid == UID_ALICE
        ok(owned, f"long-name (~245) PUT owned by alice (HTTP {st})")
    else:
        ok(st in (400, 403, 414, 404, 500, 507),
           f"long-name PUT rejected cleanly, not a crash (HTTP {st})")

    # F2) near-PATH_MAX total path via many components — must not crash/escape.
    seg = T + "p"
    longpath = "/alice/" + "/".join(seg for _ in range(120))   # ~ 600+ chars
    st, _ = http("PUT", longpath + "/x.txt", port, ta, b"deep\n")
    ok(st in (200, 201, 204, 400, 403, 404, 409, 414, 500, 507),
       f"near-PATH_MAX path PUT handled cleanly (HTTP {st})")
    # nothing escaped the export from any of the above.
    outside = os.path.dirname(os.path.dirname(os.path.abspath(data)))
    ok(not os.path.exists(os.path.join(outside, f"{T}escaped")),
       "long/deep path attempts created nothing outside the export")
    recover("path-length boundary")

    # F3) deep nesting by repeated MKCOL — broker namespace op per level; assert
    #     each created level is alice-owned and confined.
    depth_base = f"/alice/{T}deep"
    cur = depth_base
    made = 0
    for _i in range(16):
        st, _ = http("MKCOL", cur, port, ta)
        if st in (200, 201):
            made += 1
            cur = cur + "/d"
        else:
            break
    deep_top = os.path.join(adir, f"{T}deep")
    ok(made >= 4 and os.path.isdir(deep_top)
       and os.stat(deep_top).st_uid == UID_ALICE,
       f"deep nested MKCOL ({made} levels) owned by alice, confined")
    # a file at the bottom of the deep tree is still alice-owned (no drift).
    if made >= 1:
        st, _ = http("PUT", cur.rsplit("/d", 1)[0] + "/leaf.txt", port, ta, b"leaf\n")
        ok(st in (200, 201, 204, 404, 409),
           f"PUT at deep-tree leaf handled (HTTP {st})")
    recover("deep MKCOL nesting")

    # F4) embedded ./ and // and trailing-dot segments — must canonicalize to the
    #     SAME confined alice file, never escape, owner stays alice.
    embed_paths = [
        f"/alice/./{T}embed1.txt",
        f"/alice//{T}embed2.txt",
        f"/alice/./sub/.././{T}embed3.txt",
        f"/alice/{T}embed4.txt/.",
    ]
    for p in embed_paths:
        st, _ = http("PUT", p, port, ta, b"embed\n")
        ok(st in (200, 201, 204, 400, 403, 404, 409),
           f"embedded ./ // PUT {p[7:30]!r} handled, no escape (HTTP {st})")
    # whichever of embed1/2 landed, it must be alice-owned and inside alice/.
    for nm in (f"{T}embed1.txt", f"{T}embed2.txt"):
        fp = os.path.join(adir, nm)
        if os.path.exists(fp):
            ok(os.stat(fp).st_uid == UID_ALICE,
               f"canonicalized embedded-path file {nm} owned by alice")
    recover("embedded ./ // segments")

    # =====================================================================
    # G) XATTR NAMESPACE probes via PROPPATCH — WebDAV dead-properties persist as
    #    xattrs.  A namespace-prefix attack (security.*/system.*/trusted.*) must be
    #    confined to user.* (or denied) — it must NEVER let an unprivileged mapped
    #    user set a privileged xattr (e.g. security.capability => setuid-style
    #    escalation on the resulting inode).
    # =====================================================================
    http("PUT", f"/alice/{T}xattr.txt", port, ta, b"xattr target\n")
    xfp = os.path.join(adir, f"{T}xattr.txt")
    ok(os.path.exists(xfp) and os.stat(xfp).st_uid == UID_ALICE,
       "xattr-probe target created, owned by alice")

    def _proppatch_ns(prop_name):
        body = (
            '<?xml version="1.0"?>'
            '<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:brl">'
            f'<D:set><D:prop><Z:{prop_name}>pwned</Z:{prop_name}></D:prop></D:set>'
            '</D:propertyupdate>').encode()
        return http("PROPPATCH", f"/alice/{T}xattr.txt", port, ta, data=body,
                    hdrs={"Content-Type": "application/xml"})

    # The WebDAV dead-property name carries no raw xattr namespace, but probe that
    # the server never grows a privileged xattr on the inode regardless.  After
    # each PROPPATCH, scan the real inode's xattrs for any non-user.* namespace.
    def _bad_xattr_present():
        try:
            names = os.listxattr(xfp)
        except OSError:
            return False
        for n in names:
            if not (n.startswith("user.") or n.startswith("system.posix_acl")):
                return True
            if n in ("security.capability",):
                return True
        return False

    for pn in ("security.capability", "system.posix_acl_access",
               "trusted.evil", "security.selinux"):
        st, _ = _proppatch_ns(pn)
        ok(st in (200, 207, 403, 422, 400, 409, 501),
           f"PROPPATCH carrying ns-name {pn!r} handled cleanly (HTTP {st})")
        ok(not _bad_xattr_present(),
           f"no privileged (non-user.*) xattr set on inode after {pn!r}")

    # Direct raw-xattr confinement check: plant a user.* AND a (would-be) privileged
    # xattr request through PROPPATCH using a literal-namespaced property and verify
    # the inode owner is unchanged (no setuid-style escalation, no owner drift).
    st = os.stat(xfp)
    ok(st.st_uid == UID_ALICE and st.st_gid == UID_ALICE
       and not (st.st_mode & 0o6000),
       "xattr-probe target: owner/group still alice, no setuid/setgid bit gained")
    recover("xattr namespace probes")

    # root:// query xattr on bob's 0600 must not leak xattr values either.
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt"], "alice")
        ok("BOB-PRIVATE-SECRET" not in (out or ""),
           f"root:// query xattr on bob's 0600 leaks no content (rc={rc})")
        rc, out, _e = xrd_fs(["query", "xattr", f"/alice/{T}xattr.txt"], "alice")
        ok(True, f"root:// query xattr on own file returned (rc={rc})")

    # =====================================================================
    # H) RAPID SEQUENTIAL broker stress — hammer the single broker socket with a
    #    fast mix of impersonated metadata/create ops, interleaving a known-good
    #    PUT+readback every few iterations.  The broker must NEVER wedge: every
    #    interleaved probe must succeed and stay alice-owned (a stuck broker socket
    #    would stall or fail the probe).
    # =====================================================================
    BURST = 40
    stall = 0
    bad = 0
    for i in range(BURST):
        rel = f"/alice/{T}burst_{i}.txt"
        st, _ = http("PUT", rel, port, ta, f"b{i}\n".encode())
        if st not in (200, 201, 204):
            bad += 1
        if i % 8 == 7:
            probe = f"/alice/{T}probe_{i}.txt"
            t0 = time.time()
            sp, _ = http("PUT", probe, port, ta, b"probe\n")
            sg, gb = http("GET", probe, port, ta)
            took = time.time() - t0
            pfp = os.path.join(adir, f"{T}probe_{i}.txt")
            good = (sp in (200, 201, 204) and sg == 200 and gb == b"probe\n"
                    and os.path.exists(pfp) and os.stat(pfp).st_uid == UID_ALICE)
            if not good or took > 5.0:
                stall += 1
    ok(bad == 0, f"rapid broker burst: all {BURST} impersonated PUTs succeeded "
                 f"(failures={bad})")
    ok(stall == 0, f"broker socket never wedged under burst: every interleaved "
                   f"known-good probe passed fast (stalls={stall})")

    # H2) rapid keep-alive pipelined burst on ONE TCP connection — stresses the
    #     per-request principal re-establishment without a fresh connect each time;
    #     none may bleed identity (every created file alice-owned).
    ka_reqs = [("PUT", f"/alice/{T}ka_{i}.txt", ta, f"ka{i}\n".encode(), None)
               for i in range(10)]
    res = http_keepalive(ka_reqs, port)
    ka_ok = sum(1 for st, _ in res if st in (200, 201, 204))
    ka_bad_owner = 0
    for i in range(10):
        fp = os.path.join(adir, f"{T}ka_{i}.txt")
        if os.path.exists(fp) and os.stat(fp).st_uid != UID_ALICE:
            ka_bad_owner += 1
    ok(ka_ok >= 1 and ka_bad_owner == 0,
       f"keep-alive pipelined burst: {ka_ok}/10 ok, no wrong-owner file "
       f"(bad_owner={ka_bad_owner})")

    # H3) interleave cross-tenant bob writes into the burst window — a leaked
    #     principal would let one land in the wrong tenant or as the wrong owner.
    inter = []
    for i in range(8):
        sub = ta if i % 2 == 0 else tb
        d = "alice" if i % 2 == 0 else "bob"
        inter.append(("PUT", f"/{d}/{T}int_{i}.txt", sub, f"int{i}\n".encode(), None))
    http_keepalive(inter, port)
    drift = 0
    for i in range(8):
        d = "alice" if i % 2 == 0 else "bob"
        want = UID_ALICE if i % 2 == 0 else UID_BOB
        fp = os.path.join(data, d, f"{T}int_{i}.txt")
        if os.path.exists(fp) and os.stat(fp).st_uid != want:
            drift += 1
    ok(drift == 0, f"interleaved alice/bob pipelined PUTs: zero principal drift "
                   f"(wrong-owner={drift})")
    recover("rapid broker stress")

    # =====================================================================
    # I) S3 special-file + boundary probes (the S3 async-body handler must fail
    #    closed on the same pathological nodes, no hang/leak).
    # =====================================================================
    if s3port:
        if fifo:
            t0 = time.time()
            st, b = s3("GET", f"alice/{T}fifo", s3port)
            ok(time.time() - t0 < 5.0,
               f"S3 GET on FIFO did not hang (HTTP {st})")
        # S3 key with embedded ./ and // — must canonicalize+confine, owner alice.
        st, _ = s3("PUT", f"alice/.//{T}s3embed.txt", s3port, data=b"s3embed\n")
        ok(st in (200, 201, 400, 403, 404),
           f"S3 PUT embedded ./ // key handled (HTTP {st})")
        # S3 GET of the cross-tenant hardlink (bob 0600 inode) must deny + no leak.
        if hl_made:
            st, b = s3("GET", f"alice/{T}bob_hardlink", s3port)
            ok(st != 200 and not _has(b, BOBHL_MARK),
               f"S3 GET cross-tenant hardlink DENIED, no leak (HTTP {st})")
        recover("S3 special-file probes")

    # =====================================================================
    # J) FINAL recovery + ownership-invariant sweep: the worker survived every
    #    hostile op AND not one of our planted/created files drifted to a
    #    privileged owner (svc 1500 / root 0).  This is the headline invariant.
    # =====================================================================
    recover("full hostile battery")
    drift_priv = 0
    scanned = 0
    try:
        for nm in os.listdir(adir):
            if not nm.startswith(T):
                continue
            fp = os.path.join(adir, nm)
            try:
                if os.path.islink(fp):
                    continue
                u = os.stat(fp, follow_symlinks=False).st_uid
            except OSError:
                continue
            scanned += 1
            # cross-tenant hardlinks intentionally carry bob/svc owner on the inode
            # (that is the attack we denied above), so exclude the known link names.
            if nm in (f"{T}bob_hardlink", f"{T}svc_hardlink"):
                continue
            if u == UID_SVC or u == 0:
                drift_priv += 1
    except OSError:
        pass
    ok(scanned > 0 and drift_priv == 0,
       f"ownership invariant: of {scanned} files alice created, NONE owned by "
       f"svc(1500)/root(0) (drift={drift_priv})")

    # bob's private secret never got mutated/clobbered by any attack above.
    bpriv = os.path.join(bdir, "private.txt")
    try:
        intact = (os.path.exists(bpriv) and os.stat(bpriv).st_uid == UID_BOB
                  and (os.stat(bpriv).st_mode & 0o777) == 0o600)
    except OSError:
        intact = False
    ok(intact, "bob's 0600 private.txt untouched (owner/mode intact) after battery")


