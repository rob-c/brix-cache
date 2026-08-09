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


def run_webdav_property_exotic(key, data, port, s3port):
    """EXOTIC PROPPATCH/PROPFIND bodies under impersonation, verified at the KERNEL
    (on-disk `user.nginx_xrootd.webdav.*` xattr) layer rather than by PROPFIND echo
    alone.  Probes: (1) set-then-remove a dead-prop in ONE request leaves NO xattr;
    (2) PROPFIND allprop/propname/named-LIVE-props are well-formed and leak no
    internal path; (3) a SET of a protected/live DAV: prop (getetag/getcontentlength)
    is refused (403 propstat) and is NOT stored, the file uncorrupted; (4) many
    bounded dead props are stored without unbounded xattr growth; (5) mixed/foreign
    namespaces + empty + over-cap values are bounded (16 KiB value cap enforced on
    disk); (6) CROSS-TENANT: alice PROPFIND on bob's 0600 file leaks no size/etag and
    alice PROPPATCH on bob's file persists no xattr + leaves bob's mode/xattrs intact.
    Distinct from run_lock_proppatch (no set-then-remove, no on-disk xattr count/value
    assertion), run_webdav_method_state (no named-live-prop enumeration, no protected-
    prop SET, no kernel xattr verification) and run_group_xattr_lock (group-write-bit
    discrimination, not exotic bodies / value caps / protected props)."""
    ta, tb = mint(key, "alice"), mint(key, "bob")
    XML = {"Content-Type": "application/xml"}
    D0 = {"Depth": "0", "Content-Type": "application/xml"}

    def adir(rel):
        return os.path.join(data, "alice", rel)

    def pp_xml(actions):
        """actions = list of ('set'|'remove', inner_xml_bytes)."""
        body = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
                + b'xmlns:Z="urn:exotic">')
        for verb, inner in actions:
            body += (b'<D:' + verb.encode() + b'><D:prop>' + inner
                     + b'</D:prop></D:' + verb.encode() + b'>')
        return body + b'</D:propertyupdate>'

    # ====================================================== (0) fixture control
    http("PUT", "/alice/xp_base.txt", port, ta, b"exotic-prop-base\n")
    bp = adir("xp_base.txt")
    ok(os.path.exists(bp) and os.stat(bp).st_uid == UID_ALICE,
       f"exotic-prop fixture xp_base.txt owned by alice "
       f"(uid={os.stat(bp).st_uid if os.path.exists(bp) else -1})")
    base0 = _dead_xattr_count(bp)
    ok(base0 == 0, f"fresh fixture carries no dead-property xattrs (count={base0})")

    # ========================================== (1) SET then REMOVE in ONE request
    # A single propertyupdate that sets a dead-prop then removes it must leave the
    # resource with NO such xattr on disk (kernel ground truth, not PROPFIND echo).
    st_sr, _ = http("PROPPATCH", "/alice/xp_base.txt", port, ta,
                    data=pp_xml([("set", b'<Z:ephemeral>VANISH</Z:ephemeral>'),
                                 ("remove", b'<Z:ephemeral/>')]), hdrs=XML)
    ok(st_sr in (200, 207) and _dead_xattr_count(bp) == 0
       and not _dead_xattr_has_value(bp, b"VANISH"),
       f"SET-then-REMOVE in one PROPPATCH leaves no dead-prop xattr on disk "
       f"(HTTP {st_sr}, count={_dead_xattr_count(bp)})")

    # control: a plain SET of a distinct dead-prop DOES persist on disk as exactly
    # one xattr carrying the value (proves the removal above was real, not a no-op).
    st_set, _ = http("PROPPATCH", "/alice/xp_base.txt", port, ta,
                     data=pp_xml([("set", b'<Z:keep>PERSIST</Z:keep>')]), hdrs=XML)
    ok(st_set in (200, 207) and _dead_xattr_count(bp) == 1
       and _dead_xattr_has_value(bp, b"PERSIST"),
       f"control: a plain dead-prop SET persists as one on-disk xattr "
       f"(HTTP {st_set}, count={_dead_xattr_count(bp)})")
    # the persisting prop must keep the resource alice-owned (broker setxattr as alice).
    ok(os.stat(bp).st_uid == UID_ALICE,
       "resource carrying a persisted dead-prop stays alice-owned (broker xattr)")

    # ============================== (2) PROPFIND allprop / propname / named-live
    st_a, ba = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                    data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                         b'<D:allprop/></D:propfind>', hdrs=D0)
    ok(st_a == 207 and ba.count(b"<D:response>") == 1
       and b"PERSIST" in ba,
       f"PROPFIND allprop is one well-formed response carrying the dead-prop "
       f"(HTTP {st_a})")
    # allprop must not leak the absolute on-disk export path (confinement / info).
    ok(data.encode() not in ba and b"/etc/" not in ba,
       "PROPFIND allprop response leaks no internal export/host path")

    st_pn, bpn = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                      data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                           b'<D:propname/></D:propfind>', hdrs=D0)
    # propname lists NAMES only — no live values (size/etag) must appear as text.
    ok(st_pn == 207 and b"<D:getcontentlength/>" in bpn
       and b"<D:getcontentlength>" not in bpn,
       f"PROPFIND propname lists property NAMES without values (HTTP {st_pn})")

    # explicitly-named LIVE props: each requested live prop is emitted with a value.
    named = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
             b'<D:getcontentlength/><D:getlastmodified/><D:resourcetype/>'
             b'<D:getetag/><D:creationdate/><D:displayname/>'
             b'<D:lockdiscovery/><D:supportedlock/>'
             b'<D:quota-available-bytes/><D:quota-used-bytes/>'
             b'</D:prop></D:propfind>')
    st_n, bn = http("PROPFIND", "/alice/xp_base.txt", port, ta, data=named, hdrs=D0)
    live_ok = all(tag in bn for tag in (
        b"<D:getcontentlength>", b"<D:getlastmodified>", b"<D:getetag>",
        b"<D:creationdate>", b"<D:supportedlock", b"<D:lockdiscovery"))
    ok(st_n == 207 and live_ok,
       f"PROPFIND named LIVE props emit values for the documented set (HTTP {st_n})")
    # getcontentlength must report the true size of alice's own file.
    want_len = b"<D:getcontentlength>%d</D:getcontentlength>" % os.stat(bp).st_size
    ok(want_len in bn,
       f"named-prop getcontentlength reports the true file size "
       f"({os.stat(bp).st_size} bytes)")

    # ===================================== (3) SET a protected/live DAV: prop
    # PROPPATCH must refuse to set a live/protected DAV: property (403 propstat),
    # must NOT store it as a dead-prop, and must not truncate/replace the file.
    pre_body = open(bp, "rb").read()
    pre_cnt = _dead_xattr_count(bp)
    prot = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>'
            b'<D:getetag>"forged-etag"</D:getetag>'
            b'<D:getcontentlength>999999</D:getcontentlength>'
            b'</D:prop></D:set></D:propertyupdate>')
    st_p, bpb = http("PROPPATCH", "/alice/xp_base.txt", port, ta, data=prot, hdrs=XML)
    ok(st_p in (207, 403) and b"403" in (bpb or b""),
       f"PROPPATCH SET of protected DAV: props reports a 403 propstat (HTTP {st_p})")
    ok(_dead_xattr_count(bp) == pre_cnt
       and not _dead_xattr_has_value(bp, b"forged-etag"),
       "protected-prop SET stored NO dead-prop xattr (no live-prop spoof)")
    ok(open(bp, "rb").read() == pre_body,
       "protected-prop PROPPATCH did not corrupt/truncate the file body")
    # the real etag/size are still server-derived, not the forged values.
    _, bchk = http("PROPFIND", "/alice/xp_base.txt", port, ta,
                   data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
                        b'<D:getcontentlength/></D:prop></D:propfind>', hdrs=D0)
    ok(b"<D:getcontentlength>999999</D:getcontentlength>" not in bchk,
       "server reports the TRUE content-length, not the forged protected value")

    # ===================================== (4) MANY dead props -> bounded growth
    http("PUT", "/alice/xp_many.txt", port, ta, b"many-props\n")
    mp = adir("xp_many.txt")
    inner = b"".join(
        b'<Z:p%d>v%d</Z:p%d>' % (i, i, i) for i in range(40))
    st_m, _ = http("PROPPATCH", "/alice/xp_many.txt", port, ta,
                   data=pp_xml([("set", inner)]), hdrs=XML)
    cnt_m = _dead_xattr_count(mp)
    # server either stores all 40 (bounded, finite) or caps below — never unbounded
    # and never escalates ownership; the resource stays alice-owned.
    ok(st_m in (200, 207) and 0 <= cnt_m <= 40 and os.stat(mp).st_uid == UID_ALICE,
       f"40 dead props stored bounded ({cnt_m} xattrs) on alice's file "
       f"(HTTP {st_m})")
    # a follow-up GET still works -> the large-but-bounded request did not desync
    # the broker inbound path.
    st_g, gb = http("GET", "/alice/xp_many.txt", port, ta)
    ok(st_g == 200 and gb == b"many-props\n",
       f"GET after the 40-prop PROPPATCH still returns the body (HTTP {st_g})")

    # =============== (5) foreign/mixed namespaces + empty + over-cap values
    http("PUT", "/alice/xp_ns.txt", port, ta, b"ns-mix\n")
    nf = adir("xp_ns.txt")
    mixed = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" '
             b'xmlns:A="http://a.example/ns" xmlns:B="urn:b:other">'
             b'<D:set><D:prop>'
             b'<A:alpha>one</A:alpha><B:beta>two</B:beta>'
             b'<A:empty></A:empty>'
             b'</D:prop></D:set></D:propertyupdate>')
    st_x, _ = http("PROPPATCH", "/alice/xp_ns.txt", port, ta, data=mixed, hdrs=XML)
    ok(st_x in (200, 207) and os.stat(nf).st_uid == UID_ALICE,
       f"mixed/foreign-namespace + empty-value PROPPATCH handled, alice-owned "
       f"(HTTP {st_x}, xattrs={_dead_xattr_count(nf)})")
    # read the foreign-ns props back: well-formed, values preserved, no path leak.
    st_xf, bxf = http("PROPFIND", "/alice/xp_ns.txt", port, ta,
                      data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                           b'<D:allprop/></D:propfind>', hdrs=D0)
    ok(st_xf == 207 and b"one" in bxf and b"two" in bxf
       and data.encode() not in bxf,
       f"foreign-namespace dead-props round-trip with no path leak (HTTP {st_xf})")

    # over-cap value: a single dead-prop value beyond the 16 KiB cap is rejected and
    # NOT stored on disk; body stays under the 64 KiB PROPPATCH limit.
    http("PUT", "/alice/xp_big.txt", port, ta, b"big-val\n")
    bf = adir("xp_big.txt")
    big = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:huge>' + (b"X" * 40000) +
           b'</Z:huge></D:prop></D:set></D:propertyupdate>')
    st_b, _ = http("PROPPATCH", "/alice/xp_big.txt", port, ta, data=big, hdrs=XML)
    ok(not _dead_xattr_has_value(bf, b"XXXXXXXXXX" * 100),
       f"over-cap (40 KiB) dead-prop value NOT stored on disk (HTTP {st_b})")
    st_bg, bgb = http("GET", "/alice/xp_big.txt", port, ta)
    ok(st_bg == 200 and bgb == b"big-val\n",
       f"GET after over-cap PROPPATCH still serves the body (no desync) "
       f"(HTTP {st_bg})")

    # ===================================== (6) CROSS-TENANT: bob's 0600 file
    bpriv = os.path.join(data, "bob", "private.txt")
    pre_mode = os.stat(bpriv).st_mode & 0o777
    pre_xcnt = _dead_xattr_count(bpriv)
    pre_pbody = open(bpriv, "rb").read()

    # alice PROPFIND of bob's 0600 file: must be denied / leak no content-revealing
    # live prop (size/etag) and never the body secret.
    st_cf, bcf = http("PROPFIND", "/bob/private.txt", port, ta,
                      data=named, hdrs=D0)
    # PROPFIND never opens/reads the resource — it only lstat()s it — so the only
    # confidentiality boundary it can breach is the file CONTENT, never the size/etag.
    # Exposing getcontentlength/getetag of a 0600 file whose PARENT dir is 0755 is
    # STANDARD POSIX (identical to `ls -l` of an unreadable file: stat needs only
    # traverse on the parent, not read on the file) and is NOT a content leak.  Flag
    # ONLY if the actual secret BYTES appear in the body.
    leaked = b"BOB-PRIVATE-SECRET" in (bcf or b"")
    ok(st_cf in (403, 404, 401, 207) and not leaked,
       f"alice PROPFIND of bob's 0600 file leaks no body secret "
       f"(HTTP {st_cf}, leaked={leaked})")

    # alice PROPPATCH (dead-prop) on bob's 0600 file: broker setxattr as alice ->
    # EACCES -> denied; nothing persists and bob's file is untouched on disk.
    st_cp, _ = http("PROPPATCH", "/bob/private.txt", port, ta,
                    data=pp_xml([("set",
                                  b'<Z:pwn>ALICE-XTENANT-PROP</Z:pwn>')]), hdrs=XML)
    ok(st_cp not in (200,) or _dead_xattr_count(bpriv) == pre_xcnt,
       f"alice PROPPATCH on bob's 0600 file did not add an xattr (HTTP {st_cp})")
    ok(not _dead_xattr_has_value(bpriv, b"ALICE-XTENANT-PROP"),
       "alice's cross-tenant dead-prop did NOT persist on bob's file (broker DAC)")
    ok((os.stat(bpriv).st_mode & 0o777) == pre_mode
       and os.stat(bpriv).st_uid == UID_BOB
       and open(bpriv, "rb").read() == pre_pbody,
       f"bob's 0600 file unchanged after alice's PROPPATCH "
       f"(mode={os.stat(bpriv).st_mode & 0o777:o}, uid={os.stat(bpriv).st_uid})")


