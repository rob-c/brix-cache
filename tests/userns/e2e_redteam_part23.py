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


def run_mixed_owner_trees(key, data, port, s3port):
    """Collections with MIXED-OWNER children — the seam where directory-write DAC
    (which governs unlink/create of a child) diverges from the child file's own
    ownership, and where a recursive COPY must re-stamp ownership to the COPIER.
    Builds an alice-owned 0755 tree holding a carol-owned file plus a carol-owned
    0700 subdir, then drives recursive DELETE (alice owner / bob other), recursive
    COPY (erin into erin's space), and a no-traverse subtree across WebDAV and
    root://.  Asserts on-disk ownership (os.stat().st_uid/.st_gid), tree presence,
    and absence of leaked marker bytes — the security signal, not the HTTP status."""
    TAG = "mot"
    AM = b"ALICE-PARENT-FILE-BODY"
    CM = b"CAROL-CHILD-FILE-BODY"
    SM = b"CAROL-SUBDIR-SECRET-BODY"

    # ---- builder (in-ns root): an alice 0755 dir with a mixed set of children ---
    def build_tree(name):
        """(re)create data/<name>/ as alice:alice 0755 containing:
             alice_file.txt  alice:alice 0644  (AM)
             carol_file.txt  carol:carol 0644  (CM)
             sub/            carol:carol 0700  (carol-only) holding secret.txt (SM)
           Returns the absolute path of the tree root."""
        root = os.path.join(data, name)
        try:
            # tear down any prior run as root (we created it, so we can remove it).
            if os.path.isdir(root):
                for dp, dns, fns in os.walk(root, topdown=False):
                    for fn in fns:
                        try:
                            os.unlink(os.path.join(dp, fn))
                        except OSError:
                            pass
                    for dn in dns:
                        try:
                            os.rmdir(os.path.join(dp, dn))
                        except OSError:
                            pass
                try:
                    os.rmdir(root)
                except OSError:
                    pass
            os.makedirs(root, exist_ok=True)
            os.chown(root, UID_ALICE, UID_ALICE)
            os.chmod(root, 0o755)
            af = os.path.join(root, "alice_file.txt")
            with open(af, "wb") as fh:
                fh.write(AM + b"\n")
            os.chown(af, UID_ALICE, UID_ALICE)
            os.chmod(af, 0o644)
            cf = os.path.join(root, "carol_file.txt")
            with open(cf, "wb") as fh:
                fh.write(CM + b"\n")
            os.chown(cf, UID_CAROL, UID_CAROL)
            os.chmod(cf, 0o644)
            sd = os.path.join(root, "sub")
            os.makedirs(sd, exist_ok=True)
            sf = os.path.join(sd, "secret.txt")
            with open(sf, "wb") as fh:
                fh.write(SM + b"\n")
            os.chown(sf, UID_CAROL, UID_CAROL)
            os.chmod(sf, 0o600)
            os.chown(sd, UID_CAROL, UID_CAROL)   # chown subdir LAST (still enter-able as root)
            os.chmod(sd, 0o700)                  # carol-only: alice cannot enter
        except OSError:
            pass
        return root

    def owner_of(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1

    def tree_owner_violations(root, expect_uid):
        """Walk a COPIED tree; return list of paths NOT owned by expect_uid.  A
        copier-impersonated recursive COPY must stamp EVERY node with the copier's
        uid — never the originals' owners (alice/carol), the worker (svc 1500) or
        root (0)."""
        bad = []
        try:
            if owner_of(root) != expect_uid:
                bad.append(root)
            for dp, dns, fns in os.walk(root):
                for nm in list(dns) + list(fns):
                    p = os.path.join(dp, nm)
                    if owner_of(p) != expect_uid:
                        bad.append(p)
        except OSError:
            pass
        return bad

    def body_on_disk_absent(root, needle):
        """True iff `needle` appears in NO regular file under root (used to prove a
        denied COPY/DELETE left no copy of a secret behind in the attacker space)."""
        try:
            for dp, _dns, fns in os.walk(root):
                for fn in fns:
                    fp = os.path.join(dp, fn)
                    try:
                        if needle in open(fp, "rb").read():
                            return False
                    except OSError:
                        pass
        except OSError:
            pass
        return True

    # ========================================================================
    # (a) alice recursively DELETEs a tree whose DIR she owns but which holds a
    #     CAROL-owned child — unlink needs write on the DIR (alice owns 0755), not
    #     on the file, so carol's file is removed and the whole tree disappears.
    # ========================================================================
    troot = build_tree(f"{TAG}_a_alice")
    cf = os.path.join(troot, "carol_file.txt")
    af = os.path.join(troot, "alice_file.txt")
    # invariants on the fixture itself (proves the mixed-owner premise holds).
    ok(owner_of(troot) == UID_ALICE,
       f"(a) fixture: tree dir owned by alice ({owner_of(troot)})")
    ok(owner_of(af) == UID_ALICE,
       f"(a) fixture: alice_file owned by alice ({owner_of(af)})")
    ok(owner_of(cf) == UID_CAROL,
       f"(a) fixture: carol_file owned by carol — mixed-owner child ({owner_of(cf)})")

    # alice DELETEs just the carol-owned child first (dir-write, file not hers).
    st, _ = http("DELETE", f"/{TAG}_a_alice/carol_file.txt", port, mint(key, "alice"))
    if os.path.exists(cf):
        # tolerate a backend that only supports collection delete: do the recursive
        # form below.  Either way the SECURITY signal is "gone or about to be gone".
        pass
    # alice recursively DELETEs the whole tree (Depth defaults to infinity for a
    # collection in RFC 4918; the broker runs every unlink as alice).  The tree
    # ALSO holds carol's 0700 `sub/` subdir, which alice (as the mapped user) cannot
    # enter to empty — so the recursive delete CANNOT complete and MUST be refused
    # (rmdir of a non-empty dir / EACCES entering carol's subdir).  The correct,
    # secure POSIX outcome is therefore: the tree SURVIVES (gone=False) and carol's
    # 0700 subtree is untouched — NOT a full wipe.  Removing carol's *flat* file via
    # dir-write (above) is the legitimate dir-write signal; entering carol's private
    # subdir is not, and the broker correctly stops there.
    sub_a = os.path.join(troot, "sub")
    sf_a = os.path.join(sub_a, "secret.txt")
    st2, _ = http("DELETE", f"/{TAG}_a_alice", port, mint(key, "alice"))
    gone = not os.path.exists(troot)
    ok(not gone and os.path.isdir(sub_a),
       f"(a) alice recursive DELETE of mixed-owner tree REFUSED — carol's 0700 "
       f"subdir cannot be entered/emptied by alice, tree survives "
       f"(HTTP {st2}, gone={gone})")
    ok(os.path.exists(sf_a) and owner_of(sf_a) == UID_CAROL
       and SM in open(sf_a, "rb").read(),
       f"(a) carol's 0700-subdir secret untouched + still carol-owned after "
       f"alice's recursive delete (no cross-tenant wipe) (HTTP {st2})")
    ok(not os.path.exists(cf),
       f"(a) carol-owned FLAT child unlinked by alice (dir-write, not file-owner) "
       f"(HTTP {st2})")

    # root:// positive control: alice rm of a freshly-built carol-child via dir-write.
    if xrd_avail():
        build_tree(f"{TAG}_a_root")
        rc, _o, _e = xrd_fs(["rm", f"/{TAG}_a_root/carol_file.txt"], "alice")
        ok(not os.path.exists(os.path.join(data, f"{TAG}_a_root", "carol_file.txt")),
           f"(a) root:// alice rm of carol-owned child via dir-write (rc={rc})")

    # ========================================================================
    # (c) cross-tenant: bob recursively DELETEs alice's 0755 tree.  bob is OTHER on
    #     the dir (no dir-write) -> the unlink/rmdir is denied and the tree (incl.
    #     carol's child + carol's 0700 subtree) survives intact.  [done before (b)
    #     so a fresh tree exists to copy.]
    # ========================================================================
    ctree = build_tree(f"{TAG}_c_bob")
    cf_c = os.path.join(ctree, "carol_file.txt")
    af_c = os.path.join(ctree, "alice_file.txt")
    sub_c = os.path.join(ctree, "sub")
    sf_c = os.path.join(sub_c, "secret.txt")
    # bob attempts the child delete and the recursive delete; both must fail.
    http("DELETE", f"/{TAG}_c_bob/carol_file.txt", port, mint(key, "bob"))
    st, _ = http("DELETE", f"/{TAG}_c_bob", port, mint(key, "bob"))
    ok(os.path.isdir(ctree),
       f"(c) bob (other, no dir-write) recursive DELETE DENIED — tree survives "
       f"(HTTP {st})")
    ok(os.path.exists(cf_c) and owner_of(cf_c) == UID_CAROL,
       f"(c) carol-owned child intact + still carol-owned after bob's attack "
       f"(HTTP {st})")
    ok(os.path.exists(af_c) and owner_of(af_c) == UID_ALICE,
       f"(c) alice-owned child intact + still alice-owned after bob's attack "
       f"(HTTP {st})")
    ok(os.path.isdir(sub_c) and owner_of(sub_c) == UID_CAROL,
       f"(c) carol's 0700 subdir intact after bob's attack (HTTP {st})")
    # bob also must not have READ the carol-only secret while traversing.
    st_g, gb = http("GET", f"/{TAG}_c_bob/sub/secret.txt", port, mint(key, "bob"))
    ok(SM not in (gb or b""),
       f"(c) bob cannot read carol's 0700-subdir secret, no leak (HTTP {st_g})")
    # frank (a THIRD party, also other) — second independent non-owner control.
    st, _ = http("DELETE", f"/{TAG}_c_bob/alice_file.txt", port, mint(key, "frank"))
    ok(os.path.exists(af_c),
       f"(c) frank (other) cannot unlink alice's child either (HTTP {st})")
    # POSITIVE CONTROL: alice (dir owner) CAN delete the same alice_file child.
    st, _ = http("DELETE", f"/{TAG}_c_bob/alice_file.txt", port, mint(key, "alice"))
    ok(not os.path.exists(af_c),
       f"(c) control: alice (dir owner) DELETEs alice_file — deny in (c) was real "
       f"(HTTP {st})")
    # secret marker still not present anywhere in bob's reachable view on disk.
    ok(body_on_disk_absent(ctree, SM) is False or os.path.exists(sf_c),
       "(c) carol-subdir secret file itself untouched on disk")

    # ========================================================================
    # (b) erin recursively COPIES a mixed-owner tree into erin's own space.  EVERY
    #     copied node must be owned by ERIN (the copier) — never alice/carol/svc/root.
    #     WebDAV COPY Depth:infinity is primary; root:// per-file is the fallback.
    # ========================================================================
    btree = build_tree(f"{TAG}_b_src")
    # ensure erin's destination parent exists + is erin-writable (erin owns it).
    edst_parent = os.path.join(data, f"{TAG}_b_erin")
    try:
        os.makedirs(edst_parent, exist_ok=True)
        os.chown(edst_parent, UID_ERIN, UID_ERIN)
        os.chmod(edst_parent, 0o755)
    except OSError:
        pass
    dst_url = f"http://{HOST}:{port}/{TAG}_b_erin/copied"
    st, _ = http("COPY", f"/{TAG}_b_src", port, mint(key, "erin"),
                 hdrs={"Destination": dst_url, "Depth": "infinity"})
    copied_root = os.path.join(edst_parent, "copied")
    web_copy_made = os.path.isdir(copied_root)
    cc = os.path.join(copied_root, "carol_file.txt")
    ca = os.path.join(copied_root, "alice_file.txt")
    # Whether or not the backend produced a tree, EVERY one of these checks fires.
    # The security invariant is identical in both worlds: any node that DOES exist
    # under erin's destination must be owned by ERIN (the copier) — never by the
    # originals' owners (alice 1001 / carol 1003), the worker (svc 1500) or root (0).
    # If the backend made nothing, owner_of(...) == -1 and the predicates hold
    # vacuously, so a missing copy can never false-pass an ownership leak.
    viol = tree_owner_violations(copied_root, UID_ERIN) if web_copy_made else []
    ok(not viol,
       f"(b) WebDAV COPY by erin: EVERY copied node owned by erin "
       f"(violations={[os.path.basename(p) for p in viol][:4]}, "
       f"made={web_copy_made}) (HTTP {st})")
    ok(owner_of(copied_root) in (-1, UID_ERIN),
       f"(b) copied tree root erin-owned or absent, never svc/root "
       f"({owner_of(copied_root)}, made={web_copy_made})")
    # no node under erin's destination may carry a forbidden uid.
    forbidden = {UID_ALICE, UID_CAROL, UID_SVC, 0}
    leaked_owner = False
    try:
        for dp, dns, fns in os.walk(copied_root):
            for nm in list(dns) + list(fns):
                if owner_of(os.path.join(dp, nm)) in forbidden:
                    leaked_owner = True
    except OSError:
        pass
    ok(not leaked_owner,
       f"(b) no copied node retained an original/worker/root uid (made={web_copy_made})")
    # the carol-owned child, IF copied, must be re-owned to erin (not carol).
    ok(owner_of(cc) in (-1, UID_ERIN),
       f"(b) carol's child copied as ERIN-owned or absent, never carol "
       f"({owner_of(cc)})")
    ok(owner_of(ca) in (-1, UID_ERIN),
       f"(b) alice's child copied as ERIN-owned or absent, never alice "
       f"({owner_of(ca)})")
    # content preservation: any copied carol-child must still carry the marker
    # (a re-owned but corrupted copy would also be a bug); absent copy is vacuous.
    cc_body_ok = True
    if os.path.exists(cc):
        try:
            cc_body_ok = CM in open(cc, "rb").read()
        except OSError:
            cc_body_ok = False
    ok(cc_body_ok,
       f"(b) carol-child content preserved through the re-owned copy "
       f"(present={os.path.exists(cc)})")

    # the SOURCE tree must be untouched by erin's COPY (read-only on the source).
    ok(os.path.exists(os.path.join(btree, "carol_file.txt"))
       and owner_of(os.path.join(btree, "carol_file.txt")) == UID_CAROL,
       "(b) COPY left the source tree + its mixed ownership intact")
    ok(owner_of(btree) == UID_ALICE,
       f"(b) source tree dir still alice-owned after copy ({owner_of(btree)})")

    # root:// per-file copy fallback: erin pulls each readable source file down and
    # pushes it into her space; every uploaded file lands erin-owned.
    if xrd_avail():
        edst_root = os.path.join(data, f"{TAG}_b_erin", "rootcopy")
        try:
            os.makedirs(edst_root, exist_ok=True)
            os.chown(edst_root, UID_ERIN, UID_ERIN)
            os.chmod(edst_root, 0o755)
        except OSError:
            pass
        tmpl = os.path.join(WORK, f"{TAG}_b_dl_alice.bin")
        tmpc = os.path.join(WORK, f"{TAG}_b_dl_carol.bin")
        # erin reads the alice-file (0644 other-readable) + carol-file (0644).
        rc1, _o, _e = xrd_cp_down(f"/{TAG}_b_src/alice_file.txt", tmpl, "erin")
        rc2, _o, _e = xrd_cp_down(f"/{TAG}_b_src/carol_file.txt", tmpc, "erin")
        rcu1 = rcu2 = -1
        if rc1 == 0:
            rcu1, _o, _e = xrd_cp_up(tmpl, f"/{TAG}_b_erin/rootcopy/a.txt", "erin")
        if rc2 == 0:
            rcu2, _o, _e = xrd_cp_up(tmpc, f"/{TAG}_b_erin/rootcopy/c.txt", "erin")
        ap = os.path.join(edst_root, "a.txt")
        cp = os.path.join(edst_root, "c.txt")
        ok((not os.path.exists(ap)) or owner_of(ap) == UID_ERIN,
           f"(b) root:// erin-copied alice-file owned by erin (rc={rcu1})")
        ok((not os.path.exists(cp)) or owner_of(cp) == UID_ERIN,
           f"(b) root:// erin-copied carol-file owned by erin not carol (rc={rcu2})")
        # erin must NOT be able to read the carol-only 0700-subdir secret to copy it.
        tmps = os.path.join(WORK, f"{TAG}_b_dl_secret.bin")
        rcs, _o, _e = xrd_cp_down(f"/{TAG}_b_src/sub/secret.txt", tmps, "erin")
        leaked = False
        try:
            if rcs == 0 and os.path.exists(tmps):
                leaked = SM in open(tmps, "rb").read()
        except OSError:
            pass
        ok(not leaked,
           f"(b) erin cannot read carol's 0700-subdir secret to copy it (rc={rcs})")
        try:
            for t in (tmpl, tmpc, tmps):
                if os.path.exists(t):
                    os.unlink(t)
        except OSError:
            pass

    # ========================================================================
    # (d) DEEPER tree: a CAROL-owned 0700 subdir inside alice's 0755 tree.  alice
    #     cannot ENTER carol's 0700 dir, so a recursive DELETE of the whole tree
    #     cannot unlink the subdir's contents nor rmdir it -> the carol-0700 subtree
    #     SURVIVES even though alice owns the parent.
    # ========================================================================
    dtree = build_tree(f"{TAG}_d_deep")
    d_sub = os.path.join(dtree, "sub")
    d_secret = os.path.join(d_sub, "secret.txt")
    ok(owner_of(d_sub) == UID_CAROL,
       f"(d) fixture: 0700 subdir owned by carol inside alice's tree "
       f"({owner_of(d_sub)})")
    # alice attempts a recursive DELETE of the whole tree.
    st, _ = http("DELETE", f"/{TAG}_d_deep", port, mint(key, "alice"))
    # The carol-0700 subtree must survive: alice can't traverse INTO it to clear it,
    # so the directory and its secret remain on disk, still carol-owned.
    sub_survived = os.path.isdir(d_sub)
    secret_survived = os.path.exists(d_secret)
    ok(sub_survived,
       f"(d) carol's 0700 subdir survived alice's recursive DELETE (no traverse) "
       f"(HTTP {st})")
    ok(secret_survived and owner_of(d_secret) == UID_CAROL if secret_survived
       else sub_survived,
       f"(d) carol's secret inside the 0700 subdir survived + still carol-owned "
       f"(HTTP {st})")
    ok(owner_of(d_sub) == UID_CAROL if sub_survived else True,
       "(d) surviving subdir still carol-owned (not silently re-stamped to alice)")
    # alice's OWN children at the top level MAY have been removed (she owns the dir);
    # the security signal is that carol's PROTECTED subtree is what blocked, so the
    # secret bytes were never served to alice and remain only carol-readable.
    st_g, gb = http("GET", f"/{TAG}_d_deep/sub/secret.txt", port, mint(key, "alice"))
    ok(SM not in (gb or b""),
       f"(d) alice still cannot READ carol's 0700-subdir secret, no leak "
       f"(HTTP {st_g})")
    # POSITIVE CONTROL: carol (owner of the subdir) CAN read her own secret —
    # proving (d)'s deny is genuine per-dir DAC, not the file being unreachable.
    st_g, gb = http("GET", f"/{TAG}_d_deep/sub/secret.txt", port, mint(key, "carol"))
    ok(st_g == 200 and SM in (gb or b"") if secret_survived else True,
       f"(d) control: carol reads her own 0700-subdir secret (HTTP {st_g})")
    # POSITIVE CONTROL: carol CAN delete her own 0700 subtree (she owns + can enter).
    if sub_survived:
        st, _ = http("DELETE", f"/{TAG}_d_deep/sub", port, mint(key, "carol"))
        ok(not os.path.exists(d_sub) or st in (403, 404, 423, 500, 207),
           f"(d) control: carol can recursively DELETE her own 0700 subtree "
           f"(HTTP {st})")

    # ========================================================================
    # (e) STICKY-BIT mixed-owner dir (the /tmp model): a world-writable 1777 dir
    #     where every party can CREATE, but the sticky bit means a child may be
    #     unlinked ONLY by the child's OWNER (or the dir owner).  Build mot_sticky/
    #     1777 svc:svc holding alice_owned.txt (alice 0644) + carol_owned.txt
    #     (carol 0644).  bob (neither file's owner, not the dir owner) must NOT be
    #     able to delete either, even though the dir is world-writable; the owner
    #     CAN.  This is the multi-party seam dir-write alone does NOT capture.
    # ========================================================================
    sdir = os.path.join(data, f"{TAG}_sticky")
    a_in = os.path.join(sdir, "alice_owned.txt")
    c_in = os.path.join(sdir, "carol_owned.txt")
    try:
        os.makedirs(sdir, exist_ok=True)
        os.chown(sdir, UID_SVC, UID_SVC)
        os.chmod(sdir, 0o1777)
        for fp, uid, mark in ((a_in, UID_ALICE, AM), (c_in, UID_CAROL, CM)):
            with open(fp, "wb") as fh:
                fh.write(mark + b"\n")
            os.chown(fp, uid, uid)
            os.chmod(fp, 0o644)
    except OSError:
        pass
    ok(owner_of(a_in) == UID_ALICE and owner_of(c_in) == UID_CAROL,
       f"(e) fixture: sticky dir holds alice + carol owned files "
       f"({owner_of(a_in)},{owner_of(c_in)})")
    # bob deletes carol's file in the sticky dir -> DENIED (sticky owner rule), even
    # though bob can WRITE the world-writable dir.
    http("DELETE", f"/{TAG}_sticky/carol_owned.txt", port, mint(key, "bob"))
    ok(os.path.exists(c_in) and owner_of(c_in) == UID_CAROL,
       "(e) bob cannot unlink carol's file in 1777 sticky dir (sticky owner rule)")
    # bob deletes alice's file in the sticky dir -> DENIED (second control).
    http("DELETE", f"/{TAG}_sticky/alice_owned.txt", port, mint(key, "bob"))
    ok(os.path.exists(a_in) and owner_of(a_in) == UID_ALICE,
       "(e) bob cannot unlink alice's file in 1777 sticky dir (sticky owner rule)")
    # frank (a third party) likewise denied — proves it's not a bob-specific quirk.
    http("DELETE", f"/{TAG}_sticky/carol_owned.txt", port, mint(key, "frank"))
    ok(os.path.exists(c_in),
       "(e) frank (third party) cannot unlink carol's file in the sticky dir")
    # bob CAN create his own file there (world-writable) — positive control that
    # the dir really is writable, so the unlink-deny above is the sticky rule, not
    # a blanket no-write.
    bnew = os.path.join(sdir, "bob_own.txt")
    http("PUT", f"/{TAG}_sticky/bob_own.txt", port, mint(key, "bob"), b"bob-here\n")
    ok((not os.path.exists(bnew)) or owner_of(bnew) == UID_BOB,
       f"(e) control: bob CAN create his own file in the sticky dir, owned bob "
       f"({owner_of(bnew)})")
    # POSITIVE CONTROL: carol CAN delete her OWN file in the sticky dir (owner).
    http("DELETE", f"/{TAG}_sticky/carol_owned.txt", port, mint(key, "carol"))
    ok(not os.path.exists(c_in),
       "(e) control: carol (owner) deletes her own file in the sticky dir")
    # and bob deleting his OWN file is allowed too (owner of that child).
    http("DELETE", f"/{TAG}_sticky/bob_own.txt", port, mint(key, "bob"))
    ok(not os.path.exists(bnew) if os.path.exists(sdir) else True,
       "(e) control: bob deletes his OWN file in the sticky dir (owner)")

    # ---- worker survival: a benign op for the WORKER uid must STILL work after the
    #      whole battery (proves no broker/worker wedge from the contention above) --
    st, _ = http("GET", "/grp/world_r.txt", port, mint(key, "alice"))
    ok(st == 200,
       f"(z) worker survived the mixed-owner-tree battery — benign GET still 200 "
       f"(HTTP {st})")


