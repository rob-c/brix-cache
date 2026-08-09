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


def run_battery(key, data, port, s3port, sock):
    tok_alice = mint(key, "alice")
    tok_bob = mint(key, "bob")

    # (1) BASELINE — the whole real chain: alice PUT -> 201, owned alice:alice
    #     (NOT the svc worker uid, NOT root).  This single check exercises
    #     lifecycle spawn + worker connect + auth + dispatch hook + put body
    #     bracket + broker + idmap + setfsuid.
    st, _ = http("PUT", "/alice/hello.txt", port, tok_alice, b"hi from alice\n")
    ok(st in (200, 201, 204), f"alice PUT accepted (HTTP {st})")
    p = os.path.join(data, "alice", "hello.txt")
    owned = os.path.exists(p) and os.stat(p).st_uid == UID_ALICE \
        and os.stat(p).st_gid == UID_ALICE
    ok(owned, "alice's file owned by the MAPPED user (1001:1001), not worker/root")

    # (2) bob PUT -> owned bob.
    st, _ = http("PUT", "/bob/b.txt", port, tok_bob, b"bob\n")
    bp = os.path.join(data, "bob", "b.txt")
    ok(st in (200, 201, 204) and os.path.exists(bp)
       and os.stat(bp).st_uid == UID_BOB,
       "bob's file owned by bob (1002)")

    # (3) alice reads her own file.
    st, body = http("GET", "/alice/hello.txt", port, tok_alice)
    ok(st == 200 and body == b"hi from alice\n", "alice GET own file")

    # (4) DAC: alice cannot read bob's 0700-dir file.
    st, _ = http("GET", "/bobsecret/s.txt", port, tok_alice)
    ok(st in (403, 404, 401), f"alice DENIED reading bob's 0700 file (HTTP {st})")

    # (5-9) ESCALATION / FORBIDDEN identities — each holds a VALID write-scoped
    #       token, so authz passes; impersonation MUST still refuse them.
    def escalation_denied(sub, label, group_member=False):
        extra = {}
        tok = mint(key, sub)
        path = f"/pub/{sub}_evil.txt"          # world-writable dir, so only the
        st, _ = http("PUT", path, port, tok, b"escalate\n")   # guard can stop it
        fp = os.path.join(data, "pub", f"{sub}_evil.txt")
        created = os.path.exists(fp)
        bad_owner = created and os.stat(fp).st_uid < 1000
        ok(st not in (200, 201, 204) and not created and not bad_owner,
           f"{label} -> DENIED (HTTP {st}, file_created={created})")

    escalation_denied("root", "escalate to root (uid 0)")
    escalation_denied("sys100", "escalate to sys uid 100 (< floor)")
    escalation_denied("svc", "impersonate the worker/service account (uid 1500)")
    escalation_denied("dockerite", "member of forbidden 'docker' group (gid 1600)")
    escalation_denied("mallory", "unmapped principal")

    # (10) confinement: a symlink inside the export pointing at /etc must not let
    #      a GET escape the root.
    st, body = http("GET", "/escape/passwd", port, tok_alice)
    leaked = (st == 200 and b"root:x:0:0" in body)
    ok(not leaked, f"symlink escape /escape/passwd blocked (HTTP {st})")

    # (11) confined-write traversal: must not create a file outside the export.
    sentinel = os.path.join(os.path.dirname(data), "OUTSIDE")
    http("PUT", "/../OUTSIDE", port, tok_alice, b"x\n")
    http("PUT", "/%2e%2e/OUTSIDE", port, tok_alice, b"x\n")
    ok(not os.path.exists(sentinel),
       "path-traversal PUT did not escape the export root")

    # (11b) WebDAV NAMESPACE ops as the mapped user (MKCOL/MOVE/COPY/DELETE).
    run_namespace_ops(key, data, port)

    # (11c) directory-LISTING confidentiality — does PROPFIND leak a dir the user
    #       has no UNIX permission to read?
    run_dirlist_confidentiality(key, data, port)

    # (11d) LOCK + PROPPATCH persist xattrs on the resource — broker XATTR op.
    run_lock_proppatch(key, data, port)

    # (11e) S3 (SigV4) under impersonation — objects owned by the mapped user.
    s3_up = wait_port(s3port, 5)
    if s3_up:
        run_s3(data, s3port)
    else:
        ok(False, "S3 server did not come up on its port")

    if s3_up:
        # (11e1) S3 SigV4 auth-error gating + S3 ops/multipart not yet covered.
        run_s3_sigv4_errors(key, data, s3port)
        run_s3_extended(key, data, s3port)

    # (11e2) root:// native STREAM protocol (xrdfs/xrdcp + token) under impersonation.
    run_root_battery(key, data)

    # (11f) cross-tenant CONFIDENTIALITY — alice must not READ bob's private data
    #       via any protocol (WebDAV GET/HEAD, S3 GET/HEAD); but MAY read a file
    #       bob made world-readable (control proving the deny is real per-file DAC).
    run_cross_tenant_read(key, data, port, s3port if s3_up else 0)

    # (11g) cross-tenant INTEGRITY — alice must not WRITE/DELETE/MUTATE bob's data
    #       via any protocol (WebDAV PUT/DELETE/MOVE/COPY/PROPPATCH/LOCK; S3
    #       PUT/DELETE/CopyObject/DeleteObjects/POST).  Every async-body handler.
    run_cross_tenant_write(key, data, port, s3port if s3_up else 0)

    # (11h) every CREATE path lands owned by the mapped user — exercises the
    #       remaining async-body S3 handlers (POST form-object, CopyObject) and the
    #       WebDAV LOCK-creates-a-zero-byte-resource path.
    run_create_ownership(key, data, port, s3port if s3_up else 0)

    # (11i) recursive PROPFIND (Depth: infinity) must not leak a private subtree.
    run_recursive_propfind(key, data, port)

    # (11j) confinement — traversal / escape via S3 keys and COPY/MOVE Destination.
    run_confinement_extended(key, data, port, s3port if s3_up else 0)

    # (11k) token -> UNIX principal mapping attacks (empty/long/traversal/reserved).
    run_token_principal_attacks(key, data, port)

    # (11l) exhaustive WebDAV method coverage (HEAD/OPTIONS/UNLOCK/COPY-coll/Overwrite).
    run_webdav_methods(key, data, port)

    # (11m) WebDAV protocol/header/error modes (conditional/Range/keep-alive/malformed).
    run_webdav_errors(key, data, port)

    # (11n) cross-PROTOCOL identity boundaries + erroring connections (FIFO/dangling).
    run_cross_cutting(key, data, port, s3port if s3_up else 0)

    # (11o) forged/invalid bearer tokens rejected across WebDAV + root://.
    run_auth_matrix(key, data, port)

    # (11p) per-subcommand root:// (stream) self vs cross-tenant matrix.
    run_root_deep(key, data, port)

    # (11q) deep S3: CopyObject/UploadPartCopy/DeleteObjects/Range/list confinement.
    if s3_up:
        run_s3_deep(key, data, s3port)

    # (11r) path-traversal / encoding / NUL across every protocol.
    run_traversal_matrix(key, data, port, s3port if s3_up else 0)

    # (11s+) DEEP workflow-designed batches — each ISOLATED so one broken/raising
    #        batch records a failure + traceback but never aborts the rest of the
    #        suite.  These push the suite from ~224 to ~700 checks.
    import traceback as _tb

    def _guard(fn, *a):
        _reset_fixtures(data)   # restore canonical shared-fixture state before each batch
        try:
            fn(*a)
        except Exception as e:  # noqa: BLE001
            _tb.print_exc()
            ok(False, f"{fn.__name__} raised an exception: {e!r}")

    _s3p = s3port if s3_up else 0
    for _fn in (run_root_protocol_depth, run_webdav_method_state,
                run_s3_multipart_adversarial, run_concurrency_state_race,
                run_broker_resource_limits, run_confine_encoding_exhaustive,
                run_crossproto_ownership_invariant, run_malformed_hostile_inputs,
                run_auth_scheme_confusion,
                run_http_protocol_abuse, run_s3_presigned,
                run_crossproto_chmod_chains, run_samefile_contention,
                run_group_read_dac, run_group_write_dac, run_permission_matrix,
                run_group_dir_dac, run_setgid_inheritance, run_sticky_bit_dac, run_mixed_owner_trees, run_multiuser_party, run_chown_chgrp_dac, run_manygroups_dac, run_boundary_mapping, run_group_concurrency, run_group_xattr_lock, run_group_traversal_depth,
                run_stream_extended_ops, run_native_tpc, run_dataplane_integrity, run_connection_errors, run_protocol_features_s3, run_protocol_features_webdav,
                run_combo_setgid_via_copymove, run_combo_symlink_crossproto_toctou, run_combo_multipart_lock_identity, run_combo_authfail_resource_state, run_combo_broker_pressure, run_combo_encoding_group_targets, run_combo_concurrent_crossproto, run_combo_xattr_namespace_group, run_combo_idmap_edge_full_matrix, run_combo_rare_opcodes, run_combo_connection_state_identity, run_combo_error_rollback,
                run_s3_subresource_fallthrough, run_s3_post_form_and_bucketops, run_webdav_undispatched_methods, run_webdav_property_exotic, run_http_smuggling_desync_deep, run_conditional_header_matrix, run_content_negotiation_ranges, run_frm_prepare_stage, run_broker_internals_stress, run_resource_dos_limits, run_raw_kxr_wire, run_header_injection_matrix, run_tpc_pull_push_matrix, run_multistep_lifecycle_invariants,
                run_http_tpc_webdav, run_checksum_digest_oracle, run_raw_kxr_deep, run_query_subcode_oracle, run_scoped_token_dac_matrix, run_special_file_rename_matrix, run_broker_dos_resilience, run_deep_novel_combos_r8,
                run_s3_conditional_impersonation, run_s3_checksum_verify_impersonation, run_s3_acl_tagging_dac, run_compression_impersonation, run_raw_kxr_authed, run_phase_features_combos):
        _guard(_fn, key, data, port, _s3p)

    # (12) CONCURRENCY: interleave alice/bob PUTs; every file must end up owned by
    #      the correct uid (no setfsuid credential leak across the real worker).
    N = 24
    results = {}

    def worker(i):
        sub = "alice" if i % 2 == 0 else "bob"
        tok = tok_alice if sub == "alice" else tok_bob
        sub_dir = "alice" if sub == "alice" else "bob"
        rel = f"/{sub_dir}/c_{sub}_{i}.txt"
        http("PUT", rel, port, tok, f"{sub}{i}\n".encode())
        results[i] = (sub_dir, f"c_{sub}_{i}.txt",
                      UID_ALICE if sub == "alice" else UID_BOB)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    leak = 0
    for i in range(N):
        sub_dir, name, want = results[i]
        fp = os.path.join(data, sub_dir, name)
        if not (os.path.exists(fp) and os.stat(fp).st_uid == want):
            leak += 1
    ok(leak == 0,
       f"interleaved alice/bob ({N} concurrent PUTs): every file correct owner "
       f"(no setfsuid leak); mismatches={leak}")

    # (12b) MIXED-OP concurrency: interleave DIFFERENT op types AND cross-tenant
    #       attacks across alice/bob — stresses the per-worker principal global for
    #       any race window where a leaked principal lets an op run as the wrong
    #       identity (every legit op correct-owner; every cross-tenant op denied).
    run_mixed_concurrency(key, data, port, s3port if s3_up else 0)

    # (13) confused-deputy summary: re-confirm the headline file is the user's,
    #      not the worker's (svc 1500) nor the broker's (root 0).
    hp = os.path.join(data, "alice", "hello.txt")
    su = os.stat(hp).st_uid if os.path.exists(hp) else -1
    ok(su == UID_ALICE and su != UID_SVC and su != 0,
       "no worker/broker identity leaks into created-file ownership")

    # (14) BROKER FAIL-CLOSED — kill the broker, then impersonated ops (PUT, the
    #      LOCK xattr op, S3 PUT) must be DENIED (and create no file), NOT silently
    #      performed as the worker uid.  MUST BE LAST: it tears the broker down.
    run_broker_failclosed(key, data, port, s3port if s3_up else 0, sock, tok_alice)


def run_namespace_ops(key, data, port):
    """MKCOL / MOVE / COPY / DELETE as the mapped user — confirm the namespace
    mutations route through the broker (owned by the user, DAC enforced)."""
    tok_alice = mint(key, "alice")

    st, _ = http("MKCOL", "/alice/ndir", port, tok_alice)
    dp = os.path.join(data, "alice", "ndir")
    ok(st in (201, 200) and os.path.isdir(dp) and os.stat(dp).st_uid == UID_ALICE,
       f"MKCOL: new dir owned by mapped user alice (HTTP {st})")

    # DAC: alice MKCOL inside bob's 0700 dir -> denied.
    st, _ = http("MKCOL", "/bobsecret/evil", port, tok_alice)
    ok(st not in (200, 201)
       and not os.path.exists(os.path.join(data, "bobsecret", "evil")),
       f"MKCOL inside bob's 0700 dir -> denied (HTTP {st})")

    http("PUT", "/alice/mv_src.txt", port, tok_alice, b"movable\n")
    st, _ = http("MOVE", "/alice/mv_src.txt", port, tok_alice,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/mv_dst.txt"})
    md = os.path.join(data, "alice", "mv_dst.txt")
    ok(st in (201, 204) and os.path.exists(md) and os.stat(md).st_uid == UID_ALICE
       and not os.path.exists(os.path.join(data, "alice", "mv_src.txt")),
       f"MOVE: dest owned by alice, src gone (HTTP {st})")

    st, _ = http("COPY", "/alice/mv_dst.txt", port, tok_alice,
                 hdrs={"Destination": f"http://{HOST}:{port}/alice/cp_dst.txt"})
    cd = os.path.join(data, "alice", "cp_dst.txt")
    ok(st in (201, 204) and os.path.exists(cd) and os.stat(cd).st_uid == UID_ALICE,
       f"COPY: dest owned by alice (HTTP {st})")

    st, _ = http("DELETE", "/alice/cp_dst.txt", port, tok_alice)
    ok(st in (200, 204) and not os.path.exists(cd), f"DELETE as alice (HTTP {st})")


def run_dirlist_confidentiality(key, data, port):
    """A user must NOT be shown the contents of a directory they have no UNIX
    permission to read, even if the worker uid can read it (worker-side readdir
    leak).  /svconly is svc:svc 0750 — readable by the svc worker, NOT by alice."""
    tok_alice = mint(key, "alice")
    st, body = http("PROPFIND", "/svconly/", port, tok_alice,
                    data=b'<?xml version="1.0"?><propfind xmlns="DAV:">'
                         b'<prop><displayname/></prop></propfind>',
                    hdrs={"Depth": "1", "Content-Type": "application/xml"})
    leaked = (st in (200, 207) and b"secret-name.txt" in (body or b""))
    ok(not leaked,
       f"PROPFIND of a dir alice cannot read does NOT leak its entries "
       f"(HTTP {st}, leaked={leaked})")

    # control: alice CAN list her own dir.
    st, body = http("PROPFIND", "/alice/", port, tok_alice,
                    data=b'<?xml version="1.0"?><propfind xmlns="DAV:">'
                         b'<prop><displayname/></prop></propfind>',
                    hdrs={"Depth": "1", "Content-Type": "application/xml"})
    ok(st in (200, 207), f"PROPFIND of alice's own dir works (HTTP {st})")

    # (11c-2) SAME confidentiality class via DASL SEARCH — SEARCH also walks the
    #         namespace and is read asynchronously, so it suffered the identical
    #         principal-loss leak as PROPFIND.  It must NOT enumerate /svconly.
    search_body = (
        b'<?xml version="1.0"?>'
        b'<D:searchrequest xmlns:D="DAV:"><D:basicsearch>'
        b'<D:select><D:prop><D:displayname/></D:prop></D:select>'
        b'<D:from><D:scope><D:href>/svconly/</D:href>'
        b'<D:depth>1</D:depth></D:scope></D:from>'
        b'</D:basicsearch></D:searchrequest>')
    st, body = http("SEARCH", "/svconly/", port, tok_alice,
                    data=search_body,
                    hdrs={"Content-Type": "application/xml"})
    leaked = (st in (200, 207) and b"secret-name.txt" in (body or b""))
    ok(not leaked,
       f"SEARCH of a dir alice cannot read does NOT leak its entries "
       f"(HTTP {st}, leaked={leaked})")

    # positive control: alice SEARCHing her OWN dir DOES enumerate it (proves the
    # walk actually runs — depth parsed, opendir reached, gate allows — so the
    # /svconly result above is a real deny, not a trivially-empty walk).
    search_own = search_body.replace(b"/svconly/", b"/alice/")
    st, body = http("SEARCH", "/alice/", port, tok_alice,
                    data=search_own,
                    hdrs={"Content-Type": "application/xml"})
    ok(st in (200, 207) and b"hello.txt" in (body or b""),
       f"SEARCH of alice's own dir enumerates her files (HTTP {st})")


def run_lock_proppatch(key, data, port):
    """WebDAV LOCK and PROPPATCH persist their state as `user.*` xattrs ON the
    resource.  Under impersonation the worker (svc, uid 1500) is "other" on
    alice's 0644 file and CANNOT setxattr it (EACCES) — so before the broker
    XATTR op these operations were broken.  The broker, acting AS alice (the
    owner), can.  These checks therefore prove the broker xattr op works
    end-to-end, and that its DAC matches the mapped user (bob is denied)."""
    tok_alice = mint(key, "alice")
    tok_bob = mint(key, "bob")

    # The file must be non-other-writable for the check to discriminate (else the
    # worker svc could have set the xattr itself, masking a broken broker).
    http("PUT", "/alice/propme.txt", port, tok_alice, b"prop target\n")
    fp = os.path.join(data, "alice", "propme.txt")
    mode = os.stat(fp).st_mode if os.path.exists(fp) else 0
    ok(os.stat(fp).st_uid == UID_ALICE and (mode & 0o022) == 0,
       f"lock/prop target is alice-owned and not group/other-writable "
       f"(uid={os.stat(fp).st_uid if os.path.exists(fp) else -1}, mode={mode & 0o777:o})")

    # --- PROPPATCH dead-property round-trips as alice (broker setxattr + getxattr).
    pp = (b'<?xml version="1.0"?>'
          b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example">'
          b'<D:set><D:prop><Z:color>cerulean</Z:color></D:prop></D:set>'
          b'</D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/propme.txt", port, tok_alice,
                    data=pp, hdrs={"Content-Type": "application/xml"})
    st_pf, body = http("PROPFIND", "/alice/propme.txt", port, tok_alice,
                       data=b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                            b'<D:allprop/></D:propfind>',
                       hdrs={"Depth": "0", "Content-Type": "application/xml"})
    ok(st_pp in (200, 207) and b"cerulean" in (body or b""),
       f"PROPPATCH dead-property round-trips as alice via broker xattr "
       f"(PROPPATCH {st_pp}, PROPFIND {st_pf})")

    # --- LOCK acquires (broker setxattr XATTR_CREATE as alice).
    li = (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
          b'<D:lockscope><D:exclusive/></D:lockscope>'
          b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    http("PUT", "/alice/lockme.txt", port, tok_alice, b"lock target\n")
    st_l, body = http("LOCK", "/alice/lockme.txt", port, tok_alice,
                      data=li, hdrs={"Content-Type": "application/xml",
                                     "Timeout": "Second-3600"})
    ok(st_l in (200, 201) and b"locktoken" in (body or b"").lower(),
       f"LOCK as alice acquires via broker xattr (HTTP {st_l})")

    # --- DAC: bob cannot LOCK alice's 0644 file (broker fsetxattr as bob -> EACCES).
    st_b, _ = http("LOCK", "/alice/propme.txt", port, tok_bob,
                   data=li, hdrs={"Content-Type": "application/xml",
                                  "Timeout": "Second-3600"})
    ok(st_b not in (200, 201),
       f"bob CANNOT LOCK alice's file — broker enforces xattr DAC (HTTP {st_b})")

    # --- a PROPPATCH dead-property value over the 16 KiB cap must be rejected and
    #     must NOT desync the broker inbound-payload path — a following op still
    #     works (the broker bounds req_data_len and drops a connection it cannot
    #     trust, so the worker reconnects cleanly).
    big = (b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:x">'
           b'<D:set><D:prop><Z:big>' + (b"A" * 20000) +
           b'</Z:big></D:prop></D:set></D:propertyupdate>')
    st_pp, _ = http("PROPPATCH", "/alice/propme.txt", port, tok_alice, data=big,
                    hdrs={"Content-Type": "application/xml"})
    st_g, body = http("GET", "/alice/propme.txt", port, tok_alice)
    ok(st_g == 200 and _has(body, b"prop target"),
       f"oversized PROPPATCH did not desync the broker; follow-up GET OK "
       f"(PROPPATCH {st_pp}, GET {st_g})")


