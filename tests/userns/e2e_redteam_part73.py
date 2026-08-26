def _rt73_segment_01(data):

    absp = lambda rel: os.path.join(data, *rel.split("/"))
    TAG_XATTR = "user.s3.tagging"
    SECRET = b"BOB-PRIVATE-SECRET"
    return absp, TAG_XATTR, SECRET


def _rt73_segment_02(TAG_XATTR):

    def disk_tag(fp):
        """The stored tag blob on disk ('' if none / unsupported / missing)."""
        try:
            return os.getxattr(fp, TAG_XATTR)
        except OSError:
            return b""
    return disk_tag


def _rt73_segment_03():

    def stat_triple(fp):
        try:
            s = os.stat(fp)
            return (s.st_uid, s.st_gid, s.st_mode & 0o777)
        except OSError:
            return (-1, -1, -1)
    return stat_triple


def _rt73_probe_whether_the_export_fs_stores(absp, s3port):

    # Probe whether the export FS stores user.* xattrs at all (overlay/tmpfs may
    # silently drop them).  If not, the on-disk tag assertions degrade to "no xattr
    # present" which is still the correct security outcome (no cross-tenant write).
    xattr_fs_ok = False
    probe = absp("alice")
    try:
        os.setxattr(probe, "user.s3probe", b"1")
        xattr_fs_ok = os.getxattr(probe, "user.s3probe") == b"1"
        os.removexattr(probe, "user.s3probe")
    except OSError:
        xattr_fs_ok = False

    # ============================================================== (A) ===
    # CANNED ACL is target-oblivious.  GET ?acl on alice's own object, bob's 0600
    # private.txt, bob's 0700 bobsecret/ child, and a NONEXISTENT key must ALL
    # return 200 with a byte-IDENTICAL AccessControlPolicy -- proving the handler
    # never opens / stats / discriminates the target (no existence oracle, no
    # cross-tenant disclosure).  bob's secret bytes / path must never appear.
    s3("PUT", "alice/acl_own.txt", s3port, data=b"ACL-OWN-BODY\n")
    acl_docs = {}
    return xattr_fs_ok, acl_docs


def _rt73_acl_outcome_ok(st, body, SECRET):
    """One GET ?acl outcome is acceptable iff it is a canned 200 ACL doc OR a
    gated 403/404 — and NEITHER leaks the target's bytes/path/secret."""
    for needle in (SECRET, b'bob-only', b'bobsecret', b'private.txt'):
        if needle in body:
            return False
    if st in (403, 404):
        return True
    return st == 200 and b'<AccessControlPolicy' in body


def _rt73_the_canned_owner_is_a_fixed(s3port, acl_docs, SECRET):
    acl_targets = [
        ("alice/acl_own.txt", "own object"),
        ("bob/private.txt", "bob 0600 (inaccessible)"),
        ("bobsecret/s.txt", "bob 0700-dir child (inaccessible)"),
        ("alice/does_not_exist_zzz.txt", "nonexistent key"),
    ]
    # brix DELIBERATELY runs GetObjectAcl behind the object gate: it stats the key
    # as the mapped user and answers 404 NoSuchKey for a missing / inaccessible one
    # rather than minting a FULL_CONTROL grant for a nonexistent object (see
    # src/protocols/s3/tagging.c A-3/T3 -- AWS-compatible, and consistent with the
    # object GET/HEAD gate which already reveals existence the same way).  So the
    # security property we hold is not "target-oblivious 200 for everything" but:
    # neither outcome (a canned 200 doc OR a gated 403/404) may leak the target's
    # bytes / path / secret.
    for relkey, label in acl_targets:
        st, b = s3("GET", relkey, s3port, params={"acl": ""})
        b = b or b""
        acl_docs[relkey] = b
        ok(_rt73_acl_outcome_ok(st, b, SECRET),
           f"S3 GET ?acl on {label} -> canned ACL or gated NoSuchKey, no target "
           f"bytes/path/secret leaked (HTTP {st})")

    _rt73_check_canned_doc(acl_docs)


def _rt73_check_canned_doc(acl_docs):
    # The canned doc that IS produced (for the keys that resolve) is a FIXED gateway
    # document -- byte-identical, so no per-object ACL discloses ownership.
    base_doc = acl_docs.get("alice/acl_own.txt", b"")
    canned_docs = [d for d in acl_docs.values() if b'<AccessControlPolicy' in d]
    ok(all((base_doc != b'', all((d == base_doc for d in canned_docs)))),
       "S3 GET ?acl canned doc is byte-identical across the keys that resolve "
       "(fixed gateway Owner -- no per-object identity oracle)")

    # The canned Owner is a FIXED gateway identity, NOT the named target tenant --
    # so the ACL cannot be used to confirm who owns 'bob/private.txt'.
    ok(all((b'<Owner>' in base_doc, b'FULL_CONTROL' in base_doc, b'bob' not in base_doc.split(b'</Owner>')[0])),
       "S3 GET ?acl Owner is the gateway identity, never the target tenant (no "
       "ownership disclosure)")


def _rt73_b(absp, disk_tag, s3port, SECRET):

    # ============================================================== (B) ===
    # GET ?tagging is the DAC-gated counterpart: it opens bob's 0600 private.txt as
    # the impersonated mapped user (alice) -- bob's mode denies the broker open ->
    # NoSuchKey 404, no secret, and NO tag xattr is fabricated on bob's file.
    bpriv = absp("bob/private.txt")
    priv_tag_before = disk_tag(bpriv)
    st, b = s3("GET", "bob/private.txt", s3port, params={"tagging": ""})
    ok(all((st in (403, 404), SECRET not in any((b, b'')))),
       f"S3 alice GET ?tagging on bob's 0600 DENIED (broker open as alice fails), "
       f"no secret (HTTP {st})")
    ok(disk_tag(bpriv) == priv_tag_before,
       "S3 GET ?tagging on bob's 0600 created no tag xattr on bob's file")
    return bpriv


def _rt73_c(absp, stat_triple, s3port):

    # ============================================================== (C) ===
    # OWN-OBJECT round-trip: alice PUTs a tag set on her OWN object, then GETs it.
    # This exercises whether the worker (svc) can fsetxattr the broker-opened fd for
    # the LEGITIMATE owner.  Whatever the result, the object's owner/mode must be
    # unchanged (no privilege bleed) and any stored xattr must reflect alice's tag,
    # never svc-owned side state.
    own = absp("alice/acl_own.txt")
    own_before = stat_triple(own)
    put_tag = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
               b'<Key>team</Key><Value>ALICE-TAG</Value></Tag></TagSet></Tagging>')
    stp, _ = s3("PUT", "alice/acl_own.txt", s3port, params={"tagging": ""},
                data=put_tag)
    own_after = stat_triple(own)
    return own, own_before, stp, own_after


def _rt73_if_the_store_succeeded_the_tag(own_after, own_before, stp, s3port, xattr_fs_ok, disk_tag, own, absp, stat_triple):
    ok(all((own_after == own_before, own_after[0] == UID_ALICE)),
       f"S3 PUT ?tagging on own object never changes object owner/mode "
       f"(stays {UID_ALICE}:{own_before[1]} {own_before[2]:o}, HTTP {stp})")
    stg, gb = s3("GET", "alice/acl_own.txt", s3port, params={"tagging": ""})
    if stp == 200:
        # If the store succeeded, the tag must round-trip in the GET XML and be the
        # value alice supplied -- and on disk (when the FS keeps user.* xattrs) the
        # blob is alice's tag, not anything svc-authored.
        ok(all((stg == 200, b'ALICE-TAG' in any((gb, b'')), b'team' in any((gb, b'')))),
           f"S3 PUT->GET ?tagging round-trips alice's own tag set (PUT {stp}, GET {stg})")
        ok(any((not xattr_fs_ok, b'ALICE-TAG' in disk_tag(own))),
           "S3 own-object tag is persisted in the object's user.s3.tagging xattr")
    else:
        # Store failed (e.g. svc-as-worker cannot fsetxattr the owner's file) --
        # acceptable as long as it failed CLOSED (no partial svc-owned artifact) and
        # the object is intact.
        ok(all((stp in (403, 404, 500, 501), own_after == own_before)),
           f"S3 PUT ?tagging on own object failed closed, object intact (HTTP {stp})")
        ok(any((disk_tag(own) == b'', b'svc' not in disk_tag(own))),
           "S3 failed own-object tag left no svc-authored xattr")

    # ============================================================== (D) ===
    # THE KEY BUG HUNT -- write-as-worker on a READABLE-but-NOT-WRITABLE foreign
    # file.  bob/readable.txt is 0644 owned by bob: alice CAN read it (so the
    # brokered O_RDONLY open SUCCEEDS) but alice CANNOT write it.  A correct
    # impersonation boundary takes the xattr-WRITE DAC decision as alice -> DENY.
    # The bug class: tagging.c does the fsetxattr from the worker (svc) on the
    # broker-passed fd, so the write may be evaluated against svc's creds instead of
    # alice's.  Assert the op is DENIED *and* -- the real proof -- that NO tag xattr
    # landed on bob's file and bob's owner/mode/bytes are byte-for-byte unchanged.
    bread = absp("bob/readable.txt")
    bread_before_stat = stat_triple(bread)
    return bread, bread_before_stat


def _rt73_segment_09(bread, disk_tag, s3port):
    bread_before_bytes = open(bread, "rb").read() if os.path.exists(bread) else None
    bread_tag_before = disk_tag(bread)
    cross_tag = (b'<?xml version="1.0"?><Tagging><TagSet><Tag>'
                 b'<Key>pwn</Key><Value>ALICE-WROTE-THIS</Value>'
                 b'</Tag></TagSet></Tagging>')
    stx, _ = s3("PUT", "bob/readable.txt", s3port, params={"tagging": ""},
                data=cross_tag)
    bread_tag_after = disk_tag(bread)
    return bread_before_bytes, bread_tag_before, cross_tag, stx, bread_tag_after


def _rt73_security_verdict_a_real_write_as(bread_tag_after, stx, stat_triple, bread, bread_before_stat, bread_before_bytes, s3port, disk_tag, bread_tag_before):
    # Security verdict: a real write-as-worker breach is a tag xattr appearing on
    # bob's file that alice authored.  That is the ONLY hard failure here.
    ok(b"ALICE-WROTE-THIS" not in bread_tag_after,
       f"S3 alice PUT ?tagging on bob's 0644 file did NOT write a tag xattr as the "
       f"worker (no cross-tenant xattr breach, HTTP {stx})")
    ok(stx in (403, 404, 500, 501),
       f"S3 alice PUT ?tagging on bob's 0644 (readable, not writable) is rejected, "
       f"not 200 (HTTP {stx})")
    ok(all((stat_triple(bread) == bread_before_stat, (open(bread, 'rb').read() if os.path.exists(bread) else None) == bread_before_bytes)),
       "S3 cross-tenant PUT ?tagging left bob's file owner/mode/bytes unchanged")

    # DELETE ?tagging is the removexattr-as-worker mirror: alice DELETE ?tagging on
    # bob's 0644 file must not remove/alter bob's xattrs.  (If a tag existed it must
    # survive; either way bob's file is untouched.)
    std, _ = s3("DELETE", "bob/readable.txt", s3port, params={"tagging": ""})
    ok(all((disk_tag(bread) == bread_tag_before, stat_triple(bread) == bread_before_stat)),
       f"S3 alice DELETE ?tagging on bob's 0644 did not remove/alter bob's xattrs "
       f"or file metadata (HTTP {std})")


def _rt73_cross_tenant_tag_on_bob_s(s3port, cross_tag, disk_tag, bpriv, SECRET):

    # Cross-tenant tag on bob's 0600 (open itself denied) -- the simpler deny, but a
    # distinct DAC gate (open-time, not xattr-time) and on-disk no-write proof.
    stp6, _ = s3("PUT", "bob/private.txt", s3port, params={"tagging": ""},
                 data=cross_tag)
    ok(all((stp6 in (403, 404, 500, 501), b'ALICE-WROTE-THIS' not in disk_tag(bpriv), open(bpriv, 'rb').read() == SECRET + b'\n')),
       f"S3 alice PUT ?tagging on bob's 0600 DENIED at open, no xattr, secret "
       f"intact (HTTP {stp6})")

    # ============================================================== (E) ===
    # MALFORMED / OVERSIZED tag XML on alice's OWN object: the libxml2 parser
    # (s3_tag_blob_from_xml) + S3_TAG_XML_MAX cap must reject cleanly (4xx) without
    # crashing the worker, fabricating an svc artifact, or storing a partial blob.
    own2 = "alice/acl_own.txt"
    malformed = [
        (b"<Tagging><TagSet><Tag><Key>k", "truncated XML"),
        (b"not xml at all <<<>>>", "non-XML garbage"),
        (b'<?xml version="1.0"?><NotTagging/>', "wrong root element"),
        (b'<?xml version="1.0"?><Tagging><TagSet><Tag><Key>' + b"A" * 9000
         + b"</Key><Value>v</Value></Tag></TagSet></Tagging>", "oversized (>8KiB) body"),
    ]
    for body, label in malformed:
        st, _ = s3("PUT", own2, s3port, params={"tagging": ""},
                   data=body[:64 * 1024])
        ok(st in (400, 413, 403, 500),
           f"S3 PUT ?tagging with {label} rejected 4xx/5xx cleanly (HTTP {st})")


def _rt73_the_malformed_sweep_must_not_have(stat_triple, own, s3port):
    # The malformed sweep must not have left a svc artifact: object still alice's.
    ok(stat_triple(own)[0] == UID_ALICE,
       "S3 object survived malformed-tagging sweep still owned by alice")

    # ============================================================== (F) ===
    # WORKER LIVENESS: after the ACL + tagging + malformed sweep the worker still
    # serves a clean request as alice (no crash / connection wedge).
    st, b = s3("GET", "alice/acl_own.txt", s3port)
    ok(all((st == 200, b'ACL-OWN-BODY' in any((b, b'')))),
       f"S3 worker survived acl/tagging DAC sweep (follow-up GET OK, HTTP {st})")


def run_s3_acl_tagging_dac(key, data, port, s3port):
    """S3 GetObjectAcl + Object Tagging (src/protocols/s3/tagging.c, phase-43 W5) DAC under
    per-request impersonation.

    Two distinct sub-surfaces, neither asserted by run_s3_subresource_fallthrough
    (which only checks ?acl/?tagging on bob's *0600* file + own-object fall-through
    ownership) or run_protocol_features_s3 / run_s3_deep:

      1. s3_handle_get_acl returns a CANNED owner-FULL_CONTROL ACL templated on the
         SERVER's configured identity (cf->access_key), WITHOUT opening the object.
         So it answers 200 for ANY key -- existing, inaccessible, or nonexistent.
         The invariant under attack: that canned doc must disclose NOTHING about the
         TARGET (no bytes, no path, not even existence), and must be byte-identical
         regardless of which key/tenant is named.  (Borderline authz nit: a real
         GetObjectAcl SHOULD 403/404 an inaccessible key -- documented, not failed.)

      2. Object tagging GET/PUT/DELETE /<key>?tagging DOES touch the object: it opens
         it via the brokered brix_open_confined_canon (DAC-checked as the MAPPED
         user) but then performs the xattr op (fgetxattr/fsetxattr/fremovexattr) on
         the broker-passed fd FROM THE WORKER (svc, uid 1500) -- NOT via the brokered
         brix_{set,get,remove}xattr_confined_canon wrappers the WebDAV
         LOCK/PROPPATCH path (run_lock_proppatch) correctly uses.  This is the
         "non-brokered-xattr class": a tag op on a file the requester can READ but
         not WRITE (bob's 0644 readable.txt accessed by alice) takes its xattr-write
         DAC decision as svc, not as the mapped user.  The security invariant: a
         cross-tenant PUT/DELETE ?tagging must NEVER land an xattr on another tenant's
         file, and the object's on-disk owner/mode/bytes must be unchanged."""
    if not s3port:
        ok(True, "S3 port not configured -- acl/tagging DAC suite skipped (handled)")
        return
    absp, TAG_XATTR, SECRET = _rt73_segment_01(data)

    disk_tag = _rt73_segment_02(TAG_XATTR)

    stat_triple = _rt73_segment_03()

    xattr_fs_ok, acl_docs = _rt73_probe_whether_the_export_fs_stores(absp, s3port)

    _rt73_the_canned_owner_is_a_fixed(s3port, acl_docs, SECRET)

    bpriv = _rt73_b(absp, disk_tag, s3port, SECRET)

    own, own_before, stp, own_after = _rt73_c(absp, stat_triple, s3port)

    bread, bread_before_stat = _rt73_if_the_store_succeeded_the_tag(own_after, own_before, stp, s3port, xattr_fs_ok, disk_tag, own, absp, stat_triple)

    bread_before_bytes, bread_tag_before, cross_tag, stx, bread_tag_after = _rt73_segment_09(bread, disk_tag, s3port)

    _rt73_security_verdict_a_real_write_as(bread_tag_after, stx, stat_triple, bread, bread_before_stat, bread_before_bytes, s3port, disk_tag, bread_tag_before)

    _rt73_cross_tenant_tag_on_bob_s(s3port, cross_tag, disk_tag, bpriv, SECRET)

    _rt73_the_malformed_sweep_must_not_have(stat_triple, own, s3port)

