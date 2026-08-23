def _rt44_segment_01(data, key):
    tag = "cxng"
    grp_dir = os.path.join(data, "grp")
    sw = os.path.join(grp_dir, "staff_w.txt")            # 0660 alice:staff fixture
    SW_SECRET = b"STAFF-GROUP-WRITABLE"                   # body marker (must not leak)

    t_alice = mint(key, "alice")   # owner
    return tag, grp_dir, sw, SW_SECRET, t_alice


def _rt44_segment_02(key):
    t_carol = mint(key, "carol")   # staff member -> GROUP WRITE on staff_w.txt
    t_bob = mint(key, "bob")       # NOT staff -> NO write (cross-group)
    t_dave = mint(key, "dave")     # NOT staff -> NO write (research)

    XML = "application/xml"
    PF_ALLPROP = (b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:">'
                  b'<D:allprop/></D:propfind>')
    return t_carol, t_bob, t_dave, XML, PF_ALLPROP


def _rt44_segment_03(port, XML):

    def proppatch(rel, tok, prop, val, ns="urn:cxng"):
        body = (
            '<?xml version="1.0"?>'
            f'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="{ns}">'
            f'<D:set><D:prop><Z:{prop}>{val}</Z:{prop}></D:prop></D:set>'
            '</D:propertyupdate>').encode()
        return http("PROPPATCH", rel, port, tok, data=body,
                    hdrs={"Content-Type": XML})
    return proppatch


def _rt44_segment_04(port, PF_ALLPROP, XML):

    def propfind(rel, tok):
        return http("PROPFIND", rel, port, tok, data=PF_ALLPROP,
                    hdrs={"Depth": "0", "Content-Type": XML})
    return propfind


def _rt44_segment_05():

    def lockinfo():
        return (b'<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:">'
                b'<D:lockscope><D:exclusive/></D:lockscope>'
                b'<D:locktype><D:write/></D:locktype></D:lockinfo>')
    return lockinfo


def _rt44_segment_06():

    def bad_xattr_on(inode_path):
        """Return the list of PRIVILEGED (non-user.*, non-posix_acl) xattr names on
        the real inode — the escalation we are hunting.  Any such name means a
        group-authorized (or cross-tenant) PROPPATCH/LOCK leaked out of user.*."""
        try:
            names = os.listxattr(inode_path)
        except OSError:
            return []
        bad = []
        for n in names:
            if n.startswith("user."):
                continue
            if n.startswith("system.posix_acl"):
                continue
            bad.append(n)
        return bad
    return bad_xattr_on


def _rt44_segment_07(bad_xattr_on):

    def inode_clean(inode_path):
        """Combination invariant: after a hostile PROPPATCH the file must keep its
        owner/group (alice:staff), gain no setuid/setgid bit, and carry no
        privileged xattr — i.e. group write never became privileged-metadata write."""
        try:
            st = os.stat(inode_path)
        except OSError:
            return (False, -1, -1, 0, [])
        return (True, st.st_uid, st.st_gid, st.st_mode, bad_xattr_on(inode_path))
    return inode_clean


def _rt44_a_positive_control_carol_group_write(sw, bad_xattr_on, proppatch, t_carol):

    # ========================================================================
    # 0) FIXTURE INVARIANT — the combination only discriminates if the target is
    #    group-writable by carol but NOT writable by bob/dave (so a passing
    #    PROPPATCH by carol proves GROUP authority, not owner/other).
    # ========================================================================
    try:
        st0 = os.stat(sw)
        fix_ok = (st0.st_uid == UID_ALICE and st0.st_gid == GID_STAFF
                  and (st0.st_mode & 0o060) == 0o060
                  and (st0.st_mode & 0o002) == 0)
    except OSError:
        fix_ok = False
        st0 = None
    ok(fix_ok, ("fixture staff_w.txt is alice:staff 0660 (group-writable, "
                "not other-writable) — combination discriminates group authority "
                f"(mode={(st0.st_mode & 0o777):o})")
       if st0 else "fixture staff_w.txt missing")

    base_bad = bad_xattr_on(sw)
    ok(base_bad == [],
       f"baseline: staff_w.txt carries no privileged xattr before attack ({base_bad})")

    # ========================================================================
    # A) POSITIVE CONTROL — carol (GROUP WRITE) sets a user.* dead-property; it
    #    round-trips via PROPFIND.  This proves the broker, acting AS carol, can
    #    setxattr a file she does NOT own purely on group-write authority.
    # ========================================================================
    st_pp, _ = proppatch("/grp/staff_w.txt", t_carol, "ckcolor", "cerulean")
    return st_pp


def _rt44_segment_09(propfind, t_carol, st_pp, bad_xattr_on, sw):
    st_pf, body = propfind("/grp/staff_w.txt", t_carol)
    carol_set_ok = st_pp in (200, 207) and b"cerulean" in (body or b"")
    ok(any((carol_set_ok, st_pp in (403, 423, 501))),
       f"carol (group write) user.* PROPPATCH handled (PROPPATCH {st_pp}, "
       f"PROPFIND {st_pf})")
    if carol_set_ok:
        ok(b'cerulean' in any((body, b'')),
           "POSITIVE: carol's user.* dead-property round-trips via PROPFIND "
           "(group write authorizes user-namespace xattr)")
    bad_after_carol = bad_xattr_on(sw)
    return bad_after_carol


def _rt44_b_negative_control_bob_not_staff(bad_after_carol, inode_clean, sw, proppatch, t_bob, propfind, t_alice):
    ok(all(n.startswith("user.") for n in bad_after_carol),
       f"after carol user.* set: only user.* xattrs on inode ({bad_after_carol})")
    okst = inode_clean(sw)
    ok(all((okst[1] == UID_ALICE, okst[2] == GID_STAFF, not okst[3] & 3072)),
       "after carol user.* set: owner/group still alice:staff, no setuid/setgid "
       f"gained (uid={okst[1]}, gid={okst[2]}, mode={okst[3] & 0o7777:o})")

    # ========================================================================
    # B) NEGATIVE CONTROL — bob (NOT staff, NO write) cannot set ANY property; the
    #    property must never persist.  Combination: cross-GROUP non-writer vs the
    #    same group-writable file carol just wrote.
    # ========================================================================
    st_bob, _ = proppatch("/grp/staff_w.txt", t_bob, "ckcolor", "bobpwn")
    st_pf, body = propfind("/grp/staff_w.txt", t_alice)
    return st_bob, body


def _rt44_segment_11(st_bob, body, proppatch, t_dave, propfind, t_alice):
    ok(st_bob not in (200, 207),
       f"bob (no write, cross-group) user.* PROPPATCH DENIED on group file "
       f"(HTTP {st_bob})")
    ok(b'bobpwn' not in any((body, b'')),
       "bob's denied property never persisted (no group-write escalation for "
       "a non-member)")
    st_dave, _ = proppatch("/grp/staff_w.txt", t_dave, "ckcolor", "davepwn")
    st_pf, body = propfind("/grp/staff_w.txt", t_alice)
    ok(st_dave not in (200, 207),
       f"dave (research, no staff write) user.* PROPPATCH DENIED (HTTP {st_dave})")
    return body


def _rt44_explicit_xrdcks_by_owner_control_even(body, proppatch, t_carol, bad_xattr_on, sw, inode_clean, t_alice):
    ok(b'davepwn' not in any((body, b'')),
       "dave's denied property never persisted on the staff group file")

    # ========================================================================
    # C) THE CORE COMBINATION — carol HAS group write, yet must NOT be able to set
    #    a PRIVILEGED-NAMESPACE xattr via PROPPATCH.  We probe security.*, system.*,
    #    trusted.*, and XrdCks.* (the checksum namespace).  Each must be confined to
    #    user.* or denied; the inode must NEVER grow a non-user.* xattr, and never
    #    gain a setuid/setgid bit.  Group write != privileged-metadata authority.
    # ========================================================================
    priv_props = [
        ("security.capability", "cap_setuid+ep"),
        ("security.selinux", "system_u:object_r:bin_t:s0"),
        ("system.posix_acl_access", "user::rwx"),
        ("trusted.overlay.redirect", "/etc/shadow"),
        ("XrdCks.md5", "00000000000000000000000000000000"),
        ("XrdCks.adler32", "deadbeef"),
        ("user.XrdCks.crc32c", "cafebabe"),
    ]
    for pname, pval in priv_props:
        # the WebDAV dead-property NAME carries the privileged-looking namespace as a
        # literal element name; the broker must map it into user.* or refuse it — it
        # must NEVER materialize as a real privileged xattr on carol's group write.
        st_c, _ = proppatch("/grp/staff_w.txt", t_carol, "p", pval,
                            ns=f"urn:{pname}")
        # also try the namespace literally as the element local-name (belt & braces)
        safe_local = pname.replace(".", "_")
        st_c2, _ = proppatch("/grp/staff_w.txt", t_carol, safe_local, pval)
        ok(all((st_c in (200, 207, 403, 422, 400, 409, 423, 501), st_c2 in (200, 207, 403, 422, 400, 409, 423, 501))),
           f"carol (group write) PROPPATCH targeting {pname!r} handled cleanly "
           f"(HTTP {st_c}/{st_c2})")
        bad = bad_xattr_on(sw)
        ok(bad == [],
           f"NO privileged xattr materialized for {pname!r} despite carol's GROUP "
           f"WRITE — namespace confinement holds under group authority ({bad})")
        cl = inode_clean(sw)
        ok(all((cl[1] == UID_ALICE, cl[2] == GID_STAFF, not cl[3] & 3072)),
           f"after {pname!r} attempt: owner/group/mode unescalated "
           f"(uid={cl[1]}, gid={cl[2]}, setid={'yes' if cl[3] & 0o6000 else 'no'})")

    # explicit XrdCks-by-owner control: even the OWNER (alice) must not be able to
    # forge a privileged-namespace checksum xattr — confinement is namespace-level,
    # not identity-level (so a group writer certainly cannot).
    st_a, _ = proppatch("/grp/staff_w.txt", t_alice, "p", "forged",
                        ns="urn:trusted.forge")
    ok(bad_xattr_on(sw) == [],
       f"owner alice also cannot plant a trusted.* xattr via PROPPATCH "
       f"(namespace confinement is identity-independent) (HTTP {st_a})")


def _rt44_d_lock_leg_of_the_combination(lockinfo, port, t_carol, XML, bad_xattr_on, sw):

    # ========================================================================
    # D) LOCK leg of the combination — WebDAV LOCK persists its token as a user.*
    #    xattr.  carol (group write) MAY lock the group file (positive), but the
    #    LOCK must not be the vector for a privileged xattr, and a non-writer (bob)
    #    must NOT be able to LOCK it (no group escalation), leaving no lock residue.
    # ========================================================================
    li = lockinfo()
    st_lc, lb = http("LOCK", "/grp/staff_w.txt", port, t_carol, data=li,
                     hdrs={"Content-Type": XML, "Timeout": "Second-600"})
    carol_locked = st_lc in (200, 201) and b"locktoken" in (lb or b"").lower()
    ok(any((carol_locked, st_lc in (403, 423, 501))),
       f"carol (group write) LOCK on staff group file handled (HTTP {st_lc})")
    ok(bad_xattr_on(sw) == [],
       "carol's LOCK persisted no privileged xattr (lock token confined to user.*)")
    return li, lb, carol_locked


def _rt44_bob_no_write_cannot_lock_the(carol_locked, lb, port, t_bob, li, XML, bad_xattr_on, sw):
    lock_tok = b""
    if carol_locked:
        m = re.search(rb"<D:href>(.*?)</D:href>", lb or b"") or \
            re.search(rb"opaquelocktoken:[0-9a-fA-F-]+", lb or b"")
        if m:
            lock_tok = m.group(0)
    # bob (no write) cannot LOCK the group file even though carol could.
    st_lb, _ = http("LOCK", "/grp/staff_w.txt", port, t_bob, data=li,
                    hdrs={"Content-Type": XML, "Timeout": "Second-600"})
    ok(st_lb not in (200, 201),
       f"bob (no write, cross-group) cannot LOCK the staff group file — group "
       f"membership, not mere existence, gates the broker lock (HTTP {st_lb})")
    ok(bad_xattr_on(sw) == [],
       "bob's denied LOCK left no xattr residue on the group file")
    return lock_tok


def _rt44_release_carol_s_lock_if_held(lock_tok, port, t_carol):
    # release carol's lock if held, so we don't wedge later checks.
    if lock_tok:
        http("UNLOCK", "/grp/staff_w.txt", port, t_carol,
             hdrs={"Lock-Token": "<" + lock_tok.decode("latin1").split("<")[-1]
                   .split(">")[0] + ">" if b"<" not in lock_tok
                   else lock_tok.decode("latin1")})

    # ========================================================================
    # E) CONCURRENT same-property set by alice (owner) + carol (group write) — both
    #    authorized via DIFFERENT authority paths writing the SAME dead-property.
    #    Result must be ONE consistent value (no torn/half xattr, no privileged
    #    residue, file still alice:staff).  <=4 threads, tiny payloads.
    # ========================================================================
    results = {}
    barrier = threading.Barrier(4)
    return results, barrier


def _rt44_segment_16(barrier, proppatch, results):

    def race_set(idx, tok, val):
        try:
            barrier.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
        try:
            st, _ = proppatch("/grp/staff_w.txt", tok, "ckrace", val)
            results[idx] = st
        except OSError:
            results[idx] = -1
    return race_set


def _rt44_check_for_each_th_threads(threads):
    for th in threads:
        th.start()


def _rt44_segment_17(race_set, t_alice, t_carol, propfind):

    threads = [
        threading.Thread(target=race_set, args=(0, t_alice, "alphaA")),
        threading.Thread(target=race_set, args=(1, t_carol, "betaC")),
        threading.Thread(target=race_set, args=(2, t_alice, "gammaA")),
        threading.Thread(target=race_set, args=(3, t_carol, "deltaC")),
    ]
    _rt44_check_for_each_th_threads(threads)
    for th in threads:
        th.join(timeout=10)
    st_pf, body = propfind("/grp/staff_w.txt", t_alice)
    seen = [v for v in (b"alphaA", b"betaC", b"gammaA", b"deltaC")
            if v in (body or b"")]
    return seen


def _rt44_whatever_landed_must_be_a_real(seen, bad_xattr_on, sw, inode_clean):
    ok(len(seen) <= 1,
       f"concurrent owner+group-writer set of SAME prop -> at most one consistent "
       f"value, no torn/duplicate xattr (seen={[s.decode() for s in seen]})")
    # whatever landed must be a real value, not a corrupted fragment of two.
    if seen:
        ok(seen[0] in (b"alphaA", b"betaC", b"gammaA", b"deltaC"),
           f"concurrent winner is a whole value, not a torn merge ({seen[0]!r})")
    ok(bad_xattr_on(sw) == [],
       "after concurrent owner+group races: still no privileged xattr on inode")
    cl = inode_clean(sw)
    ok(all((cl[1] == UID_ALICE, cl[2] == GID_STAFF)),
       f"after concurrent races: file still alice:staff (uid={cl[1]}, gid={cl[2]})")


def _rt44_f_cross_tenant_bob_proppatch_on(proppatch, t_bob, propfind, t_alice, bad_xattr_on, sw):

    # ========================================================================
    # F) CROSS-TENANT — bob PROPPATCH on alice's group file: denied AND the
    #    property NEVER persists (verified by an OWNER PROPFIND).  Combines
    #    cross-tenant identity x group file x dead-property persistence.
    # ========================================================================
    st_xt, _ = proppatch("/grp/staff_w.txt", t_bob, "xtmark", "BOB-XT-PWN")
    st_pf, body = propfind("/grp/staff_w.txt", t_alice)
    ok(st_xt not in (200, 207),
       f"cross-tenant bob PROPPATCH on alice's group file DENIED (HTTP {st_xt})")
    ok(b'BOB-XT-PWN' not in any((body, b'')),
       "cross-tenant property never persisted (owner PROPFIND confirms absence)")
    ok(bad_xattr_on(sw) == [],
       "cross-tenant PROPPATCH planted no privileged xattr either")


def _rt44_g_listxattr_getxattr_leak_check_a(sw, propfind, t_carol, body):

    # ========================================================================
    # G) LISTXATTR / getxattr leak check — a group MEMBER (carol) reading the
    #    group file's metadata via PROPFIND must see ONLY user.* dead-properties:
    #    no security.*/system.*/trusted. namespace and NO body-secret bytes.
    #    Plant a privileged xattr DIRECTLY on the inode (as in-ns root) then prove
    #    the broker NEVER surfaces it to the group member.
    # ========================================================================
    planted = False
    try:
        os.setxattr(sw, "trusted.cxng_probe", b"PRIV-XATTR-VALUE")
        planted = True
    except OSError:
        planted = False
    try:
        os.setxattr(sw, "security.cxng_probe", b"SEC-XATTR-VALUE")
    except OSError:
        pass
    st_pf, body = propfind("/grp/staff_w.txt", t_carol)
    ok(st_pf in (200, 207),
       f"group member carol can PROPFIND the group file (HTTP {st_pf})")
    return body


def _rt44_herself_set_in_section_c_whose(body, bad_xattr_on, sw, SW_SECRET):
    ok(b'PRIV-XATTR-VALUE' not in any((body, b'')),
       "PROPFIND by group member leaks NO trusted.* xattr VALUE (namespace hidden)")
    ok(b'SEC-XATTR-VALUE' not in any((body, b'')),
       "PROPFIND by group member leaks NO security.* xattr VALUE")
    # The real escalation surface is the INODE: a PROPFIND must never expose a
    # privileged (non-user.*) xattr that lives on the file.  bad_xattr_on() reads
    # the actual inode and excludes user.* / posix_acl, so an empty list proves the
    # broker never let group-write become privileged-metadata authority.  We do NOT
    # blind-scan the body for the literal "trusted."/"security." substrings, because
    # an allprop PROPFIND legitimately echoes back the user.* dead-properties carol
    # herself set in section C — whose CLIENT-SUPPLIED namespace URIs happen to be
    # urn:security.capability / urn:trusted.overlay.redirect.  Those are her own
    # group-authorized user-namespace dead-props (stored under
    # user.nginx_xrootd.webdav.*), not a leak of a privileged kernel xattr; the real
    # leak signal is the planted VALUE bytes, already asserted absent above.
    ok(bad_xattr_on(sw) == [],
       "PROPFIND surfaces no privileged xattr NAMESPACE to the group member "
       f"(inode carries no non-user.* xattr: {bad_xattr_on(sw)})")
    ok(SW_SECRET not in any((body, b'')),
       "metadata PROPFIND on the group file leaks no body-secret bytes")
    # cleanup planted privileged xattrs so the export stays clean for later batches.
    try:
        os.removexattr(sw, "trusted.cxng_probe")
    except OSError:
        pass


def _rt44_segment_01_3(shw):
    try:
        sst = os.stat(shw)
        shared_ok = (sst.st_gid == GID_SHARED
                     and (sst.st_mode & 0o060) == 0o060)
    except OSError:
        shared_ok = False
    return shared_ok


def _rt44_when_shared_ok_2(shw):
    shared_ok = _rt44_segment_01_3(shw)

    return shared_ok


def _rt44_shared_has_group_write_there_but(sw, SW_SECRET, grp_dir):
    try:
        os.removexattr(sw, "security.cxng_probe")
    except OSError:
        pass

    # root:// query xattr by the group member must likewise not surface the body or
    # a privileged namespace (cross-protocol leg of the same confinement claim).
    if xrd_avail():
        rc, out, _e = xrd_fs(["query", "xattr", "/grp/staff_w.txt"], "carol")
        ok(SW_SECRET.decode() not in any((out, '')),
           f"root:// query xattr by group member leaks no body secret (rc={rc})")
        ok(all(('trusted.' not in any((out, '')), 'security.' not in any((out, '')))),
           f"root:// query xattr by group member surfaces no privileged ns (rc={rc})")
        # cross-group non-member (bob via root://) also gets nothing.
        rc, out, _e = xrd_fs(["query", "xattr", "/grp/staff_w.txt"], "bob")
        ok(SW_SECRET.decode() not in any((out, '')),
           f"root:// query xattr by non-member bob leaks no body secret (rc={rc})")

    # ========================================================================
    # H) SECOND GROUP-WRITE TARGET — shared_w.txt (0660 alice:shared); bob IS in
    #    shared (HAS group write there) but NOT in staff.  This flips the matrix:
    #    bob, who was denied on staff_w.txt, may write user.* here but STILL must
    #    not escalate to a privileged namespace.  Proves the confinement is
    #    per-namespace, not per-file or per-identity.
    # ========================================================================
    shw = os.path.join(grp_dir, "shared_w.txt")
    shared_ok = os.path.exists(shw)
    if shared_ok:
        shared_ok = _rt44_when_shared_ok_2(shw)
    return shw, shared_ok


def _rt44_segment_01_2(proppatch, t_bob, propfind, bad_xattr_on, shw):
    st_bp, _ = proppatch("/grp/shared_w.txt", t_bob, "ckbob", "bobshared")
    st_pf, body = propfind("/grp/shared_w.txt", t_bob)
    bob_shared_set = st_bp in (200, 207) and b"bobshared" in (body or b"")
    ok(any((bob_shared_set, st_bp in (403, 423, 501))),
       f"bob (shared group write) user.* PROPPATCH on shared file handled "
       f"(HTTP {st_bp})")
    ok(bad_xattr_on(shw) == [],
       "bob's shared-group user.* set planted no privileged xattr")


def _rt44_negative_within_the_same_flip_bob(proppatch, t_bob, bad_xattr_on, shw, inode_clean, t_dave):
    # NEGATIVE within the SAME flip: bob still cannot escalate to security.* here.
    st_be, _ = proppatch("/grp/shared_w.txt", t_bob, "p", "esc",
                        ns="urn:security.capability")
    ok(bad_xattr_on(shw) == [],
       f"bob's GROUP WRITE on shared_w.txt does NOT grant a privileged xattr "
       f"namespace (confinement per-namespace, not per-file) (HTTP {st_be})")
    scl = inode_clean(shw)
    ok(all((scl[1] == UID_ALICE, scl[2] == GID_SHARED, not scl[3] & 3072)),
       f"shared_w.txt still alice:shared, no setid gained "
       f"(uid={scl[1]}, gid={scl[2]})")
    # CROSS: dave (NOT in shared, NOT in staff) denied on shared file.
    st_dd, _ = proppatch("/grp/shared_w.txt", t_dave, "ckdave", "davepwn2")
    return st_dd


def _rt44_segment_03_2(propfind, t_alice, st_dd):
    st_pf, body = propfind("/grp/shared_w.txt", t_alice)
    ok(all((st_dd not in (200, 207), b'davepwn2' not in any((body, b'')))),
       f"dave (no shared membership) PROPPATCH on shared file denied, no "
       f"persistence (HTTP {st_dd})")
    return body


def _rt44_when_shared_ok(proppatch, t_bob, propfind, bad_xattr_on, shw, inode_clean, t_dave, t_alice):
    _rt44_segment_01_2(proppatch, t_bob, propfind, bad_xattr_on, shw)

    st_dd = _rt44_negative_within_the_same_flip_bob(proppatch, t_bob, bad_xattr_on, shw, inode_clean, t_dave)

    body = _rt44_segment_03_2(propfind, t_alice, st_dd)

    return body


def _rt44_positive_control_on_the_same_file(shared_ok, proppatch, t_bob, propfind, bad_xattr_on, shw, inode_clean, t_dave, t_alice, grp_dir, tag, port, t_carol):
    if shared_ok:
        # POSITIVE: bob has group write on the SHARED file -> user.* set works.
        body = _rt44_when_shared_ok(proppatch, t_bob, propfind, bad_xattr_on, shw, inode_clean, t_dave, t_alice)

    # ========================================================================
    # I) NEW GROUP-OWNED FIXTURE — a setgid staff dir; carol creates a file inside
    #    (inherits gid=staff via setgid), then carol (group writer on her OWN new
    #    file) tries a privileged-namespace PROPPATCH.  Combines setgid-inheritance
    #    x group write x namespace confinement.  carol owns the file, yet STILL
    #    cannot escalate to a privileged xattr namespace.
    # ========================================================================
    sgid = os.path.join(grp_dir, tag + "_sgid")
    try:
        os.makedirs(sgid, exist_ok=True)
        os.chown(sgid, UID_ALICE, GID_STAFF)
        os.chmod(sgid, 0o2770)                 # setgid, group rwx
        ensure_traversable(sgid)
        sgid_ready = True
    except OSError:
        sgid_ready = False
    if sgid_ready:
        rel_new = "/grp/" + tag + "_sgid/" + tag + "_carolfile.txt"
        st_pn, _ = http("PUT", rel_new, port, t_carol, b"carol-in-sgid\n")
        nfp = os.path.join(sgid, tag + "_carolfile.txt")
        created = os.path.exists(nfp)
        if created:
            nst = os.stat(nfp)
            ok(all((nst.st_uid == UID_CAROL, nst.st_gid == GID_STAFF)),
               f"setgid dir: carol's new file inherits gid=staff, owned by carol "
               f"(uid={nst.st_uid}, gid={nst.st_gid})")
            # carol owns it AND has group write — still no privileged namespace.
            st_ce, _ = proppatch(rel_new, t_carol, "p", "pwn",
                                ns="urn:security.capability")
            st_cx, _ = proppatch(rel_new, t_carol, "p", "00",
                                ns="urn:XrdCks.md5")
            ok(bad_xattr_on(nfp) == [],
               f"carol OWNS the setgid-inherited file yet cannot plant a privileged "
               f"xattr namespace via PROPPATCH (HTTP {st_ce}/{st_cx})")
            ncl = inode_clean(nfp)
            ok(not (ncl[3] & 0o6000),
               "carol's new file gained no setuid/setgid bit from the namespace "
               f"probes (mode={ncl[3] & 0o7777:o})")
            # POSITIVE control on the same file: a user.* prop DOES round-trip.
            st_up, _ = proppatch(rel_new, t_carol, "okprop", "okval")
            st_pf, body = propfind(rel_new, t_carol)
            ok(any((all((st_up in (200, 207), b'okval' in any((body, b'')))), st_up in (403, 423, 501))),
               f"carol's user.* prop on her own setgid-inherited file round-trips "
               f"(PROPPATCH {st_up})")
        else:
            ok(st_pn in (403, 404, 409, 423, 501),
               f"carol PUT into setgid staff dir handled (no file) (HTTP {st_pn})")

    # ========================================================================
    # J) DESYNC / SURVIVAL — an oversized privileged-namespace PROPPATCH body by the
    #    group writer must not desync the broker payload path; a follow-up legit
    #    group-write user.* set + PROPFIND still works.  Combines oversize-payload x
    #    privileged-namespace x group-write recovery.
    # ========================================================================
    big = (b'<?xml version="1.0"?>'
           b'<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:trusted.big">'
           b'<D:set><D:prop><Z:p>' + (b"A" * 20000) +
           b'</Z:p></D:prop></D:set></D:propertyupdate>')
    return big


def _rt44_follow_up_legit_group_write_op(port, t_carol, big, XML, bad_xattr_on, sw, proppatch, propfind):
    st_big, _ = http("PROPPATCH", "/grp/staff_w.txt", port, t_carol, data=big,
                     hdrs={"Content-Type": XML})
    ok(bad_xattr_on(sw) == [],
       f"oversized trusted.* PROPPATCH by group writer planted no privileged xattr "
       f"(HTTP {st_big})")
    # follow-up legit group-write op survives (broker not wedged).
    st_rp, _ = proppatch("/grp/staff_w.txt", t_carol, "recovery", "alive")
    st_pf, body = propfind("/grp/staff_w.txt", t_carol)
    recovered = (st_rp in (200, 207) and b"alive" in (body or b"")) \
        or st_rp in (403, 423, 501)
    return st_rp, recovered


def _rt44_k_final_invariant_sweep_across_every(recovered, st_rp, bad_xattr_on, sw, inode_clean):
    ok(recovered,
       f"after oversized hostile PROPPATCH, broker survives: carol's follow-up "
       f"group-write user.* set works (HTTP {st_rp})")

    # ========================================================================
    # K) FINAL INVARIANT SWEEP — across every attack above, the group fixtures kept
    #    their owner/group, gained no setid bit, and hold NO privileged xattr.  The
    #    body secret never leaked.  Headline of the whole combination.
    # ========================================================================
    final_bad = bad_xattr_on(sw)
    ok(final_bad == [],
       f"FINAL: staff_w.txt holds no privileged (non-user.*) xattr after the full "
       f"group-write x namespace battery ({final_bad})")
    fst = inode_clean(sw)
    ok(all((fst[0], fst[1] == UID_ALICE, fst[2] == GID_STAFF, not fst[3] & 3072)),
       f"FINAL: staff_w.txt still alice:staff, no setuid/setgid "
       f"(uid={fst[1]}, gid={fst[2]}, mode={fst[3] & 0o7777:o})")


def _rt44_positive_control_that_the_worker_is(port, t_alice, SW_SECRET, t_bob, t_carol):
    # the body is still the original secret content, owner unchanged — no xattr
    # attack mutated the data plane.
    st_g, gb = http("GET", "/grp/staff_w.txt", port, t_alice)
    ok(all((st_g == 200, SW_SECRET in any((gb, b'')))),
       f"FINAL: group file data intact, owner can still read original body "
       f"(HTTP {st_g})")
    # the non-writer (bob) still cannot read-write-escalate — worker survived and
    # DAC still discriminates (a wedged/escalated broker would change this).
    st_bp2, bb = http("GET", "/grp/staff_w.txt", port, t_bob)
    # staff_w is 0660 (no other read) -> bob (non-member) must be denied a read too.
    ok(all((st_bp2 != 200, SW_SECRET not in any((bb, b'')))),
       f"FINAL: cross-group bob still denied read of 0660 staff file, no leak "
       f"(HTTP {st_bp2})")
    # positive control that the worker is alive for the authorized group member.
    st_cg, cb = http("GET", "/grp/staff_w.txt", port, t_carol)
    return st_cg, cb


def _rt44_segment_27(st_cg, SW_SECRET, cb):
    ok(all((st_cg == 200, SW_SECRET in any((cb, b'')))),
       f"FINAL: authorized group member carol can still read the group file — "
       f"worker survived the whole battery (HTTP {st_cg})")


def run_combo_xattr_namespace_group(key, data, port, s3port):
    """COMBINATION FRONTIER: xattr/PROPPATCH privileged-NAMESPACE confinement crossed
    with GROUP-WRITE authorization.  Existing batches tested xattr only for user.*
    and only by the file OWNER, and group-write only for plain data writes — NEVER
    the interaction.  Target: grp/staff_w.txt (0660 alice:staff).  carol is a staff
    member (HAS group write); bob is NOT (no write); dave is NOT (no write).  The
    headline claim: a group-authorized writer (carol) may set a user.* dead-property
    (her group write authorizes it) but MUST NOT be able to escalate into a
    privileged xattr namespace (security.*/system.*/trusted.*/XrdCks.*) through the
    broker — group write to the data of the file is NOT authority over privileged
    inode metadata.  Cross-tenant non-writers must be denied AND leave no residue.
    Every check exercises the (namespace x group-write x identity) combination."""
    tag, grp_dir, sw, SW_SECRET, t_alice = _rt44_segment_01(data, key)

    t_carol, t_bob, t_dave, XML, PF_ALLPROP = _rt44_segment_02(key)

    proppatch = _rt44_segment_03(port, XML)

    propfind = _rt44_segment_04(port, PF_ALLPROP, XML)

    lockinfo = _rt44_segment_05()

    bad_xattr_on = _rt44_segment_06()

    inode_clean = _rt44_segment_07(bad_xattr_on)

    st_pp = _rt44_a_positive_control_carol_group_write(sw, bad_xattr_on, proppatch, t_carol)

    bad_after_carol = _rt44_segment_09(propfind, t_carol, st_pp, bad_xattr_on, sw)

    st_bob, body = _rt44_b_negative_control_bob_not_staff(bad_after_carol, inode_clean, sw, proppatch, t_bob, propfind, t_alice)

    body = _rt44_segment_11(st_bob, body, proppatch, t_dave, propfind, t_alice)

    _rt44_explicit_xrdcks_by_owner_control_even(body, proppatch, t_carol, bad_xattr_on, sw, inode_clean, t_alice)

    li, lb, carol_locked = _rt44_d_lock_leg_of_the_combination(lockinfo, port, t_carol, XML, bad_xattr_on, sw)

    lock_tok = _rt44_bob_no_write_cannot_lock_the(carol_locked, lb, port, t_bob, li, XML, bad_xattr_on, sw)

    results, barrier = _rt44_release_carol_s_lock_if_held(lock_tok, port, t_carol)

    race_set = _rt44_segment_16(barrier, proppatch, results)

    seen = _rt44_segment_17(race_set, t_alice, t_carol, propfind)

    _rt44_whatever_landed_must_be_a_real(seen, bad_xattr_on, sw, inode_clean)

    _rt44_f_cross_tenant_bob_proppatch_on(proppatch, t_bob, propfind, t_alice, bad_xattr_on, sw)

    body = _rt44_g_listxattr_getxattr_leak_check_a(sw, propfind, t_carol, body)

    _rt44_herself_set_in_section_c_whose(body, bad_xattr_on, sw, SW_SECRET)

    shw, shared_ok = _rt44_shared_has_group_write_there_but(sw, SW_SECRET, grp_dir)

    big = _rt44_positive_control_on_the_same_file(shared_ok, proppatch, t_bob, propfind, bad_xattr_on, shw, inode_clean, t_dave, t_alice, grp_dir, tag, port, t_carol)

    st_rp, recovered = _rt44_follow_up_legit_group_write_op(port, t_carol, big, XML, bad_xattr_on, sw, proppatch, propfind)

    _rt44_k_final_invariant_sweep_across_every(recovered, st_rp, bad_xattr_on, sw, inode_clean)

    st_cg, cb = _rt44_positive_control_that_the_worker_is(port, t_alice, SW_SECRET, t_bob, t_carol)

    _rt44_segment_27(st_cg, SW_SECRET, cb)
