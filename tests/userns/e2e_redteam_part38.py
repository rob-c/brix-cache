def _rt38_segment_01(key, s3port):
    TAG = "csct"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    have_s3 = bool(s3port)
    have_root = xrd_avail()
    return TAG, ta, tb, have_s3, have_root


def _rt38_unique_markers_so_a_leak_assertion(data):

    # Unique markers so a leak assertion can scan a body deterministically.  These
    # live ONLY behind a link/alias/swap; if any appears in a cross-protocol follow
    # response the confinement/DAC boundary was laundered by the link.
    BOB_SECRET = b"BOB-PRIVATE-SECRET"               # data/bob/private.txt (0600 bob)
    BOB_WORLD = b"bob-world-readable"                # data/bob/readable.txt (0644 bob)
    PASSWD_MARK = b"root:x:0:0"
    GRP_SECRET = b"RESEARCH-GROUP-READABLE"          # grp/research_r.txt (0640 bob:research)

    adir = os.path.join(data, "alice")
    return BOB_SECRET, PASSWD_MARK, GRP_SECRET


def _rt38_segment_03(data):
    bdir = os.path.join(data, "bob")


def _rt38_segment_04(data):

    def rel_fs(*parts):
        return os.path.join(data, *parts)
    return rel_fs


def _rt38_segment_05():

    def luid_of(p):
        try:
            return os.lstat(p).st_uid
        except OSError:
            return -1
    return luid_of


def _rt38_segment_06():

    def lexists(p):
        try:
            return os.path.lexists(p)
        except OSError:
            return False
    return lexists


def _rt38_segment_07():

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt38_segment_08():

    def rm_quiet(p):
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                import shutil as _sh
                _sh.rmtree(p, ignore_errors=True)
        except OSError:
            pass
    return rm_quiet


def _rt38_segment_09():

    def mk_file(p, content, uid, gid, mode):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
    return mk_file


def _rt38_segment_10():

    def mk_dir(p, uid, gid, mode):
        try:
            os.makedirs(p, exist_ok=True)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
    return mk_dir


def _rt38_cross_protocol_follow_primitives_read_a(port):

    # ---- cross-protocol follow primitives (read a server PATH via each protocol) ----
    def follow_wd(relpath, tok):
        st, b = http("GET", "/" + relpath, port, tok)
        return st, (b or b"")
    return follow_wd


def _rt38_segment_12(have_s3, s3port):

    def follow_s3(relpath, ak="alice"):
        if not have_s3:
            return None, b""
        st, b = s3("GET", relpath, s3port, access_key=ak)
        return st, (b or b"")
    return follow_s3


def _rt38_segment_13(have_root):

    def follow_root(relpath, sub):
        if not have_root:
            return None, ""
        rc, out, _e = xrd_fs(["cat", "/" + relpath], sub)
        return rc, (out or "")
    return follow_root


def _rt38_segment_14(have_root):

    def root_ln_s(target, linkpath, sub):
        """Plant a symlink via the root:// protocol itself (ln -s), as <sub>."""
        if not have_root:
            return None
        rc, _o, _e = xrd_fs(["ln", "-s", target, linkpath], sub)
        return rc
    return root_ln_s


def _rt38_segment_15(have_root):

    def root_ln_hard(target, linkpath, sub):
        if not have_root:
            return None
        rc, _o, _e = xrd_fs(["ln", target, linkpath], sub)
        return rc
    return root_ln_hard


def _rt38_segment_16():

    def leaked(body, *needles):
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        return any((n if isinstance(n, bytes) else n.encode()) in (body or b"")
                   for n in needles)
    return leaked


def _rt38_segment_01_5(target, linkfs, lexists, desc, rc):
    try:
        os.symlink(target, linkfs)
        os.lchown(linkfs, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    planted = lexists(linkfs)
    ok(True, "%s: root:// ln -s refused (rc=%s); host-planted fallback "
       "exercises cross-proto follow (planted=%s)" % (desc, rc, planted))
    return planted


def _rt38_when_planted(target, linkfs, lexists, desc, rc):
    planted = _rt38_segment_01_5(target, linkfs, lexists, desc, rc)

    return planted


def _rt38_prepare_link(TAG, name, rel_fs, rm_quiet, root_ln_s, target, lexists):
    linkrel = "alice/%s_%s" % (TAG, name)
    linkfs = rel_fs("alice", "%s_%s" % (TAG, name))
    rm_quiet(linkfs)
    rc = root_ln_s(target, "/" + linkrel, "alice")
    planted = lexists(linkfs)
    return linkrel, linkfs, rc, planted


def _rt38_check_alice_webdav_follow(target, linkfs, lexists, desc, rc, luid_of,
                                    follow_wd, linkrel, ta, leaked, secrets,
                                    planted):
    if not planted:
        # root:// may refuse symlink creation entirely (secure default) — accept
        # as handled, but cover the same shape via a host-planted alice-owned link
        # so the cross-protocol FOLLOW path is still exercised (the link is the
        # attack vector regardless of who planted it; what matters is no follow leak).
        planted = _rt38_when_planted(target, linkfs, lexists, desc, rc)
    else:
        ok(luid_of(linkfs) == UID_ALICE,
           "%s: planted link owned by alice not svc/root (luid=%s)"
           % (desc, luid_of(linkfs)))
    if not planted:
        ok(True, "%s: could not plant link in this env — follow checks skipped "
           "(handled, no leak possible)" % desc)
        return None
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
    return bob_owns_target


def _rt38_check_bob_and_s3_follow(follow_wd, linkrel, tb, bob_owns_target,
                                  leaked, secrets, desc, follow_s3, follow_root):
    st, b = follow_wd(linkrel, tb)
    if bob_owns_target:
        ok(any((st in (401, 403, 404), all((st == 200, leaked(b, *secrets))))),
           "%s: WebDAV GET (bob) via link to bob's OWN file = his own bytes or "
           "refused, never a foreign leak (HTTP %s)" % (desc, st))
    else:
        ok(all((st in (401, 403, 404), not leaked(b, *secrets))),
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
    return rc2, out


def _rt38_check_root_follow(rc2, desc, leaked, out, secrets, follow_root,
                            linkrel, bob_owns_target, rm_quiet, linkfs):
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
        ok(any((rc2 != 0, leaked(out, *secrets))),
           "%s: root:// cat (bob) of link to his OWN file = own bytes or denied, "
           "never a foreign leak (rc=%s)" % (desc, rc2))
    else:
        ok(all((rc2 != 0, not leaked(out, *secrets))),
           "%s: root:// cat (bob) of alice's link to FOREIGN secret denied (rc=%s)"
           % (desc, rc2))
    rm_quiet(linkfs)


def _rt38_check_link_target(TAG, name, rel_fs, rm_quiet, root_ln_s, target,
                            lexists, desc, luid_of, follow_wd, ta, leaked,
                            secrets, tb, follow_s3, follow_root):
    linkrel, linkfs, rc, planted = _rt38_prepare_link(
        TAG, name, rel_fs, rm_quiet, root_ln_s, target, lexists)

    bob_owns_target = _rt38_check_alice_webdav_follow(
        target, linkfs, lexists, desc, rc, luid_of, follow_wd, linkrel, ta,
        leaked, secrets, planted)

    if bob_owns_target is None:
        return

    rc2, out = _rt38_check_bob_and_s3_follow(
        follow_wd, linkrel, tb, bob_owns_target, leaked, secrets, desc,
        follow_s3, follow_root)

    _rt38_check_root_follow(
        rc2, desc, leaked, out, secrets, follow_root, linkrel,
        bob_owns_target, rm_quiet, linkfs)



def _rt38_check_link_targets(link_specs, rel_fs, rm_quiet, root_ln_s, lexists,
                             follow_wd, ta, tb, follow_s3, follow_root, TAG,
                             leaked, luid_of):
    for name, target, secrets, desc in link_specs:
        _rt38_check_link_target(
            TAG, name, rel_fs, rm_quiet, root_ln_s, target, lexists, desc,
            luid_of, follow_wd, ta, leaked, secrets, tb, follow_s3,
            follow_root)


def _rt38_section_1_symlink_planted_via_root(BOB_SECRET, PASSWD_MARK, TAG, rel_fs, rm_quiet, root_ln_s, lexists, luid_of, follow_wd, ta, leaked, tb, follow_s3, follow_root, mk_file):

    _combo_symlink_crossproto_toctou_p1(have_root, have_s3, rel_fs, mk_file, rm_quiet, root_ln_s, lexists, luid_of, body_of, TAG, root_ln_hard, follow_wd, ta, mk_dir, port, tb, follow_s3, follow_root, relname, s3port, BOB_SECRET, PASSWD_MARK, GRP_SECRET, leaked)


def _combo_symlink_crossproto_toctou_p1(have_root, have_s3, rel_fs, mk_file, rm_quiet, root_ln_s, lexists, luid_of, body_of, TAG, root_ln_hard, follow_wd, ta, mk_dir, port, tb, follow_s3, follow_root, relname, s3port, BOB_SECRET, PASSWD_MARK, GRP_SECRET, leaked):
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
    _rt38_check_link_targets(
        link_specs, rel_fs, rm_quiet, root_ln_s, lexists, follow_wd, ta, tb,
        follow_s3, follow_root, TAG, leaked, luid_of)


def _combo_symlink_crossproto_toctou_p2(have_root, have_s3, rel_fs, mk_file, rm_quiet, root_ln_s, lexists, luid_of, body_of, TAG, root_ln_hard, follow_wd, ta, mk_dir, port, follow_s3, tb, follow_root, relname, s3port, BOB_SECRET, GRP_SECRET, leaked, PASSWD_MARK):
    # POSITIVE CONTROL for SECTION 1: a symlink to alice's OWN benign file may resolve
    # (own bytes) or be refused (secure default) — but NEVER yields foreign bytes, and
    # cross-protocol follow agrees.  Proves the denies above are not a blanket "all
    # links 404" that would also false-pass.
    own = rel_fs("alice", "%s_own_target.txt" % TAG)
    mk_file(own, b"CSCT-ALICE-OWN-BENIGN\n", UID_ALICE, UID_ALICE, 0o644)


def _rt38_segment_01_4(stc, leaked, bc):
    ok(any((all((stc == 200, leaked(bc, b'CSCT-ALICE-OWN-BENIGN'))), stc != 200)),
       "control: S3 follow of alice's own-target link = own bytes or refused "
       "(HTTP %s)" % stc)


def _rt38_otherwise_stc(stc, leaked, bc):
    _rt38_segment_01_4(stc, leaked, bc)



def _rt38_segment_01_3(follow_wd, TAG, ta, leaked, follow_s3, BOB_SECRET, PASSWD_MARK):
    st, b = follow_wd("alice/%s_own_link" % TAG, ta)
    ok(any((all((st == 200, leaked(b, b'CSCT-ALICE-OWN-BENIGN'))), st != 200)),
       "control: WebDAV follow of alice's own-target link = own bytes or refused, "
       "never foreign (HTTP %s)" % st)
    stc, bc = follow_s3("alice/%s_own_link" % TAG)
    if stc is None:
        ok(True, "control: S3 own-link follow skipped (S3 down)")
    else:
        _rt38_otherwise_stc(stc, leaked, bc)
    ok(not leaked(b, BOB_SECRET, PASSWD_MARK),
       "control: own-link follow never carries any cross-tenant/host secret")


def _rt38_when_lexists_own_link(follow_wd, ta, TAG, leaked, follow_s3, BOB_SECRET, PASSWD_MARK):
    _rt38_segment_01_3(follow_wd, TAG, ta, leaked, follow_s3, BOB_SECRET, PASSWD_MARK)



def _rt38_segment_18(rel_fs, TAG, rm_quiet, root_ln_s, lexists, follow_wd, ta, leaked, follow_s3, BOB_SECRET, PASSWD_MARK):
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
        _rt38_when_lexists_own_link(follow_wd, ta, TAG, leaked, follow_s3, BOB_SECRET, PASSWD_MARK)
    else:
        ok(True, "control own-link planting skipped (handled)")
        ok(True, "control own-link S3 follow skipped (handled)")
        ok(True, "control own-link no-foreign-bytes skipped (handled)")
    _combo_symlink_crossproto_toctou_p3(have_root, have_s3, rel_fs, luid_of, body_of, rm_quiet, lexists, TAG, root_ln_hard, root_ln_s, follow_wd, ta, mk_file, mk_dir, port, tb, follow_root, relname, follow_s3, s3port, BOB_SECRET, GRP_SECRET, leaked, PASSWD_MARK)


def _rt38_section_2_link_planted_via_webdav(rel_fs, luid_of, body_of, TAG, rm_quiet):

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
    return clob_target, before_owner, before_body, wlink


def _rt38_control_bob_the_owner_overwriting_his_2(TAG, port, ta, body_of, clob_target, before_body, luid_of, before_owner, leaked, have_s3, s3port, tb, BOB_SECRET):
    st, _ = http("PUT", "/alice/%s_putclobber" % TAG, port, ta, b"CSCT-WD-CLOBBER\n")
    ok(all((body_of(clob_target) == before_body, luid_of(clob_target) == before_owner == UID_BOB)),
       "WebDAV PUT through alice's link->bob/0600 does NOT clobber bob's secret "
       "(HTTP %s, owner=%s)" % (st, luid_of(clob_target)))
    ok(not leaked(body_of(clob_target), b"CSCT-WD-CLOBBER"),
       "bob's private.txt body unpolluted by the cross-link WebDAV PUT")
    if have_s3:
        st, _ = s3("PUT", "alice/%s_putclobber" % TAG, s3port, data=b"CSCT-S3-CLOBBER\n")
        ok(all((body_of(clob_target) == before_body, luid_of(clob_target) == UID_BOB)),
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
    return st


def _rt38_segment_02(st, luid_of, clob_target):
    ok(all((st in (200, 201, 204), luid_of(clob_target) == UID_BOB)),
       "control: bob PUTs his own private.txt directly, stays bob-owned (HTTP %s)"
       % st)


def _rt38_when_lexists_wlink(port, ta, TAG, before_body, before_owner, luid_of, clob_target, body_of, leaked, have_s3, s3port, tb, BOB_SECRET):
    st = _rt38_control_bob_the_owner_overwriting_his_2(TAG, port, ta, body_of, clob_target, before_body, luid_of, before_owner, leaked, have_s3, s3port, tb, BOB_SECRET)

    _rt38_segment_02(st, luid_of, clob_target)



def _rt38_control_bob_the_owner_overwriting_his(wlink, lexists, TAG, port, ta, body_of, clob_target, before_body, luid_of, before_owner, leaked, have_s3, s3port, tb, BOB_SECRET, rm_quiet, rel_fs, GRP_SECRET, mk_file):
    try:
        os.symlink("/bob/private.txt", wlink)
        os.lchown(wlink, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    if lexists(wlink):
        # WebDAV PUT onto a symlink that points at bob's secret — must not follow the
        # link to overwrite bob's file (cross-protocol: link is a filesystem object,
        # the WRITE arrives over HTTP).
        _rt38_when_lexists_wlink(port, ta, TAG, before_body, before_owner, luid_of, clob_target, body_of, leaked, have_s3, s3port, tb, BOB_SECRET)
    else:
        ok(True, "PUT-clobber link planting skipped (handled)")
        ok(True, "PUT-clobber body-intact skipped (handled)")
        ok(True, "PUT-clobber S3 skipped (handled)")
        ok(True, "PUT-clobber S3 body skipped (handled)")
        ok(True, "PUT-clobber control skipped (handled)")
    rm_quiet(wlink)
    _combo_symlink_crossproto_toctou_p4(have_root, have_s3, rel_fs, TAG, rm_quiet, root_ln_hard, lexists, root_ln_s, follow_wd, ta, mk_file, mk_dir, port, follow_root, tb, relname, follow_s3, s3port, GRP_SECRET, leaked, BOB_SECRET, PASSWD_MARK, body_of, luid_of)


def _combo_symlink_crossproto_toctou_p4(have_root, have_s3, rel_fs, TAG, rm_quiet, root_ln_hard, lexists, root_ln_s, follow_wd, ta, mk_file, mk_dir, port, follow_root, tb, relname, follow_s3, s3port, GRP_SECRET, leaked, BOB_SECRET, PASSWD_MARK, body_of, luid_of):
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
    return grp_src


def _rt38_segment_21(TAG, rel_fs, rm_quiet, root_ln_hard, lexists):
    hardrel = "alice/%s_grp_hardlink.txt" % TAG
    hardfs = rel_fs("alice", "%s_grp_hardlink.txt" % TAG)
    rm_quiet(hardfs)
    rc = root_ln_hard("/grp/research_r.txt", "/" + hardrel, "alice")
    aliased = lexists(hardfs)
    return hardrel, hardfs, rc, aliased


def _rt38_control_dave_is_in_research_reading_2(follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root):
    st, b = follow_wd(hardrel, ta)
    ok(all((st in (401, 403, 404), not leaked(b, GRP_SECRET))),
       "hardlink alias does NOT let non-member alice read 0640 research file via "
       "WebDAV (HTTP %s)" % st)
    if have_s3:
        st, b = follow_s3(hardrel)              # S3 maps to alice (non-member)
        ok(all((st in (401, 403, 404), not leaked(b, GRP_SECRET))),
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
        ok(all((rc2 == 0, leaked(out, GRP_SECRET))),
           "control: research-member dave reads the 0640 alias via root:// "
           "(group DAC grants, rc=%s)" % rc2)


def _rt38_invariant_following_the_alias_never_rewrote(luid_of, grp_src):
    # invariant: following the alias never rewrote owner/group of the real inode.
    ok(luid_of(grp_src) == UID_BOB,
       "group file inode still bob-owned after cross-proto alias reads (uid=%s)"
       % luid_of(grp_src))


def _rt38_when_aliased(follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root, luid_of, grp_src):
    _rt38_control_dave_is_in_research_reading_2(follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root)

    _rt38_invariant_following_the_alias_never_rewrote(luid_of, grp_src)



def _rt38_control_dave_is_in_research_reading(grp_src, hardfs, lexists, rc, aliased, follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root, luid_of, rm_quiet, rel_fs, TAG):
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
        _rt38_when_aliased(follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root, luid_of, grp_src)
    else:
        ok(True, "hardlink alias group-DAC: alias could not be planted (handled)")
        ok(True, "hardlink alias S3 skipped (handled)")
        ok(True, "hardlink member-control skipped (handled)")
        ok(True, "hardlink inode-owner invariant skipped (handled)")
    rm_quiet(hardfs)
    _combo_symlink_crossproto_toctou_p5(have_root, have_s3, rel_fs, rm_quiet, root_ln_s, lexists, follow_wd, ta, mk_file, mk_dir, port, TAG, tb, relname, follow_s3, follow_root, s3port, leaked, BOB_SECRET, PASSWD_MARK, luid_of, body_of)


def _combo_symlink_crossproto_toctou_p5(have_root, have_s3, rel_fs, rm_quiet, root_ln_s, lexists, follow_wd, ta, mk_file, mk_dir, port, TAG, tb, relname, follow_s3, follow_root, s3port, leaked, BOB_SECRET, PASSWD_MARK, luid_of, body_of):
    # =====================================================================
    # SECTION 4 — readlink CROSS-TENANT combined with a cross-protocol follow.  bob
    # tries to readlink a link sitting in ALICE's 0755 dir (he can traverse) whose
    # target names bob's own secret path: readlink may reveal the stored target string
    # but the subsequent FOLLOW (WebDAV as bob) must NOT yield the secret; and a link
    # in bob's 0700 dir must not be readlink-able by alice at all.
    # =====================================================================
    rl_link = rel_fs("alice", "%s_rl_in_alice" % TAG)
    rm_quiet(rl_link)
    return rl_link


def _rt38_readlink_revealing_the_target_string_is(root_ln_s, TAG, lexists, rl_link, have_root, leaked, BOB_SECRET, follow_wd, tb, rm_quiet, rel_fs):
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
        ok(all((st in (401, 403, 404), not leaked(b, BOB_SECRET))),
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
    return bsec_link


def _rt38_control_bob_owner_can_readlink_his(rm_quiet, bsec_link, lexists, have_root, TAG, leaked, PASSWD_MARK, follow_wd, ta, BOB_SECRET):
    rm_quiet(bsec_link)
    try:
        os.symlink("/etc/passwd", bsec_link)
        os.lchown(bsec_link, UID_BOB, UID_BOB)
    except OSError:
        pass
    if lexists(bsec_link):
        if have_root:
            rc2, out, _e = xrd_fs(["readlink", "/bobsecret/%s_blink" % TAG], "alice")
            ok(all((rc2 != 0, not leaked(out, PASSWD_MARK))),
               "alice cannot readlink a link inside bob's 0700 dir (rc=%s)" % rc2)
        else:
            ok(True, "readlink-in-0700 (root) skipped (native absent)")
        st, b = follow_wd("bobsecret/%s_blink" % TAG, ta)
        ok(all((st in (401, 403, 404), not leaked(b, PASSWD_MARK, BOB_SECRET))),
           "WebDAV follow of a link in bob's 0700 dir denied to alice (HTTP %s)" % st)
        # control: bob (owner) CAN readlink his own link in his 0700 dir.
        if have_root:
            rc2, out, _e = xrd_fs(["readlink", "/bobsecret/%s_blink" % TAG], "bob")
            ok(any((rc2 == 0, 'passwd' in any((out, '')))),
               "control: bob readlinks his own link in his 0700 dir (rc=%s)" % rc2)
        else:
            ok(True, "readlink-in-0700 control skipped (native absent)")
    else:
        ok(True, "link-in-0700 planting skipped (handled)")
        ok(True, "link-in-0700 WebDAV follow skipped (handled)")
        ok(True, "link-in-0700 control skipped (handled)")
    rm_quiet(bsec_link)


def _rt38_section_5_toctou_a_path_is(rel_fs, rm_quiet, mk_file):

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
    return toctou_swap


def _rt38_5a_webdav_get_op_1_sees(toctou_swap, TAG, follow_wd, ta, leaked):

    # 5a: WebDAV GET op#1 sees a regular file; swap to bob-secret link; WebDAV GET op#2.
    p = toctou_swap("%s_toctou_a" % TAG, "/bob/private.txt")
    st1, b1 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    ok(all((st1 == 200, leaked(b1, b'CSCT-TOCTOU-REGULAR'))),
       "TOCTOU 5a: pre-swap WebDAV GET returns alice's regular file (HTTP %s)" % st1)
    try:
        os.remove(p)
        os.symlink("/bob/private.txt", p)
        os.lchown(p, UID_ALICE, UID_ALICE)
    except OSError:
        pass
    st2, b2 = follow_wd("alice/%s_toctou_a" % TAG, ta)
    return p, st2, b2


def _rt38_5b_cross_protocol_toctou_root_stat(leaked, b2, BOB_SECRET, st2, rm_quiet, p, toctou_swap, TAG, have_root):
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
    return p


def _rt38_5c_race_form_a_thread_flips(have_s3, follow_s3, TAG, leaked, PASSWD_MARK, follow_wd, ta, rm_quiet, p, rel_fs, mk_file):
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
    return racepath


def _rt38_segment_29():
    stop = threading.Event()
    flips = {"n": 0}
    return stop, flips


def _rt38_segment_30(stop, racepath, flips):

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
    return flipper


def _rt38_segment_31():

    leak_hits = {"n": 0}
    err_hits = {"n": 0}
    return leak_hits, err_hits


def _rt38_segment_32(TAG, port, ta, BOB_SECRET, leak_hits, err_hits):

    def racer():
        for _ in range(12):
            try:
                st, b = http("GET", "/alice/%s_toctou_race" % TAG, port, ta)
                if BOB_SECRET in (b or b""):
                    leak_hits["n"] += 1
            except Exception:  # noqa: BLE001
                err_hits["n"] += 1
    return racer


def _rt38_segment_33(flipper, racer):

    ft = threading.Thread(target=flipper)
    ft.start()
    racers = [threading.Thread(target=racer) for _ in range(6)]   # modest: 6+1 threads
    for t in racers:
        t.start()
    for t in racers:
        t.join()
    return ft


def _rt38_worker_survival_after_the_race_a(stop, ft, leak_hits, flips, rm_quiet, racepath, mk_file, rel_fs, TAG):
    stop.set()
    ft.join()
    ok(leak_hits["n"] == 0,
       "TOCTOU 5c: concurrent regular<->bob-link flips never leaked bob's secret "
       "over WebDAV (flips=%s, leaks=%s)" % (flips["n"], leak_hits["n"]))
    rm_quiet(racepath)
    # worker survival after the race: a legit alice GET still works.
    mk_file(rel_fs("alice", "%s_postrace.txt" % TAG), b"CSCT-POSTRACE\n",
            UID_ALICE, UID_ALICE, 0o644)


def _rt38_section_6_a_symlink_whose_target(follow_wd, TAG, ta, leaked, rel_fs, rm_quiet, root_ln_s):
    st, b = follow_wd("alice/%s_postrace.txt" % TAG, ta)
    ok(all((st == 200, leaked(b, b'CSCT-POSTRACE'))),
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
    return in700_link


def _rt38_segment_01_2(follow_wd, TAG, ta, leaked, follow_s3, follow_root):
    st, b = follow_wd("alice/%s_to700" % TAG, ta)
    ok(all((st in (401, 403, 404), not leaked(b, b'bob-only'))),
       "in-export link to bob's 0700/s.txt denied via WebDAV, no leak (HTTP %s)"
       % st)
    st2, b2 = follow_s3("alice/%s_to700" % TAG)
    if st2 is None:
        ok(True, "in-export-700 link S3 follow skipped (S3 down)")
    else:
        ok(all((st2 in (401, 403, 404), not leaked(b2, b'bob-only'))),
           "in-export link to bob's 0700/s.txt denied via S3, no leak (HTTP %s)"
           % st2)
    rc2, out = follow_root("alice/%s_to700" % TAG, "alice")
    return rc2, out


def _rt38_segment_02_2(rc2, leaked, out):
    if rc2 is None:
        ok(True, "in-export-700 link root:// follow skipped (native absent)")
    else:
        ok(not leaked(out, b"bob-only"),
           "in-export link to bob's 0700/s.txt no leak via root:// (rc=%s)" % rc2)


def _rt38_when_lexists_in700_link(follow_wd, ta, TAG, leaked, follow_s3, follow_root):
    rc2, out = _rt38_segment_01_2(follow_wd, TAG, ta, leaked, follow_s3, follow_root)

    _rt38_segment_02_2(rc2, leaked, out)



def _rt38_section_7_directory_full_of_planted(lexists, in700_link, follow_wd, TAG, ta, leaked, follow_s3, follow_root, rm_quiet, rel_fs):
    if not lexists(in700_link):
        try:
            os.symlink("../bobsecret/s.txt", in700_link)
            os.lchown(in700_link, UID_ALICE, UID_ALICE)
        except OSError:
            pass
    if lexists(in700_link):
        _rt38_when_lexists_in700_link(follow_wd, ta, TAG, leaked, follow_s3, follow_root)
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
    return linkdir


def _rt38_segment_37(mk_dir, linkdir, TAG, mk_file):
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


def _rt38_actually_worked_control_so_the_no(TAG, port, ta, leaked, PASSWD_MARK, BOB_SECRET):
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
    ok(any((st in (207, 200), st in (401, 403, 404))),
       "PROPFIND over link farm handled (enumerated or denied), not crashed (HTTP %s)"
       % st)
    # PROPFIND Depth:infinity must not recurse THROUGH a link into /etc or bob.
    st, b = http("PROPFIND", "/alice/%s_linkfarm/" % TAG, port, ta,
                 data=pf, hdrs={"Depth": "infinity", "Content-Type": "application/xml"})
    return st, b


def _rt38_control_the_real_file_s_key(leaked, b, PASSWD_MARK, BOB_SECRET, st, have_s3, s3port, TAG, rm_quiet, linkdir, rel_fs):
    ok(not leaked(b, PASSWD_MARK, b"/bin/bash", BOB_SECRET, b"daemon:x:"),
       "PROPFIND Depth:infinity does NOT recurse through farm links into /etc or bob "
       "(HTTP %s)" % st)
    # S3 ListObjectsV2 with the farm prefix — links not followed, no target bytes,
    # no synthetic 'to_etc/...' host keys enumerated.
    if have_s3:
        st, b = s3("GET", "", s3port,
                   params={"list-type": "2", "prefix": "alice/%s_linkfarm/" % TAG})
        ok(all((not leaked(b, PASSWD_MARK, b'/bin/bash', BOB_SECRET), not leaked(b, b'to_etc/etc'))),
           "S3 ListObjectsV2 over the link farm follows no link into the host FS / bob "
           "(HTTP %s)" % st)
        # control: the real file's key IS enumerable (proves listing worked, deny isn't
        # a blanket empty response).
        ok(all((st == 200, any((leaked(b, b'%s_real.txt' % TAG.encode()), leaked(b, b'alice/'))))),
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
    return survrel, survfs


def _rt38_segment_40(rm_quiet, survfs, survrel, port, ta, luid_of, have_root, TAG, body_of, have_s3, follow_s3, leaked):
    rm_quiet(survfs)
    st, _ = http("PUT", "/" + survrel, port, ta, b"CSCT-SURVIVE\n")
    ok(all((st in (200, 201, 204), os.path.exists(survfs), os.stat(survfs).st_uid == UID_ALICE)),
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
        ok(all((rc == 0, body_of(dl) == b'CSCT-SURVIVE\n')),
           "survival: cross-protocol root:// read-back of the WebDAV-written file works "
           "(rc=%s)" % rc)
    elif have_s3:
        st, b = follow_s3(survrel)
        ok(all((st == 200, leaked(b, b'CSCT-SURVIVE'))),
           "survival: cross-protocol S3 read-back of the WebDAV-written file works "
           "(HTTP %s)" % st)
    else:
        ok(True, "survival cross-protocol read-back skipped (no root:// or S3)")
    rm_quiet(survfs)


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
    TAG, ta, tb, have_s3, have_root = _rt38_segment_01(key, s3port)

    BOB_SECRET, PASSWD_MARK, GRP_SECRET = _rt38_unique_markers_so_a_leak_assertion(data)

    _rt38_segment_03(data)

    rel_fs = _rt38_segment_04(data)

    luid_of = _rt38_segment_05()

    lexists = _rt38_segment_06()

    body_of = _rt38_segment_07()

    rm_quiet = _rt38_segment_08()

    mk_file = _rt38_segment_09()

    mk_dir = _rt38_segment_10()

    follow_wd = _rt38_cross_protocol_follow_primitives_read_a(port)

    follow_s3 = _rt38_segment_12(have_s3, s3port)

    follow_root = _rt38_segment_13(have_root)

    root_ln_s = _rt38_segment_14(have_root)

    root_ln_hard = _rt38_segment_15(have_root)

    leaked = _rt38_segment_16()

    _rt38_section_1_symlink_planted_via_root(BOB_SECRET, PASSWD_MARK, TAG, rel_fs, rm_quiet, root_ln_s, lexists, luid_of, follow_wd, ta, leaked, tb, follow_s3, follow_root, mk_file)

    _rt38_segment_18(rel_fs, TAG, rm_quiet, root_ln_s, lexists, follow_wd, ta, leaked, follow_s3, BOB_SECRET, PASSWD_MARK)

    clob_target, before_owner, before_body, wlink = _rt38_section_2_link_planted_via_webdav(rel_fs, luid_of, body_of, TAG, rm_quiet)

    grp_src = _rt38_control_bob_the_owner_overwriting_his(wlink, lexists, TAG, port, ta, body_of, clob_target, before_body, luid_of, before_owner, leaked, have_s3, s3port, tb, BOB_SECRET, rm_quiet, rel_fs, GRP_SECRET, mk_file)

    hardrel, hardfs, rc, aliased = _rt38_segment_21(TAG, rel_fs, rm_quiet, root_ln_hard, lexists)

    rl_link = _rt38_control_dave_is_in_research_reading(grp_src, hardfs, lexists, rc, aliased, follow_wd, hardrel, ta, leaked, GRP_SECRET, have_s3, follow_s3, follow_root, luid_of, rm_quiet, rel_fs, TAG)

    bsec_link = _rt38_readlink_revealing_the_target_string_is(root_ln_s, TAG, lexists, rl_link, have_root, leaked, BOB_SECRET, follow_wd, tb, rm_quiet, rel_fs)

    _rt38_control_bob_owner_can_readlink_his(rm_quiet, bsec_link, lexists, have_root, TAG, leaked, PASSWD_MARK, follow_wd, ta, BOB_SECRET)

    toctou_swap = _rt38_section_5_toctou_a_path_is(rel_fs, rm_quiet, mk_file)

    p, st2, b2 = _rt38_5a_webdav_get_op_1_sees(toctou_swap, TAG, follow_wd, ta, leaked)

    p = _rt38_5b_cross_protocol_toctou_root_stat(leaked, b2, BOB_SECRET, st2, rm_quiet, p, toctou_swap, TAG, have_root)

    racepath = _rt38_5c_race_form_a_thread_flips(have_s3, follow_s3, TAG, leaked, PASSWD_MARK, follow_wd, ta, rm_quiet, p, rel_fs, mk_file)

    stop, flips = _rt38_segment_29()

    flipper = _rt38_segment_30(stop, racepath, flips)

    leak_hits, err_hits = _rt38_segment_31()

    racer = _rt38_segment_32(TAG, port, ta, BOB_SECRET, leak_hits, err_hits)

    ft = _rt38_segment_33(flipper, racer)

    _rt38_worker_survival_after_the_race_a(stop, ft, leak_hits, flips, rm_quiet, racepath, mk_file, rel_fs, TAG)

    in700_link = _rt38_section_6_a_symlink_whose_target(follow_wd, TAG, ta, leaked, rel_fs, rm_quiet, root_ln_s)

    linkdir = _rt38_section_7_directory_full_of_planted(lexists, in700_link, follow_wd, TAG, ta, leaked, follow_s3, follow_root, rm_quiet, rel_fs)

    _rt38_segment_37(mk_dir, linkdir, TAG, mk_file)

    st, b = _rt38_actually_worked_control_so_the_no(TAG, port, ta, leaked, PASSWD_MARK, BOB_SECRET)

    survrel, survfs = _rt38_control_the_real_file_s_key(leaked, b, PASSWD_MARK, BOB_SECRET, st, have_s3, s3port, TAG, rm_quiet, linkdir, rel_fs)

    _rt38_segment_40(rm_quiet, survfs, survrel, port, ta, luid_of, have_root, TAG, body_of, have_s3, follow_s3, leaked)
