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

