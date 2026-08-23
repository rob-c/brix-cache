def _rt9_segment_01():

    A, B = "alice", "bob"
    MARK_BOB = b"BOB-PRIVATE-SECRET"          # planted in data/bob/private.txt (0600)
    MARK_SVC = b"svc-only-secret"             # planted in data/svconly/secret-name.txt
    return A, B, MARK_BOB, MARK_SVC


def _rt9_segment_02(data):

    def realp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return realp


def _rt9_segment_03(realp):

    def uid_of(rel):
        fp = realp(rel)
        try:
            return os.stat(fp).st_uid if os.path.exists(fp) else -1
        except OSError:
            return -1
    return uid_of


def _rt9_segment_04(realp):

    def mode_of(rel):
        fp = realp(rel)
        try:
            return (os.stat(fp).st_mode & 0o777) if os.path.exists(fp) else -1
        except OSError:
            return -1
    return mode_of


def _rt9_segment_05(realp):

    def size_of(rel):
        fp = realp(rel)
        try:
            return os.path.getsize(fp) if os.path.exists(fp) else -1
        except OSError:
            return -1
    return size_of


def _rt9_segment_06():

    def local(name, content=b""):
        lp = os.path.join(WORK, "rpd_" + name)
        try:
            with open(lp, "wb") as fh:
                fh.write(content)
        except OSError:
            pass
        return lp
    return local


def _rt9_seed_local_payloads_of_distinct_sizes(local, A):

    # ---- seed local payloads of distinct sizes (open-mode matrix) ---------------
    BIG = b"RPD-OPEN-MODE-PAYLOAD-0123456789\n" * 64     # ~2 KiB
    SMALL = b"rpd-small\n"
    lf_big = local("big.bin", BIG)
    lf_small = local("small.bin", SMALL)

    # =====================================================================
    # (A) OPEN-MODE / OWNERSHIP MATRIX  (new file -> update -> shrink -> regrow)
    # =====================================================================
    # (A1) NEW FILE create via data plane -> owned by alice, byte-exact size.
    rc, _o, e = xrd_cp_up(lf_big, "/alice/rpd_om.bin", A)
    return BIG, SMALL, lf_big, lf_small, rc


def _rt9_a2_update_overwrite_existing_with_a(rc, uid_of, size_of, BIG, lf_small, A, SMALL):
    ok(all((rc == 0, uid_of('/alice/rpd_om.bin') == UID_ALICE, size_of('/alice/rpd_om.bin') == len(BIG))),
       f"root:// open(new) write owned by alice, full size (rc={rc}, "
       f"uid={uid_of('/alice/rpd_om.bin')}, sz={size_of('/alice/rpd_om.bin')})")

    # (A2) UPDATE/OVERWRITE existing with a SMALLER payload (-f forces truncate-on-
    #      open).  Same file, still owned by alice, new (smaller) size — proves the
    #      update/truncate open mode re-establishes the principal, not the worker.
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_om.bin", A)
    ok(all((rc == 0, uid_of('/alice/rpd_om.bin') == UID_ALICE, size_of('/alice/rpd_om.bin') == len(SMALL))),
       f"root:// open(update/truncate) overwrite still alice-owned, shrunk "
       f"(rc={rc}, sz={size_of('/alice/rpd_om.bin')})")

    # (A3) explicit truncate-SHRINK via xrdfs truncate on own file (mutation).
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_om.bin", "4"], A)
    ok(all((rc == 0, size_of('/alice/rpd_om.bin') == 4, uid_of('/alice/rpd_om.bin') == UID_ALICE)),
       f"root:// truncate-shrink own file to 4 bytes (rc={rc}, "
       f"sz={size_of('/alice/rpd_om.bin')})")


def _rt9_a4_truncate_grow_sparse_own_file(A, size_of, uid_of, lf_big, rc):

    # (A4) truncate-GROW (sparse) own file — size grows, ownership unchanged.
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_om.bin", "4096"], A)
    ok(all((rc == 0, size_of('/alice/rpd_om.bin') == 4096, uid_of('/alice/rpd_om.bin') == UID_ALICE)),
       f"root:// truncate-grow own file to 4096 (rc={rc}, "
       f"sz={size_of('/alice/rpd_om.bin')})")

    # (A5) READ-ONLY open: download own file byte-exact (read path as alice).
    rc, _o, _e = xrd_cp_up(lf_big, "/alice/rpd_rd.bin", A)
    dl = os.path.join(WORK, "rpd_rd_dl.bin")
    rc2, _o2, _e2 = xrd_cp_down("/alice/rpd_rd.bin", dl, A)
    return rc, dl, rc2


def _rt9_a6_bob_writes_his_own_new(dl, rc, rc2, BIG, lf_small, B, uid_of):
    got = b""
    try:
        got = open(dl, "rb").read() if os.path.exists(dl) else b""
    except OSError:
        got = b""
    ok(all((rc == 0, rc2 == 0, got == BIG)),
       f"root:// open(read-only) own file byte-exact (up={rc}, down={rc2})")

    # (A6) bob writes his OWN new file -> owned by BOB, not alice/svc (control that
    #      the open path maps the *token* identity, not a sticky last-principal).
    rc, _o, _e = xrd_cp_up(lf_small, "/bob/rpd_bom.bin", B)
    ok(all((rc == 0, uid_of('/bob/rpd_bom.bin') == UID_BOB)),
       f"root:// bob's open(new) write owned by bob (rc={rc}, "
       f"uid={uid_of('/bob/rpd_bom.bin')})")


def _rt9_b_query_matrix_checksum_config_space(A, MARK_BOB, rc):

    # =====================================================================
    # (B) QUERY MATRIX — checksum / config / space / xattr  (self vs bob no-leak)
    # =====================================================================
    # (B1) query checksum of OWN file succeeds.
    rc, out, _e = xrd_fs(["query", "checksum", "/alice/rpd_rd.bin"], A)
    ok(rc == 0, f"root:// query checksum own file (rc={rc})")

    # (B2) query checksum of bob's 0600 file: DENIED, and the body must not carry the
    #      secret marker (checksum could leak content/derived data).
    rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], A)
    ok(all((rc != 0, MARK_BOB.decode() not in any((out, '')))),
       f"root:// query checksum of bob's 0600 DENIED + no leak (rc={rc})")

    # (B3) query checksum of svc-only file: DENIED + no svc secret marker.
    rc, out, _e = xrd_fs(["query", "checksum", "/svconly/secret-name.txt"], A)
    return rc, out


def _rt9_b4_query_config_of_a_benign(rc, MARK_SVC, out, A, MARK_BOB):
    ok(all((rc != 0, MARK_SVC.decode() not in any((out, '')))),
       f"root:// query checksum of svc-only file DENIED + no leak (rc={rc})")

    # (B4) query config of a benign server key works (no path -> no DAC) and does
    #      NOT echo any planted secret.
    rc, out, _e = xrd_fs(["query", "config", "version"], A)
    ok(all((MARK_BOB.decode() not in any((out, '')), MARK_SVC.decode() not in any((out, '')))),
       f"root:// query config does not leak any tenant secret (rc={rc})")

    # (B5) query space of own dir works; of bob's 0600 file must not leak content.
    rc, _o, _e = xrd_fs(["query", "space", "/alice/"], A)
    ok(rc == 0, f"root:// query space own dir (rc={rc})")


def _rt9_b6_query_xattr_user_xrdcks_on(A, MARK_BOB, MARK_SVC, rc, out):
    rc, out, _e = xrd_fs(["query", "space", "/bob/private.txt"], A)
    ok(MARK_BOB.decode() not in any((out, '')),
       f"root:// query space of bob's 0600 leaks no content (rc={rc})")

    # (B6) query xattr (user.* / XrdCks.*) on OWN file — optional feature: accept
    #      unsupported (rc!=0) as handled, but a SUCCESS must carry no foreign secret.
    rc, out, _e = xrd_fs(["query", "xattr", "/alice/rpd_rd.bin"], A)
    ok(all((MARK_BOB.decode() not in any((out, '')), MARK_SVC.decode() not in any((out, '')))),
       f"root:// query xattr own file leaks no foreign secret (rc={rc})")

    # (B7) query xattr on bob's 0600 file — DENIED or unsupported, never the secret.
    rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt"], A)
    return rc, out


def _rt9_c_stat_statx_locate_self_vs(MARK_BOB, out, rc, A):
    ok(MARK_BOB.decode() not in any((out, '')),
       f"root:// query xattr of bob's 0600 leaks no content (rc={rc})")

    # =====================================================================
    # (C) STAT / STATX / LOCATE  — self vs cross-tenant
    # =====================================================================
    # (C1) stat own file succeeds.
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_rd.bin"], A)
    ok(rc == 0, f"root:// stat own file (rc={rc})")

    # (C2) stat bob's world-readable 0644 file: metadata is not secret -> may succeed,
    #      but the stat output must not leak the PRIVATE file's secret bytes.
    rc, out, _e = xrd_fs(["stat", "/bob/readable.txt"], A)
    ok(MARK_BOB.decode() not in any((out, '')),
       f"root:// stat bob's 0644 file leaks no private content (rc={rc})")


def _rt9_c4_locate_own_dir_works_positive(A, rc, out):

    # (C3) stat a NON-EXISTENT path -> error (no phantom success / no escape).
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_does_not_exist_xyz"], A)
    ok(rc != 0, f"root:// stat of missing file errors cleanly (rc={rc})")

    # (C4) locate own dir works (positive control for the namespace walk).
    rc, _o, _e = xrd_fs(["locate", "/alice/"], A)
    ok(rc == 0, f"root:// locate own dir (rc={rc})")

    # (C5) locate of bob's secret 0700 dir entry must not leak its protected child.
    rc, out, _e = xrd_fs(["locate", "/bobsecret/s.txt"], A)
    return rc, out


def _rt9_d_nested_mkdir_per_level_ownership(out, rc, A, uid_of, lf_small):
    ok('bob-only' not in any((out, '')),
       f"root:// locate of bob's 0700 file leaks no content (rc={rc})")

    # =====================================================================
    # (D) NESTED MKDIR + PER-LEVEL OWNERSHIP  (self) and cross-tenant DENY
    # =====================================================================
    # (D1) create a parent then a child; each level owned by alice.
    rc1, _o, _e = xrd_fs(["mkdir", "/alice/rpd_nest"], A)
    rc2, _o, _e = xrd_fs(["mkdir", "/alice/rpd_nest/child"], A)
    ok(all((rc1 == 0, rc2 == 0, uid_of('/alice/rpd_nest') == UID_ALICE, uid_of('/alice/rpd_nest/child') == UID_ALICE)),
       f"root:// nested mkdir: every level owned by alice (rc={rc1}/{rc2})")

    # (D2) a file inside the nested dir is owned by alice too (write into own subtree).
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_nest/child/leaf.bin", A)
    return rc


def _rt9_d3_mkdir_into_bob_s_0700(rc, uid_of, A, realp):
    ok(all((rc == 0, uid_of('/alice/rpd_nest/child/leaf.bin') == UID_ALICE)),
       f"root:// file in nested own dir owned by alice (rc={rc})")

    # (D3) mkdir into bob's 0700 dir -> DENIED, nothing created.
    rc, _o, _e = xrd_fs(["mkdir", "/bobsecret/rpd_intrude"], A)
    ok(all((rc != 0, not os.path.exists(realp('/bobsecret/rpd_intrude')))),
       f"root:// mkdir into bob's 0700 dir DENIED (rc={rc})")

    # (D4) mkdir into svc-only 0750 dir -> DENIED (alice is other, no write).
    rc, _o, _e = xrd_fs(["mkdir", "/svconly/rpd_intrude"], A)
    ok(all((rc != 0, not os.path.exists(realp('/svconly/rpd_intrude')))),
       f"root:// mkdir into svc-only 0750 dir DENIED (rc={rc})")


def _rt9_e_rmdir_non_empty_vs_empty(A, realp):

    # =====================================================================
    # (E) RMDIR non-empty vs empty  (self) and cross-tenant DENY
    # =====================================================================
    # (E1) rmdir a NON-EMPTY own dir must FAIL (ENOTEMPTY), dir + child survive.
    rc, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest"], A)
    ok(all((rc != 0, os.path.isdir(realp('/alice/rpd_nest/child')))),
       f"root:// rmdir non-empty own dir refused (ENOTEMPTY) (rc={rc})")

    # (E2) empty the subtree leaf-first, then rmdir EMPTY own dirs succeeds.
    xrd_fs(["rm", "/alice/rpd_nest/child/leaf.bin"], A)
    rcA, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest/child"], A)
    rcB, _o, _e = xrd_fs(["rmdir", "/alice/rpd_nest"], A)
    return rcA, rcB


def _rt9_e3_rmdir_bob_s_secret_0700(rcA, rcB, realp, A, lf_small, rc):
    ok(all((rcA == 0, rcB == 0, not os.path.exists(realp('/alice/rpd_nest')))),
       f"root:// rmdir empty own dirs succeeds, tree gone (rc={rcA}/{rcB})")

    # (E3) rmdir bob's secret 0700 dir -> DENIED, dir + secret child intact.
    rc, _o, _e = xrd_fs(["rmdir", "/bobsecret"], A)
    ok(all((rc != 0, os.path.isdir(realp('/bobsecret')), os.path.exists(realp('/bobsecret/s.txt')))),
       f"root:// rmdir bob's 0700 dir DENIED, intact (rc={rc})")

    # =====================================================================
    # (F) MV  — within-tenant OK / cross-tenant-source DENY / into-svconly DENY
    # =====================================================================
    # (F1) within-tenant rename: src disappears, dst owned by alice, content kept.
    xrd_fs(["rm", "/alice/rpd_mv_src.bin"], A)   # idempotent cleanup
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_mv_src.bin", A)
    return rc


def _rt9_f2_cross_tenant_source_mv_bob(A, rc, uid_of, realp, size_of, SMALL):
    rc2, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_src.bin", "/alice/rpd_mv_dst.bin"], A)
    ok(all((rc == 0, rc2 == 0, uid_of('/alice/rpd_mv_dst.bin') == UID_ALICE, not os.path.exists(realp('/alice/rpd_mv_src.bin')), size_of('/alice/rpd_mv_dst.bin') == len(SMALL))),
       f"root:// mv within alice's tenant OK, dst alice-owned (rc={rc2})")

    # (F2) cross-tenant SOURCE: mv bob's 0644 file into alice's dir -> DENIED.  The
    #      source removal needs write on bob's dir; bob's file stays put, no copy.
    before_uid = uid_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["mv", "/bob/readable.txt", "/alice/rpd_stolen.bin"], A)
    ok(all((rc != 0, os.path.exists(realp('/bob/readable.txt')), uid_of('/bob/readable.txt') == before_uid, not os.path.exists(realp('/alice/rpd_stolen.bin')))),
       f"root:// mv of bob's file (cross-tenant source) DENIED (rc={rc})")


def _rt9_control_proving_f3_s_deny_is(A, realp, uid_of, lf_small):

    # (F3) mv own file INTO svc-only 0750 dir as DEST -> DENIED (no write on svconly);
    #      the source file must survive in alice's dir (atomic refusal, no loss).
    rc, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_dst.bin", "/svconly/rpd_planted.bin"], A)
    ok(all((rc != 0, os.path.exists(realp('/alice/rpd_mv_dst.bin')), not os.path.exists(realp('/svconly/rpd_planted.bin')))),
       f"root:// mv own file INTO svc-only dest DENIED, src kept (rc={rc})")

    # (F4) mv own file into the world-writable pub/ 0777 dir -> OK, owner preserved
    #      (control proving F3's deny is the DEST dir's DAC, not a blanket mv block).
    rc, _o, _e = xrd_fs(["mv", "/alice/rpd_mv_dst.bin", "/pub/rpd_pubmoved.bin"], A)
    ok(all((rc == 0, uid_of('/pub/rpd_pubmoved.bin') == UID_ALICE, not os.path.exists(realp('/alice/rpd_mv_dst.bin')))),
       f"root:// mv own file into pub/ (0777) OK, still alice-owned (rc={rc})")

    # =====================================================================
    # (G) CHMOD  — own (mode actually changes) vs bob (DENIED, mode intact)
    # =====================================================================
    # (G1) chmod own file changes the mode (and to a DIFFERENT value than before).
    xrd_cp_up(lf_small, "/alice/rpd_chmod.bin", A)


def _rt9_segment_22(mode_of, A):
    pre = mode_of("/alice/rpd_chmod.bin")
    target = 0o640 if pre != 0o640 else 0o600
    rc, _o, _e = xrd_fs(["chmod", "/alice/rpd_chmod.bin", oct(target)[2:]], A)
    post = mode_of("/alice/rpd_chmod.bin")
    ok(all((rc == 0, post == target, post != pre)),
       f"root:// chmod own file changes mode {pre:o}->{post:o} (rc={rc})")


def _rt9_g2_chmod_bob_s_private_0600(mode_of, A, rc):

    # (G2) chmod bob's PRIVATE 0600 file -> DENIED, mode unchanged (no DAC widening).
    pre_b = mode_of("/bob/private.txt")
    rc, _o, _e = xrd_fs(["chmod", "/bob/private.txt", "666"], A)
    ok(all((rc != 0, mode_of('/bob/private.txt') == pre_b, pre_b == 384)),
       f"root:// chmod bob's 0600 file DENIED, mode intact ({pre_b:o}, rc={rc})")

    # (G3) chmod bob's 0644 file -> DENIED too (alice is not the owner).
    pre_r = mode_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["chmod", "/bob/readable.txt", "600"], A)
    return rc, pre_r


def _rt9_h_truncate_own_shrinks_vs_bob(rc, mode_of, pre_r, A, size_of):
    ok(all((rc != 0, mode_of('/bob/readable.txt') == pre_r)),
       f"root:// chmod bob's 0644 file DENIED, mode intact ({pre_r:o}, rc={rc})")

    # =====================================================================
    # (H) TRUNCATE  — own (shrinks) vs bob (DENIED, size intact)
    # =====================================================================
    # (H1) truncate own file to 0 succeeds.
    rc, _o, _e = xrd_fs(["truncate", "/alice/rpd_chmod.bin", "0"], A)
    ok(all((rc == 0, size_of('/alice/rpd_chmod.bin') == 0)),
       f"root:// truncate own file to 0 (rc={rc})")

    # (H2) truncate bob's 0600 PRIVATE file -> DENIED, size unchanged.
    sz_b = size_of("/bob/private.txt")
    rc, _o, _e = xrd_fs(["truncate", "/bob/private.txt", "0"], A)
    return rc, sz_b


def _rt9_h3_truncate_bob_s_0644_file(rc, size_of, sz_b, A, lf_small):
    ok(all((rc != 0, size_of('/bob/private.txt') == sz_b, sz_b > 0)),
       f"root:// truncate bob's 0600 file DENIED, size intact ({sz_b}, rc={rc})")

    # (H3) truncate bob's 0644 file -> DENIED (no write perm on other's file).
    sz_r = size_of("/bob/readable.txt")
    rc, _o, _e = xrd_fs(["truncate", "/bob/readable.txt", "0"], A)
    ok(all((rc != 0, size_of('/bob/readable.txt') == sz_r)),
       f"root:// truncate bob's 0644 file DENIED, size intact ({sz_r}, rc={rc})")

    # =====================================================================
    # (I) PUB/ (0777 shared) — write owned by the WRITER (alice vs bob distinct)
    # =====================================================================
    rc, _o, _e = xrd_cp_up(lf_small, "/pub/rpd_alice_pub.bin", A)
    return rc


def _rt9_invariant_neither_shared_dir_file_is(rc, uid_of, lf_small, B):
    ok(all((rc == 0, uid_of('/pub/rpd_alice_pub.bin') == UID_ALICE)),
       f"root:// write into pub/ owned by alice the writer (rc={rc})")
    rc, _o, _e = xrd_cp_up(lf_small, "/pub/rpd_bob_pub.bin", B)
    ok(all((rc == 0, uid_of('/pub/rpd_bob_pub.bin') == UID_BOB)),
       f"root:// write into pub/ owned by bob the writer (rc={rc})")
    # invariant: NEITHER shared-dir file is owned by svc(1500) or root(0).
    ua = uid_of("/pub/rpd_alice_pub.bin")
    ub = uid_of("/pub/rpd_bob_pub.bin")
    return ua, ub


def _rt9_j_read_then_delete_lifecycle_own(ua, ub, lf_small, A, rc):
    ok(all((ua >= 1000, ub >= 1000, ua != UID_SVC, ub != UID_SVC, ua != 0, ub != 0, ua != ub)),
       f"root:// pub/ files owned by distinct mapped users, never svc/root "
       f"(alice={ua}, bob={ub})")

    # =====================================================================
    # (J) READ-then-DELETE lifecycle (own file)
    # =====================================================================
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_rmlife.bin", A)
    dl2 = os.path.join(WORK, "rpd_rmlife_dl.bin")
    rcd, _o, _e = xrd_cp_down("/alice/rpd_rmlife.bin", dl2, A)
    got2 = b""
    return rc, dl2, rcd


def _rt9_alice_must_not_be_able_to(dl2, A, rc, rcd, SMALL, realp):
    try:
        got2 = open(dl2, "rb").read() if os.path.exists(dl2) else b""
    except OSError:
        got2 = b""
    rcrm, _o, _e = xrd_fs(["rm", "/alice/rpd_rmlife.bin"], A)
    ok(all((rc == 0, rcd == 0, got2 == SMALL, rcrm == 0, not os.path.exists(realp('/alice/rpd_rmlife.bin')))),
       f"root:// read-then-delete own file lifecycle (up={rc}, down={rcd}, "
       f"rm={rcrm})")

    # alice must NOT be able to rm bob's file (delete needs write on bob's dir).
    rc, _o, _e = xrd_fs(["rm", "/bob/readable.txt"], A)
    ok(all((rc != 0, os.path.exists(realp('/bob/readable.txt')))),
       f"root:// rm bob's file DENIED, file intact (rc={rc})")


def _rt9_k_escalation_via_the_stream_data(lf_small, realp, uid_of, A, rc):

    # =====================================================================
    # (K) ESCALATION via the STREAM data plane — forbidden / unmapped principals
    # =====================================================================
    for sub in ["root", "svc", "sys100", "dockerite", "mallory"]:
        fp_rel = f"/pub/rpd_esc_{sub}.bin"
        rc, _o, _e = xrd_cp_up(lf_small, fp_rel, sub)
        created = os.path.exists(realp(fp_rel))
        bad_owner = created and uid_of(fp_rel) < 1000
        ok(all((rc != 0, not created, not bad_owner)),
           f"root:// data-plane write as principal '{sub}' DENIED, no file "
           f"(rc={rc}, created={created})")

    # =====================================================================
    # (L) CONFINEMENT via the stream protocol — symlink escape + traversal
    # =====================================================================
    rc, out, _e = xrd_fs(["cat", "/escape/passwd"], A)
    ok('root:x:0:0' not in any((out, '')),
       f"root:// cat through /escape symlink did NOT read /etc/passwd (rc={rc})")
    pw = os.path.join(WORK, "rpd_pw.bin")
    rc, _o, _e = xrd_cp_down("/escape/passwd", pw, A)
    return rc, pw


def _rt9_traversal_in_the_wire_path_must(pw, rc, data):
    leaked_pw = False
    try:
        leaked_pw = os.path.exists(pw) and b"root:x:0:0" in open(pw, "rb").read()
    except OSError:
        leaked_pw = False
    ok(not leaked_pw, f"root:// xrdcp through symlink did NOT exfil /etc/passwd (rc={rc})")
    # traversal in the wire path must not escape (no OUTSIDE sentinel created).
    sentinel = os.path.join(os.path.dirname(data.rstrip("/")), "RPD_OUTSIDE")
    try:
        if os.path.exists(sentinel):
            os.remove(sentinel)
    except OSError:
        pass
    return sentinel


def _rt9_m_sequential_many_small_files_burst(lf_small, A, sentinel, data):
    xrd_cp_up(lf_small, "/../RPD_OUTSIDE", A)
    xrd_fs(["mkdir", "/../RPD_OUTSIDE_DIR"], A)
    ok(all((not os.path.exists(sentinel), not os.path.exists(os.path.join(os.path.dirname(data.rstrip('/')), 'RPD_OUTSIDE_DIR')))),
       "root:// traversal (../) did not escape the export root")

    # =====================================================================
    # (M) SEQUENTIAL many-small-files burst — every file owned by the mapping user
    #     (no setfsuid principal drift across back-to-back ops on one worker).
    # =====================================================================
    N = 16
    bad = 0
    return N, bad


def _rt9_interleave_a_single_bob_write_in(N, lf_small, A, uid_of, bad, B):
    for i in range(N):
        rel = f"/alice/rpd_seq_{i}.bin"
        rc, _o, _e = xrd_cp_up(lf_small, rel, A)
        if not (rc == 0 and uid_of(rel) == UID_ALICE):
            bad += 1
    ok(bad == 0,
       f"root:// {N} sequential alice writes all owned by alice (mismatches={bad})")

    # interleave a single bob write in the middle of alice's burst and re-verify a
    # FRESH alice write still lands as alice (principal not stuck on bob).
    xrd_cp_up(lf_small, "/bob/rpd_seq_bob.bin", B)
    rc, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_seq_after_bob.bin", A)
    ok(all((rc == 0, uid_of('/alice/rpd_seq_after_bob.bin') == UID_ALICE, uid_of('/bob/rpd_seq_bob.bin') == UID_BOB)),
       f"root:// alice write after an interleaved bob write stays alice-owned "
       f"(rc={rc})")


def _rt9_n_second_identity_self_matrix_bob(lf_small, B, uid_of, mode_of, A):

    # =====================================================================
    # (N) SECOND-IDENTITY SELF-MATRIX (bob) — full ownership/DAC parity, and the
    #     reverse cross-tenant deny (bob must not touch ALICE's data).
    # =====================================================================
    # (N1) bob creates a private file -> owned by bob.
    rc, _o, _e = xrd_cp_up(lf_small, "/bob/rpd_bself.bin", B)
    ok(all((rc == 0, uid_of('/bob/rpd_bself.bin') == UID_BOB)),
       f"root:// bob self-write owned by bob (rc={rc})")
    # (N2) bob chmod own file works.
    rc, _o, _e = xrd_fs(["chmod", "/bob/rpd_bself.bin", "600"], B)
    ok(all((rc == 0, mode_of('/bob/rpd_bself.bin') == 384)),
       f"root:// bob chmod own file (rc={rc})")
    # (N3) seed an alice 0600 secret, then prove BOB cannot read/mutate it.
    rcseed, _o, _e = xrd_cp_up(lf_small, "/alice/rpd_asecret.bin", A)


def _rt9_segment_34(A, B, mode_of, rc):
    xrd_fs(["chmod", "/alice/rpd_asecret.bin", "600"], A)
    rc, out, _e = xrd_fs(["cat", "/alice/rpd_asecret.bin"], B)
    ok(all((rc != 0, 'rpd-small' not in any((out, '')))),
       f"root:// bob cat alice's 0600 file DENIED + no leak (rc={rc})")
    pre_m = mode_of("/alice/rpd_asecret.bin")
    rc, _o, _e = xrd_fs(["chmod", "/alice/rpd_asecret.bin", "777"], B)
    return rc, pre_m


def _rt9_o_forged_invalid_raw_tokens_over(rc, mode_of, pre_m, B, realp, key, lf_small, A):
    ok(all((rc != 0, mode_of('/alice/rpd_asecret.bin') == pre_m)),
       f"root:// bob chmod alice's file DENIED, mode intact ({pre_m:o}, rc={rc})")
    rc, _o, _e = xrd_fs(["rm", "/alice/rpd_asecret.bin"], B)
    ok(all((rc != 0, os.path.exists(realp('/alice/rpd_asecret.bin')))),
       f"root:// bob rm alice's file DENIED, intact (rc={rc})")

    # =====================================================================
    # (O) FORGED / INVALID raw tokens over the stream protocol — none may map to a
    #     UNIX identity or create a file in the shared pub/ dir.
    # =====================================================================
    for label, tok in _forged_tokens(key):
        rel = f"/pub/rpd_forge.bin"
        try:
            if os.path.exists(realp(rel)):
                os.remove(realp(rel))
        except OSError:
            pass
        rc, _o, _e = xrd_fs_token(["stat", "/alice/"], tok)
        ok(rc != 0,
           f"root:// forged token '{label}' rejected for stat (rc={rc})")

    # =====================================================================
    # (P) WORKER SURVIVES — after all the abuse, a legit alice op still succeeds
    #     (the broker / worker were not wedged by any of the above attacks).
    # =====================================================================
    rc, _o, e = xrd_cp_up(lf_small, "/alice/rpd_survive.bin", A)
    return rc, e


def _rt9_segment_36(rc, uid_of, e, A):
    ok(all((rc == 0, uid_of('/alice/rpd_survive.bin') == UID_ALICE)),
       f"root:// worker SURVIVES the battery; legit alice op still works "
       f"(rc={rc}, {e.strip()[:60]})")
    rc, _o, _e = xrd_fs(["stat", "/alice/rpd_survive.bin"], A)
    ok(rc == 0, f"root:// follow-up stat after survival write OK (rc={rc})")


def run_root_protocol_depth(key, data, port, s3port):
    """root:// STREAM protocol DEPTH under impersonation — combinatorial xrdfs/xrdcp
    matrix that goes deeper than run_root_battery / run_root_deep.  Exhaustively
    drives open modes (new / update / truncate-shrink / re-write / read-only) and
    their resulting ownership, query checksum/config/space/xattr (self vs bob 0600,
    no body leak), locate, stat self vs cross-tenant, nested mkdir + per-level
    ownership, rmdir non-empty-vs-empty (self + bob), mv within-tenant /
    cross-tenant-source / into-svconly, chmod own (mode actually changes) vs bob
    (denied, mode intact), truncate own vs bob, pub/ (0777 shared) write owned by
    the WRITER, read-then-delete, query xattr of user.* on own file, and a burst of
    sequential small files all owned by the mapping user.  Every mutating op has a
    self-success POSITIVE CONTROL beside its cross-tenant/escalation DENY so a
    blanket block cannot false-pass.  GUARDED by xrd_avail()."""
    if not xrd_avail():
        ok(True, "root:// protocol-depth skipped (native xrdfs/xrdcp absent)")
        return
    A, B, MARK_BOB, MARK_SVC = _rt9_segment_01()

    realp = _rt9_segment_02(data)

    uid_of = _rt9_segment_03(realp)

    mode_of = _rt9_segment_04(realp)

    size_of = _rt9_segment_05(realp)

    local = _rt9_segment_06()

    BIG, SMALL, lf_big, lf_small, rc = _rt9_seed_local_payloads_of_distinct_sizes(local, A)

    _rt9_a2_update_overwrite_existing_with_a(rc, uid_of, size_of, BIG, lf_small, A, SMALL)

    rc, dl, rc2 = _rt9_a4_truncate_grow_sparse_own_file(A, size_of, uid_of, lf_big, rc)

    _rt9_a6_bob_writes_his_own_new(dl, rc, rc2, BIG, lf_small, B, uid_of)

    rc, out = _rt9_b_query_matrix_checksum_config_space(A, MARK_BOB, rc)

    _rt9_b4_query_config_of_a_benign(rc, MARK_SVC, out, A, MARK_BOB)

    rc, out = _rt9_b6_query_xattr_user_xrdcks_on(A, MARK_BOB, MARK_SVC, rc, out)

    _rt9_c_stat_statx_locate_self_vs(MARK_BOB, out, rc, A)

    rc, out = _rt9_c4_locate_own_dir_works_positive(A, rc, out)

    rc = _rt9_d_nested_mkdir_per_level_ownership(out, rc, A, uid_of, lf_small)

    _rt9_d3_mkdir_into_bob_s_0700(rc, uid_of, A, realp)

    rcA, rcB = _rt9_e_rmdir_non_empty_vs_empty(A, realp)

    rc = _rt9_e3_rmdir_bob_s_secret_0700(rcA, rcB, realp, A, lf_small, rc)

    _rt9_f2_cross_tenant_source_mv_bob(A, rc, uid_of, realp, size_of, SMALL)

    _rt9_control_proving_f3_s_deny_is(A, realp, uid_of, lf_small)

    _rt9_segment_22(mode_of, A)

    rc, pre_r = _rt9_g2_chmod_bob_s_private_0600(mode_of, A, rc)

    rc, sz_b = _rt9_h_truncate_own_shrinks_vs_bob(rc, mode_of, pre_r, A, size_of)

    rc = _rt9_h3_truncate_bob_s_0644_file(rc, size_of, sz_b, A, lf_small)

    ua, ub = _rt9_invariant_neither_shared_dir_file_is(rc, uid_of, lf_small, B)

    rc, dl2, rcd = _rt9_j_read_then_delete_lifecycle_own(ua, ub, lf_small, A, rc)

    _rt9_alice_must_not_be_able_to(dl2, A, rc, rcd, SMALL, realp)

    rc, pw = _rt9_k_escalation_via_the_stream_data(lf_small, realp, uid_of, A, rc)

    sentinel = _rt9_traversal_in_the_wire_path_must(pw, rc, data)

    N, bad = _rt9_m_sequential_many_small_files_burst(lf_small, A, sentinel, data)

    _rt9_interleave_a_single_bob_write_in(N, lf_small, A, uid_of, bad, B)

    _rt9_n_second_identity_self_matrix_bob(lf_small, B, uid_of, mode_of, A)

    rc, pre_m = _rt9_segment_34(A, B, mode_of, rc)

    rc, e = _rt9_o_forged_invalid_raw_tokens_over(
        rc, mode_of, pre_m, B, realp, key, lf_small, A
    )

    _rt9_segment_36(rc, uid_of, e, A)
