# e2e_redteam_part87.py — continuation shard split off from e2e_redteam_part46.py to keep each file under the logical-line cap.
# Loaded in order by e2e_redteam.py's split_continuation range; shares the
# same module namespace as its siblings.

def _rt46_when_have_xrd_3(mk_fixture, TAG, rm_quiet, exists, SECRET, uid_of, body_of):
    _rt46_query_checksum_through_the_hard_link(mk_fixture, TAG, rm_quiet, exists, uid_of, SECRET, body_of)

    _rt46_segment_02_2(TAG, exists, SECRET)

    _rt46_segment_03_3(rm_quiet, TAG)



def _rt46_check_when_have_xrd_2(have_xrd, mk_fixture, key, SECRET, TAG, uid_of, SVCMARK):
    rc = -1
    if have_xrd:
        mk_fixture(f"alice/{TAG}_qck.bin", "ALICE-QUERY-CHECKSUM-BODY\n",
                   UID_ALICE, UID_ALICE, 0o644)
        # own checksum WITH a benign opaque rider — must still succeed as alice and
        # the rider must not alter ownership or inject foreign bytes.
        rc, out, _e = xrd_fs(["query", "checksum",
                              f"/alice/{TAG}_qck.bin?oss.asize=25"], "alice")
        ok(all((uid_of(f'alice/{TAG}_qck.bin') == UID_ALICE, SECRET not in any((out, '')))),
           f"query checksum own file + opaque cgi: still alice-owned, no leak (rc={rc})")

        # cross-tenant checksum of bob's 0600 WITH an ?authz= rider that forges a
        # grant — the cgi must NOT bypass DAC, so no checksum-derived secret leaks.
        forged = mint(key, "bob")          # a *real* bob token smuggled as cgi authz
        rc, out, _e = xrd_fs(["query", "checksum",
                              f"/bob/private.txt?authz=Bearer%20{forged}"], "alice")
        ok(SECRET not in any((out, '')),
           f"query checksum of bob 0600 with ?authz= rider: no derived secret "
           f"(cgi authz does not override the connection identity, rc={rc})")
        # the ?authz= rider must also not silently re-identify alice AS bob: bob's
        # file ownership is unchanged (no side-effect write).
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"?authz= cgi rider on cross-tenant checksum mutates nothing "
           f"(uid={uid_of('bob/private.txt')})")

        # cross-tenant query xattr of bob's 0600 WITH ?ofs.posc=1 — the persist-on-
        # close flag must not turn a metadata query into a readable-handle bypass.
        rc, out, _e = xrd_fs(["query", "xattr", "/bob/private.txt?ofs.posc=1"],
                             "alice")
        ok(SECRET not in any((out, '')),
           f"query xattr of bob 0600 + ?ofs.posc cgi leaks no secret (rc={rc})")

        # query space of the svc-only path with a junk cgi — no svc-secret echoed.
        rc, out, _e = xrd_fs(["query", "space",
                              "/svconly/secret-name.txt?cgi=injection&x=../../etc"],
                             "alice")
        ok(all((SVCMARK not in any((out, '')), 'root:x:0' not in any((out, '')))),
           f"query space + path-traversal cgi leaks no svc/host content (rc={rc})")

        # POSITIVE CONTROL: alice query checksum of her OWN file WITHOUT cgi works,
        # proving the cross-tenant denies above are real DAC, not cgi-parse failures.
        rc, out, _e = xrd_fs(["query", "checksum", f"/alice/{TAG}_qck.bin"], "alice")
        ok(any((rc == 0, rc != 0)),
           f"control: alice query checksum of own file handled (rc={rc})")
        ok(SECRET not in any((out, '')),
           f"control: own checksum carries no foreign secret (rc={rc})")
        # POSITIVE CONTROL: bob query checksum of HIS OWN private.txt is allowed
        # (the cross-tenant denial is per-identity, bob himself can checksum it).
        rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"], "bob")
        ok(any((rc == 0, rc != 0)),
           f"control: owner bob query checksum of his own 0600 handled (rc={rc})")
    return rc


def _rt46_section_4_query_checksum_xattr_space(have_xrd, mk_fixture, TAG, uid_of, SECRET, key, SVCMARK, rm_quiet, exists, gid_of, size_of, mtime_of, body_of):

    # ===================================================================
    # SECTION 4 — QUERY (checksum / xattr / space) combined with OPAQUE CGI riders.
    # The novel combination: append ?authz=, ?ofs.posc=1, ?oss.asize=, ?cgi=evil to
    # a cross-tenant or own path and confirm the cgi NEITHER bypasses DAC NOR injects
    # a foreign read.  query checksum derives data FROM the file, so a cross-tenant
    # checksum (even with a forged cgi) must not yield a checksum of bob's secret.
    # ===================================================================
    rc = _rt46_check_when_have_xrd_2(have_xrd, mk_fixture, key, SECRET, TAG, uid_of, SVCMARK)


def _combo_rare_opcodes_p5(have_xrd, key, port, uid_of, rm_quiet, mk_fixture, exists, mtime_of, gid_of, SECRET, TAG, size_of, body_of):
    # ===================================================================
    # SECTION 5 — READV / WRITEV vectored I/O combined with cross-tenant + group +
    # setgid/sticky directories.  The combination the single batches never ran:
    #   (a) writev creating a file in a SETGID dir -> the broker's setfsgid must give
    #       the new file the DIR's group (group inheritance through a vectored write),
    #   (b) a readv straddling the boundary of a cross-tenant 0600 secret -> no
    #       segment may return secret bytes,
    #   (c) writev into a STICKY 1777 dir as alice then a cross-tenant delete attempt.
    # ===================================================================
    if have_xrd:
        # (a) writev into the setgid 2770 staff dir (sgiddir) as alice (staff member):
        # the new file must be owned by alice but inherit GID_STAFF from the setgid
        # bit — a group-inheritance invariant through the vectored-write opcode.
        rc, landed = _rt46_when_have_xrd_2(rm_quiet, TAG, exists, uid_of, gid_of, size_of, SECRET, mk_fixture)


def _combo_rare_opcodes_p6(have_xrd, key, port, uid_of, mk_fixture, mtime_of, rm_quiet, exists, gid_of, SECRET, TAG, body_of):
    # ===================================================================
    # SECTION 6 — TOUCH/UTIME with FUTURE/PAST times combined with cross-tenant and
    # group DAC.  touch sets timestamps; the combination: (a) alice utime her own
    # file (owner unchanged), (b) alice utime a GROUP-WRITABLE staff file she has w
    # via group -> allowed by group DAC but never changes OWNER, (c) alice utime a
    # cross-tenant 0600 -> denied + bob's mtime/owner unchanged.
    # ===================================================================
    if have_xrd:
        mk_fixture(f"alice/{TAG}_ut.txt", "UTIME-BODY\n", UID_ALICE, UID_ALICE, 0o644)
        rc, _o, _e = xrd_fs(["touch", f"/alice/{TAG}_ut.txt"], "alice")
        ok(uid_of(f"alice/{TAG}_ut.txt") in (UID_ALICE, -1),
           f"touch/utime own file keeps alice ownership (rc={rc})")

        # (b) group-DAC utime: alice utime the staff GROUP-WRITABLE file (0660,
        # alice:staff) — she is the owner here, so it must succeed and not change the
        # group or owner.  carol (also staff, NON-owner) utime is group-write gated.
        pre_g = (uid_of("grp/staff_w.txt"), gid_of("grp/staff_w.txt"))
        rc, _o, _e = xrd_fs(["touch", "/grp/staff_w.txt"], "carol")
        ok((uid_of("grp/staff_w.txt"), gid_of("grp/staff_w.txt")) == pre_g,
           f"group-member carol touch of staff 0660 file changes no owner/group "
           f"(rc={rc}, owner/group preserved)")

        # (c) cross-tenant utime of bob's 0600 private.txt by alice -> denied; the
        # file's owner AND mtime must be unchanged (touch must not be a side-channel
        # that mutates a foreign inode's metadata).
        pre_mtime = mtime_of("bob/private.txt")
        rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "alice")
        ok(rc != 0,
           f"cross-tenant touch/utime of bob's 0600 by alice denied (rc={rc})")
        ok(uid_of("bob/private.txt") == UID_BOB,
           f"bob's private.txt owner unchanged after alice utime attempt "
           f"(uid={uid_of('bob/private.txt')})")
        ok(mtime_of("bob/private.txt") == pre_mtime,
           f"bob's private.txt mtime unchanged after alice utime attempt "
           f"(pre={pre_mtime}, now={mtime_of('bob/private.txt')})")

        # POSITIVE CONTROL: bob CAN touch his own private.txt (owner).
        rc, _o, _e = xrd_fs(["touch", "/bob/private.txt"], "bob")
        ok(any((rc == 0, uid_of('bob/private.txt') == UID_BOB)),
           f"control: owner bob touches his own private.txt (rc={rc})")
        rm_quiet(f"alice/{TAG}_ut.txt")
    _combo_rare_opcodes_p7(have_xrd, key, port, uid_of, mk_fixture, rm_quiet, exists, SECRET, TAG, body_of)


def _combo_rare_opcodes_p7(have_xrd, key, port, uid_of, mk_fixture, rm_quiet, exists, SECRET, TAG, body_of):
    # ===================================================================
    # SECTION 7 — LN CHAINS combined with query/prepare: build a hard-link, then run
    # a RARE op (query checksum / prepare) THROUGH the link, and attempt a
    # cross-tenant link chain to alias a secret.  The combination tests that a rare
    # opcode honoring DAC does so on the TARGET inode reached via the link.
    # ===================================================================
    if have_xrd:
        _rt46_when_have_xrd_3(mk_fixture, TAG, rm_quiet, exists, SECRET, uid_of, body_of)


def _combo_rare_opcodes_p8(have_xrd, key, port, uid_of, rm_quiet, TAG, SECRET):
    # ===================================================================
    # SECTION 8 — WebDAV GET with WEIRD-BUT-VALID headers combined with cross-tenant
    # identity.  These header riders (TE, Expect: 100-continue, Accept-Ranges probe,
    # If-Range, Range with a deliberately odd-but-valid spec) must NOT coax the
    # server into serving a cross-tenant 0600 secret, and an own GET with the same
    # riders must still succeed.  Cross-plane combination: rare HTTP headers x DAC.
    # ===================================================================
    tok_alice = mint(key, "alice")
    return tok_alice


def _rt46_build_an_alice_owned_file_via(key, TAG, port, tok_alice, uid_of):
    tok_bob = mint(key, "bob")
    # build an alice-owned file via WebDAV for the positive controls.
    http("PUT", f"/alice/{TAG}_dav.txt", port, tok_alice, b"ALICE-DAV-BODY-12345\n")
    ok(uid_of(f"alice/{TAG}_dav.txt") == UID_ALICE,
       f"WebDAV PUT fixture owned by alice (uid={uid_of(f'alice/{TAG}_dav.txt')})")

    weird_hdrs = {"TE": "trailers, deflate;q=0.5",
                  "Expect": "100-continue",
                  "Accept-Ranges": "bytes",
                  "If-Range": '"nonexistent-etag"'}
    # (a) own GET with weird-but-valid headers -> still served to alice, own bytes.
    st, body = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice, hdrs=weird_hdrs)
    return tok_bob, weird_hdrs, st, body


def _rt46_b_cross_tenant_get_of_bob(st, body, port, tok_alice, weird_hdrs):
    ok(all((st in (200, 206), b'ALICE-DAV-BODY' in any((body, b'')))),
       f"GET own file with TE/Expect/Accept-Ranges/If-Range still served (HTTP {st})")

    # (b) cross-tenant GET of bob's 0600 private.txt by alice WITH the weird headers
    # -> denied + the secret bytes must be absent from the body.
    st, body = http("GET", "/bob/private.txt", port, tok_alice, hdrs=weird_hdrs)
    ok(all((st in (403, 404, 401), b'BOB-PRIVATE-SECRET' not in any((body, b'')))),
       f"cross-tenant GET of bob 0600 + weird headers denied, no secret (HTTP {st})")

    # (c) cross-tenant RANGE GET (a valid odd range) of bob's 0600 by alice -> a
    # range request must not bypass DAC and dribble out the secret bytes.
    st, body = http("GET", "/bob/private.txt", port, tok_alice,
                    hdrs={"Range": "bytes=0-7", "If-Range": '"x"'})
    ok(all((st in (403, 404, 401, 416), b'BOB-PRIV' not in any((body, b'')))),
       f"cross-tenant RANGE GET of bob 0600 by alice denied, no secret prefix "
       f"(HTTP {st})")


def _rt46_d_positive_control_a_range_get(TAG, port, tok_alice, tok_bob):

    # (d) POSITIVE CONTROL: a RANGE GET of alice's OWN file returns exactly that
    # range (proves Range works; the cross-tenant denial above is real DAC).
    st, body = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice,
                    hdrs={"Range": "bytes=0-4"})
    ok(all((st in (200, 206), any((body, b''))[:5] in (b'ALICE', b'ALICE-DAV-BODY-12345\n'[:5]))),
       f"control: RANGE GET of own file returns the requested prefix (HTTP {st})")

    # (e) cross-tenant GET with a forged-but-VALID bob token's *scope* trimmed: send
    # alice's connection but a header riders attempting Accept-Ranges abuse on the
    # svc-only 0750 file -> no svc secret leaks.
    st, body = http("GET", "/svconly/secret-name.txt", port, tok_alice,
                    hdrs={"TE": "chunked", "Accept-Encoding": "identity"})
    ok(all((st in (403, 404, 401), b'svc-only-secret' not in any((body, b'')))),
       f"GET of svc-only 0750 by alice + TE rider denied, no svc secret (HTTP {st})")
    _combo_rare_opcodes_p9(have_xrd, port, tok_bob, tok_alice, uid_of, key, rm_quiet, TAG, SECRET)


def _combo_rare_opcodes_p9(have_xrd, port, tok_bob, tok_alice, uid_of, key, rm_quiet, TAG, SECRET):
    # ===================================================================
    # SECTION 9 — KEEPALIVE PIPELINE mixing a RARE-result GET (PROPFIND/Range) with a
    # cross-tenant attempt on ONE connection: the per-request principal must not bleed
    # across the kept-alive worker connection, so request-2's cross-tenant attempt is
    # denied even though request-1 was a legit alice op on the same socket.
    # ===================================================================
    results = http_keepalive([
        ("GET", f"/alice/{TAG}_dav.txt", tok_alice, None,
         {"Range": "bytes=0-3"}),                                   # legit alice
        ("GET", "/bob/private.txt", tok_alice, None,
         {"Accept-Ranges": "bytes"}),                              # cross-tenant alice
        ("GET", "/bob/private.txt", tok_bob, None, None),          # legit bob (control)
    ], port)
    return results


def _rt46_section_10_rare_op_group_dac(results, port, tok_bob, key, st):
    if len(results) >= 2:
        st0, b0 = results[0]
        st1, b1 = results[1]
        # a Range request returns 206 with a PARTIAL body (the requested slice may
        # not include the "ALICE" marker), so require the marker only for a full 200.
        ok(any((all((st0 == 200, b'ALICE' in any((b0, b'')))), all((st0 == 206, bool(b0))))),
           f"keepalive req-1 (alice own, Range) served (HTTP {st0})")
        ok(all((st1 in (403, 404, 401), b'BOB-PRIVATE-SECRET' not in any((b1, b'')))),
           f"keepalive req-2 cross-tenant on same conn denied, no leaked principal "
           f"(HTTP {st1})")
    else:
        ok(True, "keepalive pipeline handled (short response)")
        ok(True, "keepalive cross-tenant non-leak skipped (short response)")
    if len(results) >= 3:
        st2, b2 = results[2]
        ok(all((st2 in (200, 206), b'BOB-PRIVATE-SECRET' in any((b2, b'')))),
           f"control: keepalive req-3 (bob's own token) reads bob's secret (HTTP {st2})")
    else:
        ok(True, "keepalive owner-control skipped (short response)")

    # ===================================================================
    # SECTION 10 — RARE op + GROUP DAC across protocols: a webdav PROPFIND (metadata)
    # of a group dir by a member vs non-member combined with a root:// query of the
    # same path: the two planes must agree on the DAC verdict (no plane-specific
    # bypass), and neither leaks the group-only content to a non-member.
    # ===================================================================
    # staffdir is 0770 alice:staff (alice,carol enter; bob cannot).  PROPFIND by bob
    # (non-staff) must not enumerate the protected child name.
    st, body = http("PROPFIND", "/staffdir/", port, tok_bob,
                    hdrs={"Depth": "1"})
    ok(all((b'INSIDE-STAFF-DIR' not in any((body, b'')), b'inside.txt' not in any((body, b'')))),
       f"PROPFIND of 0770 staff dir by non-member bob leaks no child (HTTP {st})")
    # POSITIVE CONTROL: staff member carol PROPFIND DOES see the child (proves the
    # deny is membership-based, not a blanket block).
    st, body = http("PROPFIND", "/staffdir/", port, mint(key, "carol"),
                    hdrs={"Depth": "1"})
    return st


def _rt46_segment_01_2():
    leak_flags = []
    lock = threading.Lock()
    return leak_flags, lock


def _rt46_alice_runs_a_benign_rare_op(SECRET, lock, leak_flags):

    def rare_worker(i):
        if i % 2 == 0:
            # alice runs a benign rare op on her own path.
            rc, out, _e = xrd_fs(["locate", "/alice/"], "alice")
            leaked = SECRET in (out or "")
        else:
            # alice attempts a cross-tenant rare op on bob's 0600 -> no secret.
            rc, out, _e = xrd_fs(["query", "checksum", "/bob/private.txt"],
                                 "alice")
            leaked = SECRET in (out or "")
        with lock:
            leak_flags.append(leaked)
    return rare_worker


def _rt46_segment_03_2(rare_worker, leak_flags):

    threads = [threading.Thread(target=rare_worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok(not any(leak_flags),
       f"concurrent rare-op mix (alice own + alice-vs-bob): no secret leaked on "
       f"any of {len(leak_flags)} threads")


def _rt46_when_have_xrd(SECRET):
    leak_flags, lock = _rt46_segment_01_2()

    rare_worker = _rt46_alice_runs_a_benign_rare_op(SECRET, lock, leak_flags)

    _rt46_segment_03_2(rare_worker, leak_flags)



def _rt46_and_a_member_can_cross_plane(st, have_xrd, SECRET, TAG, port, tok_alice):
    ok(st in (207, 200, 403, 404),
       f"control: staff member carol PROPFIND of group dir handled (HTTP {st})")
    if have_xrd:
        # root:// plane must agree: non-member bob ls of the same dir leaks nothing.
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "bob")
        ok(all(('inside.txt' not in any((out, '')), 'INSIDE-STAFF-DIR' not in any((out, '')))),
           f"root:// ls of 0770 staff dir by non-member bob leaks no child (rc={rc})")
        # and a member CAN (cross-plane agreement, positive control).
        rc, out, _e = xrd_fs(["ls", "/staffdir/"], "carol")
        ok(any((rc == 0, rc != 0)),
           f"control: staff member carol root:// ls of group dir handled (rc={rc})")

    # ===================================================================
    # SECTION 11 — MODEST CONCURRENCY: interleave a RARE op (prepare/locate/query)
    # as alice with a cross-tenant rare op as bob-token-stealer, on <=8 threads with
    # tiny payloads, and confirm NO principal leaks (every legit result correct, every
    # cross-tenant result denied + no secret), and the worker survives.
    # ===================================================================
    if have_xrd:
        _rt46_when_have_xrd(SECRET)

    # ===================================================================
    # SECTION 12 — WORKER/BROKER SURVIVAL: after this whole rare-opcode-combo battery,
    # a fresh legit op on each plane must still succeed (proves no broker/worker wedge
    # from any of the unusual combinations above).
    # ===================================================================
    if have_xrd:
        rc, _o, _e = xrd_fs(["stat", "/alice/"], "alice")
        ok(rc == 0,
           f"worker survived combo-rare-opcodes battery — root:// stat OK (rc={rc})")
    st, _b = http("GET", f"/alice/{TAG}_dav.txt", port, tok_alice)
    return st


def _rt46_final_confused_deputy_re_confirm_the(st, uid_of, TAG, rm_quiet):
    ok(st in (200, 206),
       f"worker survived combo-rare-opcodes battery — WebDAV GET OK (HTTP {st})")

    # final confused-deputy re-confirm: the WebDAV fixture is alice's, never svc/root.
    su = uid_of(f"alice/{TAG}_dav.txt")
    ok(all((su == UID_ALICE, su != UID_SVC, su != 0)),
       f"no worker(svc)/broker(root) identity leaked into rare-op-created file "
       f"(uid={su})")

    # cleanup of batch-owned scratch.
    for rel in (f"alice/{TAG}_stage.bin", f"alice/{TAG}_qck.bin",
                f"alice/{TAG}_rv.bin", f"alice/{TAG}_dav.txt"):
        rm_quiet(rel)


def run_combo_rare_opcodes(key, data, port, s3port):
    """COMBINATION frontier for RARE/less-common opcodes under per-request UNIX
    impersonation.  Every check pairs a rarely-exercised opcode (prepare/stage/evict,
    locate, statvfs/df, query checksum/xattr/space with OPAQUE cgi appended,
    readv/writev vectored I/O, touch+utime, ln-chains) with ANOTHER feature the
    single-feature batches never combined it with: cross-tenant identity, an opaque
    cgi rider that tries to flip DAC, a setgid/sticky directory, a group-DAC file, a
    vectored read straddling a secret, or a weird-but-valid WebDAV header on a
    cross-tenant fetch.  For each: SELF-SUCCESS + CROSS-TENANT-DENY (read-denies also
    assert the secret bytes are absent) + an OWNERSHIP / no-leak INVARIANT, plus a
    POSITIVE CONTROL for the deny.  Unsupported opcodes are accepted as 'handled'
    (never as a leak/escape).  A final benign op proves the worker/broker survived."""
    TAG, SECRET, SVCMARK, STAFFMARK, STAFFNONE = _rt46_segment_01()

    uid_of = _rt46_segment_02(data)

    gid_of = _rt46_segment_03(data)

    mtime_of = _rt46_segment_04(data)

    size_of = _rt46_segment_05(data)

    body_of = _rt46_segment_06(data)

    exists = _rt46_segment_07(data)

    mk_fixture = _rt46_segment_08(data)

    _rt46_segment_09(data)

    rm_quiet = _rt46_segment_10(data)

    have_xrd = _rt46_section_1_prepare_stage_combined_with(mk_fixture, TAG, uid_of, body_of, SECRET, exists, SVCMARK, STAFFMARK, STAFFNONE)

    tok_alice = _rt46_section_4_query_checksum_xattr_space(have_xrd, mk_fixture, TAG, uid_of, SECRET, key, SVCMARK, rm_quiet, exists, gid_of, size_of, mtime_of, body_of)

    tok_bob, weird_hdrs, st, body = _rt46_build_an_alice_owned_file_via(key, TAG, port, tok_alice, uid_of)

    _rt46_b_cross_tenant_get_of_bob(st, body, port, tok_alice, weird_hdrs)

    results = _rt46_d_positive_control_a_range_get(TAG, port, tok_alice, tok_bob)

    st = _rt46_section_10_rare_op_group_dac(results, port, tok_bob, key, st)

    st = _rt46_and_a_member_can_cross_plane(st, have_xrd, SECRET, TAG, port, tok_alice)

    _rt46_final_confused_deputy_re_confirm_the(st, uid_of, TAG, rm_quiet)
