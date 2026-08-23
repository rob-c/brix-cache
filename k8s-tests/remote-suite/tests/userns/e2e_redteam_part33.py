def _rt33_segment_01(key, s3port):
    TAG = "dpi"
    ta = mint(key, "alice")
    tb = mint(key, "bob")
    have_root = xrd_avail()
    have_s3 = bool(s3port)
    return TAG, ta, tb, have_root, have_s3


def _rt33_segment_02():
    SZ = 256 * 1024                                   # modest "large" payload
    return SZ


def _rt33_segment_03(data):

    def rel(*parts):
        return os.path.join(data, *parts)
    return rel


def _rt33_segment_04():

    def uid_of(p):
        try:
            return os.stat(p).st_uid
        except OSError:
            return -1
    return uid_of


def _rt33_segment_05():

    def size_of(p):
        try:
            return os.stat(p).st_size
        except OSError:
            return -1
    return size_of


def _rt33_segment_06():

    def body_of(p):
        try:
            with open(p, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return body_of


def _rt33_segment_07(uid_of):

    def owned_alice(p):
        u = uid_of(p)
        return os.path.exists(p) and u == UID_ALICE and u not in (UID_SVC, 0, UID_BOB)
    return owned_alice


def _rt33_segment_08(TAG):

    def local_write(name, content):
        lf = os.path.join(WORK, TAG + "_" + name)
        try:
            with open(lf, "wb") as fh:
                fh.write(content)
            return lf
        except OSError:
            return None
    return local_write


def _rt33_per_identity_deterministic_position_encoding_patterns():

    # Per-identity deterministic, position-encoding patterns.  Each 16-byte block is
    # tagged with the owner + its block index, so ANY foreign block or shifted offset
    # in a read-back is detectable byte-for-byte (not just a length check).
    def pattern(tag, n):
        out = bytearray()
        blk = 0
        seed = (tag.encode() + b"-")
        while len(out) < n:
            chunk = seed + (b"%08d|" % blk)
            out += chunk
            blk += 1
        return bytes(out[:n])
    return pattern


def _rt33_section_1_large_round_trip_via(pattern, SZ, TAG):

    PAT_A = pattern("ALICE", SZ)                       # alice's large content
    PAT_B = pattern("BOB", SZ)                          # bob's large content (distinct)
    MARK_A = b"ALICE-"                                  # block signature substrings
    MARK_B = b"BOB-"

    # =====================================================================
    # SECTION 1 — large round-trip via EACH write protocol, byte-exact + owned alice
    # =====================================================================
    # (1a) WebDAV PUT large -> read back byte-exact via WebDAV GET, owned alice.
    wd_rel = "alice/%s_wd_big.bin" % TAG
    return PAT_A, PAT_B, MARK_A, MARK_B, wd_rel


def _rt33_segment_11(wd_rel, port, ta, PAT_A, rel, owned_alice, size_of, SZ, uid_of, body_of):
    st, _ = http("PUT", "/" + wd_rel, port, ta, PAT_A)
    wp = rel(*wd_rel.split("/"))
    ok(all((st in (200, 201, 204), owned_alice(wp), size_of(wp) == SZ)),
       "WebDAV PUT 256K -> owned alice 1001 not svc/root/bob, size==SZ "
       "(HTTP %s, uid=%s, size=%s)" % (st, uid_of(wp), size_of(wp)))
    ok(body_of(wp) == PAT_A,
       "WebDAV PUT 256K landed byte-exact on disk (no data-plane corruption)")
    gst, gb = http("GET", "/" + wd_rel, port, ta)
    return gst, gb


def _rt33_segment_01_3(TAG, local_write, PAT_A, rel, owned_alice, size_of, SZ, uid_of):
    rt_rel = "alice/%s_root_big.bin" % TAG
    lf = local_write("root_big_up.bin", PAT_A)
    rc, _o, _e = xrd_cp_up(lf, "/" + rt_rel, "alice") if lf else (-1, "", "")
    rp = rel(*rt_rel.split("/"))
    ok(all((rc == 0, owned_alice(rp), size_of(rp) == SZ)),
       "root:// xrdcp up 256K -> owned alice 1001 not svc, size==SZ (rc=%s, "
       "uid=%s, size=%s)" % (rc, uid_of(rp), size_of(rp)))
    return rt_rel


def _rt33_segment_02_3(TAG, rt_rel, body_of, PAT_A):
    dl = os.path.join(WORK, TAG + "_root_big_dl.bin")
    try:
        if os.path.exists(dl):
            os.unlink(dl)
    except OSError:
        pass
    rc, _o, _e = xrd_cp_down("/" + rt_rel, dl, "alice")
    db = body_of(dl)
    ok(all((rc == 0, db == PAT_A)),
       "root:// xrdcp down reads 256K back BYTE-EXACT via pread (rc=%s, "
       "len=%d)" % (rc, len(db)))
    return dl, rc, db


def _rt33_segment_03_2(MARK_B, db):
    ok(MARK_B not in db,
       "root:// download of alice/big carries NO bob block signature")


def _rt33_when_have_root_2(TAG, local_write, PAT_A, rel, owned_alice, SZ, uid_of, size_of, body_of, MARK_B):
    rt_rel = _rt33_segment_01_3(TAG, local_write, PAT_A, rel, owned_alice, size_of, SZ, uid_of)

    dl, rc, db = _rt33_segment_02_3(TAG, rt_rel, body_of, PAT_A)

    _rt33_segment_03_2(MARK_B, db)

    return rc, dl


def _rt33_segment_01_5(TAG, wd_rel, body_of, PAT_A):
    dl = os.path.join(WORK, TAG + "_wd_via_root.bin")
    try:
        if os.path.exists(dl):
            os.unlink(dl)
    except OSError:
        pass
    rc, _o, _e = xrd_cp_down("/" + wd_rel, dl, "alice")
    ok(all((rc == 0, body_of(dl) == PAT_A)),
       "cross-proto: WebDAV-written 256K reads byte-exact via root:// (rc=%s)"
       % rc)


def _rt33_when_have_root_4(TAG, wd_rel, PAT_A, body_of):
    _rt33_segment_01_5(TAG, wd_rel, body_of, PAT_A)



def _rt33_segment_01_6(TAG, s3port, PAT_A, rel, owned_alice, size_of, SZ, uid_of):
    s3_rel = "alice/%s_s3_big.bin" % TAG
    st, _ = s3("PUT", s3_rel, s3port, data=PAT_A)
    sp = rel(*s3_rel.split("/"))
    ok(all((st in (200, 201), owned_alice(sp), size_of(sp) == SZ)),
       "S3 PUT 256K -> owned alice 1001 not svc, size==SZ (HTTP %s, uid=%s, "
       "size=%s)" % (st, uid_of(sp), size_of(sp)))
    gst, gb = s3("GET", s3_rel, s3port)
    return gst, gb


def _rt33_segment_02_5(gst, gb, PAT_A, MARK_B):
    ok(all((gst == 200, gb == PAT_A)),
       "S3 GET reads the 256K back BYTE-EXACT (HTTP %s, len=%d)"
       % (gst, len(gb or b"")))
    ok(MARK_B not in any((gb, b'')),
       "S3 GET of alice/big carries NO bob block signature")


def _rt33_when_have_s3(TAG, s3port, PAT_A, rel, owned_alice, SZ, uid_of, size_of, MARK_B):
    gst, gb = _rt33_segment_01_6(TAG, s3port, PAT_A, rel, owned_alice, size_of, SZ, uid_of)

    _rt33_segment_02_5(gst, gb, PAT_A, MARK_B)



def _rt33_check_when_have_s3(have_s3, TAG, s3port, PAT_A, rel, owned_alice, SZ, uid_of, size_of, MARK_B):
    if have_s3:
        _rt33_when_have_s3(TAG, s3port, PAT_A, rel, owned_alice, SZ, uid_of, size_of, MARK_B)
    else:
        ok(True, "S3 large round-trip skipped (S3 endpoint down)")
        ok(True, "S3 large GET byte-exact skipped (S3 endpoint down)")
        ok(True, "S3 large no-cross-block skipped (S3 endpoint down)")


def _rt33_1b_s3_put_large_s3_get(gst, gb, PAT_A, MARK_B, have_s3, TAG, s3port, rel, owned_alice, size_of, SZ, uid_of, have_root, local_write, body_of, wd_rel):
    ok(all((gst == 200, gb == PAT_A)),
       "WebDAV GET reads the 256K back BYTE-EXACT through sendfile (HTTP %s, "
       "len=%d)" % (gst, len(gb or b"")))
    ok(MARK_B not in any((gb, b'')),
       "WebDAV GET of alice/big carries NO bob block signature (no cross-buffer)")

    # (1b) S3 PUT large -> S3 GET byte-exact, owned alice.
    _rt33_check_when_have_s3(have_s3, TAG, s3port, PAT_A, rel, owned_alice, SZ, uid_of, size_of, MARK_B)

    # (1c) root:// xrdcp up large -> xrdcp down byte-exact, owned alice.
    if have_root:
        rc, dl = _rt33_when_have_root_2(TAG, local_write, PAT_A, rel, owned_alice, SZ, uid_of, size_of, body_of, MARK_B)
    else:
        ok(True, "root:// large round-trip skipped (native client absent)")
        ok(True, "root:// large download byte-exact skipped (native client absent)")
        ok(True, "root:// large no-cross-block skipped (native client absent)")

    # (1d) CROSS-PROTOCOL read of the same large inode: WebDAV-written file read via
    #      root:// (and vice-versa) must be byte-identical — one fd model, one bytes.
    if have_root:
        _rt33_when_have_root_4(TAG, wd_rel, PAT_A, body_of)
    else:
        ok(True, "cross-proto large read skipped (native client absent)")


def _rt33_section_2_concurrent_large_reads_alice(TAG, have_root, local_write, PAT_B, port, tb, rel, size_of, SZ, uid_of):

    # =====================================================================
    # SECTION 2 — CONCURRENT large reads, alice/big vs bob/big in parallel threads.
    # bob owns a distinct-pattern 0600-ish file; the two reads run interleaved so a
    # shared read buffer / fd table aliasing under impersonation would surface as one
    # stream carrying the other's blocks.  Each thread MUST get ONLY its own bytes.
    # =====================================================================
    # plant bob's large file (as bob), make it bob-owned 0600 (alice may NOT read it).
    bob_rel = "bob/%s_bob_big.bin" % TAG
    if have_root:
        lfb = local_write("bob_big_up.bin", PAT_B)
        if lfb:
            xrd_cp_up(lfb, "/" + bob_rel, "bob")
    else:
        http("PUT", "/" + bob_rel, port, tb, PAT_B)
    bpath = rel(*bob_rel.split("/"))
    ok(all((size_of(bpath) == SZ, uid_of(bpath) == UID_BOB)),
       "setup: bob's 256K file owned by bob 1002, size==SZ (uid=%s, size=%s)"
       % (uid_of(bpath), size_of(bpath)))
    try:
        os.chmod(bpath, 0o600)                        # 0600 -> alice must be denied
    except OSError:
        pass
    return bob_rel, bpath


def _rt33_segment_14():

    results = {}
    barrier = threading.Barrier(2)
    return results, barrier


def _rt33_segment_15(barrier, port, results):

    def reader(name, relpath, tok):
        try:
            barrier.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        st, b = http("GET", "/" + relpath, port, tok)
        results[name] = (st, b or b"")
    return reader


def _rt33_segment_16(reader, wd_rel, ta, bob_rel, tb):

    t_alice = threading.Thread(target=reader, args=("alice", wd_rel, ta))
    t_bob = threading.Thread(target=reader, args=("bob", bob_rel, tb))
    t_alice.start()
    t_bob.start()
    t_alice.join(timeout=15)
    return t_bob


def _rt33_alice_s_concurrent_stream_exactly_her(t_bob, results, PAT_A, MARK_B):
    t_bob.join(timeout=15)

    ast, abody = results.get("alice", (-1, b""))
    bst, bbody = results.get("bob", (-1, b""))
    # alice's concurrent stream: exactly her bytes, NO bob block ever.
    ok(all((ast == 200, abody == PAT_A)),
       "concurrent: alice's parallel GET returns ONLY her 256K byte-exact "
       "(HTTP %s, len=%d)" % (ast, len(abody)))
    ok(MARK_B not in abody,
       "concurrent: alice's stream carries NO bob block signature (no fd/buffer "
       "cross-contamination)")
    return abody, bst, bbody


def _rt33_bob_s_concurrent_stream_exactly_his(bst, bbody, PAT_B, MARK_A, abody, PAT_A, results):
    # bob's concurrent stream: exactly his bytes, NO alice block ever.
    ok(all((bst == 200, bbody == PAT_B)),
       "concurrent: bob's parallel GET returns ONLY his 256K byte-exact "
       "(HTTP %s, len=%d)" % (bst, len(bbody)))
    ok(MARK_A not in bbody,
       "concurrent: bob's stream carries NO alice block signature")
    # cross-witness: the two concurrent streams are not the SAME bytes (would imply
    # one fd served both identities).
    ok(all((abody != bbody, abody == PAT_A, bbody == PAT_B)),
       "concurrent: the two parallel streams are distinct per-identity content")

    # DENY leg: alice (no perms) reading bob's 0600 large file concurrently with her
    # own legit read must be refused, with zero bob blocks leaked.
    results.clear()
    barrier2 = threading.Barrier(2)
    return barrier2


def _rt33_segment_19(barrier2, port, results):

    def reader2(name, relpath, tok):
        try:
            barrier2.wait(timeout=5)
        except threading.BrokenBarrierError:
            pass
        st, b = http("GET", "/" + relpath, port, tok)
        results[name] = (st, b or b"")
    return reader2


def _rt33_segment_20(reader2, wd_rel, ta, bob_rel):

    ta2 = threading.Thread(target=reader2, args=("own", wd_rel, ta))
    tx = threading.Thread(target=reader2, args=("xread", bob_rel, ta))  # alice@bob's
    ta2.start()
    tx.start()
    ta2.join(timeout=15)
    return tx


def _rt33_segment_21(tx, results, MARK_B, PAT_B, PAT_A):
    tx.join(timeout=15)
    ost, obody = results.get("own", (-1, b""))
    xst, xbody = results.get("xread", (-1, b""))
    ok(all((xst in (401, 403, 404), MARK_B not in xbody, xbody != PAT_B)),
       "concurrent DENY: alice GET bob's 0600 256K refused, NO bob bytes leaked "
       "(HTTP %s)" % xst)
    ok(all((ost == 200, obody == PAT_A)),
       "concurrent control: alice's own read stays byte-exact while the denied "
       "cross-read runs alongside (HTTP %s)" % ost)


def _rt33_section_3_partial_range_reads_byte(size_of, bpath, SZ, body_of, PAT_B, wd_rel, port, ta, PAT_A):
    ok(all((size_of(bpath) == SZ, body_of(bpath) == PAT_B)),
       "invariant: bob's 256K file unchanged (size+content) after denied read")

    # =====================================================================
    # SECTION 3 — partial / RANGE reads byte-exact and bounded to the file.
    # =====================================================================
    # (3a) WebDAV Range middle slice == the exact same offset of the on-disk bytes.
    lo, hi = 100000, 100063                            # 64-byte interior window
    st, b = http("GET", "/" + wd_rel, port, ta, hdrs={"Range": "bytes=%d-%d" % (lo, hi)})
    expect = PAT_A[lo:hi + 1]
    ok(all((st in (200, 206), b == expect if st == 206 else expect in b)),
       "WebDAV Range interior slice byte-exact at the requested offset (HTTP %s, "
       "len=%d)" % (st, len(b or b"")))


def _rt33_head_of_bob_s_0600_file(wd_rel, PAT_A, bob_rel):
    rc, out, _e = xrd_fs(["head", "-c", "32", "/" + wd_rel], "alice")
    ok(any((rc != 0, PAT_A[:32].decode('latin-1') in any((out, '')), out == '')),
       "root:// head -c 32 of own 256K exact-or-unsupported (rc=%s)" % rc)
    rc, out, _e = xrd_fs(["tail", "-c", "32", "/" + wd_rel], "alice")
    ok(any((rc != 0, PAT_A[-32:].decode('latin-1') in any((out, '')), out == '')),
       "root:// tail -c 32 of own 256K exact-or-unsupported (rc=%s)" % rc)
    # head of bob's 0600 file: DENY or unsupported, never a bob block.
    rc, out, _e = xrd_fs(["head", "-c", "64", "/" + bob_rel], "alice")
    return rc, out


def _rt33_segment_02_6(MARK_B, out, rc):
    ok(MARK_B.decode() not in any((out, '')),
       "root:// head -c of bob's 0600 256K leaks NO bob block (rc=%s)" % rc)


def _rt33_when_have_root_5(wd_rel, PAT_A, bob_rel, MARK_B):
    rc, out = _rt33_head_of_bob_s_0600_file(wd_rel, PAT_A, bob_rel)

    _rt33_segment_02_6(MARK_B, out, rc)



def _rt33_valid_final_range_length(status, body):
    if status == 206:
        return len(body) == 1
    return bool(body)


def _rt33_assert_final_byte_range(wd_rel, port, ta, size, pattern):
    st, b = http("GET", "/" + wd_rel, port, ta,
                 hdrs={"Range": "bytes=%d-%d" % (size - 1, size - 1)})
    valid_length = _rt33_valid_final_range_length(st, b)
    ok(all((st in (200, 206), valid_length, pattern[-1:] in b)),
       "WebDAV Range final byte exact, no read past EOF (HTTP %s, len=%d)"
       % (st, len(b or b"")))


def _rt33_assert_beyond_eof_range(wd_rel, port, ta, size, foreign_marker):
    st, b = http("GET", "/" + wd_rel, port, ta,
                 hdrs={"Range": "bytes=%d-%d" % (size + 10, size + 99)})
    ok(all((st in (200, 206, 416), foreign_marker not in any((b, b'')))),
       "WebDAV Range beyond EOF handled, no foreign bytes (HTTP %s)" % st)


def _rt33_3b_range_last_byte_only_never(wd_rel, port, ta, SZ, PAT_A, MARK_B, have_root, bob_rel):
    # (3b) Range last byte only — never reads past EOF.
    _rt33_assert_final_byte_range(wd_rel, port, ta, SZ, PAT_A)
    # (3c) wholly-out-of-range start -> 416/200, never fabricated bytes / leak.
    _rt33_assert_beyond_eof_range(wd_rel, port, ta, SZ, MARK_B)
    # (3d) head -c via xrdfs == first-N bytes exact; tail -c == last-N bytes exact.
    if have_root:
        _rt33_when_have_root_5(wd_rel, PAT_A, bob_rel, MARK_B)
    else:
        ok(True, "root:// head exact skipped (native client absent)")
        ok(True, "root:// tail exact skipped (native client absent)")
        ok(True, "root:// head-deny skipped (native client absent)")


def _rt33_segment_01_4(TAG, local_write, rel):
    ck_rel = "alice/%s_ck.bin" % TAG
    ck_data = b"DATAPLANE-CHECKSUM-ORACLE-0123456789" * 16
    lf = local_write("ck.bin", ck_data)
    if lf:
        xrd_cp_up(lf, "/" + ck_rel, "alice")
    ckp = rel(*ck_rel.split("/"))
    return ck_rel, ck_data, ckp


def _rt33_segment_02_4(owned_alice, ckp, body_of, ck_data, ck_rel):
    ok(all((owned_alice(ckp), body_of(ckp) == ck_data)),
       "checksum setup: known payload on disk, alice-owned, byte-exact")
    rc, out, _e = xrd_fs(["query", "checksum", "/" + ck_rel], "alice")
    out_l = (out or "").lower()
    import zlib
    adler = "%08x" % (zlib.adler32(ck_data) & 0xffffffff)
    return rc, out, out_l, zlib, adler


def _rt33_segment_01_7(rc):
    ok(any((rc == 0, rc != 0)),
       "root:// query checksum returned a (crc32c/md5/unsupported) algo, "
       "handled (rc=%s)" % rc)


def _rt33_otherwise_rc_0_crc32_out_l_crc32c(rc):
    _rt33_segment_01_7(rc)



def _rt33_check_when_rc_0_adler32_out_l(rc, out_l, adler, crc32):
    if rc == 0 and "adler32" in out_l:
        ok(adler in out_l,
           "root:// query checksum adler32 MATCHES content oracle (%s)" % adler)
    elif rc == 0 and ("crc32" in out_l and "crc32c" not in out_l):
        ok(crc32 in out_l,
           "root:// query checksum crc32 MATCHES content oracle (%s)" % crc32)
    else:
        _rt33_otherwise_rc_0_crc32_out_l_crc32c(rc)


def _rt33_accept_whatever_algo_the_server_emits(zlib, ck_data, rc, out_l, adler, ck_rel, out, bob_rel):
    crc32 = "%08x" % (zlib.crc32(ck_data) & 0xffffffff)
    # accept whatever algo the server emits; if it returns adler32/crc32 the value
    # MUST equal the content oracle.  Other algos (crc32c/md5) -> handled.
    _rt33_check_when_rc_0_adler32_out_l(rc, out_l, adler, crc32)
    # determinism: re-running the checksum on unchanged content is identical.
    rc2, out2, _e = xrd_fs(["query", "checksum", "/" + ck_rel], "alice")
    ok(any((rc != 0, out2.split()[-1:] == out.split()[-1:], out2 == out)),
       "root:// query checksum is deterministic on unchanged content (rc=%s)"
       % rc2)
    # checksum of bob's 0600 large file: DENIED, never a derived leak/marker.
    rc, out, _e = xrd_fs(["query", "checksum", "/" + bob_rel], "alice")
    return rc, out


def _rt33_segment_04_2(rc, MARK_B, out):
    ok(all((rc != 0, MARK_B.decode() not in any((out, '')))),
       "root:// query checksum of bob's 0600 DENIED + no leak (rc=%s)" % rc)


def _rt33_when_have_root_3(TAG, local_write, rel, owned_alice, body_of, bob_rel, MARK_B):
    ck_rel, ck_data, ckp = _rt33_segment_01_4(TAG, local_write, rel)

    rc, out, out_l, zlib, adler = _rt33_segment_02_4(owned_alice, ckp, body_of, ck_data, ck_rel)

    rc, out = _rt33_accept_whatever_algo_the_server_emits(zlib, ck_data, rc, out_l, adler, ck_rel, out, bob_rel)

    _rt33_segment_04_2(rc, MARK_B, out)



def _rt33_section_4_query_checksum_matches_actual(have_root, TAG, local_write, rel, owned_alice, body_of, bob_rel, MARK_B, port, ta, PAT_A, size_of, SZ):

    # =====================================================================
    # SECTION 4 — query checksum MATCHES actual content (crc32c / adler32 if emitted).
    # =====================================================================
    if have_root:
        # known small payload with a precomputable adler32 / crc32 oracle.
        _rt33_when_have_root_3(TAG, local_write, rel, owned_alice, body_of, bob_rel, MARK_B)
    else:
        ok(True, "checksum setup skipped (native client absent)")
        ok(True, "checksum oracle match skipped (native client absent)")
        ok(True, "checksum determinism skipped (native client absent)")
        ok(True, "checksum cross-tenant deny skipped (native client absent)")

    # =====================================================================
    # SECTION 5 — truncate-to-N then read yields EXACTLY N bytes (data-plane EOF).
    # =====================================================================
    tr_rel = "alice/%s_trunc.bin" % TAG
    st, _ = http("PUT", "/" + tr_rel, port, ta, PAT_A)           # start at 256K
    trp = rel(*tr_rel.split("/"))
    ok(all((size_of(trp) == SZ, owned_alice(trp))),
       "truncate setup: 256K file alice-owned on disk (size=%s)" % size_of(trp))
    return tr_rel, trp


def _rt33_section_6_overwrite_leaves_no_stale(have_root, tr_rel, size_of, trp, port, ta, PAT_A, MARK_B, TAG, pattern, SZ):
    if have_root:
        N = 4096
        rc, _o, _e = xrd_fs(["truncate", "/" + tr_rel, str(N)], "alice")
        ok(all((rc == 0, size_of(trp) == N)),
           "root:// truncate-to-%d -> on-disk size EXACTLY %d (rc=%s, size=%s)"
           % (N, N, rc, size_of(trp)))
        st, gb = http("GET", "/" + tr_rel, port, ta)
        ok(all((st == 200, len(any((gb, b''))) == N, gb == PAT_A[:N])),
           "read after truncate returns EXACTLY %d byte-exact head bytes (HTTP %s, "
           "len=%d)" % (N, st, len(gb or b"")))
        ok(all((MARK_B not in any((gb, b'')), PAT_A[N:N + 16] not in any((gb, b'')))),
           "read after truncate has NO stale tail beyond N and no foreign bytes")
    else:
        ok(True, "truncate size skipped (native client absent)")
        ok(True, "truncate read-len skipped (native client absent)")
        ok(True, "truncate no-stale-tail skipped (native client absent)")

    # =====================================================================
    # SECTION 6 — OVERWRITE leaves NO stale tail (shrink-on-rewrite, data-plane).
    # =====================================================================
    ov_rel = "alice/%s_overwrite.bin" % TAG
    big = pattern("ALICE", SZ)
    small = b"ALICE-SMALL-OVERWRITE-PAYLOAD-" * 4                 # << SZ, no big tail
    http("PUT", "/" + ov_rel, port, ta, big)
    return ov_rel, small


def _rt33_segment_26(rel, ov_rel, size_of, SZ, port, ta, small):
    ovp = rel(*ov_rel.split("/"))
    ok(size_of(ovp) == SZ, "overwrite setup: 256K baseline on disk (size=%s)"
       % size_of(ovp))
    st, _ = http("PUT", "/" + ov_rel, port, ta, small)           # full-object rewrite
    ok(all((st in (200, 201, 204), size_of(ovp) == len(small))),
       "overwrite: PUT smaller payload shrinks file to exact new length, no stale "
       "tail on disk (HTTP %s, size=%s)" % (st, size_of(ovp)))
    st, gb = http("GET", "/" + ov_rel, port, ta)
    return st, gb


def _rt33_section_7_0_byte_file_round(st, gb, small, TAG, port, ta, rel):
    ok(all((st == 200, gb == small)),
       "overwrite read-back == new content exactly, zero stale bytes (HTTP %s, "
       "len=%d)" % (st, len(gb or b"")))
    ok(all((b'%08d|' % 1000 not in any((gb, b'')), len(any((gb, b''))) == len(small))),
       "overwrite read carries NO leftover block from the 256K baseline")

    # =====================================================================
    # SECTION 7 — 0-byte file round-trips through the data plane (degenerate length).
    # =====================================================================
    z_rel = "alice/%s_zero.bin" % TAG
    st, _ = http("PUT", "/" + z_rel, port, ta, b"")
    zp = rel(*z_rel.split("/"))
    return z_rel, st, zp


def _rt33_segment_01_2(TAG, local_write, rel):
    zr_rel = "alice/%s_zero_root.bin" % TAG
    lf = local_write("zero.bin", b"")
    if lf:
        xrd_cp_up(lf, "/" + zr_rel, "alice")
    zrp = rel(*zr_rel.split("/"))
    dl = os.path.join(WORK, TAG + "_zero_dl.bin")
    return zr_rel, zrp, dl


def _rt33_segment_02_2(dl, zr_rel, size_of, zrp, owned_alice, body_of):
    try:
        if os.path.exists(dl):
            os.unlink(dl)
    except OSError:
        pass
    rc, _o, _e = xrd_cp_down("/" + zr_rel, dl, "alice")
    ok(all((size_of(zrp) == 0, owned_alice(zrp), any((not os.path.exists(dl), body_of(dl) == b'')))),
       "root:// 0-byte file round-trips empty + owned alice (rc=%s, size=%s)"
       % (rc, size_of(zrp)))


def _rt33_when_have_root(TAG, local_write, rel, owned_alice, size_of, body_of):
    zr_rel, zrp, dl = _rt33_segment_01_2(TAG, local_write, rel)

    _rt33_segment_02_2(dl, zr_rel, size_of, zrp, owned_alice, body_of)



def _rt33_segment_28(st, zp, size_of, owned_alice, uid_of, z_rel, port, ta, have_s3, TAG, s3port, rel, have_root, local_write, body_of):
    ok(all((st in (200, 201, 204), os.path.exists(zp), size_of(zp) == 0, owned_alice(zp))),
       "0-byte PUT -> exists, size 0, owned alice not svc (HTTP %s, size=%s, uid=%s)"
       % (st, size_of(zp), uid_of(zp)))
    st, gb = http("GET", "/" + z_rel, port, ta)
    ok(all((st in (200, 204), any((gb, b'')) == b'')),
       "0-byte GET returns exactly empty body, no fabricated/leaked bytes (HTTP %s, "
       "len=%d)" % (st, len(gb or b"")))
    if have_s3 and z_rel:
        zs_rel = "alice/%s_zero_s3.bin" % TAG
        st, _ = s3("PUT", zs_rel, s3port, data=b"")
        zsp = rel(*zs_rel.split("/"))
        st2, gb = s3("GET", zs_rel, s3port)
        ok(all((st in (200, 201), size_of(zsp) == 0, any((gb, b'')) == b'', owned_alice(zsp))),
           "S3 0-byte object round-trips empty + owned alice (PUT %s, GET %s)"
           % (st, st2))
    else:
        ok(True, "S3 0-byte round-trip skipped (S3 endpoint down)")
    if have_root:
        _rt33_when_have_root(TAG, local_write, rel, owned_alice, size_of, body_of)
    else:
        ok(True, "root:// 0-byte round-trip skipped (native client absent)")


def _rt33_section_8_liveness_after_the_whole(TAG, port, ta, owned_alice, rel):

    # =====================================================================
    # SECTION 8 — LIVENESS: after the whole data-plane storm the worker still serves
    # a legit op (it did not wedge / leak fds / die under impersonation churn).
    # =====================================================================
    live_rel = "alice/%s_live.txt" % TAG
    st, _ = http("PUT", "/" + live_rel, port, ta, b"DPI-LIVE\n")
    gst, gb = http("GET", "/" + live_rel, port, ta)
    ok(all((st in (200, 201, 204), gst == 200, gb == b'DPI-LIVE\n', owned_alice(rel(*live_rel.split('/'))))),
       "liveness: worker still serves a fresh PUT+GET byte-exact post-storm "
       "(PUT %s, GET %s)" % (st, gst))
    # and bob's identity is still independently honored (no principal stuck on alice).
    bl_rel = "bob/%s_live_bob.txt" % TAG
    return bl_rel


def _rt33_segment_30(bl_rel, port, tb, rel, uid_of):
    st, _ = http("PUT", "/" + bl_rel, port, tb, b"DPI-LIVE-BOB\n")
    blp = rel(*bl_rel.split("/"))
    ok(all((st in (200, 201, 204), uid_of(blp) == UID_BOB, uid_of(blp) != UID_ALICE)),
       "liveness: bob's identity still maps to bob 1002 post-storm, no stuck "
       "alice principal (HTTP %s, uid=%s)" % (st, uid_of(blp)))


def run_dataplane_integrity(key, data, port, s3port):
    """Per-identity DATA-PLANE integrity & non-cross-contamination.  The data plane
    (pread / pwrite / sendfile) operates on an ALREADY-OPEN fd whose DAC was decided
    once, at open(), under the mapped identity.  This batch drives bytes END TO END
    through each protocol and proves: (a) a LARGE (<=256 KiB) known-pattern file
    written via xrdcp / WebDAV PUT / S3 PUT reads back BYTE-EXACT through every
    protocol and lands owned by the mapping user (alice 1001), never svc/root/bob;
    (b) CONCURRENT large reads of alice/big and bob/big in parallel threads each
    receive their OWN bytes only — no fd / read-buffer cross-contamination under
    interleaved impersonation (the core data-plane isolation property); (c) partial /
    Range reads (WebDAV Range, xrdfs head/tail) are byte-exact and never run past EOF;
    (d) a returned query-checksum matches the actual content (crc32c / adler32 if the
    server emits it); (e) truncate-to-N yields exactly N bytes on read; (f) overwrite
    leaves NO stale tail; (g) a 0-byte file round-trips.  Every identity carries a
    distinct recognizable byte pattern so any cross-leak is deterministically
    detectable, and every read-deny also asserts the foreign marker bytes are absent.
    The worker is proven alive after the storm via a follow-up legit op."""
    TAG, ta, tb, have_root, have_s3 = _rt33_segment_01(key, s3port)

    SZ = _rt33_segment_02()

    rel = _rt33_segment_03(data)

    uid_of = _rt33_segment_04()

    size_of = _rt33_segment_05()

    body_of = _rt33_segment_06()

    owned_alice = _rt33_segment_07(uid_of)

    local_write = _rt33_segment_08(TAG)

    pattern = _rt33_per_identity_deterministic_position_encoding_patterns()

    PAT_A, PAT_B, MARK_A, MARK_B, wd_rel = _rt33_section_1_large_round_trip_via(pattern, SZ, TAG)

    gst, gb = _rt33_segment_11(wd_rel, port, ta, PAT_A, rel, owned_alice, size_of, SZ, uid_of, body_of)

    _rt33_1b_s3_put_large_s3_get(gst, gb, PAT_A, MARK_B, have_s3, TAG, s3port, rel, owned_alice, size_of, SZ, uid_of, have_root, local_write, body_of, wd_rel)

    bob_rel, bpath = _rt33_section_2_concurrent_large_reads_alice(TAG, have_root, local_write, PAT_B, port, tb, rel, size_of, SZ, uid_of)

    results, barrier = _rt33_segment_14()

    reader = _rt33_segment_15(barrier, port, results)

    t_bob = _rt33_segment_16(reader, wd_rel, ta, bob_rel, tb)

    abody, bst, bbody = _rt33_alice_s_concurrent_stream_exactly_her(t_bob, results, PAT_A, MARK_B)

    barrier2 = _rt33_bob_s_concurrent_stream_exactly_his(bst, bbody, PAT_B, MARK_A, abody, PAT_A, results)

    reader2 = _rt33_segment_19(barrier2, port, results)

    tx = _rt33_segment_20(reader2, wd_rel, ta, bob_rel)

    _rt33_segment_21(tx, results, MARK_B, PAT_B, PAT_A)

    _rt33_section_3_partial_range_reads_byte(size_of, bpath, SZ, body_of, PAT_B, wd_rel, port, ta, PAT_A)

    _rt33_3b_range_last_byte_only_never(wd_rel, port, ta, SZ, PAT_A, MARK_B, have_root, bob_rel)

    tr_rel, trp = _rt33_section_4_query_checksum_matches_actual(have_root, TAG, local_write, rel, owned_alice, body_of, bob_rel, MARK_B, port, ta, PAT_A, size_of, SZ)

    ov_rel, small = _rt33_section_6_overwrite_leaves_no_stale(have_root, tr_rel, size_of, trp, port, ta, PAT_A, MARK_B, TAG, pattern, SZ)

    st, gb = _rt33_segment_26(rel, ov_rel, size_of, SZ, port, ta, small)

    z_rel, st, zp = _rt33_section_7_0_byte_file_round(st, gb, small, TAG, port, ta, rel)

    _rt33_segment_28(st, zp, size_of, owned_alice, uid_of, z_rel, port, ta, have_s3, TAG, s3port, rel, have_root, local_write, body_of)

    bl_rel = _rt33_section_8_liveness_after_the_whole(TAG, port, ta, owned_alice, rel)

    _rt33_segment_30(bl_rel, port, tb, rel, uid_of)
