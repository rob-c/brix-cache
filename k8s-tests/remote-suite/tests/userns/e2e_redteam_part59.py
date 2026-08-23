def _rt59_segment_01():

    BOB_SECRET = b"BOB-PRIVATE-SECRET"          # planted in data/bob/private.txt (0600)
    return BOB_SECRET


def _rt59_segment_02():

    def survives(label):
        """Native xrdfs stat as alice on her own dir MUST succeed after an attack —
        proves the worker (and the privileged broker) did not crash/wedge."""
        rc, _o, _e = xrd_fs(["stat", "/alice"], "alice")
        ok(rc == 0,
           f"worker survived {label}: native xrdfs stat /alice (alice) ok (rc={rc})")
    return survives


def _rt59_baseline_the_raw_client_can_at():

    # ----- baseline: the raw client can at least negotiate the parser entry --
    s0, hs0, _lg0 = _kxr_session(do_protocol=True, do_login=True)
    if s0 is not None:
        try:
            s0.close()
        except OSError:
            pass
    ok(hs0 == _KXR_OK,
       f"raw kXR 20-byte handshake accepted by impersonation stream server (status={hs0})")

    # ----- (1) MALFORMED / SHORT HANDSHAKE -----------------------------------
    hs_status, _st, _b, closed = _kxr_oneshot(b"", handshake=b"\x00\x00\x00\x04")
    ok(hs_status != _KXR_OK,
       f"raw: short 4-byte handshake not accepted as ok (status={hs_status}, closed={closed})")


def _rt59_2_garbage_magic_handshake(survives):
    survives("short-handshake")

    # ----- (2) GARBAGE-MAGIC HANDSHAKE ---------------------------------------
    bad_hs = _kxr_handshake_bytes(fourth=0xDEADBEEF, fifth=0xCAFEBABE)
    hs_status, _st, _b, _c = _kxr_oneshot(b"", handshake=bad_hs)
    ok(hs_status != _KXR_OK,
       f"raw: garbage-magic handshake rejected/closed (status={hs_status})")
    survives("garbage-magic-handshake")


def _rt59_3_oversized_dlen_stat_claims_1(survives):

    # ----- (3) OVERSIZED dlen (stat claims ~1 GiB body, sends none) ----------
    over = _kxr_stat_bytes(b"", streamid=b"\x00\x10", dlen=0x40000000)
    hs_status, status, body, closed = _kxr_oneshot(over)
    ok(status != _KXR_OK,
       f"raw: pre-auth stat claiming ~1GiB dlen not ok (status={status}, closed={closed})")
    survives("oversized-dlen")

    # ----- (4) NEGATIVE dlen (-1 -> 0xFFFFFFFF) on stat ----------------------
    neg = _kxr_stat_bytes(b"", streamid=b"\x00\x18", dlen=0xFFFFFFFF)
    return neg


def _rt59_5_opcode_out_of_valid_range(neg, survives):
    hs_status, status, body, closed = _kxr_oneshot(neg)
    ok(status != _KXR_OK,
       f"raw: stat with negative/huge dlen (-1) not ok (status={status}, closed={closed})")
    survives("negative-dlen")

    # ----- (5) OPCODE OUT OF VALID RANGE -------------------------------------
    garbage_op = struct.pack("!2sH16sI", b"\x00\x11", 9999, b"\x00" * 16, 0)
    hs_status, status, body, closed = _kxr_oneshot(garbage_op)
    return status, closed


def _rt59_6_file_op_before_login_pre(status, closed, survives):
    ok(status != _KXR_OK,
       f"raw: out-of-range opcode 9999 rejected/closed (status={status}, closed={closed})")
    survives("garbage-opcode")

    # ----- (6) FILE OP BEFORE LOGIN (pre-login stat of a real cross-tenant path)
    pre = _kxr_stat_bytes(b"/bob/private.txt", streamid=b"\x00\x12")
    hs_status, status, body, closed = _kxr_oneshot(pre)
    ok(status != _KXR_OK,
       f"raw: stat BEFORE login rejected, no metadata served (status={status})")
    return body


def _rt59_7_unauthenticated_anon_login_no_kxr(BOB_SECRET, body, survives):
    ok(BOB_SECRET not in body,
       "raw: pre-login stat body carries no bob secret bytes")
    survives("pre-login-stat")

    # ----- (7) UNAUTHENTICATED (anon-login, NO kXR_auth) stat of bob file ----
    s, _hs, lg = _kxr_session(do_login=True)
    if s is not None and lg == _KXR_OK:
        status, body = _kxr_send_recv(s, _kxr_stat_bytes(b"/bob/private.txt"))
        ok(status != _KXR_OK,
           f"raw: anon-login (unauthenticated) stat of bob file NOT ok (status={status})")
        ok(BOB_SECRET not in body,
           "raw: unauthenticated stat returns no bob secret bytes")
        try:
            s.close()
        except OSError:
            pass
    else:
        ok(True, "raw kXR session not established; unauthenticated-stat check skipped")
        ok(True, "raw kXR session not established; unauthenticated-leak check skipped")
    survives("unauthenticated-stat")


def _rt59_8_double_login_on_one_connection(survives, status, body):

    # ----- (8) DOUBLE LOGIN on one connection --------------------------------
    s, _hs, _lg = _kxr_session(do_login=True)
    if s is not None:
        status2, _b2 = _kxr_send_recv(s, _kxr_login_bytes(streamid=b"\x00\x13"))
        # Any deterministic outcome (error / ignore / close) is acceptable; the
        # invariant is no crash — proven by the survives() follow-up.
        ok(True, f"raw: second kXR_login on one connection handled (status={status2})")
        try:
            s.close()
        except OSError:
            pass
    else:
        ok(True, "raw kXR session not established; double-login check skipped")
    survives("double-login")

    # ----- (9) TRAVERSAL PATH via raw stat (../../../../etc/passwd) -----------
    trav = _kxr_stat_bytes(b"/alice/../../../../etc/passwd", streamid=b"\x00\x14")
    hs_status, status, body, closed = _kxr_oneshot(trav)
    return status, body


def _rt59_10_truncated_body_login_claims_64(status, body, survives, closed):
    ok(status != _KXR_OK,
       f"raw: traversal stat ../../etc/passwd not served (status={status})")
    ok(all((b'root:' not in body, b'/bin/' not in body, b'daemon:' not in body)),
       "raw: traversal stat body has no /etc/passwd content")
    survives("traversal-stat")

    # ----- (10) TRUNCATED BODY (login claims 64-byte cred, sends 4) ----------
    trunc = _kxr_login_bytes(streamid=b"\x00\x15")[:-4] + struct.pack("!I", 64) \
        + b"\xAA\xBB\xCC\xDD"
    hs_status, status, body, closed = _kxr_oneshot(trunc)
    return status, closed


def _rt59_11_readv_with_oob_overflowing_segments(status, closed, survives):
    ok(any((status != _KXR_OK, closed)),
       f"raw: login claiming 64-byte body but sending 4 -> not ok (status={status}, closed={closed})")
    survives("truncated-body")

    # ----- (11) readv with OOB / overflowing segments (pre-auth) -------------
    # ClientReadVRequest: streamid[2] requestid[2] reserved[15] pathid[1] dlen[4]
    # + one read_list element {fhandle[4], rlen[int32], offset[int64]} whose
    # offset/len are at the int boundary on a bogus handle.
    rl = struct.pack("!4siq", b"\xFF\xFF\xFF\xFF", 0x7FFFFFFF, 0x7FFFFFFFFFFFFFFF)
    readv = struct.pack("!2sH15sBI", b"\x00\x16", _KXR_READV, b"\x00" * 15, 0,
                        len(rl)) + rl
    hs_status, status, body, closed = _kxr_oneshot(readv)
    return status


def _rt59_12_kxr_bind_to_a_foreign(status, survives):
    ok(status != _KXR_OK,
       f"raw: readv with overflowing offset/len on bogus handle not ok (status={status})")
    survives("readv-overflow")

    # ----- (12) kXR_bind to a FOREIGN / garbage session id -------------------
    bind = struct.pack("!2sH16sI", b"\x00\x17", _KXR_BIND, b"\xFF" * 16, 0)
    s, _hs, _lg = _kxr_session(do_login=True)
    if s is not None:
        status, body = _kxr_send_recv(s, bind)
        ok(status != _KXR_OK,
           f"raw: kXR_bind to foreign/garbage sessid not granted (status={status})")
        try:
            s.close()
        except OSError:
            pass
    else:
        ok(True, "raw kXR session not established; foreign-bind check skipped")


def _rt59_final_a_clean_native_data_round(survives):
    survives("foreign-bind")

    # ----- final: a clean native data round-trip still works as alice --------
    rc, _out, _e = xrd_fs(["ls", "/alice"], "alice")
    ok(rc == 0,
       f"raw: after all adversarial framings, native xrdfs ls /alice (alice) ok (rc={rc})")


def run_raw_kxr_wire(key, data, port, s3port):
    """RAW kXR WIRE FRAMING under per-request impersonation — a hand-rolled root://
    client feeds the protocol parser/state-machine adversarial framings the native
    client could never emit (malformed/garbage handshake, oversized & negative
    dlen, garbage opcode, truncated body, pre-login & unauthenticated file ops,
    double-login, traversal-path stat, readv OOB/overflow vectors, foreign-session
    bind).  After EACH the server must (a) respond with a clean error or clean close
    — never crash, never serve bob's bytes, never escape the export — and (b) STILL
    serve a clean native xrdfs op as alice, proving the worker AND the privileged
    broker survived.  DISTINCT from run_root_protocol_depth / run_root_deep /
    run_stream_extended_ops, which drive only the WELL-FORMED native client and
    never exercise raw framing or the parser's error paths.  GUARDED by xrd_avail()."""
    if not xrd_avail() or not _stream_port:
        ok(True, "raw-kXR wire skipped (native xrdfs/xrdcp absent or no stream port)")
        return
    BOB_SECRET = _rt59_segment_01()

    survives = _rt59_segment_02()

    _rt59_baseline_the_raw_client_can_at()

    _rt59_2_garbage_magic_handshake(survives)

    neg = _rt59_3_oversized_dlen_stat_claims_1(survives)

    status, closed = _rt59_5_opcode_out_of_valid_range(neg, survives)

    body = _rt59_6_file_op_before_login_pre(status, closed, survives)

    _rt59_7_unauthenticated_anon_login_no_kxr(BOB_SECRET, body, survives)

    status, body = _rt59_8_double_login_on_one_connection(survives, status, body)

    status, closed = _rt59_10_truncated_body_login_claims_64(status, body, survives, closed)

    status = _rt59_11_readv_with_oob_overflowing_segments(status, closed, survives)

    _rt59_12_kxr_bind_to_a_foreign(status, survives)

    _rt59_final_a_clean_native_data_round(survives)
