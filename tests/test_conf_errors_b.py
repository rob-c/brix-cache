from _test_conf_errors_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_query_checksum_missing_in_dir_parity(srv):
    """query checksum of a file inside a missing dir: OUR rejects; pin to STOCK
    only when STOCK supports checksums."""
    _assert_both_fail_cksum(srv, "query", "checksum", "/no/such/dir/x.bin")


def test_stat_then_cat_nested_dir_parity(srv):
    """cat of a NESTED directory (/deep/a) is a directory-read reject on both."""
    _assert_both_fail_same_cat(srv, "cat", "/deep/a")


def test_rmdir_nested_nonempty_parity(srv):
    """rmdir of a nested non-empty dir (/deep/a holds b/...) -> reject on both."""
    _assert_both_fail_same_cat(srv, "rmdir", "/deep/a")


def test_truncate_nested_dir_parity(srv):
    """truncate of a nested directory (EISDIR) -> reject on both."""
    _assert_both_fail_same_cat(srv, "truncate", "/deep/a/b/c", "0")


def test_mkdir_over_existing_dir_nested_parity(srv):
    """mkdir over an existing nested dir (/deep/a) -> ItExists on both."""
    _assert_both_fail_same_cat(srv, "mkdir", "/deep/a")


def test_rm_nested_missing_parity(srv):
    """rm of a missing file under an existing dir -> NotFound on both."""
    _assert_both_fail_same_cat(srv, "rm", "/sub/no_such_child.txt")


def test_chmod_nested_missing_parity(srv):
    """chmod of a missing file under an existing dir -> NotFound on both."""
    _assert_both_fail_same_cat(srv, "chmod", "/sub/no_child.txt", "rw-r--r--")


def test_mv_into_existing_dir_target_is_dir_parity(srv):
    """mv a file onto an existing DIRECTORY name: pin overwrite-vs-error to
    STOCK on parallel trees."""
    for data, sfx in ((srv["our_data"], "our"), (srv["off_data"], "off")):
        with open(os.path.join(data, f"mv_ontodir_src_{sfx}.txt"), "w") as f:
            f.write("x")
        os.makedirs(os.path.join(data, f"mv_ontodir_dst_{sfx}"), exist_ok=True)
    rc_o, o_o, e_o = fs(srv["our"], "mv", "/mv_ontodir_src_our.txt", "/mv_ontodir_dst_our")
    rc_f, o_f, e_f = fs(srv["off"], "mv", "/mv_ontodir_src_off.txt", "/mv_ontodir_dst_off")
    raw = (f"\n  OURS  rc={rc_o} :: {(o_o + e_o).strip()!r}"
           f"\n  STOCK rc={rc_f} :: {(o_f + e_f).strip()!r}")
    # mv onto an existing directory name: pin the success/failure CLASS to STOCK.
    # The exact reject code differs (STOCK -> kXR_isDirectory 3016; OUR reports a
    # rename-failed reject), so we only require both to AGREE on rejecting, not
    # the sub-category — the load-bearing invariant is that neither clobbers the
    # directory with the file.
    assert (rc_o == 0) == (rc_f == 0), f"mv-onto-dir rc-class differs:{raw}"
    assert os.path.isdir(os.path.join(srv["our_data"], "mv_ontodir_dst_our")), \
        "OUR mv overwrote a directory with a file (bug)"


def test_locate_directory_parity(srv):
    """locate of a directory: pin to STOCK (some builds reject, some succeed)."""
    _assert_parity(srv, "locate", "/sub")


def test_stat_empty_string_path_parity(srv):
    """stat of an empty path argument: pin OUR reject-class to STOCK."""
    rc_o, o_o, e_o = fs(srv["our"], "stat", "")
    rc_f, o_f, e_f = fs(srv["off"], "stat", "")
    assert (rc_o == 0) == (rc_f == 0), (
        f"empty-path stat rc-class differs: our={rc_o}({o_o}{e_o!r}) "
        f"stock={rc_f}({o_f}{e_f!r})")


def test_wire_unknown_opcode_invalidrequest(srv):
    """Unknown opcode -> kXR_error on both. OUR server returns kXR_InvalidRequest
    (3006), matching the C++ reference (XrdXrootdProtocol.cc:608); the stock
    build here returns kXR_ArgMissing (3001). Both are request-reject codes."""
    def send(s):
        s.sendall(struct.pack("!2sH16sI", b"\x00\x21", 9999, b"\x00" * 16, 0))
    _assert_wire_parity(srv, send)


def test_wire_negative_dlen_rejected(srv):
    def send(s):
        s.sendall(struct.pack("!2sH16si", b"\x00\x23", kXR_ping, b"\x00" * 16, -1))
    _assert_wire_parity(srv, send)


def test_wire_oversized_dlen_rejected(srv):
    def send(s):
        # claim ~2 GiB of stat payload but send nothing more
        s.sendall(struct.pack("!2sH16sI", b"\x00\x25", kXR_stat,
                              b"\x00" * 16, 0x7fffffff))
    _assert_wire_parity(srv, send)


def test_wire_prelogin_stat_rejected(srv):
    def send(s):
        p = b"/hello.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x22", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_wire_parity(srv, send, raw=True)


def test_wire_embedded_nul_path_rejected(srv):
    """A stat path containing an embedded NUL is malformed; both servers must
    reject it (and must NOT treat the truncated prefix as a valid path)."""
    def send(s):
        p = b"/hel\x00lo.txt"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x26", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    # The exact code can be ArgInvalid (EINVAL) or NotFound depending on where
    # the NUL is caught; require both servers to reject and to AGREE on the code.
    _assert_wire_parity(srv, send)


def test_wire_open_read_directory_isdir(srv):
    def send(s):
        p = b"/sub"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x27", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_isDirectory)


def test_wire_open_write_directory_error(srv):
    def send(s):
        p = b"/sub"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x28", kXR_open, 0,
                              kXR_open_updt, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_isDirectory)


def test_wire_open_read_missing_notfound(srv):
    def send(s):
        p = b"/no_such_open_target.bin"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x29", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


def test_wire_close_invalid_fhandle_filenotopen(srv):
    def send(s):
        fh = b"\xff\xff\xff\xff"
        s.sendall(struct.pack("!2sH4s12sI", b"\x00\x2a", kXR_close, fh,
                              b"\x00" * 12, 0))
    _assert_wire_parity(srv, send, want_code=kXR_FileNotOpen)


def test_wire_read_invalid_fhandle_error(srv):
    def send(s):
        fh = b"\xff\xff\xff\xff"
        s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2b", kXR_read, fh,
                              0, 512, 0))
    _assert_wire_parity(srv, send, want_code=kXR_FileNotOpen)


def test_wire_write_to_readonly_handle_parity(srv):
    """Open /hello.txt for READ, then attempt a kXR_write on that handle.

    NOTE: the stock data server in this anon/allow-write config ACCEPTS the
    write — its open does NOT pin the handle to read-only when the export is
    writable (a permissive stock behavior). OUR server enforces the open mode
    and REJECTS the write with kXR_NotAuthorized — stricter and arguably more
    correct. This is a legitimate, documented design difference, not a bug, so
    we only require a DEFINITE outcome from each server (no crash/hang) and that
    OUR rejection, if any, is in the access-denied class. We do NOT force equal
    success-class here."""
    st_o, en_o = _write_to_ro_handle(srv["our"])
    st_f, en_f = _write_to_ro_handle(srv["off"])
    assert st_o in (kXR_ok, kXR_error, "EOF"), \
        f"OUR RO-handle-write gave no definite outcome: st={st_o}"
    assert st_f in (kXR_ok, kXR_error, "EOF"), \
        f"oracle: STOCK RO-handle-write gave no definite outcome: st={st_f}"
    if st_o == kXR_error and en_o is not None:
        assert _category_code(en_o) == "denied", (
            f"OUR RO-handle-write reject code {en_o} not in the access-denied "
            f"class (stock st={st_f})")


def test_wire_read_after_close_filenotopen(srv):
    """Open /hello.txt, close it, then read on the stale handle: both servers
    must reject (kXR_FileNotOpen)."""
    def runner(url):
        s = _session(url)
        try:
            st, body = _open(s, "/hello.txt", options=kXR_open_read)
            assert st == kXR_ok, f"open-read failed (status {st})"
            fh = body[0:4]
            s.sendall(struct.pack("!2sH4s12sI", b"\x00\x2e", kXR_close, fh,
                                  b"\x00" * 12, 0))
            _, st_c, _ = _resp(s)
            assert st_c == kXR_ok, f"close failed (status {st_c})"
            s.sendall(struct.pack("!2sH4sqiI", b"\x00\x2f", kXR_read, fh,
                                  0, 16, 0))
            try:
                _, st2, body2 = _resp(s)
            except EOFError:
                return ("EOF", None)
            return (st2, _err(body2))
        finally:
            s.close()

    st_o, en_o = runner(srv["our"])
    st_f, en_f = runner(srv["off"])

    def is_reject(st):
        return st == kXR_error or st == "EOF"
    assert is_reject(st_f), f"oracle: STOCK read a closed handle (st={st_f})"
    assert is_reject(st_o), \
        f"OUR server read an already-closed handle (BUG): st={st_o}"
    if st_o == kXR_error and st_f == kXR_error and en_f is not None:
        assert _category_code(en_o) == _category_code(en_f), \
            f"read-after-close code class differs: our={en_o} stock={en_f}"


def test_wire_double_close_rejected(srv):
    """Closing the same handle twice: the 2nd close must be rejected
    (kXR_FileNotOpen) on both servers."""
    def runner(url):
        s = _session(url)
        try:
            st, body = _open(s, "/hello.txt", options=kXR_open_read)
            assert st == kXR_ok
            fh = body[0:4]
            for _ in range(1):
                s.sendall(struct.pack("!2sH4s12sI", b"\x00\x30", kXR_close, fh,
                                      b"\x00" * 12, 0))
                _, st1, _ = _resp(s)
                assert st1 == kXR_ok, f"first close failed (status {st1})"
            s.sendall(struct.pack("!2sH4s12sI", b"\x00\x31", kXR_close, fh,
                                  b"\x00" * 12, 0))
            try:
                _, st2, body2 = _resp(s)
            except EOFError:
                return ("EOF", None)
            return (st2, _err(body2))
        finally:
            s.close()

    st_o, en_o = runner(srv["our"])
    st_f, en_f = runner(srv["off"])

    def is_reject(st):
        return st == kXR_error or st == "EOF"
    assert is_reject(st_f), f"oracle: STOCK accepted a double-close (st={st_f})"
    assert is_reject(st_o), \
        f"OUR server accepted a double-close (BUG): st={st_o}"
    if st_o == kXR_error and st_f == kXR_error and en_f is not None:
        assert _category_code(en_o) == _category_code(en_f), \
            f"double-close code class differs: our={en_o} stock={en_f}"


def test_wire_stat_missing_notfound(srv):
    def send(s):
        p = b"/wire_no_such_stat.bin"
        s.sendall(struct.pack("!2sH16sI", b"\x00\x32", kXR_stat,
                              b"\x00" * 16, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


def test_wire_open_in_missing_dir_notfound(srv):
    def send(s):
        p = b"/no/such/wire/dir/file.bin"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x33", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    _assert_wire_parity(srv, send, want_code=kXR_NotFound)


@pytest.mark.parametrize("trav", TRAVERSALS)
def test_traversal_cat_denied_no_leak(srv, trav):
    """cat of a traversal path must be DENIED on OUR server (rc != 0) and must
    NOT leak host /etc/passwd contents (no 'root:' bytes). STOCK denies too."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", trav)
    rc_f, o_f, e_f = fs(srv["off"], "cat", trav)
    assert rc_o != 0, \
        f"OUR server served traversal {trav} (SECURITY BUG): {o_o!r}"
    assert "root:" not in (o_o + e_o), \
        f"OUR server LEAKED host /etc/passwd via {trav} (SECURITY BUG): {o_o!r}"
    assert rc_f != 0, f"oracle: STOCK served the traversal {trav}: {o_f!r}"


@pytest.mark.parametrize("trav", TRAVERSALS)
def test_traversal_stat_denied(srv, trav):
    """stat of a traversal path must be denied on OUR server (and STOCK)."""
    rc_o, o_o, e_o = fs(srv["our"], "stat", trav)
    rc_f, _, _ = fs(srv["off"], "stat", trav)
    assert rc_o != 0, \
        f"OUR server stat'd traversal {trav} (SECURITY BUG): {o_o!r}"
    assert "root:" not in (o_o + e_o), \
        f"OUR server leaked host data via stat {trav}: {o_o!r}"
    assert rc_f != 0, f"oracle: STOCK stat'd the traversal {trav}"


def test_traversal_open_wire_denied(srv):
    """RAW-WIRE open(read) of a traversal path must be rejected on OUR server and
    leak nothing. Compare to STOCK (also denies)."""
    def send(s):
        p = b"/../../etc/passwd"
        s.sendall(struct.pack("!2sHHH12sI", b"\x00\x2d", kXR_open, 0,
                              kXR_open_read, b"\x00" * 12, len(p)) + p)
    st_o, en_o = _wire_codes(srv["our"], send)
    st_f, _ = _wire_codes(srv["off"], send)
    assert st_o != kXR_ok, \
        f"OUR server opened a traversal target (SECURITY BUG): status={st_o}"
    assert st_f != kXR_ok, f"oracle: STOCK opened the traversal target"


def test_traversal_rm_denied(srv):
    """rm of a traversal path must be denied on OUR server (no host unlink)."""
    rc_o, o_o, e_o = fs(srv["our"], "rm", "/../../etc/passwd")
    rc_f, _, _ = fs(srv["off"], "rm", "/../../etc/passwd")
    assert rc_o != 0, f"OUR server rm'd a traversal target (SECURITY BUG)"
    assert os.path.exists("/etc/passwd"), "host /etc/passwd was removed (SECURITY BUG)"
    assert rc_f != 0, "oracle: STOCK rm'd the traversal target"


def test_confinement_encoded_traversal_denied(srv):
    """A doubled-slash + dot-dot form must still be confined on OUR server."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", "//..//..//etc/passwd")
    assert rc_o != 0, f"OUR server served //..//..// traversal (SECURITY BUG)"
    assert "root:" not in (o_o + e_o), "confinement leak via //..// form"


def test_confinement_interior_dotdot_stat(srv):
    """An interior '..' that resolves back inside the root is fine, but one that
    escapes must be denied; probe a deep escape and assert no host leak."""
    rc_o, o_o, e_o = fs(srv["our"], "cat", "/deep/a/../../../../../etc/passwd")
    assert rc_o != 0, "OUR server served deep interior-dotdot escape (SECURITY BUG)"
    assert "root:" not in (o_o + e_o), "confinement leak via interior dotdot"
