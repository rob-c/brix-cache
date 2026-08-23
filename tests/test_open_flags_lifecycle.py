from split_continuation import reexport as _reexport
def _check_test_posc_abort_leaves_no_final_file_3(final):
    assert not os.path.exists(final), (
        "aborted POSC upload must NOT produce the final file")

def _check_test_posc_abort_leaves_no_final_file_4(leaked):
    assert not leaked, f"orphan POSC temp files left behind: {leaked}"

def _check_test_posc_abort_leaves_no_final_file_1(status, body):
    assert status == kXR_ok, f"POSC open failed: {_error_code(body)}"

def _check_test_posc_abort_leaves_no_final_file_2(wstatus):
    assert wstatus == kXR_ok

def _check_test_posc_abort_leaves_no_final_file_5(sock2):
    assert _ping(sock2)[1] == kXR_ok


_reexport(globals(), "_test_open_flags_lifecycle_helpers")

class TestOpenFlagSemantics:
    """Each open flag is asserted against the documented handler behavior, with
    a sanity op afterwards proving the connection survived."""

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_new_on_existing_itexists(self, wr_stack):
        """kXR_new on an EXISTING path maps to O_EXCL -> EEXIST -> already-exists.

        kXR_new without kXR_delete sets O_EXCL (open_resolved_file.c), so the
        create must fail with an EEXIST code (canonically kXR_ItExists; this
        server returns kXR_FileLocked) rather than truncating the file."""
        rel = "/new_existing.bin"
        _wr_seed(wr_stack, rel, b"PRECIOUS-DO-NOT-CLOBBER")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new)
            assert status == kXR_error, "kXR_new on existing must fail"
            assert _error_code(body) in _EEXIST_CODES, (
                f"expected an EEXIST code {_EEXIST_CODES}, "
                f"got {_error_code(body)}")
            # Original content must be untouched by the failed exclusive create.
            with open(_wr_full(wr_stack, rel), "rb") as f:
                assert f.read() == b"PRECIOUS-DO-NOT-CLOBBER"
            # Session still usable.
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_delete_truncates_to_zero(self, wr_stack):
        """kXR_delete on an existing file maps to O_CREAT|O_TRUNC: the file is
        truncated to zero length on open."""
        rel = "/delete_trunc.bin"
        _wr_seed(wr_stack, rel, b"X" * 4096)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_delete)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _close(sock, fh)
            assert os.path.getsize(_wr_full(wr_stack, rel)) == 0, (
                "kXR_delete must truncate the file to zero")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_apnd_appends(self, wr_stack):
        """kXR_open_apnd maps to O_WRONLY|O_APPEND: a write lands at EOF,
        preserving existing content regardless of the requested offset."""
        rel = "/append.bin"
        seed = b"HEAD-"
        _wr_seed(wr_stack, rel, seed)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_apnd)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            tail = b"TAIL"
            # offset 0 is ignored under O_APPEND; the write goes to EOF.
            _, wstatus, wbody = _write(sock, fh, 0, tail)
            assert wstatus == kXR_ok, _error_code(wbody)
            _close(sock, fh)
            with open(_wr_full(wr_stack, rel), "rb") as f:
                final = f.read()
            assert final == seed + tail, f"append produced {final!r}"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_mkpath_creates_parents(self, wr_stack):
        """kXR_mkpath creates missing parent directories before the create."""
        rel = "/mkpath_a/mkpath_b/leaf.bin"
        # Idempotent: the persistent /tmp data dir may carry over a prior run.
        shutil.rmtree(_wr_full(wr_stack, "/mkpath_a"), ignore_errors=True)
        parent = os.path.dirname(_wr_full(wr_stack, rel))
        assert not os.path.exists(parent), "precondition: parents absent"
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_mkpath)
            assert status == kXR_ok, (
                f"kXR_mkpath open failed: {_error_code(body)}")
            fh = body[:4]
            _close(sock, fh)
            assert os.path.isdir(parent), "kXR_mkpath did not create parents"
            assert os.path.exists(_wr_full(wr_stack, rel))
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_mkpath_absent_without_flag(self, wr_stack):
        """Without kXR_mkpath, a create under a missing parent must fail
        cleanly (ENOENT -> kXR_NotFound), not silently create dirs."""
        rel = "/no_mkpath_x/no_mkpath_y/leaf.bin"
        shutil.rmtree(_wr_full(wr_stack, "/no_mkpath_x"), ignore_errors=True)
        parent = os.path.dirname(_wr_full(wr_stack, rel))
        assert not os.path.exists(parent)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new)
            assert status == kXR_error, "create under missing parent must fail"
            assert _error_code(body) in (kXR_NotFound, kXR_IOError,
                                         kXR_ServerError), _error_code(body)
            assert not os.path.exists(parent), (
                "parent must NOT be created without kXR_mkpath")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_retstat_returns_inline_stat(self, ro_data, anon):
        """kXR_retstat appends a null-terminated stat string after the 12-byte
        ServerOpenBody; the size field must match the on-disk file size."""
        full = os.path.join(DATA_ROOT, ro_data.lstrip("/"))
        expected_size = os.path.getsize(full)
        sock = _session(*anon)
        try:
            _, status, body = _open(sock, ro_data,
                                    kXR_open_read | kXR_retstat)
            assert status == kXR_ok, _error_code(body)
            assert len(body) > OPEN_BODY_LEN, (
                "kXR_retstat must append an inline stat after ServerOpenBody")
            stat_str = body[OPEN_BODY_LEN:].split(b"\x00", 1)[0].decode()
            # Format is "<id> <size> <flags> <mtime>" (open_resolved_file.c).
            fields = stat_str.split()
            assert len(fields) >= 4, f"malformed inline stat: {stat_str!r}"
            assert int(fields[1]) == expected_size, (
                f"inline stat size {fields[1]} != actual {expected_size}")
            _close(sock, body[:4])
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_invalid_flag_combo_apnd_delete(self, wr_stack):
        """kXR_open_apnd|kXR_delete is a contradictory combination (append vs
        truncate).  The handler must produce a deterministic, clean result —
        never crash or hang — and the session must survive.

        The implementation evaluates kXR_open_updt/apnd for oflags and
        kXR_delete for O_CREAT|O_TRUNC, so it resolves to a concrete open; we
        assert it returns a well-formed protocol message either way."""
        rel = "/apnd_delete.bin"
        _wr_seed(wr_stack, rel, b"SEED-CONTENT")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_apnd | kXR_delete)
            assert status in (kXR_ok, kXR_error), (
                f"unexpected status for contradictory flags: {status}")
            if status == kXR_ok:
                _close(sock, body[:4])
            else:
                # An explicit rejection must carry a sane error code.
                assert _error_code(body) in (
                    kXR_ArgInvalid, kXR_IOError, kXR_NotAuthorized,
                    kXR_ServerError, kXR_Unsupported), _error_code(body)
            # The connection must remain usable after the odd request.
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# POSC (persist-on-successful-close) lifecycle
# ===========================================================================

class TestPoscLifecycle:
    """kXR_posc stages writes to a temp file; a clean kXR_close renames it to
    the final name, while a disconnect/abort unlinks the temp and leaves NO
    final file (open_resolved_file.c + close.c + fd_table.c free_fhandle)."""

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_posc_clean_close_persists(self, wr_stack):
        rel = "/posc_clean.bin"
        final = _wr_full(wr_stack, rel)
        _wr_clear_staging(wr_stack, rel)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_posc)
            assert status == kXR_ok, f"POSC open failed: {_error_code(body)}"
            fh = body[:4]
            payload = b"POSC-PERSISTED-PAYLOAD"
            _, wstatus, wbody = _write(sock, fh, 0, payload)
            assert wstatus == kXR_ok, _error_code(wbody)
            _, cstatus, _ = _close(sock, fh)
            assert cstatus == kXR_ok, "clean POSC close should succeed"
            # The final file must now exist with the written content.
            assert os.path.exists(final), "POSC clean close must persist file"
            with open(final, "rb") as f:
                assert f.read() == payload
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_posc_abort_leaves_no_final_file(self, wr_stack):
        """A POSC open that is written to but never cleanly closed (the client
        just drops the connection) must leave NO final file: the staging temp
        is unlinked on session teardown."""
        rel = "/posc_aborted.bin"
        final = _wr_full(wr_stack, rel)
        _wr_clear_staging(wr_stack, rel)
        data_dir = wr_stack["data_dir"]
        before = set(os.listdir(data_dir))

        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_posc)
            _check_test_posc_abort_leaves_no_final_file_1(status, body)
            fh = body[:4]
            _, wstatus, _ = _write(sock, fh, 0, b"PARTIAL-UPLOAD-WILL-VANISH")
            _check_test_posc_abort_leaves_no_final_file_2(wstatus)
        finally:
            # Abort: hard-drop the connection WITHOUT closing the handle. Done
            # in finally so an early assertion still drops the socket (which is
            # itself a valid abort) instead of leaking the fd to later tests.
            sock.close()

        # The abort is processed asynchronously by the server event loop:
        # the dropped socket surfaces as a readable EOF, which drives
        # on_disconnect -> close_all_files -> free_fhandle -> unlink(temp).
        # That teardown is prompt (~tens of ms) but NOT synchronous with our
        # sock.close(), so poll for both invariants to settle rather than
        # checking once and racing the event loop.  POSC staging uses
        # brix_make_tmp_path(), producing a "<base>.xrd-tmp.<pid>.<random>"
        # sibling (src/core/compat/tmp_path.c), so the orphan marker is ".xrd-tmp.".
        def _orphan_temps():
            return {n for n in (set(os.listdir(data_dir)) - before)
                    if ".xrd-tmp." in n}

        deadline = time.time() + 5.0
        while (time.time() < deadline
               and (os.path.exists(final) or _orphan_temps())):
            time.sleep(0.05)

        _check_test_posc_abort_leaves_no_final_file_3(final)
        leaked = _orphan_temps()
        _check_test_posc_abort_leaves_no_final_file_4(leaked)

        # A fresh session still works after the abort.
        sock2 = _session(wr_stack["host"], wr_stack["port"])
        try:
            _check_test_posc_abort_leaves_no_final_file_5(sock2)
        finally:
            sock2.close()


# ===========================================================================
# File-handle lifecycle: exhaustion + double-close + capability
# ===========================================================================

class TestHandleLifecycle:

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_handle_exhaustion_clean_error(self, wr_stack):
        """Opening more than BRIX_MAX_FILES (16) handles on one session must
        return a clean kXR_ServerError ('too many open files'), not crash; and
        after closing one handle a subsequent open must succeed again."""
        rel = "/exhaust.bin"
        _wr_seed(wr_stack, rel, b"EXHAUST")
        sock = _session(wr_stack["host"], wr_stack["port"])
        handles = []
        try:
            # Fill every slot.
            for i in range(BRIX_MAX_FILES):
                sid = struct.pack("!H", 0x100 + i)
                _, status, body = _open(sock, rel, kXR_open_read, streamid=sid)
                assert status == kXR_ok, (
                    f"open #{i} failed unexpectedly: {_error_code(body)}")
                handles.append(body[:4])
            # The (MAX+1)th open must be rejected cleanly.
            _, status, body = _open(sock, rel, kXR_open_read,
                                    streamid=b"\x0f\xff")
            def _assert_test_handle_exhaustion_clean_error_1():
                assert status == kXR_error, "over-cap open should be rejected"
                assert _error_code(body) == kXR_ServerError, (
                    f"expected kXR_ServerError, got {_error_code(body)}")

            _assert_test_handle_exhaustion_clean_error_1()
            # Session still alive; the cap is graceful, not fatal.
            assert _ping(sock)[1] == kXR_ok
            # Free one slot -> a new open must succeed (slot reuse).
            _, cstatus, _ = _close(sock, handles.pop())
            assert cstatus == kXR_ok
            _, status, body = _open(sock, rel, kXR_open_read,
                                    streamid=b"\x0f\xfe")
            assert status == kXR_ok, (
                f"open after freeing a slot failed: {_error_code(body)}")
            handles.append(body[:4])
        finally:
            for fh in handles:
                try:
                    _close(sock, fh)
                except Exception:
                    pass
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_double_close_rejected(self, wr_stack):
        """Closing a handle twice: the first close succeeds, the second must be
        rejected with kXR_FileNotOpen (the slot's fd is now -1)."""
        rel = "/double_close.bin"
        _wr_seed(wr_stack, rel, b"DOUBLE-CLOSE")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_read)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _, c1, _ = _close(sock, fh)
            assert c1 == kXR_ok, "first close should succeed"
            _, c2, b2 = _close(sock, fh)
            assert c2 == kXR_error, "second close must be rejected"
            assert _error_code(b2) == kXR_FileNotOpen, (
                f"expected kXR_FileNotOpen, got {_error_code(b2)}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    @pytest.mark.registry_server("open-flags-lifecycle")
    def test_readonly_handle_write_rejected(self, ro_data, anon):
        """Opening a file read-only (kXR_open_read) then issuing kXR_write must
        be rejected with kXR_NotAuthorized — the writable capability flag was
        never set at open time (fd_table.c validate_write_handle)."""
        sock = _session(*anon)
        try:
            _, status, body = _open(sock, ro_data, kXR_open_read)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _, wstatus, wbody = _write(sock, fh, 0, b"SHOULD-NOT-BE-WRITTEN")
            assert wstatus == kXR_error, "write on read-only handle must fail"
            assert _error_code(wbody) == kXR_NotAuthorized, (
                f"expected kXR_NotAuthorized, got {_error_code(wbody)}")
            # A legitimate read on the same handle still works.
            _, rstatus, rbody = _read(sock, fh, 0, 8)
            assert rstatus == kXR_ok, _error_code(rbody)
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
