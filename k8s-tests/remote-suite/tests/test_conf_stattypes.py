from _test_conf_stattypes_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

# =========================================================================== #
# REGULAR FILE @ each mode -> flags integer matches stock EXACTLY.
# Owner perms govern (we run as owner). 0644 -> readable|writable;
# 0400 -> readable; 0000 -> no r/w/x bits; 0755 -> readable|writable|xset; etc.
# =========================================================================== #
@pytest.mark.parametrize("mode", REG_MODES)
def test_regfile_flags_int_matches_stock(srv, mode):
    rel = f"/types/reg_{mode:04o}.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert on == fn, (
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")
    # not a dir, not other
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} misclassified: 0x{on:02x} ({_decode_flags(on)})"


# =========================================================================== #
# REGULAR FILE @ each mode -> derive the EXPECTED owner-governed bits and pin
# BOTH servers to that derivation (catches a server that ignores perms).
# =========================================================================== #
@pytest.mark.parametrize("mode", REG_MODES)
def test_regfile_owner_bits_derivation(srv, mode):
    rel = f"/types/reg_{mode:04o}.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed ours={ost} stock={fst}"
    # We run as the file's owner, so owner bits decide r/w/x.
    want = 0
    if mode & 0o400:
        want |= kXR_readable
    if mode & 0o200:
        want |= kXR_writable
    if mode & 0o100:
        want |= kXR_xset
    on, fn = _flags_int(of), _flags_int(ff)
    # mask off only the r/w/x bits for the derivation check
    rwx_mask = kXR_readable | kXR_writable | kXR_xset
    assert (fn & rwx_mask) == want, (
        f"stock {rel} owner-bit derivation wrong (oracle): "
        f"flags={fn}({_decode_flags(fn)}) want r/w/x bits 0x{want:02x}")
    assert (on & rwx_mask) == want, (
        f"our {rel} owner-bit derivation wrong: "
        f"flags={on}({_decode_flags(on)}) want r/w/x bits 0x{want:02x}")


# =========================================================================== #
# 0000-perm file -> readable/writable/xset bits ALL CLEARED on both (owner has
# no perms; owner bits govern when we are the owner).
# =========================================================================== #
def test_zero_perm_file_clears_rwx(srv):
    rel = "/types/reg_0000.bin"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    rwx = kXR_readable | kXR_writable | kXR_xset
    assert (_flags_int(ff) & rwx) == 0, \
        f"stock {rel} has r/w/x bits set on a 0000 file (oracle): {_flags_int(ff)}"
    assert (_flags_int(of) & rwx) == 0, \
        f"our {rel} has r/w/x bits set on a 0000 file: {_flags_int(of)}"


# =========================================================================== #
# Executable files -> kXR_xset SET on both; full flags integer matches.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/exec.sh", "/types/exec_711",
                                 "/types/reg_0755.bin", "/types/reg_0744.bin"])
def test_executable_xset_set(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    assert _flags_int(ff) & kXR_xset, \
        f"stock {rel} missing kXR_xset on an executable (oracle): {_flags_int(ff)}"
    assert _flags_int(of) & kXR_xset, \
        f"our {rel} missing kXR_xset on an executable: {_flags_int(of)}"
    assert _flags_int(of) == _flags_int(ff), \
        f"FLAGS divergence {rel}: ours={_flags_int(of)} stock={_flags_int(ff)}"


# =========================================================================== #
# Non-executable files -> kXR_xset CLEAR on both.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/reg_0644.bin", "/types/reg_0600.bin",
                                 "/types/reg_0400.bin", "/types/reg_0640.bin"])
def test_nonexecutable_xset_clear(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    assert not (_flags_int(ff) & kXR_xset), \
        f"stock {rel} sets kXR_xset on a non-exec file (oracle): {_flags_int(ff)}"
    assert not (_flags_int(of) & kXR_xset), \
        f"our {rel} sets kXR_xset on a non-exec file: {_flags_int(of)}"


# =========================================================================== #
# DIRECTORY @ each mode -> kXR_isDir set + r/w/x bits match stock exactly.
# =========================================================================== #
@pytest.mark.parametrize("mode", DIR_MODES)
def test_dir_flags_int_matches_stock(srv, mode):
    rel = f"/types/dir_{mode:04o}"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost}"
    on, fn = _flags_int(of), _flags_int(ff)
    assert fn & kXR_isDir, f"stock {rel} missing kXR_isDir (oracle): {fn}"
    assert on & kXR_isDir, f"our {rel} missing kXR_isDir: {on}"
    assert on == fn, (
        f"FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")


# =========================================================================== #
# DIRECTORY @ each mode -> owner-governed r/w/x derivation pinned on both.
# =========================================================================== #
@pytest.mark.parametrize("mode", DIR_MODES)
def test_dir_owner_bits_derivation(srv, mode):
    rel = f"/types/dir_{mode:04o}"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert ost == kXR_ok and fst == kXR_ok, f"{rel} stat failed"
    want = 0
    if mode & 0o400:
        want |= kXR_readable
    if mode & 0o200:
        want |= kXR_writable
    if mode & 0o100:
        want |= kXR_xset
    rwx = kXR_readable | kXR_writable | kXR_xset
    assert (_flags_int(ff) & rwx) == want, \
        f"stock {rel} dir owner-bit derivation wrong (oracle): {_flags_int(ff)}"
    assert (_flags_int(of) & rwx) == want, \
        f"our {rel} dir owner-bit derivation wrong: {_flags_int(of)}"


# =========================================================================== #
# FIFO / named pipe -> kXR_other (not file, not dir) on both; full parity.
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/fifo1", "/types/fifo_600"])
def test_fifo_is_other(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert fn & kXR_other and not (fn & kXR_isDir), \
        f"stock {rel} not classified kXR_other (oracle): {fn}({_decode_flags(fn)})"
    assert on & kXR_other and not (on & kXR_isDir), \
        f"our {rel} not classified kXR_other: {on}({_decode_flags(on)})"
    assert on == fn, (
        f"FIFO FLAGS divergence {rel}: ours={on}({_decode_flags(on)}) "
        f"stock={fn}({_decode_flags(fn)})")


# =========================================================================== #
# FIFO via statx -> the single flag byte must be byte-IDENTICAL to stock. (The
# stock do_Statx flag byte is NOT the same as its do_Stat flags integer for a
# fifo — it does not surface kXR_other in statx — so this is a pure differential
# pinned to the oracle, not a guess about which bit "should" be set.)
# =========================================================================== #
@pytest.mark.parametrize("rel", ["/types/fifo1", "/types/fifo_600"])
def test_fifo_statx_matches_stock(srv, rel):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert len(fbody) == 1 and len(obody) == 1, "statx flag byte count != 1"
        # neither stock nor we may classify a fifo as a directory
        assert not (fbody[0] & kXR_isDir), \
            f"stock statx {rel} flag 0x{fbody[0]:02x} sets kXR_isDir (oracle)"
        assert obody == fbody, \
            f"statx FIFO byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


# =========================================================================== #
# SYMLINK -> target (default follow): a link to a FILE resolves to the file's
# type+size; a link to a DIR resolves to kXR_isDir. Parity vs stock.
# =========================================================================== #
def test_symlink_to_file_follows(srv):
    rel = "/types/lnk_file"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle) body={ff!r}"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert not (fn & kXR_isDir) and not (fn & kXR_other), \
        f"stock {rel} did not follow link to file (oracle): {fn}({_decode_flags(fn)})"
    assert not (on & kXR_isDir) and not (on & kXR_other), \
        f"our {rel} did not follow link to file: {on}({_decode_flags(on)})"
    # the target file is 17 bytes ("target-file-12345")
    assert _size_int(ff) == 17, f"stock {rel} size={_size_int(ff)} want 17 (oracle)"
    assert _size_int(of) == 17, f"our {rel} size={_size_int(of)} want 17"
    assert on == fn, f"FLAGS divergence {rel}: ours={on} stock={fn}"


def test_symlink_to_dir_follows(srv):
    rel = "/types/lnk_dir"
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel)
    assert fst == kXR_ok, f"stock stat {rel} status={fst} (oracle)"
    assert ost == kXR_ok, f"our stat {rel} status={ost} body={of!r}"
    fn, on = _flags_int(ff), _flags_int(of)
    assert fn & kXR_isDir, f"stock {rel} did not follow link to dir (oracle): {fn}"
    assert on & kXR_isDir, f"our {rel} did not follow link to dir: {on}"
    assert on == fn, f"FLAGS divergence {rel}: ours={on} stock={fn}"


# =========================================================================== #
# SYMLINK via statx (default follow) -> the flag byte reflects the TARGET type.
# =========================================================================== #
@pytest.mark.parametrize("rel,want_dir", [
    ("/types/lnk_file", False),
    ("/types/lnk_dir", True),
])
def test_symlink_statx_follows_target(srv, rel, want_dir):
    _present(srv, rel)
    o = _session(srv["our_port"])
    f = _session(srv["off_port"])
    try:
        ost, obody = _statx(o, [rel])[1:]
        fst, fbody = _statx(f, [rel])[1:]
        assert fst == kXR_ok, f"stock statx {rel} status={fst} (oracle)"
        assert ost == kXR_ok, f"our statx {rel} status={ost} err={_err(obody)}"
        assert bool(fbody[0] & kXR_isDir) == want_dir, \
            f"stock statx {rel} isDir={bool(fbody[0] & kXR_isDir)} want {want_dir}"
        assert bool(obody[0] & kXR_isDir) == want_dir, \
            f"our statx {rel} flag 0x{obody[0]:02x} isDir wrong (want {want_dir})"
        assert obody == fbody, \
            f"statx symlink byte divergence {rel}: ours={obody!r} stock={fbody!r}"
    finally:
        o.close(); f.close()


@pytest.mark.parametrize("rel", ["/types/lnk_file", "/types/lnk_dir"])
def test_symlink_nofollow_matches_stock(srv, rel):
    _present(srv, rel)
    of, ff, ost, fst = _raw_stat(srv, rel, options=kXR_statNoFollow)
    assert ost == fst, \
        f"statNoFollow status divergence {rel}: ours={ost} stock={fst}"
    if fst == kXR_ok and ost == kXR_ok:
        on, fn = _flags_int(of), _flags_int(ff)
        assert on == fn, (
            f"statNoFollow FLAGS divergence {rel}: "
            f"ours={on}({_decode_flags(on)}) stock={fn}({_decode_flags(fn)})")
