from split_continuation import reexport as _reexport
_reexport(globals(), "_test_conf_sequences_helpers")

pytestmark = pytest.mark.xdist_group("conf_sequences_b")

@pytest.mark.parametrize("n", [0, 1, 100, 4096, 4097, 10000, 65536])
def test_checksum_matches_adler32_of_written(srv, n):
    payload = det_bytes(n, seed=16)
    wire = uniq(f"seq_cks_{n}.bin")
    s = _session(srv["our"])
    try:
        fh = _open_handle(s, wire, WRITE_NEW)
        if n:
            assert _write(s, fh, 0, payload)[0] == kXR_ok, "write"
        assert _close(s, fh)[0] == kXR_ok, "close"
    finally:
        s.close()
    rc, out, err = L.run([L.OFF_XRDFS, srv["our"], "query", "checksum", wire],
                         timeout=120)
    assert rc == 0, f"OUR query checksum failed: {out}{err}"
    toks = out.split()
    assert len(toks) >= 2, f"unexpected checksum reply: {out!r}"
    algo, got = toks[0], toks[1]
    assert algo == "adler32", f"default checksum algo not adler32: {algo!r}"
    want = f"{zlib.adler32(payload) & 0xffffffff:08x}"
    assert got == want, \
        f"OUR adler32 over written bytes WRONG: server={got} reference={want} (n={n})"


# =========================================================================== #
# 13. CREATE IN A NEW DIR (mkpath) -> write -> close -> ls dir shows file ->
#     stat size -> rm file -> rmdir. Full lifecycle, differential.
# =========================================================================== #
@pytest.mark.parametrize("idx,n", [(0, 100), (1, 4096), (2, 0), (3, 65536)])
def test_mkpath_write_ls_stat_rm_rmdir(srv, idx, n):
    payload = det_bytes(n, seed=17)
    for who, url in both(srv):
        d = f"seq_md_{who}_{idx}"
        wire = uniq(f"{d}/sub/file.bin")
        dir_url = f"{url}//{d}/sub"
        s = _session(url)
        try:
            fh = _open_handle(s, wire, kXR_open_wrto | kXR_new | kXR_mkpath)
            if n:
                _require(_write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write")
            _require(_close(s, fh)[0] == kXR_ok, f"{who} close")
        finally:
            s.close()
        _require(
            os.path.exists(disk_for(srv, url, wire)),
            f"{who} mkpath did not create the file",
        )
        # ls the new dir shows the file
        rc, out, e = fs(url, "ls", f"/{d}/sub")
        _require(rc == 0, f"{who} ls new dir failed: {out}{e}")
        _require("file.bin" in out, f"{who} ls did not list the new file: {out!r}")
        # stat size parity
        rc, out, e = fs(url, "stat", wire)
        _require(rc == 0, f"{who} stat new file failed: {out}{e}")
        _require(
            f"Size:   {n}" in out or f"Size: {n}" in out,
            f"{who} stat size not {n}: {out!r}",
        )
        # rm file then rmdir the (now empty) subdir
        _require(fs(url, "rm", wire)[0] == 0, f"{who} rm file")
        _require(
            not os.path.exists(disk_for(srv, url, wire)), f"{who} file not removed"
        )
        _require(fs(url, "rmdir", f"/{d}/sub")[0] == 0, f"{who} rmdir sub")
        _require(
            not os.path.isdir(os.path.join(srv[f"{who}_data"], d, "sub")),
            f"{who} subdir not removed",
        )


# =========================================================================== #
# 14. UPLOAD (xrdcp) -> stat -> download -> md5 round-trip -> overwrite (-f) ->
#     re-download -> new md5. Differential across sizes incl 1 MB.
# =========================================================================== #
@pytest.mark.parametrize("n", [0, 1, 4096, 65536, 1 << 20])
def test_xrdcp_upload_stat_download_overwrite(srv, tmp_path, n):
    src1 = make_local(str(tmp_path / f"u1_{n}.bin"), n, seed=21)
    src2 = make_local(str(tmp_path / f"u2_{n}.bin"), n, seed=22)
    for who, url in both(srv):
        wire = uniq(f"seq_cp_{who}_{n}.bin")
        # upload v1
        rc, o, e = cp("-f", src1, f"{url}/{wire}")
        assert rc == 0, f"{who} upload v1 n={n}: {o}{e}"
        assert os.path.getsize(disk_for(srv, url, wire)) == n, \
            f"{who} on-disk size after upload != {n}"
        # stat size
        rc, out, e = fs(url, "stat", wire)
        assert rc == 0 and (f"Size:   {n}" in out or f"Size: {n}" in out), \
            f"{who} stat after upload: {out!r}"
        # download v1, md5 round-trip
        dl1 = str(tmp_path / f"dl1_{who}_{n}.bin")
        assert cp("-f", f"{url}/{wire}", dl1)[0] == 0, f"{who} download v1"
        with open(src1, "rb") as a, open(dl1, "rb") as b:
            assert md5(a.read()) == md5(b.read()), f"{who} v1 round-trip md5"
        # overwrite with v2 (-f), re-download, new md5
        assert cp("-f", src2, f"{url}/{wire}")[0] == 0, f"{who} overwrite v2"
        dl2 = str(tmp_path / f"dl2_{who}_{n}.bin")
        assert cp("-f", f"{url}/{wire}", dl2)[0] == 0, f"{who} download v2"
        with open(src2, "rb") as a, open(dl2, "rb") as b:
            assert md5(a.read()) == md5(b.read()), f"{who} v2 round-trip md5"


# =========================================================================== #
# 15. CREATE -> write -> close -> truncate(path) to 0 -> stat 0 -> read empty
#     -> write again -> verify.
# =========================================================================== #
@pytest.mark.parametrize("n,n2", [(1000, 500), (4096, 4096), (1, 8192),
                                  (65536, 100), (8192, 1)])
def test_truncate_path_zero_then_rewrite(srv, n, n2):
    first = det_bytes(n, seed=23)
    second = det_bytes(n2, seed=24)
    for who, url in both(srv):
        wire = uniq(f"seq_t0_{who}_{n}_{n2}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, first)[0] == kXR_ok, f"{who} write first"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close first"
        finally:
            s.close()
        # path-based truncate to 0
        assert fs(url, "truncate", wire, "0")[0] == 0, f"{who} truncate0"
        assert os.path.getsize(disk_for(srv, url, wire)) == 0, f"{who} not 0 on disk"
        s = _session(url)
        try:
            # stat(path) size 0, read empty
            st, body = _stat_path(s, wire)
            assert st == kXR_ok and _stat_size(body) == 0, f"{who} stat not 0"
            fhr = _open_handle(s, wire, kXR_open_read)
            st, rb = _read(s, fhr, 0, 4096)
            assert st == kXR_ok and rb == b"", f"{who} read after trunc0 not empty"
            _close(s, fhr)
            # write again
            fhw = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fhw, 0, second)[0] == kXR_ok, f"{who} rewrite"
            assert _close(s, fhw)[0] == kXR_ok, f"{who} close rewrite"
        finally:
            s.close()
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == second, f"{who} rewrite content wrong"


# =========================================================================== #
# 16. ERROR-MID-SEQUENCE — open -> write -> close, then a SECOND write on the
#     now-closed handle -> error parity; prior data must remain intact on both.
# =========================================================================== #
def test_write_to_closed_handle_errors_data_intact(srv):
    payload = det_bytes(1024, seed=25)
    extra = det_bytes(64, seed=26)
    res = {}
    for who, url in both(srv):
        wire = uniq(f"seq_err_{who}.bin")
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_NEW)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
            # write to the (closed) handle -> must error
            st, body = _write(s, fh, 0, extra)
            res[who] = st
        finally:
            s.close()
        # the previously written data must be intact and unchanged
        with open(disk_for(srv, url, wire), "rb") as f:
            assert f.read() == payload, \
                f"{who} prior data corrupted by write to closed handle"
    assert res["our"] == kXR_error, \
        f"OUR accepted write to a closed handle (st={res['our']})"
    assert res["off"] == kXR_error, \
        f"STOCK accepted write to a closed handle (st={res['off']})"


# =========================================================================== #
# 17. MANY SMALL FILES — create+write+close 20 files -> ls shows 20 -> stat
#     each -> read each -> rm each. Counts/bytes compared to stock.
# =========================================================================== #
def _create_small_files(url, who, directory, count):
    bytes_total = 0
    connection = _session(url)
    try:
        for index in range(count):
            wire = uniq(f"{directory}/f{index:02d}.bin")
            options = kXR_open_wrto | kXR_new | kXR_mkpath
            handle = _open_handle(connection, wire, options)
            payload = det_bytes(10 + index, seed=index)
            bytes_total += len(payload)
            _require(
                _write(connection, handle, 0, payload)[0] == kXR_ok,
                f"{who} write {index}",
            )
            _require(
                _close(connection, handle)[0] == kXR_ok,
                f"{who} close {index}",
            )
    finally:
        connection.close()
    return bytes_total


def _assert_small_file_listing(url, who, directory, count):
    status, output, error = fs(url, "ls", f"/{directory}")
    _require(status == 0, f"{who} ls failed: {output}{error}")
    names = [line.strip().split("/")[-1] for line in output.splitlines() if line.strip()]
    names = [name for name in names if name.startswith("f")]
    _require(
        len(names) == count,
        f"{who} ls listed {len(names)} files, want {count}: {names}",
    )


def _read_small_files(url, who, directory, count):
    connection = _session(url)
    disk_bytes = 0
    try:
        for index in range(count):
            wire = uniq(f"{directory}/f{index:02d}.bin")
            expected = det_bytes(10 + index, seed=index)
            status, body = _stat_path(connection, wire)
            _require(
                status == kXR_ok and _stat_size(body) == len(expected),
                f"{who} stat f{index:02d} size wrong",
            )
            handle = _open_handle(connection, wire, kXR_open_read)
            status, data = _read(connection, handle, 0, len(expected))
            _require(
                status == kXR_ok and data == expected,
                f"{who} read f{index:02d} mismatch",
            )
            disk_bytes += len(data)
            _close(connection, handle)
    finally:
        connection.close()
    return disk_bytes


def _remove_small_files(url, who, directory, count):
    for index in range(count):
        wire = uniq(f"{directory}/f{index:02d}.bin")
        _require(fs(url, "rm", wire)[0] == 0, f"{who} rm f{index:02d}")
    _, output, _ = fs(url, "ls", f"/{directory}")
    remaining = [line for line in output.splitlines() if line.strip().endswith(".bin")]
    _require(not remaining, f"{who} files remain after rm: {remaining}")


def test_many_small_files_lifecycle(srv):
    count = 20
    for who, url in both(srv):
        directory = f"seq_many_{who}"
        bytes_total = _create_small_files(url, who, directory, count)
        _assert_small_file_listing(url, who, directory, count)
        disk_bytes = _read_small_files(url, who, directory, count)
        _require(
            disk_bytes == bytes_total,
            f"{who} total bytes read {disk_bytes} != written {bytes_total}",
        )
        _remove_small_files(url, who, directory, count)


# =========================================================================== #
# 18. PGWRITE then PLAIN-READ — write a file via kXR_pgwrite, read it back with
#     a plain kXR_read; the bytes must match (cross-mode coherence). If pgwrite
#     is not plainly supported on this wire path on a server, that server's pair
#     is skipped cleanly (we still require OUR to support it if STOCK does).
# =========================================================================== #
def _close_ignoring_errors(connection, handle):
    try:
        _close(connection, handle)
    except Exception:
        pass


def _pgwrite_one(srv, who, url, n, payload):
    wire = uniq(f"seq_pgw_{who}_{n}.bin")
    connection = _session(url)
    try:
        handle = _open_handle(connection, wire, WRITE_NEW)
        status, _ = _pgwrite(connection, handle, 0, payload)
        if status not in (kXR_ok, kXR_status):
            _close_ignoring_errors(connection, handle)
            return False
        _require(_close(connection, handle)[0] == kXR_ok, f"{who} close")
        read_handle = _open_handle(connection, wire, kXR_open_read)
        read_status, data = _read(connection, read_handle, 0, n)
        _require(
            read_status == kXR_ok and data == payload,
            f"{who} pgwrite->plain-read coherence mismatch",
        )
        _close(connection, read_handle)
    finally:
        connection.close()
    with open(disk_for(srv, url, wire), "rb") as handle:
        _require(handle.read() == payload, f"{who} pgwrite on-disk bytes wrong")
    return True


@pytest.mark.parametrize("n", [100, 4095, 4096, 4097, 8192])
def test_pgwrite_then_plain_read(srv, n):
    payload = det_bytes(n, seed=27)
    supported = {}
    for who, url in both(srv):
        supported[who] = _pgwrite_one(srv, who, url, n, payload)
    # If stock supports pgwrite on this wire path, OUR must too (no silent gap).
    if supported.get("off") and not supported.get("our"):
        pytest.fail("STOCK accepts kXR_pgwrite but OUR server does not")
    if not any(supported.values()):
        pytest.skip("kXR_pgwrite not plainly supported on either server")


# =========================================================================== #
# 19. WRITE -> SYNC -> mtime advances vs the pre-write mtime (both servers).
# =========================================================================== #
def test_write_sync_advances_mtime(srv):
    payload = det_bytes(4096, seed=28)
    for who, url in both(srv):
        wire = uniq(f"seq_mt_{who}.bin")
        # Seed the file out-of-band, then let >1s elapse so a write+sync must
        # land in a LATER integer second than the creation mtime.  Never
        # backdate the mtime below "now": _wipe_stale_working_files judges
        # staleness by mtime vs each worker's import time, so a backdated
        # fixture looks like a prior run's leftover and a concurrent xdist
        # worker's janitor deletes it mid-test.
        disk = disk_for(srv, url, wire)
        with open(disk, "wb") as f:
            f.write(det_bytes(64, seed=99))
        before = int(os.stat(disk).st_mtime)
        time.sleep(1.1)
        s = _session(url)
        try:
            fh = _open_handle(s, wire, WRITE_UPD)
            assert _write(s, fh, 0, payload)[0] == kXR_ok, f"{who} write"
            assert _sync(s, fh)[0] == kXR_ok, f"{who} sync"
            assert _close(s, fh)[0] == kXR_ok, f"{who} close"
        finally:
            s.close()
        after = int(os.stat(disk).st_mtime)
        assert after > before, \
            f"{who} mtime did not advance after write+sync ({before} -> {after})"
