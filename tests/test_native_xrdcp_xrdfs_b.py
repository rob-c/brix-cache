from _test_native_xrdcp_xrdfs_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

def test_m5_wait_then_served(native_xrdfs):
    """kXR_wait is honored: the client backs off and re-sends to the same server."""
    def wait_then_ok(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        conn.sendall(_hdr(sid, kXR_wait, 4))
        conn.sendall(_struct.pack(">I", 1))      # wait 1 second
        sid2 = _read_request(conn)               # client re-sends the stat
        _stat_ok_reply(conn, sid2)

    with _StubServer(wait_then_ok) as srv:
        t0 = time.monotonic()
        rc, out, err = _run(
            native_xrdfs, f"root://{url_host(HOST)}:{srv.port}", "stat", "/f",
            timeout=15,
        )
        elapsed = time.monotonic() - t0
    assert rc == 0, f"wait+retry failed (rc={rc}): {err}"
    assert "Size:" in out, f"stat not served after wait: {out}"
    assert elapsed >= 1.0, f"client did not actually back off (elapsed={elapsed:.2f}s)"


def test_m6_pgread_download_byte_exact(native_xrdcp, seeded_file, tmp_path):
    """--pgrw download (kXR_pgread + per-page CRC32c) is byte-exact vs origin."""
    name, _ = seeded_file
    origin = os.path.join(DATA_ROOT, name)
    out = str(tmp_path / "pg.bin")
    rc = subprocess.run([native_xrdcp, "--pgrw", "-f", f"{NGINX_URL}//{name}", out],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "pgread download failed"
    assert _md5_file(out) == _md5_file(origin), "pgread bytes differ"


def test_m6_pgwrite_upload_byte_exact(native_xrdcp, remote_upload_name, tmp_path):
    """--pgrw upload (kXR_pgwrite + per-page CRC32c) lands byte-exact on disk."""
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(1024 * 1024 + 4097))   # spans pages, short last page
    rc = subprocess.run([native_xrdcp, "--pgrw", src, f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "pgwrite upload failed"
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(src)


def test_m6_cksum_source_agrees(native_xrdcp, seeded_file, tmp_path):
    """--cksum adler32:source computes locally and matches the server's Qcksum."""
    name, _ = seeded_file
    out = str(tmp_path / "ck.bin")
    proc = subprocess.run(
        [native_xrdcp, "--cksum", "adler32:source", "-f", f"{NGINX_URL}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    )
    assert proc.returncode == 0, f"cksum source-compare failed: {proc.stderr}"
    assert "OK (matches server)" in proc.stdout, proc.stdout


def test_m6_cksum_bad_value_fails(native_xrdcp, seeded_file, tmp_path):
    """--cksum adler32:<wrong> fails non-zero and drops the destination."""
    name, _ = seeded_file
    out = str(tmp_path / "bad.bin")
    proc = subprocess.run(
        [native_xrdcp, "--cksum", "adler32:deadbeef", "-f", f"{NGINX_URL}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    )
    assert proc.returncode != 0, "bad expected-checksum unexpectedly succeeded"
    assert not os.path.exists(out), "destination left behind after checksum failure"


def test_m6_pgread_clean_stub_ok(native_xrdcp, tmp_path):
    """Self-check: a stub with correct header+page CRC32c downloads successfully —
    this proves the Python CRC32c matches the client's, so the corruption test
    below is exercising the PAGE digest path (not a header-CRC reject)."""
    payload = os.urandom(777)
    out = str(tmp_path / "clean.bin")
    with _StubServer(lambda conn, port: _serve_one_pgread(conn, payload, False)) as srv:
        rc = subprocess.run(
            [native_xrdcp, "--pgrw", "-f", f"root://{url_host(HOST)}:{srv.port}//f", out],
            capture_output=True, text=True, env=_CLEAN_ENV, timeout=15,
        ).returncode
    assert rc == 0, "clean pgread stub failed (Python CRC32c mismatch?)"
    assert open(out, "rb").read() == payload, "clean pgread bytes differ"


def test_m6_pgread_corrupt_page_detected(native_xrdcp, tmp_path):
    """A page whose data no longer matches its CRC32c is detected and rejected."""
    payload = os.urandom(777)
    out = str(tmp_path / "corrupt.bin")
    with _StubServer(lambda conn, port: _serve_one_pgread(conn, payload, True)) as srv:
        proc = subprocess.run(
            [native_xrdcp, "--pgrw", "-f", f"root://{url_host(HOST)}:{srv.port}//f", out],
            capture_output=True, text=True, env=_CLEAN_ENV, timeout=15,
        )
    assert proc.returncode != 0, "corrupted page was NOT detected"
    assert re.search(r"crc|checksum|integrity", proc.stderr, re.I), \
        f"expected a CRC diagnostic, got: {proc.stderr}"
    assert not os.path.exists(out), "destination left behind after CRC failure"


@pytest.mark.slow
@pytest.mark.timeout(300)
def test_m6_pgrw_large_roundtrip(native_xrdcp, remote_upload_name, tmp_path):
    """200 MB up+down via paged I/O stays md5-exact (every page CRC32c checked)."""
    src = str(tmp_path / "big.bin")
    with open(src, "wb") as fh:
        for _ in range(200):
            fh.write(os.urandom(1024 * 1024))
    src_md5 = _md5_file(src)
    rc = subprocess.run([native_xrdcp, "--pgrw", src, f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=240).returncode
    assert rc == 0, "large pgwrite upload failed"
    back = str(tmp_path / "big_back.bin")
    rc = subprocess.run([native_xrdcp, "--pgrw", "-f",
                         f"{NGINX_URL}//{remote_upload_name}", back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=240).returncode
    assert rc == 0, "large pgread download failed"
    assert _md5_file(back) == src_md5, "large pgrw round-trip md5 mismatch"


def test_m9_mkdir_stat_rmdir(native_xrdfs, m9_dir):
    rc, _, err = _fs(native_xrdfs, "mkdir", f"/{m9_dir}")
    assert rc == 0, f"mkdir failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}")
    assert rc == 0 and "IsDir" in out, f"dir not created/flagged:\n{out}"
    rc, _, err = _fs(native_xrdfs, "rmdir", f"/{m9_dir}")
    assert rc == 0, f"rmdir failed: {err}"
    rc, _, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}")
    assert rc != 0, "stat of removed dir unexpectedly succeeded"


def test_m9_mkdir_p_nested(native_xrdfs, m9_dir):
    rc, _, err = _fs(native_xrdfs, "mkdir", "-p", f"/{m9_dir}/a/b/c")
    assert rc == 0, f"mkdir -p failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}/a/b/c")
    assert rc == 0 and "IsDir" in out


def test_m9_mv(native_xrdcp, native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    src_disk = os.path.join(DATA_ROOT, m9_dir, "a.bin")
    with open(src_disk, "wb") as fh:
        fh.write(b"move me")
    rc, _, err = _fs(native_xrdfs, "mv", f"/{m9_dir}/a.bin", f"/{m9_dir}/b.bin")
    assert rc == 0, f"mv failed: {err}"
    assert _fs(native_xrdfs, "stat", f"/{m9_dir}/a.bin")[0] != 0, "src still present"
    assert _fs(native_xrdfs, "stat", f"/{m9_dir}/b.bin")[0] == 0, "dst missing"


def test_m9_chmod(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "c.bin")
    with open(disk, "wb") as fh:
        fh.write(b"x")
    rc, _, err = _fs(native_xrdfs, "chmod", f"/{m9_dir}/c.bin", "0640")
    assert rc == 0, f"chmod failed: {err}"
    assert (os.stat(disk).st_mode & 0o777) == 0o640, "mode not applied on disk"


def test_m9_truncate(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "t.bin")
    with open(disk, "wb") as fh:
        fh.write(b"0123456789")
    rc, _, err = _fs(native_xrdfs, "truncate", f"/{m9_dir}/t.bin", "4")
    assert rc == 0, f"truncate failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}/t.bin")
    assert _stat_field(out, "Size") == "4", f"size not truncated:\n{out}"


def test_m9_cat(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "cat.txt")
    payload = os.urandom(40000)
    with open(disk, "wb") as fh:
        fh.write(payload)
    proc = subprocess.run([native_xrdfs, NGINX_URL, "cat", f"/{m9_dir}/cat.txt"],
                          capture_output=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"cat failed: {proc.stderr}"
    assert proc.stdout == payload, "cat content differs"


def test_m9_tail(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "tail.txt")
    payload = bytes(range(256)) * 40   # 10240 bytes
    with open(disk, "wb") as fh:
        fh.write(payload)
    proc = subprocess.run([native_xrdfs, NGINX_URL, "tail", "-c", "100", f"/{m9_dir}/tail.txt"],
                          capture_output=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"tail failed: {proc.stderr}"
    assert proc.stdout == payload[-100:], "tail window differs"


def test_m9_locate(native_xrdfs, seeded_file):
    name, _ = seeded_file
    rc, out, err = _fs(native_xrdfs, "locate", f"/{name}")
    assert rc == 0, f"locate failed: {err}"
    assert out.strip().startswith("S"), f"unexpected locate token: {out}"


def test_m9_query_checksum_matches_adler32(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "q.bin")
    payload = os.urandom(50000)
    with open(disk, "wb") as fh:
        fh.write(payload)
    rc, out, err = _fs(native_xrdfs, "query", "checksum", f"/{m9_dir}/q.bin")
    assert rc == 0, f"query checksum failed: {err}"
    parts = out.split()
    assert len(parts) >= 2, f"unexpected checksum reply: {out}"
    if parts[0] == "adler32":
        assert int(parts[1], 16) == _zlib.adler32(payload) & 0xffffffff, "adler32 differs"


def test_m9_query_config(native_xrdfs):
    rc, out, err = _fs(native_xrdfs, "query", "config", "tpc")
    assert rc == 0, f"query config failed: {err}"
    assert out.strip() != "", "empty config reply"


def test_m9_statvfs(native_xrdfs):
    rc, out, err = _fs(native_xrdfs, "statvfs", "/")
    assert rc == 0, f"statvfs failed: {err}"
    assert len(out.split()) >= 4, f"unexpected statvfs reply: {out}"


def test_m9_repl_basic(native_xrdfs):
    """The interactive shell handles pwd/cd/stat/exit over piped stdin."""
    script = "pwd\nstat /test.txt\nexit\n"
    proc = subprocess.run([native_xrdfs, NGINX_URL], input=script,
                          capture_output=True, text=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"repl failed: {proc.stderr}"
    assert "Size:" in proc.stdout, f"repl stat produced no output:\n{proc.stdout}"


# --- M9 error / security-negative ---

def test_m9_rmdir_nonempty_fails(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", "-p", f"/{m9_dir}/child")[0] == 0
    rc, _, _ = _fs(native_xrdfs, "rmdir", f"/{m9_dir}")
    assert rc != 0, "rmdir of a non-empty directory unexpectedly succeeded"


def test_m9_rm_missing_fails(native_xrdfs):
    rc, _, _ = _fs(native_xrdfs, "rm", f"/_fstest_absent_{os.getpid()}.bin")
    assert rc != 0, "rm of a missing file unexpectedly succeeded"


def test_m9_mv_traversal_rejected(native_xrdfs, m9_dir):
    """A destination escaping the export root must never write outside it.

    The native client normalises a leading-``../`` absolute path
    (/../../../../etc/pwn -> /etc/pwn), which the server then CONFINES under the
    export root (<root>/etc/pwn).  So the move may succeed in-root (rc=0) or be
    refused, but the one invariant is that nothing is ever written to the real
    /etc.  (The raw, un-normalised form is rejected with kXR_InvalidDest — see the
    stock-client parity in test_gsi_handshake / test_conf_errors.)"""
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "s.bin")
    with open(disk, "wb") as fh:
        fh.write(b"x")
    _fs(native_xrdfs, "mv", f"/{m9_dir}/s.bin", "/../../../../etc/pwn")
    assert not os.path.exists("/etc/pwn"), "traversal wrote outside the export root"


def test_m8_streams_roundtrip_byte_exact(native_xrdcp, remote_upload_name, tmp_path):
    """xrdcp --streams 4 up+down is byte-exact and emits kXR_bind log entries."""
    src = str(tmp_path / "s.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(2 * 1024 * 1024 + 13))
    src_md5 = _md5_file(src)
    before = _count_log(ANON_ACCESS_LOG, '"BIND - -" OK')

    rc = subprocess.run([native_xrdcp, "-f", "--streams", "4", src,
                         f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "streams upload failed"
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == src_md5

    back = str(tmp_path / "b.bin")
    rc = subprocess.run([native_xrdcp, "-f", "--streams", "4",
                         f"{NGINX_URL}//{remote_upload_name}", back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "streams download failed"
    assert _md5_file(back) == src_md5

    after = _count_log(ANON_ACCESS_LOG, '"BIND - -" OK')
    assert after > before, "no kXR_bind entries — streams fell back to one connection"


@pytest.mark.skipif(not _port_open(ROOT_TPC_NGINX_PORT),
                    reason="root-tpc nginx (:11110) not running")
def test_m8_tpc_only_nginx_to_nginx(native_xrdcp):
    """--tpc only drives a server-side third-party copy between two nginx paths
    (the dest server pulls from the source; no bytes transit the client)."""
    uid = f"{os.getpid()}_{int(time.time()*1000)}"
    src = f"_m8tpc_src_{uid}.bin"
    dst = f"_m8tpc_dst_{uid}.bin"
    payload = os.urandom(48000)
    with open(os.path.join(ROOT_TPC_DATA, src), "wb") as fh:
        fh.write(payload)
    url = f"root://{SERVER_HOST}:{ROOT_TPC_NGINX_PORT}"
    try:
        proc = subprocess.run([native_xrdcp, "-f", "--tpc", "only",
                               f"{url}//{src}", f"{url}//{dst}"],
                              capture_output=True, text=True, env=_CLEAN_ENV, timeout=60)
        assert proc.returncode == 0, f"tpc only failed: {proc.stderr}"
        landed = os.path.join(ROOT_TPC_DATA, dst)
        assert os.path.exists(landed), "TPC destination not created"
        assert open(landed, "rb").read() == payload, "TPC bytes differ"
    finally:
        for n in (src, dst):
            try:
                os.unlink(os.path.join(ROOT_TPC_DATA, n))
            except OSError:
                pass


@pytest.mark.skipif(not (_port_open(ROOT_TPC_NGINX_PORT) and _port_open(ROOT_TPC_REF_PORT)),
                    reason="root-tpc pair (:11110/:11111) not running")
def test_m8_tpc_first_falls_back_to_client_copy(native_xrdcp):
    """--tpc first against a reference xrootd (which uses the async waitresp TPC
    model the native client does not drive) cleanly falls back to a
    client-mediated copy and still completes byte-exact."""
    uid = f"{os.getpid()}_{int(time.time()*1000)}"
    src = f"_m8tpcfb_src_{uid}.bin"
    dst = f"_m8tpcfb_dst_{uid}.bin"
    payload = os.urandom(32000)
    with open(os.path.join(ROOT_TPC_DATA, src), "wb") as fh:
        fh.write(payload)
    nurl = f"root://{SERVER_HOST}:{ROOT_TPC_NGINX_PORT}"
    rurl = f"root://{SERVER_HOST}:{ROOT_TPC_REF_PORT}"
    try:
        proc = subprocess.run([native_xrdcp, "-f", "--tpc", "first",
                               f"{nurl}//{src}", f"{rurl}//{dst}"],
                              capture_output=True, text=True, env=_CLEAN_ENV, timeout=60)
        assert proc.returncode == 0, f"tpc first (fallback) failed: {proc.stderr}"
        landed = os.path.join(ROOT_TPC_REF_DATA, dst)
        if os.path.exists(landed):
            assert open(landed, "rb").read() == payload, "fallback bytes differ"
    finally:
        try:
            os.unlink(os.path.join(ROOT_TPC_DATA, src))
        except OSError:
            pass
        try:
            os.unlink(os.path.join(ROOT_TPC_REF_DATA, dst))
        except OSError:
            pass
