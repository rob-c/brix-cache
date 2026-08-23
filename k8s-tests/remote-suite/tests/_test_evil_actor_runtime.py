# ---------------------------------------------------------------------------
# the server under attack: real master + workers, thread pool, big cold file
# ---------------------------------------------------------------------------

class _Srv:
    def __init__(self, prefix, conf, pidfile, root_port, http_port, datadir):
        self.prefix = prefix; self.conf = conf; self.pidfile = pidfile
        self.root_port = root_port; self.http_port = http_port
        self.datadir = datadir
        self.master: "int | None" = None
        self._log_mark = 0

    @property
    def logfile(self):
        return os.path.join(self.prefix, "logs", "error.log")

    def log_since_mark(self):
        try:
            with open(self.logfile, errors="replace") as f:
                f.seek(self._log_mark)
                return f.read()
        except OSError:
            return ""

    def mark_log(self):
        try:
            self._log_mark = os.path.getsize(self.logfile)
        except OSError:
            self._log_mark = 0

    def assert_healthy(self, phase):
        """The core verdict: no worker broke during `phase`."""
        delta = self.log_since_mark()
        for pat in CRASH_PATTERNS:
            assert pat not in delta, (
                "WORKER BROKE during %s — %r in error log:\n%s"
                % (phase, pat, delta[-1500:]))
        assert _alive(self.master), "master died during %s" % phase
        assert _worker_pids(self.master), "no workers alive after %s" % phase
        assert _ping_ok(self.root_port), "server not serving after %s" % phase


def _require_fixture_ready():
    if REMOTE_SERVER:
        pytest.skip("self-contained; not for REMOTE mode")
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx not built at %s" % NGINX_BIN)
    if shutil.which("pgrep") is None:
        pytest.skip("pgrep required")


def _fixture_directories(prefix):
    datadir = os.path.join(prefix, "data")
    for path in (os.path.join(prefix, "logs"), datadir):
        os.makedirs(path, exist_ok=True)
    return datadir


def _populate_fixture_data(datadir):
    chunk = bytes((index * 31 + 7) & 0xFF for index in range(65536))
    with open(os.path.join(datadir, "big.bin"), "wb") as target:
        for _ in range(BIGFILE_MB * 16):
            target.write(chunk)
    open(os.path.join(datadir, "w.bin"), "wb").close()


def _skip_fixture(prefix, message):
    shutil.rmtree(prefix, ignore_errors=True)
    pytest.skip(message)


def _unused_ports(prefix):
    ports = _free_ports(2)
    for port in ports:
        if _reachable(port):
            _skip_fixture(prefix, "port %d in use" % port)
    return ports


def _stop_nginx(prefix, config_path):
    subprocess.run(
        [NGINX_BIN, "-p", prefix, "-c", config_path, "-s", "stop"],
        capture_output=True,
    )


def _validate_and_start(prefix, config_path, root_port):
    check = subprocess.run(
        [NGINX_BIN, "-t", "-p", prefix, "-c", config_path],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        tail = (check.stderr or check.stdout).strip()[-400:]
        _skip_fixture(prefix, "nginx rejected config: %s" % tail)
    run = subprocess.run(
        [NGINX_BIN, "-p", prefix, "-c", config_path],
        capture_output=True, text=True,
    )
    if run.returncode == 0 and _wait_port(root_port):
        return
    tail = (run.stderr or run.stdout).strip()[-400:]
    _stop_nginx(prefix, config_path)
    _skip_fixture(prefix, "nginx did not start: %s" % tail)


def _fixture_server(prefix, config_path, ports, datadir):
    pidfile = os.path.join(prefix, "logs", "nginx.pid")
    server = _Srv(prefix, config_path, pidfile, *ports, datadir)
    server.master = _master_pid(pidfile)
    return server


def _require_fixture_master(server):
    if server.master and _alive(server.master):
        return
    _stop_nginx(server.prefix, server.conf)
    _skip_fixture(server.prefix, "master pid never appeared")


def _report_fixture(server):
    print(
        "\n[evil] master=%d root=%d http=%d workers=%s"
        % (server.master, server.root_port, server.http_port,
           _worker_pids(server.master))
    )


def _cleanup_fixture(server):
    _stop_nginx(server.prefix, server.conf)
    time.sleep(0.3)
    if server.master and _alive(server.master):
        try:
            os.kill(server.master, 9)
        except OSError:
            pass
    shutil.rmtree(server.prefix, ignore_errors=True)


@pytest.fixture(scope="module")
def srv():
    _require_fixture_ready()
    prefix = tempfile.mkdtemp(prefix="evil-")
    datadir = _fixture_directories(prefix)
    _populate_fixture_data(datadir)
    ports = _unused_ports(prefix)
    root_port, http_port = ports

    conf = ("""
worker_processes 3;
daemon on;
master_process on;
pid %s/logs/nginx.pid;
error_log %s/logs/error.log info;
thread_pool aiopool threads=4 max_queue=4096;
events { worker_connections 1024; }
stream {
    server {
        listen %s:%d;
        brix_root on;
        brix_storage_backend posix:%s;
        brix_auth none;
        brix_allow_write on;
        brix_thread_pool aiopool;
        brix_memory_budget 8m;
    }
}
http {
    access_log off;
    server {
        listen %s:%d;
        location = /metrics { brix_metrics on; }
    }
}
""" % (prefix, prefix, BIND_HOST, root_port, datadir, BIND_HOST, http_port))
    conf_path = os.path.join(prefix, "nginx.conf")
    with open(conf_path, "w") as target:
        target.write(conf)
    _validate_and_start(prefix, conf_path, root_port)
    server = _fixture_server(prefix, conf_path, ports, datadir)
    _require_fixture_master(server)
    _report_fixture(server)
    try:
        yield server
    finally:
        _cleanup_fixture(server)


# ---------------------------------------------------------------------------
# helper: open the big file on a session, return its 4-byte fhandle
# ---------------------------------------------------------------------------

def _open_big(s):
    st, body = _open(s, "/big.bin", flags=0x0010)
    if st != kXR_ok or len(body) < 4:
        raise ConnectionError("open /big.bin failed: %r" % st)
    return body[:4]


def _open_w(s):
    st, body = _open(s, "/w.bin", flags=0x0010 | 0x0020)   # read|update
    if st != kXR_ok or len(body) < 4:
        raise ConnectionError("open /w.bin failed: %r" % st)
    return body[:4]


# ---------------------------------------------------------------------------
# Phase A — broad hostile-frame barrage (each on a fresh session; best-effort)
# ---------------------------------------------------------------------------

def _hostile_frames(fh_big, fh_w):
    """A list of (name, raw-bytes-to-send-after-login) hostile requests."""
    F = []
    bad = bytes([random.choice([15, 16, 17, 64, 200, 255])]) + b"\x00\x00\x00"

    # fhandle OOB (16..255) across every handle-indexed opcode
    for op, body in (
        (kXR_read,  struct.pack("!4sqi", bad, 0, 4096)),
        (kXR_pgread, struct.pack("!4sqi", bad, 0, 4096)),
        (kXR_close, bad + b"\x00" * 12),
        (kXR_stat,  struct.pack("!B11s4s", 0, b"\x00" * 11, bad)),
        (kXR_truncate, bad + struct.pack("!q", 4096) + b"\x00" * 4),
        (kXR_write, struct.pack("!4sqB3s", bad, 0, 0, b"\x00" * 3)),
        (kXR_pgwrite, struct.pack("!4sqBB2s", bad, 0, 0, 0, b"\x00\x00")),
    ):
        F.append(("fhandle_oob_%d" % op, _frame(op, body,
                  b"x" * 4096 if op in (kXR_write,) else b"")))

    # negative / overflow offsets
    F.append(("read_neg_off", _frame(kXR_read, struct.pack("!4sqi", fh_big, -1, 4096))))
    F.append(("read_huge_off", _frame(kXR_read, struct.pack("!4sQi", fh_big, 0x7FFFFFFFFFFFFFFF, 4096))))
    F.append(("read_huge_rlen", _frame(kXR_read, struct.pack("!4sqi", fh_big, 0, 0x7FFFFFFF))))
    F.append(("read_neg_rlen", _frame(kXR_read, struct.pack("!4sqi", fh_big, 0, -1))))
    F.append(("pgread_unaligned", _frame(kXR_pgread, struct.pack("!4sqi", fh_big, 1, 4097))))
    F.append(("pgread_neg_off", _frame(kXR_pgread, struct.pack("!4sqi", fh_big, -7, 8192))))

    # readv abuse
    seg_valid = lambda fh, off, rl: struct.pack("!4siq", fh, rl, off)
    F.append(("readv_dlen_not_mult16", _frame(kXR_readv, b"", b"\x00" * 17)))
    F.append(("readv_zero_segs", _frame(kXR_readv, b"", b"")))
    F.append(("readv_1025_segs", _frame(kXR_readv, b"", seg_valid(fh_big, 0, 16) * 1025)))
    F.append(("readv_oob_handle", _frame(kXR_readv, b"", seg_valid(bad, 0, 4096))))
    F.append(("readv_valid_then_oob", _frame(kXR_readv, b"",
              seg_valid(fh_big, 0, 4096) + seg_valid(bad, 0, 4096))))
    F.append(("readv_huge_rlen", _frame(kXR_readv, b"", seg_valid(fh_big, 0, 0x7FFFFFFF))))
    F.append(("readv_neg_off", _frame(kXR_readv, b"", struct.pack("!4siq", fh_big, 4096, -1))))
    # long contiguous coalesce run (stress the 64-iovec cap)
    contig = b"".join(seg_valid(fh_big, i * 4096, 4096) for i in range(200))
    F.append(("readv_long_contig", _frame(kXR_readv, b"", contig)))

    # pgwrite framing abuse (needs a writable handle)
    F.append(("pgwrite_bad_crc", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 0, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0xDEADBEEF) + b"z" * 4096)))
    F.append(("pgwrite_tiny", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 0, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0) + b"")))
    F.append(("pgwrite_unaligned", _frame(kXR_pgwrite,
              struct.pack("!4sqBB2s", fh_w, 4095, 0, 0, b"\x00\x00"),
              struct.pack("!I", 0xCAFEBABE) + b"q" * 10)))

    # writev N-discovery confusion: header count vs payload mismatch
    F.append(("writev_seg_mismatch", _frame(kXR_writev, b"",
              struct.pack("!4sii", fh_w, 0, 0x7FFFFFFF) + b"short")))

    # kXR_clone unvalidated offsets (negative + near 2^63)
    F.append(("clone_neg_off", _frame(kXR_clone,
              struct.pack("!4s4sq", fh_big, fh_w, -1),
              struct.pack("!qqQ", -1, -1, 0x7FFFFFFFFFFFFFFF))))

    # fattr abuse: numattr 17/255, bad subcode, truncated nvec
    F.append(("fattr_numattr_255", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 0, 255, b"\x00" * 10),
              b"\xff" + b"\x00" * 32)))
    F.append(("fattr_subcode_99", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 99, 1, b"\x00" * 10), b"\x00" * 8)))
    F.append(("fattr_trunc_nvec", _frame(kXR_fattr,
              struct.pack("!4sBB10s", fh_big, 0, 16, b"\x00" * 10), b"\x00\x02")))

    # query hostile subcodes / paths
    F.append(("query_bad_subcode", _frame(kXR_query,
              struct.pack("!H2s4s8s", 999, b"\x00\x00", b"\x00" * 4, b"\x00" * 8),
              b"/" + b"../" * 64 + b"\x00")))

    # path abuse on open
    F.append(("open_traversal", _open_frame("/" + "../" * 80 + "etc/passwd")))
    F.append(("open_nul", _open_frame(b"/big\x00.bin")))
    F.append(("open_overlong", _open_frame("/" + "A" * 9000)))

    # lying / oversized dlen (allocation gate)
    F.append(("read_lying_dlen", _frame(kXR_read,
              struct.pack("!4sqi", fh_big, 0, 4096), b"", dlen=0x40000000)))
    F.append(("write_oversize_dlen", _frame(kXR_write,
              struct.pack("!4sqB3s", fh_w, 0, 0, b"\x00" * 3), b"x" * 64, dlen=0x7FFFFFFF)))
    F.append(("stat_oversize_dlen", _frame(kXR_stat,
              struct.pack("!B11s4s", 0, b"\x00" * 11, b"\x00" * 4), b"", dlen=0x10000000)))

    # unknown / reserved opcodes
    for op in (2999, 3005, 3099, 4099, 65535, 0):
        F.append(("opcode_%d" % op, _frame(op, b"", b"")))

    return F


def _open_frame(path):
    p = (path.encode() if isinstance(path, str) else path)
    if not p.endswith(b"\x00"):
        p += b"\x00"
    body = struct.pack("!HH2s6s4s", 0o644, 0x0010, b"\x00\x00", b"\x00" * 6, b"\x00" * 4)
    return _frame(kXR_open, body, p, sid=b"\x00\x02")


def _build_attacks(srv):
    """Open the two handles once per call to embed VALID fhandles in the frames
    (so handle-mixing attacks reach the per-segment validator)."""
    s = _session(srv.root_port)
    try:
        fh_big = _open_big(s)
        fh_w = _open_w(s)
    except Exception:
        fh_big = fh_w = b"\x00\x00\x00\x00"
    # the handles belong to session `s`; the attack frames are replayed on OTHER
    # sessions where those handles are NOT open — that is intentional (it makes
    # even the "valid" handle invalid on the attacker session, exercising the
    # not-open path), plus the OOB handles which are invalid everywhere.
    attacks = _hostile_frames(fh_big, fh_w)
    try:
        s.close()
    except OSError:
        pass
    return attacks


# ---------------------------------------------------------------------------
# Phase B — disconnect-mid-AIO torture (the headline use-after-free hunt)
# ---------------------------------------------------------------------------

def _aio_readv_segments(handle, offset):
    return b"".join(
        struct.pack("!4siq", handle, 1 << 20, offset + index * (1 << 20))
        for index in range(16)
    )


def _aio_write_handle(connection, fallback):
    try:
        return _open_w(connection)
    except Exception:
        return fallback


def _send_aio_operation(connection, operation, handle, offset, length):
    if operation == "pgread":
        connection.sendall(_frame(
            kXR_pgread, struct.pack("!4sqi", handle, offset, length)
        ))
        return
    if operation == "read":
        connection.sendall(_frame(
            kXR_read, struct.pack("!4sqi", handle, offset, length)
        ))
        return
    if operation == "readv":
        connection.sendall(_frame(
            kXR_readv, b"", _aio_readv_segments(handle, offset)
        ))
        return
    write_handle = _aio_write_handle(connection, handle)
    request = struct.pack("!4sqB3s", write_handle, 0, 0, b"\x00" * 3)
    connection.sendall(_frame(kXR_write, request, b"Z" * (1 << 20)))


def _aio_rst_round(port, rng):
    connection = None
    try:
        connection = _connect(port, timeout=4)
        _login(connection)
        handle = _open_big(connection)
        operation = rng.choice(("pgread", "readv", "read", "write"))
        limit = max(1, BIGFILE_MB * 1024 * 1024 - (32 << 20))
        offset = rng.randrange(0, limit)
        length = rng.choice((8 << 20, 24 << 20, 48 << 20))
        _send_aio_operation(connection, operation, handle, offset, length)
    except Exception:
        pass
    finally:
        if connection is not None:
            delay = rng.choice((0, 0, 0.0005, 0.002, 0.008))
            if delay:
                time.sleep(delay)
            _rst_close(connection)


def _aio_rst_worker(port, rounds, stop_at, counter):
    rng = random.Random(threading.get_ident())
    while time.time() < stop_at and counter[0] < rounds:
        counter[0] += 1
        _aio_rst_round(port, rng)


__all__ = [name for name in dir() if not name.startswith("__")]
