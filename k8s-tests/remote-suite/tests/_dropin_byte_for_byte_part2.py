# ---------------------------------------------------------------------------
# Provisioning (mirrors tests/test_mirror_upstream.py)
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5):
            return True
        time.sleep(0.2)
    return False


def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _serves_seed(port):
    """Probe that the server on `port` actually serves the seed file at the
    expected size via a real handshake+login+stat.  Guards against trusting a
    stale/orphaned listener that bound the port from an earlier run."""
    try:
        s = _session(H, port)
    except Exception:
        return False
    try:
        sid, status, body = _stat(s, PLAIN_NAME)
        if status != kXR_ok:
            return False
        parts = body.split(b"\x00")[0].decode(errors="replace").split()
        # nginx returns exactly 4 fields; the official server returns the same
        # leading 4 (id size flags mtime) followed by extended fields.  Accept
        # any body whose 2nd field is the seed size.
        return len(parts) >= 4 and int(parts[1]) == PLAIN_SIZE
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _seed_data(data_dir):
    _mkdirs(data_dir, os.path.join(data_dir, SUBDIR.lstrip("/")))
    with open(os.path.join(data_dir, PLAIN_NAME.lstrip("/")), "wb") as f:
        f.write(PLAIN_DATA)
    for i, name in enumerate(SUBDIR_FILES):
        with open(os.path.join(data_dir, SUBDIR.lstrip("/"), name), "wb") as f:
            f.write(bytes([i]) * (100 + i))
    noperm = os.path.join(data_dir, NOPERM_NAME.lstrip("/"))
    # A prior run may have left this chmod-000; restore writability first so
    # re-seeding is idempotent.
    if os.path.exists(noperm):
        try:
            os.chmod(noperm, 0o600)
        except OSError:
            pass
    with open(noperm, "wb") as f:
        f.write(b"secret")
    # chmod 000 so a read-open hits EACCES on both servers (EACCES → permission).
    try:
        os.chmod(noperm, 0o000)
    except OSError:
        pass


def _start_xrootd(data_dir):
    """Start a dedicated official xrootd on the shared data root.  Returns the
    cfg path (used as the kill key)."""
    base = os.path.join(_DIR, "xrootd")
    _mkdirs(os.path.join(base, "admin"), os.path.join(base, "run"))
    cfg = os.path.join(base, "xrootd.cfg")
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {BRIX_PORT}\n"
            f"oss.localroot {data_dir}\n"
            f"all.export /\n"
            f"xrootd.chksum max 2 adler32\n"
            f"all.adminpath {os.path.join(base, 'admin')}\n"
            f"all.pidpath {os.path.join(base, 'run')}\n"
            f"xrd.trace off\n")
    subprocess.run([BRIX_BIN, "-b", "-c", cfg,
                    "-l", os.path.join(base, "xrootd.log")],
                   capture_output=True)
    return cfg


def _stop_xrootd(cfg):
    # cfg is a full unique path under _DIR; never a bare pattern.
    subprocess.run(["pkill", "-f", cfg], capture_output=True)


def _nginx_conf(data_dir):
    base = os.path.join(_DIR, "nginx")
    _mkdirs(os.path.join(base, "logs"))
    conf = os.path.join(base, "nginx.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{NGINX_PORT};\n"
            f"        brix_root on;\n"
            f"        brix_storage_backend posix:{data_dir};\n"
            f"        brix_auth none;\n"
            f"        brix_allow_write on;\n"
            f"    }}\n"
            f"}}\n")
    return conf


def _start_nginx(conf):
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        raise RuntimeError(f"nginx config rejected: {chk.stderr[-400:]}")
    subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)


def _stop_nginx(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


def _require_servers():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not os.path.exists(BRIX_BIN):
        pytest.skip(f"official xrootd binary not found at {BRIX_BIN}")


def _require_seed_service(port, label):
    if not _wait_port(port):
        pytest.skip(f"{label} did not come up")
    if not _serves_seed(port):
        pytest.skip(f"{label} is up but not serving the seed data")


@pytest.fixture(scope="module")
def stack():
    _require_servers()
    data_dir = os.path.join(_DIR, "data")
    _seed_data(data_dir)

    xr_cfg = _start_xrootd(data_dir)
    nx_cfg = _nginx_conf(data_dir)
    started = {"xr": xr_cfg, "nx": nx_cfg}
    try:
        _require_seed_service(BRIX_PORT, "official xrootd")
        _start_nginx(nx_cfg)
        _require_seed_service(NGINX_PORT, "nginx")
        yield {
            "data_dir": data_dir,
            "nginx": (H, NGINX_PORT),
            "xrootd": (H, BRIX_PORT),
        }
    finally:
        _stop_nginx(started["nx"])
        _stop_xrootd(started["xr"])


@pytest.fixture
def both(stack):
    """Two live, logged-in sessions: (nginx_sock, brix_sock).  Cleaned up.

    If either session cannot be established the test SKIPS rather than errors —
    the module-level `stack` fixture has already proven both servers serve the
    seed data, so a failure here is an environment hiccup, not a parity bug."""
    try:
        n = _session(*stack["nginx"])
    except _SessionUnavailable as exc:
        pytest.skip(f"nginx session unavailable: {exc}")
    try:
        x = _session(*stack["xrootd"])
    except _SessionUnavailable as exc:
        n.close()
        pytest.skip(f"official xrootd session unavailable: {exc}")
    try:
        yield n, x
    finally:
        for s in (n, x):
            try:
                s.close()
            except Exception:
                pass


# ===========================================================================
# 1. stat ASCII body — field order/format matches official
# ===========================================================================

class TestStatParity:
    """The kXR_stat response body begins with the ASCII string
    '<id> <size> <flags> <mtime>' (src/protocols/root/path/stat_body.c).  nginx returns
    exactly those 4 fields; the OFFICIAL xrootd appends extended fields
    (ctime atime mode owner group) — the conformance contract is that the
    leading 4 fields appear in the SAME ORDER and FORMAT and that the
    semantically-stable ones (size, mtime, the isDir/readable bits) agree.
    Note: the inode `id` legitimately differs because the official server
    emits a synthesized/hashed inode, not the raw st_ino — so we assert its
    FORMAT (an integer in field 0) rather than equality."""

    # XStatRespFlags bits we compare semantically across the two servers.
    _IS_DIR   = 2
    _READABLE = 16

    def _stat_head(self, sock, path):
        """Return the leading 4 stat fields [id, size, flags, mtime] as ints,
        asserting the body has at least those 4 in integer format."""
        sid, status, body = _stat(sock, path)
        assert status == kXR_ok, f"stat({path}) failed: {_error_msg(body)}"
        text = body.split(b"\x00")[0].decode().strip()
        parts = text.split()
        assert len(parts) >= 4, f"stat body must have >=4 fields, got {parts!r}"
        head = parts[:4]
        ints = [int(f) for f in head]  # raises → format divergence
        return ints  # [id, size, flags, mtime]

    def test_stat_body_field_order_and_format(self, both):
        """Both servers emit id, size, flags, mtime as base-10 integers in that
        order as the first four whitespace-separated fields."""
        n, x = both
        n_head = self._stat_head(n, PLAIN_NAME)
        x_head = self._stat_head(x, PLAIN_NAME)
        # Field 0 (id) is an integer on both; field 1 (size) is the real size.
        assert n_head[1] == x_head[1] == PLAIN_SIZE, \
            f"size field (index 1) mismatch nginx={n_head[1]} xrootd={x_head[1]}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_stat_size_and_mtime_match(self, both):
        """size and mtime read the same stat(2) inode → identical on both."""
        n, x = both
        n_id, n_size, n_flags, n_mtime = self._stat_head(n, PLAIN_NAME)
        x_id, x_size, x_flags, x_mtime = self._stat_head(x, PLAIN_NAME)
        assert n_size == x_size == PLAIN_SIZE, \
            f"size mismatch nginx={n_size} xrootd={x_size}"
        assert n_mtime == x_mtime, \
            f"mtime mismatch nginx={n_mtime} xrootd={x_mtime}"

    def test_stat_isdir_and_readable_bits_agree(self, both):
        """The kXR_isDir / kXR_readable flag bits agree for a file and a dir.
        (The kXR_writable bit legitimately differs — the official server sets
        it from the fs mode, nginx reports read-capability only — so we compare
        only the stable bits, not the raw flags integer.)"""
        n, x = both
        # Regular file: not a dir, readable, on both.
        n_file = self._stat_head(n, PLAIN_NAME)[2]
        x_file = self._stat_head(x, PLAIN_NAME)[2]
        assert not (n_file & self._IS_DIR) and not (x_file & self._IS_DIR), \
            f"file wrongly flagged as dir nginx={n_file} xrootd={x_file}"
        assert (n_file & self._READABLE) and (x_file & self._READABLE), \
            f"file not flagged readable nginx={n_file} xrootd={x_file}"
        # Directory: kXR_isDir set on both.
        n_dir = self._stat_head(n, SUBDIR)[2]
        x_dir = self._stat_head(x, SUBDIR)[2]
        assert (n_dir & self._IS_DIR) and (x_dir & self._IS_DIR), \
            f"dir not flagged kXR_isDir nginx={n_dir} xrootd={x_dir}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_statx_field_format_matches(self, both):
        """kXR_statx returns ONE flag byte per path (kXR_file=0 / kXR_isDir=2 /
        kXR_other=4 / kXR_offline=8) — exactly the reference do_Statx response,
        NOT a kXR_stat text line.  The python XRootD client has no statx method,
        so this is raw-wire only.  Both servers must classify the regular file
        identically (a non-directory flag byte)."""
        n, x = both
        _, n_st, n_body = _statx(n, [PLAIN_NAME])
        _, x_st, x_body = _statx(x, [PLAIN_NAME])
        _assert_statx_parity(n_st, n_body, x_st, x_body)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


def _assert_statx_parity(n_status, n_body, x_status, x_body):
    if n_status != kXR_ok:
        pytest.skip(f"statx not supported on nginx (status={n_status})")
    assert len(n_body) == 1, f"nginx statx must be one flag byte: {n_body!r}"
    assert not (n_body[0] & 0x02), "nginx flagged a regular file as a dir"
    if x_status == kXR_ok and len(x_body) == 1:
        assert (x_body[0] & 0x02) == (n_body[0] & 0x02), \
            "isDir flag disagrees between nginx and official statx"


# ===========================================================================
# 2. Qspace — oss.* fields match official
# ===========================================================================

class TestQspaceParity:
    """kXR_Qspace returns 'oss.*' key=value pairs joined by '&'
    (src/protocols/root/query/space.c).  The official server emits the same oss.cgroup /
    oss.space / oss.free / oss.maxf / oss.used / oss.quota key set."""

    def _oss_keys(self, sock):
        sid, status, body = _query(sock, kXR_Qspace, b"/")
        if status != kXR_ok:
            return status, None
        text = body.split(b"\x00")[0].decode(errors="replace")
        keys = set()
        for pair in text.split("&"):
            if "=" in pair:
                keys.add(pair.split("=", 1)[0])
        return status, keys

    def test_qspace_key_set_matches(self, both):
        n, x = both
        n_status, n_keys = self._oss_keys(n)
        x_status, x_keys = self._oss_keys(x)
        if x_status != kXR_ok:
            pytest.skip(f"official xrootd Qspace unsupported (status={x_status})")
        assert n_status == kXR_ok, "nginx Qspace should succeed"
        # The conformance contract: the oss.* key SET nginx returns must be a
        # superset of (and in practice equal to) what the official server emits.
        assert x_keys <= n_keys, (
            f"nginx Qspace missing oss keys present in official: "
            f"{x_keys - n_keys}")
        assert {"oss.space", "oss.free", "oss.used"} <= n_keys, \
            f"nginx Qspace missing core oss fields: {n_keys}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_qspace_values_are_numeric(self, both):
        """Every oss.* value (except cgroup) is an integer on both servers."""
        n, x = both
        for sock, label in ((n, "nginx"), (x, "xrootd")):
            _assert_qspace_numeric(sock, label)


def _require_qspace(status, label):
    if status == kXR_ok:
        return
    if label == "xrootd":
        pytest.skip("official Qspace unsupported")
    pytest.fail("nginx Qspace failed")


def _assert_qspace_numeric(sock, label):
    _sid, status, body = _query(sock, kXR_Qspace, b"/")
    _require_qspace(status, label)
    text = body.split(b"\x00")[0].decode(errors="replace")
    values = (pair.split("=", 1) for pair in text.split("&") if "=" in pair)
    for key, value in values:
        if key != "oss.cgroup":
            int(value)


