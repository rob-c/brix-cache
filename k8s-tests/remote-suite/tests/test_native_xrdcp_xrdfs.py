# brix-remote-skip
from _test_native_xrdcp_xrdfs_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_stat_size_matches_disk(native_xrdfs, seeded_file, label, endpoint):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, endpoint, "stat", f"/{name}")
    assert rc == 0, f"[{label}] stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), f"[{label}] size mismatch:\n{out}"
    flags = _stat_field(out, "Flags")
    assert flags is not None and "IsReadable" in flags, f"[{label}] flags:\n{out}"


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_ls_contains_seeded_file(native_xrdfs, seeded_file, label, endpoint):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, endpoint, "ls", "/")
    assert rc == 0, f"[{label}] ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), f"[{label}] {name} not in ls:\n{out}"


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_ls_matches_system_xrdfs(native_xrdfs, label, endpoint):
    """The native client and the system xrdfs see the same directory entries.

    Lists a dedicated, test-owned subdirectory — NOT the shared root.  The suite
    runs under pytest-xdist and sibling tests continuously create and delete files
    in "/", so an exact set-equality comparison of two time-separated `ls /` calls
    is inherently racy (the entry set changes between the native and the system
    call).  A private subdirectory that only this test populates is stable, so any
    difference is a genuine native-vs-stock divergence rather than a timing flake."""
    if shutil.which("xrdfs") is None:
        pytest.skip("system xrdfs not installed")
    sub = f"_native_lsmatch_{os.getpid()}_{int(time.time() * 1000)}"
    subdir = os.path.join(DATA_ROOT, sub)
    os.makedirs(subdir, exist_ok=True)
    try:
        for fn in ("alpha.bin", "beta.txt", "gamma.dat"):
            with open(os.path.join(subdir, fn), "wb") as fh:
                fh.write(os.urandom(64))
        os.makedirs(os.path.join(subdir, "nested"), exist_ok=True)
        rc_n, out_n, _ = _run(native_xrdfs, endpoint, "ls", f"/{sub}")
        rc_s, out_s, _ = _run("xrdfs", endpoint, "ls", f"/{sub}")
        assert rc_n == 0 and rc_s == 0, f"[{label}] native rc={rc_n} system rc={rc_s}"
        assert _ls_basenames(out_n) == _ls_basenames(out_s), (
            f"[{label}] entry set differs:\nnative={_ls_basenames(out_n)}\n"
            f"system={_ls_basenames(out_s)}"
        )
    finally:
        shutil.rmtree(subdir, ignore_errors=True)


# --------------------------------------------------------------------------
# M2 — xrdcp download
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,url",
    [("nginx", NGINX_URL), ("ref", REF_URL)],
)
def test_download_md5_matches_origin(native_xrdcp, seeded_file, tmp_path, label, url):
    name, _ = seeded_file
    origin = os.path.join(DATA_ROOT, name)
    out = str(tmp_path / "dl.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{url}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    ).returncode
    assert rc == 0, f"[{label}] download failed rc={rc}"
    assert _md5_file(out) == _md5_file(origin), f"[{label}] bytes differ"


def test_download_large_200mb(native_xrdcp, tmp_path):
    """The harness seeds large200.bin (200 MB); download it byte-exact."""
    origin = os.path.join(DATA_ROOT, "large200.bin")
    if not os.path.exists(origin):
        pytest.skip("large200.bin not seeded")
    out = str(tmp_path / "large.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{NGINX_URL}//large200.bin", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=120,
    ).returncode
    assert rc == 0, f"200MB download failed rc={rc}"
    assert _md5_file(out) == _md5_file(origin)


def test_download_to_stdout(native_xrdcp):
    proc = subprocess.run(
        [native_xrdcp, f"{NGINX_URL}//test.txt", "-"],
        capture_output=True, env=_CLEAN_ENV, timeout=30,
    )
    assert proc.returncode == 0
    with open(os.path.join(DATA_ROOT, "test.txt"), "rb") as fh:
        assert proc.stdout == fh.read()


def test_upload_roundtrip_md5(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(3 * 1024 * 1024 + 17))
    src_md5 = _md5_file(src)
    remote = f"{NGINX_URL}//{remote_upload_name}"

    rc = subprocess.run([native_xrdcp, src, remote],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "upload failed"
    # On-disk file the server wrote matches the source byte-for-byte.
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == src_md5
    # And it reads back identically.
    back = str(tmp_path / "back.bin")
    rc = subprocess.run([native_xrdcp, "-f", remote, back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0 and _md5_file(back) == src_md5


def test_upload_existing_without_force_fails(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(1024))
    remote = f"{NGINX_URL}//{remote_upload_name}"
    assert subprocess.run([native_xrdcp, src, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    # Second upload without -f must fail (destination exists).
    rc = subprocess.run([native_xrdcp, src, remote], capture_output=True,
                        env=_CLEAN_ENV, timeout=30).returncode
    assert rc != 0, "upload over existing file without -f should fail"


def test_upload_force_overwrites(native_xrdcp, remote_upload_name, tmp_path):
    remote = f"{NGINX_URL}//{remote_upload_name}"
    a = str(tmp_path / "a.bin")
    b = str(tmp_path / "b.bin")
    with open(a, "wb") as fh:
        fh.write(os.urandom(2048))
    with open(b, "wb") as fh:
        fh.write(os.urandom(4096))
    assert subprocess.run([native_xrdcp, a, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    assert subprocess.run([native_xrdcp, "-f", b, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(b)


def test_upload_posc(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(64 * 1024))
    remote = f"{NGINX_URL}//{remote_upload_name}"
    rc = subprocess.run([native_xrdcp, "-f", "-P", src, remote],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=30).returncode
    assert rc == 0, "POSC upload failed"
    # POSC commits on clean close → the file persists.
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(src)


def test_token_stat(native_xrdfs, have_token, seeded_file):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                        "stat", f"/{name}", env=_token_env())
    assert rc == 0, f"token stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_token_ls(native_xrdfs, have_token, seeded_file):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                        "ls", "/", env=_token_env())
    assert rc == 0, f"token ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), out


def test_token_download_md5(native_xrdcp, have_token, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "tok.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{TOKEN_URL}//{name}", out],
        capture_output=True, text=True, env=_token_env(), timeout=60,
    ).returncode
    assert rc == 0, "token download failed"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_token_missing_creds_fails(native_xrdfs):
    """Token server with no token → clean auth failure (non-zero), not a crash."""
    rc, _, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                      "stat", "/test.txt")   # _CLEAN_ENV has no BEARER_TOKEN*
    assert rc != 0, f"expected auth failure, got rc={rc}: {err}"


def test_gsi_stat(native_xrdfs, have_proxy, seeded_file):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                        "stat", f"/{name}", env=_gsi_env())
    assert rc == 0, f"GSI stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_gsi_ls(native_xrdfs, have_proxy, seeded_file):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                        "ls", "/", env=_gsi_env())
    assert rc == 0, f"GSI ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), out


def test_gsi_download_md5(native_xrdcp, have_proxy, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "gsi.bin")
    proc = subprocess.run(
        [native_xrdcp, "-f", f"{GSI_URL}//{name}", out],
        capture_output=True, text=True, env=_gsi_env(), timeout=60,
    )
    assert proc.returncode == 0, f"GSI download failed: {proc.stderr}"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_gsi_no_proxy_fails(native_xrdfs, have_proxy):
    """GSI server with no proxy → clean auth failure, not a crash."""
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = "/nonexistent/proxy.pem"
    env["X509_CERT_DIR"] = CA_DIR
    rc, _, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                      "stat", "/test.txt", env=env)
    assert rc != 0, f"expected GSI failure, got rc={rc}: {err}"


def test_gsi_tls_stat(native_xrdfs, have_proxy, seeded_file):
    """roots:// → TLS upgrade (peer verified vs CA) then GSI auth over TLS."""
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, GSI_TLS_ENDPOINT, "stat", f"/{name}",
                        env=_gsi_env())
    assert rc == 0, f"GSI+TLS stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_gsi_tls_download_md5(native_xrdcp, have_proxy, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "tls.bin")
    proc = subprocess.run(
        [native_xrdcp, "-f", f"{GSI_TLS_URL}//{name}", out],
        capture_output=True, text=True, env=_gsi_env(), timeout=60,
    )
    assert proc.returncode == 0, f"GSI+TLS download failed: {proc.stderr}"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_roots_to_nontls_port_refused(native_xrdfs, have_proxy):
    """No silent downgrade: roots:// to a non-TLS server must fail."""
    rc, _, err = _run(native_xrdfs, f"roots://{SERVER_HOST}:{NGINX_ANON_PORT}",
                      "stat", "/test.txt", env=_gsi_env())
    assert rc != 0, f"roots:// to non-TLS port should be refused, got rc={rc}"


def test_gsi_tls_bad_ca_fails(native_xrdfs, have_proxy, tmp_path):
    """TLS peer verification: an empty CA dir must make the handshake fail."""
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = str(tmp_path)   # no CA here
    rc, _, err = _run(native_xrdfs, GSI_TLS_ENDPOINT, "stat", "/test.txt", env=env)
    assert rc != 0, f"TLS with empty CA dir should fail verification, got rc={rc}"


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_stat_missing_matches_system_exitcode(native_xrdfs, label, endpoint):
    """A missing path fails non-zero with the same shell code as system xrdfs."""
    missing = f"/_native_m1_absent_{os.getpid()}.bin"
    rc_n, _, _ = _run(native_xrdfs, endpoint, "stat", missing)
    assert rc_n != 0, f"[{label}] stat of missing path unexpectedly succeeded"
    if shutil.which("xrdfs") is not None:
        rc_s, _, _ = _run("xrdfs", endpoint, "stat", missing)
        assert rc_n == rc_s, f"[{label}] exit code {rc_n} != system {rc_s}"


# --------------------------------------------------------------------------
# negative / invariant
# --------------------------------------------------------------------------

def test_bad_url_scheme_rejected(native_xrdfs):
    """A genuinely unsupported scheme is rejected as a usage error (exit 50), not a
    crash. root:// and http(s)/dav(s) WebDAV ARE supported now; ftp:// is not."""
    rc, _, err = _run(native_xrdfs, "ftp://example.com:21", "stat", "/x")
    assert rc == 50, f"expected usage error 50, got {rc}: {err}"


def test_no_libbrixl_dependency(native_xrdfs):
    """The whole point of phase-37: zero libXrdCl/libXrdSec* linkage."""
    out = subprocess.run(["ldd", native_xrdfs], capture_output=True, text=True).stdout
    bad = [ln for ln in out.splitlines() if re.search(r"XrdCl|XrdSec|libXrd", ln)]
    assert not bad, f"native client links upstream xrootd libs:\n{out}"


def test_m5_redirect_followed_to_target(native_xrdfs):
    """A single redirect is followed to the target, which then serves the stat."""
    def serve_file(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        _stat_ok_reply(conn, sid)

    def redirect_once(conn, port, target_port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        body = _redirect_body(HOST, target_port)
        conn.sendall(_hdr(sid, kXR_redirect, len(body)))
        conn.sendall(body)

    with _StubServer(serve_file) as target:
        def redir(conn, port):
            redirect_once(conn, port, target.port)
        with _StubServer(redir) as front:
            rc, out, err = _run(
                native_xrdfs, f"root://{url_host(HOST)}:{front.port}", "stat", "/f",
                timeout=15,
            )
    assert rc == 0, f"redirect not followed (rc={rc}): {err}"
    assert "Size:" in out, f"target did not serve stat: {out}"


def test_m5_redirect_loop_refused(native_xrdfs):
    """A server that redirects to itself is detected as a loop, not chased forever."""
    def redirect_to_self(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        body = _redirect_body(HOST, port)   # point back at ourselves
        conn.sendall(_hdr(sid, kXR_redirect, len(body)))
        conn.sendall(body)

    with _StubServer(redirect_to_self) as srv:
        rc, out, err = _run(
            native_xrdfs, f"root://{url_host(HOST)}:{srv.port}", "stat", "/f",
            timeout=15,
        )
    assert rc != 0, "redirect loop was not refused"
    assert re.search(r"redirect|loop|too many", err, re.I), \
        f"expected a redirect-loop diagnostic, got: {err}"
