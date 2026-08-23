def pytest_configure(config):
    """Register custom markers and confine all scratch under TEST_ROOT.

    Many tests (and the servers/clients they spawn) create scratch via
    ``tempfile.mkdtemp/mkstemp/TemporaryDirectory`` or a ``TMPDIR``-honoring
    subprocess.  Left at the default they litter bare ``/tmp`` (e.g.
    ``/tmp/xrd-jwks-test-*``).  Point Python's tempdir AND the inherited
    ``$TMPDIR`` at ``TEST_ROOT/tmp`` so every such artifact lands under the one
    test tree that the session wipes and recreates — nothing leaks into /tmp.
    Runs on the controller and on every xdist worker, before any test executes.
    """
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ["TMPDIR"] = TMP_DIR
    tempfile.tempdir = TMP_DIR

    config.addinivalue_line(
        "markers",
        "requires_local_server: test writes directly to the server filesystem "
        "and cannot run against a remote server (skipped when TEST_SERVER_HOST is set)",
    )


# Module-name substrings that identify the multi-minute "slow" families: the
# destructive/resilience suites, multi-node meshes, differential client suites,
# conformance/interop batches, and throughput/perf runs.  Tests in these modules
# are auto-marked `slow` so a fast iteration check can deselect them with
# `-m "not slow"` (see tests/run_suite.sh --fast).  Over-inclusion is safe: the
# full run (run_suite.sh) covers everything regardless of this marker.
_SLOW_MODULE_HINTS = (
    "resilien", "chaos", "evil_actor", "evil_paths", "netfault", "net_resilience",
    "topolog", "conformance", "official", "clientconf", "hybrid", "throughput",
    "performance", "stress", "redteam", "gfal", "busybox", "xrootdfs",
    "fuse", "concurrent", "proxy_large", "large_read", "_mesh", "cms_mesh",
    "interop", "_load", "_e2e",
    # build/compile matrices — a single test can rebuild+dlopen a module (~73s),
    # which has no place in a minutes-long iteration check (full run still runs it).
    "build_matrix",
)


def _is_slow_module(name):
    """True if a test module's basename marks it a slow-family test."""
    stem = name[:-3] if name.endswith(".py") else name
    return any(h in stem for h in _SLOW_MODULE_HINTS)


_remote_skip_cache = {}


def _is_remote_skip(path):
    """True if <path>'s first line is the brix-remote-skip marker (cached)."""
    hit = _remote_skip_cache.get(path)
    if hit is None:
        try:
            with open(path, encoding="utf-8") as fh:
                hit = fh.readline().strip() == "# brix-remote-skip"
        except Exception:
            hit = False
        _remote_skip_cache[path] = hit
    return hit


def pytest_collection_modifyitems(config, items):
    """Skip requires_local_server tests in remote mode; order CMS tests last;
    auto-mark the slow families so `-m "not slow"` yields a fast iteration set."""
    cms_items = []
    other_items = []

    for item in items:
        name = os.path.basename(str(item.fspath))
        _apply_collection_markers(item, name)
        if name == "test_cms.py":
            cms_items.append(item)
        else:
            other_items.append(item)

    if cms_items:
        items[:] = other_items + cms_items


def _apply_collection_markers(item, name):
    _mark_slow(item, name)
    _mark_local_only(item)
    _mark_remote_skip(item)
    _mark_serial(item)


def _mark_slow(item, name):
    if _is_slow_module(name):
        item.add_marker(pytest.mark.slow)


def _mark_local_only(item):
    if item.get_closest_marker("requires_local_server") and REMOTE_SERVER:
        reason = ("requires_local_server: test writes to server filesystem "
                  f"(remote: {SERVER_HOST})")
        item.add_marker(pytest.mark.skip(reason=reason))


def _mark_remote_skip(item):
    if REMOTE_SERVER and _is_remote_skip(str(item.fspath)):
        reason = ("brix-remote-skip: multi-server topology not served "
                  "by the remote mega server")
        item.add_marker(pytest.mark.skip(reason=reason))


def _mark_serial(item):
    if item.get_closest_marker("serial"):
        item.add_marker(pytest.mark.xdist_group("serial"))


def pytest_sessionfinish(session, exitstatus):
    """Stop local servers when the session ends (no-op in remote mode or xdist workers)."""
    import subprocess

    # xdist workers must not call stop-all: the controller owns server lifecycle.
    # A worker finishing early would kill servers other workers still need.
    if hasattr(session.config, "workerinput"):
        return

    if REMOTE_SERVER or _should_skip_local_lifecycle(session.config):
        return

    try:
        subprocess.run(
            [
                os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
                "stop-all",
            ],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass  # best-effort cleanup

    # MANDATED CLEANUP: leave nothing behind.  Restore the original CWD first
    # (we are currently inside CWD_DIR, which is about to be deleted), then
    # destroy the whole temp tree so the next run starts from a clean slate and
    # regenerates every file.  Only reached on the controller in local mode
    # (remote/skip/no-server returned above).
    try:
        os.chdir(_ORIG_CWD)
    except OSError:
        pass
    shutil.rmtree(TEST_ROOT, ignore_errors=True)


@pytest.fixture(scope="session")
def _test_session_setup():
    """Session-scoped fixture that ensures servers are running.

    In remote mode: verifies connectivity; does not start/stop any process.
    In local mode: starts servers and tears them down when the session ends.
    """
    _setup_session()
    yield
    if REMOTE_SERVER or _external_fleet_attached():
        return
    import subprocess

    try:
        subprocess.run(
            [
                os.path.join(os.path.dirname(__file__), "manage_test_servers.sh"),
                "stop-all",
            ],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass


@pytest.fixture(scope="session")
def test_env():
    h = SERVER_HOST
    ports = {
        "anon_port": NGINX_ANON_PORT,
        "gsi_port": NGINX_GSI_PORT,
        "gsi_tls_port": NGINX_GSI_TLS_PORT,
        "token_port": NGINX_TOKEN_PORT,
        "krb5_port": NGINX_KRB5_PORT,
        "metrics_port": NGINX_METRICS_PORT,
        "webdav_port": NGINX_WEBDAV_PORT,
        "webdav_gsi_tls_port": NGINX_WEBDAV_GSI_TLS_PORT,
        "http_webdav_port": NGINX_HTTP_WEBDAV_PORT,
        "s3_port": NGINX_S3_PORT,
        "jwks_refresh_port": NGINX_JWKS_REFRESH_PORT,
        "readonly_port": READONLY_PORT,
        "vo_port": VO_PORT,
        "webdav_auth_cache_manual_port": WEBDAV_AUTH_CACHE_MANUAL_PORT,
        "webdav_auth_cache_nginx_port": WEBDAV_AUTH_CACHE_NGINX_PORT,
        "webdav_tpc_source_required_port": WEBDAV_TPC_SOURCE_REQUIRED_PORT,
        "webdav_tpc_source_open_port": WEBDAV_TPC_SOURCE_OPEN_PORT,
        "webdav_tpc_dest_cafile_port": WEBDAV_TPC_DEST_CAFILE_PORT,
        "webdav_tpc_dest_cadir_port": WEBDAV_TPC_DEST_CADIR_PORT,
        "webdav_tpc_dest_no_service_cert_port": WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
        "webdav_tpc_dest_disabled_port": WEBDAV_TPC_DEST_DISABLED_PORT,
        "webdav_tpc_dest_readonly_port": WEBDAV_TPC_DEST_READONLY_PORT,
        "upstream_redirect_nginx_port": UPSTREAM_REDIRECT_NGINX_PORT,
        "upstream_wait_nginx_port": UPSTREAM_WAIT_NGINX_PORT,
        "upstream_waitresp_nginx_port": UPSTREAM_WAITRESP_NGINX_PORT,
        "upstream_error_nginx_port": UPSTREAM_ERROR_NGINX_PORT,
        "upstream_auth_nginx_port": UPSTREAM_AUTH_NGINX_PORT,
        "upstream_auth_nofile_nginx_port": UPSTREAM_AUTH_NOFILE_NGINX_PORT,
        "upstream_gotorls_notls_nginx_port": UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
        "upstream_redirect_backend_port": UPSTREAM_REDIRECT_BACKEND_PORT,
        "upstream_wait_backend_port": UPSTREAM_WAIT_BACKEND_PORT,
        "upstream_waitresp_backend_port": UPSTREAM_WAITRESP_BACKEND_PORT,
        "upstream_error_backend_port": UPSTREAM_ERROR_BACKEND_PORT,
        "upstream_auth_backend_port": UPSTREAM_AUTH_BACKEND_PORT,
        "upstream_auth_nofile_backend_port": UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
        "upstream_gotorls_notls_backend_port": UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
    }

    return {
        **ports,
        "server_host": h,
        "anon_url": f"root://{h}:{ports['anon_port']}",
        "gsi_url": f"root://{h}:{ports['gsi_port']}",
        "gsi_tls_url": f"roots://{h}:{ports['gsi_tls_port']}",
        "token_url": f"root://{h}:{ports['token_port']}",
        "krb5_url": f"root://{h}:{ports['krb5_port']}",
        "metrics_url": f"http://{h}:{ports['metrics_port']}/metrics",
        "webdav_url": f"https://{h}:{ports['webdav_port']}",
        "webdav_gsi_tls_url": f"https://{h}:{ports['webdav_gsi_tls_port']}",
        "http_webdav_url": f"http://{h}:{ports['http_webdav_port']}",
        "s3_url": f"http://{h}:{ports['s3_port']}",
        "data_dir": DATA_ROOT,
        "ca_dir": CA_DIR,
        "ca_pem": CA_CERT,
        "proxy_pem": PROXY_STD,
        "token_dir": TOKENS_DIR,
        "log_dir": LOG_DIR,
    }


@pytest.fixture(scope="session")
def ref_xrootd(test_env):
    return {
        "url": f"root://{HOST}:{REF_BRIX_PORT}",
        "port": REF_BRIX_PORT,
        "data_dir": test_env["data_dir"],
    }


@pytest.fixture(scope="session")
def ref_brix_gsi(test_env):
    return {
        "url": f"root://{HOST}:{REF_BRIX_GSI_PORT}",
        "port": REF_BRIX_GSI_PORT,
        "data_dir": os.path.join(TEST_ROOT, "data-gsi-bridge"),
    }


@pytest.fixture(scope="session")
def ref_brix_gsi_shared(test_env):
    return {
        "url": f"root://{HOST}:{REF_BRIX_GSI_SHARED_PORT}",
        "port": REF_BRIX_GSI_SHARED_PORT,
        "data_dir": test_env["data_dir"],
    }


# ---------------------------------------------------------------------------
# brix-remote: in REMOTE mode (TEST_SERVER_HOST set), skip test files marked
# with a "# brix-remote-skip" first line — multi-server topologies (cache tiers,
# clusters, upstream chains, ipv6 tiers) the single remote "mega" server does not
# provide. Local runs (REMOTE_SERVER False) are unaffected.
# ---------------------------------------------------------------------------
def pytest_ignore_collect(collection_path, config):
    if not REMOTE_SERVER:
        return None
    try:
        p = str(collection_path)
        if p.endswith(".py"):
            with open(p, encoding="utf-8") as fh:
                if fh.readline().strip() == "# brix-remote-skip":
                    return True
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# brix-remote: the local fleet ships standard test files (/test.txt) in every
# server's data root. In REMOTE mode seed them once per session on the mega so
# adapted tests that assume they exist pass without per-file boilerplate.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _brix_remote_seed_standard_files():
    if REMOTE_SERVER:
        try:
            import klib
            klib.svc_write("mega", "/data/xrootd/test.txt",
                           b"hello from nginx-xrootd\n")
        except Exception:
            pass
    yield
