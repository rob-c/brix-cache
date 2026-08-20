"""Session/service fixtures and the matrix parametrization layer.

Moved verbatim from tests/conftest_part5.py (TS-2, testsuite-modernization-plan
§11).  tests/conftest.py re-exports every fixture (and pytest_generate_tests)
into its own namespace; pytest collects fixtures from the conftest module's
namespace by name, so where they are physically defined is invisible to tests.

One deliberate deviation from the verbatim source: the ``registry`` fixture
used ``os.path.dirname(__file__)`` to find the tests directory, which was
correct only while the code executed inside the conftest namespace.  Here the
anchor is ``settings.TESTS_DIR``, the flat tree's own published location
(TS-3 moved the settings body into the package, so ``settings.__file__`` no
longer resolves to tests/).
"""

import os

import pytest

import settings
from server_launcher import LifecycleHarness, RegistryLauncher
from server_registry import get_server
from settings import (
    CA_CERT,
    CA_DIR,
    HOST,
    DATA_ROOT,
    LOG_DIR,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_METRICS_PORT,
    NGINX_JWKS_REFRESH_PORT,
    NGINX_KRB5_PORT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    READONLY_PORT,
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
    UPSTREAM_AUTH_BACKEND_PORT,
    UPSTREAM_AUTH_NGINX_PORT,
    UPSTREAM_AUTH_NOFILE_BACKEND_PORT,
    UPSTREAM_AUTH_NOFILE_NGINX_PORT,
    UPSTREAM_ERROR_BACKEND_PORT,
    UPSTREAM_ERROR_NGINX_PORT,
    UPSTREAM_GOTORLS_NOTLS_BACKEND_PORT,
    UPSTREAM_GOTORLS_NOTLS_NGINX_PORT,
    UPSTREAM_REDIRECT_BACKEND_PORT,
    UPSTREAM_REDIRECT_NGINX_PORT,
    UPSTREAM_WAIT_BACKEND_PORT,
    UPSTREAM_WAIT_NGINX_PORT,
    UPSTREAM_WAITRESP_BACKEND_PORT,
    UPSTREAM_WAITRESP_NGINX_PORT,
    VO_PORT,
    WEBDAV_AUTH_CACHE_MANUAL_PORT,
    WEBDAV_AUTH_CACHE_NGINX_PORT,
    WEBDAV_TPC_DEST_CADIR_PORT,
    WEBDAV_TPC_DEST_CAFILE_PORT,
    WEBDAV_TPC_DEST_DISABLED_PORT,
    WEBDAV_TPC_DEST_NO_SERVICE_CERT_PORT,
    WEBDAV_TPC_DEST_READONLY_PORT,
    WEBDAV_TPC_SOURCE_OPEN_PORT,
    WEBDAV_TPC_SOURCE_REQUIRED_PORT,
)

# The tests/ directory — where the registry launcher runs helper scripts from.
_TESTS_DIR = settings.TESTS_DIR


@pytest.fixture(scope="session")
def registry():
    return RegistryLauncher(_TESTS_DIR)


@pytest.fixture
def registry_server():
    def _lookup(name):
        return get_server(name)

    return _lookup


@pytest.fixture
def lifecycle():
    """Per-test registry lifecycle harness for throwaway nginx instances.

    Tests whose subject is lifecycle behavior (reload/reopen/restart/crash)
    drive their own short-lived instances through this instead of hand-rolled
    subprocess calls; teardown stops and unregisters everything it created.
    """
    harness = LifecycleHarness()
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def command_runner(registry):
    return registry.run_cmd


# --------------------------------------------------------------------------- #
# The (protocol × auth × tls × backend) parametrization layer.                  #
# --------------------------------------------------------------------------- #
def pytest_generate_tests(metafunc):
    """Expand `@pytest.mark.matrix(...)` into one case per coverage cell.

    Before this hook the suite had no generative parametrization at all: every
    cell of the matrix was a hand-written module with its own template, which is
    why the matrix was sparse and re-sparsified with each new backend
    (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md item 19).
    Unreachable combinations are parametrized too and skip with the product
    reason from `matrix_layer.supported()`, so "empty" and "impossible" stay
    distinguishable in the report.
    """
    if "matrix_node" not in metafunc.fixturenames:
        return
    mark = metafunc.definition.get_closest_marker("matrix")
    if mark is None:
        raise pytest.UsageError(
            f"{metafunc.definition.nodeid}: requests the `matrix_node` fixture "
            "but carries no @pytest.mark.matrix(...) to expand")
    import matrix_layer
    cells, ids = matrix_layer.expand(**mark.kwargs)
    metafunc.parametrize("matrix_node", cells, ids=ids, indirect=True)


@pytest.fixture(scope="module")
def matrix_node(request, tmp_path_factory):
    """Stand up the parametrized cell; one instance per cell, not per test."""
    import matrix_layer
    from server_launcher import LifecycleHarness

    cell = request.param
    token = None
    if cell.auth == "token":
        from utils.make_token import TokenIssuer
        ti = TokenIssuer(matrix_layer.TOKEN_DIR)
        if not os.path.exists(ti.key_path):
            ti.init_keys()
        token = ti.generate(scope="storage.read:/ storage.modify:/")
    harness = LifecycleHarness()
    try:
        yield matrix_layer.make_node(
            cell, tmp=tmp_path_factory.mktemp(f"matrix-{cell.id}"),
            lifecycle=harness, token=token)
    finally:
        harness.close()


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
