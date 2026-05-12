"""Shared fixtures for nginx-xrootd test suite.

Servers must be started before running tests:
    tests/manage_test_servers.sh start

Servers are stopped after tests finish:
    tests/manage_test_servers.sh stop

This module provides access to running server configuration.
"""

import os
import shutil
import random

import pytest
from pki_helpers import blitz_test_pki
from settings import (
    CA_CERT,
    CA_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_METRICS_PORT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    PKI_DIR,
    REF_XROOTD_GSI_PORT,
    REF_XROOTD_GSI_SHARED_PORT,
    REF_XROOTD_PORT,
    TEST_ROOT,
    TOKENS_DIR,
    TMP_DIR,
)


def _setup_session():
    """Shared session setup logic used by both pytest_sessionstart and fixture."""
    import subprocess

    # Clear data and pki folders before each test session
    if os.path.exists(DATA_ROOT):
        shutil.rmtree(DATA_ROOT)
    os.makedirs(DATA_ROOT, exist_ok=True)

    if os.path.exists(PKI_DIR):
        shutil.rmtree(PKI_DIR)
    os.makedirs(PKI_DIR, exist_ok=True)

    # Create subdirectories for PKI
    for subdir in ["ca", "server", "user", "voms", "vomsdir"]:
        os.makedirs(os.path.join(PKI_DIR, subdir), exist_ok=True)

    # Create logs and tmp directories
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(TMP_DIR, exist_ok=True)

    # Create data-gsi-bridge directory for cross-server GSI tests (test_gsi_bridge.py)
    gsi_bridge_data = os.path.join(TEST_ROOT, "data-gsi-bridge")
    if os.path.exists(gsi_bridge_data):
        shutil.rmtree(gsi_bridge_data)
    os.makedirs(gsi_bridge_data, exist_ok=True)

    # Create required test files in data directory
    with open(os.path.join(DATA_ROOT, "test.txt"), "wb") as f:
        f.write(b"hello from nginx-xrootd\n")

    # Generate random.bin (5MB of random data)
    with open(os.path.join(DATA_ROOT, "random.bin"), "wb") as f:
        f.write(bytes(random.getrandbits(8) for _ in range(5242880)))

    # Generate large200.bin (200 MiB) — MD5 exposed via env var for tests that need it.
    LARGE_FILE_SIZE = 200 * 1024 * 1024
    LARGE_FILE_PATH = os.path.join(DATA_ROOT, "large200.bin")
    import hashlib as _hashlib
    h = _hashlib.md5()
    seed_val = int(os.environ.get("LARGE_FILE_SEED", "42"))
    rng = random.Random(seed_val)
    if not os.path.exists(LARGE_FILE_PATH):
        with open(LARGE_FILE_PATH, "wb") as f:
            # Write in 16 MiB chunks to limit memory pressure
            chunk_size = 16 * 1024 * 1024
            remaining = LARGE_FILE_SIZE
            while remaining > 0:
                n = min(chunk_size, remaining)
                chunk = bytes(rng.getrandbits(8) for _ in range(n))
                f.write(chunk)
                h.update(chunk)
                remaining -= n
        os.environ["LARGE_FILE_MD5"] = h.hexdigest()
    else:
        # File exists from prior run — recompute MD5 to stay consistent.
        with open(LARGE_FILE_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        os.environ["LARGE_FILE_MD5"] = h.hexdigest()

    os.environ["X509_CERT_DIR"] = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_STD

    if os.environ.get("TEST_SKIP_PKI_REGEN") == "1":
        subprocess.run(
            ["bash", "-c", f"{os.path.dirname(__file__)}/manage_test_servers.sh", "start"],
            check=True,
        )
        return

    try:
        blitz_test_pki()
    except RuntimeError as exc:
        raise pytest.UsageError(
            f"failed to regenerate PKI under {PKI_DIR}: {exc}"
        ) from exc

    subprocess.run(["python3", os.path.join(os.path.dirname(__file__), "..", "utils", "make_proxy.py"), PKI_DIR],
                   check=True, capture_output=True)

    subprocess.run(
        ["bash", "-c", f"{os.path.dirname(__file__)}/manage_test_servers.sh start"],
        check=True,
        capture_output=True,
    )


def pytest_sessionstart(session):
    _setup_session()


def pytest_collection_modifyitems(config, items):
    """Run the CMS threaded fixture after PyXRootD-based tests."""
    cms_items = []
    other_items = []

    for item in items:
        name = os.path.basename(str(item.fspath))
        if name == "test_cms.py":
            cms_items.append(item)
        else:
            other_items.append(item)

    if cms_items:
        items[:] = other_items + cms_items


def pytest_sessionfinish(session, exitstatus):
    """Ensure test servers are stopped when the session ends (even on timeout/crash)."""
    import subprocess

    # Only stop if we didn't skip PKI regen (in that case, caller manages servers)
    if os.environ.get("TEST_SKIP_PKI_REGEN") == "1":
        return

    try:
        subprocess.run(
            ["bash", "-c", f"{os.path.dirname(__file__)}/manage_test_servers.sh stop"],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass  # best-effort cleanup


@pytest.fixture(scope="session")
def _test_session_setup():
    """Session-scoped fixture that ensures servers are running.

    This replaces the old pytest_sessionstart hook for tests that need
    the test_env fixture. The fixture guarantees proper teardown even
    if individual tests fail or timeout.
    """
    _setup_session()
    yield
    # Teardown: stop servers when session ends
    import subprocess

    try:
        subprocess.run(
            ["bash", "-c", f"{os.path.dirname(__file__)}/manage_test_servers.sh stop"],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass


@pytest.fixture(scope="session")
def test_env():
    ports = {
        "anon_port": NGINX_ANON_PORT,
        "gsi_port": NGINX_GSI_PORT,
        "gsi_tls_port": NGINX_GSI_TLS_PORT,
        "token_port": NGINX_TOKEN_PORT,
        "metrics_port": NGINX_METRICS_PORT,
        "webdav_port": NGINX_WEBDAV_PORT,
        "http_webdav_port": NGINX_HTTP_WEBDAV_PORT,
        "s3_port": NGINX_S3_PORT,
    }

    return {
        **ports,
        "anon_url": f"root://127.0.0.1:{ports['anon_port']}",
        "gsi_url": f"root://127.0.0.1:{ports['gsi_port']}",
        "gsi_tls_url": f"roots://127.0.0.1:{ports['gsi_tls_port']}",
        "token_url": f"root://127.0.0.1:{ports['token_port']}",
        "metrics_url": f"http://127.0.0.1:{ports['metrics_port']}/metrics",
        "webdav_url": f"https://127.0.0.1:{ports['webdav_port']}",
        "http_webdav_url": f"http://127.0.0.1:{ports['http_webdav_port']}",
        "s3_url": f"http://127.0.0.1:{ports['s3_port']}",
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
        "url": f"root://localhost:{REF_XROOTD_PORT}",
        "port": REF_XROOTD_PORT,
        "data_dir": test_env["data_dir"],
    }


@pytest.fixture(scope="session")
def ref_xrootd_gsi(test_env):
    return {
        "url": f"root://localhost:{REF_XROOTD_GSI_PORT}",
        "port": REF_XROOTD_GSI_PORT,
        "data_dir": os.path.join(TEST_ROOT, "data-gsi-bridge"),
    }


@pytest.fixture(scope="session")
def ref_xrootd_gsi_shared(test_env):
    return {
        "url": f"root://localhost:{REF_XROOTD_GSI_SHARED_PORT}",
        "port": REF_XROOTD_GSI_SHARED_PORT,
        "data_dir": test_env["data_dir"],
    }
