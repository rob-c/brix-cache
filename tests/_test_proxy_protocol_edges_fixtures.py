# _test_proxy_protocol_edges_fixtures.py - continuation shard of
# _test_proxy_protocol_edges_helpers.py: the nginx proxy-front provisioning and
# the per-scenario fixtures that pair one stub backend with one front.
#
# split_continuation.load() execs this file into that module's namespace, so the
# wire constants, the per-scenario port constants and the client-side helpers are
# already bound here.  It is NOT importable on its own and nothing imports it:
# re-running the parent's module body would re-run its free_ports() allocation
# and hand out a second, different set of ports.

import os
import socket
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_launcher import LifecycleHarness, RegistryCommandFailure
from server_registry import NginxInstanceSpec

# ===========================================================================
# nginx proxy-front provisioning
# ===========================================================================

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((HOST, port), timeout=timeout).close()
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


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(scope="module", autouse=True)
def _require_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _stack(name, front_port, scenarios, upstream_port, extra="", _retry=True):
    """Spin a stub (one or more ports) + a registry-owned nginx proxy front,
    wait for ready, and return (stub, harness, front_port).  Caller tears down
    via the fixture that wraps this: ``harness.close()`` then ``stub.stop()``.

    The stub backends are in-process Python listeners (bound directly on their
    dedicated ports); only the nginx front is launched — through the phase-81
    LifecycleHarness, which renders nginx_proxy_protocol_edges.conf, runs
    ``nginx -t``, launches, and waits TCP-ready on the front port before start()
    returns.  A rejected config surfaces as an error (a broken committed
    template must not pass silently); a front that never binds is skipped."""
    stub = _StubServer(scenarios)
    try:
        stub.start()
    except OSError as exc:
        # A dedicated high port was genuinely unavailable (e.g. a wedged stub
        # from a crashed prior run still holds it) — skip cleanly, never error.
        stub.stop()
        pytest.skip(f"stub backend could not bind a dedicated port: {exc}")
    # Wait for the primary upstream port (the one the front points at) before
    # the front comes up, exactly as before — the proxy connects on demand.
    if not _wait_port(upstream_port):
        stub.stop()
        pytest.skip(f"stub backend did not bind on {upstream_port}")
    harness = LifecycleHarness()
    # The pre-existing free_ports()/env-override front port is honoured verbatim
    # (spec.port pins it); the harness only appends a per-pid name suffix for
    # xdist/registry uniqueness.  ``extra`` renders as an extra server-block line.
    extra_line = f"        {extra}\n" if extra else ""
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_proxy_protocol_edges.conf",
            port=front_port,
            protocol="root",
            readiness="tcp",
            template_values={
                "BIND_HOST": BIND_HOST,
                "HOST": HOST,
                "UPSTREAM_PORT": upstream_port,
                "EXTRA": extra_line,
            },
        ))
    except RegistryCommandFailure as exc:
        harness.close()
        stub.stop()
        if _retry and "Address already in use" in exc.stderr_tail:
            # free_ports() is intentionally advisory; a concurrent fleet or a
            # stale throwaway instance can claim the selected port before nginx
            # binds it.  Retry once with a fresh front port, while preserving
            # real configuration failures as test errors.
            return _stack(name, free_ports(1)[0], scenarios, upstream_port,
                          extra, _retry=False)
        raise
    except Exception as exc:
        harness.close()
        stub.stop()
        pytest.skip(f"proxy front {name} did not come up on {front_port}: {exc}")
    return stub, harness, endpoint.port


@pytest.fixture
def saturation_stack():
    stub, harness, port = _stack("ppe_sat", SAT_FRONT_PORT,
                        [(SAT_BACKEND_PORT, _h_saturation)], SAT_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def reuse_stack():
    stub, harness, port = _stack("ppe_reuse", REUSE_FRONT_PORT,
                        [(REUSE_BACKEND_PORT, _h_reuse)], REUSE_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def wait_exhaust_stack():
    stub, harness, port = _stack("ppe_waitx", WAITX_FRONT_PORT,
                        [(WAITX_BACKEND_PORT, _h_wait_exhaust)], WAITX_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def wait_bigpayload_stack():
    stub, harness, port = _stack("ppe_waitbig", WAITBIG_FRONT_PORT,
                        [(WAITBIG_BACKEND_PORT, _h_wait_bigpayload)],
                        WAITBIG_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def hop_stack():
    stub, harness, port = _stack("ppe_hop", HOP_FRONT_PORT,
                        [(HOP_BACKEND_PORT, _make_hop_chain())], HOP_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def redirect_stack():
    stub, harness, port = _stack(
        "ppe_redir", REDIR_FRONT_PORT,
        [(REDIR_BACKEND_PORT, _h_redirect_then_open),
         (REDIR_TARGET_PORT, _h_redirect_target)],
        REDIR_BACKEND_PORT)
    # The redirect-target port must also be bound before we drive the test.
    if not _wait_port(REDIR_TARGET_PORT):
        harness.close()
        stub.stop()
        pytest.skip("redirect-target stub did not bind")
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def oksofar_stack():
    stub, harness, port = _stack("ppe_oks", OKS_FRONT_PORT,
                        [(OKS_BACKEND_PORT, _h_oksofar_dirlist)], OKS_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def oksofar_wait_stack():
    stub, harness, port = _stack("ppe_oksw", OKSW_FRONT_PORT,
                        [(OKSW_BACKEND_PORT, _h_oksofar_wait)], OKSW_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def chmod_stack():
    stub, harness, port = _stack("ppe_chmod", CHMOD_FRONT_PORT,
                        [(CHMOD_BACKEND_PORT, _h_chmod)], CHMOD_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def endsess_stack():
    stub, harness, port = _stack("ppe_endsess", ENDSESS_FRONT_PORT,
                        [(ENDSESS_BACKEND_PORT, _h_endsess)], ENDSESS_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


@pytest.fixture
def path_rewrite_stack():
    # Dedicated ports so this does not collide with oksofar_stack (which reuses
    # the same listen ports and would otherwise EADDRINUSE back-to-back).
    stub, harness, port = _stack("ppe_prw", PRW_FRONT_PORT,
                        [(PRW_BACKEND_PORT, _h_oksofar_dirlist)], PRW_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


# ===========================================================================
# Scenarios
# ===========================================================================
