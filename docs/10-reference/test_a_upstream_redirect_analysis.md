# Analysis: `test_a_upstream_redirect.py` Architecture & Limitations

> **Status: CLOSED — the refactoring described below was carried out.**
> `tests/test_a_upstream_redirect.py` now connects only to pre-started fleet
> instances; it creates no server objects of its own. `MockUpstreamServer` and
> `tests/mock_upstream.py` no longer exist, and the fleet manager is the
> pure-Python `tests/cmdscripts/manage_test_servers.py` (the `.sh` runner named
> throughout the original text was retired by the bash-fleet dissolution). This
> page is kept as the record of *why* the suite was reshaped; see
> "Resolution" at the end for what it looks like today.

## Overview
`test_a_upstream_redirect.py` validates the XRootD redirector and upstream proxy functionality in `nginx-xrootd`. It probes how nginx handles redirection responses (e.g., `kXR_wait`, `kXR_waitresp`, `kXR_redirect`) from upstream servers.

<!-- doc-paths:off -->

## Original architecture (superseded)
The test suite used a hybrid server strategy:
1.  **Shared nginx instance:** Started once via `manage_test_servers.sh` (listening on a set of fixed ports).
2.  **Dynamic Mock Servers:** Python `MockUpstreamServer` instances (defined in `tests/mock_upstream.py`) are spawned inside individual test fixtures.

### Why dynamic mocks?
The suite was designed before the dedicated server infrastructure (`manage_test_servers.sh` + fixed port allocation) was mature. The dynamic approach allowed developers to quickly inject state-specific behaviors (like `wait_then_redirect`) into the upstream server without modifying the global config.

### Why it was failing
1.  **Port Contention (Race Conditions):** The fixture used `subprocess.run(["fuser", "-k", ...])` to clear ports before binding. In a parallelized test environment (like `pytest`), multiple tests or cleanup processes may conflict for the same ports, leading to `OSError: [Errno 98] Address already in use`.
2.  **Cleanup Fragility:** If a test process crashes or is interrupted, the dynamic mock servers may remain running (or in a `TIME_WAIT` state), preventing subsequent test runs from binding to the required port.
3.  **Environment Instability:** The mix of managed (fixed port) and unmanaged (dynamic port) servers makes the environment hard to debug.

## Required refactoring path (as prescribed)
1.  **Migrate to Dedicated Servers:** Update the mock-dependent tests to utilize the newly defined dedicated upstream backends (e.g., `upstream-wait`, `upstream-waitresp`, `upstream-error`) managed by `manage_test_servers.sh`.
2.  **Remove In-Process Mocks:** Delete the `MockUpstreamServer` reliance in the test fixtures.
3.  **Use Static Ports:** Reference the ports defined in `settings.py` (e.g., `UPSTREAM_WAIT_BACKEND_PORT`) rather than assuming local control over port binding.

<!-- doc-paths:on -->

## Resolution

All three steps landed.

- **Dedicated servers.** The backends are fleet specs in
  `tests/brix_suite/catalogue/backends.py` (`upstream-wait-be`,
  `upstream-waitresp-be`) and `tests/brix_suite/catalogue/dedicated.py`
  (`upstream-waitresp`, `stub-upstream-wait`, `stub-upstream-waitresp`, …),
  launched by `tests/cmdscripts/manage_test_servers.py`. The protocol stubs
  themselves live in `tests/upstream_protocol_stubs.py`.
- **No in-process mocks.** No test file references `MockUpstreamServer`, and
  `tests/mock_upstream.py` is gone. Nothing in the module calls `fuser`.
- **Static ports.** Every port comes from `tests/settings.py`
  (`UPSTREAM_WAIT_BACKEND_PORT`, `UPSTREAM_WAITRESP_NGINX_PORT`, …), which are
  themselves lane-relative offsets from `TEST_PORT_START` — see
  `tests/port_ladder.py`.

The module's own docstring now carries the resulting nginx→backend map, so the
topology each test exercises is readable without running it.
