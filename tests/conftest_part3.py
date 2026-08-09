"""Shared fixtures for nginx-xrootd test suite.

LOCAL mode (default — TEST_SERVER_HOST not set):
    conftest.py regenerates PKI, seeds test data, and starts/stops servers
    automatically.  All connections go to 127.0.0.1.

REMOTE mode (TEST_SERVER_HOST=<host>):
    conftest.py skips all local server lifecycle.  The server must already
    be running (e.g. a kubernetes pod).  Connections go to TEST_SERVER_HOST.
    Tests marked @pytest.mark.requires_local_server are skipped because they
    write directly to the server's data directory.
"""

import os
import shutil
import random
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import fleet_declares
from server_launcher import LifecycleHarness, RegistryLauncher
from server_registry import fleet_ready_for_test_root, manifest_owns_test_root
from server_registry import (
    dependency_closure,
    get_server,
    read_manifest,
    registered_specs,
)
from settings import (
    CA_CERT,
    CA_DIR,
    HOST,
    BIND_HOST6,
    CWD_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_METRICS_PORT,
    NGINX_JWKS_REFRESH_PORT,
    NGINX_KRB5_PORT,
    NGINX_TOKEN_PORT,
    KRB5_CCACHE,
    NGINX_WEBDAV_PORT,
    NGINX_WEBDAV_GSI_TLS_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    PKI_DIR,
    READONLY_PORT,
    REF_BRIX_GSI_PORT,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    FLEET_READY,
    REGISTRY_MANIFEST,
    REGISTRY_ROOT,
    REMOTE_SERVER,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
    TMP_DIR,
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

# Repo cwd captured at import (pytest's rootdir).  The session chdir()s into
# CWD_DIR for the run and restores this at teardown before wiping the tree.
# getcwd() raises FileNotFoundError if the process's cwd was removed out from
# under it (e.g. an xdist worker whose scratch cwd a concurrent session wiped,
# or a re-import of this module from a transient cwd).  Fall back to the repo
# root (this file lives in <repo>/tests/) so import never fails — a robust
# restore target regardless.  Without this, a racy getcwd() aborts collection on
# some xdist workers, tripping pytest's "different tests collected" guard.
try:
    _ORIG_CWD = os.getcwd()
except OSError:
    _ORIG_CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Guards the destructive full-tree wipe so it runs at most once per process
# (defensive — _setup_session is normally called only from pytest_sessionstart).
_test_tree_wiped = False
_pytest_config = None


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
    global _pytest_config
    _pytest_config = config
    os.makedirs(TMP_DIR, exist_ok=True)
    os.environ["TMPDIR"] = TMP_DIR
    tempfile.tempdir = TMP_DIR

    config.addinivalue_line(
        "markers",
        "requires_local_server: test writes directly to the server filesystem "
        "and cannot run against a remote server (skipped when TEST_SERVER_HOST is set)",
    )
    config.addinivalue_line(
        "markers",
        "leak: multi-user cross-user leak — encodes the correct cache-transparency "
        "invariant and fails red until the underlying code is fixed (see "
        "docs/superpowers/specs/2026-07-06-multiuser-permission-conformance-design.md)",
    )
    config.addinivalue_line(
        "markers",
        "privileged: requires root (real accounts + setfsuid impersonation)",
    )
    config.addinivalue_line(
        "markers",
        "uses_lifecycle_harness: test exercises registry-controlled server lifecycle",
    )
    config.addinivalue_line(
        "markers",
        "registry_server(name): test requires the named server registry spec",
    )
    config.addinivalue_line(
        "markers",
        "registry_servers(*names): test requires the named server registry specs",
    )
    config.addinivalue_line(
        "markers",
        "matrix(protocols, auths, tls, backends): expand this test over the "
        "coverage matrix — see tests/matrix_layer.py and pytest_generate_tests",
    )


# Load the multi-user permission conformance fixtures (mu_fleet, cast, apply_policy, ...).
pytest_plugins = ["conftest_mu"]


# Module-name substrings that identify the multi-minute "slow" families: the
# destructive/resilience suites, multi-node meshes, differential client suites,
# conformance/interop batches, and throughput/perf runs.  Tests in these modules
# are auto-marked `slow` so a fast iteration check can deselect them with
# `-m "not slow"` (see `cmdscripts.operator_runtime suite --fast`).  Over-inclusion
# is safe: the full suite run covers everything regardless of this marker.
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


# --- server-declaration gate -------------------------------------------------
# Every collected test that *uses* a dedicated fleet server (statically: it
# references that server's settings.py port constant) must *declare* it with a
# @pytest.mark.registry_server("name") marker.  The always-on backbone (core
# specs — the main nginx and the reference xrootd variants) is free: it boots
# every session and is reached through session fixtures, so no test declares it.
#
# Hard-fails collection: the tree is fully declared, so any collected test that
# references a fleet server's port constant without declaring it (or inheriting
# it from the always-on backbone) aborts the run.  Because the tree is fully
# declared, the fleet also boots only the *declared union* — the dependency
# closure of the collected seed — never the whole registry (see _specs_to_boot).
_declare_usage_cache: dict = {}
_conftest_fixture_map_cache = None


def _conftest_fixture_spec_map() -> dict:
    """Fixture-name → specs-it-reaches for this conftest's session fixtures.

    Backbone KEPT (unlike the gate's notion of "free"): a test reaches a core
    server only through a session fixture it requests, and — with the forced
    always-on backbone retired (zero-boot default) — this map is how the boot
    set learns to start it.  Cached: the conftest source is parsed once."""
    global _conftest_fixture_map_cache
    if _conftest_fixture_map_cache is None:
        try:
            with open(os.path.abspath(__file__), encoding="utf-8", errors="ignore") as fh:
                conftest_src = fh.read()
        except OSError:
            conftest_src = ""
        _conftest_fixture_map_cache = fleet_declares.conftest_fixture_spec_map(conftest_src)
    return _conftest_fixture_map_cache


def _conftest_fixture_specs_for(items) -> set:
    """Specs the collected items reach through conftest session fixtures.

    For each item, intersect its resolved fixture closure
    (``item._fixtureinfo.names_closure`` — every fixture pytest will set up for
    it, transitively) with the conftest fixture→spec map, and union the results.
    A test that requests no server-touching conftest fixture contributes
    nothing — the mechanism behind zero-boot for no-server tests."""
    fmap = _conftest_fixture_spec_map()
    if not fmap:
        return set()
    specs: set = set()
    for item in items:
        info = getattr(item, "_fixtureinfo", None)
        closure = getattr(info, "names_closure", ()) if info is not None else ()
        for fixture_name in closure:
            hit = fmap.get(fixture_name)
            if hit:
                specs |= hit
    return specs


def _required_specs_for(items) -> set:
    """Specs the collected items reach by *naming a port constant* — statically
    attributed (backbone and dedicated alike) by ``fleet_declares.analyze_source``.

    This covers a test (or a fixture defined in the test's own module) that
    references a server's ``settings`` port directly, without going through a
    conftest fixture.  Unioned with declared markers, autouse specs, and the
    conftest-fixture closure to form the boot seed."""
    specs: set = set()
    for item in items:
        usage = _module_test_usage(item.fspath).get(_item_qualname(item))
        if usage is not None:
            specs |= usage.required
        specs |= _item_declared_specs(item)
    return specs


def _specs_to_boot(items):
    """The spec set the session fleet should launch.

    Zero-boot: boot exactly the dependency closure of the *seed* — the union,
    over collected items, of the servers each one reaches by a declared
    ``registry_server`` marker, a named port constant, an autouse fixture, or a
    conftest session fixture in its fixture closure.  An empty seed boots
    *nothing* (a no-server run starts zero servers); a single-file run starts
    only that file's closure.  (xdist runs boot the whole registry up front from
    pytest_sessionstart instead, because their controller never collects.)"""
    seed = (
        _required_specs_for(items)
        | _autouse_specs_for(items)
        | _conftest_fixture_specs_for(items)
    )
    if not seed:
        return []
    closure = dependency_closure(seed)
    return [spec for spec in registered_specs() if spec.name in closure]


def _autouse_specs_for(items) -> set:
    """Dedicated specs required by autouse fixtures in the collected modules.

    Autouse fixtures bind every test in their module to a server without any
    test naming it as a parameter, so per-test declarations can't cover them
    (see REGISTRY_MIGRATION.md § blind spot); the boot set must union them in
    per collected module."""
    specs: set = set()
    for path in {str(item.fspath) for item in items}:
        cached = _declare_usage_cache.get(("autouse", path))
        if cached is None:
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
            except OSError:
                source = ""
            cached = set(fleet_declares.module_autouse_specs(source))
            _declare_usage_cache[("autouse", path)] = cached
        specs |= cached
    return specs


def _module_test_usage(fspath):
    """Cached qualname→TestUsage attribution for one test module (parsed once).

    Keyed by ``Class::method`` (bare name for module-level tests) so same-named
    methods in different classes — e.g. the three cache-tier classes in
    test_cache_write_through.py, each hitting a different dedicated spec — never
    collide."""
    key = str(fspath)
    cached = _declare_usage_cache.get(key)
    if cached is None:
        try:
            with open(key, encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError:
            source = ""
        cached = _declare_usage_cache[key] = {
            usage.qualname: usage for usage in fleet_declares.analyze_source(source)
        }
    return cached


def _item_qualname(item) -> str:
    """``Class::method`` for a class-based test item, else the bare function name.
    Matches ``TestUsage.qualname`` so the gate looks up the right attribution."""
    func = getattr(item, "originalname", None) or getattr(item, "name", "")
    func = func.split("[", 1)[0]
    cls = getattr(item, "cls", None)
    return f"{cls.__name__}::{func}" if cls is not None else func


def _item_declared_specs(item) -> set:
    declared: set = set()
    for marker_name in ("registry_server", "registry_servers"):
        for marker in item.iter_markers(marker_name):
            declared.update(str(arg) for arg in marker.args)
    return declared


def _declaration_violations(items):
    """List of (base_nodeid, lineno, sorted_missing_specs) for tests that use a
    fleet server they neither declare nor inherit from the backbone."""
    backbone = fleet_declares.backbone_specs()
    seen: set = set()
    out = []
    for item in items:
        usage = _module_test_usage(item.fspath).get(_item_qualname(item))
        if usage is None or not usage.required:
            continue
        allowed = backbone | dependency_closure(_item_declared_specs(item))
        missing = usage.required - allowed
        if not missing:
            continue
        base = item.nodeid.split("[", 1)[0]
        key = (base, tuple(sorted(missing)))
        if key in seen:
            continue
        seen.add(key)
        out.append((base, usage.lineno, sorted(missing)))
    return out


def _enforce_server_declarations(config, items):
    violations = _declaration_violations(items)
    if not violations:
        return
    lines = [
        f"  {base} (line {lineno}) uses undeclared server(s): "
        f"{', '.join(missing)}"
        for base, lineno, missing in sorted(violations)
    ]
    report = (
        f"server-declaration gate: {len(lines)} test(s) reference a fleet server "
        "they do not declare — add @pytest.mark.registry_server(<name>) for each:\n"
        + "\n".join(lines)
    )
    raise pytest.UsageError(report)


def pytest_collection_modifyitems(config, items):
    """Skip requires_local_server tests in remote mode; order CMS tests last;
    auto-mark the slow families so `-m "not slow"` yields a fast iteration set."""
    cms_items = []
    other_items = []

    for item in items:
        name = os.path.basename(str(item.fspath))

        # Auto-tag slow families (idempotent — a hand-placed @slow still counts).
        # The <5min PR gate runs `-m "not slow"`; --nightly runs the slow set.
        if _is_slow_module(name):
            item.add_marker(pytest.mark.slow)

        # The multi-user impersonation suite (test_mu_*) is privileged AND binds a
        # fixed-port paired fleet, so it can run neither unprivileged nor in
        # parallel: its mu_fleet/cast fixtures pytest.skip() without root, and
        # under xdist every worker would collide on the same MU ports (bind:
        # address already in use -> the fleet nginx exits 1 -> ~180 setup errors).
        # It is meant to run only via its dedicated serial harness
        # (tests/run_multiuser_authz.sh, under sudo, which selects test_mu_*.py by
        # name and does NOT filter on `serial`). Auto-mark it `serial` so the
        # parallel fast lane (`-m "not slow and not serial"`) excludes it cleanly;
        # the dedicated runner is unaffected. Same for any privileged/leak test.
        if (name.startswith("test_mu_")
                or item.get_closest_marker("privileged")
                or item.get_closest_marker("leak")):
            item.add_marker(pytest.mark.serial)

        if item.get_closest_marker("requires_local_server") and REMOTE_SERVER:
            item.add_marker(
                pytest.mark.skip(
                    reason=f"requires_local_server: test writes to server filesystem "
                    f"(remote: {SERVER_HOST})"
                )
            )

        # Honor the `serial` marker under pytest-xdist: assign every serial test
        # to one xdist group so they land on a single worker and never run
        # concurrently with each other.  Effective only with `--dist loadgroup`
        # (the project's canonical parallel invocation); a harmless no-op under the
        # default `--dist load` or serial runs.  Stateful suites (e.g. the chaos
        # meshes) mark themselves `serial` precisely because parallel co-execution
        # corrupts their shared mesh/port state.
        if item.get_closest_marker("serial"):
            item.add_marker(pytest.mark.xdist_group("serial"))

        # Pin each differential-interop module to ONE xdist worker.  Its
        # module-scoped start_pair() fixture binds FIXED ladder ports
        # (official_interop_lib.worker_port, now in the contiguous port range),
        # so two workers running the same module would bind the same port and
        # cross-talk into each other's data tree.  Group by module name (distinct
        # modules still distribute across workers) unless already grouped.  Detect
        # interop modules by the `L = official_interop_lib` alias every such file
        # (or its reexported helper) carries.
        if not any(m.name == "xdist_group" for m in item.iter_markers()):
            try:
                mod = item.module
            except Exception:
                mod = None
            if getattr(getattr(mod, "L", None), "__name__", "") == "official_interop_lib":
                item.add_marker(pytest.mark.xdist_group(mod.__name__))

        if name == "test_cms.py":
            cms_items.append(item)
        else:
            other_items.append(item)

    if cms_items:
        items[:] = other_items + cms_items
    _register_fleet()
    _enforce_server_declarations(config, items)
    percent = config.getoption("--first-percent")
    if percent is not None:
        if not 0 < percent <= 100:
            raise pytest.UsageError("--first-percent must be greater than 0 and at most 100")
        import math
        keep = max(1, math.ceil(len(items) * percent / 100.0))
        deselected = items[keep:]
        items[:] = items[:keep]
        if deselected:
            config.hook.pytest_deselected(items=deselected)


