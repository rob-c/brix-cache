"""Collection policy and shared local/remote suite fixtures."""

import os
import re
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
from brix_suite.harness.xdist_groups import materialize_xdist_group
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

# Preserve a stable cwd even if another worker removes this process's scratch.
try:
    _ORIG_CWD = os.getcwd()
except OSError:
    _ORIG_CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Guard the destructive tree wipe once per process.
_test_tree_wiped = False
_pytest_config = None


def _force_loadgroup(config):
    """Turn plain `--dist load` into loadgroup so xdist_group fixed-port pins hold.

    Fixed-port LifecycleHarness suites pin their tests to one xdist worker via
    xdist_group; plain `load` round-robins and IGNORES those groups, so several
    workers set up the same module-scoped fixture and bind the same fixed port
    at once — thousands of bind() "Address already in use" errors (fast_suite7).
    loadgroup is a strict superset (honours groups AND load-balances the rest).

    TWO options must flip, not just `dist`: the controller picks its scheduler
    from `config.option.dist`, but each WORKER only appends the group suffix when
    `config.getvalue("loadgroup")` is true (xdist/remote.py:184). xdist derives
    that bool from `dist` at worker-init (remote.py:317) — BEFORE any conftest
    runs — so a worker spawned with `--dist load` has loadgroup=False and drops
    every group, even though the controller then reports LoadGroupScheduling
    (verified: this exact mismatch gave a flaky 20-44 pass / 22-46 error on
    test_tls_sendfile_matrix under `-n`). Setting BOTH here — in pytest_configure,
    which runs on the controller and on every worker before collection — makes the
    collection-time group check see loadgroup=True. Backstops pytest.ini's
    `addopts=--dist=loadgroup`, which a command-line `--dist load` overrides."""
    opt = getattr(config, "option", None)
    if opt is None or getattr(opt, "dist", None) != "load":
        return
    opt.dist = "loadgroup"
    opt.loadgroup = True
    if not hasattr(config, "workerinput"):   # controller only
        sys.stderr.write(
            "\n[conftest] forcing --dist loadgroup (was 'load'): plain 'load' "
            "scheduling defeats the xdist_group fixed-port pins and causes "
            "mass bind() 'Address already in use' cascades.\n")


def pytest_configure(config):
    """Register markers and confine process scratch beneath ``TEST_ROOT``."""
    global _pytest_config
    _pytest_config = config
    _force_loadgroup(config)   # never let plain --dist load defeat the port pins

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


pytest_plugins = ["conftest_mu"]

_SLOW_MODULE_HINTS = (
    "resilien", "chaos", "evil_actor", "evil_paths", "netfault", "net_resilience",
    "topolog", "conformance", "official", "clientconf", "hybrid", "throughput",
    "performance", "stress", "redteam", "gfal", "busybox", "xrootdfs",
    "fuse", "concurrent", "proxy_large", "large_read", "_mesh", "cms_mesh",
    "ceph", "conf_xrdcl", "userns",
    "cmd_credential_wt_ztn", "cmd_metadata_live_ports", "cmd_tpc_fwd_live",
    "krb5_forward",
    "interop", "_load", "_e2e",
    "build_matrix",
    # live command matrices + destructive crash labs: single tests run 60-130s
    # (real xrootd/webdav forwarding round-trips; orphan+fsck-gc crash recovery),
    # far past the fast tier's <15s budget — the full/nightly run still covers them.
    "matrix_live", "lab_crash",
)

def _is_slow_module(name):
    """True if a test module's basename marks it a slow-family test."""
    stem = name[:-3] if name.endswith(".py") else name
    return any(h in stem for h in _SLOW_MODULE_HINTS)


_declare_usage_cache: dict = {}
_conftest_fixture_map_cache = None

_DECLARE_CACHE_KEY = "fleet_declares/analysis"
_DECLARE_CACHE_VERSION = 1
_declare_disk_cache: dict | None = None
_declare_disk_dirty = False


def _declare_disk_files() -> dict:
    """Load the stamped per-file declaration cache once."""
    global _declare_disk_cache
    if _declare_disk_cache is None:
        cache = getattr(_pytest_config, "cache", None)
        raw = cache.get(_DECLARE_CACHE_KEY, None) if cache is not None else None
        if not _valid_declare_cache(raw):
            raw = {"v": _DECLARE_CACHE_VERSION, "files": {}}
        _declare_disk_cache = raw
    return _declare_disk_cache["files"]


def _valid_declare_cache(raw):
    if not isinstance(raw, dict):
        return False
    return raw.get("v") == _DECLARE_CACHE_VERSION and isinstance(
        raw.get("files"), dict
    )


def _declare_disk_entry(path: str):
    """(entry, current_stamp) — entry is the still-fresh cache row or None."""
    try:
        st = os.stat(path)
        stamp = [st.st_mtime_ns, st.st_size]
    except OSError:
        return None, None
    entry = _declare_disk_files().get(path)
    if entry is not None and entry.get("stamp") == stamp:
        return entry, stamp
    return None, stamp


def _declare_disk_store(path: str, stamp, field_name: str, value) -> None:
    global _declare_disk_dirty
    if stamp is None:
        return
    files = _declare_disk_files()
    entry = files.get(path)
    if entry is None or entry.get("stamp") != stamp:
        entry = files[path] = {"stamp": stamp}
    entry[field_name] = value
    _declare_disk_dirty = True


def _flush_declare_cache() -> None:
    """Write dirty analysis through config.cache, from gw0 under xdist."""
    global _declare_disk_dirty
    if not _declaration_cache_ready():
        return
    workerinput = getattr(_pytest_config, "workerinput", None)
    if workerinput is not None and workerinput.get("workerid") != "gw0":
        return
    cache = getattr(_pytest_config, "cache", None)
    if cache is None:
        return
    cache.set(_DECLARE_CACHE_KEY, _declare_disk_cache)
    _declare_disk_dirty = False


def _declaration_cache_ready():
    return (
        _declare_disk_dirty
        and _declare_disk_cache is not None
        and _pytest_config is not None
    )


def _usage_to_row(usage) -> list:
    return [usage.name, usage.lineno, usage.col, sorted(usage.required),
            sorted(usage.declared), usage.is_lifecycle, usage.qualname]


def _usage_from_row(row) -> "fleet_declares.TestUsage":
    return fleet_declares.TestUsage(
        name=row[0], lineno=row[1], col=row[2], required=set(row[3]),
        declared=set(row[4]), is_lifecycle=row[5], qualname=row[6])


def _read_module_source(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _conftest_fixture_spec_map() -> dict:
    """Map conftest fixtures to every fleet spec they reach."""
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
    """Return specs reached through the collected fixtures' closure."""
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
    """Return specs named directly by collected tests and their markers."""
    specs: set = set()
    for item in items:
        usage = _module_test_usage(item.fspath).get(_item_qualname(item))
        if usage is not None:
            specs |= usage.required
        specs |= _item_declared_specs(item)
    return specs


def _specs_to_boot(items):
    """Return the registered fixed-port fleet after collection."""
    del items
    _register_fleet()
    return registered_specs()


def _autouse_specs_for(items) -> set:
    """Return specs reached by collected modules' autouse fixtures."""
    specs: set = set()
    for path in {str(item.fspath) for item in items}:
        cached = _declare_usage_cache.get(("autouse", path))
        if cached is None:
            entry, stamp = _declare_disk_entry(path)
            if entry is not None and "autouse" in entry:
                cached = set(entry["autouse"])
            else:
                cached = set(fleet_declares.module_autouse_specs(
                    _read_module_source(path)))
                _declare_disk_store(path, stamp, "autouse", sorted(cached))
            _declare_usage_cache[("autouse", path)] = cached
        specs |= cached
    _flush_declare_cache()
    return specs


def _fresh_usage(key, entry, stamp):
    if entry is not None and "usage" in entry:
        return {row[6]: _usage_from_row(row) for row in entry["usage"]}
    usage = {
        item.qualname: item
        for item in fleet_declares.analyze_source(_read_module_source(key))
    }
    rows = [_usage_to_row(item) for item in usage.values()]
    _declare_disk_store(key, stamp, "usage", rows)
    return usage


def _module_test_usage(fspath):
    """Return cached qualified-name usage attribution for one module."""
    key = str(fspath)
    cached = _declare_usage_cache.get(key)
    if cached is None:
        entry, stamp = _declare_disk_entry(key)
        cached = _fresh_usage(key, entry, stamp)
        _declare_usage_cache[key] = cached
    return cached


def _item_qualname(item) -> str:
    """Return the item's ``TestUsage`` qualified name."""
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
    """Return tests using fleet specs they neither declare nor inherit."""
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


def _add_xdist_group(item, group, suffix=False, prepend=False):
    # append=False puts the marker FIRST, so get_closest_marker() returns it —
    # the only way to override a stale group a module hard-coded for itself.
    item.add_marker(pytest.mark.xdist_group(group), append=not prepend)
    marker = f"@{group}"
    if suffix and not item.nodeid.endswith(marker):
        item._nodeid = f"{item.nodeid}{marker}"


def _force_xdist_group(item, group):
    """Put `item` in `group` for the loadgroup SCHEDULER, not just the marker.

    --dist loadgroup schedules on the ``@group`` suffix xdist appends to the
    nodeid, and xdist computes that during ITS collection hook.  A marker this
    conftest adds afterwards is therefore invisible to the scheduler: the group
    silently does nothing.  Rewrite the suffix ourselves, replacing whatever
    xdist already appended from a module's own (stale) mark.
    """
    item.add_marker(pytest.mark.xdist_group(group), append=False)
    item._brix_xdist_group_override = group
    base = item.nodeid.split("@", 1)[0]
    item._nodeid = f"{base}@{group}"


def _mark_path_groups(item, name):
    path = str(item.fspath)
    if "/resilience/" in path:
        _add_xdist_group(item, "resilience-dedicated")
    if name.startswith("test_cvmfs_"):
        _add_xdist_group(item, "cvmfs-fixed-ports", suffix=True)
    if name.startswith("test_ci_guards"):
        _add_xdist_group(item, "ci-guards", suffix=True)


def _needs_serial(item, name):
    return (
        name.startswith("test_mu_")
        or item.get_closest_marker("privileged")
        or item.get_closest_marker("leak")
    )


def _mark_remote_skip(item):
    if not REMOTE_SERVER or not item.get_closest_marker("requires_local_server"):
        return
    reason = (
        "requires_local_server: test writes to server filesystem "
        f"(remote: {SERVER_HOST})"
    )
    item.add_marker(pytest.mark.skip(reason=reason))


def _has_xdist_group(item):
    return any(marker.name == "xdist_group" for marker in item.iter_markers())


def _interop_module(item):
    try:
        module = item.module
    except Exception:
        return None
    library = getattr(module, "L", None)
    if getattr(library, "__name__", "") == "official_interop_lib":
        return module
    return None


_INTEROP_PORT_CALL = re.compile(r"worker_port\(\s*(\d+)\s*\)")
_INTEROP_REEXPORT = re.compile(r"(?:reexport|load)\(\s*globals\(\)\s*,[^)]*?"
                               r"[\"']([A-Za-z0-9_.]+)[\"']")


def _interop_bases_in(path, seen=None):
    """Every worker_port() base a test module binds, following its split helpers.

    A split module reexports its helper by exec'ing it into its own namespace,
    so the helper's ports are the MODULE's ports; a few modules also allocate
    another family's base directly.  Both must count.
    """
    seen = seen if seen is not None else set()
    if not _interop_scan_wanted(path, seen):
        return set()
    seen.add(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    bases = {int(b) for b in _INTEROP_PORT_CALL.findall(text)}
    for name in _INTEROP_REEXPORT.findall(text):
        bases |= _interop_bases_in(_interop_helper_path(path, name), seen)
    return bases


def _interop_scan_wanted(path, seen):
    """True when `path` is a file worth scanning and not already visited."""
    return path not in seen and path.exists()


def _interop_helper_path(path, name):
    """Sibling module path for a reexport/load target ('x' or 'x.py')."""
    stem = name[:-3] if name.endswith(".py") else name
    return path.with_name(stem + ".py")


def _interop_port_groups():
    """module stem -> xdist group name, keyed on the PORTS the module binds.

    ``worker_port()`` hands out ONE fixed ladder port per interop base and its
    contract is that "the owning module runs on ONE xdist worker".  Grouping by
    module NAME broke that contract wherever a base is shared: the split-file
    siblings (X, X_b, X_c) reexport one helper and so bind the SAME ports, and
    test_deep_tree_special_files allocates two other families' bases outright —
    48 of the 65 bases have more than one owner.  Two owners scheduled onto
    different workers both bind the port, the loser dies with

        nginx: [emerg] bind() to 127.0.0.1:PORT failed (98: Address already in use)

    the pair launch raises, and the whole module SKIPS.  That silently cost ~526
    conf-interop tests per fast run.  Grouping by shared ports instead puts every
    co-owner of a port on one worker (transitively, since a module can bridge two
    families) and leaves everything else parallel.
    """
    cached = getattr(_interop_port_groups, "_cache", None)
    if cached is not None:
        return cached
    tests_dir = Path(__file__).resolve().parent
    owners = {}
    for path in sorted(tests_dir.glob("test_*.py")):
        for base in _interop_bases_in(path):
            owners.setdefault(base, []).append(path.stem)
    groups = _merge_port_owners(owners)
    _interop_port_groups._cache = groups
    return groups


def _merge_port_owners(owners):
    """Union the co-owners of every port into one group per connected component.

    Transitive on purpose: if A and B share port 1 and B and C share port 2, all
    three must land on the same worker.
    """
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for names in owners.values():
        for name in names[1:]:
            union(names[0], name)
    return {name: f"interop-{find(name)}" for name in parent}


def _mark_interop_group(item):
    module = _interop_module(item)
    if module is None:
        return
    stem = module.__name__.rsplit(".", 1)[-1]
    computed = _interop_port_groups().get(stem)
    if computed is None:
        # Imports the interop library but binds no FIXED ladder port, so it has
        # nothing to collide over — respect whatever group it chose for itself.
        if not _has_xdist_group(item):
            _add_xdist_group(item, module.__name__, suffix=True)
        return
    # It DOES bind fixed ladder ports, so it must own a worker, and every
    # co-owner of a port must own the SAME one (48 of the 65 bases have more
    # than one owner).  A per-module group it declared for itself is exactly
    # what split those co-owners apart, so the computed group overrides it.
    _force_xdist_group(item, computed)


def _mark_collection_item(item, name):
    _mark_path_groups(item, name)
    if _is_slow_module(str(item.fspath)):
        item.add_marker(pytest.mark.slow)
    if _needs_serial(item, name):
        item.add_marker(pytest.mark.serial)
    _mark_remote_skip(item)
    if item.get_closest_marker("serial"):
        _add_xdist_group(item, "serial")
    _mark_interop_group(item)


def _enforce_declarations_and_flush(config, items):
    try:
        _enforce_server_declarations(config, items)
    finally:
        _flush_declare_cache()


def _apply_first_percent(config, items):
    percent = config.getoption("--first-percent")
    if percent is None:
        return
    if not 0 < percent <= 100:
        raise pytest.UsageError("--first-percent must be greater than 0 and at most 100")
    import math
    keep = max(1, math.ceil(len(items) * percent / 100.0))
    deselected = items[keep:]
    items[:] = items[:keep]
    if deselected:
        config.hook.pytest_deselected(items=deselected)


def _pin_cvmfs_conformance_family(item, filename):
    """Keep each CVMFS module and its split siblings on one worker."""
    if not filename.startswith("test_cvmfs_"):
        return
    if any(m.name == "xdist_group" for m in item.iter_markers()):
        return
    family = filename.removesuffix(".py")
    while len(family) > 2 and family[-2] == "_" and family[-1].isalpha():
        family = family[:-2]
    item.add_marker(pytest.mark.xdist_group(family))


def _pin_resilience_family(item):
    """The resilience lab classes share a fixed port ledger across modules."""
    marker = f"{os.sep}resilience{os.sep}"
    if marker not in str(item.fspath):
        return
    if any(m.name == "xdist_group" for m in item.iter_markers()):
        return
    item.add_marker(pytest.mark.xdist_group("resilience-lab"))


def _pin_lifecycle_family(item, filename):
    """Serialize fixed-ledger lifecycle fixtures, including split siblings."""
    if not item.get_closest_marker("uses_lifecycle_harness"):
        return
    if any(m.name == "xdist_group" for m in item.iter_markers()):
        return
    family = filename.removesuffix(".py")
    while len(family) > 2 and family[-2] == "_" and family[-1].isalpha():
        family = family[:-2]
    item.add_marker(pytest.mark.xdist_group(f"lifecycle-{family}"))


def pytest_collection_modifyitems(config, items):
    """Apply suite scheduling, skip, declaration, and sampling policies."""
    cms_items = []
    other_items = []
    for item in items:
        name = os.path.basename(str(item.fspath))
        _mark_collection_item(item, name)
        _pin_cvmfs_conformance_family(item, name)
        _pin_resilience_family(item)
        _pin_lifecycle_family(item, name)
        materialize_xdist_group(item)
        target = cms_items if name == "test_cms.py" else other_items
        target.append(item)
    if cms_items:
        items[:] = other_items + cms_items
    _register_fleet()
    _enforce_declarations_and_flush(config, items)
    _apply_first_percent(config, items)
