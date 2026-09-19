"""Fleet server-declaration analysis: the stamped cache and the gate over it.

Continuation shard of conftest_part3.py (loaded by conftest.py through
split_continuation), not a standalone module: it shares that file's imports and
namespace and is executed straight after it.  Split out because conftest_part3
had grown past the 600-line limit; this is the self-contained half — everything
between "which fleet servers does this test touch" and the UsageError raised
when a test touches one it never declared, plus the on-disk cache that keeps the
analysis off the collection critical path.
"""

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
    """Return the registered fixed-port fleet after collection, minus members
    this host cannot start (``brix_suite.host_caps``; their tests are skipped)."""
    del items
    _register_fleet()
    return host_caps.boot_specs(registered_specs())


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
