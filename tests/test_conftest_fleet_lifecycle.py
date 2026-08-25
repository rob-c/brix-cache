"""
tests/test_conftest_fleet_lifecycle.py

Unit coverage for the conftest "own only the fleet we started" guard.

Background: in LOCAL mode the session teardown runs `manage_test_servers.sh
stop-all` then `rmtree(TEST_ROOT)`.  When an operator keeps a fleet up out of
band (`tests/manage_test_servers.sh start-all`) and runs a single test file for
a quick iteration, that teardown would tear the whole fleet down and wipe
/tmp/xrd-test -- orphaning every still-running server's export-root fd, so the
next manual `xrdcp`/TPC hangs.  `conftest._external_fleet_attached()` closes that
footgun: when a fleet is already listening it attaches WITHOUT taking lifecycle
ownership (no wipe / start-all / stop-all / rmtree), unless TEST_OWN_FLEET=1
forces a clean restart.  These tests pin that pure decision down hermetically --
no real server is started or stopped.
"""

import importlib.util
import os
import types

import pytest

# Load the *tests/* conftest by path: a bare ``import conftest`` resolves to the
# repo-root compatibility shim (./conftest.py), not this directory's lifecycle
# conftest, so address the file sitting next to this test explicitly.
def _check_test_complete_boot_does_not_depend_on_autouse_discovery_1(ded_spec, boot):
    assert {s.name for s in boot} == {ded_spec}


_CONFTEST_PATH = os.path.join(os.path.dirname(__file__), "conftest.py")
_spec = importlib.util.spec_from_file_location("tests_conftest_under_test", _CONFTEST_PATH)
assert _spec is not None and _spec.loader is not None
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)


@pytest.fixture
def fleet_decision_env(monkeypatch):
    """Isolate `_external_fleet_attached()` from the real fleet and the ambient
    process: reset its memo, force LOCAL mode, and let the caller pick whether a
    fleet "appears" to be running and whether TEST_OWN_FLEET is set.  Restores the
    memo afterwards so the surrounding real session re-decides cleanly."""
    saved_memo = conftest._external_fleet
    saved_collision = conftest._foreign_fleet_collision
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False, raising=False)
    monkeypatch.delenv("TEST_OWN_FLEET", raising=False)
    monkeypatch.setattr(conftest, "manifest_owns_test_root", lambda: True)
    monkeypatch.setattr(conftest, "fleet_ready_for_test_root", lambda: True)
    monkeypatch.setattr(conftest, "_fleet_main_master_alive", lambda: True)

    def configure(*, fleet_running: bool):
        conftest._external_fleet = None
        conftest._foreign_fleet_collision = False
        monkeypatch.setattr(
            conftest, "_check_server_reachable",
            lambda *a, **k: fleet_running,
        )

    yield configure
    conftest._external_fleet = saved_memo
    conftest._foreign_fleet_collision = saved_collision


def test_attaches_when_fleet_already_running(fleet_decision_env):
    fleet_decision_env(fleet_running=True)
    assert conftest._external_fleet_attached() is True


def test_owns_when_no_fleet_running(fleet_decision_env):
    fleet_decision_env(fleet_running=False)
    assert conftest._external_fleet_attached() is False


def test_foreign_listener_aborts_before_lifecycle_start(
    fleet_decision_env, monkeypatch
):
    """An overlapping live lane is never treated as a reap-and-retry target."""
    fleet_decision_env(fleet_running=True)
    monkeypatch.setattr(conftest, "manifest_owns_test_root", lambda: False)
    monkeypatch.setattr(conftest, "fleet_ready_for_test_root", lambda: False)
    with pytest.raises(pytest.UsageError, match="foreign listener was not modified"):
        conftest._should_skip_local_lifecycle(_Config())


def test_owned_orphan_listener_is_reaped_instead_of_attached(
    fleet_decision_env, monkeypatch
):
    fleet_decision_env(fleet_running=True)
    monkeypatch.setattr(conftest, "_fleet_main_master_alive", lambda: False)

    assert conftest._external_fleet_attached() is False
    assert conftest._foreign_fleet_collision is False


def test_leak_reaper_only_kills_exact_test_root(monkeypatch):
    """Legacy shared /tmp markers must not make one lane kill another lane."""
    killed = []
    cmdlines = {
        "101": b"nginx\0-p\0/tmp/brix-tests/lane-b/registry/main\0",
        "202": b"nginx\0-p\0/tmp/brix-tests/lane-a/registry/main\0",
        "303": b"xrootd\0-c\0/tmp/xrd/reference.cfg\0",
    }

    class _ProcFile:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self.payload

    monkeypatch.setattr(conftest, "TEST_ROOT", "/tmp/brix-tests/lane-b")
    def fake_pgrep(argv, **kwargs):
        by_exe = {"nginx": ["101", "202"], "xrootd": ["303"]}
        live = [pid for pid in by_exe.get(argv[-1], []) if int(pid) not in killed]
        return types.SimpleNamespace(stdout="\n".join(live) + ("\n" if live else ""))

    monkeypatch.setattr(conftest.subprocess, "run", fake_pgrep)
    monkeypatch.setattr(
        "builtins.open",
        lambda path, mode: (
            _ProcFile(b"(nginx) 1 1") if path.endswith("/stat")
            else _ProcFile(cmdlines.get(path.split("/")[2], b""))
        ),
    )
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))
    # Candidate discovery unions the REAL /proc listing with pgrep; on a host
    # where a live process happens to hold pid 101, the patched open() hands it
    # the fake lane-b cmdline and the SIGKILL pass "re-kills" it.  Keep the
    # discovery inside the fake by emptying the /proc listing.
    real_listdir = os.listdir
    monkeypatch.setattr(os, "listdir",
                        lambda path: [] if path == "/proc"
                        else real_listdir(path))

    conftest._reap_leaked_test_servers()
    assert killed == [101]


def test_xdist_controller_rebuilds_registry_before_teardown(monkeypatch):
    """A non-collecting controller must still stop the fleet gw0 started."""
    events = []

    class _Launcher:
        def __init__(self, tests_dir):
            events.append(("launcher", tests_dir))

        def stop_registered(self, specs):
            events.append(("stop", specs))

    monkeypatch.setattr(conftest, "_register_fleet",
                        lambda: events.append(("register", None)))
    monkeypatch.setattr(conftest, "RegistryLauncher", _Launcher)
    monkeypatch.setattr(conftest, "_reap_leaked_test_servers",
                        lambda: events.append(("reap", None)))

    # None is the real xdist-controller shape: it never received the worker's
    # selected-spec list. Re-registering makes stop_registered(None) mean the
    # complete catalogue rather than an empty in-memory registry.
    conftest._stop_owned_fleet(None)
    assert [event[0] for event in events] == ["register", "launcher", "stop", "reap"]


def test_interrupted_fleet_start_rolls_back_partial_servers(monkeypatch):
    events = []

    class _Launcher:
        def __init__(self, tests_dir):
            pass

        def start_registered(self, specs):
            events.append("start")
            raise KeyboardInterrupt

        def stop_registered(self, specs):
            events.append("stop")

    monkeypatch.setattr(conftest, "_register_fleet", lambda: None)
    monkeypatch.setattr(conftest, "RegistryLauncher", _Launcher)
    monkeypatch.setattr(conftest, "_reap_leaked_test_servers",
                        lambda: events.append("reap"))
    # The full suite has a live fleet while this unit test runs. Force the
    # start path under test instead of attaching to that session state.
    monkeypatch.setattr(conftest, "fleet_ready_for_test_root", lambda: False)
    monkeypatch.setattr(conftest, "_check_server_reachable",
                        lambda *args, **kwargs: False)

    with pytest.raises(KeyboardInterrupt):
        conftest._start_all_resilient([])
    assert events == ["start", "stop", "reap"]


def test_own_override_forces_ownership_despite_running_fleet(
    fleet_decision_env, monkeypatch
):
    fleet_decision_env(fleet_running=True)
    monkeypatch.setenv("TEST_OWN_FLEET", "1")
    conftest._external_fleet = None  # re-decide after the env change
    assert conftest._external_fleet_attached() is False


def test_remote_mode_never_attaches(fleet_decision_env, monkeypatch):
    fleet_decision_env(fleet_running=True)
    monkeypatch.setattr(conftest, "REMOTE_SERVER", True, raising=False)
    conftest._external_fleet = None
    assert conftest._external_fleet_attached() is False


def test_session_cleanup_preserves_pytest_temp_tree(monkeypatch, tmp_path):
    root = tmp_path / "lane"
    temp_file = root / "tmp" / "pytest-current" / "popen-gw0" / "sentinel"
    stale_log = root / "logs" / "old.log"
    stale_registry = root / "registry" / "old.pid"
    unrelated = tmp_path / "other-lane" / "sentinel"
    for path in (temp_file, stale_log, stale_registry, unrelated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("present", encoding="utf-8")
    monkeypatch.setattr(conftest, "TEST_ROOT", str(root))
    monkeypatch.setattr(conftest, "TMP_DIR", str(root / "tmp"))
    monkeypatch.setattr(conftest, "LOG_DIR", str(root / "logs"))
    monkeypatch.setattr(conftest, "REGISTRY_ROOT", str(root / "registry"))

    conftest._clean_session_owned_state()

    assert temp_file.exists()
    assert not stale_log.exists()
    assert not stale_registry.exists()
    assert unrelated.exists()


def test_setup_reaps_lost_fleet_before_deleting_registry(monkeypatch, tmp_path):
    events = []
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False)
    monkeypatch.setattr(conftest, "_external_fleet_attached", lambda: False)
    monkeypatch.setattr(conftest, "_test_tree_wiped", False)
    monkeypatch.setattr(conftest, "_reap_lost_fleet_before_clean",
                        lambda: events.append("reap"))
    monkeypatch.setattr(conftest, "_clean_session_owned_state",
                        lambda: events.append("clean"))
    conftest._reset_session_tree_once()

    assert events[:2] == ["reap", "clean"]


def test_session_tree_reset_runs_only_once(monkeypatch):
    events = []
    monkeypatch.setattr(conftest, "_test_tree_wiped", False)
    monkeypatch.setattr(conftest, "_reap_lost_fleet_before_clean",
                        lambda: events.append("reap"))
    monkeypatch.setattr(conftest, "_clean_session_owned_state",
                        lambda: events.append("clean"))

    conftest._reset_session_tree_once()
    conftest._reset_session_tree_once()

    assert events == ["reap", "clean"]


def test_lost_fleet_preflight_reports_stop_error_after_reap(monkeypatch, capsys):
    monkeypatch.setattr(conftest, "_stop_owned_fleet",
                        lambda specs: (_ for _ in ()).throw(RuntimeError("one stale pid")))

    conftest._reap_lost_fleet_before_clean()

    assert "stale-fleet preflight warning: one stale pid" in capsys.readouterr().err


def test_sessionstart_clears_stale_state_before_starting_watchdog(monkeypatch):
    """The watchdog must not read a prior-run baseline during session setup."""
    events = []
    config = _Config()
    session = _Session(config, items=[])
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False)
    monkeypatch.setattr(conftest, "_validate_requested_paths",
                        lambda cfg: events.append("validate"))
    monkeypatch.setattr(conftest, "_should_skip_local_lifecycle", lambda cfg: False)
    monkeypatch.setattr(conftest, "_setup_session",
                        lambda **kwargs: events.append(("setup", kwargs)))
    monkeypatch.setattr(conftest, "_start_sentinel_watchdog",
                        lambda active: events.append(("watchdog", active)))

    conftest.pytest_sessionstart(session)

    assert events == [
        "validate", ("setup", {"chdir": True}), ("watchdog", session),
    ]


class _Options:
    def __init__(self, numprocesses=None, collectonly=False):
        self.numprocesses = numprocesses
        self.collectonly = collectonly


class _Config:
    """Minimal stand-in for pytest's Config as pytest_collection_finish sees it:
    no ``workerinput`` attribute (controller), an ``option`` namespace, and a
    positional ``args`` list."""

    def __init__(self, numprocesses=None, collectonly=False):
        self.option = _Options(numprocesses=numprocesses, collectonly=collectonly)
        self.args = ["test_read.py"]


class _Session:
    def __init__(self, config, items):
        self.config = config
        self.items = items


@pytest.fixture
def collection_finish_env(fleet_decision_env, monkeypatch):
    """Hermetic pytest_collection_finish harness: no fleet running (this session
    owns the lifecycle), env knobs cleared, full-fleet computation and fleet start
    stubbed out.  Yields the recorder list of _start_all_resilient() calls."""
    fleet_decision_env(fleet_running=False)
    monkeypatch.delenv("TEST_SKIP_SERVER_SETUP", raising=False)
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "REMOTE_SERVER", False, raising=False)
    started = []
    monkeypatch.setattr(conftest, "_start_all_resilient", started.append)
    monkeypatch.setattr(conftest, "_specs_to_boot", lambda items: ["full-spec"])
    monkeypatch.setattr(conftest, "_require_fleet_startup_stability", lambda: None)
    return started


def test_collection_finish_boots_the_complete_fleet(collection_finish_env):
    """The post-collection hook starts and records the complete fleet."""
    session = _Session(_Config(), items=[object()])
    conftest.pytest_collection_finish(session)
    assert collection_finish_env == [["full-spec"]]
    assert session.config._nginx_xrootd_selected_registry_specs == ["full-spec"]


def test_collection_finish_waits_for_full_fleet_stability(
    collection_finish_env, monkeypatch
):
    """No serial test may dispatch until the post-launch health window passes."""
    stable = []
    monkeypatch.setattr(
        conftest, "_require_fleet_startup_stability", lambda: stable.append(True)
    )
    conftest.pytest_collection_finish(_Session(_Config(), items=[object()]))
    assert collection_finish_env == [["full-spec"]]
    assert stable == [True]


def test_collection_finish_never_starts_when_attached(
    collection_finish_env, fleet_decision_env
):
    """Attach mode (an external fleet is up) must not start — or later stop —
    anything: lifecycle belongs to whoever launched the fleet."""
    fleet_decision_env(fleet_running=True)
    conftest.pytest_collection_finish(_Session(_Config(), items=[object()]))
    assert collection_finish_env == []


def test_collection_finish_defers_to_sessionstart_under_xdist(collection_finish_env):
    """With -n the controller never collects, so the hook must not double-start
    the fleet pytest_sessionstart already booted in full."""
    conftest.pytest_collection_finish(
        _Session(_Config(numprocesses=4), items=[object()])
    )
    assert collection_finish_env == []


def test_xdist_controller_boots_after_every_worker_collected(
    collection_finish_env, monkeypatch, tmp_path
):
    """The final collection report starts the fleet before xdist schedules it."""
    import types

    monkeypatch.setattr(conftest, "_xdist_collected_nodes", set())
    monkeypatch.setattr(conftest, "_xdist_fleet_started", False)
    monkeypatch.setattr(conftest, "REGISTRY_ROOT", str(tmp_path / "registry"))
    captured = []
    monkeypatch.setattr(conftest, "_capture_fleet_baseline",
                        lambda: captured.append(True))
    config = _Config(numprocesses=2)
    first = types.SimpleNamespace(
        config=config, gateway=types.SimpleNamespace(id="gw0"))
    second = types.SimpleNamespace(
        config=config, gateway=types.SimpleNamespace(id="gw1"))

    conftest.pytest_xdist_node_collection_finished(first, [])
    assert collection_finish_env == []
    conftest.pytest_xdist_node_collection_finished(second, [])

    assert collection_finish_env == [["full-spec"]]
    assert captured == [True]
    assert config._nginx_xrootd_selected_registry_specs == ["full-spec"]


def test_xdist_fleet_wait_timeout_defaults_to_fifteen_minutes(monkeypatch):
    monkeypatch.delenv("TEST_FLEET_START_TIMEOUT", raising=False)
    assert conftest._xdist_fleet_wait_seconds() == 900
    monkeypatch.setenv("TEST_FLEET_START_TIMEOUT", "17")
    assert conftest._xdist_fleet_wait_seconds() == 17
    monkeypatch.setenv("TEST_FLEET_START_TIMEOUT", "invalid")
    assert conftest._xdist_fleet_wait_seconds() == 900


def test_collection_finish_skips_collect_only_and_empty_sessions(
    collection_finish_env,
):
    conftest.pytest_collection_finish(
        _Session(_Config(collectonly=True), items=[object()])
    )
    conftest.pytest_collection_finish(_Session(_Config(), items=[]))
    assert collection_finish_env == []


def _named_spec(name):
    """A minimal stand-in for a registry spec: only ``.name`` is read by the
    boot-set closure filter."""
    spec = types.SimpleNamespace()
    spec.name = name
    return spec


def test_complete_fleet_boot_is_the_default(monkeypatch):
    """The collection hook selects every registered server, not a dependency subset."""
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "_register_fleet", lambda: None)
    monkeypatch.setattr(
        conftest, "registered_specs",
        lambda: [_named_spec(n) for n in ("a", "b", "a-dep", "unrelated")])
    boot = conftest._specs_to_boot([])
    assert sorted(s.name for s in boot) == ["a", "a-dep", "b", "unrelated"]


def test_empty_selection_still_boots_the_complete_fleet(monkeypatch):
    """A local test session reserves every server even if no item names one."""
    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "_register_fleet", lambda: None)
    monkeypatch.setattr(conftest, "registered_specs", lambda: [_named_spec("always-on")])
    assert [spec.name for spec in conftest._specs_to_boot([])] == ["always-on"]


def test_complete_boot_does_not_depend_on_autouse_discovery(monkeypatch, tmp_path):
    """Autouse declarations cannot narrow the complete post-collection fleet."""
    import fleet_declares
    import fleet_ports

    ded_spec = next(
        s for s in sorted(fleet_ports.CONST_TO_SPEC.values())
        if s not in fleet_declares.backbone_specs()
    )
    ded_const = next(
        c for c, s in sorted(fleet_ports.CONST_TO_SPEC.items()) if s == ded_spec
    )
    mod = tmp_path / "test_autouse_mod.py"
    mod.write_text(
        "import pytest\n"
        f"from settings import {ded_const}\n"
        '@pytest.fixture(scope="session", autouse=True)\n'
        "def module_env():\n"
        f"    wait_port({ded_const})\n"
    )

    class _Item:
        fspath = str(mod)

    monkeypatch.delenv("REGISTRY_SUBSET_BOOT", raising=False)
    monkeypatch.setattr(conftest, "_register_fleet", lambda: None)
    monkeypatch.setattr(conftest, "registered_specs", lambda: [_named_spec(ded_spec)])
    boot = conftest._specs_to_boot([_Item()])
    _check_test_complete_boot_does_not_depend_on_autouse_discovery_1(ded_spec, boot)


def test_decision_is_memoized(fleet_decision_env):
    """Only one probe per process: the first decision is cached so we neither
    re-probe nor re-print the attach notice on the teardown call."""
    fleet_decision_env(fleet_running=True)
    assert conftest._external_fleet_attached() is True

    calls = {"n": 0}

    def counting_probe(*a, **k):
        calls["n"] += 1
        return False  # would flip the answer if it were consulted

    conftest._check_server_reachable = counting_probe
    assert conftest._external_fleet_attached() is True  # cached True, not re-probed
    assert calls["n"] == 0


# --- persistent declaration-analysis cache -----------------------------------


@pytest.fixture
def declare_cache_env(monkeypatch):
    """Isolate the declaration cache: fresh in-process state, a dict-backed
    stand-in for pytest's config.cache, and a counter on analyze_source."""
    store = {}
    fake_cache = types.SimpleNamespace(
        get=lambda key, default=None: store.get(key, default),
        set=lambda key, value: store.__setitem__(key, value),
    )
    fake_config = types.SimpleNamespace(cache=fake_cache)
    monkeypatch.setattr(conftest, "_pytest_config", fake_config)
    monkeypatch.setattr(conftest, "_declare_usage_cache", {})
    monkeypatch.setattr(conftest, "_declare_disk_cache", None)
    monkeypatch.setattr(conftest, "_declare_disk_dirty", False)

    calls = {"n": 0}
    real = conftest.fleet_declares.analyze_source

    def counting(source):
        calls["n"] += 1
        return real(source)

    monkeypatch.setattr(conftest.fleet_declares, "analyze_source", counting)

    def new_process():
        """Simulate a fresh pytest run: in-memory caches gone, store kept."""
        monkeypatch.setattr(conftest, "_declare_usage_cache", {})
        monkeypatch.setattr(conftest, "_declare_disk_cache", None)
        monkeypatch.setattr(conftest, "_declare_disk_dirty", False)

    return types.SimpleNamespace(
        store=store, config=fake_config, calls=calls, new_process=new_process)


def test_declaration_cache_serves_unchanged_module_without_reparse(
    declare_cache_env, tmp_path
):
    mod = tmp_path / "test_cache_probe.py"
    mod.write_text("def test_alpha():\n    assert True\n", encoding="utf-8")

    first = conftest._module_test_usage(str(mod))
    assert "test_alpha" in first
    assert declare_cache_env.calls["n"] == 1
    conftest._flush_declare_cache()
    assert declare_cache_env.store, "flush must persist the analysis"

    declare_cache_env.new_process()
    second = conftest._module_test_usage(str(mod))
    assert declare_cache_env.calls["n"] == 1, "unchanged file must not re-parse"
    assert second["test_alpha"].name == "test_alpha"
    assert second["test_alpha"].qualname == "test_alpha"


def test_declaration_cache_invalidates_on_file_change(declare_cache_env, tmp_path):
    mod = tmp_path / "test_cache_probe.py"
    mod.write_text("def test_alpha():\n    assert True\n", encoding="utf-8")
    conftest._module_test_usage(str(mod))
    conftest._flush_declare_cache()

    # Different content AND size, plus an explicit mtime bump so the stamp
    # cannot collide within one clock tick.
    mod.write_text(
        "def test_alpha():\n    assert True\n\ndef test_beta():\n    assert True\n",
        encoding="utf-8",
    )
    stat = os.stat(mod)
    os.utime(mod, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    declare_cache_env.new_process()
    usage = conftest._module_test_usage(str(mod))
    assert declare_cache_env.calls["n"] == 2, "changed file must re-parse"
    assert "test_beta" in usage


def test_declaration_cache_corruption_degrades_to_full_parse(
    declare_cache_env, tmp_path
):
    mod = tmp_path / "test_cache_probe.py"
    mod.write_text("def test_alpha():\n    assert True\n", encoding="utf-8")
    declare_cache_env.store[conftest._DECLARE_CACHE_KEY] = "not-a-dict"

    usage = conftest._module_test_usage(str(mod))
    assert "test_alpha" in usage
    assert declare_cache_env.calls["n"] == 1
    conftest._flush_declare_cache()
    persisted = declare_cache_env.store[conftest._DECLARE_CACHE_KEY]
    assert isinstance(persisted, dict) and persisted["v"] == conftest._DECLARE_CACHE_VERSION


def test_declaration_cache_only_gw0_writes_under_xdist(declare_cache_env, tmp_path):
    mod = tmp_path / "test_cache_probe.py"
    mod.write_text("def test_alpha():\n    assert True\n", encoding="utf-8")
    declare_cache_env.config.workerinput = {"workerid": "gw3"}

    conftest._module_test_usage(str(mod))
    conftest._flush_declare_cache()
    assert not declare_cache_env.store, "non-gw0 workers must not write"

    declare_cache_env.config.workerinput = {"workerid": "gw0"}
    conftest._flush_declare_cache()
    assert declare_cache_env.store, "gw0 owns the write"
