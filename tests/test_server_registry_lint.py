"""Phase-81 registry lint — enforce the server-lifecycle policy on the test tree.

Policy (docs/refactor/phase-81-test-server-registry.md §"registry lint"):
  * A test must not start/stop/reload nginx directly — it goes through the
    registry (`LifecycleHarness`, marked with ``pytest.mark.uses_lifecycle_harness``)
    or the session fleet.  Direct ``subprocess.run/Popen([NGINX, ...])`` is banned.
  * No ``*.sh`` under ``tests/`` at all — the fleet is pure Python (the
    declarative ``fleet_specs`` catalogue launched by ``RegistryLauncher``).
  * Test code must not reach around the registry by shelling out to the
    (now-deleted) ``manage_test_servers.sh`` / ``tests/lib/*.sh`` helpers.

The direct-launch ban is enforced against a *strictly shrinking* backlog: files
that still launch nginx directly are enumerated in ``LAUNCH_BACKLOG``.  The lint
fails on (a) any NEW direct launch outside the backlog, and (b) any backlog entry
that no longer launches directly — a migrated file must be removed from the list.
So the only legal way to change the backlog is to make it smaller.  A file drops
out of scope the moment it carries the ``uses_lifecycle_harness`` marker.
"""

from pathlib import Path
import re


TESTS = Path(__file__).resolve().parent
PY_FILES = [p for p in TESTS.rglob("*.py") if ".pytest_cache" not in p.parts]
SH_FILES = [p for p in TESTS.rglob("*.sh") if ".pytest_cache" not in p.parts]

# Registry/infra files that own the launch primitive itself, plus this lint.
INFRA_ALLOW = {
    "server_launcher.py",
    "conftest.py",
    "test_server_registry_lint.py",
}

# A direct launch is nginx-as-argv0: the binary reference (NGINX_BIN / NGINX /
# a lowercase `nginx_bin` local, optionally attribute-qualified like
# `settings.NGINX_BIN`, and optionally wrapped in a `str(...)` coercion) is the
# *first* element of the argv list handed to subprocess.run/Popen.  Anchoring on
# argv0 is deliberate: a fleet-client test that merely mentions an
# `NGINX_*_PORT` / `NGINX_URL` constant somewhere inside an `xrdcp`/`curl` argv
# (e.g. `["xrdcp", f"root://…:{NGINX_ANON_PORT}//"]`) is NOT launching nginx and
# must not be flagged — the previous `[^\]]*NGINX` scan false-matched those.  The
# `cmdscripts/*.py` fleet config generators build argv lists too but never call
# subprocess.run([NGINX…]) themselves, so the subprocess anchor keeps them (the
# committed config source) out of scope.  The `str(...)` wrapper is matched
# because `[str(NGINX_BIN), "-t", …]` is a common idiom when the binary is a
# `Path`: without it, such a call is invisible to the guard — both letting a
# real server launch evade `_direct_launchers()` and denying a genuine `nginx -t`
# parse test its validation-only exemption.
#
# The argv tail up to the closing `]` is captured so a `nginx -t` invocation can
# be told apart from a server launch: `nginx -t` only validates config syntax and
# starts NO server, so it is neither a "direct launch" (nothing to leak/race) nor
# a runnable inline-config server.  Config-syntax/negative tests that must assert
# a directive is accepted or rejected at parse time legitimately feed a minimal
# snippet to `nginx -t` and cannot be expressed as a committed runnable template.
_LAUNCH = re.compile(
    r"subprocess\.(?:run|Popen)\(\s*\[\s*(?:str\(\s*)?(?:[A-Za-z_]\w*\.)?"
    r"(?:NGINX_BIN|NGINX|nginx_bin)\b([^\]]*)\]",
    re.S,
)
_MARKER = "uses_lifecycle_harness"

# Documented, strictly-shrinking backlog of files that still launch nginx
# directly (relative to tests/).  Burn this down phase by phase; never add to it.
# `userns/e2e_redteam.py` is a deliberate long-lived entry: it is a standalone
# in-namespace-root privilege-escalation battery (launched by the C
# userns_exec_launcher, not a shell) whose `user svc;` worker-setuid model and
# per-uid export-tree ownership conflict with the registry's prefix-ownership
# model — see the tracker's "Files requiring lifecycle-harness migration" note.
# `cmdscripts/system_live_ports.py` is the Python port of the run_ktls.sh /
# run_io_uring_backend.sh live shell scenarios: an operator-invoked CLI (never
# collected by pytest) that runs a single throwaway nginx in its own isolated
# `/tmp/xrd-perf-test` prefix and reaps it by pkill, so it neither leaks into nor
# races the shared registry fleet — the same standalone-lab shape as the redteam
# entry.  (It surfaced here only once the guard learned to see `str(nginx_bin)`
# argv0; it was an unflagged direct launcher long before.)
LAUNCH_BACKLOG = frozenset({
    "userns/e2e_redteam.py",
    "cmdscripts/system_live_ports.py",
})


# Inline-nginx-config ban applies to pytest test modules (``test_*.py``): a test
# must render from a committed template, not embed an nginx config heredoc.  The
# ``cmdscripts/*.py`` generators and ``*_lib`` helpers are the committed config
# *source* for the compat fleet and are intentionally out of scope.  Strictly
# shrinking, like LAUNCH_BACKLOG.
_INLINE_EVENTS = re.compile(r"events\s*\{")
_INLINE_HTTP_STREAM = re.compile(r"(?:^|\W)(?:http|stream)\s*\{")
INLINE_CONFIG_BACKLOG = frozenset()
# Fully burned down: every test module that embedded an nginx config heredoc has
# been migrated to a committed tests/configs/*.conf template driven through the
# registry.  An entry here would have to both embed an inline config *and* be
# unmarked; the shrink-only guard (test_inline_config_backlog_only_shrinks)
# keeps this empty.


def _rel(path):
    return path.relative_to(TESTS).as_posix()


def _argv_is_validation(argv_tail):
    """True when a captured nginx argv tail carries the `-t` config-test flag."""
    return '"-t"' in argv_tail or "'-t'" in argv_tail


def _server_launches(text):
    """nginx-as-argv0 subprocess calls that START a server (i.e. NOT `nginx -t`)."""
    return [m for m in _LAUNCH.finditer(text) if not _argv_is_validation(m.group(1))]


def _validation_only(text):
    """True when the module drives nginx solely for `nginx -t` config validation:
    at least one `nginx -t` call and no server-starting nginx launch.  Such a
    config-syntax/negative test embeds a minimal snippet on purpose and has no
    runnable-template equivalent, so it is exempt from the inline-config ban."""
    calls = list(_LAUNCH.finditer(text))
    return bool(calls) and not _server_launches(text) and any(
        _argv_is_validation(m.group(1)) for m in calls
    )


def _inline_config_modules():
    """test_*.py modules that embed a *runnable* nginx config and are not exempt.

    Marker-exempt (``uses_lifecycle_harness``) and pure `nginx -t` config-syntax
    tests are excluded — the ban targets embedding a server config that a test
    actually runs instead of rendering it from a committed template."""
    offenders = set()
    for path in PY_FILES:
        if path.name in INFRA_ALLOW or not path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _MARKER in text or _validation_only(text):
            continue
        if _INLINE_EVENTS.search(text) and _INLINE_HTTP_STREAM.search(text):
            offenders.add(_rel(path))
    return offenders


def _direct_launchers():
    """Files that START nginx directly and are not exempt via the marker.

    A `nginx -t` invocation validates config syntax and starts no server, so it
    is not a direct launch — only server-starting calls count."""
    launchers = set()
    for path in PY_FILES:
        rel = _rel(path)
        if path.name in INFRA_ALLOW:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _server_launches(text) and _MARKER not in text:
            launchers.add(rel)
    return launchers


def test_migration_doc_states_the_policy():
    migration_doc = (TESTS / "configs" / "REGISTRY_MIGRATION.md").read_text(
        encoding="utf-8"
    )
    flat_doc = " ".join(migration_doc.split())
    assert _MARKER in migration_doc
    assert "should not start or stop nginx directly" in flat_doc


def test_no_new_direct_nginx_launches():
    """No test may launch nginx directly outside the shrinking backlog."""
    launchers = _direct_launchers()
    new_offenders = sorted(launchers - LAUNCH_BACKLOG)
    assert not new_offenders, (
        "new direct nginx launch(es) — route through the registry "
        f"(LifecycleHarness + @pytest.mark.{_MARKER}): {new_offenders}"
    )


def test_launch_backlog_only_shrinks():
    """Every backlog entry must still be a direct launcher.

    A migrated file (now marked, or no longer launching nginx) must be deleted
    from LAUNCH_BACKLOG so the allowlist can only get smaller."""
    launchers = _direct_launchers()
    stale = sorted(LAUNCH_BACKLOG - launchers)
    assert not stale, (
        "stale LAUNCH_BACKLOG entries — these no longer launch nginx directly, "
        f"remove them from the list: {stale}"
    )


def test_no_test_code_sources_shell_helpers():
    """Test code must not reach around the registry by shelling out to the
    deleted fleet shell helpers (manage_test_servers.sh / tests/lib/*.sh) —
    guards against reintroducing the bash fleet."""
    pattern = re.compile(
        r"""subprocess\.(?:run|Popen|call|check_call|check_output)\([^)]*"""
        r"""(?:manage_test_servers\.sh|lib/[\w./-]+\.sh)""",
        re.S,
    )
    offenders = []
    for path in PY_FILES:
        if path.name in INFRA_ALLOW:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if pattern.search(text):
            offenders.append(_rel(path))
    assert not offenders, (
        "test code invokes the fleet shell helpers directly; drive nginx "
        f"through the registry instead: {sorted(offenders)}"
    )


def test_no_new_inline_nginx_configs():
    """No test module may embed an nginx config (events{} + http/stream{})
    outside the shrinking backlog — render from a committed template instead."""
    new_offenders = sorted(_inline_config_modules() - INLINE_CONFIG_BACKLOG)
    assert not new_offenders, (
        "new inline nginx config(s) in a test module — extract to a "
        "tests/configs/*.conf template and drive it through the registry: "
        f"{new_offenders}"
    )


def test_inline_config_backlog_only_shrinks():
    """Every INLINE_CONFIG_BACKLOG entry must still embed an inline config.
    A migrated file must be removed from the list so it can only shrink."""
    stale = sorted(INLINE_CONFIG_BACKLOG - _inline_config_modules())
    assert not stale, (
        "stale INLINE_CONFIG_BACKLOG entries — these no longer embed an inline "
        f"nginx config, remove them from the list: {stale}"
    )


def test_no_two_specs_claim_the_same_fixed_port():
    """No two distinct fleet services may pin the same fixed port.

    Every fleet instance is pinned to a hardcoded ``settings.py`` port (so the
    414 fixed-port test files stay valid).  A copy-paste slip that points two
    *different* services at one port is invisible until start-all, where they
    race for the socket — whoever binds first wins, the other dies with a
    confusing bind error.  ``port_conflicts`` surfaces every such collision
    statically from the declared specs, before anything launches.

    Built from ``fleet_specs._all_specs()`` (pure spec construction) rather than
    the live registry, so the check is independent of session registration and
    never mutates it.  Within-spec reuse (a service re-exposing its own listen
    port under an ``extra_ports`` key) is not a conflict — only cross-service."""
    import fleet_specs
    from server_registry import port_conflicts

    conflicts = port_conflicts(fleet_specs._all_specs())
    assert not conflicts, "fixed-port collisions between distinct services:\n" + "\n".join(
        f"  port {port}: {', '.join(names)}" for port, names in sorted(conflicts.items())
    )


def test_no_shell_scripts_under_tests():
    """Phase-81 endgame reached: the bash fleet is gone.

    Orchestration is pure Python — the declarative ``fleet_specs`` catalogue
    launched by ``RegistryLauncher`` (see ``cmdscripts/manage_test_servers.py``).
    No ``*.sh`` may exist anywhere under ``tests/``; a stray one is a regression
    back toward the shell fleet this migration deleted."""
    strays = sorted(_rel(p) for p in SH_FILES)
    assert not strays, f"shell scripts under tests/ — the fleet is pure Python now: {strays}"
