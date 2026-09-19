"""Phase-81 registry lint — enforce the server-lifecycle policy on the test tree.

Policy (docs/refactor/phase-81-test-server-registry.md §"registry lint"):
  * A test must not start/stop/reload nginx directly — it goes through the
    registry (`LifecycleHarness`, marked with ``pytest.mark.uses_lifecycle_harness``)
    or the session fleet.  Direct ``subprocess.run/Popen([NGINX, ...])`` is banned.
  * No ``*.sh`` under ``tests/`` at all — the fleet is pure Python (the
    declarative ``fleet_specs`` catalogue launched by ``RegistryLauncher``).
  * Test code must not reach around the registry by shelling out to the
    (now-deleted) ``cmdscripts/manage_test_servers.py`` / ``tests/lib/*.sh`` helpers.

The only direct launchers left are three explicit operator/namespace labs whose
isolation model cannot be represented by the host registry.  The lint fails on
any new direct launcher and on a stale exception after a lab is migrated.
"""

from pathlib import Path
import re


def _guard_inline_config_modules_1(text, offenders, path):
    if _INLINE_EVENTS.search(text) and _INLINE_HTTP_STREAM.search(text):
        offenders.add(_rel(path))


TESTS = Path(__file__).resolve().parent
PY_FILES = [p for p in TESTS.rglob("*.py") if ".pytest_cache" not in p.parts]
SH_FILES = [p for p in TESTS.rglob("*.sh") if ".pytest_cache" not in p.parts]

# Registry/infra files that own the launch primitive itself, plus this lint.
# ``_server_launcher_part2_mixinc.py`` is server_launcher.py's own shard — the
# file-size split moved the `nginx -t` / start argv out of the parent, so it is
# the same infra, not a test that grew a launch of its own.
INFRA_ALLOW = {
    "server_launcher.py",
    "_server_launcher_part2_mixinc.py",
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
#
# The binary reference is matched with an optional leading underscore and an
# optional empty call, so `_NGINX`, `_nginx_bin()` and `lib.nginx_bin()` are seen
# as well as the three bare names.  That is not tidiness: a closed list of exact
# identifiers does not make a differently-named launcher CLEAN, it makes it
# UNSEEN, and the guard's silence then reads as a pass.  Three files in the tree
# spelled it otherwise, and one of them —
# test_data_substreams_gateway.py, which starts two real gateway servers from a
# module-level `_NGINX` — had never once been examined by this guard.  The other
# direction costs a file its exemption for the same reason:
# test_phase115_conf_unset_sentinel.py runs `nginx -t` and nothing else through
# `_nginx_bin()`, and was flagged as an inline-config offender purely because
# `_validation_only` could not see the `nginx -t` it was named for.
_LAUNCH = re.compile(
    r"subprocess\.(?:run|Popen)\(\s*\[\s*(?:str\(\s*)?(?:[A-Za-z_]\w*\.)?"
    r"_?(?:NGINX_BIN|NGINX|nginx_bin)\b(?:\s*\(\s*\))?([^\]]*)\]",
    re.S,
)
_MARKER = "uses_lifecycle_harness"

# Documented exceptions for files that must launch nginx outside the host
# registry (relative to tests/).  Never add an ordinary pytest fixture here.
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
# `_perf_netem_helpers.py` is the third entry of that same standalone-lab class,
# and the one case the registry structurally CANNOT own: the nginx it starts runs
# inside a private network namespace (`unshare -n`) at the far end of a synthesized
# `veth`+`netem` link, so its listen is unreachable from the host the registry
# probes for readiness and its port cannot collide with a fleet port at all.  It
# is a helper module (never collected as a test) driven by the operator-invoked
# phase-33 A/B throughput harness, and it reaps its own master in the namespace
# it created.  Like the two entries above it is documented, not a target for
# migration — but it is still ON the list, so an accidental second launcher in
# the file would not slip past the guard.
LAUNCH_BACKLOG = frozenset({
    # Same entry as ever, renamed: the redteam file-size split moved the direct
    # launch from e2e_redteam.py into shard part4.  Backlog size is unchanged --
    # this is a relocation, not a new offender.
    "userns/e2e_redteam_part4.py",
    "cmdscripts/system_live_ports.py",
    "_perf_netem_helpers.py",
    # Both entries below surfaced only when the guard learned to read a binary
    # reference spelled with a leading underscore or a call; each was an
    # unflagged direct launcher for as long as it has existed.
    #
    # `test_data_substreams_gateway.py` is the fourth standalone-lab entry: a
    # `requires_local_server` rig that boots two gateway servers from the SYSTEM
    # nginx (`TEST_NGINX_BIN`, defaulting to /usr/sbin/nginx) rather than the
    # build tree's, on fixed gateway/origin ports, and skips itself when that
    # binary or xrdcp is absent.  It is a migration target, not a permanent
    # exception — recorded here so the guard sees it, which it did not before.
    "test_data_substreams_gateway.py",
    # Same entry as ever, renamed — the second relocation of this kind: the
    # file-size split moved the boot out of `test_phase115_example_configs.py`
    # into its continuation shard, so the parent no longer launches anything
    # and the shard is not a new offender.  What it does is unchanged: boot the
    # SHIPPED compose stacks (deploy/compose/*/nginx*.conf) exactly as an
    # operator would, which is the whole assertion — the deliverable under test
    # is the committed config, not a tests/configs template the registry could
    # render.  Ports are leased and remapped per run and every master is reaped
    # by the stack's own `stop()`.
    "_test_phase115_example_configs_live.py",
})


# Inline-nginx-config ban applies to pytest test modules (``test_*.py``): a test
# must render from a committed template, not embed an nginx config heredoc.  The
# ``cmdscripts/*.py`` generators and ``*_lib`` helpers are the committed config
# *source* for the compat fleet and are intentionally out of scope.  Strictly
# shrinking, like LAUNCH_BACKLOG.
_INLINE_EVENTS = re.compile(r"events\s*\{")
_INLINE_HTTP_STREAM = re.compile(r"(?:^|\W)(?:http|stream)\s*\{")
# The shared parse-only drivers (``config_parse``): they render into a throwaway
# prefix, exec ``nginx -t``, and START NOTHING.  A module that calls them has the
# same standing as one spelling the ``-t`` argv itself — more, since going
# through the helper IS the migrated idiom — but the argv scan below reads one
# file at a time and cannot see a ``-t`` that lives in another.  Without this,
# doing the right thing (`test_gsi_legacy_proxy_config.py`, whose http half
# builds a body ``nginx_t_text`` validates) was flagged as a new inline config
# while the module it copied its shape from, which runs its own subprocess, was
# exempt.  Server-starting launches are still disqualifying — `_server_launches`
# is checked first — so this widens the exemption to the helper, not past it.
_PARSE_HELPER = re.compile(
    r"^\s*from\s+config_parse\s+import\b|\bconfig_parse\.nginx_t\w*\s*\(",
    re.M,
)
INLINE_CONFIG_BACKLOG = frozenset()
# Fully burned down: every test module that embedded an nginx config heredoc has
# been migrated to a committed tests/configs/*.conf template driven through the
# registry.  An entry here would have to both embed an inline config *and* be
# unmarked; the shrink-only guard (test_inline_config_backlog_only_shrinks)
# keeps this empty.

_RUNTIME_PATH_DIRECTIVE = re.compile(
    r"^\s*(?:pid|error_log|access_log|brix_access_log|client_body_temp_path|"
    r"proxy_temp_path|fastcgi_temp_path|uwsgi_temp_path|scgi_temp_path|"
    r"all\.adminpath|all\.pidpath|oss\.localroot)\s+"
    r"([^;\s]+)",
    re.M,
)
_CONFINED_PATH_KEYS = ("{LOG_DIR}", "{TMP_DIR}", "{BASE_DIR}", "{TEST_ROOT}")


def _rel(path):
    return path.relative_to(TESTS).as_posix()


def _argv_is_non_server_action(argv_tail):
    """True when nginx exits after validation, inspection, or signalling.

    ``-s`` is signal mode: nginx reads the pidfile, sends `stop`/`quit`/`reload`
    to a master that is ALREADY running, and exits.  It starts nothing, so it is
    no more a launch than ``-t`` is — and the registry's own stop path is spelled
    exactly that way (brix_suite/kinds.py), which is why the flag has to be
    named here rather than the file exempted wholesale."""
    quoted_flags = {
        flag
        for quote in ('"', "'")
        for flag in (f"{quote}-t{quote}", f"{quote}-v{quote}",
                     f"{quote}-V{quote}", f"{quote}-s{quote}")
    }
    return any(flag in argv_tail for flag in quoted_flags)


def _server_launches(text):
    """nginx-as-argv0 subprocess calls that START a server (i.e. NOT `nginx -t`)."""
    return [
        match for match in _LAUNCH.finditer(text)
        if not _argv_is_non_server_action(match.group(1))
    ]


def _validation_only(text):
    """True when the module drives nginx solely for `nginx -t` config validation:
    no server-starting nginx launch, and at least one parse-only driver — the
    shared `config_parse` helpers or an inline `nginx -t` argv.  Such a
    config-syntax/negative test embeds a minimal snippet on purpose and has no
    runnable-template equivalent, so it is exempt from the inline-config ban."""
    if _server_launches(text):
        return False
    if _PARSE_HELPER.search(text):
        return True
    calls = list(_LAUNCH.finditer(text))
    return bool(calls) and any(
        '"-t"' in m.group(1) or "'-t'" in m.group(1) for m in calls
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
        _guard_inline_config_modules_1(text, offenders, path)
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
    migration_doc = (TESTS.parent
                     / "docs/09-developer-guide/testing/configs/REGISTRY_MIGRATION.md").read_text(
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


def test_non_server_nginx_actions_are_not_launchers():
    """Build inspection and config validation exit without starting nginx."""
    source = "\n".join((
        'subprocess.run([NGINX_BIN, "-t", "-c", config])',
        'subprocess.run([str(nginx_bin), "-V"])',
        'subprocess.run([NGINX, "-v"])',
    ))
    assert not _server_launches(source)


def test_the_detector_sees_every_spelling_of_the_binary():
    """(success) A launch is a launch whatever the module called the binary.

    Each line below starts a server; the guard's job is to see all five.  The
    old pattern accepted only the three bare names, so `_NGINX` and
    `_nginx_bin()` were not judged clean — they were never read at all."""
    spellings = (
        'subprocess.Popen([NGINX_BIN, "-c", conf])',
        'subprocess.run([str(nginx_bin), "-c", conf])',
        'subprocess.Popen([settings.NGINX, "-c", conf])',
        'subprocess.Popen([_NGINX, "-c", conf])',
        'subprocess.run([_nginx_bin(), "-p", prefix, "-c", conf])',
    )
    unseen = [line for line in spellings if not _server_launches(line)]
    assert unseen == [], (
        "these argv0 spellings start a server and the guard cannot see them; "
        f"an unseen launcher reads as a clean file: {unseen}")


def test_the_extension_caught_a_launcher_that_had_never_been_seen():
    """(error) The census that proves the widening was not cosmetic.

    ``test_data_substreams_gateway.py`` boots two gateway servers from a
    module-level ``_NGINX``.  Under the old pattern ``_direct_launchers()``
    returned it in neither the offender set nor the backlog — the file was
    invisible, and the guard's silence about it was indistinguishable from a
    pass.  It is on the backlog now precisely so it is SEEN; if it is ever
    migrated, ``test_launch_backlog_only_shrinks`` removes it.  Signal mode is
    pinned in the same row: ``brix_suite/kinds.py`` became visible at the same
    moment and must NOT be an offender, because ``-s quit`` stops a master
    rather than starting one."""
    launchers = _direct_launchers()
    assert "test_data_substreams_gateway.py" in launchers, (
        "the widened argv0 pattern no longer sees the `_NGINX` gateway rig; "
        "the extension has regressed to its blind state")
    assert "brix_suite/kinds.py" not in launchers, (
        "`nginx -s quit` was counted as a launch — the registry's own stop "
        "path is not a server start")
    assert not _server_launches('subprocess.run([_nginx_bin(), "-s", "quit"])')


def test_a_mentioned_binary_is_not_a_launch():
    """(security-negative) Widening argv0 must not widen into argv.

    The guard is anchored on argv0 for a reason: a client test that merely
    NAMES an nginx constant inside an xrdcp/curl argv launches nothing, and
    flagging it would push authors to silence the guard.  A leading underscore
    or a call must not buy a match anywhere but the first element — nor may a
    look-alike identifier that merely ends in one of the three names."""
    innocent = (
        'subprocess.run(["xrdcp", f"root://h:{NGINX_ANON_PORT}//x", dst])',
        'subprocess.run(["curl", "-sv", NGINX_URL])',
        'subprocess.run([XRDFS, str(nginx_bin), "stat", "/x"])',
        'subprocess.Popen([MY_NGINX_WRAPPER, "-c", conf])',
    )
    flagged = [line for line in innocent if _server_launches(line)]
    assert flagged == [], (
        f"argv0 anchoring lost: these launch nothing yet were flagged {flagged}")


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
    deleted fleet shell helpers (cmdscripts/manage_test_servers.py / tests/lib/*.sh) —
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


def test_config_runtime_paths_are_test_root_relative_or_placeholders():
    """Templates must never pin logs, pidfiles, or temp files outside a lane."""
    offenders = []
    config_paths = list((TESTS / "configs").glob("*.conf"))
    config_paths.extend(TESTS.glob("*.perf.conf"))
    for path in sorted(config_paths):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in _RUNTIME_PATH_DIRECTIVE.finditer(text):
            value = match.group(1).strip('"\'')
            if value in {"off", "stderr", "syslog:"}:
                continue
            if value.startswith("/") and not any(
                    key in value for key in _CONFINED_PATH_KEYS):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{_rel(path)}:{line}:{value}")
    assert not offenders, (
        "config runtime path escapes TEST_ROOT; use LOG_DIR/TMP_DIR/BASE_DIR "
        f"placeholders or a prefix-relative path: {offenders}"
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
