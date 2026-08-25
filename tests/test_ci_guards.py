from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ci_guards_helpers")

# 300s, not the 30s default: most guards finish in ~1s, but the lizard-class
# ones (check_python_quality ~23s serially, check_python_deps close behind)
# starve past 30s when 12 xdist workers saturate the box.
@pytest.mark.timeout(300)
@pytest.mark.parametrize("guard", _FAST)
def test_ci_guard_green(guard: str) -> None:
    rc, out = _run(guard)
    assert rc == 0, f"tools/ci/{guard}.py failed (exit {rc}):\n{out}"


# --- brix-namespace guard: negative (drift is actually caught) ----------------
# The green assertion above proves the tree is clean today; this proves the guard
# would redden if a pre-rebrand token crept back in (the exact P44 `xrdc_aconn`
# comment drift found in the phase-88 §5 reconciliation, 2026-07-30). Injects a
# residual into a scanned tree, asserts non-zero exit, and always cleans up.
_REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "rel,content",
    [
        ("src/core/_brix_ns_probe.h", "int xrootd_probe_symbol;\n"),
        ("client/lib/_brix_ns_probe.h", "struct xrdc_probe { int x; };\n"),
    ],
)
def test_brix_namespace_guard_catches_drift(rel: str, content: str) -> None:
    probe = _REPO / rel
    probe.write_text(content)
    try:
        rc, out = _run("check_brix_namespace")
    finally:
        probe.unlink()
    assert rc != 0, f"guard missed injected residual in {rel}:\n{out}"
    assert "_brix_ns_probe" in out, out


# --- curl enum-ifdef guard: negatives + comment immunity ----------------------
# The green assertion above proves the tree is clean; these prove the guard
# bites on both anti-pattern forms (the 2026-08 asan-lane root cause: curl
# options are enum constants, so preprocessor tests on them are always false)
# and stays quiet on doc comments and legitimate CURL_AT_LEAST_VERSION gates.
@pytest.mark.parametrize(
    "content",
    [
        "#ifdef CURLOPT_PROBE_FAKE\ncurl_easy_setopt(c, CURLOPT_PROBE_FAKE, 1L);\n#endif\n",
        "#ifndef CURLINFO_PROBE_FAKE\n#error no\n#endif\n",
        "#if defined(CURLOPT_PROBE_FAKE) && defined(CURLOPT_OTHER_FAKE)\n#endif\n",
    ],
)
def test_curl_enum_ifdef_guard_catches_drift(content: str) -> None:
    probe = _REPO / "src/core/_curl_enum_probe.h"
    probe.write_text(content)
    try:
        rc, out = _run("check_curl_enum_ifdef")
    finally:
        probe.unlink()
    assert rc != 0, f"guard missed injected curl enum #ifdef:\n{out}"
    assert "_curl_enum_probe" in out, out


def test_curl_enum_ifdef_guard_ignores_comments_and_version_gates() -> None:
    probe = _REPO / "src/core/_curl_enum_probe.h"
    probe.write_text(
        "/* an always-false test like #ifdef CURLOPT_PROTOCOLS_STR or\n"
        " * defined(CURLOPT_XFERINFOFUNCTION) must be gated on the version */\n"
        "#if CURL_AT_LEAST_VERSION(7, 85, 0)\n"
        "curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, \"https\");\n"
        "#endif\n"
    )
    try:
        rc, out = _run("check_curl_enum_ifdef")
    finally:
        probe.unlink()
    assert rc == 0, f"guard false-positived on a comment or version gate:\n{out}"


# --- file-size guard: client/ coverage + client/tests carve-out --------------
# The green assertion above proves the live tree is clean; this proves the
# Phase-38 extension that widened the scan from src/ to *also* cover client/
# (the ngx-free CLI + libbrix) while excluding client/tests/. Driven off an
# injected temp tree via list_oversized(root=...), so it is hermetic and
# independent of whatever the real backlog currently freezes.

def test_file_size_guard_scans_client_and_excludes_client_tests(tmp_path) -> None:
    cfs = _load_check_file_size()
    big = "x();\n" * (cfs.CAP + 5)   # 605 newlines > cap
    small = "y();\n" * 10
    files = {
        "src/core/big_src.c": big,             # src offender  -> listed
        "client/apps/big_client.c": big,       # client offender -> listed (NEW)
        "client/lib/small_client.c": small,    # under cap -> absent
        "client/tests/c/big_test.c": big,      # excluded tree -> absent
        "client/tests/big_test.h": big,        # excluded tree -> absent
    }
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    listed = {path for path, _ in cfs.list_oversized(root=tmp_path)}
    def _assert_test_file_size_guard_scans_client_and_excludes_client_tests_1():
        assert "client/apps/big_client.c" in listed, "guard must now scan client/"
        assert "src/core/big_src.c" in listed, "guard must still scan src/"

    _assert_test_file_size_guard_scans_client_and_excludes_client_tests_1()
    def _assert_test_file_size_guard_scans_client_and_excludes_client_tests_2():
        assert "client/lib/small_client.c" not in listed
        assert "client/tests/c/big_test.c" not in listed, "client/tests/ must be carved out"

    _assert_test_file_size_guard_scans_client_and_excludes_client_tests_2()
    assert "client/tests/big_test.h" not in listed, "client/tests/ must be carved out"


# --- duplicate-recipe guard: negative + fail-closed ---------------------------
# The green assertion above proves the live Makefiles are clean (they were not
# until 2026-08-05: client/Makefile gave six objects two recipes each, and the
# copy make kept for apps/fs/brixautofs_ext.o was the one WITHOUT the
# apps/fs/brixautofs.h prerequisite, so editing that header left the object
# stale). These drive the guard's run(root=...) against a temp tree, so they
# neither depend on nor disturb the real Makefiles.

@pytest.mark.skipif(not _have("make"), reason="needs make to parse the Makefile")
def test_make_recipe_guard_catches_a_second_recipe(tmp_path) -> None:
    cmr = _load_check_make_recipes()
    _fake_tree(
        tmp_path,
        {
            "client": (
                "OBJS := a.o b.o\n"
                "$(OBJS): %.o: %.c hdr.h\n"
                "\t@echo first $<\n"
                "a.o: a.c\n"          # second recipe, and it drops hdr.h
                "\t@echo second $<\n"
                "all: $(OBJS)\n"
            )
        },
    )
    ok, msgs = cmr.run(tmp_path)
    assert not ok, "guard missed a target with two recipes"
    assert any("a.o" in m and "DUPLICATE RECIPE" in m for m in msgs), msgs


@pytest.mark.skipif(not _have("make"), reason="needs make to parse the Makefile")
def test_make_recipe_guard_passes_a_single_recipe(tmp_path) -> None:
    cmr = _load_check_make_recipes()
    _fake_tree(
        tmp_path,
        {
            "client": (
                "OBJS := a.o b.o\n"
                "$(OBJS): %.o: %.c hdr.h\n"
                "\t@echo only $<\n"
                "LINK_LIST := a.o b.o\n"   # a list that reuses the objects is fine
                "all: $(LINK_LIST)\n"
            )
        },
    )
    ok, msgs = cmr.run(tmp_path)
    assert ok, f"guard false-positived on a single-recipe Makefile: {msgs}"


@pytest.mark.skipif(not _have("make"), reason="needs make to parse the Makefile")
def test_make_recipe_guard_fails_closed_on_a_missing_makefile(tmp_path) -> None:
    """A Makefile that moved must redden the guard, not silently drop from it."""
    cmr = _load_check_make_recipes()
    _fake_tree(tmp_path, {})
    (tmp_path / cmr.MAKEFILES[0] / "Makefile").unlink()
    ok, msgs = cmr.run(tmp_path)
    assert not ok, "guard passed while one of its Makefiles was gone"
    assert any("MISSING" in m for m in msgs), msgs


# --- template-ref ratchet: negatives ------------------------------------------
# The green assertion above proves the frozen backlog matches the tree; these
# prove the ratchet turns only one way. A dead config template is the failure the
# 2026-08-04 coverage audit found 49 instances of: it reads as coverage that
# exists, so the next author copies it instead of the live `nginx_lc_*` twin.
#
# The probe names below are assembled from a stem + suffix rather than written
# out whole, because this file is itself inside the tree the guard greps: a
# literal `nginx_zz_....conf` here would BE a reference, and the probe would be
# considered live. That is the guard working correctly, and it is why the
# workaround belongs in the test rather than in an exclusion inside the guard.
_PROBE_1 = "nginx_zz_template_ref_probe" + ".conf"
_PROBE_2 = "nginx_zz_template_regen_probe" + ".conf"


def test_template_ref_guard_catches_a_new_dead_template() -> None:
    probe = _REPO / "tests" / "configs" / _PROBE_1
    probe.write_text("# nothing in the repo names this file\n")
    try:
        rc, out = _run("check_template_refs")
    finally:
        probe.unlink()
    assert rc != 0, f"guard missed a new unreferenced template:\n{out}"
    assert _PROBE_1 in out, out


def test_template_ref_guard_refuses_to_grow_its_own_backlog(tmp_path) -> None:
    """``--regen`` is the shrink handle; it must not be usable to bless a new
    dead template, which is the only way a ratchet quietly stops ratcheting."""
    probe = _REPO / "tests" / "configs" / _PROBE_2
    probe.write_text("# nothing in the repo names this file either\n")
    try:
        p = subprocess.run(
            [sys.executable, str(CI / "check_template_refs.py"), "--regen"],
            capture_output=True, text=True)
    finally:
        probe.unlink()
    assert p.returncode != 0, f"--regen blessed a new entry:\n{p.stdout}{p.stderr}"
    assert _PROBE_2 in p.stdout + p.stderr
    backlog = (CI / "template_refs_backlog.txt").read_text()
    assert _PROBE_2 not in backlog, (
        "refused --regen must leave the backlog untouched")


def test_template_ref_guard_reddens_on_a_stale_backlog_entry() -> None:
    """A backlog entry that got wired up (or deleted) must fail too — otherwise
    the frozen count drifts above the real one and the ratchet has slack."""
    tr = _load("check_template_refs")
    ok, messages, _ = tr.run()
    assert ok, messages
    stale = _REPO / "tests" / "test_zz_template_ref_stale_probe.py"
    frozen = tr._backlog()[0]
    stale.write_text(f'"""probe that names {frozen} so the backlog goes stale."""\n')
    try:
        rc, out = _run("check_template_refs")
    finally:
        stale.unlink()
    assert rc != 0, f"guard missed a stale backlog entry:\n{out}"
    assert frozen in out and "stale backlog entry" in out, out


# --- lizard-backed ratchets ---------------------------------------------------
# check_duplication runs lizard over three trees: ~18s on an 8-core CI runner
# but ~130s on a 4-core box, so the cap has to clear the slowest hardware we run
# on. (guards.yml invokes the guard directly, without this pytest timeout.)
@pytest.mark.skipif(not _have("lizard"), reason="lizard not installed (pip install --user lizard)")
@pytest.mark.timeout(300)
@pytest.mark.parametrize("guard", ["check_complexity", "check_duplication"])
def test_ci_lizard_guard_green(guard: str) -> None:
    rc, out = _run(guard)
    assert rc == 0, f"tools/ci/{guard}.py failed (exit {rc}):\n{out}"


# --- static-analysis / coverage runners (nightly) -----------------------------
# Need the configured build at /tmp/nginx-1.28.3 and an external analyzer; they
# run for minutes. Marked slow and self-skipping so the fast lane never pays for
# them, while ``run_suite --nightly`` still exercises the real Python runner.
_NGX_BUILD = Path("/tmp/nginx-1.28.3/objs/Makefile")


@pytest.mark.slow
@pytest.mark.timeout(1800)
@pytest.mark.parametrize(
    "runner,tool",
    [("run_fanalyzer", "gcc"), ("run_codechecker", "CodeChecker")],
)
def test_ci_analyzer_runner_green(runner: str, tool: str) -> None:
    if not _NGX_BUILD.exists():
        pytest.skip("configured nginx build tree absent (/tmp/nginx-1.28.3)")
    if not _have(tool):
        pytest.skip(f"{tool} not installed")
    rc, out = _run(runner)
    assert rc == 0, f"tools/ci/{runner}.py failed (exit {rc}):\n{out}"


@pytest.mark.slow
@pytest.mark.timeout(1800)
def test_ci_coverage_runner_green() -> None:
    # coverage.py self-skips (exit 0) when lcov/gcov or the build are absent, and
    # otherwise does a full instrumented build + suite run — nightly territory.
    rc, out = _run("coverage")
    assert rc == 0, f"tools/ci/coverage.py failed (exit {rc}):\n{out}"


# --- every guard is executable + reachable from guards.yml -------------------
# A guard is only as good as CI's ability to RUN it: `.github/workflows/guards.yml`
# invokes each one as a bare `tools/ci/check_*.py`, so a script committed without
# its mode bit fails with "Permission denied" and the check it owns silently stops
# being enforced. That is exactly how check_gridftp_interop_image.py stopped
# running (found 2026-08-03), and nothing in the suite would have caught it.



@pytest.mark.parametrize("script", _ci_guard_scripts(), ids=lambda p: p.name)
def test_ci_guard_script_is_executable(script: Path) -> None:
    assert os.access(script, os.X_OK), (
        f"{script.relative_to(CI.parents[1])} is not executable — guards.yml runs it "
        f"as a bare path, so it would fail with 'Permission denied' and stop "
        f"enforcing anything. Fix with: chmod +x {script.relative_to(CI.parents[1])}"
    )


def test_ci_guard_scripts_have_a_shebang(script_dir: Path = CI) -> None:
    """A bare `tools/ci/foo.py` invocation also needs the interpreter line."""
    missing = [
        p.name
        for p in _ci_guard_scripts()
        if not p.read_text().startswith("#!/usr/bin/env python3")
    ]
    assert not missing, f"guards missing a python3 shebang: {missing}"


# Guards that deliberately do NOT block CI. Each needs a reason: an exemption
# without one is how a guard quietly stops mattering. Currently empty — every
# tools/ci/check_*.py is wired into guards.yml. check_duplication.py was the last
# holdout (advisory-only while it carried a 100+ clone backlog); it joined the
# blocking set once that backlog was burned down to zero.
_NOT_IN_CI: set[str] = set()


def test_workflow_runs_every_guard_script() -> None:
    """Every tools/ci/check_*.py is wired into the guards workflow.

    A guard nobody invokes is documentation, not enforcement — this catches the
    other half of the same failure mode as the mode-bit test above."""
    wired = {p.name for p in _GUARD_SET.ci_guards()}
    unwired = [
        p.name for p in _ci_guard_scripts() if p.name not in wired | _NOT_IN_CI
    ]
    assert not unwired, (
        f"guards not referenced by .github/workflows/guards.yml: {unwired}"
    )


# --- python dependency guard: negatives ---------------------------------------
# The green assertion in the fast lane proves the tree is clean; these prove each
# of the three rules actually bites. Every case is a synthetic root, so nothing
# here depends on the real requirements files staying as they are today.
_DEPS = _load("check_python_deps")



def test_python_deps_guard_accepts_a_bounded_declared_tree(tmp_path) -> None:
    root = _deps_tree(
        tmp_path,
        "requests>=2.25,<3\n",
        "zstandard>=0.18,<1\n",
        "import pytest\nimport requests\n\nz = pytest.importorskip('zstandard')\n",
    )
    ok, findings = _DEPS.run(root)
    assert ok, findings


def test_python_deps_guard_rejects_a_one_sided_bound(tmp_path) -> None:
    """R2: an open-ended `>=` is how a new major enters CI unreviewed."""
    root = _deps_tree(tmp_path, "requests>=2.25\n", "", "import requests\n")
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("upper bound missing" in f for f in findings), findings


def test_python_deps_guard_rejects_an_undeclared_import(tmp_path) -> None:
    """R1: a package nobody wrote down is an ImportError in a fresh clone."""
    root = _deps_tree(tmp_path, "requests>=2.25,<3\n", "", "import paramiko\n")
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("paramiko" in f and "no requirements file" in f for f in findings), findings


def test_python_deps_guard_rejects_optional_imported_at_module_scope(tmp_path) -> None:
    """R3: the real bug this guard found — optional silently becoming required."""
    root = _deps_tree(
        tmp_path, "", "zstandard>=0.18,<1\n", "import zstandard\n"
    )
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("declared optional but imported" in f for f in findings), findings


def test_python_deps_guard_accepts_guarded_optional_imports(tmp_path) -> None:
    """A try/except or in-function import cannot break collection — allowed."""
    root = _deps_tree(
        tmp_path,
        "",
        "zstandard>=0.18,<1\n",
        "try:\n    import zstandard\nexcept ImportError:\n    zstandard = None\n\n"
        "def helper():\n    import zstandard as z\n    return z\n",
    )
    ok, findings = _DEPS.run(root)
    assert ok, findings


def test_python_deps_guard_checks_match_case_module_scope_imports(tmp_path) -> None:
    """An optional import in a match case still runs during collection."""
    root = _deps_tree(
        tmp_path,
        "",
        "zstandard>=0.18,<1\n",
        "match 1:\n    case 1:\n        import zstandard\n",
    )
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("zstandard" in f and "module scope" in f for f in findings), findings


# --- metric-name guard: the exposition is the only source of metric truth -----
# The 2026-08-09 doc sweep found five families the pages cited that no exporter
# emits, plus two label sets that were simply wrong. None of it errors in
# Prometheus — a name that matches nothing produces an empty result, so the
# alert never fires and the panel stays flat, which reads as "healthy". These
# prove the guard extracts the real surface and reddens on each drift shape.
_NAMES = _load("check_metric_names")

#: Mirrors the real exporters: HELP/TYPE in one merged literal, the row
#: template split across literals, a name-by-argument helper call, and a
#: config directive that shares the brix_ prefix without being a metric.
_PROBE_EXPORTER = r'''
static void
probe_emit(metrics_writer_t *mw, probe_shm_t *shm)
{
    mw_printf(mw,
        "# HELP brix_probe_ops_total Probe operations, by protocol.\n"
        "# TYPE brix_probe_ops_total counter\n");
    mw_printf(mw,
        "brix_probe_ops_total"
            "{proto=\"%s\",op=\"%s\"} %llu\n",
        proto_name, op_name, value);
    mw_emit_scalar(mw, "brix_probe_bytes_total", "Probe bytes.", &shm->bytes);
}

static ngx_command_t probe_commands[] = {
    { ngx_string("brix_probe_stage_seconds"), 0, NULL, 0, 0, NULL },
    ngx_null_command
};
'''


def _names_tree(tmp_path: Path, page: str) -> Path:
    """A minimal repo: one exporter, one operator-facing page."""
    expo = tmp_path / "src/observability/metrics"
    expo.mkdir(parents=True)
    (expo / "probe.c").write_text(_PROBE_EXPORTER)
    docs = tmp_path / "docs/08-metrics-monitoring"
    docs.mkdir(parents=True)
    (docs / "probe.md").write_text(page)
    return tmp_path


def _messages(root: Path) -> list[str]:
    return [message for _, message, _ in _NAMES.findings(root)]


def test_metric_names_extractor_reads_the_real_exposition() -> None:
    """Row templates are split across literals; the extractor must rejoin them.

    The three assertions after the histogram are the exact facts the doc sweep
    got wrong, pinned here against the C so a doc can never re-invent them."""
    families = _NAMES.exposition(_REPO)
    assert families["brix_io_ops_total"] == {"proto", "op", "status"}
    assert families["brix_io_latency_usec_bucket"] == {"proto", "op", "le"}
    assert "proto" not in families["brix_requests_total"]
    assert families["brix_auth_total"] == {"proto", "method", "status"}
    assert families["brix_tpc_transfers_total"] == {"proto", "direction", "status"}


@pytest.mark.parametrize(
    "invented",
    [
        "brix_bytes_sent_total",
        "brix_errors_total",
        "brix_fd_cache_hits_total",
        "brix_write_through_syncs_total",
        "brix_session_bind_total",
    ],
)
def test_metric_names_guard_catches_an_invented_family(tmp_path, invented) -> None:
    """Every family the sweep found cited but never emitted, one per case."""
    root = _names_tree(tmp_path, f"Alert on `{invented}` when it saturates.\n")
    assert _messages(root) == [f"unknown metric family {invented}"]


def test_metric_names_guard_catches_a_label_the_family_never_carries(tmp_path) -> None:
    """`brix_requests_total{proto=…}` shape: real family, imaginary label."""
    root = _names_tree(
        tmp_path, 'rate(brix_probe_ops_total{proto="s3",path="/data/x"}[5m])\n'
    )
    messages = _messages(root)
    assert len(messages) == 1, messages
    assert "carries no label 'path'" in messages[0]


def test_metric_names_allow_marker_cannot_launder_the_next_line(tmp_path) -> None:
    """The escape hatch is line-scoped — one reason cannot cover a whole page.

    A file-scoped opt-out is how a guard stops guarding: the first proposed
    metric would silence every invented one written after it."""
    root = _names_tree(
        tmp_path,
        "`brix_probe_planned_total` <!-- metric-names-allow: proposed, not built -->\n"
        "`brix_probe_smuggled_total` rides along on the exemption above.\n",
    )
    assert _messages(root) == ["unknown metric family brix_probe_smuggled_total"]


def test_metric_names_guard_leaves_c_symbols_and_directives_alone(tmp_path) -> None:
    """Most brix_* tokens in the docs are functions and directives, not metrics.

    `min(exp-now, 5min)` is real prose from src/auth/token/README.md: an
    adjacency-free PromQL match would flag the function name beside it."""
    root = _names_tree(
        tmp_path,
        "`brix_vfs_read()` goes through the seam; set `brix_probe_stage_seconds`\n"
        "to bound it. L2 entries live for `min(exp-now, 5min)`, keyed by\n"
        "`brix_token_cache_lookup()`.\n",
    )
    assert _messages(root) == []
