"""Tests for tools/ci/check_directive_registry.py — the phase-101 W9.1 CI guard
that makes config-surface drift structurally visible.

Each case points the checker at a tiny FIXTURE src-tree (via BRIX_REGISTRY_SRC)
so the assertions are hermetic and independent of the real tree's current state:

  * success       — a clean two-plane fixture (one bare name on http, the same
                    name on stream — the GOOD cross-plane case) produces no
                    R1/R2 gating finding.
  * error (R1)    — the same name registered twice on ONE plane fails --fail
                    citing R1 (the SciTags-on-S3 bug class).
  * error (R2)    — brix_webdav_X beside a bare brix_X fails --fail citing R2
                    unless allowlisted.
  * tamper pin    — an allowlist line without a '# reason' is itself a failure,
                    so a rule cannot be silenced by a bare name.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER = os.path.join(ROOT, "tools", "ci", "check_directive_registry.py")


def _run(src_dir, *, allowlist=None, docs=None, fail=False):
    env = dict(os.environ)
    env["BRIX_REGISTRY_SRC"] = str(src_dir)
    env["BRIX_REGISTRY_ALLOWLIST"] = str(allowlist) if allowlist else os.devnull
    env["BRIX_REGISTRY_DOCS"] = str(docs) if docs else os.devnull
    argv = [sys.executable, CHECKER] + (["--fail"] if fail else [])
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)


def _cmd(name, ctx, setter="ngx_conf_set_flag_slot"):
    return (f'{{ ngx_string("{name}"),\n'
            f'  {ctx}, {setter},\n'
            f'  NGX_HTTP_LOC_CONF_OFFSET, 0, NULL }},\n')


def _write(tmp_path, filename, body):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / filename).write_text(
        "static ngx_command_t t[] = {\n" + body + "  ngx_null_command\n};\n")
    return src


def test_clean_cross_plane_ok(tmp_path):
    # Same name on BOTH planes is the intended "one spelling, both planes" case —
    # must NOT trip R1.
    # phase-105 R5: the HTTP-side bare registration must sit on the common
    # owner path (any other home is exactly the drift R5 exists to flag).
    _write_at(tmp_path, "core/config/http_common.c",
              _cmd("brix_storage_backend", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "clean.c",
                 _cmd("brix_storage_backend",
                      "NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1",
                      "ngx_conf_set_str_slot"))
    r = _run(src, fail=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[R1]" not in r.stdout, r.stdout


def test_same_plane_duplicate_fails_r1(tmp_path):
    # The W1 bug shape: one name registered twice on the SAME plane.
    body = (_cmd("brix_dup_knob", "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG")
            + _cmd("brix_dup_knob", "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG"))
    src = _write(tmp_path, "dup.c", body)
    r = _run(src, fail=True)
    assert r.returncode == 1, f"expected R1 failure, got rc=0:\n{r.stdout}"
    assert "[R1]" in r.stdout and "brix_dup_knob" in r.stdout, r.stdout


def test_prefixed_twin_fails_r2(tmp_path):
    _write_at(tmp_path, "core/config/http_common.c",
              _cmd("brix_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "twin.c",
                 _cmd("brix_webdav_token_issuer",
                      "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                      "ngx_conf_set_str_slot"))
    r = _run(src, fail=True)
    assert r.returncode == 1, f"expected R2 failure:\n{r.stdout}"
    assert "[R2]" in r.stdout and "brix_webdav_token_issuer" in r.stdout, r.stdout


def test_r2_silenced_only_with_allowlist_reason(tmp_path):
    _write_at(tmp_path, "core/config/http_common.c",
              _cmd("brix_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "twin.c",
                 _cmd("brix_webdav_token_issuer",
                      "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                      "ngx_conf_set_str_slot"))

    # allowlist WITH a reason → silenced, passes.
    good = tmp_path / "allow_ok.txt"
    good.write_text("brix_webdav_token_issuer  # W4 rename backlog -> brix_token_issuer\n")
    r = _run(src, allowlist=good, fail=True)
    assert r.returncode == 0, f"reasoned allowlist should silence R2:\n{r.stdout}"

    # allowlist WITHOUT a reason → tamper pin fails.
    bad = tmp_path / "allow_bad.txt"
    bad.write_text("brix_webdav_token_issuer\n")
    r = _run(src, allowlist=bad, fail=True)
    assert r.returncode == 1, "bare allowlist line must fail (tamper pin)"
    assert "ALLOWLIST" in r.stdout, r.stdout


def test_macro_expansion_counted(tmp_path):
    # A BRIX_*_DIRECTIVES definition + instantiation must contribute bare names,
    # so a same-plane dup of a macro-generated name is caught too.
    src = tmp_path / "src"
    src.mkdir()
    (src / "macro.h").write_text(
        "#define BRIX_DEMO_DIRECTIVES(pfx, conf_t, ctx, off) \\\n"
        '    { ngx_string(pfx "demo_knob"), ctx | NGX_CONF_FLAG, '
        "ngx_conf_set_flag_slot, off, 0, NULL },\n")
    (src / "use.c").write_text(
        'BRIX_DEMO_DIRECTIVES("brix_", c_t, NGX_HTTP_LOC_CONF, 0)\n'
        + "static ngx_command_t t[] = {\n"
        + _cmd("brix_demo_knob", "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG")
        + "  ngx_null_command\n};\n")
    r = _run(src, fail=True)
    assert r.returncode == 1, f"macro name + literal dup should trip R1:\n{r.stdout}"
    assert "brix_demo_knob" in r.stdout, r.stdout


def test_real_tree_no_r1(tmp_path):
    """The real src/ tree must have ZERO R1 same-plane duplicates (the invariant
    W1 restored). Uses the checked-in allowlist; R2/R3/R4 stay WARN here."""
    r = subprocess.run([sys.executable, CHECKER], capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "\n[R1]" not in r.stdout, \
        f"real tree grew a same-plane duplicate:\n{r.stdout}"


# ---- phase-105 W5.2/W5.3: R5 (bare => common owner) + R6 (near-miss stems) --


def _write_at(tmp_path, relpath, body):
    p = tmp_path / "src" / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "static ngx_command_t t[] = {\n" + body + "  ngx_null_command\n};\n")
    return tmp_path / "src"


def test_r5_bare_name_outside_common_owner_fails(tmp_path):
    # The pre-105-W1 shape: a bare cross-protocol name registered by a
    # protocol module — R5 must trip (this exact shape made brix_rate_limit
    # silently inert on S3).
    src = _write_at(tmp_path, "protocols/webdav/module_commands.c",
                    _cmd("brix_shiny_knob", "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG"))
    r = _run(src, fail=True)
    assert r.returncode == 1, r.stdout
    assert "[R5]" in r.stdout and "brix_shiny_knob" in r.stdout, r.stdout


def test_r5_common_owner_and_feature_family_ok(tmp_path):
    # The same bare name on the common module passes; a feature-prefixed
    # family owned by its feature module passes too.
    _write_at(tmp_path, "core/config/http_common.c",
              _cmd("brix_shiny_knob", "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG"))
    src = _write_at(tmp_path, "observability/dashboard/module.c",
                    _cmd("brix_dashboard_widget",
                         "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG"))
    r = _run(src, fail=True)
    assert "[R5]" not in r.stdout, r.stdout
    assert r.returncode == 0, r.stdout


def test_r6_near_miss_stems_fail(tmp_path):
    # brix_webdav_maxdelay vs brix_max_delay — the W3 drift class: different
    # spellings, one normalized stem. R6 must trip.
    src = _write_at(tmp_path, "core/config/http_common.c",
                    _cmd("brix_max_delay", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1")
                    + _cmd("brix_webdav_maxdelay",
                           "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1"))
    r = _run(src, fail=True)
    assert r.returncode == 1, r.stdout
    assert "[R6]" in r.stdout and "maxdelay" in r.stdout, r.stdout


def test_real_tree_gates_clean_under_fail():
    """phase-105 W5.4: the real tree passes --fail (R1/R2/R4/R5/R6 all clean
    with the checked-in allowlist; R3 is WARN-scoped until W6)."""
    r = subprocess.run([sys.executable, CHECKER, "--fail"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr


# ---------------------------------------------------------------------------
# phase-106 W8 — the VARIABLE rules (R7 naming, R9 plane parity, R10 exposure)
# ---------------------------------------------------------------------------

def _write_vars(tmp_path, relpath, rows, kind="http"):
    """A fixture source registering an nginx variable array."""
    p = tmp_path / "src" / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f'    {{ ngx_string("{n}"), NULL, h_{i}, 0, 0, 0 }},\n'
                   for i, n in enumerate(rows))
    p.write_text(
        f"static ngx_{kind}_variable_t v[] = {{\n{body}"
        f"      ngx_{kind}_null_variable\n}};\n")
    return tmp_path / "src"


def test_r7_unprefixed_variable_is_flagged(tmp_path):
    """An unprefixed variable sits in nginx's global namespace and collides
    with any other module registering the same name."""
    src = _write_vars(tmp_path, "protocols/x/mod.c", ["cvmfs_cache"])
    r = _run(src)
    assert "[R7]" in r.stdout, r.stdout
    assert "cvmfs_cache" in r.stdout


def test_r7_prefixed_variable_is_clean(tmp_path):
    """(non-vacuity) The rule must not fire on a correctly named variable."""
    src = _write_vars(tmp_path, "core/http/http_variables.c",
                      ["brix_cache_status", "brix_tls"])
    r = _run(src)
    assert "[R7]" not in r.stdout, r.stdout


def test_r9_same_plane_duplicate_is_flagged(tmp_path):
    """Two registrations of one name on ONE plane is a duplicate-variable
    config error at nginx startup."""
    _write_vars(tmp_path, "protocols/a/mod.c", ["brix_thing"])
    src = _write_vars(tmp_path, "protocols/b/mod.c", ["brix_thing"])
    r = _run(src)
    assert "[R9]" in r.stdout, r.stdout


def test_r9_cross_plane_same_name_is_the_goal(tmp_path):
    """(non-vacuity, and the rule's whole point) The SAME name on the http and
    stream planes is plane parity — what lets one log_format field mean the
    same thing everywhere. It must NOT be flagged."""
    _write_vars(tmp_path, "protocols/webdav/module_init.c", ["brix_protocol"])
    src = _write_vars(tmp_path, "protocols/root/stream/stream_variables.c",
                      ["brix_protocol"], kind="stream")
    r = _run(src)
    assert "[R9]" not in r.stdout, r.stdout


def test_r10_credential_shaped_variable_is_refused(tmp_path):
    """Security rule: a variable is loggable and copyable into an upstream
    header, so a credential-shaped name must never be registered."""
    src = _write_vars(tmp_path, "protocols/x/mod.c", ["brix_bearer_token"])
    r = _run(src)
    assert "[R10]" in r.stdout, r.stdout
    assert "brix_bearer_token" in r.stdout


def test_r10_is_not_trivially_evadable(tmp_path):
    """(security-neg) Near-miss spellings must still trip R10 — a rule that
    only caught the exact word would be worthless."""
    for name in ("brix_secret_thing", "brix_client_key", "brix_macaroon_x",
                 "brix_authorization_hdr"):
        src = _write_vars(tmp_path, "protocols/x/mod.c", [name])
        r = _run(src)
        assert "[R10]" in r.stdout, f"{name} slipped past R10:\n{r.stdout}"


def test_r10_actually_gates_the_process_under_fail(tmp_path):
    """(security, regression for the 'detected but not gating' bug) R10 is a
    SECURITY rule, so a credential-shaped variable must fail the CI process
    (exit 1) under --fail, not merely print a WARN line.

    The bug this pins: R10 findings were computed and printed, but R10 was NOT
    in the checker's gating set, so `check_directive_registry.py --fail` still
    returned 0 with a credential-shaped variable present. WARN-mode coverage
    (the cells above) cannot catch that — only asserting the exit code does.
    """
    src = _write_vars(tmp_path, "protocols/x/mod.c", ["brix_bearer_token"])
    r = _run(src, fail=True)
    assert r.returncode == 1, (
        "R10 did not gate under --fail (a credential-shaped variable passed "
        f"CI): rc={r.returncode}\n{r.stdout}\n{r.stderr}")
    assert "[R10]" in r.stdout, r.stdout


def test_r7_and_r9_also_gate_under_fail(tmp_path):
    """(regression) R7 (naming) and R9 (same-plane duplicate) gate too — they
    landed in the same gating-set fix as R10, so pin them the same way."""
    # R7: an unprefixed variable.
    src = _write_vars(tmp_path, "protocols/x/mod.c", ["cvmfs_cache"])
    assert _run(src, fail=True).returncode == 1, "R7 did not gate"
    # R9: one name registered twice on one plane.
    _write_vars(tmp_path, "protocols/a/mod.c", ["brix_thing"])
    src = _write_vars(tmp_path, "protocols/b/mod.c", ["brix_thing"])
    assert _run(src, fail=True).returncode == 1, "R9 did not gate"


def test_r10_allows_the_one_reviewed_exception(tmp_path):
    """$brix_delegated_cred predates the rule and exists to hand a delegated
    credential to proxy_ssl_certificate; it is the single allowlisted entry."""
    src = _write_vars(tmp_path, "protocols/webdav/module_init.c",
                      ["brix_delegated_cred"])
    r = _run(src)
    assert "[R10]" not in r.stdout, r.stdout


# ---------------------------------------------------------------------------
# phase-110 W5: the uniform-vocabulary rules R11 (parity) / R12 (shared
# vocabulary) / R13 (cross-surface key parity).
# ---------------------------------------------------------------------------

import importlib.util as _ilu


def _load_checker():
    """Import check_directive_registry as a module so R12/R13's detectors
    (which scan fixed real-tree files) can be unit-tested with temp inputs."""
    spec = _ilu.spec_from_file_location("cdr", CHECKER)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_r11_requires_a_fact_on_both_planes(tmp_path):
    """(error) A PARITY_FACT registered on the http plane only fails --fail
    citing R11 — the switching-between-planes defect this phase removes."""
    # brix_op is a parity fact; register it on ONE plane (an http source).
    src = _write_vars(tmp_path, "core/http/http_variables.c", ["brix_op"])
    r = _run(src, fail=True)
    assert r.returncode == 1, f"R11 did not gate a single-plane fact:\n{r.stdout}"
    assert "[R11]" in r.stdout and "brix_op" in r.stdout, r.stdout


def test_r11_r12_r13_pass_on_the_real_tree():
    """(success) The real tree satisfies all three uniform-vocabulary rules —
    the post-W4 state. Runs the checker against the REAL sources (no
    BRIX_REGISTRY_SRC override) so it exercises the shipped tree."""
    env = dict(os.environ)
    env.pop("BRIX_REGISTRY_SRC", None)
    env.pop("BRIX_REGISTRY_ALLOWLIST", None)
    env.pop("BRIX_REGISTRY_DOCS", None)
    r = subprocess.run([sys.executable, CHECKER, "--fail"],
                       capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, (
        f"the real tree fails a gating registry rule:\n{r.stdout}\n{r.stderr}")
    for rule in ("[R11]", "[R12]", "[R13]"):
        assert rule not in r.stdout, f"{rule} finding on the real tree:\n{r.stdout}"


def test_r12_detector_flags_inline_cache_vocabulary(tmp_path):
    """(error) A variable-handler file that hand-spells a cache word ("HIT")
    instead of calling brix_metric_cache_status_name is an R12 finding."""
    cdr = _load_checker()
    f = tmp_path / "handler.c"
    # Calls every required name fn (so only the literal trips it).
    f.write_text(
        'x = brix_metric_cache_status_name(s);\n'
        'y = brix_metric_op_name(o); z = brix_metric_err_name(e);\n'
        'w = brix_metric_auth_method_name(a);\n'
        'return v == 1 ? "HIT" : "MISS";\n')
    findings = cdr._vocab_findings_for(os.path.relpath(f, cdr.ROOT))
    assert any('"HIT"' in msg for _, _, msg in findings), findings


def test_r12_detector_flags_a_missing_name_function(tmp_path):
    """(error) A handler file that renders a shared fact without the name
    function is an R12 finding."""
    cdr = _load_checker()
    f = tmp_path / "handler.c"
    f.write_text('return brix_metric_op_name(o);\n')  # missing the other 3
    findings = cdr._vocab_findings_for(os.path.relpath(f, cdr.ROOT))
    assert any("brix_metric_cache_status_name" in msg for _, _, msg in findings)


def test_r13_detector_flags_a_missing_json_key(tmp_path):
    """(error) The cross-surface pin fires when a canonical JSON key is absent
    — i.e. a fact whose JSON key does not match its $brix_ variable name."""
    cdr = _load_checker()
    f = tmp_path / "access_log.c"
    f.write_text('log("{\\"from_cache\\":%s}");\n')   # old key only, no cache_status
    missing = cdr._missing_tokens(os.path.relpath(f, cdr.ROOT),
                                  cdr._R13_REQUIRED_JSON_KEYS)
    assert r'\"cache_status\":' in missing, missing


def test_r13_detector_is_not_vacuous(tmp_path):
    """(meta) The token check really passes when the canonical keys ARE
    present, so the real-tree success above is meaningful."""
    cdr = _load_checker()
    f = tmp_path / "access_log.c"
    f.write_text('log("{\\"cache_status\\":\\"%s\\",\\"sub\\":\\"%s\\",'
                 '\\"bytes_served\\":%d,\\"backend_time_us\\":%d}");\n')
    missing = cdr._missing_tokens(os.path.relpath(f, cdr.ROOT),
                                  cdr._R13_REQUIRED_JSON_KEYS)
    assert missing == [], missing


def test_r14_dormant_while_removal_phase_is_unwritten(tmp_path):
    """(success) R14 is silent while a deprecated alias's removal phase does not
    exist yet — the deprecation window is open, the alias is allowed."""
    cdr = _load_checker()
    import directive_registry_w5 as w5
    w5._REFACTOR_DOCS = str(tmp_path / "empty")  # no phase-112 doc
    variables = [("brix_session_dn", "src/protocols/root/stream/x.c")]
    allow = {"brix_session_dn": "removal: phase-112 — alias of brix_dn"}
    assert cdr._rule_r14(variables, allow) == [], "R14 fired with no removal doc"


def test_r14_fires_when_removal_phase_is_implemented(tmp_path):
    """(error) The self-deleting pin: once the removal phase's doc is marked
    IMPLEMENTED and the alias is still registered, R14 fails — forcing the
    cleanup at exactly the moment it is due."""
    import directive_registry_w5 as w5
    cdr = _load_checker()
    docs = tmp_path / "refactor"
    docs.mkdir()
    (docs / "phase-112-cleanup.md").write_text("# 112\n**Status:** IMPLEMENTED\n")
    w5._REFACTOR_DOCS = str(docs)
    variables = [("brix_session_dn", "src/protocols/root/stream/x.c")]
    allow = {"brix_session_dn": "removal: phase-112 — alias of brix_dn"}
    findings = cdr._rule_r14(variables, allow)
    assert len(findings) == 1 and findings[0][0] == "R14", findings
    # And it stays silent once the alias is actually removed.
    assert cdr._rule_r14([], allow) == [], "R14 fired for an unregistered alias"


def test_r14_dormant_while_removal_phase_is_only_planned(tmp_path):
    """(security-neg / non-vacuity) A removal phase still marked PLANNED does NOT
    trip the pin — the window is open until the phase actually lands, so R14
    never blocks a legitimate deprecation window."""
    import directive_registry_w5 as w5
    cdr = _load_checker()
    docs = tmp_path / "refactor"
    docs.mkdir()
    (docs / "phase-112-cleanup.md").write_text("# 112\n**Status:** PLANNED\n")
    w5._REFACTOR_DOCS = str(docs)
    variables = [("brix_session_dn", "src/protocols/root/stream/x.c")]
    allow = {"brix_session_dn": "removal: phase-112 — alias of brix_dn"}
    assert cdr._rule_r14(variables, allow) == [], "R14 fired on a PLANNED phase"


def test_r14_passes_on_the_real_tree():
    """(success) phase-112 does not exist yet, so every $brix_session_* alias is
    within its window and the real tree is clean under --fail."""
    env = dict(os.environ)
    for k in ("BRIX_REGISTRY_SRC", "BRIX_REGISTRY_ALLOWLIST",
              "BRIX_REGISTRY_DOCS", "BRIX_REGISTRY_REFACTOR_DOCS"):
        env.pop(k, None)
    r = subprocess.run([sys.executable, CHECKER, "--fail"],
                       capture_output=True, text=True, env=env, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "[R14]" not in r.stdout, r.stdout
