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
    body = (_cmd("brix_storage_backend", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                 "ngx_conf_set_str_slot")
            + _cmd("brix_storage_backend", "NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "clean.c", body)
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
    body = (_cmd("brix_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                 "ngx_conf_set_str_slot")
            + _cmd("brix_webdav_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "twin.c", body)
    r = _run(src, fail=True)
    assert r.returncode == 1, f"expected R2 failure:\n{r.stdout}"
    assert "[R2]" in r.stdout and "brix_webdav_token_issuer" in r.stdout, r.stdout


def test_r2_silenced_only_with_allowlist_reason(tmp_path):
    body = (_cmd("brix_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                 "ngx_conf_set_str_slot")
            + _cmd("brix_webdav_token_issuer", "NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1",
                   "ngx_conf_set_str_slot"))
    src = _write(tmp_path, "twin.c", body)

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
