"""Static fail-closed contracts for worker privilege hardening.

These checks deliberately guard the control-flow seams which are difficult to
force portably at runtime: a denied capset syscall, an already-target-uid worker,
and the second hardening pass after setuid.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE = (ROOT / "src/auth/impersonate/lifecycle_worker.c").read_text()
PROCESS = (ROOT / "src/core/config/process.c").read_text()


def _function(source: str, name: str) -> str:
    """Return one C function body using balanced braces."""
    start = source.index(f"\n{name}(")
    opening = source.index("{", start)
    depth = 0
    for pos in range(opening, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : pos + 1]
    raise AssertionError(f"unterminated function: {name}")


def test_capset_failure_aborts_worker_hardening():
    body = _function(LIFECYCLE, "imp_worker_prepare_drop")
    failure = body[body.index("if (brix_plat_capset") :]
    failure = failure[: failure.index("/* Best-effort bounding-set")]
    assert "return NGX_ERROR;" in failure
    assert "continuing" not in failure


def test_terminal_shed_zeros_and_verifies_every_capability_word():
    body = _function(LIFECYCLE, "imp_worker_drop_all_caps")
    assert body.index("ngx_memzero(data") < body.index("brix_plat_capset")
    assert body.index("brix_plat_capset") < body.index("brix_plat_capget")
    assert "data[i].effective != 0" in body
    assert "data[i].permitted != 0" in body
    assert "data[i].inheritable != 0" in body


def test_single_process_and_already_target_paths_are_terminally_confined():
    process = _function(PROCESS, "ngx_stream_brix_init_process")
    assert process.index("brix_imp_worker_harden") < process.index(
        "brix_imp_worker_deescalate"
    )
    assert process.index("brix_imp_worker_deescalate") < process.index(
        "brix_crypto_init"
    )
    assert process.index("brix_imp_worker_deescalate") < process.index(
        "brix_init_stage_engine_worker"
    )
    assert "if (brix_imp_init_worker(cycle) != NGX_OK)" in process
    deescalate = _function(LIFECYCLE, "brix_imp_worker_deescalate")
    exempt = deescalate[: deescalate.index("imp_worker_resolve_target")]
    assert "ngx_process == NGX_PROCESS_SINGLE" in exempt
    assert "return NGX_ERROR;" in exempt
    shortcut = deescalate[deescalate.index("getuid() == tgt_uid") :]
    assert "return imp_worker_finish_target(log, acct, tgt_uid, tgt_gid);" in shortcut
    finish = _function(LIFECYCLE, "imp_worker_finish_target")
    assert finish.index("imp_worker_groups_allowed") < finish.index(
        "imp_worker_drop_all_caps"
    )
    assert "brix_plat_setresgid(target_gid, target_gid, target_gid)" in finish
    assert "brix_plat_setresuid(target_uid, target_uid, target_uid)" in finish
    apply_drop = _function(LIFECYCLE, "imp_worker_apply_drop")
    terminal = apply_drop[apply_drop.index("imp_worker_drop_all_caps") :]
    assert terminal.index("return NGX_ERROR;") < terminal.index("return NGX_OK;")


def test_default_worker_identity_is_fail_closed():
    default_identity = _function(LIFECYCLE, "imp_worker_current_identity_safe")
    assert "imp_worker_current_ids(&uid, &gid)" in default_identity
    assert "getpwuid(uid)" in default_identity
    assert "pw->pw_gid != gid" in default_identity
    assert "imp_worker_groups_allowed(pw->pw_name, gid) == 1" in default_identity
