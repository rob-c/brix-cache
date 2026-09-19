"""test_phase115_vfs_policy_model.py — phase-115 W9.5.

WHAT: Drives tests/c/vfs_policy_model_test.c, an EXHAUSTIVE model check of the
      typed VFS mutation-policy kernel (src/fs/vfs/vfs_policy.c): five sweeps
      that each enumerate a whole 32-bit axis and assert a CLOSED-FORM count,
      plus four structural checks.  Then it mutation-tests the checker itself —
      eleven weakenings of the kernel must each be caught, by the check that
      owns it.

WHY:  INVARIANT #12 makes a claim about EVERY mutation the server can be asked
      to perform.  The kernel is pure and its inputs are 32-bit words, so
      "formal verification" here needs no solver: enumerating the domain IS the
      proof, and unlike a solver it keeps running in CI.

      The three MAGIC-CONSTANT mutants at the foot of this file are the whole
      reason W9.5 exists, and they were measured before it was written.  The
      phase-105 unit (tests/c/test_vfs_mutation_policy.c) is already mutation-
      adequate against every STRUCTURAL weakening — it kills all eight — so a
      second hand-written property checker would have bought nothing.  What it
      cannot kill, because it samples, is a kernel that opens for exactly one
      smuggled value: policy word 0x5AFE, operation word 4242, one write-shaped
      flag word.  All three survive the phase-105 unit and all three die on the
      sweep.  That gap, and only that gap, is what this suite adds.

HOW:  Compile the checker against the shipped kernel and require ALL PASSED and
      each check's own PASS line; compile it against each mutant and require a
      non-zero exit from the owning check.  Sweeps are named individually
      (`--sweep=policy` ...) so a mutant pays only for the sweep that can see
      it, and so a sweep that costs 136 s can carry `slow` while the structural
      half stays in the PR tier.

Needs no server, no fleet and no port: the kernel is pure.  Skips cleanly
without a C compiler or the nginx source tree.

Run: PYTHONPATH=tests python3 -m pytest tests/test_phase115_vfs_policy_model.py -v
"""

import os
import re
import shutil
import subprocess

import pytest

from cmdscripts.compile_run import PLATFORM_HOST_FLAGS

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX_SRC = os.environ.get("TEST_NGINX_SRC", "/tmp/nginx-1.28.3")
CC = os.environ.get("CC", "cc")

MODEL_C = os.path.join(REPO, "tests/c/vfs_policy_model_test.c")
POLICY_C = os.path.join(REPO, "src/fs/vfs/vfs_policy.c")
PHASE105_UNIT_C = os.path.join(REPO, "tests/c/test_vfs_mutation_policy.c")

# ── what the checker must prove ───────────────────────────────────────────
#
# Each sweep's PASS line names the size of the set it enumerated, and those
# sizes are closed forms, not observations:
#
#   policy — exactly ONE of 2^32 policy words is BRIX_VFS_MUTATION_ALLOWED, so
#            exactly one opens.  READ_ONLY is 0, which is what an unmerged or
#            zeroed config carries, so the gate fails closed by construction.
#   ops    — the vocabulary is BRIX_VFS_MUTATE_OP_COUNT wide and everything
#            outside it is EINVAL, never a policy denial.
#   flags  — 2^32 / 4 accmodes / 8 creation-bit combinations = 2^27 flag words
#            are provably read-only.  Pinning the count is what makes this a
#            proof rather than a spot check: a classifier that widened by one
#            bit would still "pass" a sampled test.
#   forms  — all five decision forms agree on the same single opening word.
#   derive — deriving an op ctx normalises and never widens.
#
# Measured 2026-09-07, -O2, one core: policy 5.6 s, ops 16.7 s, flags 2.2 s,
# forms 135.7 s, derive 10.1 s.  `forms` is the one that decides the timeout,
# because it runs all five decision forms over the same 2^32 axis.
SWEEPS = {
    "policy": "PASS S1 exhaustive policy axis: 1 of 4294967296 words opens",
    "ops": ("PASS S2 exhaustive operation axis: 16 of 4294967296 words in "
            "vocabulary"),
    "flags": ("PASS S3 exhaustive open-flag axis: 134217728 of 4294967296 "
              "words are provably read-only"),
    "forms": ("PASS S4 exhaustive form agreement: all 5 forms open on the "
              "same 1 of 4294967296 words"),
    "derive": ("PASS S5 exhaustive derivation: 1 of 4294967296 allow_write "
               "values opens, 0 widened"),
}

STRUCTURAL = {
    "T1": "NULL and unconfined inputs fail closed, in that order",
    "T2": "one denial per refusal, none per success or bad input",
    "T3": "kernel pure: forward and reverse sweeps identical",
    "T4": "16 operation labels, all distinct",
}

# ── the mutation table ────────────────────────────────────────────────────
#
# (needle, replacement, sweep needed to see it, checks that MUST object).
# The killer sets are MEASURED, not predicted: every mutant was run against
# every check before this table was written.  A mutant listed against the
# wrong check would let the owning check go vacuous unnoticed, which is the
# failure mode this whole suite exists to refuse.
_POLICY_GATE = ("    if (policy != BRIX_VFS_MUTATION_ALLOWED) {\n"
                "        errno = EROFS;")
_OP_RANGE = ("    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT) {\n"
             "        errno = EINVAL;\n        return NGX_ERROR;\n    }")
_NULL_CTX = ("    if (ctx == NULL) {\n        errno = EINVAL;\n"
             "        return NGX_ERROR;\n    }\n\n"
             "    if (brix_vfs_require_mutation_policy(ctx->mutation_policy, op)")
_CONFINED = ("    if (brix_vfs_require_confined(ctx) != NGX_OK) {\n"
             "        return NGX_ERROR;\n    }")

MUTANTS = {
    "non_exact_policy_opens_the_endpoint": (
        _POLICY_GATE,
        "    if (policy == BRIX_VFS_MUTATION_READ_ONLY) {\n"
        "        errno = EROFS;",
        "policy", {"S1"}),
    "refusal_answers_eacces_instead_of_erofs": (
        _POLICY_GATE,
        "    if (policy != BRIX_VFS_MUTATION_ALLOWED) {\n"
        "        errno = EACCES;",
        "policy", {"S1"}),
    "pure_kernel_drops_its_range_check": (
        _OP_RANGE,
        "    if (0) {\n        errno = EINVAL;\n        return NGX_ERROR;\n    }",
        "ops", {"S2"}),
    "null_context_is_permitted": (
        _NULL_CTX,
        "    if (ctx == NULL) {\n        return NGX_OK;\n    }\n\n"
        "    if (brix_vfs_require_mutation_policy(ctx->mutation_policy, op)",
        None, {"T1"}),
    "op_ctx_copies_the_policy_verbatim": (
        "    export_op_ctx->mutation_policy = (policy == BRIX_VFS_MUTATION_ALLOWED)\n"
        "        ? BRIX_VFS_MUTATION_ALLOWED : BRIX_VFS_MUTATION_READ_ONLY;",
        "    export_op_ctx->mutation_policy = policy;",
        "derive", {"S5"}),
    "open_flag_classifier_ignores_o_append": (
        "    return (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0 ? 1 : 0;",
        "    return (flags & (O_CREAT | O_TRUNC)) != 0 ? 1 : 0;",
        "flags", {"S3"}),
    "denials_go_uncounted": (
        "    brix_metric_vfs_mutation_denied(proto, (ngx_uint_t) op);",
        "    (void) proto;",
        None, {"T2"}),
    "unconfined_path_answered_with_the_write_posture": (
        _CONFINED,
        "    if (brix_vfs_require_confined(ctx) != NGX_OK) {\n"
        "        errno = EROFS;\n        return NGX_ERROR;\n    }",
        None, {"T1"}),
}

# The three the phase-105 unit cannot see.  Each opens the gate for exactly one
# value out of 2^32 — the shape a sampled test is structurally unable to refute,
# and the shape a backdoor takes.
SMUGGLERS = {
    "a_magic_policy_word_opens_every_export": (
        _POLICY_GATE,
        "    if (policy == 0x5AFE) {\n        return NGX_OK;\n    }\n\n"
        + _POLICY_GATE,
        "policy", {"S1"}),
    "a_magic_operation_word_escapes_the_vocabulary": (
        _OP_RANGE,
        "    if ((ngx_uint_t) op == 4242) {\n        return NGX_OK;\n    }\n\n"
        + _OP_RANGE,
        "ops", {"S2"}),
    "one_write_shaped_flag_word_is_classified_read_only": (
        "    if ((flags & O_ACCMODE) != O_RDONLY) {\n        return 1;\n    }",
        "    if (flags == (O_WRONLY | O_CREAT | O_NOCTTY)) {\n"
        "        return 0;\n    }\n\n"
        "    if ((flags & O_ACCMODE) != O_RDONLY) {\n        return 1;\n    }",
        "flags", {"S3"}),
}


# ── build/run plumbing ────────────────────────────────────────────────────

def _skip_unless_buildable():
    if not shutil.which(CC):
        pytest.skip(f"no C compiler ({CC})")
    if not os.path.isfile(os.path.join(NGINX_SRC, "src/core/ngx_config.h")):
        pytest.skip(f"nginx source tree not at {NGINX_SRC} (set TEST_NGINX_SRC)")


def _inc_flags():
    subs = ["src/core", "src/event", "src/event/modules", "src/os/unix",
            "objs", "src/stream"]
    return ([f"-I{os.path.join(NGINX_SRC, s)}" for s in subs]
            + [f"-I{os.path.join(REPO, 'src')}",
               f"-I{os.path.join(REPO, 'shared')}",
               # A mutant is compiled from a temp directory, so the kernel's
               # own quote-relative includes need their home named.
               f"-I{os.path.join(REPO, 'src/fs/vfs')}"])


def _build(driver_c, policy_c, out_bin):
    """Compile one driver against one policy kernel.  None on a build failure."""
    # The kernel reaches platform/platform.h, which selects its <host>/host.h
    # from -DBRIX_PLATFORM_HOST alone and #errors without it (INVARIANT 14).
    # ./config passes it for the module build; a line assembled here has to
    # say it too, or every mutant "fails to build" for the same wrong reason.
    cmd = [CC, "-O2", "-D_GNU_SOURCE", "-w", *PLATFORM_HOST_FLAGS, *_inc_flags(),
           "-o", str(out_bin), str(driver_c), str(policy_c)]
    build = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                           cwd=REPO)
    return None if build.returncode != 0 else build.stderr


def _run(binary, sweep=None):
    argv = [str(binary)] + ([f"--sweep={sweep}"] if sweep else [])
    done = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    return done.returncode, done.stdout + done.stderr


def _mutate(table, name, work):
    """Write the named mutant's kernel into `work`; returns its path."""
    needle, replacement, _sweep, _want = table[name]
    src = open(POLICY_C, encoding="utf-8").read()
    assert src.count(needle) == 1, (
        f"the mutation site for {name!r} is gone or ambiguous — the kernel "
        "changed shape, so this mutant no longer tests what it was written to "
        "test; re-derive it from src/fs/vfs/vfs_policy.c before deleting it")
    out = work / f"{name}.c"
    out.write_text(src.replace(needle, replacement, 1), encoding="utf-8")
    return out


def _kill(table, name, work, driver=MODEL_C):
    """Build+run one mutant; returns (rc, text, checks that objected)."""
    mutant = _mutate(table, name, work)
    binary = work / f"{name}.bin"
    err = _build(driver, mutant, binary)
    assert err is not None, (
        f"mutant {name!r} did not compile, so killing it would prove nothing")
    sweep = table[name][2]
    rc, text = _run(binary, sweep)
    return rc, text, set(re.findall(r"^FAIL \[([TS]\d+)\]", text, re.M))


@pytest.fixture(scope="module")
def model_bin(tmp_path_factory):
    """The checker compiled against the kernel as shipped."""
    _skip_unless_buildable()
    out = tmp_path_factory.mktemp("p115-w95") / "model"
    assert _build(MODEL_C, POLICY_C, out) is not None, "the checker did not build"
    return out


@pytest.fixture(scope="module")
def work(tmp_path_factory):
    _skip_unless_buildable()
    return tmp_path_factory.mktemp("p115-w95-mutants")


# ═══ success: the shipped kernel ══════════════════════════════════════════

def test_the_shipped_kernel_passes_every_structural_check(model_bin):
    """success (fast tier): the four checks that need no sweep — fail-closed
    ordering, one denial per refusal, purity, and distinct metric labels."""
    rc, text = _run(model_bin)
    assert rc == 0, text
    assert "ALL PASSED" in text, text
    ran = set(re.findall(r"^PASS (T\d+)", text, re.M))
    assert ran == set(STRUCTURAL), (
        f"structural checks that did not run: {sorted(set(STRUCTURAL) - ran)}; "
        f"checks this suite does not name: {sorted(ran - set(STRUCTURAL))}",
        text)


@pytest.mark.slow
# Match the existing 600-second subprocess bound plus fixture compilation
# (180 seconds). The full forms sweep exceeded 400 seconds on Ubuntu/Lima
# with eight workers; keep enumerating all 2^32 inputs, not a smaller sample.
@pytest.mark.timeout(800)
@pytest.mark.parametrize("sweep", sorted(SWEEPS))
def test_an_exhaustive_sweep_proves_its_closed_form_count(model_bin, sweep):
    """success (slow tier): each 2^32 sweep passes AND reports the exact size of
    the set it proved.  The count is the assertion: an edit that turned a loop
    into a sample would still print PASS, and would stop being a verification.
    """
    rc, text = _run(model_bin, sweep)
    assert rc == 0, text
    assert SWEEPS[sweep] in text, (f"{sweep}: expected {SWEEPS[sweep]!r}", text)
    assert "ALL PASSED" in text, text


# ═══ error path: the harness itself ═══════════════════════════════════════

def test_a_misspelled_sweep_is_a_failure_not_a_silent_no_op(model_bin):
    """error path of the driver: `--sweep=polciy` must FAIL.

    Discovered while writing this suite (2026-09-07): the first dispatch
    matched sweep names with a chain of strcmp and did nothing when none
    matched, so a typo here would have printed ALL PASSED having enumerated
    nothing at all.  Every parametrised test above names its sweep as a string;
    this is what stops one of those strings from silently proving zero.
    """
    rc, text = _run(model_bin, "polciy")
    assert rc != 0, text
    assert "no such sweep: polciy" in text, text


def test_an_unknown_argument_is_rejected(model_bin):
    """error path: an unrecognised argv entry is a failure, not ignored."""
    done = subprocess.run([str(model_bin), "--exhaustive"],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode != 0, done.stdout
    assert "unknown argument --exhaustive" in done.stdout, done.stdout


# ═══ security-negative: every weakening of the kernel is caught ═══════════

_FAST_MUTANTS = sorted(n for n in MUTANTS if MUTANTS[n][2] is None)
_SLOW_MUTANTS = sorted(n for n in MUTANTS if MUTANTS[n][2] is not None)


def _assert_killed(table, name, result):
    rc, text, killers = result
    assert rc != 0, f"MUTANT {name} SURVIVED — the model check has a blind spot:\n{text}"
    want = table[name][3]
    assert want <= killers, (
        f"{name} was caught by {sorted(killers)}, but the check that must "
        f"object to it is {sorted(want)} — that check is vacuous and something "
        "unrelated happens to be shadowing it", text)


@pytest.mark.parametrize("mutant", _FAST_MUTANTS)
def test_a_structurally_visible_weakening_is_caught(work, mutant):
    """security-negative (fast tier): a NULL context permitted, an uncounted
    denial, and an unconfined path answered with the write posture.  Each is a
    one-line change a reviewer could wave through, and each must be rejected by
    the structural check that owns it — no sweep needed."""
    _assert_killed(MUTANTS, mutant, _kill(MUTANTS, mutant, work))


@pytest.mark.slow
@pytest.mark.timeout(400)
@pytest.mark.parametrize("mutant", _SLOW_MUTANTS)
def test_a_sweep_visible_weakening_is_caught(work, mutant):
    """security-negative (slow tier): the weakenings only an enumeration sees —
    a non-exact policy comparison (so a zeroed or unmerged config becomes
    writable), EACCES where INVARIANT #12 requires EROFS, a dropped range check,
    a verbatim policy copy that carries a stray value into delayed work, and a
    flag classifier that calls O_APPEND read-only."""
    _assert_killed(MUTANTS, mutant, _kill(MUTANTS, mutant, work))


# ═══ the design choice: why exhaustiveness, and not more properties ═══════

@pytest.mark.slow
@pytest.mark.timeout(400)
@pytest.mark.parametrize("mutant", sorted(SMUGGLERS))
def test_exhaustiveness_catches_what_the_sampled_unit_cannot(work, mutant):
    """security-negative AND the justification for this suite's existence.

    Each mutant opens the gate for exactly ONE value out of 4294967296 and is
    otherwise the shipped kernel: a policy word 0x5AFE, an operation word 4242,
    a single write-shaped flag word.  That is what a deliberate backdoor looks
    like, and it is invisible to any finite hand-written case list.

    Both halves are asserted, because only the pair is informative:

      * the phase-105 unit (tests/c/test_vfs_mutation_policy.c) SURVIVES.  It
        is not a weak test — it kills all eight structural mutants above — it
        simply samples, and no sample refutes a one-in-four-billion smuggle.
      * the sweep KILLS it.

    If a future change makes the phase-105 unit kill these too, this test goes
    red on its FIRST assertion.  That is not a bug to route around: it means
    the sweep no longer buys anything the cheaper unit does not, and this whole
    suite should be reconsidered rather than the assertion loosened.
    """
    mutant_c = _mutate(SMUGGLERS, mutant, work)

    unit_bin = work / f"{mutant}.unit.bin"
    assert _build(PHASE105_UNIT_C, mutant_c, unit_bin) is not None, \
        "the phase-105 unit did not build against the mutant"
    unit_rc, unit_text = _run(unit_bin)
    assert unit_rc == 0, (
        "the phase-105 unit killed a magic-constant mutant — exhaustive "
        "enumeration no longer buys anything over it, so re-derive W9.5's "
        "justification before touching this assertion", unit_text)

    _assert_killed(SMUGGLERS, mutant, _kill(SMUGGLERS, mutant, work))
