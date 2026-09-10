"""test_phase115_gridftp_feat_tokens.py — phase-115 §P3.

WHAT: Drives tests/c/gftp_feat_test.c, which exercises the RFC 2389 FEAT
      capability probe (src/fs/backend/gsiftp/gftp_feat.c) over the reply
      bodies a real door sends — then mutation-tests the driver by narrowing
      the matcher back to the shape that shipped broken.

WHY:  the terminator set of `gftp_feat_line_is()` was ' ', '\\t' and NUL.  FEAT
      advertises each feature as a CRLF-terminated continuation line of a 211
      reply (RFC 2389 §3.2 over RFC 959 §4.2), so on every conforming origin
      the byte after the name was CR and the mask came back 0 — ERET and SPAS
      were never once negotiated in production.  Nothing was observably wrong:
      the driver fell back to REST+RETR and single-stream transfers and served
      the right bytes, slower and unbounded.

      The pin that was supposed to own this — `test_feature_names_match_whole
      _tokens` in test_phase115_gridftp_eret_static.py — grepped the C for the
      literal `line[len] == '\\0'`.  It was green for the whole time the matcher
      was broken and it went RED on the repair.  A check that cannot see the
      defect it is named after, and that objects to the fix, argues for the
      bug.  This suite replaces it: the matcher is RUN, and the run is shown to
      be able to fail.

HOW:  compile the driver against the shipped source and require ALL PASSED
      plus every named check's own PASS line — a check that silently stopped
      running is the failure mode the §H family exists to refuse.  Then compile
      it against two mutants and require that the checks which OWN each defect
      are the ones that object.  The killer sets below were measured, not
      predicted.

Needs no server, no fleet and no port: the probe's one external call is stubbed.
Skips cleanly without a C compiler.

Run: PYTHONPATH=tests python3 -m pytest tests/test_phase115_gridftp_feat_tokens.py -v
"""

import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CC = os.environ.get("CC", "cc")

DRIVER_C = os.path.join(REPO, "tests/c/gftp_feat_test.c")
FEAT_C = os.path.join(REPO, "src/fs/backend/gsiftp/gftp_feat.c")

# Every check the driver runs, by the tag it prints.  Named here so a check
# that stops running is a red rather than a silence.
TERMINATORS = {
    "T1": "a CRLF advertisement lights both bits",
    "T2": "CR terminates a feature name",
    "T3": "so does a bare LF",
    "T4": "so does the end of the body",
    "T5": "so does the space before parameters",
    "T6": "and the same holds for the striped-passive name",
}
SUBSTRINGS = {
    "S1": "ERETSTAT is not ERET",
    "S2": "SITE ERET is not ERET",
    "S3": "SPASV is not SPAS",
    "S4": "X-ERET is not ERET",
    "S5": "prose mentioning the name is not an advertisement",
}
REFUSALS = {
    "R1": "a non-211 reply advertises nothing",
    "R2": "a failed FEAT command advertises nothing",
    "R3": "an empty body advertises nothing",
}
CHECKS = {**TERMINATORS, **SUBSTRINGS, **REFUSALS}

# The matcher as shipped, and the two ways it can be wrong.  A boundary set is
# a two-sided property: too narrow and every conforming door goes unheard, too
# wide and another door's verb is mistaken for the feature.  One mutant per
# side, so neither half of the property can go vacuous unnoticed.
_TERMINATOR_SET = ("    return after == '\\0' || after == ' ' || after == '\\t'\n"
                   "        || after == '\\r' || after == '\\n';")

MUTANTS = {
    # The defect exactly as it shipped.
    "the_line_terminator_is_not_a_token_boundary": (
        _TERMINATOR_SET,
        "    return after == '\\0' || after == ' ' || after == '\\t';",
        {"T1", "T2", "T3", "T6"}),
    # The other side: a prefix match lights the bit for another door's verb.
    "a_feature_name_is_matched_as_a_prefix": (
        "    after = line[len];",
        "    return 1;\n\n    after = line[len];",
        {"S1", "S3"}),
}


def _skip_unless_buildable():
    if not shutil.which(CC):
        pytest.skip(f"no C compiler ({CC})")


def _build(feat_c, out_bin, work):
    """Compile the driver against one copy of the probe.  None on failure.

    The driver includes the translation unit (the matcher is static), so a
    mutant is selected by rewriting that one include line rather than by a
    link-time swap.
    """
    driver = os.path.join(work, "driver_" + os.path.basename(out_bin) + ".c")
    text = open(DRIVER_C, encoding="utf-8").read()
    needle = '#include "fs/backend/gsiftp/gftp_feat.c"'
    assert text.count(needle) == 1, "the driver no longer includes the probe"
    with open(driver, "w", encoding="utf-8") as fh:
        fh.write(text.replace(needle, f'#include "{feat_c}"', 1))

    cmd = [CC, "-O2", "-D_GNU_SOURCE", "-w",
           f"-I{os.path.join(REPO, 'src')}",
           f"-I{os.path.join(REPO, 'shared')}",
           # A mutant lives in a temp directory, so the probe's own quote-
           # relative include of gftp_feat.h needs its home named.
           f"-I{os.path.join(REPO, 'src/fs/backend/gsiftp')}",
           "-o", out_bin, driver]
    build = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                           cwd=REPO)
    return None if build.returncode != 0 else build.stderr


def _run(binary):
    done = subprocess.run([binary], capture_output=True, text=True, timeout=120)
    return done.returncode, done.stdout + done.stderr


def _mutate(name, work):
    """Write the named mutant's probe into `work`; returns its path."""
    needle, replacement, _want = MUTANTS[name]
    src = open(FEAT_C, encoding="utf-8").read()
    assert src.count(needle) == 1, (
        f"the mutation site for {name!r} is gone or ambiguous — the probe "
        "changed shape, so this mutant no longer tests what it was written "
        "to test; re-derive it from gftp_feat.c before deleting it")
    out = os.path.join(work, f"{name}.c")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(src.replace(needle, replacement, 1))
    return out


@pytest.fixture(scope="module")
def work(tmp_path_factory):
    _skip_unless_buildable()
    return str(tmp_path_factory.mktemp("p115-feat"))


@pytest.fixture(scope="module")
def shipped(work):
    """The driver compiled against the probe as shipped."""
    out = os.path.join(work, "shipped.bin")
    assert _build(FEAT_C, out, work) is not None, "the driver did not build"
    return out


# ═══ success: the probe as shipped ════════════════════════════════════════

def test_the_shipped_probe_passes_every_check(shipped):
    """success: ERET and SPAS are detected through a CRLF terminator, and are
    not detected in any of the five look-alikes."""
    rc, text = _run(shipped)
    assert rc == 0, text
    assert "ALL PASSED" in text, text


def test_every_named_check_actually_ran(shipped):
    """census: the driver's PASS lines are the set this suite names.

    Silence is not evidence.  A check that was deleted, renamed or short-
    circuited leaves a green run behind it, which is precisely how the pin
    this suite replaces stayed green across the defect it was named after.
    """
    _rc, text = _run(shipped)
    ran = set(re.findall(r"^PASS ([TSR]\d+)", text, re.M))
    assert ran == set(CHECKS), (
        f"checks that did not run: {sorted(set(CHECKS) - ran)}; "
        f"checks this suite does not name: {sorted(ran - set(CHECKS))}", text)


def test_every_advertised_feature_has_a_check(shipped):
    """census: each name in the probe's table is exercised by the driver.

    A third feature added to `gftp_feat_names[]` would otherwise inherit this
    suite's green without ever being probed.
    """
    table = re.search(r"gftp_feat_names\[\]\s*=\s*\{(.*?)\n\};",
                      open(FEAT_C, encoding="utf-8").read(), re.S)
    assert table is not None, "the feature table is gone or reshaped"
    names = re.findall(r'\{\s*"([A-Z-]+)"', table.group(1))
    assert names, "no feature names parsed out of the table"

    driver = open(DRIVER_C, encoding="utf-8").read()
    for name in names:
        assert f'" {name}\\r\\n"' in driver, (
            f"{name} is advertised by the probe but no check drives it "
            "through a CRLF-terminated line")


# ═══ error: the defect as it shipped, and its opposite ════════════════════

@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_the_owning_checks_object_to_each_mutant(name, work):
    """error: a deliberate revert reddens, and reddens in the right place.

    The killer sets were measured against this driver before they were
    written down; a mutant listed against the wrong check would let that
    check go vacuous unnoticed.
    """
    mutant = _mutate(name, work)
    binary = os.path.join(work, f"{name}.bin")
    assert _build(mutant, binary, work) is not None, (
        f"mutant {name!r} did not compile, so killing it proves nothing")

    rc, text = _run(binary)
    assert rc != 0, (f"mutant {name!r} survived — the driver cannot see it", text)
    objected = set(re.findall(r"^FAIL ([TSR]\d+)", text, re.M))
    assert objected == MUTANTS[name][2], (
        f"{name!r} was expected to be caught by "
        f"{sorted(MUTANTS[name][2])} but was caught by {sorted(objected)}",
        text)


# ═══ security-negative: no look-alike verb is ever taken for the feature ══

def test_no_look_alike_advertisement_lights_a_bit(shipped):
    """security-negative: a hostile or merely chatty door cannot talk this
    client into a bounded-retrieve or striped-passive negotiation it does not
    support, by naming the feature inside another verb, another verb's
    argument, a vendor extension or its banner prose.

    The consequence is not cosmetic: believing a phantom ERET makes every
    ranged read issue a command the door will refuse, and the refusal arrives
    after the data channel is already open.
    """
    _rc, text = _run(shipped)
    for tag in SUBSTRINGS:
        assert re.search(rf"^PASS {tag} ", text, re.M), (
            f"{tag} ({SUBSTRINGS[tag]}) did not run", text)
    assert not re.search(r"^FAIL ", text, re.M), text
