"""
tests/test_ci_duplication_overlap.py — the duplication guard's single-region
exemption (tools/ci/check_duplication.py::_one_region).

DISCOVERY (2026-09-07, phase-115 W8.6). Adding client/lib/protocols/ssi/ to the
corpus turned check_duplication.py red on
``client/lib/auth/cred/credinfo.c:86-88 / 87-89 / 88-90`` — a file untouched
since 08-04, and five lines that were never copied from anywhere:

    if (json_str(json, "iss", ...))   { fprintf(...); }     /* 86 */
    if (json_str(json, "sub", ...))   { fprintf(...); }     /* 87 */
    if (json_str(json, "aud", ...))   { fprintf(...); }     /* 88 */
    if (json_str(json, "scope", ...)) { fprintf(...); }     /* 89 */
    if (json_str(json, "exp", ...)) {                       /* 90 */

lizard reports a self-similar run of rows as overlapping windows of ITSELF, and
how it segments depends on the WHOLE corpus: with the new files present the
2-line windows (86~87, 87~88, ...) grow into 3-line ones, the widest of which
straddles line 90's block opener. The row grammar then stops calling the window
declarative and the guard says "cloned logic — extract a shared helper" about a
region with no second site and nothing to extract.

The fix asks the question that has to come first — are there two sites at all?
``_overlapping`` already carried the reasoning ("two members covering the same
lines share text because they ARE the same text"), but only ``_max_row_share``
consulted it, and the declarative test short-circuits before that. Asking it
first makes the verdict depend on the code rather than on lizard's segmentation
of the corpus around it.

This suite pins the exemption AND its limit: it must never swallow a block that
has a genuine disjoint second site, which is the shape an author would reach for
to hide a real clone behind it.

Run:
    PYTHONPATH=tests pytest tests/test_ci_duplication_overlap.py -v
"""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_ci_guard(stem: str):
    """Import a tools/ci module by path — that tree has no ``__init__.py``."""
    spec = importlib.util.spec_from_file_location(
        stem, ROOT / "tools/ci" / f"{stem}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = _load_ci_guard("check_duplication")

# The real credinfo.c rows, verbatim, laid out at their real line numbers so
# every member span below can be written exactly as the guard reported it.
CREDINFO = "client/lib/auth/cred/credinfo.c"
CREDINFO_FIRST_LINE = 85
CREDINFO_ROWS = [
    '    fprintf(out, "    token:\\n");',
    '    if (json_str(json, "iss", buf, sizeof(buf)))   '
    '{ fprintf(out, "      iss:   %s\\n", buf); }',
    '    if (json_str(json, "sub", buf, sizeof(buf)))   '
    '{ fprintf(out, "      sub:   %s\\n", buf); }',
    '    if (json_str(json, "aud", buf, sizeof(buf)))   '
    '{ fprintf(out, "      aud:   %s\\n", buf); }',
    '    if (json_str(json, "scope", buf, sizeof(buf))) '
    '{ fprintf(out, "      scope: %s\\n", buf); }',
    '    if (json_str(json, "exp", buf, sizeof(buf))) {',
    '        long expv = strtol(buf, NULL, 10);',
    '        long now = (long) time(NULL);',
]


def _file(rows, first_line=1):
    """One cache entry: `rows` padded so the first lands on `first_line`.

    _snippet slices ``lines[start - 1:end]``, so a member span is only readable
    as the file's own line numbers when the rows sit at their real offsets.
    """
    return [""] * (first_line - 1) + list(rows)


def _cache(files):
    """A _snippet cache — {path: lines}; build each value with _file()."""
    return dict(files)


def _credinfo_cache():
    return _cache({CREDINFO: _file(CREDINFO_ROWS, CREDINFO_FIRST_LINE)})


# A genuine clone: the same LOGIC pasted into two files. Nothing about it is
# declarative, and the two sites do not overlap.
CLONE_ROWS = [
    "    if (n < 0) {",
    "        brix_status_set(st, XRDC_EPROTO, 0, \"short read\");",
    "        return -1;",
    "    }",
    "    total += (size_t) n;",
    "    if (total > cap) {",
    "        brix_status_set(st, XRDC_EPROTO, 0, \"over cap\");",
    "        return -1;",
    "    }",
]


class TestSingleRegionIsExempt:

    def test_overlapping_windows_of_one_region_are_not_a_clone(self):
        """The reported regression, reduced: three mutually overlapping windows
        of credinfo.c's five `json_str` rows. The widest window straddles the
        `exp` block opener, so the row grammar does NOT call it declarative —
        which is exactly why the overlap question must be asked first."""
        key = f"{CREDINFO}:86-88+{CREDINFO}:87-89+{CREDINFO}:88-90"

        assert GUARD.classify(key, _credinfo_cache()) is None, (
            "windows of one region were reported as a clone again")

    def test_the_widest_window_really_is_non_declarative(self):
        """Guards the guard: if the row grammar ever started calling that window
        declarative on its own, this suite would pass for the wrong reason and
        stop testing the exemption at all."""
        snippet = GUARD._snippet(f"{CREDINFO}:88-90", _credinfo_cache())
        rows = GUARD._join_rows(GUARD._clean_lines(snippet))

        assert rows, "the window came back empty; the fixture lost its offsets"
        assert not GUARD._is_declarative(rows), (
            "the 88-90 window is declarative now; this suite needs a new "
            "non-declarative single-region case or it proves nothing")

    def test_a_two_member_self_overlap_is_exempt(self):
        """The narrow case lizard emits most often — one pair of adjacent
        windows over the same rows."""
        key = f"{CREDINFO}:86-89+{CREDINFO}:87-90"

        assert GUARD.classify(key, _credinfo_cache()) is None


class TestRealClonesStillFail:

    def test_cloned_logic_in_two_files_still_fails(self):
        """The exemption is about there being ONE site, not about the rows. Two
        files holding the identical block do not overlap, so nothing changes for
        the case the guard exists to catch."""
        key = "client/lib/a.c:1-9+client/lib/b.c:1-9"
        cache = _cache({"client/lib/a.c": _file(CLONE_ROWS),
                        "client/lib/b.c": _file(CLONE_ROWS)})

        reason = GUARD.classify(key, cache)
        assert reason is not None, "a two-file clone became exempt"
        assert "cloned logic" in reason, reason

    def test_disjoint_windows_in_one_file_still_fail(self):
        """Same file, two regions that do NOT overlap: still two sites, still a
        clone. `_one_region` keys on the spans, never on the filename."""
        rows = CLONE_ROWS + ["    /* gap */", "    (void) cap;"] + CLONE_ROWS
        key = "client/lib/a.c:1-9+client/lib/a.c:12-20"
        cache = _cache({"client/lib/a.c": _file(rows)})

        reason = GUARD.classify(key, cache)
        assert reason is not None, "two disjoint sites in one file became exempt"
        assert "cloned logic" in reason, reason


class TestExemptionCannotHideAClone:

    def test_a_clone_padded_with_self_overlapping_windows_still_fails(self):
        """The negative that matters: an author cannot launder a real clone
        through the exemption by getting lizard to also report overlapping
        windows of one of the two sites. `_one_region` requires EVERY pair to
        overlap, so a single disjoint pair anywhere in the block is enough to
        keep the block on the failing path."""
        rows = CLONE_ROWS + ["    /* gap */", "    (void) cap;"] + CLONE_ROWS
        key = ("client/lib/a.c:1-9+client/lib/a.c:2-10"
               "+client/lib/a.c:12-20")
        cache = _cache({"client/lib/a.c": _file(rows)})

        members = key.split("+")
        assert not GUARD._one_region(members), (
            "a block containing a disjoint pair was called one region")
        reason = GUARD.classify(key, cache)
        assert reason is not None, "a padded clone became exempt"

    def test_a_chained_run_of_windows_is_not_one_region(self):
        """Windows that merely CHAIN — each overlapping its neighbour, the ends
        disjoint — cover more than one site and must not be collapsed. The live
        tree has such a block (`directives_tier.h:27-41 … 83-97`); it stays
        exempt on the declarative path, which is where its verdict belongs."""
        members = ["src/x.h:27-41", "src/x.h:34-48", "src/x.h:41-55",
                   "src/x.h:83-97"]

        assert not GUARD._one_region(members)


# The live scan runs lizard over src/, client/ and shared/: ~18s on an 8-core
# runner but ~130s on a 4-core box, the same cap test_ci_guards.py carries for
# its own lizard-backed guards.
@pytest.mark.suite_job
@pytest.mark.timeout(300)
def test_the_live_tree_has_no_duplicate_blocks():
    """End to end on the real corpus: the guard is the absolute gate in
    guards.yml, and the regression above turned it red on a tree whose C code
    nobody had cloned."""
    if GUARD.find_lizard() is None:
        pytest.skip("lizard not installed (pip install --user lizard)")
    fail_lines, exempt = GUARD.run()

    assert fail_lines == [], "\n".join(fail_lines)
    assert exempt, "no blocks were classified at all — did the scan run?"
