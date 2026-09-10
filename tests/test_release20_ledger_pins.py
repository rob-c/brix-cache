"""Release-2.0 ledger pins: what the comparison and gap documents say 2.0 has.

Split out of tests/test_release20_surface_pins.py when that module crossed the
600-logical-line cap.  That module pins the DIRECTIVE surface — the golden
(name, plane) snapshot, the removals, the accepted-only set, the defaults, the
generated table, the `xrd config`/help exporters.  This one pins the PROSE
surface a site actually reads before deciding BriX can replace its XRootD
deployment:

* every flagship handle a closed F-item shipped is a real registration, is named
  somewhere in the comparison/gap set, and is never dispositioned "absent" by a
  row nobody re-read after the item closed;
* the quick reference lists every directive 2.0 shipped, matched on whole
  directive names;
* every shipped capability is reachable from the operator-facing doc trees, not
  only from the register and the changelog;
* every pinned handle is cited under its OWN register item, and no page cites a
  register item that does not exist;
* the "Axis (e) ... open:" status banner on every ledger page names exactly the
  register's still-OPEN items — the one sentence a reader trusts to tell them
  what is left.

Static: no nginx, no fleet, no ports.
"""
from __future__ import annotations

import re

import pytest

from test_release20_directive_surface import (
    DIRECTIVES_MD, DOCS, REGISTER_MD, REPO,
)
from test_release20_surface_pins import _live_rows

pytestmark = [pytest.mark.timeout(120)]


# --- the gap ledger must know what 2.0 shipped -------------------------------
#
# The comparison and gap documents are the pages a site reads to decide whether
# BriX can replace its XRootD deployment. Their rows were written against an
# older tree, so an F-item that closes a gap leaves its row behind — the 2026-09
# sweep found the PSS row still "❌ out of scope" after F5 shipped the
# forward:// driver, the PFC row silent on brix_cache_urlcgi, XrdOssMSS claiming
# "no in-process MSS driver stack" beside a dlopened lib adapter, and the client
# guide still calling multihop delegation a caveat after F7 closed it. A row
# nobody re-read is a feature nobody knows they have.

#: Each closed F-item's flagship operator handle: what a site would grep the
#: comparison set for. `forward://root` is a store-URL scheme, not a directive.
SHIPPED_IN_2_0 = {
    "brix_frm_queue_path": "F1", "brix_frm_stagecmd": "F1",
    "brix_frm_stagemsg": "F2", "brix_frm_purge_policy": "F4",
    "brix_frm_purge_polprog": "F4", "brix_cache_urlcgi": "F5",
    "forward://root": "F5", "brix_tpc_max_hops": "F7",
    "brix_tpc_streams": "F7", "brix_sss_getcreds": "F9",
    "brix_tap_proxy_sss_identity": "F9", "brix_checksum_plugin": "F8",
    "brix_cms_fsxeq": "F17", "brix_cms_fsxeq_timeout": "F17",
    "brix_tpc_allow_identity": "F18", "brix_tpc_require": "F18",
    "brix_tpc_restrict": "F18", "brix_tpc_oids": "F18",
}

#: A verdict cell that dispositions the row as absent. Compared against a whole
#: cell, never a substring of one: "persona / reproxy are not implemented" is a
#: true note about sub-features on a row whose verdict is **Present**.
ABSENT_VERDICTS = frozenset({
    "no", "none", "missing", "absent", "not implemented", "out of scope",
    "deferred", "❌", "not present",
})


def _ledger_pages():
    """The comparison/gap set a site reads — minus the register, which is the
    work list itself and legitimately writes the word 'missing'."""
    pages = list((DOCS / "10-reference").rglob("*.md"))
    pages.append(DOCS / "09-developer-guide" / "feature-gap-analysis.md")
    return sorted(p for p in pages
                  if "_archive" not in p.parts and p != REGISTER_MD)


def _table_cells(line: str):
    return [cell.strip(" *`✅❌").strip().lower()
            for cell in line.strip().strip("|").split("|")]


def _absent_verdict_rows(page):
    """(line number, row) for table rows that name a shipped handle and still
    disposition it as absent."""
    for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("| ") or not any(h in line for h in SHIPPED_IN_2_0):
            continue
        if "❌" in line or ABSENT_VERDICTS & set(_table_cells(line)):
            yield number, line


def _pinned_directives():
    return [handle for handle in SHIPPED_IN_2_0 if handle.startswith("brix_")]


def _unregistered_handles():
    live = {name for name, _plane in _live_rows()}
    return sorted(set(_pinned_directives()) - live)


def _unmentioned_handles(texts):
    found = {handle for text in texts for handle in SHIPPED_IN_2_0 if handle in text}
    return sorted(f"{handle} ({SHIPPED_IN_2_0[handle]})"
                  for handle in set(SHIPPED_IN_2_0) - found)


def test_every_shipped_2_0_handle_is_a_real_registration() -> None:
    """The handles the ledger pins on are load-bearing: a renamed directive must
    red here rather than quietly making the coverage pin unfalsifiable."""
    missing = _unregistered_handles()
    assert missing == [], f"pinned handles no longer registered: {missing}"
    assert "forward://root" in DIRECTIVES_MD.read_text(encoding="utf-8")


def test_the_gap_ledger_names_every_capability_2_0_shipped() -> None:
    """Coverage: a site comparing against XRootD must be able to find each
    closed gap in the comparison set, not only in the register."""
    pages = _ledger_pages()
    assert len(pages) > 10, "the ledger set collapsed — check the glob"
    unmentioned = _unmentioned_handles(
        [page.read_text(encoding="utf-8") for page in pages])
    assert unmentioned == [], (
        "shipped in 2.0 but absent from every comparison/gap page: "
        + ", ".join(unmentioned))


def test_no_gap_row_dispositions_a_shipped_capability_as_absent() -> None:
    """The inverse, and the one that actually rots: the feature ships, the row
    still says No/❌/Missing. Verdict cells only — a row may still narrate which
    sub-features are absent."""
    stale = [f"{page.relative_to(REPO)}:{number}: {line[:140]}"
             for page in _ledger_pages()
             for number, line in _absent_verdict_rows(page)]
    assert stale == [], "gap rows overtaken by 2.0:\n" + "\n".join(stale)


def test_the_absent_verdict_detector_is_not_vacuous() -> None:
    """A cell-scoped detector fails open if the cell splitting drifts, so prove
    it still fires — and still forgives the sub-feature note it must forgive."""
    assert ABSENT_VERDICTS & set(_table_cells(
        "| Proxy storage | `pss.origin` | `forward://root` | **No** | none yet |"))
    assert not ABSENT_VERDICTS & set(_table_cells(
        "| Proxy storage | `pss.origin` | `forward://root` | **Present** | "
        "persona / reproxy are not implemented. |"))


# --- the quick reference is the page a site greps first -----------------------
# Every closed F-item's operator handle reached `directives.md` by construction
# — that is where the register's docs column points. The one-page summary is
# curated by hand and 155 of 675 rows wide, so a shipped directive can be fully
# documented and still be invisible to the page an operator actually opens. Five
# of them were, on 2026-09-09.

QUICK_REFERENCE_MD = DOCS / "03-configuration" / "quick-reference.md"


def _quick_reference_gaps() -> list[str]:
    text = QUICK_REFERENCE_MD.read_text(encoding="utf-8")
    return sorted(f"{handle} ({SHIPPED_IN_2_0[handle]})"
                  for handle in _pinned_directives() if f"`{handle}" not in text)


def test_the_quick_reference_lists_every_directive_2_0_shipped() -> None:
    """A directive an operator cannot find on the one-page summary is a feature
    they will not know they have."""
    assert QUICK_REFERENCE_MD.exists()
    gaps = _quick_reference_gaps()
    assert gaps == [], ("shipped in 2.0 but missing from the quick reference: "
                        + ", ".join(gaps))


def test_the_quick_reference_pin_reads_whole_directive_names() -> None:
    """Backtick-anchored, so a row for a longer directive that merely starts
    with the same characters cannot satisfy the pin for the shorter one."""
    assert _pinned_directives(), "the pinned-handle set collapsed"
    assert "brix_tpc_streams" in _pinned_directives()
    assert "forward://root" not in _pinned_directives()


#: Doc trees written for someone running the software, as opposed to the
#: comparison ledger (10-reference) and the developer's own working notes.
OPERATOR_TREES = ("01-getting-started", "02-concepts", "02-deployment",
                  "03-configuration", "04-protocols", "05-operations",
                  "06-authentication", "07-security", "08-metrics-monitoring")


def _operator_texts() -> list:
    pages = [page for tree in OPERATOR_TREES
             for page in (DOCS / tree).rglob("*.md")
             if "_archive" not in page.parts]
    pages.append(REPO / "README.md")
    return [page.read_text(encoding="utf-8") for page in pages]


def test_every_shipped_capability_is_reachable_from_the_operator_docs() -> None:
    """The comparison ledger is what a site reads once, before adopting. A
    capability named only there is one nobody running the software will find."""
    texts = _operator_texts()
    assert len(texts) > 40, "the operator doc set collapsed — check the trees"
    unmentioned = _unmentioned_handles(texts)
    assert unmentioned == [], (
        "shipped in 2.0 and named nowhere an operator reads: "
        + ", ".join(unmentioned))


# --- F-numbers are cross-references, and cross-references rot silently --------
# The register numbers each closed gap; the user docs cite those numbers so an
# operator can trace a directive back to the work that added it. Nothing checked
# that a citation pointed at the right row, and on 2026-09-09 four pages plus
# this file's own pinned mapping cited the checksum plugin loader as F11 — which
# is `brix_mirror_exclude_opcodes`.

_F_ROW = re.compile(r"\|\s*\*\*(F\d+)\*\*\s*\|")
_F_CITE = re.compile(r"2\.0 \**(F\d+)\**")


def _register_f_rows() -> dict:
    return {match.group(1): line
            for line in REGISTER_MD.read_text(encoding="utf-8").splitlines()
            if (match := _F_ROW.match(line))}


def _misattributed_handles() -> list:
    rows = _register_f_rows()
    return sorted(f"{handle} cited as {item}"
                  for handle, item in SHIPPED_IN_2_0.items()
                  if handle.startswith("brix_") and handle not in rows.get(item, ""))


def _dangling_citations() -> list:
    rows = _register_f_rows()
    out = set()
    for page in _ledger_pages() + [QUICK_REFERENCE_MD, DOCS / "index.md"]:
        for item in _F_CITE.findall(page.read_text(encoding="utf-8")):
            if item not in rows:
                out.add(f"{page.relative_to(REPO)}: {item}")
    return sorted(out)


def test_every_pinned_handle_is_cited_under_its_own_register_item() -> None:
    """The F-number a doc prints beside a directive must be the row that added
    it — otherwise the trace an operator follows lands on unrelated work."""
    assert len(_register_f_rows()) >= 21, "the register's F table moved"
    wrong = _misattributed_handles()
    assert wrong == [], "handles cited under the wrong register item: " + ", ".join(wrong)


def test_no_doc_cites_a_register_item_that_does_not_exist() -> None:
    """A `2.0 F<n>` citation is a link into the register; a number past the end
    of the table is a dead one."""
    dangling = _dangling_citations()
    assert dangling == [], "citations with no register row: " + ", ".join(dangling)


# --- the banner every gap ledger carries -------------------------------------
# A gap ledger opens with the same status banner: 2.0 closed F1..N, these are
# open, the register supersedes anything below. The banner is the only thing
# telling a reader that the rows underneath predate the feature work, so it has
# to name exactly the items still open — a banner that keeps naming F16 after
# F16 ships is worse than none, because it is read as current.
#
# The page list is DERIVED by scanning docs/ for the banner, never carried by
# hand. It was a hand-written tuple of nine 10-reference pages until 2026-09-09,
# when the four 09-developer-guide ledgers that also carry the banner were found
# still naming F16 open after F16 shipped: they were not on the list, so nothing
# checked them. Deriving from the tree is the same lesson as every other
# "ask the tree, not the name" guard here. MIN_BANNER_PAGES keeps the derivation
# honest in the other direction — a page that silently loses its banner drops
# out of the scan, and the floor notices.
#
# Deriving from the tree then surfaced two things a hand-written list had hidden.
# (1) next-steps.md opens with the same banner but is a pointer, not a ledger: it
# names no open item on purpose. Selecting on the axis-(e) sentence rather than on
# the banner opener keeps it out without naming it. (2) feature-gap-analysis.md
# names a CLOSED item in bold (**F7**) in the closed half of its banner, as
# context for a row that has since moved — so the set comparison reads only the
# half after `open:`, which is the only half that claims anything.

_BANNER_START = "**Status (2026-09-09 — 2.0).**"
#: The sentence that makes a banner an axis-(e) LEDGER banner rather than the
#: plain "this page is history, read the register" pointer. Only the former
#: enumerates open items, so only the former can be checked against the
#: register — docs/01-getting-started/next-steps.md carries the banner start and
#: deliberately names no F item at all.
_BANNER_AXIS = "Axis (e) of that register closed"
_F_BOLD = re.compile(r"\*\*(F\d+)\*\*")
#: Split point: the CLOSED half of the banner names shipped items in prose (and
#: on one page a closed item, F7, in bold as context for a row that moved).
#: Only the half after this marker is the claim about what is still open.
_BANNER_OPEN_MARKER = "open:"
MIN_BANNER_PAGES = 13


def _banner_pages() -> list:
    """Every docs page carrying the 2.0 axis-(e) ledger banner, in a stable
    order."""
    return sorted((p for p in DOCS.rglob("*.md")
                   if _BANNER_AXIS in (_banner_of(p) or "")),
                  key=lambda p: str(p))


def _open_items() -> set:
    return {item for item, line in _register_f_rows().items() if "**OPEN" in line}


def _banner_of(page):
    """The blockquote a ledger page opens with, or None."""
    text = page.read_text(encoding="utf-8")
    if _BANNER_START not in text:
        return None
    start = text.index(_BANNER_START)
    end = text.find("\n\n", start)
    return text[start:end if end != -1 else len(text)]


def _banner_open_list(page) -> str:
    """The half of a ledger banner that follows `... and leaves **Fx–Fy** open:`
    — the only half that claims anything about what is still open."""
    banner = _banner_of(page) or ""
    cut = banner.find(_BANNER_OPEN_MARKER)
    return banner[cut:] if cut != -1 else banner


def _banner_disagreements() -> list:
    expected = _open_items()
    out = []
    for page in _banner_pages():
        rel = page.relative_to(DOCS)
        named = set(_F_BOLD.findall(_banner_open_list(page)))
        if named != expected:
            out.append(f"{rel}: names {sorted(named)}, register has "
                       f"{sorted(expected)} open")
    return out


def test_the_banner_page_set_is_derived_from_the_tree() -> None:
    """The pin must cover every page that carries the banner, not a list
    someone remembered to extend.  The floor catches the other direction: a
    page that loses its banner leaves the scan silently."""
    pages = _banner_pages()
    assert len(pages) >= MIN_BANNER_PAGES, (
        f"only {len(pages)} pages still carry the 2.0 status banner, expected "
        f"at least {MIN_BANNER_PAGES}: "
        + ", ".join(str(p.relative_to(DOCS)) for p in pages))
    # Both trees that hold gap ledgers are represented.
    trees = {str(p.relative_to(DOCS)).split("/")[0] for p in pages}
    assert {"09-developer-guide", "10-reference"} <= trees, trees


def test_a_non_ledger_banner_is_excluded_on_purpose() -> None:
    """next-steps.md opens with the same banner and deliberately names no open
    item — it points at the register instead of restating it. The exclusion is
    by the axis-(e) sentence, not by filename, so a page that grows a real open
    list joins the check automatically."""
    page = DOCS / "01-getting-started" / "next-steps.md"
    banner = _banner_of(page)
    assert banner is not None and _BANNER_START in banner
    assert _BANNER_AXIS not in banner
    assert page not in _banner_pages()
    assert _F_BOLD.findall(banner) == []


def test_the_open_half_is_what_is_checked() -> None:
    """The closed half legitimately names a closed item in bold (F7 on
    feature-gap-analysis.md, as context for a row that has since moved), so the
    check must read only the text after `open:` — and must still find the open
    items there."""
    page = DOCS / "09-developer-guide" / "feature-gap-analysis.md"
    assert "**F7**" in _banner_of(page)
    assert "F7" not in _F_BOLD.findall(_banner_open_list(page))
    assert set(_F_BOLD.findall(_banner_open_list(page))) == _open_items()


def test_every_gap_ledger_opens_with_the_register_banner() -> None:
    """One statement of what is still open, repeated verbatim, and checked
    against the register rather than against the last person to edit it.

    Axis (e) closed in full on 2026-09-10 (F21 last), so the expected set is now
    EMPTY -- and that is the assertion, not an excuse to stop checking.  The
    banners keep their `open:` marker with nothing bold after it, so a page that
    grows a new bold F item there still fails, and so does a register row that
    reopens without the banners following it.  `test_the_register_is_the_source`
    below is what stops this from decaying into "the check passes because both
    sides are empty"."""
    wrong = _banner_disagreements()
    assert wrong == [], "status banners out of step with the register:\n" + "\n".join(wrong)
    assert _open_items() == set(), sorted(_open_items())


def test_the_register_is_the_source_of_the_empty_open_set() -> None:
    """The floor under the test above: an empty open set must come from a
    register that HAS F rows and marks them all DONE -- never from a parse that
    found no rows at all, which would make every banner agree with nothing."""
    rows = _register_f_rows()
    assert len(rows) >= 22, sorted(rows)
    assert all("**DONE" in line for line in rows.values()), \
        sorted(item for item, line in rows.items() if "**DONE" not in line)


def test_a_reopened_row_still_fails_the_banner_check() -> None:
    """SECURITY-NEGATIVE for the check itself: with the open set empty, prove
    the comparison is still load-bearing by feeding it a banner that claims an
    open item the register does not have."""
    page = DOCS / "09-developer-guide" / "feature-gap-analysis.md"
    banner = _banner_of(page)
    assert "nothing open:" in banner
    # The pre-2026-09-10 shape: an item named in bold AFTER the marker, which is
    # the only half `_banner_disagreements` reads.
    reopened = banner.replace("open: axis (e) is closed",
                              "open: **F21**, so axis (e) is not closed")
    named = set(_F_BOLD.findall(reopened[reopened.find(_BANNER_OPEN_MARKER):]))
    assert named == {"F21"}
    assert named != _open_items()


def test_the_banner_check_reads_only_the_banner() -> None:
    """`F16` also appears in ordinary prose on some of these pages; the check
    must not accept that as a banner, or a page could lose its banner silently."""
    page = DOCS / "10-reference" / "comparison" / "deployment-guide.md"
    banner = _banner_of(page)
    assert banner is not None and _BANNER_START in banner
    assert "Detailed design comparison" not in banner
    assert len(banner) < len(page.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# "Remaining before tagging 2.0" — the numbered table, not the F register
# --------------------------------------------------------------------------
_TAG_ROW = re.compile(r"^\| (\d+) \| ([^|]+?) +\| (.*)$")


def _tagging_rows() -> dict:
    """{row number: (item, rest-of-row)} for the "Remaining before tagging 2.0"
    table.  It is a SEPARATE table from the F register — the F rows say whether a
    feature exists, these say whether the release is shippable — and it decayed
    independently: row 1 said "owed once more after F17-F21" for two days after
    F21 landed."""
    text = REGISTER_MD.read_text(encoding="utf-8")
    start = text.index("| # | Item | State | Evidence")
    body = text[start:].split("\n\n")[0]
    rows = {}
    for line in body.splitlines():
        if (match := _TAG_ROW.match(line)) and match.group(1).isdigit():
            rows[int(match.group(1))] = (match.group(2).strip(), match.group(3))
    return rows


def test_the_tagging_table_parses_as_a_table() -> None:
    """The floor under the two tests below: they assert things ABOUT rows, so a
    parse that silently found none would make both vacuously green — the same
    decay [[test_the_register_is_the_source_of_the_empty_open_set]] guards for
    the F register."""
    rows = _tagging_rows()
    assert sorted(rows) == list(range(1, 8)), sorted(rows)
    assert rows[1][0] == "Rebuild and re-verify", rows[1][0]
    assert rows[6][0].startswith("Feature completion"), rows[6][0]


def test_no_tagging_row_still_owes_work() -> None:
    """Every row of the tagging table must be discharged.  The two that are not
    this audit's to close say so in the row itself — row 3 waits on the
    operator's commit and row 4 is peer-owned — and both still have to be
    positively marked, not left blank."""
    rows = _tagging_rows()
    undischarged = sorted(n for n, (_, rest) in rows.items()
                          if "**DONE" not in rest
                          and "IMPLEMENTED" not in rest
                          and "the commit is the operator's" not in rest)
    assert undischarged == [], undischarged


def test_the_rebuild_row_records_a_build_of_the_final_tree() -> None:
    """SECURITY-NEGATIVE-shaped pin on the one row that is pure evidence: row 1
    is worthless unless it names a binary.  A future editor who marks it DONE
    without a size and an md5 has recorded a claim, not a verification — and the
    whole point of the row is that the tree carrying every F item was actually
    compiled and run, which is how five defect classes were found on 2026-09-09
    that no tree-only run could show."""
    _, rest = _tagging_rows()[1]
    assert "**DONE" in rest
    assert re.search(r"md5 `[0-9a-f]{32}`", rest), "row 1 names no binary md5"
    assert re.search(r"`objs/nginx` \*?\*?[\d,]{6,} bytes", rest), \
        "row 1 names no binary size"
    assert "2026-09-10" in rest, "row 1 does not record the final rebuild"
    assert "owed once more" not in rest, \
        "row 1 still owes a rebuild while claiming DONE"
