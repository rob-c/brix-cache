"""Phase-107 C9 — the typed storage domain on every ``vfs-seam-allow`` marker.

``tools/ci/check_vfs_seam.py`` grew a fourth pass in W9: every real src/
marker must lead with a domain constant, and a ``DOMAIN_*`` claim must be
entitled by the longest matching prefix in ``DOMAIN_ENTITLE`` (phase-107
Appendix G.1 is the normative table). This module pins the §9.1 C9 row:

- success — every live-tree marker names an entitled domain and the real
  guard script is green; doc-comment lines that merely MENTION the
  convention are not markers (Appendix G.2's 108-not-117 parser rule).
- error — a marker with a missing or unknown domain constant fails.
- security negative — a ``CONFIG`` waiver in a data-plane file fails, an
  unlisted path is entitled to nothing, and a domain constant grants no
  access: the escape valves (``NOT_STORAGE``/``SEAM_CORRECT``) pass
  everywhere but widen no entitlement, and ``DOMAIN_EXPORT`` does not
  exist — an export mutation takes the phase-105 policy gate, never a
  waiver.

All negatives run on synthetic (path, lineno, token) triples through the
guard's own ``domain_violation`` — no tracked file is ever damaged.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.xdist_group("ci-guards")

REPO = Path(__file__).resolve().parents[1]
CI = REPO / "tools" / "ci"


def _load_seam():
    # tools/ci has no __init__.py — import the guard by path, the same way
    # _test_ci_guards_helpers._load does.
    spec = importlib.util.spec_from_file_location(
        "check_vfs_seam", CI / "check_vfs_seam.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SEAM = _load_seam()


@pytest.fixture()
def repo_cwd(monkeypatch):
    """domain_markers() walks the relative ``src`` tree — anchor the cwd."""
    monkeypatch.chdir(REPO)


def _violations(markers):
    verdicts = (SEAM.domain_violation(p, n, t) for p, n, t in markers)
    return [v for v in verdicts if v is not None]


def _doc_mention_lines(path):
    with open(path, "r", encoding="latin-1") as fh:
        return [
            lineno
            for lineno, line in enumerate(fh, 1)
            if "vfs-seam-allow" in line and SEAM.DOC_LINE_RE.match(line)
        ]


def _doc_mentions():
    return [
        (path, lineno)
        for path in SEAM._src_ch_files()
        for lineno in _doc_mention_lines(path)
    ]


# --- success ------------------------------------------------------------------


class TestLiveTreeGreen:
    def test_guard_script_green_end_to_end(self):
        p = subprocess.run(
            [sys.executable, str(CI / "check_vfs_seam.py")],
            capture_output=True,
            text=True,
        )
        assert p.returncode == 0, p.stdout + p.stderr
        assert "every domain claim entitled" in p.stdout

    def test_every_live_marker_names_an_entitled_domain(self, repo_cwd):
        markers = SEAM.domain_markers()
        assert markers, "the marker census cannot be empty"
        assert _violations(markers) == []
        assert all(t in SEAM.DOMAIN_CONSTANTS for _, _, t in markers)

    def test_doc_comment_mentions_are_not_markers(self, repo_cwd):
        """Appendix G.2: a leading-comment line that mentions the convention
        is not a marker — only a trailing comment on a code line counts."""
        marker_sites = {(p, n) for p, n, _ in SEAM.domain_markers()}
        doc_mentions = _doc_mentions()
        assert doc_mentions, "the tree is known to hold doc-comment mentions"
        assert not (set(doc_mentions) & marker_sites)


class TestLongestPrefixEntitlement:
    def test_file_stem_bend_beats_the_directory_row(self):
        # fs/cache/origin_auth* is CONFIG (origin credentials), while the
        # directory around it is CACHE — the longer prefix must win.
        assert SEAM.domain_entitled("src/fs/cache/origin_auth_gsi.c") == frozenset(
            ("DOMAIN_CONFIG",)
        )
        assert SEAM.domain_entitled("src/fs/cache/cstore.c") == frozenset(
            ("DOMAIN_CACHE",)
        )

    def test_journal_stem_bend_inside_the_stage_tree(self):
        assert SEAM.domain_entitled(
            "src/fs/xfer/stage_request_registry.c"
        ) == frozenset(("DOMAIN_JOURNAL",))
        assert SEAM.domain_entitled("src/fs/xfer/spool.c") == frozenset(
            ("DOMAIN_STAGE",)
        )


# --- error --------------------------------------------------------------------


class TestMalformedMarkerFails:
    def test_missing_domain_constant_fails(self):
        v = SEAM.domain_violation("src/fs/cache/x.c", 7, None)
        assert v is not None and "missing domain constant" in v

    def test_unknown_domain_constant_fails(self):
        v = SEAM.domain_violation("src/fs/cache/x.c", 7, "DOMAIN_BOGUS")
        assert v is not None and "unknown domain constant" in v
        assert "DOMAIN_BOGUS" in v

    def test_legacy_reason_first_marker_parses_as_unknown(self):
        # The pre-C9 form '/* vfs-seam-allow: temp scratch file */' now
        # tokenizes its first word, which is not a constant — it must fail,
        # not silently pass as unannotated.
        m = SEAM.DOMAIN_TOKEN_RE.search("/* vfs-seam-allow: temp scratch */")
        assert m is not None
        assert SEAM.domain_violation("src/fs/cache/x.c", 7, m.group(1)) is not None


# --- security negative --------------------------------------------------------


class TestDomainGrantsNothing:
    def test_config_waiver_in_a_data_plane_file_fails(self):
        v = SEAM.domain_violation("src/fs/cache/cstore.c", 3, "DOMAIN_CONFIG")
        assert v is not None and "not entitled" in v

    def test_registry_waiver_outside_the_oci_tree_fails(self):
        v = SEAM.domain_violation("src/fs/cache/cstore.c", 3, "DOMAIN_REGISTRY")
        assert v is not None and "not entitled" in v

    def test_unlisted_path_is_entitled_to_nothing(self):
        path = "src/observability/metrics/unified_record.c"
        assert SEAM.domain_entitled(path) == frozenset()
        for domain in sorted(SEAM.DOMAIN_CONSTANTS - {"NOT_STORAGE", "SEAM_CORRECT"}):
            assert SEAM.domain_violation(path, 1, domain) is not None

    def test_escape_valves_pass_everywhere_but_widen_no_entitlement(self):
        # NOT_STORAGE / SEAM_CORRECT are honesty valves, not grants: they
        # pass in a data-plane file, yet that file's entitlement set is
        # unchanged and a DOMAIN_* claim there still fails.
        assert SEAM.domain_violation("src/fs/cache/cstore.c", 3, "NOT_STORAGE") is None
        assert SEAM.domain_violation("src/fs/cache/cstore.c", 3, "SEAM_CORRECT") is None
        assert SEAM.domain_entitled("src/fs/cache/cstore.c") == frozenset(
            ("DOMAIN_CACHE",)
        )
        assert (
            SEAM.domain_violation("src/fs/cache/cstore.c", 3, "DOMAIN_REGISTRY")
            is not None
        )

    def test_domain_export_does_not_exist(self):
        # Appendix G.1 row 1: an EXPORT mutation takes the phase-105 typed
        # policy gate — there is no waiver constant that could name it.
        assert "DOMAIN_EXPORT" not in SEAM.DOMAIN_CONSTANTS
        v = SEAM.domain_violation("src/fs/vfs/vfs_write.c", 1, "DOMAIN_EXPORT")
        assert v is not None and "unknown domain constant" in v
