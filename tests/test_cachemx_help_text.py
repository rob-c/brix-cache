"""Per-family HELP-text conformance: every exported family's HELP line
pinned verbatim.

WHAT: One scrape, then a parametrized pin of each of the 196 families'
      HELP text against the calibrated snapshot in _cachemx_catalog_data,
      plus exposition-ordering rules (HELP precedes TYPE, each emitted
      exactly once, no orphan samples before their header block).

WHY:  HELP text is operator-facing API — dashboards, alert runbooks and the
      metrics docs quote it.  Silent HELP drift (a reworded or copy-pasted
      description) breaks that chain, and a HELP/TYPE ordering slip breaks
      strict exposition parsers.  A per-family pin names the exact family
      in the failing test id and forces the docs to move with the code.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401
from _cachemx_catalog_data import HELP

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]


@pytest.fixture(scope="module")
def expo(mx):
    """One raw scrape + parsed HELP map for the whole module."""
    text = cx.mfetch(mx.metrics)
    helps = {}
    for line in text.splitlines():
        if line.startswith("# HELP "):
            _, _, fam, h = line.split(" ", 3)
            helps.setdefault(fam, []).append(h)
    return text, helps


@pytest.mark.parametrize("family", sorted(HELP))
def test_help_text_pinned(expo, family):
    """The family emits exactly one HELP line with the calibrated text."""
    _, helps = expo
    assert helps.get(family) == [HELP[family]]


def test_help_set_complete_no_drift(expo):
    """The set of HELP'd families matches the snapshot in both directions."""
    _, helps = expo
    assert set(helps) == set(HELP)


def test_help_line_precedes_type_line(expo):
    """For every family, # HELP appears before # TYPE — the ordering strict
    Prometheus text-format parsers expect."""
    text, _ = expo
    seen_help = set()
    for line in text.splitlines():
        if line.startswith("# HELP "):
            seen_help.add(line.split(" ", 3)[2])
        elif line.startswith("# TYPE "):
            fam = line.split(" ", 3)[2]
            assert fam in seen_help, f"TYPE before HELP for {fam}"


def test_no_samples_before_family_header(expo):
    """Every sample line appears after its family's HELP/TYPE block — an
    orphan sample means two emit sites for one family."""
    text, _ = expo
    headered = set()
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            headered.add(line.split(" ", 3)[2])
        elif line and not line.startswith("#"):
            sample = line.split("{", 1)[0].split(" ", 1)[0]
            base = _sample_family(sample, headered)
            assert base in headered, f"sample before header: {sample}"


def _sample_family(sample, headered):
    for suffix in ("_bucket", "_sum", "_count"):
        candidate = sample.removesuffix(suffix)
        if candidate != sample and candidate in headered:
            return candidate
    return sample


def test_help_text_is_single_line_ascii(expo):
    """HELP text stays single-line printable ASCII — embedded newlines or
    control bytes would corrupt the exposition."""
    _, helps = expo
    for fam, (h,) in helps.items():
        assert h.isprintable(), f"non-printable HELP for {fam}"
        assert "\\n" not in h, f"escaped newline in HELP for {fam}"
