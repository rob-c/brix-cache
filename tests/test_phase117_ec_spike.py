"""Phase 117 — the erasure-coding spike's claims, pinned to the tree.

A design spike is prose, and prose rots silently: the next person to plan this
work reads it as authoritative long after the files it cites have moved. These
rows are the difference between a closed spike and a stale one.

  success           the corrections the spike produced are in the tree, and the
                    document records a verdict rather than a discussion
  error             every in-tree artifact the document cites still resolves
                    (the NO-PHANTOM-EVIDENCE rule from phase 111)
  security negative no `src/` code SETS `kXR_ecRedir` — a server that
                    advertises a shard layout it does not implement misleads
                    every client that believes it.  Reading the bit off a
                    foreign server is the opposite act and stays allowed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SPIKE = REPO / "docs" / "refactor" / "phase-117-erasure-coding-design-spike.md"
GAPS = REPO / "docs" / "10-reference" / "protocol-gaps-vs-xrootd.md"
FLAGS = REPO / "src" / "protocols" / "root" / "protocol" / "flags.h"

# A path in backticks, e.g. `src/fs/backend/csi_verify.c` — optionally with one
# brace group naming several siblings: `csi_{tagstore,verify,scrub}.c`.
_CITED = re.compile(r"`((?:src|tests|client|tools|docs|shared)/[^`\s]+)`")
_BRACE = re.compile(r"\{([^}]*)\}")

# Setting the bit: an assignment or an or-in.  A decode table row
# (`{ kXR_ecRedir, "ec-redir" }`) matches none of these, by design.
_SETS = re.compile(r"(\|=|=|\|)\s*kXR_ecRedir")


def _expand(cited: str):
    """One cited path -> the concrete paths it names (brace groups expanded)."""
    group = _BRACE.search(cited)
    if not group:
        return [cited]
    return [cited[:group.start()] + alt + cited[group.end():]
            for alt in group.group(1).split(",")]


def _cited_paths(text: str):
    """Every repo path the document cites AS EXISTING.

    A design spike names artifacts of both kinds — the seams it argues from,
    which must exist, and the ones it would create, which must not.  The second
    kind is marked `(proposed` on its own line rather than guessed at here: a
    guard that inferred the difference would either red on the design or, worse,
    stop noticing when a real citation went missing.
    """
    lines = [line for line in text.splitlines() if "(proposed" not in line]
    return [p for line in lines for match in _CITED.findall(line)
            for p in _expand(match)]


def _strip_line_ref(path: str) -> str:
    """`file.c:270` cites a line; the file is what has to exist."""
    return path.split(":", 1)[0]


@pytest.fixture(scope="module")
def spike() -> str:
    return SPIKE.read_text()


# -- success: the spike produced corrections, and they are in the tree ------
def test_the_spike_records_a_verdict_not_a_discussion(spike):
    """W6.1 asked for a go/no-go, so the absence of one is a failed spike."""
    assert "NO-GO" in spike
    assert re.search(r"^## 7\. Verdict$", spike, re.M)


def test_the_verdict_carries_the_trigger_that_would_reverse_it(spike):
    """A NO-GO with no reversal condition is a refusal, not a decision."""
    verdict = spike.split("## 7. Verdict", 1)[1].split("## 8.", 1)[0]
    assert "trigger that reverses" in verdict.lower()
    assert "kXR_ecRedir" in verdict or "client-side" in verdict


def test_the_gap_table_no_longer_calls_xrdec_an_event_data_catalog():
    """The mislabel the spike found: a design started from that row would have
    been designed against the wrong module."""
    text = GAPS.read_text()
    assert "Event data catalog" not in text
    row = [line for line in text.splitlines() if line.startswith("| `XrdEc`")]
    assert len(row) == 1
    assert "Erasure coding" in row[0]


def test_the_gap_table_no_longer_calls_csi_erasure_coding():
    """`XrdOssCsi` is the integrity layer, and it is implemented here — the row
    said the opposite of both halves."""
    text = GAPS.read_text()
    row = [line for line in text.splitlines() if line.startswith("| `XrdOssCsi`")]
    assert len(row) == 1
    assert "Checksummed storage integrity" in row[0]
    assert "csi_" in row[0]


def test_the_integrity_layer_that_row_now_claims_actually_exists():
    """The correction is only worth making if the claim behind it is true."""
    for name in ("csi_tagstore.c", "csi_verify.c", "csi_scrub.c"):
        assert (REPO / "src" / "fs" / "backend" / name).is_file()


# -- error: nothing the document cites has gone missing --------------------
def test_every_in_tree_artifact_the_spike_cites_resolves(spike):
    """NO-PHANTOM-EVIDENCE (phase 111): a spike citing a file that no longer
    exists reads authoritative and is wrong."""
    missing = [p for p in _cited_paths(spike)
               if not (REPO / _strip_line_ref(p)).exists()]
    assert missing == [], missing


def test_a_proposed_path_is_exempt_but_only_where_it_says_so(spike):
    """The exemption is narrow on purpose, so prove both halves of it."""
    assert "src/fs/backend/ec/" in spike            # the document names it
    assert not (REPO / "src/fs/backend/ec").exists()   # ...and it does not exist
    assert "src/fs/backend/ec/" not in _cited_paths(spike)
    unmarked = "cites `src/fs/backend/ec/` with no marker"
    assert "src/fs/backend/ec/" in _cited_paths(unmarked)


def test_the_spike_cites_the_seams_its_placement_argument_rests_on(spike):
    """The decorator-driver argument is an argument ABOUT two existing files;
    if it stops naming them it has stopped being checkable."""
    cited = set(_cited_paths(spike))
    assert any("sd_cache" in c or "csi_" in c for c in cited)
    assert "src/fs/vfs/vfs_backend_config_http.c:223" in spike


def test_the_failover_pipe_the_spike_warns_about_is_still_failover():
    """§5 refuses to reuse `|` for stripes because it means failover today.
    If that ever stops being true the warning is stale, not merely wrong."""
    text = (REPO / "src/fs/vfs/vfs_backend_config_http.c").read_text()
    assert "failover" in text
    assert "'|'" in text or '"|"' in text or "pipe" in text


# -- security negative: the flag stays unset -------------------------------
def _sets_the_flag(root: Path):
    hits = []
    for path in root.rglob("*.[ch]"):
        for num, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith(("*", "//", "#define")):
                continue
            if _SETS.search(line):
                hits.append(f"{path.relative_to(REPO)}:{num}")
    return hits


def test_no_server_code_sets_the_erasure_code_redirect_flag():
    """`kXR_ecRedir` promises the client a shard layout it must reassemble
    itself.  A server whose EC were internal must STILL leave it clear, so this
    is not a "not implemented yet" guard — setting it is wrong either way."""
    assert _sets_the_flag(REPO / "src") == []


def test_the_client_may_still_read_the_flag_off_a_foreign_server():
    """Advertising the bit and decoding somebody else's are opposite acts.

    A guard that banned the token outright would delete the diagnostic that
    tells an operator a REAL EC-redirecting server is on the other end.
    """
    doctor = REPO / "client/apps/diag/diag_doctor_recon.c"
    assert "kXR_ecRedir" in doctor.read_text()
    assert _sets_the_flag(REPO / "client") == []


def test_the_flag_comment_gives_the_real_reason_it_is_unset():
    """It said "out of scope — requires EC storage backend", which invites the
    next person with a backend to set it."""
    text = FLAGS.read_text()
    assert "NEVER SET" in text
    assert "phase-117" in text
