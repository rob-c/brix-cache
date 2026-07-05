"""remote-suite tooling — coverage classification + sync fork logic (pure Python),
plus xrd-lab wiring (dry-run fast, live @e2e)."""
import pytest

from labtools import SUITE, coverage, sync


def test_coverage_classifies_every_file_none_unhandled():
    c = coverage.classify()
    assert sum(c.values()) == len(list(SUITE.glob("test_*.py")))
    assert c["server_local"] == 0            # fully migrated
    assert c["pure_remote"] and c["adapted"]


def test_is_protected_detects_markers(tmp_file):
    assert sync.is_protected(tmp_file("a.py", "# brix-remote-adapted\nX = 1\n"))
    assert not sync.is_protected(tmp_file("b.py", "import os\n"))


def test_sync_forks_and_never_clobbers_adapted(tmp_path):
    repo, dest = tmp_path / "repo", tmp_path / "dest"
    (repo / "tests").mkdir(parents=True)
    (repo / "utils").mkdir(parents=True)
    (repo / "tests" / "settings.py").write_text("S = 1\n")
    (repo / "utils" / "make_proxy.py").write_text("M = 1\n")
    (repo / "tests" / "adapted.py").write_text("# brix-remote-adapted\nORIG = 1\n")
    (dest / "tests").mkdir(parents=True)
    (dest / "tests" / "adapted.py").write_text("# brix-remote-adapted\nKEEP = 1\n")

    sync.sync(repo=repo, dest=dest)

    assert (dest / "tests" / "settings.py").read_text() == "S = 1\n"
    assert (dest / "utils" / "make_proxy.py").exists()
    assert "KEEP = 1" in (dest / "tests" / "adapted.py").read_text()   # preserved


def test_remote_suite_dry_run_wires_mega_and_client(monkeypatch):
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    lines = " ".join(lab_suite.run("remote-suite", []))
    assert all(t in lines for t in ("fleet-mega", "brix-client", "TEST_SERVER_HOST=srv-mega"))


@pytest.mark.e2e
def test_a_pure_remote_file_passes_against_the_mega(lab):
    lab("up")
    r = lab("test", "remote-suite", "tests/test_query.py -k 'not gsi'")
    lab("down", "remote")
    r.ok().shows("passed")
