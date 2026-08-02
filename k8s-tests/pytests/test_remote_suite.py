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


def test_s3voms_scenario_dry_run_wires_voms_zero_provisioning(monkeypatch):
    """P80.14 s3-voms: installs charts/s3-voms as release sv, points the runner
    at the VOMS gateway + MinIO, and defaults to the VOMS multiuser suite."""
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    lines = " ".join(lab_suite.run("s3voms", []))
    assert all(t in lines for t in (
        "charts/s3-voms", "brix-s3voms", "TEST_S3VOMS_HOST=sv-s3voms",
        "TEST_MINIO_HOST=sv-minio", "tests/test_s3voms_multiuser.py"))


def test_pbgsi_scenario_dry_run_wires_local_pblock_no_backend(monkeypatch):
    """P80.25 pb-gsi: installs charts/pb-gsi as release pb over a LOCAL pblock
    store — there is NO MinIO/S3 backend, so the wiring must carry no MinIO
    host, only the gateway + the group-isolation suite."""
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    lines = " ".join(lab_suite.run("pbgsi", []))
    assert all(t in lines for t in (
        "charts/pb-gsi", "brix-pbgsi", "TEST_PBGSI_HOST=pb-pbgsi",
        "tests/test_pbgsi_multiuser.py"))
    assert "MINIO" not in lines            # local pblock store, no S3 backend


def test_gridftp_scenario_dry_run_wires_interop_matrix(monkeypatch):
    """phase-82 P82.10 gridftp: installs charts/gridftp-interop as release gf,
    points the runner at the gsiftp/ftp gateway with BOTH the plain and the
    VOMS-AC proxy the chart's pki-bootstrap publishes, and defaults to the
    globus-url-copy/gfal2/VOMS/FTS interop suite."""
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    lines = " ".join(lab_suite.run("gridftp", []))
    assert all(t in lines for t in (
        "charts/gridftp-interop", "brix-gridftp", "TEST_GRIDFTP_HOST=gf-gridftp",
        "TEST_GRIDFTP_VOMS_PROXY=/auth/pki/vuser_proxy.pem",
        "tests/test_gridftp_interop.py"))


def test_gridftp_scenario_takes_an_explicit_selection(monkeypatch):
    """An explicit test selection overrides the gridftp default suite."""
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    assert "tests/test_x.py" in " ".join(lab_suite.run("gridftp", ["tests/test_x.py"]))


def test_stretch_scenarios_take_an_explicit_selection(monkeypatch):
    """An explicit test selection overrides the per-scenario default suite."""
    monkeypatch.setenv("XRD_LAB_DRY_RUN", "1")
    from labtools import lab_suite
    assert "tests/test_x.py" in " ".join(lab_suite.run("s3voms", ["tests/test_x.py"]))
    assert "tests/test_y.py" in " ".join(lab_suite.run("pbgsi", ["tests/test_y.py"]))


@pytest.mark.e2e
def test_a_pure_remote_file_passes_against_the_mega(lab):
    lab("up")
    r = lab("test", "remote-suite", "tests/test_query.py -k 'not gsi'")
    lab("down", "remote")
    r.ok().shows("passed")
