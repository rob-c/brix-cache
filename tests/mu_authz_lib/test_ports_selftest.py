"""Self-test for MU port/dir constants (unprivileged, no fleet)."""
from mu_authz_lib import ports


def test_ports_distinct_and_in_range():
    vals = ports.MU.all_ports()
    assert len(vals) == len(set(vals)), "MU ports must be unique"
    assert all(12100 <= v <= 12130 for v in vals), "MU ports live in 12100-12130"


def test_enforcing_excludes_cvmfs():
    enf = ports.MU.enforcing_ports()
    assert ports.MU.CVMFS_CACHE not in enf, "cvmfs is public-by-design, not enforcing"
    assert ports.MU.ROOT_CACHE in enf and ports.MU.WEBDAV_CACHE in enf and ports.MU.S3_CACHE in enf


def test_roots_under_mu():
    assert ports.MU.DATA_ROOT.startswith(ports.MU.MU_ROOT)
    assert ports.MU.CACHE_ROOT.startswith(ports.MU.MU_ROOT)
    assert ports.MU.CA_DIR.endswith("/ca")
