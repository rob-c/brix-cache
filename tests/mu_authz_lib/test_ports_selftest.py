"""Self-test for MU port/dir constants (unprivileged, no fleet)."""
from mu_authz_lib import fleet, ports


def test_ports_distinct():
    """Two instances on one port collide at bind; the loser looks like a flaky start.

    Only uniqueness is asserted, not a numeric band: these attributes start at
    their historical defaults and are OVERWRITTEN by the lifecycle ledger's
    assignment the moment ``fleet.start()`` runs, so a range check here passes or
    fails on whether some earlier module in the same session happened to bring
    the fleet up.  Uniqueness is true in both states and is the property that
    actually matters."""
    vals = ports.MU.all_ports()
    assert len(vals) == len(set(vals)), f"MU ports must be unique: {vals}"


def test_every_endpoint_names_a_started_instance():
    """The oracle's (protocol, variant) vocabulary must not outrun the fleet.

    ``fleet.url()`` refuses an endpoint the run did not start, but only at call
    time — deep inside a measurement.  This catches the same slip statically: an
    ``_ENDPOINT`` row whose instance has no ``_SERVERS`` template can never be
    reached, and one that names no ``ports.MU`` attribute would raise on getattr."""
    started = {attr for _template, attr, _proto in fleet._SERVERS}
    for (proto, variant), attr in fleet._ENDPOINT.items():
        assert attr in started, f"{proto}/{variant} -> {attr}, which _SERVERS never starts"
        assert hasattr(ports.MU, attr), f"{attr} is not a ports.MU attribute"


def test_enforcing_excludes_cvmfs():
    enf = ports.MU.enforcing_ports()
    assert ports.MU.CVMFS_CACHE not in enf, "cvmfs is public-by-design, not enforcing"
    assert ports.MU.CACHE_NOIMP in enf and ports.MU.WEBDAV_CACHE in enf \
        and ports.MU.S3_CACHE in enf


def test_roots_under_mu():
    assert ports.MU.DATA_ROOT.startswith(ports.MU.MU_ROOT)
    assert ports.MU.CACHE_ROOT.startswith(ports.MU.MU_ROOT)
    assert ports.MU.CA_DIR.endswith("/ca")
