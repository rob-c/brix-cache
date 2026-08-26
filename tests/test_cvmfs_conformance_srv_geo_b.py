from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_geo_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_srv_geo")

def test_ttl_back_to_back_single_probe(ttl_srv, listener):
    l = listener()
    geo_get(ttl_srv, l.token)
    geo_get(ttl_srv, l.token)
    assert l.count == 1
