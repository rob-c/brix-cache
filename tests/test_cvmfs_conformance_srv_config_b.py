from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_srv_config_helpers")

def test_delete_never_removes_cached_object(plain_srv):
    obj = plain_srv.objects()[2]
    ref = urllib.request.urlopen(plain_srv.base_url + obj, timeout=15).read()
    status, _, _ = request(HOST, plain_srv.nginx_port, "DELETE", obj)
    assert status >= 400, f"DELETE must be refused, got {status}"
    again = urllib.request.urlopen(plain_srv.base_url + obj, timeout=15).read()
    assert again == ref, "DELETE must not disturb the cached object"


def test_post_with_body_rejected(plain_srv):
    obj = plain_srv.objects()[3]
    status, _, _ = request(HOST, plain_srv.nginx_port, "POST", obj,
                           body=b"x" * 128)
    assert status >= 400, f"POST must be refused, got {status}"
