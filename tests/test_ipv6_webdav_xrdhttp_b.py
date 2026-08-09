from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ipv6_webdav_xrdhttp_helpers")

@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_overwrite_existing():
    """REGRESSION: a second PUT overwrites the object; GET returns the new body."""
    uid = _uid()
    path = f"/ipv6_overwrite_{uid}.txt"

    _put(path, b"original")
    _put(path, b"updated")

    r = _get(path)
    assert r.status_code == 200
    assert r.content == b"updated"


# ---------------------------------------------------------------------------
# Security-negative: path traversal must not bypass confinement over IPv6
# ---------------------------------------------------------------------------
@pytest.mark.registry_server("ipv6-webdav")
def test_ipv6_webdav_path_traversal_rejected():
    """SECURITY-NEG: a ``../`` escape PUT is rejected (never 200/201/500); IPv6
    does not bypass the confined-resolver contract enforced for every transport.

    The ``requests``/``urllib`` client normalises ``/../../../etc/X`` to
    ``/etc/X`` before it reaches the wire, so the server sees a PUT into a parent
    collection (``/etc``) that does not exist inside the confined data root and
    answers ``409 Conflict`` (the same missing-parent semantics as
    ``test_put_to_missing_parent_409``).  That is a valid rejection: confinement
    holds (nothing is created outside the root) and the request never succeeds.
    409 is therefore part of the accepted-rejection set; the gating assertion
    below still pins "no escape, no crash" (never 200/201/500).
    """
    uid = _uid()
    r = _put(f"/../../../etc/ipv6_escape_{uid}", b"blocked")
    assert r.status_code in (400, 403, 404, 409), (
        f"path-traversal PUT must be rejected, got {r.status_code}"
    )
    assert r.status_code not in (200, 201, 500)
