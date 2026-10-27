"""Resource-complete authorization regressions for local WebDAV COPY.

Local COPY has two caller-controlled operands and collection COPY expands each
operand into a tree.  These tests pin the edge contract: source reads,
destination create/update, overwrite deletion, and every recursive child are
authorized before their storage operation.  The async-backend fixture is used
deliberately so identity-free background execution cannot reappear unnoticed.
"""

import pathlib

import pytest
import requests

from test_backend_async_webdav import _Server, _bearer, _have_nginx


pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-webdav-copy-authorization")]


@pytest.fixture()
def make_copy_server(lifecycle, tmp_path):
    """Build isolated token or XrdAcc WebDAV COPY fixtures."""
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the async queue")

    def _factory(**kwargs):
        kwargs.setdefault("wait", "30000ms")
        return _Server(lifecycle, tmp_path, **kwargs).start()

    return _factory


def _copy(srv, source, destination, headers=None):
    """Issue one same-export COPY with deterministic headers."""
    request_headers = {"Destination": f"{srv.base}/{destination}"}
    if headers:
        request_headers.update(headers)
    return requests.request(
        "COPY", f"{srv.base}/{source}", headers=request_headers,
        verify=False, timeout=15)


def _seed_collection(srv, root, files):
    """Create one backend collection without exercising HTTP authorization."""
    base = pathlib.Path(srv.data) / root
    base.mkdir(parents=True, exist_ok=True)
    for relative, payload in files.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return base


def test_copy_token_read_source_write_destination_succeeds(make_copy_server):
    """Success: COPY reads its source and writes its independent Destination."""
    srv = make_copy_server(token_auth=True)
    source_dir = _seed_collection(srv, "copy-source", {"item.txt": b"copy\n"})
    (srv.data / "copy-target").mkdir()
    token = srv.issuer.generate(
        scope="storage.read:/copy-source storage.write:/copy-target")

    response = _copy(
        srv, "copy-source/item.txt", "copy-target/item.txt", _bearer(token))

    assert response.status_code == 201, response.text
    assert (source_dir / "item.txt").read_bytes() == b"copy\n"
    assert (srv.data / "copy-target/item.txt").read_bytes() == b"copy\n"


def test_copy_token_source_only_cannot_cross_destination_scope(make_copy_server):
    """SECURITY-NEG: source read authority never grants Destination writes."""
    srv = make_copy_server(token_auth=True)
    source_dir = _seed_collection(srv, "copy-source", {"secret.txt": b"stay\n"})
    target_dir = _seed_collection(srv, "other-tenant", {})
    token = srv.issuer.generate(
        scope="storage.read:/copy-source storage.write:/copy-source")

    response = _copy(
        srv, "copy-source/secret.txt", "other-tenant/stolen.txt",
        _bearer(token))

    assert response.status_code == 403, response.text
    assert (source_dir / "secret.txt").read_bytes() == b"stay\n"
    assert not (target_dir / "stolen.txt").exists()


def test_copy_xrdacc_fresh_destination_rejects_update_only(make_copy_server):
    """Error: Update without Insert cannot create a fresh destination."""
    srv = make_copy_server(
        xrdacc_rules="u * /copy-source r /copy-target rw\n")
    _seed_collection(srv, "copy-source", {"item.txt": b"source\n"})
    (srv.data / "copy-target").mkdir()

    response = _copy(
        srv, "copy-source/item.txt", "copy-target/item.txt")

    assert response.status_code == 403, response.text
    assert not (srv.data / "copy-target/item.txt").exists()


def test_copy_xrdacc_create_privileges_permit_fresh_copy(make_copy_server):
    """Control: Insert, Read, and Write permit creation by COPY."""
    srv = make_copy_server(
        xrdacc_rules="u * /copy-source r /copy-target irw\n")
    _seed_collection(srv, "copy-source", {"item.txt": b"source\n"})
    (srv.data / "copy-target").mkdir()

    response = _copy(srv, "copy-source/item.txt", "copy-target/item.txt")

    assert response.status_code == 201, response.text
    assert (srv.data / "copy-target/item.txt").read_bytes() == b"source\n"


def test_copy_xrdacc_overwrite_requires_destination_delete(make_copy_server):
    """SECURITY-NEG: Update/Create cannot remove an existing destination."""
    srv = make_copy_server(
        xrdacc_rules="u * /copy-source r /copy-target irw\n")
    source = _seed_collection(srv, "copy-source", {"item.txt": b"new\n"})
    target = _seed_collection(srv, "copy-target", {"item.txt": b"old\n"})

    response = _copy(srv, "copy-source/item.txt", "copy-target/item.txt")

    assert response.status_code == 403, response.text
    assert (source / "item.txt").read_bytes() == b"new\n"
    assert (target / "item.txt").read_bytes() == b"old\n"


def test_copy_collection_denied_source_child_is_not_published(make_copy_server):
    """SECURITY-NEG: recursive COPY checks every source child for READ."""
    srv = make_copy_server(xrdacc_rules=(
        "u * /copy-source r /copy-source/secret.txt -r "
        "/copy-target irwd\n"))
    source = _seed_collection(
        srv, "copy-source", {"public.txt": b"public\n",
                             "secret.txt": b"secret\n"})

    response = _copy(srv, "copy-source", "copy-target")

    assert response.status_code == 403, response.text
    assert (source / "secret.txt").read_bytes() == b"secret\n"
    assert not (srv.data / "copy-target").exists()


def test_copy_collection_denied_destination_child_survives(make_copy_server):
    """SECURITY-NEG: overwrite checks each destination child before deletion."""
    srv = make_copy_server(xrdacc_rules=(
        "u * /copy-source r /copy-target irwd "
        "/copy-target/protected.txt -d\n"))
    _seed_collection(srv, "copy-source", {"replacement.txt": b"new\n"})
    target = _seed_collection(
        srv, "copy-target", {"protected.txt": b"keep\n"})

    response = _copy(srv, "copy-source", "copy-target")

    assert response.status_code == 403, response.text
    assert (target / "protected.txt").read_bytes() == b"keep\n"
    assert not (target / "replacement.txt").exists()


def test_copy_collection_fully_authorized_control_succeeds(make_copy_server):
    """Control: complete read/create/delete authority preserves recursive COPY."""
    srv = make_copy_server(
        xrdacc_rules="u * /copy-source r /copy-target irwd\n")
    source = _seed_collection(
        srv, "copy-source", {"nested/item.txt": b"new\n"})
    target = _seed_collection(srv, "copy-target", {"old.txt": b"old\n"})

    response = _copy(srv, "copy-source", "copy-target")

    assert response.status_code == 204, response.text
    assert (source / "nested/item.txt").read_bytes() == b"new\n"
    assert not (target / "old.txt").exists()
    assert (target / "nested/item.txt").read_bytes() == b"new\n"
