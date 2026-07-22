"""WebDAV SEARCH (RFC 5323 DAV:basicsearch) tests.

Exercises src/protocols/webdav/search.c against the anonymous plain-HTTP
WebDAV listener of the shared "main" nginx instance: scope-only (depth 0),
direct children (depth 1) and recursive (depth infinity) enumeration, the
DAV:contains/DAV:literal displayname filter, malformed-query rejection, and
the namespace-hiding invariants (dotfiles and reserved internal sidecars must
never appear in a result set).

The fixture tree is created directly under DATA_ROOT (the instance's export
root), mirroring the PROPFIND suites' setup style, and removed on teardown.
"""

import os
import shutil
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

from settings import DATA_ROOT, NGINX_HTTP_WEBDAV_PORT, SERVER_HOST

BASE_URL = f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}"
DAV_NS = "DAV:"


def _search_body(depth="1", literal=None):
    """Build a DAV:basicsearch request body for the given scope depth and
    optional DAV:contains displayname literal."""
    where = ""
    if literal is not None:
        where = (
            "<D:where><D:contains>"
            f"<D:literal>{literal}</D:literal>"
            "</D:contains></D:where>"
        )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<D:searchrequest xmlns:D="DAV:">'
        "<D:basicsearch>"
        "<D:from><D:scope>"
        "<D:href>.</D:href>"
        f"<D:depth>{depth}</D:depth>"
        "</D:scope></D:from>"
        f"{where}"
        "</D:basicsearch>"
        "</D:searchrequest>"
    )


def _search(path, body):
    return requests.request(
        "SEARCH",
        f"{BASE_URL}{path}",
        data=body,
        headers={"Content-Type": "application/xml"},
        timeout=15,
    )


def _hrefs(xml_text):
    """Return the list of D:href texts from a 207 multistatus document."""
    root = ET.fromstring(xml_text)
    assert root.tag == f"{{{DAV_NS}}}multistatus", f"unexpected root {root.tag}"
    return [
        resp.findtext(f"{{{DAV_NS}}}href")
        for resp in root.findall(f"{{{DAV_NS}}}response")
    ]


@pytest.fixture(scope="module")
def search_tree():
    """A small directory tree under the export root:

        <dir>/file_a.txt
        <dir>/file_b.log
        <dir>/sub/nested.txt
        <dir>/.hidden.txt        (dotfile — must never be listed)
        <dir>/shadow.bin.cinfo   (reserved sidecar — must never be listed)
    """
    name = f"search_{uuid.uuid4().hex}"
    root = os.path.join(DATA_ROOT, name)
    os.makedirs(os.path.join(root, "sub"))
    for rel in ("file_a.txt", "file_b.log", os.path.join("sub", "nested.txt"),
                ".hidden.txt", "shadow.bin.cinfo"):
        with open(os.path.join(root, rel), "w") as fh:
            fh.write(f"search fixture {rel}\n")
    yield name
    shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Success paths
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("main")
def test_search_depth1_lists_direct_children(search_tree):
    """Depth 1 returns the scope plus its direct children, not grandchildren."""
    r = _search(f"/{search_tree}/", _search_body(depth="1"))
    assert r.status_code == 207, f"SEARCH failed: {r.status_code} {r.text}"
    assert "application/xml" in r.headers.get("Content-Type", "")

    hrefs = _hrefs(r.text)
    assert f"/{search_tree}/" in hrefs
    assert f"/{search_tree}/file_a.txt" in hrefs
    assert f"/{search_tree}/file_b.log" in hrefs
    assert f"/{search_tree}/sub" in hrefs
    assert not any(h.endswith("nested.txt") for h in hrefs), \
        "depth 1 must not descend into subdirectories"


@pytest.mark.registry_server("main")
def test_search_depth_infinity_recurses(search_tree):
    """Depth infinity descends into subdirectories."""
    r = _search(f"/{search_tree}/", _search_body(depth="infinity"))
    assert r.status_code == 207
    hrefs = _hrefs(r.text)
    assert f"/{search_tree}/sub/nested.txt" in hrefs


@pytest.mark.registry_server("main")
def test_search_depth0_scope_only(search_tree):
    """Depth 0 returns exactly one response: the scope itself."""
    r = _search(f"/{search_tree}/", _search_body(depth="0"))
    assert r.status_code == 207
    assert _hrefs(r.text) == [f"/{search_tree}/"]


@pytest.mark.registry_server("main")
def test_search_contains_literal_filters_displayname(search_tree):
    """A DAV:contains literal keeps only matching displaynames (substring of
    the final path segment), including filtering out the scope itself."""
    r = _search(f"/{search_tree}/", _search_body(depth="1", literal="file_a"))
    assert r.status_code == 207
    hrefs = _hrefs(r.text)
    assert hrefs == [f"/{search_tree}/file_a.txt"], f"unexpected hrefs: {hrefs}"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("main")
def test_search_malformed_xml_rejected(search_tree):
    """A non-XML body must be rejected with 400."""
    r = _search(f"/{search_tree}/", "this is not xml <<<")
    assert r.status_code == 400


@pytest.mark.registry_server("main")
def test_search_wrong_root_element_rejected(search_tree):
    """A well-formed body that is not DAV:searchrequest>basicsearch is 400."""
    body = '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>'
    r = _search(f"/{search_tree}/", body)
    assert r.status_code == 400


@pytest.mark.registry_server("main")
def test_search_empty_body_rejected(search_tree):
    """SEARCH without a request body must be rejected with 400."""
    r = _search(f"/{search_tree}/", "")
    assert r.status_code == 400


@pytest.mark.registry_server("main")
def test_search_nonexistent_scope_404(search_tree):
    """SEARCH on a missing collection resolves to 404, not an empty 207."""
    r = _search(f"/{search_tree}/no_such_dir/", _search_body(depth="1"))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Security-negative: namespace hiding
# ---------------------------------------------------------------------------

@pytest.mark.registry_server("main")
def test_search_hides_dotfiles_and_internal_sidecars(search_tree):
    """A match-all recursive SEARCH must never surface dotfiles or reserved
    internal sidecar names (.cinfo etc.) — their existence is a residency leak."""
    r = _search(f"/{search_tree}/", _search_body(depth="infinity"))
    assert r.status_code == 207
    hrefs = _hrefs(r.text)
    assert not any(".hidden" in h for h in hrefs), f"dotfile leaked: {hrefs}"
    assert not any(h.endswith(".cinfo") for h in hrefs), f"sidecar leaked: {hrefs}"


@pytest.mark.registry_server("main")
def test_search_literal_cannot_reveal_hidden_names(search_tree):
    """Even a literal that matches a hidden name exactly must return nothing —
    the filter runs over the already-hidden-pruned listing."""
    for literal in (".hidden.txt", "shadow.bin.cinfo"):
        r = _search(f"/{search_tree}/", _search_body(depth="infinity",
                                                     literal=literal))
        assert r.status_code == 207
        hrefs = _hrefs(r.text)
        assert hrefs == [], f"hidden name {literal!r} surfaced: {hrefs}"
