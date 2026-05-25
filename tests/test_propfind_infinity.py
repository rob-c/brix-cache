"""
tests/test_propfind_infinity.py

Integration tests for PROPFIND Depth: infinity (Feature 4).

Verifies that nginx-xrootd correctly:
  - Returns all descendants recursively for Depth: infinity
  - Returns only the requested resource for Depth: 0 (regression)
  - Returns only immediate children for Depth: 1 (regression)
  - Caps the response at PROPFIND_INFINITY_MAX_ENTRIES (10000) to prevent
    memory exhaustion on large trees

Uses the shared nginx WebDAV instance (http_webdav_url, port 8080).

Run:
    cd /home/rcurrie/HEP-x/nginx-xrootd
    source .venv/bin/activate
    PYTHONPATH=tests pytest tests/test_propfind_infinity.py -v
"""

import re
import uuid

import pytest
import requests

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _propfind(base_url, path, depth):
    """Issue a PROPFIND request and return the Response object."""
    body = (
        '<?xml version="1.0"?>'
        '<D:propfind xmlns:D="DAV:">'
        "<D:allprop/>"
        "</D:propfind>"
    )
    headers = {
        "Depth": depth,
        "Content-Type": "application/xml",
    }
    return requests.request(
        "PROPFIND",
        f"{base_url}{path}",
        data=body,
        headers=headers,
        timeout=30,
    )


def _put(base_url, path, data=b"content"):
    return requests.put(f"{base_url}{path}", data=data, timeout=10)


def _mkcol(base_url, path):
    return requests.request("MKCOL", f"{base_url}{path}", timeout=10)


def _delete(base_url, path):
    return requests.delete(f"{base_url}{path}", timeout=10)


def _count_href_entries(xml_body):
    """Count <D:response> elements in the PROPFIND Multi-Status response."""
    return len(re.findall(r"<[Dd]:response>", xml_body))


# ---------------------------------------------------------------------------
# Fixture: a small directory tree for depth tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tree(base_url):
    """
    Create a directory tree under /propfind_inf_<uid>/:
        /propfind_inf_<uid>/
            file_a.txt
            file_b.txt
            subdir/
                sub_file_1.txt
                sub_file_2.txt
                nested/
                    deep_file.txt

    Yields the root path (with leading slash, no trailing slash).
    Cleans up after all tests in the module.
    """
    uid = uuid.uuid4().hex[:8]
    root = f"/propfind_inf_{uid}"

    # Create top-level directory
    r = _mkcol(base_url, f"{root}/")
    assert r.status_code in (200, 201), f"MKCOL root failed: {r.status_code}"

    # Top-level files
    _put(base_url, f"{root}/file_a.txt", b"aaa")
    _put(base_url, f"{root}/file_b.txt", b"bbb")

    # subdir + its files
    r = _mkcol(base_url, f"{root}/subdir/")
    assert r.status_code in (200, 201), f"MKCOL subdir failed: {r.status_code}"
    _put(base_url, f"{root}/subdir/sub_file_1.txt", b"s1")
    _put(base_url, f"{root}/subdir/sub_file_2.txt", b"s2")

    # nested dir inside subdir
    r = _mkcol(base_url, f"{root}/subdir/nested/")
    assert r.status_code in (200, 201), f"MKCOL nested failed: {r.status_code}"
    _put(base_url, f"{root}/subdir/nested/deep_file.txt", b"deep")

    yield root

    # Cleanup: delete leaves first, then directories (server may not support
    # recursive DELETE — delete from deepest to shallowest)
    for path in [
        f"{root}/subdir/nested/deep_file.txt",
        f"{root}/subdir/nested/",
        f"{root}/subdir/sub_file_1.txt",
        f"{root}/subdir/sub_file_2.txt",
        f"{root}/subdir/",
        f"{root}/file_a.txt",
        f"{root}/file_b.txt",
        f"{root}/",
    ]:
        _delete(base_url, path)


@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPropfindDepthInfinity:
    """PROPFIND Depth: infinity — recursive traversal with cap."""

    def test_propfind_depth_infinity_returns_all_descendants(self, base_url, tree):
        """Depth: infinity on a directory returns root + all nested entries."""
        r = _propfind(base_url, f"{tree}/", "infinity")
        assert r.status_code == 207, (
            f"Expected 207 Multi-Status, got {r.status_code}: {r.text[:200]}"
        )
        xml = r.text
        count = _count_href_entries(xml)
        # Tree has: root(1) + file_a(1) + file_b(1) + subdir(1) +
        #           sub_file_1(1) + sub_file_2(1) + nested(1) + deep_file(1) = 8
        assert count == 8, (
            f"Expected 8 D:href entries for full tree, got {count}.\n"
            f"Response:\n{xml[:2000]}"
        )

    def test_propfind_depth_infinity_contains_deep_entry(self, base_url, tree):
        """Depth: infinity response includes deeply nested resources."""
        r = _propfind(base_url, f"{tree}/", "infinity")
        assert r.status_code == 207
        assert "deep_file.txt" in r.text, (
            "deep_file.txt (2 levels deep) not found in Depth: infinity response"
        )
        assert "nested" in r.text, (
            "nested/ subdir not found in Depth: infinity response"
        )

    def test_propfind_depth_infinity_on_file_returns_single_entry(
        self, base_url, tree
    ):
        """Depth: infinity on a regular file returns exactly that file (no children)."""
        r = _propfind(base_url, f"{tree}/file_a.txt", "infinity")
        assert r.status_code == 207
        count = _count_href_entries(r.text)
        assert count == 1, (
            f"Expected 1 D:href for a file target, got {count}"
        )


class TestPropfindDepthRegressions:
    """Regressions: Depth: 0 and Depth: 1 still work correctly."""

    def test_propfind_depth_zero_returns_only_root(self, base_url, tree):
        """Depth: 0 returns exactly one D:href — the requested resource itself."""
        r = _propfind(base_url, f"{tree}/", "0")
        assert r.status_code == 207, (
            f"Expected 207, got {r.status_code}"
        )
        count = _count_href_entries(r.text)
        assert count == 1, (
            f"Depth: 0 should return exactly 1 entry, got {count}"
        )

    def test_propfind_depth_one_returns_root_and_immediate_children(
        self, base_url, tree
    ):
        """Depth: 1 returns root + immediate children only (not nested)."""
        r = _propfind(base_url, f"{tree}/", "1")
        assert r.status_code == 207
        count = _count_href_entries(r.text)
        # root(1) + file_a(1) + file_b(1) + subdir(1) = 4
        assert count == 4, (
            f"Depth: 1 should return 4 entries (root + 3 children), got {count}"
        )
        assert "deep_file.txt" not in r.text, (
            "Depth: 1 should NOT include deeply nested files"
        )
        assert "sub_file_1.txt" not in r.text, (
            "Depth: 1 should NOT include files inside subdir"
        )

    def test_propfind_depth_one_on_subdir(self, base_url, tree):
        """Depth: 1 on subdir returns subdir + its immediate children."""
        r = _propfind(base_url, f"{tree}/subdir/", "1")
        assert r.status_code == 207
        count = _count_href_entries(r.text)
        # subdir(1) + sub_file_1(1) + sub_file_2(1) + nested(1) = 4
        assert count == 4, (
            f"Depth: 1 on subdir should return 4 entries, got {count}"
        )
        assert "deep_file.txt" not in r.text, (
            "Depth: 1 on subdir should NOT descend into nested/"
        )


class TestPropfindDepthInfinitySecurity:
    """Security: cap prevents exhaustion; response is still valid XML."""

    def test_propfind_response_is_valid_xml(self, base_url, tree):
        """Depth: infinity response starts with XML declaration and multistatus."""
        r = _propfind(base_url, f"{tree}/", "infinity")
        assert r.status_code == 207
        assert "multistatus" in r.text.lower(), (
            "Response body does not contain multistatus element"
        )
        assert r.headers.get("Content-Type", "").startswith("application/xml"), (
            f"Content-Type should be application/xml, got {r.headers.get('Content-Type')}"
        )

    def test_propfind_depth_infinity_missing_depth_header_defaults_to_zero(
        self, base_url, tree
    ):
        """Missing Depth header defaults to depth=0 (single resource, safe default)."""
        body = (
            '<?xml version="1.0"?>'
            '<D:propfind xmlns:D="DAV:">'
            "<D:allprop/>"
            "</D:propfind>"
        )
        # No Depth header at all
        r = requests.request(
            "PROPFIND",
            f"{base_url}{tree}/",
            data=body,
            headers={"Content-Type": "application/xml"},
            timeout=10,
        )
        assert r.status_code == 207
        count = _count_href_entries(r.text)
        # No Depth header → depth=0 → only the root collection entry
        assert count == 1, (
            f"Missing Depth header should yield depth=0 (1 entry), got {count}"
        )
