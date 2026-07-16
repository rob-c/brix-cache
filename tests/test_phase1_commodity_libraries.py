"""
Phase 1 commodity-library inventory.

The behavioral tests live in the unit and integration suites.  This file keeps
the source-reduction plan honest by checking that Phase 1's library-backed
adapters and XML helper migrations remain wired into the tree.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"Phase 1 file is missing: {relpath}"
    return path.read_text(encoding="utf-8").lower()


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker.lower() not in text]
    assert not missing, f"{relpath} is missing Phase 1 markers: {missing}"


def test_phase1_dependency_detection_hooks_present():
    # libxml2 remains optional; jansson is now a required dependency.
    # config must still probe for jansson and fail loudly if absent.
    _assert_markers(
        "config",
        [
            "pkg-config --exists libxml-2.0",
            "brix_have_libxml2",
            "pkg-config --exists jansson",
            "jansson library is required",  # hard-fail message when not found
        ],
    )
    _assert_markers(
        "tests/cmdscripts/unit_tests.py",
        [
            "pkg-config",
            "libxml-2.0",
            "jansson",
            "test_json.c",
            "test_xml_compat.c",
        ],
    )


def test_phase1_jansson_token_adapter_present():
    # Jansson is now a required dependency; no fallback path, no BRIX_HAVE_JANSSON guard.
    _assert_markers(
        "src/auth/token/json.c",
        [
            "#include <jansson.h>",
            "json_loadb",
            "json_backend_name",
        ],
    )
    _assert_markers(
        "src/auth/token/jwks.c",
        [
            "brix_jwks_load_jansson",
            "json_array_foreach",
            "loaded %d jwks key(s) from",
            "using jansson",
        ],
    )
    _assert_markers(
        "tests/unit/test_json.c",
        [
            "json_backend_name",
            "line\\\\nnext",
            "jansson unicode array decode",
        ],
    )


def test_phase1_shared_xml_element_helpers_present():
    _assert_markers(
        "src/core/compat/xml.h",
        [
            "brix_xml_text_element_len",
            "brix_xml_write_text_element",
        ],
    )
    # s3_xml_append_text_element was removed by Plan 4 Item 7; XML_APPEND_ELEM in
    # s3.h now calls brix_xml_write_text_element directly.
    _assert_markers(
        "src/protocols/s3/s3.h",
        [
            "brix_xml_write_text_element",
        ],
    )
    _assert_markers(
        "tests/unit/test_xml_compat.c",
        [
            "brix_xml_write_text_element",
            "invalid element name was accepted",
        ],
    )


def test_phase1_s3_response_builders_use_xml_helpers():
    # s3_xml_append_text_element was removed by Plan 4 Item 7.  XML_APPEND_ELEM
    # (defined in s3.h) now calls brix_xml_write_text_element directly.
    for relpath in (
        "src/protocols/s3/list_objects_v2.c",
        "src/protocols/s3/multipart_complete_list_parts.c",
        "src/protocols/s3/multipart_complete_list_uploads.c",
    ):
        _assert_markers(
            relpath,
            [
                "xml_append_elem",
            ],
        )


def test_phase1_roadmap_documents_status_and_macaroon_decision():
    _assert_markers(
        "docs/09-developer-guide/source-reduction-plan.md",
        [
            "Phase 1: Commodity libraries",
            "status: **complete",           # cleanup done 2026-05-20
            "jansson is now a **required",  # documents that Jansson is required
            "libmacaroons compatibility decision",
            "tests/test_phase1_commodity_libraries.py",
        ],
    )
