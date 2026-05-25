"""
Cross-protocol shared-helper inventory.

These tests keep the source-sharing work honest without starting nginx.  The
behavioral coverage lives in the WebDAV, S3, TPC, query, and metrics suites;
this file verifies that the protocol handlers remain wired through the shared
helpers instead of silently growing private copies again.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath):
    path = ROOT / relpath
    assert path.exists(), f"missing expected file: {relpath}"
    return path.read_text(encoding="utf-8")


def _assert_markers(relpath, markers):
    text = _read(relpath)
    missing = [marker for marker in markers if marker not in text]
    assert not missing, f"{relpath} is missing markers: {missing}"


def _assert_absent(relpath, markers):
    text = _read(relpath)
    present = [marker for marker in markers if marker in text]
    assert not present, f"{relpath} still has private helper markers: {present}"


def test_copy_and_http_file_response_helpers_are_shared():
    _assert_markers(
        "src/s3/copy.c",
        ['#include "s3.h"', "xrootd_ns_local_copy("],
    )
    _assert_absent("src/s3/copy.c", ["static int\ns3_copy_file"])
    _assert_markers(
        "src/webdav/fs/copy_engine.c",
        ["../../compat/copy_range.h", "xrootd_copy_range("],
    )
    _assert_markers(
        "src/webdav/get.c",
        ["../compat/http_file_response.h", "xrootd_http_send_file_range("],
    )
    _assert_markers(
        "src/s3/object.c",
        ["../compat/http_file_response.h", "xrootd_http_send_file_range("],
    )


def test_query_xml_and_base64url_helpers_are_shared():
    for relpath in (
        "src/s3/list_objects_v2.c",
        "src/s3/multipart_helpers.c",
        "src/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["xrootd_http_query_"])

    _assert_markers(
        "src/webdav/propfind.c",
        ["../compat/http_xml.h", "xrootd_http_chain_appendf("],
    )
    _assert_markers(
        "src/webdav/lock.c",
        ["../compat/http_xml.h", "xrootd_http_chain_appendf("],
    )
    _assert_absent("src/webdav/lock.c", ["webdav_propfind_append("])
    _assert_markers(
        "src/s3/util.c",
        ["../compat/http_xml.h", "xrootd_http_send_xml_error("],
    )
    _assert_markers(
        "src/s3/list_objects_v2.c",
        ["../token/b64url.h", "b64url_encode(", "b64url_decode("],
    )
    _assert_absent(
        "src/s3/list_objects_v2.c",
        ["static const signed char inv", "s3_b64url_"],
    )


def test_iso8601_and_hex_helpers_are_shared():
    _assert_markers(
        "src/compat/time.c",
        ["xrootd_format_iso8601(", ".000Z"],
    )
    for relpath in (
        "src/s3/copy.c",
        "src/s3/list_objects_v2.c",
        "src/s3/multipart_complete_list_parts.c",
        "src/s3/multipart_complete_list_uploads.c",
        "src/s3/multipart_complete_upload_part_copy.c",
        "src/webdav/propfind.c",
    ):
        _assert_markers(relpath, ["xrootd_format_iso8601("])
    _assert_markers("src/webdav/propfind.c", ["../compat/time.h"])
    _assert_absent("src/s3/util.c", ["s3_iso8601("])
    _assert_absent("src/s3/s3.h", ["s3_iso8601("])

    _assert_markers(
        "src/compat/hex.h",
        ["xrootd_hex_nibble(", "xrootd_hex_from_char(", "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/path/helpers.c",
        ["../compat/hex.h", "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/compat/xml.c",
        ['#include "hex.h"', "xrootd_hex_nibble("],
    )
    _assert_markers(
        "src/token/macaroon.c",
        ["../compat/hex.h", "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/compat/uri.c",
        ['#include "hex.h"', "xrootd_hex_from_char("],
    )
    _assert_markers(
        "src/compat/checksum.c",
        ['#include "hex.h"', "xrootd_hex_encode("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_verify.c",
        ["../compat/hex.h", "xrootd_hex_encode("],
    )
    _assert_absent("src/path/helpers.c", ["xrootd_hex_digit("])
    _assert_absent("src/compat/xml.c", ["xrootd_xml_hex_digit("])
    _assert_absent("src/token/macaroon.c", ["hex_to_int("])
    _assert_absent("src/compat/uri.c", ["hex_val("])
    _assert_absent("src/s3/auth_sigv4_canonical.c", ["hex_encode("])
    _assert_absent("src/s3/s3_auth_internal.h", ["hex_encode("])


def test_token_fs_usage_and_shm_slot_helpers_are_shared():
    for relpath in (
        "src/upstream/auth.c",
        "src/tpc/gsi_outbound_common.c",
        "src/tpc/tpc_token.c",
    ):
        _assert_markers(relpath, ["xrootd_token_read_file("])

    for relpath in ("src/tpc/tpc_token.c", "src/webdav/tpc_cred_parse.c"):
        _assert_markers(relpath, ["xrootd_oauth2_parse_access_token("])

    for relpath in (
        "src/query/space.c",
        "src/metrics/stream_cache.c",
        "src/webdav/propfind.c",
    ):
        _assert_markers(relpath, ["xrootd_fs_usage_"])

    for relpath in (
        "src/manager/pending.c",
        "src/tpc/key_registry.c",
        "src/webdav/lock.c",
    ):
        _assert_markers(relpath, ["../compat/shm_slots.h", "xrootd_shm_"])


def test_http_header_body_and_condition_helpers_are_shared():
    _assert_markers(
        "src/webdav/webdav.h",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )
    _assert_markers(
        "src/s3/auth_sigv4_parse.c",
        ["../compat/http_headers.h", "xrootd_http_get_header("],
    )
    _assert_markers(
        "src/s3/copy.c",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )
    _assert_markers(
        "src/compat/http_headers.h",
        ["xrootd_http_extract_bearer("],
    )
    _assert_markers(
        "src/webdav/auth_token.c",
        ["../compat/http_headers.h", "xrootd_http_extract_bearer("],
    )
    _assert_absent(
        "src/webdav/auth_token.c",
        ['ngx_strncmp(auth_hdr.data, "Bearer ", 7)'],
    )
    _assert_markers(
        "src/webdav/tpc.c",
        ["../compat/http_headers.h", "xrootd_http_extract_bearer("],
    )
    _assert_absent(
        "src/webdav/tpc.c",
        ['bearer_prefix = "Bearer "', "ngx_strncasecmp(auth_hdr->value.data"],
    )

    for relpath in ("src/webdav/put.c", "src/s3/put.c"):
        _assert_markers(
            relpath,
            ["../compat/http_body.h", "xrootd_http_body_write_to_fd("],
        )

    for relpath in ("src/webdav/propfind.c", "src/s3/delete_objects.c"):
        _assert_markers(relpath, ["../compat/http_body.h", "xrootd_http_body_read_all("])

    _assert_markers(
        "src/webdav/put.c",
        ["../compat/http_conditionals.h", "xrootd_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/webdav/methods/copy_conditionals.c",
        ["../../compat/http_conditionals.h", "xrootd_http_check_etag_preconditions("],
    )
    _assert_markers(
        "src/webdav/get.c",
        ["../compat/http_conditionals.h", "xrootd_http_check_if_modified_since("],
    )
    for relpath in ("src/webdav/copy.c", "src/webdav/move.c"):
        _assert_markers(relpath, ["xrootd_http_overwrite_forbidden("])


def test_phase1_http_status_header_and_query_helpers_are_shared():
    _assert_markers(
        "src/compat/http_headers.h",
        [
            "xrootd_http_effective_status(",
            "xrootd_http_set_header_num(",
            "xrootd_http_request_header_add(",
        ],
    )
    for relpath in ("src/webdav/metrics.c", "src/s3/metrics.c"):
        _assert_markers(
            relpath,
            ["../compat/http_headers.h", "xrootd_http_effective_status("],
        )

    _assert_markers(
        "src/webdav/xrdhttp.c",
        [
            "../compat/http_headers.h",
            "xrootd_http_set_header(",
            "xrootd_http_set_header_num(",
            "xrootd_http_request_header_add(",
        ],
    )
    _assert_absent(
        "src/webdav/xrdhttp.c",
        ["static ngx_int_t\nadd_header_str", "static ngx_int_t\nadd_header_num"],
    )

    _assert_markers(
        "src/s3/handler.c",
        [
            "../compat/http_query.h",
            "xrootd_http_query_get(",
            "xrootd_http_find_header(",
        ],
    )
    _assert_absent("src/s3/handler.c", ['needle[] = "list-type=2"'])
    _assert_markers(
        "src/s3/multipart_complete_upload_part_copy.c",
        ["../compat/http_headers.h", "xrootd_http_find_header("],
    )


def test_checksum_fs_walk_staging_and_cms_frame_helpers_are_shared():
    for relpath in (
        "src/query/checksum_qcksum.c",
        "src/query/checksum_qcksum_async.c",
        "src/query/checksum_ckscan_common.c",
        "src/query/checksum_ckscan_dispatch.c",
        "src/query/checksum_ckscan_async.c",
        "src/dirlist/dcksm.c",
        "src/webdav/xrdhttp.c",
    ):
        _assert_markers(relpath, ["../compat/checksum.h", "xrootd_checksum_"])

    for relpath in ("src/webdav/namespace.c", "src/s3/multipart_helpers.c"):
        _assert_markers(
            relpath,
            ["../compat/fs_walk.h", "xrootd_fs_remove_tree_confined("],
        )

    for relpath in ("src/webdav/propfind.c", "src/query/checksum_ckscan_common.c"):
        _assert_markers(relpath, ["xrootd_fs_is_dot_entry("])

    for relpath in (
        "src/s3/put.c",
        "src/webdav/tpc.c",
    ):
        _assert_markers(relpath, ["../compat/staged_file.h", "xrootd_staged_open("])

    for relpath in (
        "src/s3/copy.c",
        "src/webdav/copy.c",
    ):
        _assert_markers(relpath, ['#include "s3.h"' if "s3" in relpath else "webdav.h", "xrootd_ns_local_copy("])

    for relpath in ("src/cms/send.c", "src/cms/server_send.c"):
        _assert_markers(relpath, ["frame_io.h", "xrootd_cms_send_frame("])


def test_webdav_config_path_validation_is_shared():
    _assert_markers(
        "src/webdav/config.c",
        ["../config/config.h", "#define webdav_validate_path          xrootd_validate_path"],
    )
    _assert_absent(
        "src/webdav/config.c",
        ["typedef enum", "static char *\nwebdav_validate_path"],
    )


def test_security_level_enforcement_is_linked():
    _assert_markers(
        "src/handshake/dispatch.c",
        ["xrootd_verify_pending_sigver(", "xrootd_signing_enforce_level("],
    )
    _assert_markers(
        "src/handshake/sigver.c",
        [
            "xrootd_signing_enforce_level(",
            "xrootd_sigver_opcode_requires(",
            "kXR_InvalidRequest",
        ],
    )


def test_new_shared_helpers_are_wired_into_module_config():
    for marker in (
        "src/compat/checksum.c",
        "src/compat/fs_walk.c",
        "src/compat/http_body.c",
        "src/compat/http_conditionals.c",
        "src/compat/http_headers.c",
        "src/compat/hex.c",
        "src/compat/staged_file.c",
        "src/compat/time.c",
        "src/cms/frame_io.c",
    ):
        _assert_markers("config", [marker])
