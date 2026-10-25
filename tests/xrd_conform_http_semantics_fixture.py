"""Controlled positive and hostile fixtures for the completed HTR semantics."""
import base64
import hashlib
import json
import os
import struct
import subprocess
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ephemeral_port import bind_port, free_port
from settings import HOST
from xrd_conform_s3_auth_fixture import (
    S3_ACCESS, S3_REGION, S3_SECRET, S3AuthMixin,
)
from _test_phase115_pgread_verify_helpers import (
    PgOrigin, error_frame, kXR_stat, ok_frame,
)

kXR_dirlist = 3004


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 31 + 11) & 0xFF for index in range(8192))
TARGET_ETAG = '"phase118-target"'


def _multipart(payload, ranges, corrupt=False):
    boundary = "brix-phase118-boundary"
    body = bytearray()
    for start, end in ranges:
        part = bytearray(payload[start:end + 1])
        if corrupt and part:
            part[0] ^= 0xFF
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(b"Content-Type: application/octet-stream\r\n")
        body.extend(
            f"Content-Range: bytes {start}-{end}/{len(payload)}\r\n\r\n".encode()
        )
        body.extend(part)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return boundary, bytes(body)


class _SemanticHandler(S3AuthMixin, BaseHTTPRequestHandler):
    """Handle one request using behavior and scratch state owned by the server."""

    protocol_version = "HTTP/1.1"

    def _etag(self, body):
        if self.server.behaviour == "etag_static":
            return '"static-etag"'
        return f'"{hashlib.sha256(body).hexdigest()}"'

    def _reply(self, status, body=b"", headers=()):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _request_path(self):
        """Return the decoded URI path without applying form-query rules."""
        return urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)

    def _object(self):
        path = self._request_path()
        if path in ("/fixture", "/bucket/fixture"):
            return self._base_object(path)
        body = self.server.scratch.get(path)
        alterers = {
            "prf_baseline_corrupt": self._alter_prf_object,
            "mutation_http_bytes_bad": self._alter_mutation_object,
            "s3_special_get_bad": self._alter_special_object,
        }
        alter = alterers.get(self.server.behaviour)
        return alter(path, body) if alter else body

    def _base_object(self, path):
        if self.server.behaviour == "htr_bad_009":
            return b""
        if self.server.behaviour == "s3_size_mismatch" \
                and path == "/bucket/fixture":
            return PAYLOAD + b"x"
        return PAYLOAD

    @staticmethod
    def _alter_prf_object(path, body):
        if path.endswith("brix-conform-http-prf") and body:
            return bytes([body[0] ^ 0xFF]) + body[1:]
        return body

    @staticmethod
    def _alter_mutation_object(path, body):
        if path.endswith("brix-conform-xpr-mutation") and body is not None:
            return b"wrong-object"
        return body

    @staticmethod
    def _alter_special_object(path, body):
        if path.endswith("brix-conform-s3-key-percent%"):
            return b"!"
        return body

    def _filename_variant(self):
        raw_path = urllib.parse.urlsplit(self.path).path.upper()
        suffixes = (".BRIX-CONFORM-UTF8-%C3%A9",
                    ".BRIX-CONFORM-LATIN1-%E9",
                    ".BRIX-CONFORM-RAW-%FF")
        return any(raw_path.endswith(suffix) for suffix in suffixes)

    def _s3_missing(self):
        path = self._request_path()
        if path.startswith("/bucket/fixture.brix-conform-missing-"):
            code = "InternalError" if self.server.behaviour == "s3_key_code_bad" \
                else "NoSuchKey"
        elif path.startswith("/brix-conform-missing-") \
                and path.endswith("/fixture"):
            code = "InternalError" \
                if self.server.behaviour == "s3_bucket_code_bad" \
                else "NoSuchBucket"
        else:
            return False
        body = f"<Error><Code>{code}</Code></Error>".encode()
        self._reply(404, body, (("Content-Type", "application/xml"),))
        return True

    def _visible_missing_prefix(self):
        return {
            "http_missing_visible": "/fixture.",
            "s3_missing_visible": "/bucket/fixture.",
        }.get(self.server.behaviour)

    def _cross_plane_visible(self):
        prefix = self._visible_missing_prefix()
        path = self._request_path()
        if prefix is None or not path.startswith(prefix) \
                or ".brix-conform-missing-" not in path:
            return False
        self._reply(200, b"unexpected-object")
        return True

    def _scratch_keys(self, prefix):
        return sorted(
            path.removeprefix("/bucket/")
            for path in self.server.scratch
            if path.startswith(f"/bucket/{prefix}")
        )

    def _alter_listing_keys(self, keys, prefix):
        if self.server.behaviour == "mutation_s3_hidden" \
                and prefix == "scratch/brix-conform-xpr-mutation":
            return []
        if self.server.behaviour == "s3_list_extra":
            return sorted(keys + [f"{prefix}unexpected"])
        if self.server.behaviour == "s3_special_list_bad" \
                and prefix == "scratch/brix-conform-s3-key-" and keys:
            return [f"{prefix}rewritten", *keys[1:]]
        return keys

    def _listed_keys(self, prefix, token):
        keys = self._scratch_keys(prefix)
        if prefix == "":
            keys.append("fixture")
            if self.server.behaviour == "s3_namespace_extra":
                keys.append("unexpected")
        keys = self._alter_listing_keys(sorted(keys), prefix)
        return [key for key in keys if key > token] if token else keys

    def _page_limit(self, keys, query):
        if self.server.behaviour == "s3_list_unbounded":
            return len(keys)
        return int(query.get("max-keys", [str(len(keys) or 1)])[0])

    def _alter_replayed_page(self, page, prefix, token):
        if not token or self.server.behaviour != "s3_list_replay_bad":
            return
        hits = self.server.token_hits.get(token, 0) + 1
        self.server.token_hits[token] = hits
        if hits > 1 and page:
            page[0] = f"{prefix}replay-diverged"

    def _list_page(self, keys, query, prefix, token):
        maximum = self._page_limit(keys, query)
        page = keys[:maximum]
        more = len(keys) > len(page)
        self._alter_replayed_page(page, prefix, token)
        return page, more

    def _s3_list(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/bucket" or query.get("list-type") != ["2"]:
            return False
        prefix = query.get("prefix", [""])[0]
        token = query.get("continuation-token", [""])[0]
        keys = self._listed_keys(prefix, token)
        page, more = self._list_page(keys, query, prefix, token)
        next_token = page[-1] if more and page else ""
        body = self._s3_list_body(page, more, next_token)
        self._reply(200, body, (("Content-Type", "application/xml"),))
        return True

    def _s3_list_body(self, page, more, next_token):
        contents = "".join(f"<Contents><Key>{key}</Key></Contents>"
                           for key in page)
        truncated = more or self.server.behaviour == "s3_namespace_truncated"
        return (
            "<ListBucketResult>"
            f"<IsTruncated>{str(truncated).lower()}</IsTruncated>"
            f"{contents}"
            f"<NextContinuationToken>{next_token}</NextContinuationToken>"
            "</ListBucketResult>"
        ).encode()

    def _multipart_query(self):
        parsed = urllib.parse.urlsplit(self.path)
        return parsed, urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True
        )

    def _multipart_error(self, code):
        body = f"<Error><Code>{code}</Code></Error>".encode()
        self._reply(400, body, (("Content-Type", "application/xml"),))

    def _multipart_start(self, parsed, query):
        if "uploads" not in query:
            return False
        self.server.upload_sequence += 1
        upload_id = f"upload-{self.server.upload_sequence}"
        self.server.uploads[upload_id] = {
            "path": urllib.parse.unquote(parsed.path),
            "parts": {},
            "order": [],
        }
        body = f"<InitiateMultipartUploadResult><UploadId>{upload_id}" \
               f"</UploadId></InitiateMultipartUploadResult>".encode()
        self._reply(200, body, (("Content-Type", "application/xml"),))
        return True

    def _completion_parts(self, body):
        try:
            root = ET.fromstring(body)
            return [int(part.findtext("PartNumber", "0"))
                    for part in root.findall("Part")]
        except (ET.ParseError, ValueError):
            return []

    @staticmethod
    def _multipart_missing(upload, requested):
        return any(part not in upload["parts"] for part in requested)

    @staticmethod
    def _multipart_small_nonfinal(upload, requested):
        present = [part for part in requested if part in upload["parts"]]
        return any(len(upload["parts"][part]) < 5 * 1024 * 1024
                   for part in present[:-1])

    def _multipart_order(self, upload, present):
        if self.server.behaviour == "s3_multipart_order_bad":
            return upload["order"]
        return present

    def _multipart_etag(self, part_count):
        if self.server.behaviour == "s3_multipart_etag_bad":
            return '"mock"'
        return f'"mock-{part_count}"'

    def _publish_multipart(self, upload_id, upload, requested):
        present = [part for part in requested if part in upload["parts"]]
        order = self._multipart_order(upload, present)
        self.server.scratch[upload["path"]] = b"".join(
            upload["parts"][part] for part in order
        )
        etag = self._multipart_etag(len(present))
        response = f"<CompleteMultipartUploadResult><ETag>{etag}</ETag>" \
                   f"</CompleteMultipartUploadResult>".encode()
        self.server.uploads.pop(upload_id, None)
        self._reply(200, response, (("Content-Type", "application/xml"),))

    def _multipart_complete(self, query, body):
        upload_id = query.get("uploadId", [""])[0]
        upload = self.server.uploads.get(upload_id)
        requested = self._completion_parts(body)
        if upload is None or not requested:
            self._multipart_error("InvalidRequest")
            return
        if self._multipart_missing(upload, requested) \
                and self.server.behaviour != "s3_multipart_missing_accepted":
            self._multipart_error("InvalidPart")
            return
        if self._multipart_small_nonfinal(upload, requested) \
                and self.server.behaviour != "s3_multipart_small_accepted":
            self._multipart_error("EntityTooSmall")
            return
        self._publish_multipart(upload_id, upload, requested)

    def do_POST(self):
        if not self._authorize():
            return
        parsed, query = self._multipart_query()
        if self._multipart_start(parsed, query):
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if "uploadId" in query:
            self._multipart_complete(query, body)
            return
        self._reply(405)

    def do_HEAD(self):
        if not self._authorize():
            return
        body = self._object()
        if body is None:
            self._reply(404)
            return
        self.server.head_hits += 1
        if (self.server.behaviour == "htr_bad_002"
                and self.server.head_hits > 1):
            body = body[:-1]
        self._reply(200, body, (("ETag", self._etag(body)),))

    def _chunked(self, body, mode):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("ETag", TARGET_ETAG)
        self.end_headers()
        if mode == "oversize":
            self.wfile.write(f"{len(body) + 10:x}\r\n".encode())
            self.wfile.write(body + b"\r\n0\r\n\r\n")
            self.close_connection = True
            return
        midpoint = len(body) // 2
        for part in (body[:midpoint], body[midpoint:]):
            self.wfile.write(f"{len(part):x}\r\n".encode())
            self.wfile.write(part + b"\r\n")
        if mode == "complete":
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.close_connection = True

    def _serve_chunked(self, body):
        modes = {
            "chunked_ok": "complete",
            "chunked_bad": "unterminated",
            "chunked_oversize": "oversize",
        }
        mode = modes.get(self.server.behaviour)
        if self.path != "/fixture" or mode is None \
                or self.headers.get("Range") is not None:
            return False
        self._chunked(body, mode)
        return True

    def _multipart_range(self, value):
        if value.count(",") >= 256:
            self._reply(200, PAYLOAD, (("ETag", TARGET_ETAG),))
            return
        ranges = ((0, 0), (2, 3)) if "0-0,2-3" in value else ((0, 5),)
        boundary, body = _multipart(
            PAYLOAD, ranges, corrupt=self.server.behaviour == "multipart_bad"
        )
        content_type = f"multipart/byteranges; boundary={boundary}"
        self._reply(206, body, (("Content-Type", content_type),))

    def _single_range(self, value, body):
        if value == "bytes=-1":
            start = len(body) - 1
            end = start
        else:
            first, last = value[6:].split("-", 1)
            start = int(first)
            end = len(body) - 1 if last == "" else min(
                int(last), len(body) - 1
            )
        part = body[start:end + 1]
        content_range = f"bytes {start}-{end}/{len(body)}"
        self._reply(206, part, (("Content-Range", content_range),))

    def _range_reply(self, value, body):
        bad_ranges = {
            "htr_bad_003": "bytes=0-0",
            "htr_bad_004": f"bytes={len(body) - 1}-",
            "htr_bad_005": "bytes=-1",
            "htr_bad_006": "bytes=-0",
            "htr_bad_007": f"bytes={len(body)}-",
            "htr_bad_008": f"bytes=0-{len(body)}",
            "htr_bad_009": "bytes=0-",
            "htr_bad_013": "bytes=abc-def",
            "htr_bad_014": "bytes=2-1",
        }
        if bad_ranges.get(self.server.behaviour) == value:
            self._bad_range_reply(body)
            return
        self._regular_range_reply(value, body)

    def _bad_range_reply(self, body):
        if self.server.behaviour in ("htr_bad_003", "htr_bad_004",
                                     "htr_bad_005"):
            byte = bytes([body[0] ^ 1]) if body else b"X"
            self._reply(206, byte, (("Content-Range",
                f"bytes 0-0/{len(body)}"),))
            return
        status = {
            "htr_bad_008": 416,
            "htr_bad_013": 500,
            "htr_bad_014": 500,
        }.get(self.server.behaviour)
        if status is not None:
            self._reply(status)
            return
        self._reply(200, body)

    def _regular_range_reply(self, value, body):
        if value == "bytes=abc-def":
            self._reply(200, body, (("ETag", TARGET_ETAG),))
            return
        if not body and value == "bytes=0-":
            self._reply(416)
            return
        if "," in value:
            self._multipart_range(value)
            return
        if value in ("bytes=-0", f"bytes={len(body)}-", "bytes=2-1"):
            self._reply(416)
            return
        self._single_range(value, body)

    def _serve_range(self, body):
        value = self.headers.get("Range")
        if value is None:
            return False
        if self.server.behaviour == "range_error":
            self._reply(500)
            return True
        if self.headers.get("If-Range"):
            self._reply(200, body, (("ETag", TARGET_ETAG),))
        else:
            self._range_reply(value, body)
        return True

    def _ordinary_headers(self, body):
        etag = TARGET_ETAG \
            if self._request_path() in ("/fixture", "/bucket/fixture") \
            else self._etag(body)
        headers = [("ETag", etag)]
        self._append_checksum_header(headers, body)
        self._append_digest_header(headers, body)
        return headers

    def _append_checksum_header(self, headers, body):
        if self.headers.get("x-amz-checksum-mode") == "ENABLED" \
                and self.server.behaviour != "s3_checksum_absent":
            raw_digest = hashlib.sha256(body).digest()
            if self.server.behaviour == "s3_checksum_bad":
                raw_digest = bytes(len(raw_digest))
            headers.append(("x-amz-checksum-sha256",
                            base64.b64encode(raw_digest).decode()))

    def _append_digest_header(self, headers, body):
        if self.headers.get("Want-Digest") != "sha256":
            return
        digest = hashlib.sha256(body).hexdigest()
        if self.server.behaviour == "digest_bad":
            digest = "0" * 64
        name = "sha-256" if self.server.behaviour == "digest_name_bad" \
            else "sha256"
        headers.append(("Digest", f"{name}={digest}"))

    def _serve_truncated_length(self, body):
        if self.server.behaviour != "htr_bad_015" \
                or self.headers.get("Range") is not None:
            return False
        self.send_response(200)
        self.send_header("Content-Length", str(len(body) + 1))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        return True

    def do_GET(self):
        if not self._authorize():
            return
        if self._serve_filename_variant():
            return
        decoded_path = self._request_path()
        if self._serve_case_variant(decoded_path):
            return
        if self._serve_traversal(decoded_path):
            return
        if self._s3_list():
            return
        if self._cross_plane_visible():
            return
        if self._s3_missing():
            return
        body = self._object()
        if body is None:
            self._reply(404)
            return
        self._serve_object(body)

    def _serve_filename_variant(self):
        if not self._filename_variant():
            return False
        s3_plane = self._request_path().startswith("/bucket/")
        visible = self._filename_visible(s3_plane)
        wrong = self.server.behaviour == "s3_filename_wrong" and s3_plane
        self._filename_reply(visible, wrong)
        return True

    def _filename_visible(self, s3_plane):
        return (self.server.behaviour == "filename_visible"
                or (self.server.behaviour == "http_filename_visible"
                    and not s3_plane))

    def _filename_reply(self, visible, wrong):
        if wrong:
            self._reply(200, b"wrong-object")
            return
        if visible:
            self._reply(200, PAYLOAD)
            return
        self._reply(400)

    def _serve_case_variant(self, decoded_path):
        if decoded_path not in ("/Fixture", "/bucket/Fixture"):
            return False
        exposed = ((self.server.behaviour == "http_case_visible"
                    and decoded_path == "/Fixture")
                   or (self.server.behaviour == "s3_case_visible"
                       and decoded_path == "/bucket/Fixture"))
        self._reply(200 if exposed else 404, PAYLOAD if exposed else b"")
        return True

    def _serve_traversal(self, decoded_path):
        if "/../" not in decoded_path:
            return False
        s3_plane = decoded_path.startswith("/bucket/")
        exposed = ((self.server.behaviour == "http_traversal_visible"
                    and not s3_plane)
                   or (self.server.behaviour == "s3_traversal_visible"
                       and s3_plane))
        self._reply(200 if exposed else 403,
                    b"unexpected-object" if exposed else b"")
        return True

    def _serve_object(self, body):
        if self.headers.get("If-None-Match") == TARGET_ETAG:
            self._reply(304, headers=(("ETag", TARGET_ETAG),))
            return
        if self._serve_truncated_length(body) \
                or self._serve_chunked(body) or self._serve_range(body):
            return
        self._reply(200, body, self._ordinary_headers(body))

    def do_PROPFIND(self):
        if not self._authorize():
            return
        if self.headers.get("Depth") != "1" or self._request_path() != "/":
            self._reply(404)
            return
        names = ["fixture"]
        if self.server.behaviour == "http_namespace_extra":
            names.append("unexpected")
        responses = [
            "<D:response><D:href>/</D:href><D:propstat><D:prop>"
            "<D:resourcetype><D:collection/></D:resourcetype>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat></D:response>"
        ]
        responses.extend(
            f"<D:response><D:href>/{name}</D:href><D:propstat><D:prop>"
            "<D:getcontentlength>8192</D:getcontentlength>"
            "</D:prop><D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat></D:response>"
            for name in names
        )
        body = ("<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
                + "".join(responses) + "</D:multistatus>").encode()
        self._reply(207, body, (("Content-Type", "application/xml"),))

    def do_PUT(self):
        if not self._authorize():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self._readonly_put(body):
            return
        _parsed, query = self._multipart_query()
        upload_id = query.get("uploadId", [""])[0]
        if upload_id:
            upload = self.server.uploads.get(upload_id)
            part = int(query.get("partNumber", ["0"])[0])
            if upload is None or part <= 0:
                self._multipart_error("InvalidRequest")
                return
            upload["parts"][part] = body
            upload["order"].append(part)
            self._reply(200, headers=(("ETag", f'"part-{part}"'),))
            return
        self.server.scratch[self._request_path()] = body
        self._reply(201)

    def do_DELETE(self):
        if not self._authorize():
            return
        _parsed, query = self._multipart_query()
        upload_id = query.get("uploadId", [""])[0]
        if upload_id:
            self.server.uploads.pop(upload_id, None)
            self._reply(204)
            return
        if self.server.behaviour != "mutation_delete_bad":
            self.server.scratch.pop(self._request_path(), None)
        self._reply(204)

    def do_BRIXX(self):
        self._reply(405, headers=(("Allow", "GET, HEAD, PUT, DELETE"),))

    def log_message(self, _format, *_args):
        return
