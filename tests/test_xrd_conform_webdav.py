"""Phase-118 read-only WebDAV multistatus fixtures."""
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from ephemeral_port import free_port
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 41 + 13) & 0xFF for index in range(4096))


class _WebdavHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, body=b"", content_type=None, headers=()):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._reply(200, PAYLOAD)

    def do_GET(self):
        if self.path == "/outside":
            with self.server.state_lock:
                body = self.server.objects.get(self.path)
            if body is None:
                self._reply(404)
            else:
                self._reply(200, body)
            return
        if self.path.startswith("/scratch/"):
            with self.server.state_lock:
                body = self.server.objects.get(self.path)
            if body is None:
                self._reply(404)
            else:
                self._reply(200, body)
            return
        self._reply(200, PAYLOAD)

    def _infinity_reply(self, status):
        if self.server.behaviour != "bad-status":
            self._reply(403)
        else:
            body = (
                "<D:multistatus xmlns:D=\"DAV:\"><D:response>"
                f"<D:status>{status}</D:status></D:response>"
                "</D:multistatus>"
            ).encode("ascii")
            self._reply(207, body, "application/xml")

    def _depth_zero_reply(self, status):
        size = len(PAYLOAD) + 1 \
            if self.server.behaviour == "wrong-size" else len(PAYLOAD)
        duplicate = "<D:response><D:status>HTTP/1.1 200 OK</D:status>" \
            "</D:response>" if self.server.behaviour == "duplicate" else ""
        body = (
            "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
            f"<D:response><D:href>{self.path}</D:href><D:propstat><D:prop>"
            f"<D:getcontentlength>{size}"
            "</D:getcontentlength></D:prop>"
            f"<D:status>{status}</D:status></D:propstat></D:response>"
            f"{duplicate}</D:multistatus>"
        ).encode("ascii")
        self._reply(207, body, "application/xml")

    def do_PROPFIND(self):
        request_body = self._read_propfind_body()
        if self.path.startswith("/scratch/brix-conform-dav-delete"):
            self._delete_collection_propfind()
            return
        if b"<!DOCTYPE" in request_body:
            self._xxe_reply()
            return
        status = "HTTP/1.1 xxx Broken" \
            if self.server.behaviour == "bad-status" else "HTTP/1.1 200 OK"
        if self.headers.get("Depth") == "infinity":
            self._infinity_reply(status)
            return
        if self.headers.get("Depth") == "1":
            self._depth_one_reply(status)
            return
        self._depth_zero_reply(status)

    def _read_propfind_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    @staticmethod
    def _is_direct_child(path, prefix):
        return path.startswith(prefix) and "/" not in path[len(prefix):]

    def _delete_collection_propfind(self):
        with self.server.state_lock:
            exists = (self.path in self.server.collections
                      or self.path in self.server.objects)
            if not exists:
                self._reply(404)
                return
            prefix = self.path.rstrip("/") + "/"
            children = sorted(
                path for path in self.server.collections | set(self.server.objects)
                if self._is_direct_child(path, prefix)
            )
            paths = [self.path, *children]
        responses = "".join(
            f"<D:response><D:href>{path}</D:href>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:response>"
            for path in paths
        )
        body = ("<D:multistatus xmlns:D=\"DAV:\">" + responses
                + "</D:multistatus>").encode("ascii")
        self._reply(207, body, "application/xml")

    def _xxe_reply(self):
        if self.server.behaviour == "xxe-accepted":
            self._reply(207, b"<D:multistatus xmlns:D=\"DAV:\"/>",
                        "application/xml")
            return
        self._reply(400, b"external entities disabled")

    def _depth_one_reply(self, status):
        child_status = ("HTTP/1.1 404 Not Found"
                        if self.server.behaviour == "multistatus-mismatch"
                        else status)
        duplicate = ("<D:response><D:href>/fixture</D:href>"
                     f"<D:status>{status}</D:status></D:response>"
                     if self.server.behaviour == "multistatus-duplicate-href"
                     else "")
        body = (
            "<D:multistatus xmlns:D=\"DAV:\">"
            f"<D:response><D:href>/</D:href><D:status>{status}"
            "</D:status></D:response>"
            f"<D:response><D:href>/fixture</D:href><D:status>"
            f"{child_status}</D:status></D:response>{duplicate}"
            "</D:multistatus>"
        ).encode("ascii")
        self._reply(207, body, "application/xml")

    def do_MKCOL(self):
        if self.server.behaviour == "delete-setup-fail" \
                and self.path.endswith("/nested"):
            self._reply(500)
            return
        if self.path not in self.server.collections:
            with self.server.state_lock:
                self.server.collections.add(self.path)
            self._reply(201)
        elif self.server.behaviour == "mkcol-accepted":
            self._reply(200)
        else:
            self._reply(405)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path in self.server.locks \
                and self.server.behaviour != "unlocked-write":
            self._reply(423)
            return
        with self.server.state_lock:
            self.server.objects[self.path] = body
        self._reply(201)

    def do_MOVE(self):
        destination = urlsplit(self.headers.get("Destination", "")).path
        if destination == "/outside":
            if self.server.behaviour == "outside-accepted":
                with self.server.state_lock:
                    self.server.objects[destination] = \
                        self.server.objects.pop(self.path, b"")
                self._reply(201)
            else:
                self._reply(403)
            return
        refuse = self.headers.get("Overwrite") == "F" \
            and destination in self.server.objects \
            and self.server.behaviour != "overwrite"
        if refuse:
            self._reply(412)
            return
        self.server.objects[destination] = self.server.objects.pop(self.path, b"")
        self._reply(204)

    def do_COPY(self):
        destination = urlsplit(self.headers.get("Destination", "")).path
        if destination == "/outside" \
                and self.server.behaviour != "outside-accepted":
            self._reply(403)
            return
        with self.server.state_lock:
            self.server.objects[destination] = self.server.objects.get(
                self.path, b"",
            )
        self._reply(201)

    def do_DELETE(self):
        prefix = self.path.rstrip("/") + "/"
        self._partial_delete(prefix)
        if self._orphan_delete():
            self._reply(204)
            return
        self._complete_delete(prefix)
        self._reply(204)

    def _partial_delete(self, prefix):
        partial = (self.server.behaviour == "delete-partial"
                   and self.path.endswith("brix-conform-dav-delete"))
        if not partial:
            return
        with self.server.state_lock:
            self.server.objects.pop(prefix + "first", None)
        time.sleep(0.4)

    def _orphan_delete(self):
        orphan = (self.server.behaviour == "delete-orphans"
                  and self.path.endswith("brix-conform-dav-delete"))
        if not orphan:
            return False
        with self.server.state_lock:
            self.server.collections.discard(self.path)
        return True

    def _complete_delete(self, prefix):
        with self.server.state_lock:
            self.server.objects = {
                path: body for path, body in self.server.objects.items()
                if self._outside_deleted_tree(path, prefix)
            }
            self.server.collections = {
                path for path in self.server.collections
                if self._outside_deleted_tree(path, prefix)
            }
            self.server.locks.discard(self.path)

    def _outside_deleted_tree(self, path, prefix):
        return path != self.path and not path.startswith(prefix)

    def do_LOCK(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self.server.locks.add(self.path)
        headers = () if self.server.behaviour == "missing-lock-token" \
            else (("Lock-Token", "<opaquelocktoken:brix-test>"),)
        self._reply(200, headers=headers)

    def do_UNLOCK(self):
        valid = self.headers.get("Lock-Token") == \
            "<opaquelocktoken:brix-test>"
        if not valid or self.server.behaviour == "unlock-fail":
            self._reply(409)
            return
        self.server.locks.discard(self.path)
        self._reply(204)

    def log_message(self, _format, *_args):
        return


class WebdavOrigin:
    def __init__(self, behaviour="ok"):
        port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, port), _WebdavHandler)
        self.server.behaviour = behaviour
        self.server.collections = set()
        self.server.objects = {}
        self.server.locks = set()
        self.server.state_lock = threading.Lock()
        self.port = port
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_webdav_command(command, origin, outside, verify_negative):
    if outside:
        command.extend((
            "--webdav-outside-fixture",
            f"http://{HOST}:{origin.port}/outside",
        ))
    if verify_negative is not None:
        command.extend(("--verify-negative", verify_negative))


def _run(tmp_path, behaviour, outside=True, verify_negative=None):
    _require_xrd()
    output = tmp_path / behaviour
    with WebdavOrigin(behaviour) as origin:
        target = f"http://{HOST}:{origin.port}/fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "http", "--families", "DAV",
             "--allow-mutate", "--scratch", "/scratch",
             "--allow-disrupt", "--confirm-target", target,
             "--budget", "boundary", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "80",
             "--byte-limit", "2097152", "--out", str(output)]
        _extend_webdav_command(command, origin, outside, verify_negative)
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_rm008(tmp_path, behaviour, verify_negative=None):
    output = tmp_path / f"rm008-{behaviour}"
    with WebdavOrigin(behaviour) as origin:
        target = f"http://{HOST}:{origin.port}/fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "full", "--only", "RM-008",
             "--allow-mutate", "--scratch", "/scratch",
             "--allow-disrupt", "--confirm-target", target,
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "80", "--byte-limit", "2097152",
             "--out", str(output)]
        if verify_negative is not None:
            command.extend(("--verify-negative", verify_negative))
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "RM-008")
    return result, row


def test_webdav_read_only_success_paths(tmp_path):
    result, rows = _run(tmp_path, "ok")
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("DAV-001", "DAV-003", "DAV-004", "DAV-005", "DAV-007",
                   "DAV-006", "DAV-008", "DAV-010", "DAV-011"):
        assert rows[clause]["verdict"] == "conformant", rows[clause]
    assert rows["DAV-002"]["reason"] == \
        "fixture-required:paired-root-directory"
    assert rows["DAV-009"]["verdict"] == "conformant"


def test_multistatus_resource_status_mismatch_is_reported(tmp_path):
    """Error: Depth-1 and independent Depth-0 statuses must agree."""
    result, rows = _run(tmp_path, "multistatus-mismatch",
                        verify_negative="DAV-009")
    assert result.returncode == 1
    assert rows["DAV-009"]["verdict"] == "divergent"


def test_multistatus_duplicate_href_is_reported(tmp_path):
    """Security-negative: duplicate hrefs cannot hide conflicting entries."""
    result, rows = _run(tmp_path, "multistatus-duplicate-href",
                        verify_negative="DAV-009")
    assert result.returncode == 1
    assert rows["DAV-009"]["verdict"] == "divergent"


def test_malformed_multistatus_resource_status_is_reported(tmp_path):
    result, rows = _run(tmp_path, "bad-status", verify_negative="DAV-003")
    assert result.returncode == 1
    assert rows["DAV-003"]["verdict"] == "divergent"


def test_existing_mkcol_acceptance_is_reported(tmp_path):
    result, rows = _run(tmp_path, "mkcol-accepted",
                        verify_negative="DAV-005")
    assert result.returncode == 1
    assert rows["DAV-005"]["verdict"] == "divergent"


def test_move_overwrite_f_replacement_is_reported(tmp_path):
    result, rows = _run(tmp_path, "overwrite", verify_negative="DAV-007")
    assert result.returncode == 1
    assert rows["DAV-007"]["verdict"] == "divergent"


@pytest.mark.parametrize("behaviour", [
    "missing-lock-token", "unlocked-write", "unlock-fail",
])
def test_incomplete_lock_contract_is_reported(tmp_path, behaviour):
    result, rows = _run(tmp_path, behaviour, verify_negative="DAV-010")
    assert result.returncode == 1
    assert rows["DAV-010"]["verdict"] == "divergent"


def test_external_entity_document_acceptance_is_reported(tmp_path):
    result, rows = _run(tmp_path, "xxe-accepted",
                        verify_negative="DAV-011")
    assert result.returncode == 1
    assert rows["DAV-011"]["verdict"] == "divergent"


def test_recursive_delete_setup_failure_stays_inconclusive(tmp_path):
    """Error: an unplantable recursive fixture cannot become a false pass."""
    result, rows = _run(tmp_path, "delete-setup-fail")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["DAV-006"]["verdict"] == "inconclusive"


def test_partial_recursive_delete_is_detected(tmp_path):
    """Security-negative: one observable partial tree turns DAV-006 red."""
    result, rows = _run(tmp_path, "delete-partial",
                        verify_negative="DAV-006")
    assert result.returncode == 1
    assert rows["DAV-006"]["verdict"] == "divergent"
    assert rows["DAV-006"]["received"] == "partial-tree-observed"


def test_recursive_delete_rejects_orphaned_descendants(tmp_path):
    """Security-negative: hiding the parent while retaining children fails."""
    result, rows = _run(tmp_path, "delete-orphans",
                        verify_negative="DAV-006")
    assert result.returncode == 1
    assert rows["DAV-006"]["verdict"] == "divergent"
    assert rows["DAV-006"]["received"] == "orphaned-descendant-observed"


def test_rm008_reuses_the_concurrent_collection_delete_oracle(tmp_path):
    result, row = _run_rm008(tmp_path, "ok")
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == "recursive-delete-observed-atomically"


def test_rm008_setup_failure_stays_inconclusive(tmp_path):
    result, row = _run_rm008(tmp_path, "delete-setup-fail")
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "inconclusive"
    assert row["reason"] == "fixture-setup:recursive-webdav-collection"


@pytest.mark.parametrize("behaviour,received", [
    ("delete-partial", "partial-tree-observed"),
    ("delete-orphans", "orphaned-descendant-observed"),
])
def test_rm008_detects_partial_or_orphaned_trees(tmp_path, behaviour,
                                                received):
    result, row = _run_rm008(tmp_path, behaviour, "RM-008")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["received"] == received


def test_outside_export_fixture_is_explicit(tmp_path):
    """Error: no implicit path outside scratch is ever probed."""
    result, rows = _run(tmp_path, "ok", outside=False)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["DAV-008"]["verdict"] == "inconclusive"
    assert rows["DAV-008"]["reason"] == \
        "fixture-required:outside-export-destination"


def test_outside_export_destination_acceptance_is_detected(tmp_path):
    """Security-negative: accepted COPY/MOVE outside the export turns red."""
    result, rows = _run(tmp_path, "outside-accepted",
                        verify_negative="DAV-008")
    assert result.returncode == 1
    assert rows["DAV-008"]["verdict"] == "divergent"


@pytest.mark.parametrize("behaviour, clause", [
    ("wrong-size", "DAV-004"),
    ("duplicate", "DAV-001"),
])
def test_multistatus_property_or_cardinality_divergence(
        tmp_path, behaviour, clause):
    result, rows = _run(tmp_path, behaviour, verify_negative=clause)
    assert result.returncode == 1
    assert rows[clause]["verdict"] == "divergent"
