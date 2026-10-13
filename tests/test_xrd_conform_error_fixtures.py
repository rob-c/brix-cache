"""Controlled external fixtures for the Phase-118 errno-to-kXR ledger."""
import contextlib
import json
import socketserver
import struct
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from _test_phase115_pgread_verify_helpers import (
    PgOrigin, error_frame, kXR_error, kXR_login, kXR_open, kXR_query,
    kXR_redirect, kXR_stat, ok_frame,
)
from ephemeral_port import free_port
from settings import HOST
from test_xrd_conform_http_semantics import PAYLOAD, XRD, _clean_environment

kXR_auth = 3000
kXR_locate = 3027


class ManagerOutageOrigin(PgOrigin):
    """Manager-only fixture advertising a controlled holder set."""

    def __init__(self, holders, open_status, holder_sequences=None):
        self.holders = holders
        self.open_status = open_status
        self.holder_sequences = holder_sequences
        self.locate_count = 0
        super().__init__(PAYLOAD, behaviour="empty_manager")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_locate:
            holders = self.holders
            if self.holder_sequences is not None:
                index = min(
                    self.locate_count, len(self.holder_sequences) - 1,
                )
                holders = self.holder_sequences[index]
                self.locate_count += 1
            if holders is None:
                conn.sendall(error_frame(sid, 3007, b"map unavailable"))
                return authenticated
            reply = " ".join(
                f"S={HOST}:{port}" for port in holders
            ).encode()
            conn.sendall(ok_frame(sid, reply))
            return authenticated
        if reqid == kXR_open:
            if self.open_status == 0:
                conn.sendall(ok_frame(sid, b"\x00" * 12))
            elif self.open_status == kXR_error:
                conn.sendall(error_frame(sid, 3007, b"all holders down"))
            else:
                conn.sendall(struct.pack("!2sHI", sid, kXR_redirect, 0))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class ErrorOrigin(PgOrigin):
    """A normal ROOT endpoint whose read-open returns one selected wire error."""

    def __init__(self, code, message=b"controlled failure"):
        self.error_code = code
        self.error_message = message
        super().__init__(PAYLOAD, behaviour="ok")

    def _open_frame(self, sid):
        return error_frame(sid, self.error_code, self.error_message)


class ChangingErrorOrigin(ErrorOrigin):
    """Return different codes on the two fresh observations."""

    def __init__(self):
        self._answers = 0
        super().__init__(3010)

    def _open_frame(self, sid):
        self._answers += 1
        code = 3010 if self._answers == 1 else 3011
        return error_frame(sid, code, b"changed answer")


class CrossVerbOrigin(PgOrigin):
    """Return the same policy error through open, stat, and query."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid in (kXR_open, kXR_stat, kXR_query):
            conn.sendall(error_frame(sid, 3010, b"policy denied"))
            return authenticated
        return super()._dispatch(
            conn, sid, reqid, hdr, body, authenticated,
        )


class CrossVerbMismatchOrigin(CrossVerbOrigin):
    """Return a different policy classification through query."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_query:
            conn.sendall(error_frame(sid, 3011, b"not found"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class ExistenceOrigin(PgOrigin):
    """Serve the planted path but classify its missing sibling as NotFound."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_open and body.endswith(b".brix-missing"):
            conn.sendall(error_frame(sid, 3011, b"not found"))
            return authenticated
        return super()._dispatch(
            conn, sid, reqid, hdr, body, authenticated,
        )


class _HttpErrorHandler(BaseHTTPRequestHandler):
    """Return the configured status with a deterministic bounded body."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = self.server.error_body
        self.send_response(self.server.error_status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_PUT = do_GET

    def log_message(self, _format, *_args):
        return


class HttpErrorOrigin:
    """A labelled HTTP-plane error endpoint for paired ERR-043 evidence."""

    is_http = True

    def __init__(self, status, body=b"controlled HTTP failure"):
        self.port = free_port(HOST)
        self.server = ThreadingHTTPServer((HOST, self.port), _HttpErrorHandler)
        self.server.error_status = status
        self.server.error_body = body
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _FtpReadonlyHandler(socketserver.StreamRequestHandler):
    """Minimal anonymous FTP control channel refusing STOR at policy."""

    def handle(self):
        self.wfile.write(b"220 controlled fixture\r\n")
        while True:
            line = self.rfile.readline(4096)
            if not line:
                return
            command = line.decode("ascii", "replace").strip().upper()
            if command.startswith("USER "):
                reply = b"331 password required\r\n"
            elif command.startswith("PASS "):
                reply = b"230 logged in\r\n"
            elif command == "TYPE I":
                reply = b"200 binary\r\n"
            elif command.startswith("STOR "):
                reply = self.server.stor_reply
            elif command == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                reply = b"500 unsupported\r\n"
            self.wfile.write(reply)


class FtpReadonlyOrigin:
    """Controlled GridFTP spelling fixture using the production FTP client."""

    def __init__(self, correct=True):
        self.port = free_port(HOST)
        self.server = socketserver.ThreadingTCPServer(
            (HOST, self.port), _FtpReadonlyHandler,
        )
        self.server.stor_reply = (
            b"550 Permission denied (read-only)\r\n" if correct
            else b"550 no such file\r\n"
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class AuthFailureOrigin(PgOrigin):
    """Advertise one ROOT security protocol and reject malformed auth."""

    def __init__(self, protocol, code):
        self.protocol = protocol
        self.auth_code = code
        super().__init__(PAYLOAD, behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_login:
            security = f"&P={self.protocol}".encode("ascii")
            conn.sendall(ok_frame(sid, b"\x00" * 16 + security))
            return True
        if reqid == kXR_auth:
            conn.sendall(error_frame(sid, self.auth_code, b"auth rejected"))
            return authenticated
        return super()._dispatch(
            conn, sid, reqid, hdr, body, authenticated,
        )


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _run_fixture_options(tmp_path, clause, primary, options, mutate=False,
                         profile="data", verify=False):
    """Run one exact ERR row with dedicated non-errno fixture options."""
    _require_xrd()
    output = tmp_path / clause
    command = [
        str(XRD), "conform", "accept",
        f"root://{HOST}:{primary.port}//fixture",
        "--profile", profile, "--only", clause, "--out", str(output),
        "--wall-seconds", "20", "--request-limit", "128",
        "--byte-limit", "65536",
    ]
    _extend_fixture_authority(command, clause, mutate, verify)
    command.extend(options)
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=25,
        check=False, env=_clean_environment(),
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _extend_fixture_authority(command, clause, mutate, verify):
    if mutate:
        command.extend(("--allow-mutate", "--scratch", "/phase118"))
    if verify:
        command.extend(("--verify-negative", clause))


def _append_error_fixture(command, name, origin):
    is_http = getattr(origin, "is_http", False)
    scheme = "http" if is_http else "root"
    label = f"{name}@http" if is_http else name
    command.extend([
        "--error-fixture",
        f"{label}={scheme}://{HOST}:{origin.port}//fixture",
    ])


def _run(tmp_path, clause, fixtures, primary=None, profile="data",
         mutate=False, verify=False):
    """Run one exact ERR clause with explicitly labelled fixture endpoints."""
    _require_xrd()
    output = tmp_path / clause
    primary = fixtures[0][1] if primary is None else primary
    command = [
        str(XRD), "conform", "accept",
        f"root://{HOST}:{primary.port}//fixture",
        "--profile", profile, "--only", clause,
        "--out", str(output), "--wall-seconds", "20",
        "--request-limit", "128", "--byte-limit", "65536",
    ]
    _extend_fixture_authority(command, clause, mutate, verify)
    for name, origin in fixtures:
        _append_error_fixture(command, name, origin)
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=25,
        check=False, env=_clean_environment(),
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    return result, rows


def _run_manager_outage(tmp_path, clause, manager, verify=False,
                        also_manager=None):
    """Run one exact CMS outage row against a controlled manager fixture."""
    output = tmp_path / clause
    target = f"root://{HOST}:{manager.port}//fixture"
    command = [str(XRD), "conform", "accept",
         target,
         "--profile", "manager", "--only", clause, "--out", str(output),
         "--allow-disrupt", "--confirm-target", target,
         "--budget", "boundary",
         "--fail-on", "divergent", "--wall-seconds", "20",
         "--request-limit", "64", "--byte-limit", "65536"]
    if also_manager is not None:
        command.extend(("--also",
                        f"root://{HOST}:{also_manager.port}//fixture"))
    if verify:
        command.extend(("--verify-negative", clause))
    result = subprocess.run(
        command,
        text=True, capture_output=True, timeout=25, check=False,
        env=_clean_environment(),
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_labelled_errno_fixture_maps_exact_wire_code(tmp_path):
    """Success: EPERM observed as NotAuthorized makes ERR-003 conformant."""
    with ErrorOrigin(3010) as origin:
        result, rows = _run(tmp_path, "ERR-003", [("EPERM", origin)])
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-003"]["verdict"] == "conformant"


def test_wrong_wire_code_is_divergent(tmp_path):
    """Error: an EPERM fixture returning NotFound cannot pass the map row."""
    with ErrorOrigin(3011) as origin:
        result, rows = _run(
            tmp_path, "ERR-003", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-003"]["verdict"] == "divergent"


@pytest.mark.parametrize(("clause", "errno_name"), (
    ("ERR-001", "ENOENT"),
    ("ERR-002", "EINVAL"),
    ("ERR-004", "EACCES"),
    ("ERR-005", "EROFS"),
    ("ERR-006", "EEXIST"),
    ("ERR-007", "ENOTEMPTY"),
    ("ERR-008", "EISDIR"),
    ("ERR-009", "ENAMETOOLONG"),
    ("ERR-010", "EIO"),
    ("ERR-011", "ENOMEM"),
    ("ERR-012", "ENOBUFS"),
    ("ERR-013", "ENOSPC"),
    ("ERR-014", "EDQUOT"),
    ("ERR-015", "ENOTSUP"),
    ("ERR-016", "EBADF"),
    ("ERR-017", "ETIMEDOUT"),
    ("ERR-018", "ETIME"),
    ("ERR-019", "ECANCELED"),
    ("ERR-020", "ETXTBSY"),
    ("ERR-021", "EBADRQC"),
    ("ERR-022", "ENOTBLK"),
    ("ERR-023", "ENODEV"),
    ("ERR-024", "EFAULT"),
    ("ERR-025", "EDOM"),
    ("ERR-026", "EILSEQ"),
    ("ERR-027", "ERANGE"),
    ("ERR-028", "EUSERS"),
    ("ERR-029", "ENOATTR"),
    ("ERR-030", "EPROTOTYPE"),
    ("ERR-031", "EADDRNOTAVAIL"),
    ("ERR-032", "EAUTH"),
    ("ERR-033", "EIDRM"),
    ("ERR-034", "ENOTTY"),
    ("ERR-035", "ETOOMANYREFS"),
    ("ERR-037", "DEFAULT"),
))
def test_every_simple_errno_row_rejects_a_wrong_wire_code(
        tmp_path, clause, errno_name):
    """Security-negative: every simple mapper arm owns a red fixture."""
    wrong_code = 3010 if clause == "ERR-001" else 3011
    with ErrorOrigin(wrong_code) as origin:
        result, rows = _run(
            tmp_path, clause, [(errno_name, origin)], verify=True,
            mutate=clause in {
                "ERR-005", "ERR-006", "ERR-007", "ERR-013", "ERR-014",
            },
        )
    assert result.returncode == 1
    assert rows[clause]["verdict"] == "divergent"
    assert rows[clause]["reason"] == "missing-or-mismapped-errno-fixture"


def test_compound_network_mapping_requires_every_errno(tmp_path):
    """Security-negative: one network errno cannot stand in for all three."""
    with ErrorOrigin(3014) as origin:
        result, rows = _run(
            tmp_path, "ERR-036", [("ENETUNREACH", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-036"]["verdict"] == "divergent"
    assert rows["ERR-036"]["received"] == "fixtures=1/3 exact=1/3"


def test_error_message_disclosure_is_detected(tmp_path):
    """Security-negative: an absolute host path turns ERR-040 red."""
    with ErrorOrigin(3010, b"open /etc/shadow: permission denied") as origin:
        result, rows = _run(
            tmp_path, "ERR-040", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-040"]["verdict"] == "divergent"


def test_empty_error_message_is_not_readable_evidence(tmp_path):
    """Security-negative: a code-only error cannot satisfy ERR-039."""
    with ErrorOrigin(3010, b"") as origin:
        result, rows = _run(
            tmp_path, "ERR-039", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-039"]["reason"] == "unreadable-error-message"


def test_error_response_must_be_repeat_deterministic(tmp_path):
    """Security-negative: two fresh sessions cannot change classification."""
    with ChangingErrorOrigin() as origin:
        result, rows = _run(
            tmp_path, "ERR-041", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-041"]["reason"] == "fixture-answer-changed"


def test_error_code_above_fence_is_rejected(tmp_path):
    """Security-negative: kXR_ERRFENCE itself is not a valid error code."""
    with ErrorOrigin(3036) as origin:
        result, rows = _run(
            tmp_path, "ERR-045", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-045"]["reason"] == "error-code-outside-fence"


def test_collapse_row_requires_every_documented_member(tmp_path):
    """Security-negative: one collapse member cannot prove the whole set."""
    with ErrorOrigin(3010) as origin:
        result, rows = _run(
            tmp_path, "ERR-046", [("EPERM", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-046"]["reason"] == \
        "collapse-fixture-set-incomplete-or-wrong"


def test_server_error_outside_efault_is_rejected(tmp_path):
    """Security-negative: an EIO fixture cannot return ServerError."""
    with ErrorOrigin(3012) as origin:
        result, rows = _run(
            tmp_path, "ERR-038", [("EIO", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-038"]["reason"] == \
        "server-error-observed-outside-efault-fixture"


def test_cross_verb_policy_code_agrees(tmp_path):
    """Open, stat, and query returning NotAuthorized resolves ERR-042."""
    with CrossVerbOrigin(PAYLOAD, behaviour="ok") as origin:
        result, rows = _run(tmp_path, "ERR-042", [("EACCES", origin)])
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-042"]["verdict"] == "conformant"


def test_cross_verb_policy_code_mismatch_is_detected(tmp_path):
    """Security-negative: query cannot expose a different policy code."""
    with CrossVerbMismatchOrigin(PAYLOAD, behaviour="ok") as origin:
        result, rows = _run(
            tmp_path, "ERR-042", [("EACCES", origin)], verify=True,
        )
    assert result.returncode == 1
    assert rows["ERR-042"]["reason"] == "cross-verb-policy-code-diverged"


def test_policy_denial_hides_existence_but_authorized_missing_is_distinct(
        tmp_path):
    """Authorized and denied fixture twins resolve ERR-048 without an oracle."""
    with ExistenceOrigin(PAYLOAD, behaviour="ok") as allowed:
        with ErrorOrigin(3010, b"policy denied") as denied:
            result, rows = _run(
                tmp_path, "ERR-048", [("EACCES", denied)], primary=allowed,
            )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-048"]["verdict"] == "conformant"


def test_policy_denial_cannot_collapse_to_not_found(tmp_path):
    """Security-negative: denied present and absent paths retain policy code."""
    with ExistenceOrigin(PAYLOAD, behaviour="ok") as allowed:
        with ErrorOrigin(3011, b"not found") as denied:
            result, rows = _run(
                tmp_path, "ERR-048", [("EACCES", denied)], primary=allowed,
                verify=True,
            )
    assert result.returncode == 1
    assert rows["ERR-048"]["reason"] == \
        "policy-versus-absence-contract-failed"


def _paired_matrix(stack, wrong_http=None):
    """Start every required ROOT/HTTP pair and return labelled endpoints."""
    mappings = (
        ("ENOENT", 3011, 404),
        ("EACCES", 3010, 403),
        ("EROFS", 3025, 403),
        ("EINVAL", 3000, 400),
        ("EIO", 3007, 500),
        ("ENOMEM", 3008, 507),
    )
    fixtures = []
    for name, root_code, http_status in mappings:
        fixtures.append((name, stack.enter_context(ErrorOrigin(root_code))))
        if name == wrong_http:
            http_status = 418
        fixtures.append((
            name, stack.enter_context(HttpErrorOrigin(http_status)),
        ))
    return fixtures


def test_complete_root_http_error_matrix_agrees(tmp_path):
    """Success: six real ROOT errors agree with six real HTTP statuses."""
    with contextlib.ExitStack() as stack:
        fixtures = _paired_matrix(stack)
        result, rows = _run(tmp_path, "ERR-043", fixtures)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ERR-043"]["verdict"] == "conformant"
    assert rows["ERR-043"]["received"] == "pairs=6/6 exact=6/6"


def test_root_http_error_matrix_rejects_one_wrong_status(tmp_path):
    """Security-negative: one inconsistent HTTP status makes ERR-043 red."""
    with contextlib.ExitStack() as stack:
        fixtures = _paired_matrix(stack, wrong_http="EROFS")
        result, rows = _run(tmp_path, "ERR-043", fixtures, verify=True)
    assert result.returncode == 1
    assert rows["ERR-043"]["verdict"] == "divergent"
    assert rows["ERR-043"]["received"] == "pairs=6/6 exact=5/6"


def test_http_error_matrix_maps_every_required_status(tmp_path):
    """Success: HTE-001 observes the complete native HTTP errno mapping."""
    with contextlib.ExitStack() as stack:
        fixtures = _paired_matrix(stack)
        result, rows = _run(
            tmp_path, "HTE-001", fixtures, profile="http",
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTE-001"]["verdict"] == "conformant"
    assert rows["HTE-001"]["received"] == "pairs=6/6 exact=6/6"


def test_http_error_matrix_rejects_wrong_native_status(tmp_path):
    """Security-negative: HTE-001 rejects one inconsistent HTTP mapping."""
    with contextlib.ExitStack() as stack:
        fixtures = _paired_matrix(stack, wrong_http="EIO")
        result, rows = _run(
            tmp_path, "HTE-001", fixtures, profile="http", verify=True,
        )
    assert result.returncode == 1
    assert rows["HTE-001"]["verdict"] == "divergent"
    assert rows["HTE-001"]["received"] == "pairs=6/6 exact=5/6"


def test_http_error_matrix_requires_all_six_categories(tmp_path):
    """Error: five exact pairs cannot claim the complete HTE-001 matrix."""
    with contextlib.ExitStack() as stack:
        fixtures = _paired_matrix(stack)[:-2]
        result, rows = _run(
            tmp_path, "HTE-001", fixtures, profile="http", verify=True,
        )
    assert result.returncode == 1
    assert rows["HTE-001"]["verdict"] == "divergent"
    assert rows["HTE-001"]["received"] == "pairs=5/6 exact=5/6"


def test_readonly_http_put_matches_root_readonly_error(tmp_path):
    """Success: denied HTTP PUT and ROOT EROFS complete HTC-002."""
    with contextlib.ExitStack() as stack:
        fixtures = [
            ("EROFS", stack.enter_context(ErrorOrigin(3025))),
            ("EROFS", stack.enter_context(HttpErrorOrigin(403))),
        ]
        result, rows = _run(
            tmp_path, "HTC-002", fixtures, profile="http", mutate=True,
        )
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["HTC-002"]["verdict"] == "conformant"


def test_readonly_http_put_rejects_wrong_status(tmp_path):
    """Security-negative: a non-403 HTTP denial cannot pass HTC-002."""
    with contextlib.ExitStack() as stack:
        fixtures = [
            ("EROFS", stack.enter_context(ErrorOrigin(3025))),
            ("EROFS", stack.enter_context(HttpErrorOrigin(404))),
        ]
        result, rows = _run(
            tmp_path, "HTC-002", fixtures, profile="http", mutate=True,
            verify=True,
        )
    assert result.returncode == 1
    assert rows["HTC-002"]["verdict"] == "divergent"


def test_readonly_http_put_requires_both_planes(tmp_path):
    """Error: a ROOT-only EROFS fixture is insufficient for HTC-002."""
    with ErrorOrigin(3025) as root:
        result, rows = _run(
            tmp_path, "HTC-002", [("EROFS", root)], profile="http",
            mutate=True, verify=True,
        )
    assert result.returncode == 1
    assert rows["HTC-002"]["verdict"] == "divergent"
    assert rows["HTC-002"]["received"] == \
        "missing-or-mismatched-EROFS-pair"
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrd_conform_error_fixtures_manager")
