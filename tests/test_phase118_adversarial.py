"""The Phase-118 adversarial arm is bounded, live, and reproducible."""

import json
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin, error_frame
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "client/apps/diag/xrd_conform_adversarial.c").read_text()
LEDGER = (ROOT / "client/lib/conform/ledger_rows.inc").read_text()
XRD = ROOT / "client/bin/xrd"
XRDDIAG = ROOT / "client/bin/xrddiag"


class _InternalErrorOrigin(PgOrigin):
    """Return an internal error for the selected reserved-gap corpus case."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == 3032:
            conn.sendall(error_frame(sid, 3012, b"controlled internal error"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class _HalfOpenOrigin(PgOrigin):
    """Leave the reserved-gap request unanswered past the one-second bound."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == 3032:
            time.sleep(1.25)
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class _UnavailableOrigin(PgOrigin):
    """Stop accepting fresh sessions after one bounded hostile request."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == 3032:
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._srv.close()
            conn.sendall(error_frame(sid, 3013, b"controlled refusal"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class _MutatingOrigin(PgOrigin):
    """Alter baseline metadata while processing the reserved-gap case."""

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == 3032:
            self.payload += b"changed"
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class _UnstableInternalErrorOrigin(PgOrigin):
    """Emit one non-reproducible internal error so minimization must fail."""

    def __init__(self, payload):
        self.internal_errors = 0
        super().__init__(payload)

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == 3032 and self.internal_errors == 0:
            self.internal_errors += 1
            conn.sendall(error_frame(sid, 3012, b"one-shot internal error"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class _MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with self.server.metrics_lock:
            call = self.server.metrics_calls
            self.server.metrics_calls += 1
        rss = self.server.before_rss if call == 0 else self.server.after_rss
        fds = self.server.before_fds if call == 0 else self.server.after_fds
        body = f"rss_bytes={rss}\nopen_fds={fds}\n".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class _MetricsServer:
    def __init__(self, after_rss=104857600, after_fds=12):
        self.server = ThreadingHTTPServer((HOST, 0), _MetricsHandler)
        self.server.metrics_lock = threading.Lock()
        self.server.metrics_calls = 0
        self.server.before_rss = 104857600
        self.server.before_fds = 12
        self.server.after_rss = after_rss
        self.server.after_fds = after_fds
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def url(self):
        return f"http://{HOST}:{self.server.server_port}/metrics"


def _run_negative(tmp_path, origin, owner, observer=None):
    """Run one explicitly selected adversarial negative fixture."""
    output = tmp_path / owner
    target = f"root://{HOST}:{origin.port}//fixture"
    command = [
        str(XRD), "conform", "full", target,
        "--profile", "full", "--families", "ADV", "--only", owner,
        "--allow-mutate", "--scratch", "/",
        "--allow-disrupt", "--confirm-target", target,
        "--verify-negative", owner,
        "--fail-on", "divergent", "--wall-seconds", "30",
        "--request-limit", "192", "--byte-limit", "1048576",
        "--out", str(output),
    ]
    if observer is not None:
        command.extend(["--adv-observer", observer])
    fixture = {
        "ADV-007": "generator-gap",
        "ADV-009": "nondeterministic",
        "ADV-010": "authority-bypass",
    }.get(owner)
    if fixture is not None:
        command.extend(["--adv-fixture", fixture])
    result = subprocess.run(
        command, text=True, capture_output=True, timeout=45, check=False,
    )
    report = json.loads((output / "report.json").read_text())
    rows = {row["id"]: row for row in report["results"]}
    return result, rows


def _require_binary(binary):
    if not binary.exists():
        pytest.skip(f"native diagnostic client is not built: {binary}")


def _assert_live_ledger_clause(clause):
    line = next(line for line in LEDGER.splitlines()
                if f'BRIX_CONFORM_CLAUSE("{clause}"' in line)
    assert "BRIX_CONFORM_REF_SPEC" in line
    assert "BRIX_CONFORM_ORACLE_O1" in line
    assert f'"fault-proxy/hostile-input-liveness/{clause}"' in line
    assert "not-applicable/retracted" not in line


def _assert_all_adv_conformant(rows):
    for index in range(1, 11):
        assert rows[f"ADV-{index:03d}"]["verdict"] == "conformant"


def _assert_finding_report(report):
    rows = {row["id"]: row for row in report["results"]}
    assert rows["ADV-006"]["verdict"] == "divergent"
    assert report["negative_verification"] == {
        "requested": ["ADV-006"], "passed": True,
    }
    assert rows["ADV-008"]["verdict"] == "conformant"


def _assert_minimal_capture(capture):
    raw = capture.read_bytes()
    assert raw[:11] == b"XRDCAP1\nF>\x01"
    wire_length = int.from_bytes(raw[15:19], "big")
    assert wire_length == 24
    assert len(raw) == 19 + wire_length


def _replay_capture(capture, target):
    return subprocess.run(
        [str(XRDDIAG), "replay", str(capture), "--playback", target],
        text=True, capture_output=True, timeout=15, check=False,
    )


def test_corpus_cases_must_terminate_and_leave_endpoint_live():
    """Success: every selected hostile case is followed by a fresh connect."""
    assert "all_terminated &= outcome.terminated" in SOURCE
    assert "all_alive &= endpoint_alive" in SOURCE
    assert '"ADV-001"' in SOURCE and '"ADV-002"' in SOURCE


def test_internal_errors_and_half_open_connections_fail_closed():
    """Error: timeout and internal server errors cannot become evidence."""
    assert "status->sys_errno != ETIMEDOUT" in SOURCE
    assert "code == kXR_ServerError" in SOURCE
    assert "code == kXR_FSError" in SOURCE
    assert '"rss_bytes=%llu\\nopen_fds=%u\\n%n"' in SOURCE
    assert "after->open_fds <= before->open_fds" in SOURCE


def test_corpus_generation_is_keyed_and_covers_finite_domains():
    """Security-negative: a changed key changes bytes; domains are exhaustive."""
    assert "value <= UINT16_MAX" in SOURCE
    assert "value <= UINT8_MAX" in SOURCE
    assert "changed.bytes[0] ^= 1" in SOURCE
    assert '"ADV-009"' in SOURCE


def test_live_adversarial_contracts_are_not_labelled_retracted():
    """Error honesty: lack of an external citation does not withdraw a row."""
    for clause in ("ADV-007", "ADV-008", "ADV-009", "ADV-010"):
        _assert_live_ledger_clause(clause)


def test_controlled_origin_survives_bounded_adversarial_corpus(tmp_path):
    """Live: hostile cases terminate, preserve liveness, and keep the baseline."""
    _require_binary(XRD)
    output = tmp_path / "report"
    payload = bytes((index * 19 + 3) & 0xFF for index in range(4096))
    with PgOrigin(payload) as origin, _MetricsServer() as metrics:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "full", target,
             "--profile", "full", "--families", "ADV",
             "--allow-mutate", "--scratch", "/",
             "--allow-disrupt", "--confirm-target", target,
             "--adv-observer", metrics.url,
             "--fail-on", "divergent", "--wall-seconds", "30",
             "--request-limit", "128", "--byte-limit", "1048576",
             "--out", str(output)],
            text=True, capture_output=True, timeout=40, check=False,
        )
    assert result.returncode == 0, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text())
    rows = {row["id"]: row for row in report["results"]}
    _assert_all_adv_conformant(rows)


def test_half_open_adversarial_case_is_rejected(tmp_path):
    payload = bytes((index * 7 + 1) & 0xFF for index in range(4096))
    with _HalfOpenOrigin(payload) as origin:
        result, rows = _run_negative(tmp_path, origin, "ADV-001")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["ADV-001"]["verdict"] == "divergent"
    assert rows["ADV-001"]["reason"] == "adversarial-case-left-half-open"


def test_endpoint_loss_during_corpus_is_rejected(tmp_path):
    payload = bytes((index * 11 + 1) & 0xFF for index in range(4096))
    with _UnavailableOrigin(payload) as origin:
        result, rows = _run_negative(tmp_path, origin, "ADV-002")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["ADV-002"]["verdict"] == "divergent"
    assert rows["ADV-002"]["reason"] == "endpoint-unavailable-after-case"


@pytest.mark.parametrize(("owner", "after_rss", "after_fds"), [
    ("ADV-003", 209715200, 12),
    ("ADV-004", 104857600, 13),
])
def test_resource_nonrecovery_is_rejected(tmp_path, owner, after_rss,
                                          after_fds):
    payload = bytes((index * 13 + 1) & 0xFF for index in range(4096))
    with PgOrigin(payload) as origin, _MetricsServer(
            after_rss, after_fds) as metrics:
        result, rows = _run_negative(tmp_path, origin, owner, metrics.url)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_baseline_mutation_during_corpus_is_rejected(tmp_path):
    payload = bytes((index * 17 + 1) & 0xFF for index in range(4096))
    with _MutatingOrigin(payload) as origin:
        result, rows = _run_negative(tmp_path, origin, "ADV-005")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["ADV-005"]["verdict"] == "divergent"
    assert rows["ADV-005"]["reason"] == "baseline-object-changed-after-corpus"


def test_nonreproducible_finding_fails_minimization(tmp_path):
    payload = bytes((index * 31 + 1) & 0xFF for index in range(4096))
    with _UnstableInternalErrorOrigin(payload) as origin:
        result, rows = _run_negative(tmp_path, origin, "ADV-008")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["ADV-008"]["verdict"] == "divergent"
    assert rows["ADV-008"]["reason"] == "finding-minimization-incomplete"


@pytest.mark.parametrize("owner", ["ADV-007", "ADV-009", "ADV-010"])
def test_assessor_self_property_mutations_are_rejected(tmp_path, owner):
    payload = bytes((index * 37 + 1) & 0xFF for index in range(4096))
    with PgOrigin(payload) as origin:
        result, rows = _run_negative(tmp_path, origin, owner)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[owner]["verdict"] == "divergent"


def test_adversarial_calibration_fixture_requires_matching_verification():
    result = subprocess.run(
        [str(XRD), "conform", "full", f"root://{HOST}:1//fixture",
         "--adv-fixture", "generator-gap"],
        text=True, capture_output=True, timeout=5, check=False,
    )
    assert result.returncode == 4
    assert "requires its matching --verify-negative" in result.stderr


def test_finding_is_minimized_emitted_and_live_replayable(tmp_path):
    """Finding: emit deletion-minimal exact bytes in a scrubbed live capture."""
    _require_binary(XRD)
    _require_binary(XRDDIAG)
    output = tmp_path / "report"
    payload = bytes((index * 23 + 7) & 0xFF for index in range(4096))
    with _InternalErrorOrigin(payload) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "full", target,
             "--profile", "full", "--families", "ADV",
             "--allow-mutate", "--scratch", "/",
             "--allow-disrupt", "--confirm-target", target,
             "--verify-negative", "ADV-006",
             "--fail-on", "divergent", "--wall-seconds", "45",
             "--request-limit", "192", "--byte-limit", "1048576",
             "--out", str(output)],
            text=True, capture_output=True, timeout=55, check=False,
        )
        assert result.returncode == 1, result.stderr + result.stdout
        report = json.loads((output / "report.json").read_text())
        _assert_finding_report(report)
        capture = output / "ADV-008.xrdcap"
        _assert_minimal_capture(capture)
        replay = _replay_capture(capture, target)
    assert replay.returncode == 0, replay.stderr + replay.stdout
    assert "(1 request(s) re-issued, 0 ok)" in replay.stdout


def test_negative_verification_fails_when_fixture_does_not_turn_row_red(
        tmp_path):
    """Error: a declared hostile fixture cannot silently produce a green row."""
    _require_binary(XRD)
    output = tmp_path / "report"
    payload = bytes((index * 29 + 11) & 0xFF for index in range(4096))
    with PgOrigin(payload) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "full", target,
             "--profile", "full", "--families", "ADV",
             "--allow-mutate", "--scratch", "/",
             "--allow-disrupt", "--confirm-target", target,
             "--verify-negative", "ADV-006",
             "--fail-on", "divergent", "--wall-seconds", "30",
             "--request-limit", "128", "--byte-limit", "1048576",
             "--out", str(output)],
            text=True, capture_output=True, timeout=40, check=False,
        )
    assert result.returncode == 3, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text())
    assert report["negative_verification"] == {
        "requested": ["ADV-006"], "passed": False,
    }
    assert "negative fixture did not make ADV-006 divergent" in result.stderr


def test_negative_verification_rejects_an_incomplete_run(tmp_path):
    """Security-negative: a red row cannot certify an incomplete assessment."""
    _require_binary(XRD)
    output = tmp_path / "report"
    baseline = tmp_path / "invalid-baseline.json"
    baseline.write_text("not-json", encoding="utf-8")
    payload = bytes((index * 31 + 13) & 0xFF for index in range(4096))
    with _InternalErrorOrigin(payload) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "full", target,
             "--profile", "full", "--families", "ADV",
             "--allow-mutate", "--scratch", "/",
             "--allow-disrupt", "--confirm-target", target,
             "--verify-negative", "ADV-006", "--baseline", str(baseline),
             "--fail-on", "divergent", "--wall-seconds", "45",
             "--request-limit", "192", "--byte-limit", "1048576",
             "--out", str(output)],
            text=True, capture_output=True, timeout=55, check=False,
        )
    assert result.returncode == 3, result.stderr + result.stdout
    report = json.loads((output / "report.json").read_text())
    assert report["negative_verification"] == {
        "requested": ["ADV-006"], "passed": False,
    }
    assert "baseline rejected" in result.stderr
    assert "evidence rejected because the run is incomplete" in result.stderr


def test_negative_verification_rejects_retracted_clause_before_network():
    """Security-negative: withdrawn rows can never become fabricated evidence."""
    _require_binary(XRD)
    result = subprocess.run(
        [str(XRD), "conform", "full", f"root://{HOST}:1//fixture",
         "--verify-negative", "PGR-027"],
        text=True, capture_output=True, timeout=5, check=False,
    )
    assert result.returncode == 4
    assert "invalid option '--verify-negative'" in result.stderr
