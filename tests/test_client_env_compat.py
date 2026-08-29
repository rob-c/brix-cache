"""Stock XRD_* environment compatibility (parity-audit §7.10).

The vanilla XRootD client honors ~40 ``XRD_*`` environment variables; BriX
historically ignored every one silently — the audit's "drop-in hazard".  Two
mechanisms close it:

  * ALIASES — the stock timeout spellings map onto the native millisecond
    knobs (nettmo.c): ``XRD_CONNECTIONWINDOW``→connect,
    ``XRD_REQUESTTIMEOUT``→io, ``XRD_STREAMTIMEOUT``→stall, each seconds
    ×1000, with the native ``XRDC_*`` variable always winning.
  * DISCLOSURE — any other set ``XRD_*`` variable triggers ONE TTY-gated
    note naming it (envalias.c); scripts (non-TTY stderr) keep byte-identical
    output per the C3 hint gate.

All cases are fleet-free: a tarpit socket (accepts, stays silent) separates
"short window honored" from the 15 s compiled default, and a closed port
separates parse robustness from behavior change.

  * success   — XRD_CONNECTIONWINDOW=1 bounds bring-up to ~1 s
  * precedence— XRDC_CONNECT_TIMEOUT_MS beats a longer XRD_CONNECTIONWINDOW
  * security  — overflow values clamp huge (never wrap tiny/negative);
                garbage values fall through cleanly; the disclosure note
                names unsupported keys on a TTY only, never values

Run:
    PYTHONPATH=tests pytest tests/test_client_env_compat.py -v
"""

import os
import socket
import subprocess
import threading
import time

import pytest

from cli_pty import run_pty
from ephemeral_port import free_port

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]


class _Tarpit(threading.Thread):
    """Accept TCP connections and hold them silent — bring-up then hangs on
    the handshake read until the connect window expires (free_port-exempt
    in-process mock)."""

    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", free_port()))  # net-literal-allow: loopback mock shim; leased mock-range port (never kernel-assigned)
        self._lsock.listen(8)
        self._lsock.settimeout(0.2)
        self.port = self._lsock.getsockname()[1]
        self._conns = []

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
                self._conns.append(conn)
            except socket.timeout:
                continue
            except OSError:
                break
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass
        self._lsock.close()

    def stop(self):
        self._stop.set()


def _env(overrides):
    """Caller environment scrubbed of every XRD*/XRDC* key, plus overrides —
    leftover shell variables must not perturb the case under test."""
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("XRD_") or k.startswith("XRDC_"))}
    env.update(overrides)
    return env


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", free_port()))  # net-literal-allow: loopback mock shim; leased mock-range port (never kernel-assigned)
    port = s.getsockname()[1]
    s.close()
    return port


class TestStockTimeoutAliases:

    def test_stock_connectionwindow_bounds_bringup(self, tmp_path):
        """(success) XRD_CONNECTIONWINDOW=1 fails a tarpit bring-up in ~1 s —
        far under the 15 s compiled default, proving seconds→ms mapping."""
        pit = _Tarpit()
        pit.start()
        try:
            t0 = time.monotonic()
            res = subprocess.run(
                [XRDCP, "--retry", "0",
                 f"root://127.0.0.1:{pit.port}//x",  # net-literal-allow: URL targets the loopback mock shim
                 str(tmp_path / "out.bin")],
                env=_env({"XRD_CONNECTIONWINDOW": "1"}),
                capture_output=True, text=True, timeout=60)
            elapsed = time.monotonic() - t0
        finally:
            pit.stop()
        assert res.returncode != 0
        assert elapsed < 8, (
            f"stock connect window ignored: bring-up took {elapsed:.1f}s")

    def test_native_ms_beats_stock_seconds(self, tmp_path):
        """(precedence) with both spellings set, the native millisecond value
        wins: 1500 ms beats a 60 s stock window."""
        pit = _Tarpit()
        pit.start()
        try:
            t0 = time.monotonic()
            res = subprocess.run(
                [XRDCP, "--retry", "0",
                 f"root://127.0.0.1:{pit.port}//x",  # net-literal-allow: URL targets the loopback mock shim
                 str(tmp_path / "out.bin")],
                env=_env({"XRDC_CONNECT_TIMEOUT_MS": "1500",
                          "XRD_CONNECTIONWINDOW": "60"}),
                capture_output=True, text=True, timeout=60)
            elapsed = time.monotonic() - t0
        finally:
            pit.stop()
        assert res.returncode != 0
        assert elapsed < 8, (
            f"native XRDC_* did not take precedence: {elapsed:.1f}s")


class TestStockEnvHostile:

    def test_overflow_stock_value_clamps_not_wraps(self, tmp_path):
        """(security-neg) an absurd XRD_CONNECTIONWINDOW must clamp to a huge
        window, never wrap into a tiny/negative one: the tarpit bring-up is
        still alive after 4 s (a wrapped value would fail instantly)."""
        pit = _Tarpit()
        pit.start()
        proc = subprocess.Popen(
            [XRDCP, f"root://127.0.0.1:{pit.port}//x",  # net-literal-allow: URL targets the loopback mock shim
             str(tmp_path / "out.bin")],
            env=_env({"XRD_CONNECTIONWINDOW": "99999999999999"}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                proc.wait(timeout=4)
        finally:
            proc.kill()
            proc.wait()
            pit.stop()

    def test_garbage_stock_value_falls_through(self, tmp_path):
        """(security-neg) a non-numeric stock value is ignored cleanly — the
        copy against a closed port still refuses immediately (exit 51), no
        crash, no hang."""
        res = subprocess.run(
            [XRDCP, f"root://127.0.0.1:{_closed_port()}//x",  # net-literal-allow: URL targets the loopback mock shim
             str(tmp_path / "out.bin")],
            env=_env({"XRD_CONNECTIONWINDOW": "bogus",
                      "XRD_REQUESTTIMEOUT": ""}),
            capture_output=True, text=True, timeout=30)
        assert res.returncode == 51, (res.returncode, res.stderr)


class TestStockEnvDisclosure:

    def test_unsupported_vars_note_on_tty(self, tmp_path):
        """(disclosure) unsupported-but-set XRD_* names are listed once on a
        TTY; honored aliases and values never appear in the note."""
        # run_pty returns (rc, COMBINED pty output, b"") — stdout and stderr
        # share the one PTY, so the note is read off the combined stream.
        rc, out, _err = run_pty(
            [XRDCP, f"root://127.0.0.1:{_closed_port()}//x",  # net-literal-allow: URL targets the loopback mock shim
             str(tmp_path / "out.bin")],
            env=_env({"XRD_LOGLEVEL": "Dump",
                      "XRD_CPRETRY": "3",
                      "XRD_CONNECTIONWINDOW": "20"}))
        text = out.decode("utf-8", "replace")
        assert rc != 0
        assert "not supported by brix-client" in text, text
        assert "XRD_LOGLEVEL" in text and "XRD_CPRETRY" in text, text
        # the honored alias is not "unsupported", and values never print
        note = [ln for ln in text.splitlines()
                if "not supported by brix-client" in ln][0]
        assert "XRD_CONNECTIONWINDOW" not in note, note
        assert "Dump" not in text.replace("XRD_LOGLEVEL=Dump", ""), text

    def test_no_note_without_tty(self, tmp_path):
        """(C3 gate) the same environment through a plain pipe emits NO note —
        script-visible output stays byte-identical."""
        res = subprocess.run(
            [XRDCP, f"root://127.0.0.1:{_closed_port()}//x",  # net-literal-allow: URL targets the loopback mock shim
             str(tmp_path / "out.bin")],
            env=_env({"XRD_LOGLEVEL": "Dump"}),
            capture_output=True, text=True, timeout=30)
        assert res.returncode != 0
        assert "not supported by brix-client" not in res.stderr
