"""
test_metrics_slowop.py — §3.15 OssStats `slowop` threshold classifier.

The unified latency histogram booked op latency at completion but never
classified "slow" ops as a first-class figure.  `brix_metrics_slowop <usec>`
arms a threshold that is stamped into the metrics SHM at init_module; the
lock-free latency record path then books any op whose measured latency meets or
exceeds it into a new `brix_io_slowop_total{proto,op}` counter, and the armed
threshold is exported as the `brix_io_slowop_threshold_usec` gauge.

The discriminator across the three cases is the threshold value driving one
otherwise-identical node + upload:

  * success       — armed at 1µs: a root upload (an AIO write, which is always
                    latency-sampled) is booked as slow — brix_io_slowop_total
                    {proto="stream",op="write"} >= 1 and the gauge reads 1.
  * default/off   — armed at 0 (the default): the classifier is disabled, so the
                    gauge reads 0 and no brix_io_slowop_total series is emitted
                    even though the SAME upload still files its latency sample
                    (byte-identical to the pre-knob behaviour).
  * security-neg  — armed at 1h (3.6e9 µs): the gauge reflects the huge
                    threshold but the sub-second upload is NOT booked — proving
                    the latency is actually COMPARED against the threshold, not a
                    broken "any op counts" classifier.

All three reuse the one `lc-slowop` ledger subject serially (xdist_group), each
starting a fresh node with its own threshold.

Run:
    PYTHONPATH=tests pytest tests/test_metrics_slowop.py -v
"""

import os
import subprocess
import urllib.request

import pytest

from settings import BIND_HOST, SERVER_HOST
from server_registry import NginxInstanceSpec
from metrics_helpers import value, scalar

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-slowop")]

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")

GAUGE = "brix_io_slowop_threshold_usec"
SLOWOP = "brix_io_slowop_total"
WRITE = {"proto": "stream", "op": "write"}


def _scrape(port):
    with urllib.request.urlopen("http://%s:%d/metrics" % (BIND_HOST, port),
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _upload(src, sport, name):
    """Upload `src` to the node over root:// — an AIO write, so it files a
    latency sample the slowop classifier can act on. A clean subprocess so the
    session's counters flush on disconnect."""
    url = "root://%s:%d//%s" % (SERVER_HOST, sport, name)
    return subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH", _XRDCP, "-f", str(src), url],
        capture_output=True, text=True, timeout=60)


def _start(lifecycle, tmp_path, slowop_usec):
    if not os.access(_XRDCP, os.X_OK):
        pytest.skip("native xrdcp not built")
    root = tmp_path / "root"
    root.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-slowop",
        template="nginx_lc_slowop.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "ROOT_DIR": str(root),
                         "SLOWOP_USEC": slowop_usec},
        reason="§3.15 slowop classifier"))
    return ep


def test_slowop_booked_when_threshold_armed(lifecycle, tmp_path):
    """(success) armed at 1µs: an AIO write is booked slow and the gauge shows
    the armed threshold."""
    ep = _start(lifecycle, tmp_path, 1)
    src = tmp_path / "payload.bin"
    src.write_bytes(os.urandom(65536))
    r = _upload(src, ep.port, "slowop_probe.bin")
    assert r.returncode == 0, r.stderr

    text = _scrape(ep.extra_ports["METRICS_PORT"])
    assert scalar(text, GAUGE) == 1, \
        f"armed 1µs threshold not reflected in {GAUGE}"
    booked = value(text, SLOWOP, WRITE)
    assert booked >= 1, \
        f"a >=1µs AIO write was not booked as a slow op ({SLOWOP}{WRITE}={booked})"


def test_slowop_disabled_by_default(lifecycle, tmp_path):
    """(default/off) armed at 0: the classifier is disabled — gauge 0 and no
    counter series — while the identical upload still succeeds (and still files
    its latency sample), so the knob is inert when unset."""
    ep = _start(lifecycle, tmp_path, 0)
    src = tmp_path / "payload.bin"
    src.write_bytes(os.urandom(65536))
    r = _upload(src, ep.port, "slowop_off.bin")
    assert r.returncode == 0, r.stderr

    text = _scrape(ep.extra_ports["METRICS_PORT"])
    assert scalar(text, GAUGE) == 0, \
        f"{GAUGE} must be 0 when brix_metrics_slowop is unset/0"
    assert value(text, SLOWOP, WRITE) == -1, \
        "a disabled classifier must not emit a brix_io_slowop_total series"


def test_slowop_not_booked_below_threshold(lifecycle, tmp_path):
    """(security-neg) armed at 1h: the gauge reflects the huge threshold but a
    sub-second upload is NOT booked — the latency is genuinely compared, not a
    broken 'every op is slow' classifier."""
    one_hour_usec = 3600 * 1000 * 1000
    ep = _start(lifecycle, tmp_path, one_hour_usec)
    src = tmp_path / "payload.bin"
    src.write_bytes(os.urandom(65536))
    r = _upload(src, ep.port, "slowop_fast.bin")
    assert r.returncode == 0, r.stderr

    text = _scrape(ep.extra_ports["METRICS_PORT"])
    assert scalar(text, GAUGE) == one_hour_usec, \
        f"{GAUGE} must reflect the armed threshold"
    assert value(text, SLOWOP, WRITE) == -1, \
        "a fast op must not be booked against a 1h threshold"
