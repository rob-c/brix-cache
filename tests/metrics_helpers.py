"""
metrics_helpers.py — shared Prometheus /metrics scrape + delta helpers.

WHAT: A tiny, dependency-free toolkit the metric-coverage suites
      (test_metrics_coverage_root/webdav/s3.py) use to snapshot a counter
      before an operation, drive the operation, re-snapshot, and assert the
      delta on the exact labelled series.

WHY:  These tests answer one question per metric: "does this counter actually
      increment when its operation runs, on every pathway we care about (data
      transfer + file create/modify/delete/rename)?"  A robust before/after
      delta over the live endpoint is the only way to verify the wiring end to
      end (handler -> op_ok/op_err slot -> exposition label), and to catch
      enum<->label-table skew (e.g. the phase-44 query_space fix).

HOW:  fetch() GETs the metrics text; value() extracts one labelled series;
      Snapshot caches a scrape and computes deltas; the root:// byte counters
      flush at TCP disconnect, so byte assertions use xrdcp subprocesses (which
      fully disconnect) and lower-bound deltas.
"""

import os
import re
import subprocess
import urllib.request

from settings import NGINX_METRICS_PORT, SERVER_HOST

METRICS_URL = f"http://{SERVER_HOST}:{NGINX_METRICS_PORT}/metrics"

# Absolute paths to the native client binaries (repo_root/client/bin/*), so the
# tests work regardless of pytest's working directory.
_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_XRDCP = os.path.join(_REPO, "client", "bin", "xrdcp")
_XRDFS = os.path.join(_REPO, "client", "bin", "xrdfs")


def fetch() -> str:
    """Return the raw /metrics text."""
    with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
        return resp.read().decode()


def value(text: str, name: str, labels: dict) -> int:
    """Value of `name{...labels...}`, or -1 if the series is absent.

    Labels are matched as a set (order-independent) within the { } block, so a
    caller need only pin the labels it cares about.
    """
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        m = re.match(r"^" + re.escape(name) + r"\{([^}]*)\}\s+([0-9]+)", line)
        if not m:
            continue
        block, val = m.group(1), m.group(2)
        if all(f'{k}="{v}"' in block for k, v in labels.items()):
            return int(val)
    return -1


def scalar(text: str, name: str) -> int:
    """Value of an unlabelled (or first-matching) series `name ...`, or -1."""
    for line in text.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            m = re.search(r"\s([0-9]+)\s*$", line)
            if m:
                return int(m.group(1))
    return -1


class Snapshot:
    """Capture /metrics now; later compute deltas against a fresh scrape."""

    def __init__(self):
        self.before = fetch()

    def delta(self, name: str, labels: dict, after: str = None) -> int:
        """Increment of name{labels} since the snapshot. Missing-before = 0.

        Asserts the series exists *after* the operation (a -1 there means the
        metric was never emitted — a real exposition gap, surfaced loudly).
        """
        after = after if after is not None else fetch()
        if labels:
            vb = value(self.before, name, labels)
            va = value(after, name, labels)
        else:
            # Unlabelled (scalar) series, e.g. xrootd_s3_list_contents_total.
            vb = scalar(self.before, name)
            va = scalar(after, name)
        assert va != -1, f"metric {name}{labels} not exported after activity"
        return va - (vb if vb != -1 else 0)


def xrdcp(*args, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run the native xrdcp (a clean subprocess that fully disconnects, so the
    root:// session byte counters flush)."""
    return subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH", _XRDCP, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def xrdfs(*args, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run the native xrdfs (used where pyxrootd does not issue the wire op,
    e.g. kXR_locate against a standalone data server)."""
    return subprocess.run(
        ["env", "-u", "LD_LIBRARY_PATH", _XRDFS, *args],
        capture_output=True, text=True, timeout=timeout,
    )
