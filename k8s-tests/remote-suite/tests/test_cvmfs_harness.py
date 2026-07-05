# tests/test_cvmfs_harness.py
import os, sys
# conftest chdir()s into a scratch dir — anchor the import path on this file.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "cvmfs"))
from harness import percentile, summarize

def test_percentile_interpolation():
    assert percentile([10, 20, 30, 40], 50) == 25.0
    assert percentile([5], 99) == 5.0

def test_summarize_counts_errors_and_corruption():
    samples = [
        {"ok": True,  "ttfb_ms": 10, "body_sha1": "aa", "expect_sha1": "aa"},
        {"ok": False, "ttfb_ms": None, "body_sha1": None, "expect_sha1": "aa"},
        {"ok": True,  "ttfb_ms": 30, "body_sha1": "XX", "expect_sha1": "aa"},
    ]
    s = summarize(samples)
    assert s["error_rate"] == 1 / 3
    assert s["corrupt_served"] == 1
    assert s["ttfb_p50_ms"] == 20.0
