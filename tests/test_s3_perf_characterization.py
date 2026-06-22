"""S3 data-plane performance characterization (phase-45).

Deterministic assertions that hold on any host (no wall-clock / Gbps, which are
untrustworthy on WSL2):

  - W1 listing scales with the PAGE, not the bucket: a max-keys=K list over an
    N-object bucket issues ~K per-object stats, not N (proved via strace; skipped
    when strace/ptrace is unavailable).
  - W1 correctness at scale: paginating a large bucket returns every key exactly
    once, in lexicographic order — the growable store + lazy stat preserve the
    wire contract.

Uses the pre-started nginx_shared instance (port 9001), anonymous + write.
"""

import glob
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET
PORT = 9001


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


# ---------------------------------------------------------------------------
# W1 — correctness at scale (always runs)
# ---------------------------------------------------------------------------


def test_pagination_returns_every_key_once_in_order(s3_url):
    pfx = f"perf_scale_{uuid.uuid4().hex}/"
    n = 120
    created = [f"{pfx}k{i:04d}.bin" for i in range(n)]
    for k in created:
        assert requests.put(f"{s3_url}/{BUCKET}/{k}", data=b"x", timeout=10).status_code == 200

    seen, token, pages = [], None, 0
    while True:
        url = f"{s3_url}/{BUCKET}/?list-type=2&prefix={pfx}&max-keys=40"
        if token:
            url += f"&continuation-token={token}"
        r = requests.get(url, timeout=10)
        assert r.status_code == 200
        import xml.etree.ElementTree as ET

        ns = "http://s3.amazonaws.com/doc/2006-03-01/"
        root = ET.fromstring(r.text)
        seen += [el.findtext(f"{{{ns}}}Key") for el in root.findall(f"{{{ns}}}Contents")]
        pages += 1
        if root.findtext(f"{{{ns}}}IsTruncated") != "true":
            break
        token = root.findtext(f"{{{ns}}}NextContinuationToken")
        assert token and pages < 10  # guard against a pagination loop

    for k in created:
        requests.delete(f"{s3_url}/{BUCKET}/{k}", timeout=10)

    assert pages >= 3                      # 120 / 40 → at least 3 pages
    assert seen == sorted(created)         # every key once, lexicographic order
    assert len(seen) == len(set(seen))     # no duplicates across pages


# ---------------------------------------------------------------------------
# W1 — strace syscall-count proof (skipped if strace/ptrace unavailable)
# ---------------------------------------------------------------------------


def _strace_usable():
    if shutil.which("strace") is None:
        return False
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            if f.read().strip() not in ("0",):
                return False
    except FileNotFoundError:
        pass  # no yama → attach allowed
    return True


def _worker_pids(port=PORT):
    out = subprocess.run(
        ["ss", "-tlnpH", f"sport = :{port}"],
        capture_output=True, text=True,
    ).stdout
    return sorted(set(re.findall(r"pid=(\d+)", out)))


@pytest.mark.skipif(not _strace_usable(), reason="strace/ptrace not available")
def test_list_stats_scale_with_page_not_bucket(s3_url):
    """A max-keys=K list over N objects must issue ~K per-object stats, not N.

    Pre-phase-45 the walker lstat'd every object in the subtree (O(N) per page);
    after W1 it stats only the emitted page slice (O(K)).
    """
    pids = _worker_pids()
    if not pids:
        pytest.skip("could not enumerate nginx workers")

    uid = uuid.uuid4().hex
    pfx = f"perf_strace_{uid}/"
    n, k = 40, 10
    for i in range(n):
        requests.put(f"{s3_url}/{BUCKET}/{pfx}k{i:03d}.bin", data=b"x", timeout=10)

    tmpdir = tempfile.mkdtemp(prefix="s3perf_")
    procs = []
    try:
        for p in pids:
            outf = os.path.join(tmpdir, f"s_{p}.txt")
            # -s 300 so long object paths are not truncated before the uuid.
            pr = subprocess.Popen(
                ["strace", "-f", "-s", "300", "-e", "trace=newfstatat",
                 "-p", p, "-o", outf],
                stderr=subprocess.DEVNULL,
            )
            procs.append(pr)
        time.sleep(1.2)  # let strace attach

        requests.get(
            f"{s3_url}/{BUCKET}/?list-type=2&prefix={pfx}&max-keys={k}", timeout=10
        )
        time.sleep(1.0)

        for pr in procs:
            pr.send_signal(signal.SIGINT)
        for pr in procs:
            try:
                pr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pr.kill()

        # Count per-object lstats (newfstatat AT_SYMLINK_NOFOLLOW) on our objects.
        per_object = 0
        for fn in glob.glob(os.path.join(tmpdir, "s_*.txt")):
            with open(fn, errors="ignore") as fh:
                for line in fh:
                    if uid in line and ".bin" in line and "SYMLINK_NOFOLLOW" in line:
                        per_object += 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        for i in range(n):
            requests.delete(f"{s3_url}/{BUCKET}/{pfx}k{i:03d}.bin", timeout=10)

    if per_object == 0:
        pytest.skip("no per-object stats captured (attach race) — inconclusive")

    # The win: stats track the page (k), not the bucket (n).  Allow generous
    # slack but require it to be well below O(bucket).
    assert per_object <= k + 8, f"expected ~{k} page stats, saw {per_object}"
    assert per_object < n, f"stats {per_object} should be << bucket size {n}"
