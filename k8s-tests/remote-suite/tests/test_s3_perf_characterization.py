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
    created = _create_objects(s3_url, pfx, 120)
    seen, pages = _collect_pages(s3_url, pfx, 40)
    _delete_objects(s3_url, created)
    assert pages >= 3                      # 120 / 40 → at least 3 pages
    assert seen == sorted(created)         # every key once, lexicographic order
    assert len(seen) == len(set(seen))     # no duplicates across pages


def _create_objects(s3_url, prefix, count):
    keys = [f"{prefix}k{index:04d}.bin" for index in range(count)]
    for key in keys:
        result = requests.put(f"{s3_url}/{BUCKET}/{key}", data=b"x", timeout=10)
        assert result.status_code == 200
    return keys


def _delete_objects(s3_url, keys):
    for key in keys:
        requests.delete(f"{s3_url}/{BUCKET}/{key}", timeout=10)


def _collect_pages(s3_url, prefix, page_size):
    seen, token, pages = [], None, 0
    while True:
        keys, truncated, token = _list_page(s3_url, prefix, page_size, token)
        seen.extend(keys)
        pages += 1
        if not truncated:
            return seen, pages
        assert token and pages < 10


def _list_page(s3_url, prefix, page_size, token):
    url = f"{s3_url}/{BUCKET}/?list-type=2&prefix={prefix}&max-keys={page_size}"
    if token:
        url += f"&continuation-token={token}"
    response = requests.get(url, timeout=10)
    assert response.status_code == 200
    import xml.etree.ElementTree as ET
    namespace = "http://s3.amazonaws.com/doc/2006-03-01/"
    root = ET.fromstring(response.text)
    keys = [element.findtext(f"{{{namespace}}}Key")
            for element in root.findall(f"{{{namespace}}}Contents")]
    truncated = root.findtext(f"{{{namespace}}}IsTruncated") == "true"
    next_token = root.findtext(f"{{{namespace}}}NextContinuationToken")
    return keys, truncated, next_token


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
    pids = _require_worker_pids()
    uid = uuid.uuid4().hex
    pfx = f"perf_strace_{uid}/"
    n, k = 40, 10
    _create_strace_objects(s3_url, pfx, n)
    tmpdir = tempfile.mkdtemp(prefix="s3perf_")
    try:
        procs = _start_strace(pids, tmpdir)
        time.sleep(1.2)  # let strace attach
        requests.get(
            f"{s3_url}/{BUCKET}/?list-type=2&prefix={pfx}&max-keys={k}", timeout=10
        )
        time.sleep(1.0)
        _stop_strace(procs)
        per_object = _count_object_stats(tmpdir, uid)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        _delete_strace_objects(s3_url, pfx, n)
    _require_captured_stats(per_object)
    assert per_object <= k + 8, f"expected ~{k} page stats, saw {per_object}"
    assert per_object < n, f"stats {per_object} should be << bucket size {n}"


def _require_worker_pids():
    pids = _worker_pids()
    if not pids:
        pytest.skip("could not enumerate nginx workers")
    return pids


def _create_strace_objects(s3_url, prefix, count):
    for index in range(count):
        key = f"{prefix}k{index:03d}.bin"
        requests.put(f"{s3_url}/{BUCKET}/{key}", data=b"x", timeout=10)


def _delete_strace_objects(s3_url, prefix, count):
    keys = (f"{prefix}k{index:03d}.bin" for index in range(count))
    _delete_objects(s3_url, keys)


def _start_strace(pids, tmpdir):
    processes = []
    for pid in pids:
        output = os.path.join(tmpdir, f"s_{pid}.txt")
        process = subprocess.Popen(
            ["strace", "-f", "-s", "300", "-e", "trace=newfstatat",
             "-p", pid, "-o", output], stderr=subprocess.DEVNULL)
        processes.append(process)
    return processes


def _stop_strace(processes):
    for process in processes:
        process.send_signal(signal.SIGINT)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def _count_object_stats(tmpdir, uid):
    return sum(_count_stats_in(path, uid)
               for path in glob.glob(os.path.join(tmpdir, "s_*.txt")))


def _count_stats_in(path, uid):
    with open(path, errors="ignore") as handle:
        return sum(uid in line and ".bin" in line and "SYMLINK_NOFOLLOW" in line
                   for line in handle)


def _require_captured_stats(count):
    if count == 0:
        pytest.skip("no per-object stats captured (attach race) — inconclusive")
