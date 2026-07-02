"""common — shared CLI plumbing for the Python migration tools.

WHAT: The pieces both migration tools share: the adler32 checksum helper
      (seed 1, XRootD convention), worklist filtering (--list/--prefix/
      --match), the resumable state manifest (--state), the Reporter (human +
      --json JSONL output, progress, thread-safe counters, warning budget,
      exit code), and the thread-pool runner.

WHY:  Keeping this out of the tools proper means both CLIs behave identically
      for every shared flag, and each piece unit-tests without a cluster.

HOW:  Reporter is the single output/failure channel: workers never raise
      through run_parallel (exceptions are caught and returned), and the exit
      code comes from Reporter.summary() — 0 all ok/skip, 1 any failure.
      StateManifest is append-only JSONL keyed on (soid, action, mode) so a
      migrate run's records never suppress a rollback run.

Pure stdlib; no rados/cephfs imports by design.
"""

from __future__ import annotations

import fnmatch
import json
import sys
import threading
import time
import zlib
from typing import Iterable, Optional

WARN_BUDGET = 400          # per-run cap on per-item warnings (matches the C++ tool)
PROGRESS_INTERVAL = 5.0    # seconds between progress lines


def adler32_hex(chunks: Iterable[bytes]) -> str:
    """adler32 over a chunk stream, seed 1 (zlib/XRootD convention), rendered
    as 8 lowercase hex digits — the user.XrdCks.adler32 format."""
    a = 1
    for c in chunks:
        a = zlib.adler32(c, a)
    return "%08x" % (a & 0xFFFFFFFF)


def read_list_file(path: str) -> "list[str]":
    """One soid per line; strips trailing CR/space; skips blank lines."""
    out = []
    with open(path, "r") as f:
        for line in f:
            line = line.rstrip("\r\n ").strip()
            if line:
                out.append(line)
    return out


def filter_worklist(items: "list[str]", list_file: Optional[str],
                    prefix: Optional[str], match: Optional[str]) -> "list[str]":
    """Apply the worklist filters (intersection). With a --list file the file's
    order is preserved and entries absent from `items` are kept only if
    `items` is empty (callers pass [] when enumeration was skipped)."""
    if list_file is not None:
        listed = read_list_file(list_file)
        if items:
            present = set(items)
            items = [s for s in listed if s in present]
        else:
            items = listed
    if prefix is not None:
        items = [s for s in items if s.startswith(prefix)]
    if match is not None:
        items = [s for s in items if fnmatch.fnmatch(s, match)]
    return items


class StateManifest:
    """Append-only JSONL manifest of per-soid outcomes for resumable runs.

    Records: {"ts", "soid", "action", "mode", "result", ...extra}. The latest
    record per (soid, action, mode) wins. A None path disables everything.
    """

    def __init__(self, path: Optional[str]):
        self.path = path
        self._lock = threading.Lock()
        self._state = {}
        self._fh = None
        if path is None:
            return
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        key = (rec["soid"], rec["action"], rec["mode"])
                        self._state[key] = rec["result"]
                    except (ValueError, KeyError):
                        continue          # tolerate a torn trailing line
        except FileNotFoundError:
            pass
        self._fh = open(path, "a")

    def done_ok(self, soid: str, action: str, mode: str) -> bool:
        if self.path is None:
            return False
        with self._lock:
            return self._state.get((soid, action, mode)) == "ok"

    def record(self, soid: str, action: str, mode: str, result: str, **extra):
        if self.path is None or self._fh is None:
            return
        rec = {"ts": time.time(), "soid": soid, "action": action,
               "mode": mode, "result": result}
        rec.update(extra)
        line = json.dumps(rec, sort_keys=True)
        with self._lock:
            self._state[(soid, action, mode)] = result
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class Reporter:
    """Thread-safe result reporting: human log or --json JSONL, counters,
    budget-capped warnings, optional progress, final summary + exit code.

    Human mode: per-item lines to stdout (C++-tool style). JSON mode: JSONL
    records to stdout, human lines to stderr.
    """

    def __init__(self, json_mode: bool = False, progress: bool = False,
                 total: int = 0):
        self.json_mode = json_mode
        self.progress = progress
        self.total = total
        self.ok = 0
        self.skip = 0
        self.fail = 0
        self.bytes = 0
        self.deleted = 0
        self._warn_left = WARN_BUDGET
        self._lock = threading.Lock()
        self._t0 = time.monotonic()
        self._last_progress = self._t0

    def _human(self, line: str):
        out = sys.stderr if self.json_mode else sys.stdout
        print(line, file=out)

    def item(self, soid: str, action: str, result: str, nbytes: int = 0,
             objects: int = 0, dest: Optional[str] = None,
             error: Optional[str] = None, detail: str = ""):
        with self._lock:
            if result == "ok":
                self.ok += 1
                self.bytes += nbytes
            elif result == "skip":
                self.skip += 1
            else:
                self.fail += 1

            tag = {"ok": "OK  ", "skip": "SKIP", "fail": "FAIL"}[result]
            arrow = (" -> " + dest) if dest else ""
            extra = " (%d bytes, %d obj%s)" % (nbytes, objects, detail) \
                if result == "ok" else ((": " + error) if error else
                                        ((" (" + detail + ")") if detail else ""))
            self._human("%s %s%s%s" % (tag, soid, arrow, extra))

            if self.json_mode:
                rec = {"soid": soid, "action": action, "result": result,
                       "bytes": nbytes, "objects": objects}
                if dest is not None:
                    rec["dest"] = dest
                if error is not None:
                    rec["error"] = error
                print(json.dumps(rec, sort_keys=True), flush=True)

            self._maybe_progress()

    def warn(self, msg: str):
        with self._lock:
            if self._warn_left > 0:
                self._warn_left -= 1
                print(msg, file=sys.stderr)
            elif self._warn_left == 0:
                self._warn_left = -1
                print("  ... (further per-item warnings suppressed; "
                      "see final summary)", file=sys.stderr)

    def note(self, msg: str):
        """An unconditional operator-facing status line (stderr)."""
        print(msg, file=sys.stderr)

    def _maybe_progress(self, force: bool = False):
        if not self.progress:
            return
        now = time.monotonic()
        if not force and now - self._last_progress < PROGRESS_INTERVAL:
            return
        self._last_progress = now
        done = self.ok + self.skip + self.fail
        dt = max(now - self._t0, 1e-6)
        rate = self.bytes / dt / (1024 * 1024)
        eta = ""
        if self.total and done and done < self.total:
            eta = ", ETA %ds" % int((self.total - done) * dt / done)
        print("progress: %d/%d files, %.1f MiB, %.1f MiB/s%s"
              % (done, self.total or done, self.bytes / (1024 * 1024),
                 rate, eta), file=sys.stderr)

    def summary(self) -> int:
        """Print the final totals; return the process exit code (0/1)."""
        with self._lock:
            self._maybe_progress(force=True)
            line = ("done: %d ok, %d skipped, %d failed, %d bytes"
                    % (self.ok, self.skip, self.fail, self.bytes))
            if self.deleted:
                line += ", %d source objects deleted" % self.deleted
            print(line, file=sys.stderr)
            if self.json_mode:
                print(json.dumps({"summary": {
                    "ok": self.ok, "skip": self.skip, "fail": self.fail,
                    "bytes": self.bytes, "deleted": self.deleted}},
                    sort_keys=True), flush=True)
            return 0 if self.fail == 0 else 1


def run_parallel(items, fn, threads: int):
    """Run fn(item) across a thread pool. fn must report its own outcome via
    the Reporter; exceptions are caught (never abort the estate for one file)
    and returned as [(item, exc)] for the caller to count as failures."""
    import concurrent.futures

    errors = []
    lock = threading.Lock()

    def wrapped(item):
        try:
            fn(item)
        except KeyboardInterrupt:
            raise
        except Exception as e:          # noqa: BLE001 - the isolation boundary
            with lock:
                errors.append((item, e))

    threads = max(1, threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(wrapped, items))
    return errors
