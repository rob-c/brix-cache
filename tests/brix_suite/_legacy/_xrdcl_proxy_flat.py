"""ARCHIVE — the flat ``tests/_xrdcl_proxy.py`` as it stood before TS-5.

Kept verbatim so the move can be checked body-by-body (AST hash) rather than
taken on trust.  Nothing imports it; the live module is ``brix_suite.clients.xrdcl``.

It was ``exec``-composed with ``_xrdcl_proxy_part2.py`` via
``split_continuation.load``, so this archive is only the first shard's
half of the module; the second is beside it.
"""

def _guard_call_1(self):
    if not self._alive:
        raise XrdClWorkerError("XrdCl worker is not running")

def _guard_call_3(got, self, timeout, req):
    if not got:
        # Hung op — destroy the worker so the deadlock cannot persist.
        self.kill()
        raise XrdClWorkerError(
            "XrdCl op timed out after %ss (op=%s) — worker killed"
            % (timeout, req.get("op")))

def _guard_call_4(msg, self, req):
    if msg is None or not self._alive and msg is None:
        raise XrdClWorkerError("XrdCl worker died during op %s"
                               % req.get("op"))

def _guard_call_2(sig, self, req):
    if sig != self._env_sig:
        req["env"] = dict(os.environ)
        self._env_sig = sig

def _guard_call_5(cls, msg):
    if isinstance(cls, type) and issubclass(cls, Exception) \
            and cls not in (Exception, BaseException):
        raise cls(msg.get("emsg", ""))


"""
tests/_xrdcl_proxy.py

Parent-side half of the out-of-process XrdCl isolation layer.  The shadow
``XRootD`` package (tests/XRootD/) re-exports the proxy classes defined here so
that ``from XRootD import client`` inside a test transparently drives the real
bindings hosted in tests/_xrdcl_worker.py — WITHOUT importing pyxrootd into the
pytest interpreter.

Design
    * One worker subprocess per pytest process, started lazily and reused.
      xdist gives each of its workers a distinct process, hence a distinct
      XrdCl worker — no cross-talk.
    * Every call carries a monotonic request id.  A background reader thread
      demultiplexes worker responses into per-request slots.  Calls block on a
      real wall-clock timeout; on expiry the worker is killed and the call
      raises, so a hung XrdCl op becomes an ordinary test failure instead of a
      frozen interpreter.
    * Proxy result objects (Status / StatInfo / DirectoryList / LocationInfo /
      VectorReadInfo) reproduce exactly the attribute surface the tests use.
"""

import atexit
import base64
import builtins
import collections
import functools
import json
import os
import subprocess
import sys
import threading


_WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "_xrdcl_worker.py")

# Per-call wall-clock ceiling.  Generous enough for legitimate large transfers,
# small enough that a deadlocked XrdCl op fails the test promptly rather than
# stalling the suite.
_CALL_TIMEOUT = float(os.environ.get("XRDCL_PROXY_TIMEOUT", "90"))


@functools.lru_cache(maxsize=1)
def _worker_python():
    """Return an interpreter able to import the real XRootD bindings.

    Importing ``XRootD`` in pytest is not a capability check: ``tests/XRootD``
    is deliberately a shadow package and therefore always imports.  Starting
    the worker with an empty request stream exercises its shadow-path removal
    and real binding import without creating any client handles.

    The test runner and the bindings do not have to live in the same Python
    environment.  This matters on build hosts where ``pytest`` is provided by
    the system interpreter but pyxrootd is installed in the test virtualenv.
    ``TEST_XRDCL_PYTHON`` is the authoritative override; the remaining entries
    cover the active virtualenv and the conventional project test environments.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.environ.get("TEST_XRDCL_PYTHON"),
        os.environ.get("XRDCL_PYTHON"),
        os.path.join(os.environ.get("VIRTUAL_ENV", ""), "bin", "python"),
        sys.executable,
        os.path.join(repo_root, ".venv", "bin", "python"),
        os.path.expanduser("~/.venvs/brix/bin/python"),
        "/root/.venvs/brix/bin/python",
    ]
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        candidate = os.path.abspath(candidate)
        if candidate in seen or not os.access(candidate, os.X_OK):
            continue
        seen.add(candidate)
        try:
            probe_env = dict(os.environ)
            probe_env["XRDCL_IMPORT_PROBE"] = "1"
            result = subprocess.run(
                [candidate, "-u", _WORKER], input="", text=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, env=probe_env,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            return candidate
    return None


def real_bindings_available():
    """Return whether any isolated worker can import real XRootD bindings."""
    return _worker_python() is not None


class XrdClWorkerError(RuntimeError):
    """Raised when the isolated worker errors, dies, or times out."""


# ==========================================================================
# Worker connection (singleton per process).
# ==========================================================================
class _Worker:
    def __init__(self):
        worker_python = _worker_python()
        if worker_python is None:
            raise XrdClWorkerError(
                "no Python interpreter with real XRootD bindings found; "
                "set TEST_XRDCL_PYTHON=/path/to/python")
        env = dict(os.environ)
        # The worker must import the REAL bindings; keep it off the shadow.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self._proc = subprocess.Popen(
            [worker_python, "-u", _WORKER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1,
        )
        self._lock = threading.Lock()          # guards stdin writes + _next_id
        self._slots = {}                       # id -> [event, result]
        self._slots_lock = threading.Lock()
        self._next_id = 1
        self._env_sig = None                    # last os.environ synced to child
        # Handles whose proxies were garbage-collected.  Finalizers (__del__)
        # MUST NOT take self._lock — GC can fire while another thread holds it,
        # and the lock is non-reentrant, which self-deadlocks the interpreter.
        # deque.append is atomic and lock-free; the releases are flushed lazily
        # at the start of the next call().
        self._pending_releases = collections.deque()
        self._alive = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # -- response demultiplexer -------------------------------------------
    def _read_loop(self):
        try:
            for line in self._proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                rid = msg.get("id")
                with self._slots_lock:
                    slot = self._slots.get(rid)
                if slot is not None:
                    slot[1] = msg
                    slot[0].set()
        finally:
            self._alive = False
            # Wake every waiter so nobody blocks on a dead worker.
            with self._slots_lock:
                for slot in self._slots.values():
                    slot[0].set()

    # -- request/response --------------------------------------------------
    def call(self, req, timeout=_CALL_TIMEOUT):
        _guard_call_1(self)
        ev = threading.Event()
        slot = [ev, None]
        with self._lock:
            # Flush finalizer-queued handle releases (fire-and-forget; the
            # worker tags the reply id=None which the reader simply drops).
            while self._pending_releases:
                h = self._pending_releases.popleft()
                try:
                    self._proc.stdin.write(
                        json.dumps({"op": "release", "h": h}) + "\n")
                except Exception:
                    break
            rid = self._next_id
            self._next_id += 1
            req["id"] = rid
            # Keep the child's os.environ in lock-step with the parent's so that
            # credential vars (X509_USER_PROXY, BEARER_TOKEN, XrdSec*, XRD_*, …)
            # a test sets right before connecting reach the real bindings.  Only
            # resend when something changed; the worker applies it in request
            # order, before dispatching the op.
            sig = hash(tuple(sorted(os.environ.items())))
            _guard_call_2(sig, self, req)
            with self._slots_lock:
                self._slots[rid] = slot
            try:
                self._proc.stdin.write(json.dumps(req) + "\n")
                self._proc.stdin.flush()
            except Exception as exc:
                raise XrdClWorkerError("worker stdin write failed: %s" % exc)

        got = ev.wait(timeout)
        with self._slots_lock:
            self._slots.pop(rid, None)
        _guard_call_3(got, self, timeout, req)
        msg = slot[1]
        _guard_call_4(msg, self, req)
        if not msg.get("ok"):
            # Re-raise the binding's native exception type when it was a plain
            # builtin (ValueError, TypeError, …) so test ``except`` clauses that
            # target the real pyxrootd behaviour still match.  Anything else
            # surfaces as XrdClWorkerError.
            etype = msg.get("etype")
            cls = getattr(builtins, etype, None) if etype else None
            _guard_call_5(cls, msg)
            raise XrdClWorkerError(msg.get("error", "unknown worker error"))
        return msg

    def kill(self):
        self._alive = False
        try:
            self._proc.kill()
        except Exception:
            pass


_worker_singleton = None
_worker_singleton_lock = threading.Lock()


def _worker():
    global _worker_singleton
    with _worker_singleton_lock:
        w = _worker_singleton
        if w is None or not w._alive:
            w = _Worker()
            _worker_singleton = w
        return w


@atexit.register
def _shutdown_worker():
    w = _worker_singleton
    if w is not None:
        try:
            w._proc.stdin.write(json.dumps({"op": "shutdown"}) + "\n")
            w._proc.stdin.flush()
        except Exception:
            pass
        w.kill()


# ==========================================================================
# Result wrappers — faithful attribute surface, no XrdCl import required.
# ==========================================================================
class Status:
    __slots__ = ("ok", "error", "fatal", "code", "status", "errno",
                 "shellcode", "message")

    def __init__(self, d):
        d = d or {}
        self.ok = bool(d.get("ok", False))
        self.error = bool(d.get("error", not d.get("ok", False)))
        self.fatal = bool(d.get("fatal", False))
        self.code = int(d.get("code", 0))
        self.status = int(d.get("status", 0))
        self.errno = int(d.get("errno", 0))
        self.shellcode = int(d.get("shellcode", 0))
        self.message = str(d.get("message", ""))

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return "<Status ok=%s code=%s errno=%s msg=%r>" % (
            self.ok, self.code, self.errno, self.message)


class StatInfo:
    __slots__ = ("size", "flags", "id", "modtime", "modtimestr")

    def __init__(self, d):
        self.size = d.get("size", 0)
        self.flags = d.get("flags", 0)
        self.id = d.get("id")
        self.modtime = d.get("modtime", 0)
        self.modtimestr = d.get("modtimestr")


class StatInfoVFS:
    def __init__(self, d):
        for k, v in d.items():
            if k != "__type__":
                setattr(self, k, v)


class _ListEntry:
    __slots__ = ("name", "hostaddr", "statinfo")

    def __init__(self, d):
        self.name = d.get("name")
        self.hostaddr = d.get("hostaddr")
        si = d.get("statinfo")
        self.statinfo = StatInfo(si) if si else None


class DirectoryList:
    def __init__(self, d):
        self.parent = d.get("parent")
        self._entries = [_ListEntry(e) for e in d.get("entries", [])]
        self.size = d.get("size", len(self._entries))

    def __iter__(self):
        return iter(self._entries)

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, i):
        return self._entries[i]


class _Location:
    __slots__ = ("address", "type", "accesstype", "is_server", "is_manager")

    def __init__(self, d):
        self.address = d.get("address")
        self.type = d.get("type", 0)
        self.accesstype = d.get("accesstype", 0)
        self.is_server = d.get("is_server", False)
        self.is_manager = d.get("is_manager", False)


class LocationInfo:
    def __init__(self, d):
        self.locations = [_Location(x) for x in d.get("locations", [])]

    def __iter__(self):
        return iter(self.locations)

    def __len__(self):
        return len(self.locations)

    def __getitem__(self, i):
        return self.locations[i]


class _Chunk:
    __slots__ = ("offset", "length", "buffer")

    def __init__(self, d):
        self.offset = d.get("offset", 0)
        self.length = d.get("length", 0)
        self.buffer = base64.b64decode(d.get("buffer", ""))


class VectorReadInfo:
    def __init__(self, d):
        self.size = d.get("size", 0)
        self.chunks = [_Chunk(c) for c in d.get("chunks", [])]

    # Real pyxrootd VectorReadInfo iterates its chunks.
    def __iter__(self):
        return iter(self.chunks)

    def __len__(self):
        return len(self.chunks)

    def __getitem__(self, i):
        return self.chunks[i]


class _Generic:
    """Fallback wrapper for response types without a dedicated class."""
    def __init__(self, d):
        for k, v in d.items():
            if k == "__type__":
                continue
            setattr(self, k, _decode_response(v))


_RESP_TYPES = {
    "StatInfo": StatInfo,
    "StatInfoVFS": StatInfoVFS,
    "DirectoryList": DirectoryList,
    "LocationInfo": LocationInfo,
    "VectorReadInfo": VectorReadInfo,
}

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "_xrdcl_proxy_part2.py")
