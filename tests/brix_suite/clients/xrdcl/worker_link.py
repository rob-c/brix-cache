"""Worker process, interpreter discovery and the request/response link.

Shard 1 of the grown ``tests/_xrdcl_proxy.py``, minus the result wrappers.
Everything here is *singleton state for the pytest process*: the interpreter
probe is memoised, the worker connection is a module global, and the atexit
shutdown hook is registered once at import.  Split modules must therefore
import these names from HERE — a second copy would mean a second worker, and
the whole point of the layer is that there is exactly one.
"""

import atexit
import builtins
import collections
import functools
import json
import os
import subprocess
import sys
import threading

#: The worker script this package carries.  The grown module derived it from
#: its own ``__file__`` and named it ``_WORKER``; that spelling stays live for
#: the shim's baseline.  The path is DATA the package owns, and it is checked
#: at import: a wrong path here does not raise — ``_worker_python()`` simply
#: finds no interpreter, ``real_bindings_available()`` returns False, and every
#: XrdCl suite SKIPs.  That failure is green, so it is asserted, not assumed.
WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "worker.py")
_WORKER = WORKER_SCRIPT

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
        if not self._alive:
            raise XrdClWorkerError("XrdCl worker is not running")
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
            if sig != self._env_sig:
                req["env"] = dict(os.environ)
                self._env_sig = sig
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
        if not got:
            # Hung op — destroy the worker so the deadlock cannot persist.
            self.kill()
            raise XrdClWorkerError(
                "XrdCl op timed out after %ss (op=%s) — worker killed"
                % (timeout, req.get("op")))
        msg = slot[1]
        if msg is None or not self._alive and msg is None:
            raise XrdClWorkerError("XrdCl worker died during op %s"
                                   % req.get("op"))
        if not msg.get("ok"):
            # Re-raise the binding's native exception type when it was a plain
            # builtin (ValueError, TypeError, …) so test ``except`` clauses that
            # target the real pyxrootd behaviour still match.  Anything else
            # surfaces as XrdClWorkerError.
            etype = msg.get("etype")
            cls = getattr(builtins, etype, None) if etype else None
            if isinstance(cls, type) and issubclass(cls, Exception) \
                    and cls not in (Exception, BaseException):
                raise cls(msg.get("emsg", ""))
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

