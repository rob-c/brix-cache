# brix-remote-adapted
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


class XrdClWorkerError(RuntimeError):
    """Raised when the isolated worker errors, dies, or times out."""


def real_bindings_available():
    """Return whether the configured worker can import the real bindings."""
    environment = dict(os.environ)
    environment["XRDCL_IMPORT_PROBE"] = "1"
    executable = os.environ.get("XRDCL_WORKER_PYTHON", sys.executable)
    try:
        result = subprocess.run(
            [executable, "-u", _WORKER], input="", text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, env=environment)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


# ==========================================================================
# Worker connection (singleton per process).
# ==========================================================================
class _Worker:
    def __init__(self):
        env = dict(os.environ)
        # The worker must import the REAL bindings; keep it off the shadow.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self._proc = subprocess.Popen(
            # brix-remote: the XrdCl worker needs the interpreter that has the
            # real pyxrootd bindings (EPEL python3-xrootd is built for the distro
            # python), which may differ from the one running pytest.
            [os.environ.get("XRDCL_WORKER_PYTHON", sys.executable), "-u", _WORKER],
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
    def _flush_pending_releases(self):
        while self._pending_releases:
            handle = self._pending_releases.popleft()
            try:
                message = json.dumps({"op": "release", "h": handle}) + "\n"
                self._proc.stdin.write(message)
            except Exception:
                return

    def _prepare_request(self, request, slot):
        request_id = self._next_id
        self._next_id += 1
        request["id"] = request_id
        signature = hash(tuple(sorted(os.environ.items())))
        if signature != self._env_sig:
            request["env"] = dict(os.environ)
            self._env_sig = signature
        with self._slots_lock:
            self._slots[request_id] = slot
        return request_id

    def _write_request(self, request):
        try:
            self._proc.stdin.write(json.dumps(request) + "\n")
            self._proc.stdin.flush()
        except Exception as error:
            raise XrdClWorkerError("worker stdin write failed: %s" % error)

    def _wait_for_response(self, event, slot, request_id, request, timeout):
        received = event.wait(timeout)
        with self._slots_lock:
            self._slots.pop(request_id, None)
        if not received:
            self.kill()
            raise XrdClWorkerError(
                "XrdCl op timed out after %ss (op=%s) — worker killed"
                % (timeout, request.get("op")))
        message = slot[1]
        if message is None:
            raise XrdClWorkerError("XrdCl worker died during op %s"
                                   % request.get("op"))
        return message

    @staticmethod
    def _native_exception(message):
        exception_name = message.get("etype")
        exception = getattr(builtins, exception_name, None) if exception_name else None
        if not isinstance(exception, type):
            return None
        if not issubclass(exception, Exception):
            return None
        if exception in (Exception, BaseException):
            return None
        return exception

    def _validate_response(self, message):
        if message.get("ok"):
            return message
        exception = self._native_exception(message)
        if exception is not None:
            raise exception(message.get("emsg", ""))
        raise XrdClWorkerError(message.get("error", "unknown worker error"))

    def call(self, req, timeout=_CALL_TIMEOUT):
        if not self._alive:
            raise XrdClWorkerError("XrdCl worker is not running")
        event = threading.Event()
        slot = [event, None]
        with self._lock:
            self._flush_pending_releases()
            request_id = self._prepare_request(req, slot)
            self._write_request(req)
        message = self._wait_for_response(
            event, slot, request_id, req, timeout)
        return self._validate_response(message)

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


def _decode_list(value):
    return [_decode_response(item) for item in value]


def _decode_tuple(value):
    return tuple(_decode_response(item) for item in value)


def _decode_dict(value):
    return {key: _decode_response(item) for key, item in value.items()}


def _decode_typed_or_plain(payload):
    response_type = payload.get("__type__")
    if response_type is None:
        return _decode_dict(payload)
    response_class = _RESP_TYPES.get(response_type)
    if response_class is None:
        return _Generic(payload)
    return response_class(payload)


def _decode_mapping(payload):
    handlers = (
        ("__bytes__", base64.b64decode),
        ("__status__", Status),
        ("__list__", _decode_list),
        ("__tuple__", _decode_tuple),
        ("__dict__", _decode_dict),
    )
    for marker, handler in handlers:
        if marker in payload:
            return handler(payload[marker])
    return _decode_typed_or_plain(payload)


def _decode_response(payload):
    """Inverse of the worker's _encode_response.

    Markers: __bytes__ (binary), __status__ (an XRootDStatus), __list__ (a
    list), __dict__ (a plain dict, e.g. a copy-job result), __type__ (a typed
    response object).  Bare lists/dicts are decoded element-wise too.
    """
    if payload is None:
        return None
    if isinstance(payload, list):
        return _decode_list(payload)
    if isinstance(payload, dict):
        return _decode_mapping(payload)
    return payload


def _encode_arg(a):
    if isinstance(a, (bytes, bytearray, memoryview)):
        return {"__bytes__": base64.b64encode(bytes(a)).decode("ascii")}
    if isinstance(a, (list, tuple)):
        return [_encode_arg(x) for x in a]
    return a


def _encode_args(args, kwargs):
    return ([_encode_arg(a) for a in args],
            {k: _encode_arg(v) for k, v in kwargs.items()})



from split_continuation import load as _load_continuation

_load_continuation(globals(), __file__, "_xrdcl_proxy_part2.py")
