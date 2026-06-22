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


# ==========================================================================
# Worker connection (singleton per process).
# ==========================================================================
class _Worker:
    def __init__(self):
        env = dict(os.environ)
        # The worker must import the REAL bindings; keep it off the shadow.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self._proc = subprocess.Popen(
            [sys.executable, "-u", _WORKER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1,
        )
        self._lock = threading.Lock()          # guards stdin writes + _next_id
        self._slots = {}                       # id -> [event, result]
        self._slots_lock = threading.Lock()
        self._next_id = 1
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
            rid = self._next_id
            self._next_id += 1
            req["id"] = rid
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


class _Generic:
    """Fallback wrapper for response types without a dedicated class."""
    def __init__(self, d):
        for k, v in d.items():
            if k == "__type__":
                continue
            if isinstance(v, dict) and "__bytes__" in v:
                v = base64.b64decode(v["__bytes__"])
            setattr(self, k, v)


_RESP_TYPES = {
    "StatInfo": StatInfo,
    "StatInfoVFS": StatInfoVFS,
    "DirectoryList": DirectoryList,
    "LocationInfo": LocationInfo,
    "VectorReadInfo": VectorReadInfo,
}


def _decode_response(payload):
    if payload is None:
        return None
    if isinstance(payload, dict):
        if "__bytes__" in payload:
            return base64.b64decode(payload["__bytes__"])
        t = payload.get("__type__")
        cls = _RESP_TYPES.get(t)
        if cls is not None:
            return cls(payload)
        return _Generic(payload)
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


# ==========================================================================
# Proxy objects — the public API mirrored by the shadow package.
# ==========================================================================
class _RemoteObject:
    _NEW_OP = None      # subclass: worker op that constructs the remote object
    _CALL_OP = None     # subclass: worker op that invokes a method

    def __init__(self, *ctor_args, **ctor_kwargs):
        req = {"op": self._NEW_OP}
        self._init_request(req, ctor_args, ctor_kwargs)
        self._h = _worker().call(req)["h"]

    def _init_request(self, req, args, kwargs):
        pass

    def _invoke(self, method, args, kwargs):
        enc_args, enc_kwargs = _encode_args(list(args), dict(kwargs))
        # pyxrootd accepts a per-op timeout kwarg; honour it for our wait too.
        op_timeout = kwargs.get("timeout", 0) or 0
        wait = max(_CALL_TIMEOUT, float(op_timeout) + 15) if op_timeout else _CALL_TIMEOUT
        msg = _worker().call(
            {"op": self._CALL_OP, "h": self._h,
             "method": method, "args": enc_args, "kwargs": enc_kwargs},
            timeout=wait)
        status = Status(msg.get("status"))
        resp = _decode_response(msg.get("response"))
        return status, resp

    def __getattr__(self, name):
        # Any unknown attribute is treated as a remote method.
        if name.startswith("_"):
            raise AttributeError(name)

        def _method(*args, **kwargs):
            return self._invoke(name, args, kwargs)
        return _method

    def __del__(self):
        try:
            w = _worker_singleton
            if w is not None and w._alive:
                w.call({"op": "release", "h": self._h}, timeout=5)
        except Exception:
            pass


class FileSystem(_RemoteObject):
    _NEW_OP = "fs_new"
    _CALL_OP = "fs_call"

    def _init_request(self, req, args, kwargs):
        url = args[0] if args else kwargs.get("url")
        req["url"] = url


class File(_RemoteObject):
    _NEW_OP = "file_new"
    _CALL_OP = "file_call"

    # Context-manager support (tests use ``with client.File() as f:``).
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self._invoke("close", (), {})
        except Exception:
            pass
        return False


class CopyProcess(_RemoteObject):
    _NEW_OP = "cp_new"
    _CALL_OP = "cp_call"


class URL:
    """Local-looking URL parser backed by the worker's real XrdCl URL."""
    def __init__(self, url):
        fields = _worker().call({"op": "url_parse", "url": url})["fields"]
        self._f = fields

    def is_valid(self):
        return bool(self._f.get("is_valid"))

    def __getattr__(self, name):
        f = object.__getattribute__(self, "_f")
        if name in f:
            return f[name]
        raise AttributeError(name)
