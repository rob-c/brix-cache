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


def _decode_response(payload):
    """Inverse of the worker's _encode_response.

    Markers: __bytes__ (binary), __status__ (an XRootDStatus), __list__ (a
    list), __dict__ (a plain dict, e.g. a copy-job result), __type__ (a typed
    response object).  Bare lists/dicts are decoded element-wise too.
    """
    if payload is None:
        return None
    if isinstance(payload, list):
        return [_decode_response(x) for x in payload]
    if isinstance(payload, dict):
        if "__bytes__" in payload:
            return base64.b64decode(payload["__bytes__"])
        if "__status__" in payload:
            return Status(payload["__status__"])
        if "__list__" in payload:
            return [_decode_response(x) for x in payload["__list__"]]
        if "__tuple__" in payload:
            return tuple(_decode_response(x) for x in payload["__tuple__"])
        if "__dict__" in payload:
            return {k: _decode_response(v)
                    for k, v in payload["__dict__"].items()}
        t = payload.get("__type__")
        if t is not None:
            cls = _RESP_TYPES.get(t)
            if cls is not None:
                return cls(payload)
            return _Generic(payload)
        # Plain dict with no marker — decode values.
        return {k: _decode_response(v) for k, v in payload.items()}
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
        self._w = _worker()
        self._h = self._w.call(req)["h"]

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
        # A plain-value method (e.g. File.is_open() -> bool) returns the value
        # directly; status-returning methods return the (status, response) pair.
        if "value" in msg:
            return _decode_response(msg["value"])
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
        # Finalizer: queue the handle for release WITHOUT any blocking call or
        # lock acquisition (see _Worker._pending_releases).  deque.append is
        # atomic; the release is flushed on the next call().
        try:
            w = self._w
            if w is not None and w._alive:
                w._pending_releases.append(self._h)
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
