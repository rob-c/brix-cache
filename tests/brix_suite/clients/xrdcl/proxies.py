"""The proxy objects the shadow ``XRootD.client`` package re-exports.

``FileSystem``, ``File``, ``CopyProcess`` and ``URL`` look local and are not:
every attribute access becomes a worker call.  They were shard 2 of the grown
module and reached ``_worker``, ``Status``, ``_decode_response`` and
``_RESP_TYPES`` across the ``exec`` seam without importing them — the class of
reference that only becomes a ``NameError`` once the shards are real modules.
Those four are now real imports.
"""

from brix_suite.clients.xrdcl.results import (
    Status, _decode_response, _encode_args,
)
from brix_suite.clients.xrdcl.worker_link import _CALL_TIMEOUT, _worker

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
