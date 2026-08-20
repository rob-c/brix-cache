"""Out-of-process XrdCl isolation layer — the flat ``_xrdcl_proxy`` surface.

The shadow ``XRootD`` package (``tests/XRootD/``) re-exports the proxy classes
from here, so ``from XRootD import client`` inside a test transparently drives
the real bindings hosted in :mod:`~brix_suite.clients.xrdcl.worker` — WITHOUT
importing pyxrootd into the pytest interpreter.  Why that matters, and the
JSON-lines protocol, are documented in :mod:`~brix_suite.clients.xrdcl.worker`.

The grown module was two ``exec``-composed shards; it is three modules now:

* :mod:`~brix_suite.clients.xrdcl.worker_link` — interpreter probe, the worker
  connection and **all of this layer's mutable process state**;
* :mod:`~brix_suite.clients.xrdcl.results` — result wrappers + wire codec;
* :mod:`~brix_suite.clients.xrdcl.proxies` — ``FileSystem``/``File``/
  ``CopyProcess``/``URL``.

``_worker_singleton`` is served by a module ``__getattr__`` rather than
re-exported.  That is not style: it is the only way this facade can name it
*truthfully*.  ``worker_link._worker()`` rebinds that global, and a plain
``from … import _worker_singleton`` here would freeze the value it had at
import — ``None``, forever — while the worker it is supposed to describe came
and went.  A re-export would have satisfied guard #3, which checks that a name
exists, not that it still means anything.
"""

from brix_suite.clients.xrdcl import worker_link as _worker_link
from brix_suite.clients.xrdcl.proxies import (
    CopyProcess, File, FileSystem, URL, _RemoteObject,
)
from brix_suite.clients.xrdcl.results import (
    DirectoryList, LocationInfo, StatInfo, StatInfoVFS, Status, VectorReadInfo,
    _Chunk, _Generic, _ListEntry, _Location, _RESP_TYPES, _decode_response,
    _encode_arg, _encode_args,
)
from brix_suite.clients.xrdcl.worker_link import (
    WORKER_SCRIPT, XrdClWorkerError, _CALL_TIMEOUT, _WORKER, _Worker,
    _shutdown_worker, _worker, _worker_python, _worker_singleton_lock,
    real_bindings_available,
)

#: Names that are live state in :mod:`worker_link` and must never be copied.
_LIVE_STATE = ("_worker_singleton",)

__all__ = [
    "CopyProcess", "DirectoryList", "File", "FileSystem", "LocationInfo",
    "StatInfo", "StatInfoVFS", "Status", "URL", "VectorReadInfo",
    "WORKER_SCRIPT", "XrdClWorkerError", "real_bindings_available",
]


def __getattr__(name):
    if name in _LIVE_STATE:
        return getattr(_worker_link, name)
    raise AttributeError(
        "module %r has no attribute %r" % (__name__, name))


def __dir__():
    return sorted(set(globals()) | set(_LIVE_STATE))
