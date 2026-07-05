"""
Shadow of ``XRootD.client``.

Re-exports the out-of-process proxy classes so that test code written against
the real bindings keeps working unchanged:

    from XRootD import client
    fs = client.FileSystem("root://host:port")
    status, info = fs.stat("/path")

All calls are serviced by the isolated worker; no pyxrootd is imported here.
"""

import importlib
import sys

# Load the parent-side proxy implementation, which lives next to tests/ on the
# path (tests/_xrdcl_proxy.py).  It is imported by module name so the shadow
# package has no relative dependency on its location.
_proxy = importlib.import_module("_xrdcl_proxy")

from . import flags  # noqa: F401,E402

FileSystem = _proxy.FileSystem
File = _proxy.File
CopyProcess = _proxy.CopyProcess
URL = _proxy.URL
XrdClWorkerError = _proxy.XrdClWorkerError

# Expose ``flags`` as a submodule attribute (tests do ``client.flags.OpenFlags``)
sys.modules[__name__ + ".flags"] = flags

__all__ = ["FileSystem", "File", "CopyProcess", "URL", "flags",
           "XrdClWorkerError"]
