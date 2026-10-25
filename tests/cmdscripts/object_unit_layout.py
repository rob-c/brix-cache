"""One configured nginx SDK and its platform-specific native unit closure."""

import os
import sys
from pathlib import Path

from cmdscripts.compile_run import pal_host_addon
from lib_py.nginx_build import configured_dependency_includes

# Honour NGX_SRC (mirroring c_regression_units.py) so the unit runners link
# against whichever configured build tree the caller points at — the shared
# /tmp/nginx-1.28.3 by default, or a private tree during concurrent-session work.
NGX_SRC = Path(os.environ.get("TEST_NGINX_SRC", os.environ.get("NGX_SRC", "/tmp/nginx-1.28.3")))
OBJS = Path(os.environ.get("TEST_NGINX_OBJS", str(NGX_SRC / "objs")))


def addon(path: str) -> Path:
    return OBJS / "addon" / path


def _inc(*dirs) -> tuple[str, ...]:
    """Interleave ``-I`` flags for `dirs` (Paths or strings), in order."""
    flags: list[str] = []
    for d in dirs:
        flags += ["-I", str(d)]
    return tuple(flags + configured_dependency_includes(OBJS / 'Makefile', NGX_SRC))


# The nginx header sets the object-linked units compile against, in the same
# order the build tree uses; HTTP adds the stream/http trees for specs whose
# structs reach past them.
_NGX_CORE_INC = (NGX_SRC / "src/core", NGX_SRC / "src/event",
                 NGX_SRC / "src/event/modules", NGX_SRC / "src/event/quic",
                 NGX_SRC / "src/os/unix")
_NGX_HTTP_INC = (NGX_SRC / "src/stream", NGX_SRC / "src/http",
                 NGX_SRC / "src/http/modules")
# ngx_string/palloc/alloc: the three libngx objects ngx_link_stubs.c leans on.
_NGX_LIB_OBJS = (str(OBJS / "src/core/ngx_string.o"),
                 str(OBJS / "src/core/ngx_palloc.o"),
                 str(OBJS / "src/os/unix/ngx_alloc.o"))

# Darwin's anonymous descriptor lives in its host PAL, not the Linux/shared
# CVMFS shim. Link the actual selected owner rather than skipping a missing TU.
_ANON_FD_OBJECT = addon(pal_host_addon("posix_wrapper")
                        if sys.platform == "darwin" else "platform/platform.o")
_ANON_FD_LINK = ("-Wl,-dead_strip", "-framework", "Security") if sys.platform == "darwin" else ()
