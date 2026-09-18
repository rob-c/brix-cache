"""The POSIX preload shim as the test tier drives it, on either dynamic linker.

WHAT: Where the shim is, how a process is started with it inserted, what its
      wrappers are called in the symbol table, and which host programs can
      actually be interposed.
WHY:  Linux and macOS differ on all four.  glibc loads ``LD_PRELOAD`` objects
      whose wrappers carry libc's own names; dyld loads
      ``DYLD_INSERT_LIBRARIES`` dylibs whose ``brixposix_*`` wrappers reach
      libc through an ``__interpose`` table, and System Integrity Protection
      strips that variable from every Apple-signed binary (``/bin/cat``,
      ``/usr/bin/python3``, ...), so only binaries outside the protected
      locations, such as a Homebrew python or a freshly compiled driver, see
      the shim at all.
HOW:  ``preload_env`` sets the right variable; ``interposable_python`` and
      ``posix_tool`` hand back executables the insertion reaches on this host.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLIENT_DIR = os.path.join(REPO, "client")

IS_DARWIN = sys.platform == "darwin"
#: The shared-object suffix the client Makefile builds on this host.
SHLIB_EXT = "dylib" if IS_DARWIN else "so"
#: The Makefile goal / artifact name of the shim on this host.
SHIM_NAME = f"libbrixposix_preload.{SHLIB_EXT}"
#: The absolute path of the built shim.
SHIM_PATH = os.path.join(CLIENT_DIR, SHIM_NAME)
#: The environment variable that inserts a library on this host.
PRELOAD_VAR = "DYLD_INSERT_LIBRARIES" if IS_DARWIN else "LD_PRELOAD"
#: Separator between several inserted objects in that variable.
PRELOAD_SEP = ":" if IS_DARWIN else " "


def wrap_name(symbol: str) -> str:
    """The shim's own name for its wrapper of libc ``symbol``."""
    return f"brixposix_{symbol}" if IS_DARWIN else symbol


def preload_env(env: dict | None = None, *chain: str) -> dict:
    """``env`` (default: a copy of os.environ) with the shim, and any objects
    in ``chain`` before it (sanitizer runtimes), inserted the host's way."""
    out = dict(os.environ if env is None else env)
    parts = [x for x in (*chain, SHIM_PATH) if x]
    out[PRELOAD_VAR] = PRELOAD_SEP.join(parts)
    return out


def exported_symbols(path: str = SHIM_PATH) -> set[str]:
    """The defined, externally visible text symbols of the shared object,
    spelled without Mach-O's leading underscore."""
    argv = ["nm", "-gU", path] if IS_DARWIN else ["nm", "-D", "--defined-only", path]
    out = subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    names = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[-2] == "T":
            name = fields[-1]
            names.add(name[1:] if IS_DARWIN and name.startswith("_") else name)
    return names


def interposable_python() -> str:
    """A python executable the insertion reaches: on macOS the interpreter
    running the tests (a Homebrew / venv build outside SIP's protected paths),
    elsewhere whatever ``python3`` resolves to."""
    if IS_DARWIN:
        return sys.executable
    return shutil.which("python3") or sys.executable


_TOOL_SRC = r"""
/* cat / cp through plain POSIX calls: a stand-in for the Apple-signed
 * coreutils that DYLD_INSERT_LIBRARIES can never reach. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int pump(int in, int out)
{
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t) (n - off));
            if (w < 0) { perror("write"); return 1; }
            off += w;
        }
    }
    if (n < 0) { perror("read"); return 1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "cat") == 0) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) { perror(argv[2]); return 1; }
        int rc = pump(fd, 1);
        close(fd);
        return rc;
    }
    if (argc == 4 && strcmp(argv[1], "cp") == 0) {
        int in = open(argv[2], O_RDONLY);
        if (in < 0) { perror(argv[2]); return 1; }
        int out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out < 0) { perror(argv[3]); close(in); return 1; }
        int rc = pump(in, out);
        close(in);
        if (close(out) != 0) { perror("close"); rc = 1; }
        return rc;
    }
    fprintf(stderr, "usage: %s cat <path> | cp <src> <dst>\n", argv[0]);
    return 2;
}
"""

_tool_cache: dict[str, str] = {}


def posix_tool(name: str) -> list[str]:
    """argv prefix for ``cat`` or ``cp`` as an interposable program: the
    system tool on Linux; on macOS a small C driver compiled once per
    session (the coreutils there are SIP-protected)."""
    if name not in ("cat", "cp"):
        raise ValueError(name)
    if not IS_DARWIN:
        return [name]
    if "bin" not in _tool_cache:
        _tool_cache["bin"] = _compile_tool()
    return [_tool_cache["bin"], name]


def _compile_tool() -> str:
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        raise RuntimeError("no C compiler for the preload posix tool")
    work = tempfile.mkdtemp(prefix="brix-preload-tool-")
    src = os.path.join(work, "posix_tool.c")
    out = os.path.join(work, "posix_tool")
    with open(src, "w") as fh:
        fh.write(_TOOL_SRC)
    subprocess.run([cc, "-O1", "-o", out, src], check=True, capture_output=True,
                   timeout=120)
    return out
