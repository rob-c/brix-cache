"""Shared helpers for Python ports of small compile-and-run shell tests."""

from __future__ import annotations

from pathlib import Path
import sys
import os
import subprocess


def _expression_1(args):
    return (
        [a for a in args if str(a).endswith(".o")
                    and Path(a if os.path.isabs(str(a)) else REPO_ROOT / a).exists()]
    )

def _expression_2(objs):
    return (
        run(["nm", *[str(o) for o in objs]])
    )

def _expression_3(proc):
    return (
        proc.stdout if proc.returncode == 0 else ""
    )


def _guard_sanitizer_link_flags_1(syms, flags):
    if "__asan_" in syms:
        flags.append("-fsanitize=address")

def _guard_sanitizer_link_flags_2(syms, flags):
    if "__ubsan_" in syms or "__ubsan" in syms:
        flags.append("-fsanitize=undefined")

def _guard_sanitizer_link_flags_3(syms, flags):
    if "__tsan_" in syms:
        flags.append("-fsanitize=thread")


REPO_ROOT = Path(__file__).resolve().parents[2]


def run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd or REPO_ROOT),
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = proc.communicate()
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)


def sanitizer_link_flags(args: list[str]) -> list[str]:
    """`-fsanitize=...` when a linked-in .o was built under a sanitizer.

    An object compiled with -fsanitize=address/undefined/thread carries
    __asan_*/__ubsan_*/__tsan_* references, so linking it without the matching
    runtime dies at LD time with `undefined reference to __asan_*` — exactly the
    contaminated-nginx-object case (a tree built with -fsanitize whose objs/ the
    object-linked units reuse).  One nm pass picks the right flags."""
    objs = _expression_1(args)
    if not objs:
        return []
    proc = _expression_2(objs)
    syms = _expression_3(proc)
    flags = []
    _guard_sanitizer_link_flags_1(syms, flags)
    _guard_sanitizer_link_flags_2(syms, flags)
    _guard_sanitizer_link_flags_3(syms, flags)
    return flags


#: The PAL host selector every tree source needs (src/platform/platform.h
#: refuses to compile without it); mirrors ./config and client/Makefile.
#:
#: The host feature level rides along for the same reason on both platforms:
#: ``src/platform/<host>/host_endian.h`` names htobe64/be32toh, which glibc
#: gates on ``__USE_MISC`` and Darwin on ``_DARWIN_C_SOURCE``.  A source that
#: picks a strict level of its own withdraws that default — ``brixcvmfs_
#: publish.c`` sets ``_POSIX_C_SOURCE`` for kill/lstat — and the PAL then fails
#: with "implicit declaration of function 'htobe64'" in a header the source
#: never named.  ./config gets it from nginx's own ``-D_GNU_SOURCE``; a line
#: assembled here has to say it.
PLATFORM_HOST_FLAGS = (
    ["-DBRIX_PLATFORM_HOST=darwin", "-D_DARWIN_C_SOURCE"]
    if sys.platform == "darwin"
    else ["-DBRIX_PLATFORM_HOST=linux", "-D_DEFAULT_SOURCE"])


#: The PAL host bodies a standalone build must link when it calls ``brix_plat_*``
#: (the module and client Makefiles compile the whole ``<host>/`` directory; a
#: hand-rolled test build lists only what it needs).
PAL_HOST_DIR = f"src/platform/{'darwin' if sys.platform == 'darwin' else 'linux'}"


#: The CLIENT PAL host bodies (client/lib/platform/<host>/), which carry the
#: client-only verbs: FUSE option support, host mount options, unmount tiers.
CLIENT_PAL_HOST_DIR = (
    f"client/lib/platform/{'darwin' if sys.platform == 'darwin' else 'linux'}")


def client_pal_host_sources(*names: str) -> list[str]:
    """``client/lib/platform/<host>/<name>.c`` for each body the build needs."""
    return [f"{CLIENT_PAL_HOST_DIR}/{name}.c" for name in names]


def pal_host_sources(*names: str) -> list[str]:
    """``src/platform/<host>/<name>.c`` for each wrapper the build calls into."""
    return [f"{PAL_HOST_DIR}/{name}.c" for name in names]


def pal_host_addon(name: str) -> str:
    """``<host>/<name>.o`` — where the nginx build puts one compiled PAL host
    wrapper under ``objs/addon/``, relative to that directory.

    nginx names an addon object after its source directory's LAST component, so
    ``src/platform/linux/path_wrapper.c`` and its darwin twin land at different
    paths for the same wrapper.  Derived from ``PAL_HOST_DIR`` rather than a
    second ``sys.platform`` test, so an object-link line and a standalone
    compile line can never disagree about which host they are building for.

    A unit needs this whenever an object it links calls ``brix_plat_*``: the PAL
    seam (invariant 14) moved the openat2/renameat2/statx bodies out of
    ``src/fs/path/beneath.c`` and behind the wrapper, so ``beneath.o`` stopped
    being self-contained and every unit linking it failed at LINK time on a
    symbol that says nothing about the unit's own subject.
    """
    return f"{os.path.basename(PAL_HOST_DIR)}/{name}.o"


#: How to name liblz4 on the link line.  ``-l:<soname>`` is GNU-ld syntax that
#: Apple's ld64 has no form of, so Darwin links the plain ``-llz4`` (Homebrew's
#: dylib sits on the default loader path) — the same split client/Makefile
#: makes.  ``BRIX_LZ4_LIBS`` overrides both, as it does for the Makefile.
LZ4_LINK_FLAGS = (
    os.environ["BRIX_LZ4_LIBS"].split() if os.environ.get("BRIX_LZ4_LIBS")
    else ["-llz4"] if sys.platform == "darwin"
    else ["-l:liblz4.so.1"])


def weak_undefined_flags(*symbols: str) -> list[str]:
    """Link flags allowing ``symbols`` to stay undefined (an optional front-end
    the umbrella may be linked without).  ELF resolves an undefined weak symbol
    to NULL on its own; Mach-O's ld64 refuses one in a static link unless the
    name is listed with ``-U``, so BRIX_WEAK_REF alone is not enough there.
    """
    if sys.platform != "darwin":
        return []
    return [f"-Wl,-U,_{name}" for name in symbols]


def compile_binary(output: Path, args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return run(["gcc", *PLATFORM_HOST_FLAGS, *args, *sanitizer_link_flags(args),
                "-o", str(output)], cwd=cwd)


def result(ok: bool, message: str) -> tuple[bool, str]:
    return ok, message
