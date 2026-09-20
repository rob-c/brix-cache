"""Shared helper: preload the sanitizer runtime ahead of an instrumented shim.

``client/libbrixposix_preload.so`` is compiled ``-fsanitize=address,undefined``
in the sanitizer build.  A ``.so`` shim does NOT ``DT_NEEDED`` the sanitizer
runtimes (they normally come from the executable), so LD_PRELOAD'ing it into an
uninstrumented host (``python3``, ``cp``, ``cat``) dies with
``undefined symbol: __asan_report_*`` / ``__ubsan_handle_*`` unless the matching
runtimes precede it in ``LD_PRELOAD``.  ``ldd`` shows nothing for such a shim,
so this asks the compiler for the loadable versioned objects (the bare
``libasan.so`` is a linker script, not LD_PRELOAD-able) and only for the
runtimes the shim's own undefined symbols actually reference — a plain
(non-sanitizer) build needs no preload at all.
"""

from __future__ import annotations

import functools
import os
import subprocess


@functools.lru_cache(maxsize=1)
def leak_detection_available() -> bool:
    """True when LeakSanitizer can actually run on this host.

    LSan stops threads and walks memory through ptrace, so where
    ``kernel.yama.ptrace_scope`` is restricted an unprivileged process dies at
    exit with "LeakSanitizer has encountered a fatal error ... does not work
    under ptrace".  That turns EVERY instrumented binary's exit into a spurious
    non-zero, which is indistinguishable from the failure the test is looking
    for.  Root keeps CAP_SYS_PTRACE whatever the scope says.
    """
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope", encoding="ascii") as fh:
            return fh.read().strip() == "0"
    except FileNotFoundError:
        return True                      # no yama LSM -> ptrace unrestricted
    except OSError:
        return True                      # unreadable -> assume usable


def asan_options(*settings: str) -> str:
    """Join ASAN_OPTIONS `settings`, dropping leak detection where it cannot run.

    Callers keep asking for ``detect_leaks=1``; this downgrades that one key to
    ``0`` on a ptrace-restricted host so the rest of the sanitizer (the
    use-after-free / overflow checks the test is actually asserting) still
    runs, instead of the whole binary aborting before it reports anything.
    """
    usable = leak_detection_available()
    out = []
    for item in settings:
        key = item.split("=", 1)[0]
        if key == "detect_leaks" and not usable:
            item = "detect_leaks=0"
        out.append(item)
    return ":".join(out)


def sanitizer_runtimes(shim_path: str) -> str:
    """Space-joined loadable sanitizer runtimes for ``shim_path`` ("" if none).

    Prepend the result to LD_PRELOAD, before the shim, when driving an
    uninstrumented host process through it.
    """
    try:
        dyn = subprocess.run(
            ["nm", "-D", shim_path], capture_output=True, timeout=10
        ).stdout
    except Exception:
        return ""
    return " ".join(_resolve_sonames(_wanted_sonames(dyn)))


def _wanted_sonames(dyn: bytes) -> list[str]:
    """Candidate sanitizer sonames (newest-first) for the symbols in `dyn`."""
    wanted = []
    if b"__asan" in dyn:
        wanted += ["libasan.so.8", "libasan.so.6", "libasan.so.5"]
    if b"__ubsan" in dyn:
        wanted += ["libubsan.so.1", "libubsan.so.0"]
    return wanted


def _resolve_soname(soname: str) -> str:
    """The on-disk path `cc` resolves for `soname`, or "" when not found."""
    try:
        path = subprocess.run(
            ["cc", f"-print-file-name={soname}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except Exception:
        return ""
    return path if path and path != soname and os.path.exists(path) else ""


def _resolve_sonames(wanted: list[str]) -> list[str]:
    """The first resolvable soname per family (asan/ubsan), in `wanted` order."""
    found: list[str] = []
    seen_family: set[str] = set()
    for soname in wanted:
        family = soname.rsplit(".so", 1)[0]
        if family in seen_family:
            continue
        path = _resolve_soname(soname)
        if path:
            found.append(path)
            seen_family.add(family)
    return found
