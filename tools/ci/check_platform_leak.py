#!/usr/bin/env python3
#
# check_platform_leak.py — every OS-specific branch lives behind the PAL.
#
# WHAT: Fails (exit 1) when production C/C++ under src/, shared/ or client/
#       tests an OS-detection macro or includes an OS-private header outside
#       a PAL host directory:
#         server   src/platform/{linux,darwin,windows}/
#         client   client/lib/platform/{linux,darwin}/
#         shared   shared/cvmfs/platform/         (the cvmfs mmap/sync owner)
#       The PAL interface itself (src/platform/*.h, client/lib/platform/
#       platform.h) is scanned too: it selects the host with one computed
#       #include from -DBRIX_PLATFORM_HOST and carries no #if.
#       Token rules, applied to code only (comments and string literals are
#       masked first, so a comment that says "<sys/xattr.h>" is not a hit):
#         detection   __APPLE__ __MACH__ TARGET_OS_* __linux__ __FreeBSD__
#                     __ANDROID__ _WIN32 _WIN64 __CYGWIN__ __MINGW* _MSC_VER
#                     BRIX_PLATFORM_*   (the PAL's own detection spellings
#                     are as much a leak as the compiler's: a caller that
#                     branches on BRIX_PLATFORM_DARWIN is not calling the PAL)
#         member      `x->getxattr(` / `.setxattr(` ... (any xattr-named struct
#                     member call) must be written `(x->getxattr)(` — see
#                     platform_api_posix.h "Sharp edge"
#         header      <sys/xattr.h> <sys/event.h> <sys/epoll.h> <sys/eventfd.h>
#                     <sys/inotify.h> <sys/sysmacros.h> <sys/sendfile.h>
#                     <linux/*> <mach/*> <libkern/*> <endian.h> <sys/endian.h>
#                     <windows.h> <winsock2.h> <io.h> <CoreFoundation/*>
#                     <TargetConditionals.h> <Availability*.h>
#
# WHY:  Phase 119 (macOS parity) grew the tree ~80 `#if defined(__APPLE__)`
#       sites, each a private port of one call. Every such site is a second
#       place a Darwin/Windows behaviour has to be fixed, none of them is
#       exercised by the PAL native fixtures, and a reader of src/fs/ or
#       client/lib/ cannot tell what the code does without knowing the host.
#       The rule the PAL exists for: portable code calls brix_plat_*(); only
#       the owner directories know which OS they are on.
#
# HOW:  walk *.c *.h *.cc *.cpp *.hh *.hpp under the three trees (unit tests
#       excluded, `_unittest` stem), mask comments/strings, apply the two
#       token rules per line. Any hit is a failure. There is deliberately NO
#       waiver marker and NO backlog: the tree was migrated to zero on
#       2026-09-16 and the only way to add a platform branch is inside an
#       owner directory. Capability gates the PAL defines (BRIX_HAS_*,
#       BRIX_PLAT_SHM_DIR) are the sanctioned way to gate optional features.
#
# USAGE:
#   tools/ci/check_platform_leak.py                 # exit 1 on any leak
#   tools/ci/check_platform_leak.py --root <dir>    # scan another checkout
#   tools/ci/check_platform_leak.py --list          # print every hit

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCAN_DIRS = ("src", "shared", "client")
SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp")
# Host directories only: the PAL interface (src/platform/*.h, *.c and
# client/lib/platform/platform.h) is itself host-free and is scanned.
OWNER_ROOTS = (
    Path("src/platform/linux"),
    Path("src/platform/darwin"),
    Path("src/platform/windows"),
    Path("client/lib/platform/linux"),
    Path("client/lib/platform/darwin"),
    Path("shared/cvmfs/platform"),
)

DETECTION = re.compile(
    r"\b(?:__APPLE__|__MACH__|TARGET_OS_[A-Z_]+|__linux__|__linux\b|__gnu_linux__"
    r"|__FreeBSD__|__NetBSD__|__OpenBSD__|__ANDROID__"
    r"|_WIN32|_WIN64|__CYGWIN__|__MINGW(?:32|64)?__|_MSC_VER"
    r"|BRIX_PLATFORM_(?:LINUX|DARWIN|MACOS|WINDOWS|APPLE))\b"
)
HEADER = re.compile(
    r"^[ \t]*#[ \t]*include[ \t]*<("
    r"sys/xattr\.h|sys/event\.h|sys/epoll\.h|sys/eventfd\.h|sys/inotify\.h"
    r"|sys/sysmacros\.h|sys/sendfile\.h|sys/endian\.h|endian\.h"
    r"|linux/[^>]+|mach/[^>]+|libkern/[^>]+|CoreFoundation/[^>]+"
    r"|TargetConditionals\.h|Availability[^>]*\.h"
    r"|windows\.h|winsock2\.h|ws2tcpip\.h|io\.h"
    r")>",
    re.M,
)
# A struct-member call spelt like an xattr syscall (`driver->getxattr(...)`) is
# captured by the PAL's Darwin call-shape macros and fails to compile there,
# which Linux CI never sees. The parenthesised spelling `(driver->getxattr)(...)`
# suppresses the expansion; the guard demands it.
MEMBER_CALL = re.compile(r"(?:->|\.)\s*((?:l|f)?(?:get|set|list|remove)xattr)\s*\(")

NONCODE = re.compile(
    r"""/\*.*?\*/|//[^\n]*|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'""", re.S)


def mask_noncode(text: str) -> str:
    """Blank comments and string literals, keeping line numbers intact."""
    return NONCODE.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def is_owner(relative: Path) -> bool:
    return any(relative.is_relative_to(root) for root in OWNER_ROOTS)


def is_production(path: Path) -> bool:
    return path.suffix in SOURCE_SUFFIXES and not path.stem.endswith("_unittest")


def production_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in SCAN_DIRS:
        base = root / name
        if not base.is_dir():
            raise ValueError(f"missing production directory: {base}")
        files.extend(p for p in base.rglob("*") if p.is_file() and is_production(p))
    return sorted(files)


def file_hits(text: str, member_rule: bool = True) -> list[tuple[int, str]]:
    """(line, token) for every platform token in code; one entry per token."""
    code = mask_noncode(text)
    hits = []
    for number, line in enumerate(code.splitlines(), 1):
        for match in DETECTION.finditer(line):
            hits.append((number, match.group()))
        header = HEADER.match(line)
        if header:
            hits.append((number, f"<{header.group(1)}>"))
        for member in (MEMBER_CALL.finditer(line) if member_rule else ()):
            hits.append((number, f"->{member.group(1)}( unparenthesised member call"))
    return hits


def scan(root: Path) -> dict[str, list[tuple[int, str]]]:
    """{relative path -> hits} for every non-owner production file with hits."""
    found: dict[str, list[tuple[int, str]]] = {}
    for path in production_files(root):
        relative = path.relative_to(root)
        if is_owner(relative):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue   # a scratch file another process removed mid-scan
        # The member rule guards C that sees the PAL's Darwin macros; the C++
        # librados tools (client/apps/ceph) call real member functions.
        hits = file_hits(text, member_rule=path.suffix in (".c", ".h"))
        if hits:
            found[relative.as_posix()] = hits
    return found


def violations(current: dict[str, list[tuple[int, str]]]) -> list[str]:
    """Every file with a platform token outside an owner is a failure."""
    owners = ", ".join(r.as_posix() for r in OWNER_ROOTS)
    out = []
    for name in sorted(current):
        hits = current[name]
        where = "; ".join(f"{line}:{token}" for line, token in hits[:6])
        out.append(f"{name}: {len(hits)} platform token(s) outside the PAL — "
                   f"move the branch behind brix_plat_* in an owner ({owners}) "
                   f"[{where}]")
    return out


def _print_hits(current: dict[str, list[tuple[int, str]]]) -> None:
    for name, hits in sorted(current.items()):
        for line, token in hits:
            print(f"{name}:{line}: {token}")


def _summary(current: dict[str, list[tuple[int, str]]], failed: bool) -> str:
    total = sum(len(h) for h in current.values())
    owners = ", ".join(r.as_posix() for r in OWNER_ROOTS)
    return (f"check_platform_leak: {'FAIL' if failed else 'OK'} ({len(current)} "
            f"file(s), {total} token(s) outside the PAL; owners: {owners})")


def _report(current: dict[str, list[tuple[int, str]]], list_hits: bool) -> int:
    if list_hits:
        _print_hits(current)
    problems = violations(current)
    print("\n".join(problems + [_summary(current, bool(problems))]))
    return int(bool(problems))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="checkout to scan")
    parser.add_argument("--list", action="store_true", help="print every hit")
    args = parser.parse_args(argv)
    try:
        current = scan(Path(args.root).resolve())
    except (OSError, ValueError) as error:
        print(f"check_platform_leak: {error}", file=sys.stderr)
        return 1
    return _report(current, args.list)


if __name__ == "__main__":
    sys.exit(main())
