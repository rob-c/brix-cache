"""
Phase-42 cross-cutting guardrails — clean-room + no-goto + docblock lint.

These are static guardrails over the phase-42 compression work; NO servers are
needed (every check is a plain file read / `ldd` over the built artifacts):

  (1) Clean-room: each built native client binary
      (client/bin/{xrdcp,xrdfs,xrootdfs}) must NOT dynamically link any
      libXrd* (libXrdCl / libXrdSec / ...) — the whole point of the native
      clean-room clients is that they ride on libxrdproto, never on XrdCl.

  (2) No-goto: the phase-42 NEW source files must contain zero `goto` STATEMENTS
      (HARD BLOCK in the coding standard). We match the statement form
      (`goto <label>;`) so the substring "goto" inside an identifier or a comment
      does not produce a false positive.

  (3) Docblock: each of those new source files must carry a top-of-file comment
      block (a WHAT/WHY header or at least a leading /* ... */).

Modeled on tests/test_compression_zip.py for skip/style conventions. Each check
degrades gracefully via pytest.skip(...) when a needed binary/source is absent,
so the file is always runnable as-is.
"""

import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- (1) clean-room target binaries ---------------------------------------
CLIENT_BINARIES = ["xrdcp", "xrdfs", "xrootdfs"]

# --- (2)/(3) phase-42 NEW source files (relative to REPO) ------------------
PHASE42_SOURCES = [
    "src/protocols/root/read/read_compress.c",
    "src/protocols/root/write/write_compress.c",
    "src/core/compat/codec_core.c",
    "src/core/compat/codec_zlib.c",
    "src/core/compat/codec_zstd.c",
    "src/core/compat/codec_lzma.c",
    "src/core/compat/codec_brotli.c",
    "src/core/compat/codec_bzip2.c",
    "src/core/compat/codec_lz4.c",
    "src/core/http/http_compress.c",
    "client/lib/zip.c",
]

# `goto <label>;` — the statement form only. \bgoto\b ensures we never match
# "goto" inside an identifier (e.g. goto_label, retry_goto); requiring a label
# and a terminating ';' means the comment word "goto" (no trailing `;label;`)
# is also ignored. Whitespace between tokens may include newlines.
GOTO_STMT = re.compile(r"\bgoto\b\s+[A-Za-z_]\w*\s*;")


def _read_text(rel):
    """Return file text, or None if the file is absent (caller skips)."""
    path = os.path.join(REPO, rel)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# (1) Clean-room: no libXrd* in the dynamic dependency list
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", CLIENT_BINARIES)
def test_client_binary_is_cleanroom(name):
    binpath = os.path.join(REPO, "client", "bin", name)
    _require_executable(binpath)
    ldd = _require_ldd()
    r = subprocess.run([ldd, binpath], capture_output=True, text=True, timeout=60)
    # `ldd` returns non-zero for a static / non-dynamic binary; that is itself a
    # clean-room pass (nothing dynamically linked => certainly no libXrd*).
    out = (r.stdout or "") + (r.stderr or "")
    if _is_static_binary(out):
        return
    assert r.returncode == 0, f"ldd failed for {name}: {out[:300]}"

    offenders = _xrootd_dependencies(r.stdout)
    assert not offenders, (
        f"{name} links XRootD libraries (clean-room violation): {offenders}"
    )


def _require_executable(path):
    if not os.access(path, os.X_OK):
        pytest.skip(f"client binary not built/executable: {path}")


def _require_ldd():
    path = shutil.which("ldd")
    if path is None:
        pytest.skip("ldd not available on this host")
    return path


def _is_static_binary(output):
    return "not a dynamic executable" in output or "statically linked" in output


def _xrootd_dependencies(output):
    return [line.strip() for line in output.splitlines() if "libXrd" in line]


# ---------------------------------------------------------------------------
# (2) No-goto in the phase-42 NEW source files
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rel", PHASE42_SOURCES)
def test_phase42_source_has_no_goto(rel):
    text = _read_text(rel)
    if text is None:
        pytest.skip(f"source file absent: {rel}")
    matches = GOTO_STMT.findall(text)
    assert not matches, f"{rel} contains goto statement(s): {matches}"


# ---------------------------------------------------------------------------
# (3) Top-of-file docblock on each phase-42 NEW source file
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rel", PHASE42_SOURCES)
def test_phase42_source_has_docblock(rel):
    text = _require_source_text(rel)
    head = "\n".join(text.splitlines()[:40])
    assert _has_docblock(head), (
        f"{rel} is missing a top-of-file docblock (no WHAT/WHY and no /* ... */ "
        f"in the first 40 lines)"
    )


def _require_source_text(relative):
    text = _read_text(relative)
    if text is None:
        pytest.skip(f"source file absent: {relative}")
    return text


def _has_docblock(head):
    named = "WHAT" in head or "WHY" in head
    block = "/*" in head and "*/" in head
    return named or block
