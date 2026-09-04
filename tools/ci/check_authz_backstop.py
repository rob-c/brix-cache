#!/usr/bin/env python3
"""Enforce the Phase-108 VFS authorization-backstop construction rules."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VFS = ROOT / "src/fs/vfs"

# A construction site must bind the export policy (or explicitly state that a
# different, already-authenticated plane owns authorization) immediately. The
# implementation site initializes the empty bundle by definition.
INIT_RE = re.compile(r"\bbrix_vfs_ctx_init\s*\(")
BINDER_RE = re.compile(
    r"\b(?:brix_vfs_ctx_bind_authz|brix_vfs_ctx_bind_no_authz_rules|"
    r"brix_http_vfs_bind_authz|brix_http_vfs_bind_no_rules|"
    r"brix_root_vfs_bind_session|s3_vfs_bind_deleg|"
    r"webdav_vfs_bind_deleg)\s*\("
)
INIT_EXEMPT = {"src/fs/vfs/vfs_open_adopt.c"}
INIT_WINDOW = 32

# Named VFS entry points are the reviewable surface. This mirrors the phase-105
# mutation inventory and adds the path-reading APIs that can touch storage.
MUTATION_SITES = (
    ("vfs_open.c", "brix_vfs_open_precheck", "brix_vfs_gate_mutation"),
    ("vfs_mkdir.c", "brix_vfs_mkdir", "brix_vfs_confined_mutation_checked"),
    ("vfs_mkdir.c", "brix_vfs_chmod", "brix_vfs_confined_mutation_checked"),
    ("vfs_mkdir.c", "brix_vfs_setattr", "brix_vfs_confined_mutation_checked"),
    ("vfs_unlink.c", "brix_vfs_delete", "brix_vfs_confined_mutation_checked"),
    ("vfs_rename.c", "brix_vfs_two_name_entry", "brix_vfs_confined_mutation_checked"),
    ("vfs_copy.c", "brix_vfs_copy", "brix_vfs_confined_mutation_checked"),
    ("vfs_sync.c", "brix_vfs_truncate", "brix_vfs_gate_file_mutation"),
    ("vfs_sync.c", "brix_vfs_truncate_path", "brix_vfs_confined_mutation_checked"),
    ("vfs_sync.c", "brix_vfs_sync", "brix_vfs_gate_file_mutation"),
    ("vfs_writer.c", "brix_vfs_writer_write", "brix_vfs_gate_mutation"),
    ("vfs_writer.c", "brix_vfs_writer_write_fd", "brix_vfs_gate_mutation"),
    ("vfs_writer.c", "brix_vfs_writer_commit_pre", "brix_vfs_gate_mutation"),
    ("vfs_staged.c", "staged_alloc_handle", "brix_vfs_confined_mutation_checked"),
    ("vfs_staged.c", "brix_vfs_staged_write", "brix_vfs_gate_mutation"),
    ("vfs_staged.c", "brix_vfs_staged_commit", "brix_vfs_gate_mutation"),
    ("vfs_xattr.c", "brix_vfs_xattr_mutate", "brix_vfs_gate_mutation"),
    ("vfs_xattr.c", "brix_vfs_fsetxattr_carried", "brix_vfs_require_carried_mutation"),
    ("vfs_xattr.c", "brix_vfs_fremovexattr_carried", "brix_vfs_require_carried_mutation"),
    ("vfs_recall.c", "brix_vfs_recall", "brix_vfs_gate_confined"),
    ("vfs_recall.c", "brix_vfs_evict", "brix_vfs_gate_confined"),
    ("vfs_unlink_many.c", "brix_vfs_delete_many", "brix_vfs_gate_confined"),
)

READ_SITES = (
    ("vfs_open.c", "brix_vfs_open_precheck", "brix_vfs_require_authorized_read"),
    ("vfs_dir.c", "brix_vfs_opendir_impl", "brix_vfs_require_authorized_lookup"),
    ("vfs_stat.c", "vfs_stat_precheck", "brix_vfs_require_authorized_lookup"),
    ("vfs_stat.c", "brix_vfs_residency", "brix_vfs_require_authorized_lookup"),
    ("vfs_stat.c", "brix_vfs_space", "brix_vfs_require_authorized_lookup"),
    ("vfs_stat.c", "brix_vfs_probe", "brix_vfs_require_authorized_lookup"),
    ("vfs_xattr.c", "brix_vfs_xattr_read", "brix_vfs_require_authorized_lookup"),
    ("vfs_xattr.c", "brix_vfs_fgetxattr", "brix_vfs_require_authorized_lookup"),
    ("vfs_xattr.c", "brix_vfs_flistxattr", "brix_vfs_require_authorized_lookup"),
)

NONCODE_RE = re.compile(r'''/\*.*?\*/|//[^\n]*|"(?:[^"\\\n]|\\.)*"''', re.S)


def _blank_noncode(text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group())

    return NONCODE_RE.sub(blank, text)


def _function_body(text: str, name: str) -> str | None:
    """Return one C function body, preserving source bytes for token checks."""
    code = _blank_noncode(text)
    match = re.search(r"\b" + re.escape(name) + r"\s*\(", code)
    if match is None:
        return None
    opening = code.find("{", match.end())
    if opening < 0:
        return None
    depth = 0
    for pos in range(opening, len(code)):
        if code[pos] == "{":
            depth += 1
        elif code[pos] == "}":
            depth -= 1
            if depth == 0:
                return code[opening:pos + 1]
    return None


def _source_files() -> list[Path]:
    files: list[Path] = []
    for base in (ROOT / "src",):
        for dirpath, dirnames, names in os.walk(base):
            dirnames.sort()
            files.extend(Path(dirpath) / name for name in sorted(names)
                         if name.endswith(".c"))
    return files


def _check_sites(sites: tuple[tuple[str, str, str], ...]) -> list[str]:
    errors: list[str] = []
    cache: dict[str, str] = {}
    for filename, function, required in sites:
        text = cache.setdefault(filename, (VFS / filename).read_text(encoding="latin-1"))
        body = _function_body(text, function)
        if body is None:
            errors.append(f"src/fs/vfs/{filename}: missing function {function}()")
        elif re.search(r"\b" + re.escape(required) + r"\s*\(", body) is None:
            errors.append(f"src/fs/vfs/{filename}: {function}() lacks {required}()")
    return errors


def _check_context_path(path: Path) -> list[str]:
    errors: list[str] = []
    rel = path.relative_to(ROOT).as_posix()
    if rel in INIT_EXEMPT:
        return errors
    text = path.read_text(encoding="latin-1")
    lines = text.splitlines()
    code_lines = _blank_noncode(text).splitlines()
    for lineno, line in enumerate(code_lines):
        if INIT_RE.search(line) is None:
            continue
        window = "\n".join(code_lines[lineno:lineno + INIT_WINDOW])
        if BINDER_RE.search(window) is None:
            errors.append(
                f"{rel}:{lineno + 1}: VFS context is not authorization-bound "
                f"within {INIT_WINDOW} lines: {lines[lineno].strip()}"
            )
    return errors


def _check_context_binders() -> list[str]:
    errors: list[str] = []
    for path in _source_files():
        errors.extend(_check_context_path(path))
    return errors


def _check_gate_order(name: str, policy: str, authz: str) -> str | None:
    body = _function_body(authz, name) or ""
    policy_at = body.find(policy + "(")
    authz_at = body.find("brix_vfs_require_authorized(")
    if policy_at < 0 or authz_at < 0 or policy_at >= authz_at:
        return f"src/fs/vfs/vfs_authz.c: {name}() is not policy-before-authz"
    return None


def _direct_policy_bypasses() -> list[str]:
    errors: list[str] = []
    for path in sorted(VFS.glob("vfs_*.c")):
        if path.name in {"vfs_authz.c", "vfs_policy.c"}:
            continue
        code = _blank_noncode(path.read_text(encoding="latin-1"))
        if re.search(r"\bbrix_vfs_require_(?:confined_)?mutation\s*\(", code):
            errors.append(f"src/fs/vfs/{path.name}: direct policy call bypasses fused authz gate")
    return errors


def _check_fused_ordering() -> list[str]:
    authz = (VFS / "vfs_authz.c").read_text(encoding="latin-1")
    errors = [error for error in (
        _check_gate_order("brix_vfs_gate_mutation",
                          "brix_vfs_require_mutation", authz),
        _check_gate_order("brix_vfs_gate_confined",
                          "brix_vfs_require_confined_mutation", authz),
    ) if error is not None]
    return errors + _direct_policy_bypasses()


def current_violations() -> list[str]:
    return sorted(set(
        _check_sites(MUTATION_SITES)
        + _check_sites(READ_SITES)
        + _check_context_binders()
        + _check_fused_ordering()
    ))


def main() -> int:
    errors = current_violations()
    if errors:
        print("ERROR: VFS authorization backstop coverage is incomplete:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("check_authz_backstop: OK — VFS gates are fused, ordered, and all contexts are bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
