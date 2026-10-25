#!/usr/bin/env python3
"""Migrate complete stderr diagnostic records, preserving terminal UI output.

This is a mechanical migration tool. Help, reports, carriage-return progress and
fragmented hexdumps stay presentation output. Each migrated call has an explicit
severity that can be reviewed at its original call site.
"""
import argparse
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEX = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                 r'\bfprintf\s*\(\s*stderr\s*,|[()]', re.S)


def _next_depth(value, depth):
    if value == "(":
        return depth + 1
    if value == ")":
        return depth - 1
    return depth


def stderr_calls(text):
    """Yield complete fprintf(stderr, ...) spans with balanced parentheses."""
    start = None
    depth = 0
    prefix_end = 0
    for token in LEX.finditer(text):
        value = token.group()
        if value.startswith("fprintf") and start is None:
            start, depth, prefix_end = token.start(), 1, token.end()
            continue
        if start is None:
            continue
        depth = _next_depth(value, depth)
        if depth == 0:
            yield start, token.end(), prefix_end
            start = None


def severity(path, body):
    """Select explicit migration levels from diagnostic intent, not stdout data."""
    lower = body.lower()
    if path.name == "trace.c" or path.name == "conn_bootstrap.c":
        return "DEBUG"
    if any(word in lower for word in ("warning", "warn:", "falling back",
                                      "retry", "not verified", "skipped", "skipping",
                                      "unavailable —", "reverting to")):
        return "WARN"
    if any(word in lower for word in ("failed", "fail:", "error", "cannot",
                                      "refus", "invalid", "too long", "exhaust",
                                      "loop", "could not", "not found",
                                      "bad ", "unsupported", "strerror",
                                      "st.msg", "st->msg", "cst.msg", "mst.msg",
                                      "out of memory", "oom", "unknown", "malformed",
                                      "unexpected", "unrecognised", "not supported",
                                      "not available", "not linked", "contradictory",
                                      " requires ", " needs ", "expected", "no source",
                                      "no local dest", "too many", ", err", "sqlite3_errmsg")):
        return "ERROR"
    return "INFO"


def _presentation_shape(literal):
    return ("\r" in literal or literal.count("\n") != 1
            or not literal.endswith("\n") or not literal.strip("\n "))


def _presentation_call(literal):
    lower = literal.lower()
    return _presentation_shape(literal) or lower.startswith("usage:") or any(
        word in lower for word in ("options:", "--help", "per-opcode rtt"))


def _replacement(path, text, span):
    start, end, prefix_end = span
    body = text[prefix_end:end - 1]
    format_prefix = re.match(r'\s*((?:"(?:\\.|[^"\\])*"\s*)+)', body)
    strings = re.findall(r'"((?:\\.|[^"\\])*)"',
                         format_prefix.group(1) if format_prefix else "")
    if _presentation_call("".join(strings)):
        return None
    macro = "BRIX_CLIENT_LOG" if "client" in path.relative_to(ROOT).parts else "BRIX_TOOL_LOG"
    return start, end, f'{macro}("{severity(path, body)}", {body})'


def _ensure_header(path, text):
    header = ROOT / "shared/observability/log_stdio.h"
    relative = Path(os.path.relpath(header, path.parent))
    include = f'#include "{relative}"'
    if include in text:
        return text
    position = text.find("#include")
    return text[:position] + include + "\n" + text[position:]


def migrate(path, text):
    """Replace full diagnostic records; return text and migration counts."""
    replacements = []
    preserved = 0
    for span in stderr_calls(text):
        replacement = _replacement(path, text, span)
        if replacement is None:
            preserved += 1
            continue
        replacements.append(replacement)
    for start, end, replacement in reversed(replacements):
        text = text[:start] + replacement + text[end:]
    if replacements:
        text = _ensure_header(path, text)
    return text, len(replacements), preserved


def _paths():
    roots = (ROOT / "client", ROOT / "tools", ROOT / "shared")
    paths = (path for root in roots for path in root.rglob("*.c"))
    return sorted(path for path in paths
                  if not any(part in ("tests", "bin") for part in path.parts)
                  and "unittest" not in path.name)


def _reclassify(path, text):
    pattern = re.compile(r'(BRIX_(?:CLIENT|TOOL)_LOG\()"INFO"(,.*?);', re.S)
    return pattern.sub(lambda match: match.group(1) + '"'
                       + severity(path, match.group(2)) + '"'
                       + match.group(2) + ';', text)


def _process(path, args):
    original = path.read_text()
    text, count, kept = migrate(path, original)
    if args.reclassify:
        text = _reclassify(path, text)
    text = re.sub(r'(BRIX_(?:CLIENT|TOOL)_LOG[^\n]*?)[ \t]+$',
                  r'\1', text, flags=re.M)
    if text != original and args.apply:
        path.write_text(text)
    return count, kept


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--reclassify", action="store_true")
    args = parser.parse_args()
    migrated = preserved = 0
    for path in _paths():
        count, kept = _process(path, args)
        migrated += count
        preserved += kept
    print(f"standalone logging: {migrated} records migrated; "
          f"{preserved} presentation calls preserved")


if __name__ == "__main__":
    main()
