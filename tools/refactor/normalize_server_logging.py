#!/usr/bin/env python3
"""Mechanically route nginx diagnostic calls through the BriX record adapter.

Preserve arguments, levels, control flow and nginx's formatting vocabulary.
The adapter itself is excluded because it owns the original nginx sinks.
"""

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "src/core/compat/log_event.h"
PATTERN = re.compile(r"\b(ngx_log_error|ngx_conf_log_error|ngx_log_debug[0-8])\s*\(")
TOKEN = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
                   r'\b(?:ngx_log_error|ngx_conf_log_error|ngx_log_debug[0-8])\s*\(',
                   re.S)


def normalize(text):
    """Replace call tokens only; leave comments, string literals and args intact."""
    count = 0

    def replace(match):
        nonlocal count
        value = match.group()
        if not PATTERN.fullmatch(value):
            return value
        name = value.split("(", 1)[0].strip()
        target = {"ngx_log_error": "BRIX_LOG",
                  "ngx_conf_log_error": "BRIX_CONF_LOG"}.get(name, "BRIX_LOG_DEBUG")
        count += 1
        return target + "("

    migrated = TOKEN.sub(replace, text)
    if count and '"core/compat/log_event.h"' not in migrated:
        first_include = migrated.find("#include")
        if first_include < 0:
            first_include = 0
        migrated = (migrated[:first_include]
                    + '#include "core/compat/log_event.h"\n'
                    + migrated[first_include:])
    return migrated, count


def _source_paths():
    for path in sorted((ROOT / "src").rglob("*")):
        if path != ADAPTER and path.suffix in (".c", ".h"):
            yield path


def _process(path, apply):
    text, count = normalize(path.read_text())
    if count and apply:
        path.write_text(text)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    total = 0
    files = 0
    for path in _source_paths():
        count = _process(path, args.apply)
        if count:
            files += 1
            total += count
    print(f"server logging: {total} calls in {files} files"
          + (" migrated" if args.apply else " require migration"))


if __name__ == "__main__":
    main()
