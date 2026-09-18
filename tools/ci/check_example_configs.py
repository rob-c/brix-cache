#!/usr/bin/env python3
"""Every shipped example nginx config must parse — phase-115 W1.3 guard.

WHAT: renders each example (compose stacks, *.conf.example, and the ```nginx
      fences of README / the configuration references) into a scratch tree
      via tools/ci/example_config_lib.py and runs `nginx -t` on it; every
      `brix_*` directive used anywhere in the docs must also be one the module
      registers.

WHY:  README carried directives that had not existed for months
      (`brix_gridftp_export`, `brix_cache_origin`, `brix_webdav_proxy_upstream`)
      because nothing executed the examples. An operator copying them got an
      "unknown directive" on first boot.

HOW:  `nginx -t` needs the built binary (TEST_NGINX_BIN or NGINX_SRC/objs/nginx),
      so the workflow step runs after the build. Without a binary the guard
      falls back to the directive-name check alone and says so. Doc fences
      outside STRICT_DOCS get the name check only; their shape is prose.

Exit 0 = all examples parse; 1 = a failure; 2 = usage/environment.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import example_config_lib as lib  # noqa: E402


def _examples(root: Path):
    yield from lib.iter_files(root)
    yield from lib.iter_fences(root)


def _check_names(example, known: set[str], failures: list[str]) -> None:
    if lib.marked_skip(example.text):
        return
    unknown = sorted(lib.directive_names(example.text) - known)
    if unknown:
        failures.append(f"{example.source}: unknown directive(s) {', '.join(unknown)}")


def _check_parse(example, scratch: Path, binary: str, failures: list[str]) -> bool:
    reason = lib.unsupported_reason(example, binary)
    if reason:
        print(f"UNSUPPORTED {reason}")
        return False
    rendered = lib.render(example, scratch)
    ok, err = lib.nginx_t(rendered, binary)
    if ok:
        return True
    limit = lib.host_limitation(err)
    if limit:
        print(f"UNSUPPORTED {example.source}: {limit}")
        return False
    failures.append(f"{example.source}: nginx -t failed\n    {err.replace(chr(10), chr(10) + '    ')}")
    return True


def _check_all(examples, known, binary, have_bin, keep) -> tuple[list[str], int]:
    """Name-check every example and `nginx -t` the strict ones; (failures, parsed)."""
    failures: list[str] = []
    parsed = 0
    scratch = Path(tempfile.mkdtemp(prefix="brix-example-configs-"))
    try:
        for e in examples:
            _check_names(e, known, failures)
            if have_bin and e.strict and e.context != "skip":
                parsed += _check_parse(e, scratch, binary, failures)
    finally:
        if keep:
            print(f"scratch tree kept at {scratch}")
        else:
            shutil.rmtree(scratch, ignore_errors=True)
    return failures, parsed


def _parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=lib.ROOT)
    ap.add_argument("--nginx", default=None, help="nginx binary (default: TEST_NGINX_BIN / NGINX_SRC)")
    ap.add_argument("--list", action="store_true", help="list discovered examples and their contexts")
    ap.add_argument("--only", help="substring filter on example source")
    ap.add_argument("--keep", action="store_true", help="keep the scratch tree (printed)")
    return ap.parse_args(argv)


def _selected(root: Path, only: str | None):
    return [e for e in _examples(root) if not only or only in e.source]


def _list(examples) -> int:
    for e in examples:
        print(f"{e.context:14} {'strict' if e.strict else 'names ':6} {e.source}")
    return 0


def _binary(requested: str | None) -> tuple[str, bool]:
    """(nginx binary path, whether it exists); a missing binary degrades to names only."""
    binary = requested or lib.nginx_bin()
    have_bin = shutil.which(binary) is not None or Path(binary).exists()
    if not have_bin:
        print(f"check_example_configs: no nginx binary at {binary}; directive-name check only",
              file=sys.stderr)
    return binary, have_bin


def main(argv=None) -> int:
    args = _parse_args(argv)
    examples = _selected(args.root, args.only)
    if args.list:
        return _list(examples)
    binary, have_bin = _binary(args.nginx)
    failures, parsed = _check_all(examples, lib.registered_directives(), binary, have_bin, args.keep)

    for f in failures:
        print(f"FAIL {f}")
    print(f"check_example_configs: {len(examples)} examples, {parsed} parsed with nginx -t, "
          f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
