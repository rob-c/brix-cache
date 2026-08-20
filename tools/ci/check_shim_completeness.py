#!/usr/bin/env python3
#
# WHAT: Fail CI when a §10.2 shim in tests/ stops exposing a name it exposed
#       before its body was moved into the package.  (Guard #3,
#       testsuite-modernization-plan §12 / TS-3.)
#
# WHY:  the migration's core promise is that ~900 import sites keep working
#       untouched: `import settings` must yield the same names after the body
#       moves as before.  A missing name is not a test failure somewhere — it
#       is an AttributeError in whichever of the 690 dependents happens to run
#       first, at whatever time of night that is.  Aliasing is only safe if
#       completeness is machine-checked, per phase, forever.
#
# HOW:  `docs/refactor/testsuite-shim-baseline.json` freezes, per shimmed
#       module, the public surface it had while still a flat file (captured
#       from the TS-0 inventory at the moment of shimming).  This guard
#       imports each shim by its FLAT name — exactly as a dependent does —
#       and fails on any baseline name the imported module does not expose.
#       Extra names are fine (surface may grow); missing names never are.
#
#       `--freeze <module>` adds a module to the baseline from the current
#       TS-0 inventory. It refuses to overwrite an existing entry: the
#       baseline is append-only, so a phase cannot make itself pass by
#       lowering the bar. Ratchet direction is enforced by
#       check_ratchet_monotonic.py like every other frozen list.
#
# USAGE:
#   tools/ci/check_shim_completeness.py            # non-zero exit on violation
#   tools/ci/check_shim_completeness.py --freeze settings

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
SRC = ROOT / "brixtest" / "src"
BASELINE = ROOT / "docs/refactor/testsuite-shim-baseline.json"
INVENTORY = ROOT / "docs/refactor/testsuite-surface-inventory.json"

_BUCKETS = ("functions", "classes", "constants", "variables")

# Import the shim by its flat name in a child process and report what it
# exposes — the dependent's-eye view, side effects contained.
#
# `dir()`, not `vars()`: a module that splits into a package cannot re-export
# its *mutable* globals truthfully — a plain `from … import _worker_singleton`
# freezes the value that global had at import time while the real one is
# rebound behind it.  The honest form is a module `__getattr__`, which serves
# `from x import y` and `x.y` alike but never appears in `__dict__`.  Probing
# with `vars()` would have rejected the truthful spelling and passed the lie.
#
# `import_module`, not `__import__`: the first shims were all top-level, but
# the stub servers live in `tests/lib/`, and `__import__("lib.tokenconf")`
# hands back the `lib` package — whose `dir()` is empty, so every baseline
# name would read as dropped.
_PROBE = r"""
import importlib, json, sys
sys.path.insert(0, %(tests)r)
sys.path.insert(0, %(src)r)
mod = importlib.import_module(%(name)r)
print(json.dumps(sorted(dir(mod))))
"""


def _exposed_names(module: str) -> list:
    code = _PROBE % {"tests": str(TESTS), "src": str(SRC), "name": module}
    proc = subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            "check_shim_completeness: cannot import shim %r:\n%s"
            % (module, proc.stderr.strip()))
    return json.loads(proc.stdout)


def _baseline() -> dict:
    if not BASELINE.is_file():
        return {}
    return json.loads(BASELINE.read_text())


def freeze(module: str) -> int:
    baseline = _baseline()
    if module in baseline:
        print("check_shim_completeness: %r is already frozen — the baseline is "
              "append-only (delete the entry by hand only when retiring the "
              "shim at TS-7)" % module)
        return 1
    inventory = json.loads(INVENTORY.read_text())["surface"]
    if module not in inventory:
        print("check_shim_completeness: %r is not in the TS-0 inventory" % module)
        return 1
    entry = inventory[module]
    names = sorted({n for bucket in _BUCKETS for n in entry.get(bucket, [])})
    baseline[module] = names
    BASELINE.write_text(json.dumps(baseline, indent=1, sort_keys=True) + "\n")
    print("check_shim_completeness: froze %r (%d names)" % (module, len(names)))
    return 0


def run() -> tuple[bool, list]:
    baseline = _baseline()
    failures: list = []
    for module in sorted(baseline):
        exposed = set(_exposed_names(module))
        missing = [n for n in baseline[module] if n not in exposed]
        if missing:
            failures.append(
                "FAIL shim %s drops %d name(s) it used to export: %s"
                % (module, len(missing), ", ".join(missing[:10])
                   + (" …" if len(missing) > 10 else "")))
    return not failures, failures


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", metavar="MODULE",
                        help="add MODULE to the baseline from the TS-0 inventory")
    args = parser.parse_args(argv)
    if args.freeze:
        return freeze(args.freeze)
    baseline = _baseline()
    if not baseline:
        print("check_shim_completeness: OK (no shims frozen yet)")
        return 0
    ok, failures = run()
    for line in failures:
        print(line)
    if ok:
        print("check_shim_completeness: OK (%d shim(s), every baseline name "
              "still exported)" % len(baseline))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
