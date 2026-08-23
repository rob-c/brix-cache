#!/usr/bin/env python3
#
# WHAT: Fail CI when the project's OWN namespace regresses to a pre-rebrand
#       spelling — server `xrootd_`/`XROOTD_`/`ngx_xrootd*`, client `xrdc_`/
#       `libxrdc`/bare-word `xrdc` — anywhere under src/, config, or client/.
#
# WHY:  The 2026-07-03 BriX symbol rebrand renamed the whole namespace to
#       `brix_`/`BRIX_`/`ngx_brix*`/`libbrix`. That was a one-shot mechanical
#       pass; nothing kept it from drifting back. It DID drift: P44 io_uring code
#       landed later carrying a stale `xrdc_aconn` in a comment (phase-88 §5
#       reconciliation, 2026-07-30). This guard is the standing backstop so a
#       reintroduced old token reddens the gate instead of silently accumulating.
#
# HOW:  Reuse the single source of truth — the rule table and EXCLUDE set in
#       tools/refactor/brix_rebrand.py — so the guard can never disagree with the
#       engine. Any file the engine WOULD still rewrite (i.e. a rule matches after
#       whitelisting the KEEP identity tokens) is a residual and fails the gate.
#       Mirrors tools/refactor/brix_verify.sh semantics in pure Python.
#
# USAGE:
#   tools/ci/check_brix_namespace.py        # check (CI mode); non-zero on residual

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "tools/refactor/brix_rebrand.py"

# KEEP tokens (module identity + on-disk cache sentinels) legitimately contain a
# post-`xrootd`/`xrdc` hyphen or char and must survive byte-for-byte. Strip them
# before scanning so they never count as residuals — same whitelist as the
# verifier's `keep_ident`.
_KEEP = re.compile(
    r"nginx-xrootd|ngx-xrootd-part|ngx-xrootd-lock|ngx-xrootd-evict-lock|nginx-xrootd-ckp-recovery"
)

# Scope -> (forbidden-token pattern, roots to scan). Matches brix_verify.sh.
_SCOPES = {
    "server": (re.compile(r"xrootd_|XROOTD_|ngx_xrootd"), ("src", "config")),
    "client": (re.compile(r"xrdc_|libxrdc|(?:^|[^A-Za-z0-9_])xrdc(?:[^A-Za-z0-9_]|$)"), ("client",)),
}


def _load_engine():
    spec = importlib.util.spec_from_file_location("brix_rebrand", ENGINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _iter_files(roots):
    for r in roots:
        base = ROOT / r
        if base.is_file():
            yield base
        if base.is_dir():
            yield from _files_below(base)


def _files_below(base):
    return (path for path in base.rglob("*") if path.is_file())


def residuals():
    engine = _load_engine()
    exclude = {str(ROOT / e) for e in engine.EXCLUDE}
    return [
        hit
        for scope, (pattern, roots) in _SCOPES.items()
        for path in _iter_files(roots)
        for hit in _file_residuals(engine, exclude, scope, pattern, path)
    ]


def _file_residuals(engine, exclude, scope, pattern, path):
    if str(path) in exclude or engine.is_binary(str(path)):
        return []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return []
    relative = str(path.relative_to(ROOT))
    return [
        (scope, relative, lineno, line.strip())
        for lineno, line in enumerate(text.splitlines(), 1)
        if pattern.search(_KEEP.sub("", line))
    ]


def main():
    hits = residuals()
    if hits:
        print("RESIDUAL pre-rebrand namespace tokens (see 2026-07-03-brix-symbol-rebrand.md):",
              file=sys.stderr)
        for scope, rel, lineno, line in hits[:50]:
            print(f"  [{scope}] {rel}:{lineno}: {line[:100]}", file=sys.stderr)
        return 1
    print("check_brix_namespace: OK (server + client namespace clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
