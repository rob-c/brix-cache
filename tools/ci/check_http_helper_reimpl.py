#!/usr/bin/env python3
#
# check_http_helper_reimpl.py — protocols must not regrow private copies of the
# shared HTTP helpers in src/core/http/.  Faithful Python port of the byte-for-byte
# verdict of tools/ci/check_http_helper_reimpl.py (kept as the CI / pre-push copy).
#
# WHAT: Fails (exit 1) when a protocol/observability handler contains one of the
#       idioms that historically preceded a private helper copy:
#         1. the raw headers_in scan loop (`&r->headers_in.headers.part`) —
#            that is brix_http_find_header()'s job;
#         2. precondition-header decision logic (reading
#            r->headers_in.if_match / if_none_match) — that is
#            brix_http_eval_preconditions() / _check_etag_preconditions()'s job
#            (the s3_eval_preconditions duplicate lived for a year);
#         3. hand-rolled ETag strings (printf'ing a "%lx-%llx"-shaped validator)
#            — that is brix_http_etag_str()'s job.
#
# WHY:  These duplications are invisible in review (each copy looks locally fine)
#       and dangerous in aggregate: conditionals gate overwrites and 304s, header
#       lookup feeds auth. One engine, one behaviour.
#
# HOW:  grep the idioms across the HTTP-consuming trees, drop comment lines,
#       subtract the ALLOWLIST of reviewed legitimate sites, fail on the rest.
#
# USAGE:
#   tools/ci/check_http_helper_reimpl.py    # exit 0 = clean, exit 1 = offender

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Trees that consume the shared HTTP helpers (the engine itself is exempt).
SCOPE = (
    "src/protocols",
    "src/observability",
    "src/net/ratelimit",
    "src/net/mirror",
    "src/net/httpguard",
    "src/fs/scan",
)

# --- ALLOWLIST: reviewed legitimate sites (file, keep sorted) ----------------
# A site belongs here only when it is an adapter over the shared helper or a
# fast-path presence check, NOT an independent decision engine.
ALLOWLIST = {
    # Presence-only fast path + If-None-Match:* exclusive-create flag; the
    # verdicts come from brix_http_eval_preconditions().
    "src/protocols/s3/conditional.c",
    # Forwarding proxy: iterates ALL request headers to relay them verbatim —
    # enumeration, not lookup.
    "src/protocols/webdav/proxy_request.c",
    # XrdHttp compat filter: enumerates headers to rewrite hop-by-hop fields.
    "src/protocols/webdav/xrdhttp_filter.c",
    # HTTP-TPC: enumerates the TransferHeader* prefix family — prefix
    # enumeration, not exact-name lookup.
    "src/protocols/webdav/tpc_headers.c",
    # S3 user metadata: enumerates the x-amz-meta-* prefix family.
    "src/protocols/s3/usermeta.c",
    # Shadow mirror: enumerates ALL request headers to replay them verbatim
    # (its former private find_header was folded into the shared helper).
    "src/net/mirror/http_mirror.c",
}

# (check name, extended regex) — matches the shell scan() invocations verbatim.
CHECKS = (
    # 1. Raw headers_in scan loop (brix_http_find_header's job).
    ("raw header scan", re.compile(r"&r->headers_in\.headers\.part")),
    # 2. Local precondition decisions (the shared evaluators' job).
    (
        "precondition logic",
        re.compile(
            r"headers_in\.(if_match|if_none_match|if_modified_since|if_unmodified_since)"
        ),
    ),
    # 3. Hand-rolled ETag validator strings (brix_http_etag_str's job).
    ("hand-rolled etag", re.compile(r'"\\?"?%l?lx-%l?lx')),
)

_HELP = "  → use the shared helper in src/core/http/ (or allowlist with a reason)"


def _is_comment_line(code: str) -> bool:
    """Drop comment continuations (`*`) and `//`/`/*` lines — the shell's
    `^\\S+:[0-9]+:\\s*(\\*|/\\*|//)` comment-marker filter applied to the code."""
    s = code.lstrip()
    return s.startswith(("*", "//", "/*"))


def _scan(root: Path, rx: re.Pattern) -> list[tuple[str, int, str]]:
    """grep -rnE rx across SCOPE --include='*.c'; raw (file, lineno, line) hits."""
    hits: list[tuple[str, int, str]] = []
    for base in SCOPE:
        d = root / base
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*.c")):
            rel = str(path.relative_to(root))
            for lineno, line in enumerate(
                path.read_text(errors="ignore").splitlines(), 1
            ):
                if rx.search(line):
                    hits.append((rel, lineno, line))
    return hits


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """(ok, messages): ok False with two-line stderr blocks per offending hit,
    mirroring the shell guard check-by-check across the scoped trees."""
    msgs: list[str] = []
    for name, rx in CHECKS:
        for rel, lineno, line in _scan(root, rx):
            if _is_comment_line(line) or rel in ALLOWLIST:
                continue
            msgs.append(f"REIMPLEMENTATION ({name}): {rel}:{lineno}:{line}\n{_HELP}")
    return (not msgs, msgs)


def main() -> int:
    # Run from the repo root so the scoped paths and the file column line up with
    # the shell's `cd "$(git rev-parse --show-toplevel)"`, regardless of cwd.
    os.chdir(ROOT)
    ok, msgs = run(ROOT)
    for m in msgs:
        print(m, file=sys.stderr)
    if not ok:
        print("check_http_helper_reimpl: FAIL", file=sys.stderr)
        return 1
    print("check_http_helper_reimpl: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
