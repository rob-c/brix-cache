#!/usr/bin/env python3
#
# check_auth_verdict_sentinel.py — enforce the C-3 auth-verdict discipline.
#
# WHAT: Fails (exit 1) if `ctx->login.auth_done = 1` — the flag that marks a
#       session AUTHENTICATED — is assigned anywhere outside the sanctioned
#       authentication setters.
#
# WHY:  The response helpers `brix_send_ok`, `brix_send_error` and
#       `BRIX_RETURN_ERR` all return `NGX_OK` (they mean "wire response queued /
#       handled", NOT "authenticated").  The authorization choke point
#       (src/protocols/root/handshake/policy.c) correctly gates on the VERDICT,
#       `login.auth_done` (with `logged_in`), never on a bare return code — so
#       the only way to forge an authenticated session is to set that flag from a
#       path that has not actually verified a credential.  Two historical bugs did
#       exactly this shape (the SSS deny→NULL-deref bypass, funnelled to
#       NGX_DONE; the proxy branch that gated on `logged_in`, an intermediate
#       step, not `auth_done`).  This guard keeps the setter surface small and
#       auditable: a new site that marks a session authenticated must live in an
#       auth handler (or the session login/bind path) and be reviewed there,
#       where the verified-success precondition is visible — it cannot appear in a
#       proxy/TPC/dispatch/op handler by accident.
#
# HOW:  grep the assignment across src/, drop comment/doc lines, and compare the
#       owning files against the sanctioned allowlist below.  Any other file
#       fails the check.
#
# USAGE:
#   tools/ci/check_auth_verdict_sentinel.py            # scan the real ./src tree
#   tools/ci/check_auth_verdict_sentinel.py <srcdir>   # scan a synthetic tree (tests)

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The verdict may be raised ONLY by a credential handler on its verified-success
# path, or by the session login/bind path (anonymous login; secondary-stream bind
# inherits the primary's already-verified state after a registry lookup).
# Paths are relative to SRCDIR.
ALLOW = {
    "auth/gsi/auth.c",
    "auth/gsi/token.c",
    "auth/host/auth.c",
    "auth/krb5/auth.c",
    "auth/pwd/auth.c",
    "auth/sss/auth_request.c",
    "auth/unix/auth.c",
    "protocols/root/session/login.c",
    "protocols/root/session/bind.c",
}

# Assignment to 1 (the "now authenticated" transition).  `= 0` resets are benign
# and not matched.  Tolerate arbitrary inner whitespace.
PATTERN = re.compile(r"login\.auth_done\s*=\s*1\s*;")


def _is_comment_line(line: str) -> bool:
    """Mirror the shell's `grep -vE '^[0-9]+:\\s*(\\*|//|/\\*)'` doc-line drop:
    a comment continuation (`*`) or a `//` / `/*` line."""
    s = line.lstrip()
    return s.startswith(("*", "//", "/*"))


def _scan(srcdir: Path) -> tuple[list[str], list[str]]:
    """(hits, violations) as paths relative to `srcdir`, sorted like the shell's
    `sort -u`.  A file is a hit when it holds at least one non-comment assignment
    of the verdict; a violation is a hit whose path is not in ALLOW."""
    hits: list[str] = []
    for path in sorted(srcdir.rglob("*.c"), key=lambda p: p.as_posix()):
        lines = path.read_text(errors="replace").splitlines()
        if not any(PATTERN.search(ln) and not _is_comment_line(ln) for ln in lines):
            continue
        hits.append(path.relative_to(srcdir).as_posix())
    violations = [f for f in hits if f not in ALLOW]
    return hits, violations


def _detail(srcdir: Path, rel: str) -> list[str]:
    """The shell's `grep -nE PATTERN | sed 's/^/    /'` for one file — every
    matching line (comments included, matching the shell here), 4-space indented."""
    lines = (srcdir / rel).read_text(errors="replace").splitlines()
    return [f"    {n}:{ln}" for n, ln in enumerate(lines, 1) if PATTERN.search(ln)]


def _format(srcdir: Path, argv0: str) -> tuple[bool, list[str]]:
    hits, violations = _scan(srcdir)
    if not violations:
        return True, [
            f"check_auth_verdict_sentinel: OK — {len(hits)} verdict setters, all sanctioned."
        ]

    out = [
        "check_auth_verdict_sentinel: FAIL — 'login.auth_done = 1' set outside the",
        "sanctioned authentication setters (C-3 verdict-sentinel discipline):",
    ]
    for v in violations:
        out.append(f"  {v}")
        out.extend(_detail(srcdir, v))
    out.append("")
    out.append("A session may be marked authenticated ONLY on a credential handler's")
    out.append("verified-success path (or the session login/bind path).  If this is a new")
    out.append(f"auth mechanism, add its file to ALLOW in {argv0} and prove the assignment sits")
    out.append("AFTER the credential is verified — never on an error/queued-response path.")
    return False, out


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Scan `root/src` (the real default) and return (ok, printable lines)."""
    return _format(root / "src", sys.argv[0])


def main() -> int:
    # Run from the repo root so the default `src` scan — and the paths reported —
    # line up regardless of cwd.
    os.chdir(ROOT)
    # Scan root defaults to the real src/, overridable for the guard's own tests.
    srcdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src")
    ok, lines = _format(srcdir, sys.argv[0])
    for line in lines:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
