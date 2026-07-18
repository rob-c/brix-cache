#!/usr/bin/env bash
#
# check_auth_verdict_sentinel.sh — enforce the C-3 auth-verdict discipline.
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
#   tools/ci/check_auth_verdict_sentinel.sh            # scan the real ./src tree
#   tools/ci/check_auth_verdict_sentinel.sh <srcdir>   # scan a synthetic tree (tests)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Scan root — defaults to the real src/, overridable for the guard's own tests.
SRCDIR="${1:-src}"

# The verdict may be raised ONLY by a credential handler on its verified-success
# path, or by the session login/bind path (anonymous login; secondary-stream bind
# inherits the primary's already-verified state after a registry lookup).
# Paths are relative to SRCDIR.
ALLOW=(
  "auth/gsi/auth.c"
  "auth/gsi/token.c"
  "auth/host/auth.c"
  "auth/krb5/auth.c"
  "auth/pwd/auth.c"
  "auth/sss/auth_request.c"
  "auth/unix/auth.c"
  "protocols/root/session/login.c"
  "protocols/root/session/bind.c"
)

# Assignment to 1 (the "now authenticated" transition).  `= 0` resets are benign
# and not matched.  Tolerate arbitrary inner whitespace.
PATTERN='login\.auth_done[[:space:]]*=[[:space:]]*1[[:space:]]*;'

# Collect the files that assign the verdict, ignoring comment / doc-block lines.
# Paths are emitted relative to SRCDIR for comparison against ALLOW.
mapfile -t hits < <(
  grep -rlnE "$PATTERN" "$SRCDIR" --include=*.c 2>/dev/null | sort -u | while read -r f; do
    # Only count a real code assignment (strip //, /* */ and ' * ' doc lines).
    if grep -nE "$PATTERN" "$f" \
         | grep -vE '^[0-9]+:[[:space:]]*(\*|//|/\*)' >/dev/null; then
      echo "${f#"$SRCDIR"/}"
    fi
  done
)

violations=()
for f in "${hits[@]}"; do
  ok=0
  for a in "${ALLOW[@]}"; do
    [ "$f" = "$a" ] && { ok=1; break; }
  done
  [ "$ok" -eq 0 ] && violations+=("$f")
done

if [ "${#violations[@]}" -gt 0 ]; then
  echo "check_auth_verdict_sentinel: FAIL — 'login.auth_done = 1' set outside the"
  echo "sanctioned authentication setters (C-3 verdict-sentinel discipline):"
  for v in "${violations[@]}"; do
    echo "  $v"
    grep -nE "$PATTERN" "$SRCDIR/$v" | sed 's/^/    /'
  done
  echo
  echo "A session may be marked authenticated ONLY on a credential handler's"
  echo "verified-success path (or the session login/bind path).  If this is a new"
  echo "auth mechanism, add its file to ALLOW in $0 and prove the assignment sits"
  echo "AFTER the credential is verified — never on an error/queued-response path."
  exit 1
fi

echo "check_auth_verdict_sentinel: OK — ${#hits[@]} verdict setters, all sanctioned."
