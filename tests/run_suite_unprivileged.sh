#!/usr/bin/env bash
#
# run_suite_unprivileged.sh — run the suite with TEST USER == SERVER USER.
#
# WHY THIS EXISTS
#   The fleet's nginx configs carry no `user` directive.  Run the harness as root
#   and every master drops its workers to `nobody`, while the harness creates the
#   export roots as root — so a worker cannot write its own export (403 on every
#   PUT/upload), and cannot chmod a file the test process created.  That second
#   one is NOT fixable with permission bits: chmod(2) requires OWNERSHIP, so the
#   xrdcl chmod/stat parity suites fail however open the mode is.
#
#   The historical workaround is brix-test-nginx injecting `user root;`
#   (TESTING.md §4b) so workers stay root.  That trades one distortion for
#   another: root bypasses every permission check, so the suite stops testing the
#   authorization semantics it exists to verify — and it cannot be applied to the
#   reference xrootd, which REFUSES to run as the superuser ("Security reasons
#   prohibit running as superuser").  Our side becomes root, stock stays `nobody`,
#   and the two diverge *by construction* in exactly the parity tests.
#
#   Running everything as ONE unprivileged user deletes the whole class: pytest,
#   the nginx master+workers and the reference xrootd all share an identity, so
#   ownership and permission behaviour is REAL rather than root-bypassed.  This is
#   the configuration upstream validated (the phase-79 burndown's 6977-pass run).
#
# WHY A COPY OF THE CHECKOUT (root mode)
#   The canonical checkout may live somewhere the test user cannot reach — on this
#   box /root, mode 0750, which is exactly why TESTING.md §6c concluded "running
#   the whole fleet as root [is] necessary here".  Rather than open a path into
#   root's home (an ACL/`o+x` on /root would grant traversal to a real account —
#   and `nobody` in particular is shared by other daemons, so that would widen far
#   beyond this suite), we SYNC the tree to a neutral location the user owns.
#   /root keeps its 0750 untouched.  The trade-off is honest: you are validating a
#   copy, so the sync happens on every run and --delete keeps it exact.
#
# TWO MODES, AUTO-DETECTED
#   unprivileged   You are already a normal user -> run in place, no copy, no
#                  sudo, nothing to grant.  This is the "single user" mode: a
#                  developer who CANNOT sudo runs exactly what root runs.
#   root           Sync the checkout to $BRIX_TEST_TREE, hand it plus the test
#                  root to $BRIX_TEST_USER, and re-exec there as that user.  Root
#                  only does what a normal user cannot do for itself: clear a
#                  root-owned fleet off the fixed ports and chown the trees.
#
# USAGE
#   tests/run_suite_unprivileged.sh --fast
#   BRIX_TEST_USER=nobody tests/run_suite_unprivileged.sh --fast
#   BRIX_TEST_TREE=/srv/brix-test tests/run_suite_unprivileged.sh --fast
#
# All other arguments pass through to run_suite.sh verbatim.
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A dedicated account, not `nobody`: nothing else on the box runs as it, so the
# trees we hand it are not implicitly shared with unrelated daemons.  `nobody`
# still works (BRIX_TEST_USER=nobody) — with the neutral copy there is no /root
# exposure either way — but it has no writable home and is shared, so it is not
# the default.
BRIX_TEST_USER="${BRIX_TEST_USER:-brixtest}"
BRIX_TEST_TREE="${BRIX_TEST_TREE:-/srv/brix-test}"

# Per-user test root, deliberately NOT the root harness's /tmp/xrd-test: the two
# must never share file ownership, so a root run and a user run cannot corrupt
# each other's PKI/exports.  (They still share the fixed ports — see
# _clear_foreign_fleet.)
TEST_ROOT_DEFAULT="/tmp/xrd-test-${BRIX_TEST_USER}"

log() { printf '[unpriv] %s\n' "$*"; }
die() { printf '[unpriv] ERROR: %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# nginx selection                                                              #
# --------------------------------------------------------------------------- #
# Respect an explicit choice; otherwise prefer the wrapper that drives the SYSTEM
# nginx.  Note the wrapper only injects `user root;` when it IS root — run
# unprivileged it is a plain module-loading shim, so workers stay this user, which
# is the entire point of this script.
_pick_nginx() {
    if   [ -n "${NGINX_BIN:-}" ];      then printf '%s' "$NGINX_BIN"
    elif [ -n "${TEST_NGINX_BIN:-}" ]; then printf '%s' "$TEST_NGINX_BIN"
    elif [ -x /usr/local/bin/brix-test-nginx ]; then printf '/usr/local/bin/brix-test-nginx'
    else printf '/tmp/nginx-1.28.3/objs/nginx'
    fi
}

# --------------------------------------------------------------------------- #
# Fixed-port hand-off                                                          #
# --------------------------------------------------------------------------- #
# The fleet binds a fixed port list, so a root-owned fleet and a user-owned fleet
# cannot coexist.  Worse, the user's start-all CANNOT reap a root-owned nginx
# (force_stop_nginx would have to kill another uid's process), so a leftover root
# fleet becomes an unfixable "Address already in use".  Clear it here, while we
# still have the privileges to do it.
_clear_foreign_fleet() {
    log "clearing any root-owned fleet off the fixed ports"
    TEST_ROOT=/tmp/xrd-test "$REPO/tests/brutal_teardown.sh" >/dev/null 2>&1 || true
}

# --------------------------------------------------------------------------- #
# Entry                                                                        #
# --------------------------------------------------------------------------- #

NGINX_PICK="$(_pick_nginx)"

if [ "$(id -u)" != "0" ]; then
    # ---- single-user mode: already unprivileged, run in place --------------- #
    # No copy: this checkout is one we can already read, which is the normal case
    # for a developer running out of their own home.
    TEST_ROOT="${TEST_ROOT:-$TEST_ROOT_DEFAULT}"
    mkdir -p "$TEST_ROOT" || die "cannot create TEST_ROOT=$TEST_ROOT"
    [ -w "$TEST_ROOT" ] || die "TEST_ROOT=$TEST_ROOT is not writable by $(id -un)"
    [ -x "$NGINX_PICK" ] || die "nginx not executable by $(id -un): $NGINX_PICK"
    export TEST_ROOT
    export NGINX_BIN="$NGINX_PICK" TEST_NGINX_BIN="$NGINX_PICK"
    # The tree may be read-only to us: keep pytest's cache (--lf needs it) and the
    # .pyc files out of it.  PYTEST_ADDOPTS reaches every lane and every xdist
    # worker without fighting run_suite.sh's `--` argument handling.
    export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} -o cache_dir=$TEST_ROOT/.pytest_cache"
    export PYTHONDONTWRITEBYTECODE=1
    log "user=$(id -un) uid=$(id -u)  tree=$REPO"
    log "TEST_ROOT=$TEST_ROOT  nginx=$NGINX_PICK"
    log "test user == server user: permission semantics are REAL (no root bypass)"
    exec "$REPO/tests/run_suite.sh" "$@"
fi

# ---- root mode: sync to a neutral tree, hand over, drop --------------------- #
id "$BRIX_TEST_USER" >/dev/null 2>&1 \
    || die "no such user: $BRIX_TEST_USER (create it, e.g.: useradd -r -m -d /var/lib/$BRIX_TEST_USER $BRIX_TEST_USER)"
[ "$(id -u "$BRIX_TEST_USER")" != "0" ] || die "BRIX_TEST_USER must not be root"
command -v rsync >/dev/null 2>&1 || die "rsync not found (needed to sync the checkout)"

TEST_ROOT="${TEST_ROOT:-$TEST_ROOT_DEFAULT}"
log "target user: $BRIX_TEST_USER (uid $(id -u "$BRIX_TEST_USER"))"

_clear_foreign_fleet

# Sync the checkout to somewhere the user can actually reach.  --delete so a
# removed/renamed file cannot linger and silently pass a stale test; .git is
# excluded (no test reads it, and it is the bulk of the tree).  Build outputs are
# excluded too — they are rebuilt/installed separately and are large.
log "syncing checkout -> $BRIX_TEST_TREE (/root is left untouched)"
mkdir -p "$BRIX_TEST_TREE"
rsync -a --delete \
    --exclude '.git/' \
    --exclude 'build/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    "$REPO/" "$BRIX_TEST_TREE/"
chown -R "$BRIX_TEST_USER" "$BRIX_TEST_TREE"
chmod 0755 "$BRIX_TEST_TREE"
log "tree owned by $BRIX_TEST_USER"

# The user owns its whole test tree: exports, PKI, logs, tmp — so nginx workers
# and the reference xrootd (which runs un-shimmed as this user) can write what
# they must.
mkdir -p "$TEST_ROOT" "$TEST_ROOT/home"
chown -R "$BRIX_TEST_USER" "$TEST_ROOT"
chmod 0755 "$TEST_ROOT"
log "TEST_ROOT=$TEST_ROOT owned by $BRIX_TEST_USER"

[ -r "$NGINX_PICK" ] || die "nginx not readable: $NGINX_PICK"
runuser -u "$BRIX_TEST_USER" -- test -x "$NGINX_PICK" \
    || die "'$BRIX_TEST_USER' cannot execute $NGINX_PICK"
log "nginx=$NGINX_PICK"
log "dropping to '$BRIX_TEST_USER' — test user == server user from here on"

# HOME must exist and be writable: `nobody`'s passwd home is / and Python/tools
# will try to write there.  Re-exec the COPY, not $REPO — the user cannot read
# $REPO, which is the whole reason for the sync.
exec runuser -u "$BRIX_TEST_USER" -- env \
    HOME="$TEST_ROOT/home" \
    TEST_ROOT="$TEST_ROOT" \
    NGINX_BIN="$NGINX_PICK" \
    TEST_NGINX_BIN="$NGINX_PICK" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} -o cache_dir=$TEST_ROOT/.pytest_cache" \
    BRIX_TEST_USER="$BRIX_TEST_USER" \
    "$BRIX_TEST_TREE/tests/run_suite_unprivileged.sh" "$@"
