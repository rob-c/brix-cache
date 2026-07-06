#!/bin/sh
# check_man.sh — flag-drift guard for the brix client man pages.
#
# WHAT: For each tool with a man page, every --flag token that appears in
#       `<tool> --help` must also appear somewhere in the corresponding man page
#       (after roff-escape normalization: \- → -).  Also fails if any page
#       contains a /home/ path (developer-machine leak guard).
# WHY:  Prevents man pages silently falling behind the implementation.
# HOW:  POSIX sh; only grep/sed/mktemp; no fleet or server required.
#       Missing binaries are skipped with a notice (not a failure).
#
# Usage:  bash man/check_man.sh            normal check
#         bash man/check_man.sh --self-check  prove failure detection works

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_DIR="$(dirname "$SCRIPT_DIR")"
BINDIR="$CLIENT_DIR/bin"
MANDIR="$SCRIPT_DIR"
ALLOWLIST="$MANDIR/check_man_allowlist.txt"
FAILED=0
SELF_CHECK=0

for _arg; do
    case "$_arg" in
        --self-check) SELF_CHECK=1 ;;
    esac
done

# ---------------------------------------------------------------------------
# strip_roff_page FILE
#   Emit the page with roff hyphen/font escapes stripped so that
#   "\-\-max\-stall" becomes "--max-stall" and grep finds it cleanly.
# ---------------------------------------------------------------------------
strip_roff_page() {
    sed 's/\\-/-/g; s/\\f[BIPR]//g; s/\\f([A-Z][A-Z]//g' "$1"
}

# ---------------------------------------------------------------------------
# is_allowlisted TOOL FLAG
#   Returns 0 (true) if this (tool, flag) pair appears in the allowlist.
#   Allowlist format: one entry per line, "TOOL FLAG" or "* FLAG".
# ---------------------------------------------------------------------------
is_allowlisted() {
    local _tool="$1" _flag="$2"
    [ -f "$ALLOWLIST" ] || return 1
    grep -qE "^(\*|$_tool)[[:space:]]+$(printf '%s' "$_flag" | sed 's/[.[\*^$]/\\&/g')([[:space:]]|$)" \
        "$ALLOWLIST" 2>/dev/null
}

# ---------------------------------------------------------------------------
# check_tool_page TOOL MANPAGE BINARY
#   Extract --long-flags from BINARY --help; verify each appears in MANPAGE.
#   Sets FAILED (global) for each missing flag.
# ---------------------------------------------------------------------------
check_tool_page() {
    local _tool="$1" _page="$2" _bin="$3"
    local _help _flags _norm _flag

    # --help may exit nonzero; capture stdout + stderr
    _help=$("$_bin" --help 2>&1 || true)

    # extract --word long options only
    _flags=$(printf '%s\n' "$_help" | grep -oE -- '--[a-z][a-z-]+' | sort -u) || true
    [ -n "$_flags" ] || return 0

    # normalize roff escapes in the page for plain-text searching
    _norm=$(strip_roff_page "$_page")

    for _flag in $_flags; do
        is_allowlisted "$_tool" "$_flag" && continue
        printf '%s\n' "$_norm" | grep -qF -- "$_flag" && continue
        printf 'FAIL [%s] flag %s not found in %s\n' "$_tool" "$_flag" "$_page" >&2
        FAILED=$((FAILED + 1))
    done
}

# ---------------------------------------------------------------------------
# check_no_home PAGE
#   Fails if the page source contains a literal /home/ path.
# ---------------------------------------------------------------------------
check_no_home() {
    local _page="$1"
    if grep -qF '/home/' "$_page" 2>/dev/null; then
        printf 'FAIL [%s] contains a /home/ path (developer-machine leak)\n' \
            "$(basename "$_page")" >&2
        FAILED=$((FAILED + 1))
    fi
}

# ===========================================================================
# --self-check: prove the guard catches a missing flag
# ===========================================================================
if [ "$SELF_CHECK" -eq 1 ]; then
    _tmpdir=$(mktemp -d)

    # fake binary that outputs a sentinel flag not in the fake page
    cat > "$_tmpdir/xrdcp-selfcheck" <<'FAKE_BIN'
#!/bin/sh
echo "usage: test [--zz-fake-self-check-sentinel]"
FAKE_BIN
    chmod +x "$_tmpdir/xrdcp-selfcheck"

    # fake page with no mention of that flag
    cat > "$_tmpdir/xrdcp-selfcheck.1" <<'FAKE_MAN'
.TH TEST 1
.SH NAME
test \- self-check sentinel page
.SH DESCRIPTION
No flags documented here.
FAKE_MAN

    # run the check against the synthetic setup; it MUST detect the miss
    _save_failed=$FAILED
    BINDIR="$_tmpdir"
    MANDIR="$_tmpdir"
    ALLOWLIST="/dev/null"
    check_tool_page "xrdcp-selfcheck" "$_tmpdir/xrdcp-selfcheck.1" \
        "$_tmpdir/xrdcp-selfcheck" 2>/dev/null
    if [ "$FAILED" -le "$_save_failed" ]; then
        printf 'ERROR: self-check did not detect the missing flag\n' >&2
        rm -rf "$_tmpdir"
        exit 1
    fi

    # also confirm /home/ detection
    _save_failed=$FAILED
    printf '.SH DESCRIPTION\nSee /home/user/.xrdrc\n' > "$_tmpdir/home_test.7"
    check_no_home "$_tmpdir/home_test.7"
    if [ "$FAILED" -le "$_save_failed" ]; then
        printf 'ERROR: self-check did not detect /home/ leak\n' >&2
        rm -rf "$_tmpdir"
        exit 1
    fi

    printf 'self-check: failure detection confirmed (flag miss + /home/ leak both caught)\n'
    rm -rf "$_tmpdir"
    exit 0
fi

# ===========================================================================
# Normal mode: run all checks
# ===========================================================================

# 1. /home/ leak check across all pages
for _page in "$MANDIR"/*.1 "$MANDIR"/*.7; do
    [ -f "$_page" ] || continue
    check_no_home "$_page"
done

# 2. Per-tool flag-drift check
for _page in "$MANDIR"/*.1; do
    [ -f "$_page" ] || continue

    # Skip .so link pages — they redirect to another page that holds the content.
    case "$(head -1 "$_page")" in .so*) continue ;; esac

    _base=$(basename "$_page" .1)
    _bin="$BINDIR/$_base"
    [ -x "$_bin" ] || {
        printf 'SKIP %s (no binary at %s)\n' "$_base" "$_bin"
        continue
    }
    check_tool_page "$_base" "$_page" "$_bin"
done

if [ "$FAILED" -gt 0 ]; then
    printf 'check_man: FAILED (%d issue(s))\n' "$FAILED" >&2
    exit 1
fi
printf 'check_man: ALL PASS\n'
