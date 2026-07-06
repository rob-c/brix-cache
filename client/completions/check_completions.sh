#!/bin/sh
# check_completions.sh — flag-drift and security guard for brix completions.
#
# WHAT: (1) Every --flag from each tool's --help must appear in brix-tools.bash
#           or _brix-client (same flag-drift idea as man/check_man.sh).
#       (2) Neither completion file may contain `eval` or a backtick command
#           substitution that interpolates the current completion word ($cur /
#           $COMP_WORDS / $COMP_CWORD) — a completion-injection risk.
#       (3) brix-tools.bash passes `bash -n` syntax check.
#       (4) _brix-client passes `zsh -n` syntax check if zsh is available;
#           otherwise prints a notice and skips.
# WHY:  Completions that suggest wrong flags confuse users; injection patterns
#       in completions are a security risk.
# HOW:  POSIX sh; only grep/sed/mktemp; no fleet or server required.
#
# Usage:  bash completions/check_completions.sh
#         bash completions/check_completions.sh --self-check

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_DIR="$(dirname "$SCRIPT_DIR")"
BINDIR="$CLIENT_DIR/bin"
BASH_COMP="$SCRIPT_DIR/brix-tools.bash"
ZSH_COMP="$SCRIPT_DIR/_brix-client"
FAILED=0
SELF_CHECK=0

for _arg; do
    case "$_arg" in
        --self-check) SELF_CHECK=1 ;;
    esac
done

# ---------------------------------------------------------------------------
# check_security FILE
#   Fails if FILE contains `eval` or a backtick that interpolates the current
#   completion word.
# ---------------------------------------------------------------------------
check_security() {
    local _file="$1"
    local _base
    _base=$(basename "$_file")

    # Rule 1: no eval statement
    if grep -n '\beval\b' "$_file" >/dev/null 2>&1; then
        printf 'FAIL [%s] contains eval (completion-injection risk)\n' "$_base" >&2
        FAILED=$((FAILED + 1))
    fi

    # Rule 2: no backtick that contains user-supplied completion state
    # Dangerous pattern: `cmd $cur` or `cmd ${COMP_WORDS...}` or `cmd $COMP_CWORD`
    # NOTE: $(...) command substitution is NOT caught by this rule (only backticks are,
    # per spec). The one legit $(...) use with compgen is safe: it expands the word
    # list (not $cur), so injection requires the user to supply a malicious word,
    # which is prevented by the compgen builtin itself.
    if grep -En '`[^`]*(\$cur|\$\{?COMP_WORDS|\$\{?COMP_CWORD)[^`]*`' \
            "$_file" >/dev/null 2>&1; then
        printf 'FAIL [%s] contains backtick-on-current-word (injection risk)\n' \
            "$_base" >&2
        FAILED=$((FAILED + 1))
    fi
}

# ---------------------------------------------------------------------------
# check_flag_coverage TOOL BINARY BASH_FILE ZSH_FILE
#   Extract --flags from BINARY --help; verify each appears in BASH_FILE or
#   ZSH_FILE (either is sufficient).
# ---------------------------------------------------------------------------
check_flag_coverage() {
    local _tool="$1" _bin="$2" _bash="$3" _zsh="$4"
    local _help _flags _flag _found

    [ -x "$_bin" ] || {
        printf 'SKIP %s (no binary at %s)\n' "$_tool" "$_bin"
        return 0
    }

    _help=$("$_bin" --help 2>&1 || true)
    _flags=$(printf '%s\n' "$_help" | grep -oE -- '--[a-z][a-z-]+' | sort -u) || true
    [ -n "$_flags" ] || return 0

    for _flag in $_flags; do
        case "$_flag" in --help) continue ;; esac  # --help is implicit

        _found=0
        grep -qF -- "$_flag" "$_bash" 2>/dev/null && _found=1
        [ "$_found" -eq 0 ] && grep -qF -- "$_flag" "$_zsh" 2>/dev/null && _found=1

        if [ "$_found" -eq 0 ]; then
            printf 'FAIL [%s] flag %s not in completions\n' "$_tool" "$_flag" >&2
            FAILED=$((FAILED + 1))
        fi
    done
}

# ---------------------------------------------------------------------------
# check_syntax FILE SHELL
#   Run SHELL -n FILE; accumulate failure.
# ---------------------------------------------------------------------------
check_syntax() {
    local _file="$1" _shell="$2"
    if ! "$_shell" -n "$_file" 2>/dev/null; then
        printf 'FAIL [%s] syntax error (via %s -n)\n' "$(basename "$_file")" "$_shell" >&2
        FAILED=$((FAILED + 1))
    fi
}

# ===========================================================================
# --self-check: prove security and flag-drift detection work
# ===========================================================================
if [ "$SELF_CHECK" -eq 1 ]; then
    _tmpdir=$(mktemp -d)

    # --- security: eval detection ---
    printf 'eval "complete -F _x x"\n' > "$_tmpdir/eval_test.bash"
    _save=$FAILED
    check_security "$_tmpdir/eval_test.bash"
    [ "$FAILED" -gt "$_save" ] || {
        printf 'ERROR: self-check did not detect eval\n' >&2
        rm -rf "$_tmpdir"; exit 1
    }

    # --- security: backtick-on-current-word detection ---
    printf '_f() { COMPREPLY=(`grep "$cur" /etc/hosts`); }\n' \
        > "$_tmpdir/backtick_test.bash"
    _save=$FAILED
    check_security "$_tmpdir/backtick_test.bash"
    [ "$FAILED" -gt "$_save" ] || {
        printf 'ERROR: self-check did not detect backtick-on-current-word\n' >&2
        rm -rf "$_tmpdir"; exit 1
    }

    # --- flag drift: missing flag detection ---
    cat > "$_tmpdir/xrdcp-sc" <<'FAKE_BIN'
#!/bin/sh
echo "usage: test [--zz-fake-self-check-sentinel]"
FAKE_BIN
    chmod +x "$_tmpdir/xrdcp-sc"
    printf '# empty completion\n' > "$_tmpdir/empty.bash"
    printf '# empty zsh\n'       > "$_tmpdir/empty.zsh"
    _save=$FAILED
    check_flag_coverage "xrdcp-sc" "$_tmpdir/xrdcp-sc" \
        "$_tmpdir/empty.bash" "$_tmpdir/empty.zsh"
    [ "$FAILED" -gt "$_save" ] || {
        printf 'ERROR: self-check did not detect missing flag in completions\n' >&2
        rm -rf "$_tmpdir"; exit 1
    }

    printf 'self-check: failure detection confirmed (eval + backtick + flag-drift all caught)\n'
    rm -rf "$_tmpdir"
    exit 0
fi

# ===========================================================================
# Normal mode
# ===========================================================================

# 1. Verify completion files exist
for _f in "$BASH_COMP" "$ZSH_COMP"; do
    [ -f "$_f" ] || {
        printf 'FAIL: completion file missing: %s\n' "$_f" >&2
        FAILED=$((FAILED + 1))
    }
done

# 2. Security checks
[ -f "$BASH_COMP" ] && check_security "$BASH_COMP"
[ -f "$ZSH_COMP" ]  && check_security "$ZSH_COMP"

# 3. Bash syntax check
if [ -f "$BASH_COMP" ]; then
    check_syntax "$BASH_COMP" bash
fi

# 4. Zsh syntax check (skip gracefully if zsh absent)
if [ -f "$ZSH_COMP" ]; then
    if command -v zsh >/dev/null 2>&1; then
        check_syntax "$ZSH_COMP" zsh
    else
        printf 'NOTICE: zsh not found; skipping syntax check for %s\n' \
            "$(basename "$ZSH_COMP")"
    fi
fi

# 5. Flag-drift check: each tool's --help flags must appear in at least one file
_tools="xrdcp xrdfs xrddiag xrdcksum xrd xrdprep xrdgsiproxy xrdsssadmin brixMount xrdstorascan"
for _tool in $_tools; do
    check_flag_coverage "$_tool" "$BINDIR/$_tool" "$BASH_COMP" "$ZSH_COMP"
done

if [ "$FAILED" -gt 0 ]; then
    printf 'check_completions: FAILED (%d issue(s))\n' "$FAILED" >&2
    exit 1
fi
printf 'check_completions: ALL PASS\n'
