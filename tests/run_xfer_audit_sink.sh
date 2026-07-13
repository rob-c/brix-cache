#!/usr/bin/env bash
# run_xfer_audit_sink.sh — xfer audit-ledger sink resolution (src/fs/xfer/xfer_ledger.c).
#
# Packaged deployments run nginx with a prefix (e.g. /usr/share/nginx) that has no
# logs/ directory, which used to disable transfer auditing with a one-shot warn.
# The sink now resolves: $BRIX_XFER_AUDIT_LOG (explicit, never falls back) →
# <prefix>/logs/xfer_audit.log → xfer_audit.log beside the cycle's error log.
#
# Three checks (project rule: success + error + edge):
#   1. success : prefix has no logs/ → the audit line lands beside error.log.
#   2. explicit: $BRIX_XFER_AUDIT_LOG (via the nginx `env` directive) wins.
#   3. error   : $BRIX_XFER_AUDIT_LOG unwritable → NO fallback, auditing off with
#                a warn, but the transfer itself still succeeds (best-effort).
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; XRDCP="$HERE/client/bin/xrdcp"
OPORT=11774; BPORT=11775; PFX="$(mktemp -d /tmp/xfer_audit.XXXXXX)"; fail=0
ok(){ printf '  ok   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o b; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX"; }
trap cleanup EXIT

# Origin O — plain root:// backend (the flush target). Its prefix HAS logs/.
mkdir -p "$PFX/o/root" "$PFX/o/logs"
cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${OPORT}; brix_root on; brix_export $PFX/o/root;
    brix_auth none; brix_allow_write on;
} }
EOF
"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>/dev/null || { echo "O start failed"; exit 2; }

# Node B — staged writes to O. Its prefix deliberately has NO logs/ directory
# (the packaged-deployment shape); error_log lives in a separate elog/ dir.
# $1 = optional extra main-context conf line (the env-override cases).
start_b(){
    [ -f "$PFX/b/nginx.pid" ] && kill "$(cat "$PFX/b/nginx.pid")" 2>/dev/null && sleep 0.5
    rm -rf "$PFX/b"; mkdir -p "$PFX/b/export" "$PFX/b/stage" "$PFX/b/elog"
    cat > "$PFX/b/nginx.conf" <<EOF
daemon on; error_log $PFX/b/elog/e.log info; pid $PFX/b/nginx.pid;
${1:-}
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${BPORT}; brix_root on; brix_export $PFX/b/export;
    brix_auth none; brix_allow_write on; brix_upload_resume off;
    brix_storage_backend root://127.0.0.1:${OPORT};
    brix_stage on;
    brix_stage_store posix:$PFX/b/stage;
    brix_stage_flush sync;
} }
EOF
    "$NGINX" -p "$PFX/b" -c "$PFX/b/nginx.conf" 2>"$PFX/b/start.err" \
        || { echo "B start failed"; cat "$PFX/b/start.err"; exit 2; }
    sleep 0.5
}

upload(){ # $1 = remote name; returns xrdcp status
    head -c 65536 /dev/urandom > "$PFX/src.bin"
    "$XRDCP" -f "$PFX/src.bin" "root://127.0.0.1:${BPORT}//$1" >/dev/null 2>&1
}

# --- 1. success: no <prefix>/logs → audit line lands beside error.log ---
start_b ""
if upload a.bin; then
    if grep -q 'result=ok .*path="/a.bin"' "$PFX/b/elog/xfer_audit.log" 2>/dev/null; then
        ok "fallback: audit line beside error.log (prefix has no logs/)"
    else
        bad "no audit line in $PFX/b/elog/xfer_audit.log"; ls "$PFX/b/elog/"
    fi
    grep -q 'xfer: audit log at' "$PFX/b/elog/e.log" \
        && ok "fallback announced with a NOTICE" || bad "fallback NOTICE missing"
else
    bad "upload failed (fallback case)"
fi

# --- 2. explicit: $BRIX_XFER_AUDIT_LOG wins over both defaults ---
mkdir -p "$PFX/custom"
start_b "env BRIX_XFER_AUDIT_LOG=$PFX/custom/audit.log;"
if upload b.bin; then
    grep -q 'result=ok .*path="/b.bin"' "$PFX/custom/audit.log" 2>/dev/null \
        && ok "explicit \$BRIX_XFER_AUDIT_LOG honored" \
        || bad "no audit line at explicit \$BRIX_XFER_AUDIT_LOG path"
else
    bad "upload failed (explicit case)"
fi

# --- 3. error: explicit path unwritable → no fallback, transfer still OK ---
start_b "env BRIX_XFER_AUDIT_LOG=$PFX/no-such-dir/audit.log;"
if upload c.bin; then
    ok "transfer succeeds with unwritable explicit sink (auditing best-effort)"
    [ ! -e "$PFX/b/elog/xfer_audit.log" ] \
        && ok "explicit override does NOT fall back" \
        || bad "explicit override fell back to the error-log dir"
    grep -q 'xfer: cannot open audit log' "$PFX/b/elog/e.log" \
        && ok "one-shot warn emitted" || bad "warn missing for unwritable sink"
else
    bad "upload failed (unwritable explicit sink case)"
fi

[ "$fail" = 0 ] && echo "run_xfer_audit_sink: ALL PASS" || echo "run_xfer_audit_sink: FAILURES"
exit "$fail"
