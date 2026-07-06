#!/usr/bin/env bash
# Transparent relay: a root:// client through the relay reaches a real origin
# byte-exact, and the relay's tap logs the opcodes (open/stat) to error.log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11950; RP=11951
PFX="$(mktemp -d /tmp/relay.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/relay_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; brix_root on; brix_export $PFX/o/root; brix_auth none; } }
EOF
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${RP}; brix_root on;
    brix_transparent_proxy 127.0.0.1:${OP};
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo relay-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 300000 /dev/urandom > "$PFX/o/root/f.bin"

# byte-exact passthrough via the relay
"$XRDFS" root://127.0.0.1:${RP} cat /f.bin > /tmp/relay_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/relay_a.got && ok "relay passthrough byte-exact" || bad "relay passthrough mismatch"

# stat through the relay (a metadata op for the tap to log)
"$XRDFS" root://127.0.0.1:${RP} stat /f.bin >/dev/null 2>&1 && ok "stat via relay" || bad "stat via relay failed"

sleep 0.5
grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" || bad "tap did not log open"
grep -q '"op":"stat"' "$PFX/n/logs/e.log" && ok "tap logged stat" || bad "tap did not log stat"
exit $fail
