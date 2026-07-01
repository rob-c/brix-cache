#!/usr/bin/env bash
# Terminating tap proxy: client authenticates to the proxy (anon), the proxy
# re-logs-in to the origin and forwards opcodes; passthrough is byte-exact and
# the tap logs the forwarded opcodes (open/read) to error.log.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11960; PP=11961
PFX="$(mktemp -d /tmp/tapproxy.XXXXXX)"
fail=0
ok(){ printf '  ok   %s\n' "$1"; }
bad(){ printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/tapproxy_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; xrootd on; xrootd_root $PFX/o/root; xrootd_auth none; } }
EOF
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${PP}; xrootd on; xrootd_auth none;
    xrootd_tap_proxy on;
    xrootd_tap_proxy_upstream 127.0.0.1:${OP};
    xrootd_tap_proxy_auth anonymous;
} }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo proxy-fail; cat "$PFX/n/err"; exit 2; }
sleep 1
head -c 400000 /dev/urandom > "$PFX/o/root/f.bin"

"$XRDFS" root://127.0.0.1:${PP} cat /f.bin > /tmp/tapproxy_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/tapproxy_a.got && ok "terminating proxy passthrough byte-exact" || bad "passthrough mismatch"
"$XRDFS" root://127.0.0.1:${PP} stat /f.bin >/dev/null 2>&1 && ok "stat via tap proxy" || bad "stat failed"

sleep 0.5
grep -q '"op":"open"' "$PFX/n/logs/e.log" && ok "tap logged open" || bad "tap did not log open"
grep -q '"dir":"u2c"' "$PFX/n/logs/e.log" && ok "tap logged a response" || bad "tap did not log response"
exit $fail
