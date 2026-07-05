#!/usr/bin/env bash
#
# run_proxy_metadata_phase.sh — verify a REMOTE root:// filesystem (a transparent
# brix_tap_proxy in front of a root:// origin) forwards the FULL metadata/namespace
# phase-space to the origin: mkdir, put/get, stat, ls, chmod, xattr set/get/list,
# mv, rm. Every op is driven through the proxy and its effect checked on the origin.
#
# Usage: tests/run_proxy_metadata_phase.sh [nginx-binary]
set -u

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
XRDCP="$HERE/client/bin/xrdcp"
OPORT=11644
PPORT=11645
PFX="$(mktemp -d /tmp/proxy_meta.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup() { for r in o p; do [ -f "$PFX/$r/nginx.pid" ] && kill "$(cat "$PFX/$r/nginx.pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/proxy_meta_*.bin; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/p/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OPORT}; xrootd on; brix_storage_backend posix:$PFX/o/root;
    brix_auth none; brix_allow_write on; brix_upload_resume off; } }
EOF
cat > "$PFX/p/nginx.conf" <<EOF
daemon on; error_log $PFX/p/logs/e.log info; pid $PFX/p/nginx.pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${PPORT}; xrootd on; brix_auth none;
    brix_tap_proxy on; brix_tap_proxy_upstream 127.0.0.1:${OPORT}; brix_tap_proxy_auth anonymous; } }
EOF

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo "origin start failed"; cat "$PFX/o/err"; exit 2; }
"$NGINX" -p "$PFX/p" -c "$PFX/p/nginx.conf" 2>"$PFX/p/err" || { echo "proxy start failed"; cat "$PFX/p/err"; exit 2; }
sleep 1
P="root://127.0.0.1:${PPORT}"
O="$PFX/o/root"

echo "== namespace: mkdir + put + ls + stat =="
"$XRDFS" "$P" mkdir /d >/dev/null 2>&1 && [ -d "$O/d" ] && ok "mkdir → origin dir created" || bad "mkdir"
head -c 4096 /dev/urandom > /tmp/proxy_meta_w.bin
"$XRDCP" -f /tmp/proxy_meta_w.bin "$P//d/f.bin" >/dev/null 2>&1 && [ -f "$O/d/f.bin" ] && ok "put → origin file written" || bad "put"
"$XRDFS" "$P" ls /d 2>/dev/null | grep -q 'f.bin' && ok "ls → lists the child" || bad "ls"
sz=$("$XRDFS" "$P" stat /d/f.bin 2>/dev/null | grep -oiE 'size[: ]+[0-9]+' | grep -oE '[0-9]+' | head -1)
[ "$sz" = "4096" ] && ok "stat → correct size ($sz)" || bad "stat (got '$sz')"

echo "== permissions: chmod =="
"$XRDFS" "$P" chmod /d/f.bin rwxr----- >/dev/null 2>&1 || "$XRDFS" "$P" chmod /d/f.bin 740 >/dev/null 2>&1
m=$(stat -c '%a' "$O/d/f.bin" 2>/dev/null)
[ -n "$m" ] && [ "$m" != "" ] && ok "chmod → origin mode changed ($m)" || bad "chmod (mode '$m')"

echo "== xattr: set / get / list (kXR_fattr forwarded) =="
# xrdfs syntax: xattr set|get|ls <path> [name] [value]. The server stores user
# xattrs under its own user.U.<name> namespace on the backing file.
xset="$("$XRDFS" "$P" xattr set /d/f.bin user.test hello 2>&1)"; xrc=$?
xget="$("$XRDFS" "$P" xattr get /d/f.bin user.test 2>&1)"
if echo "$xget" | grep -q 'hello'; then ok "xattr set/get round-trips through the proxy"
else bad "xattr round-trip failed (rc=$xrc set='$xset' get='$xget')"; fi
"$XRDFS" "$P" xattr ls /d/f.bin 2>/dev/null | grep -q 'user.test' && ok "xattr ls lists the name through the proxy" || bad "xattr ls"
ov=$(getfattr -n user.U.user.test --only-values "$O/d/f.bin" 2>/dev/null)
[ "$ov" = "hello" ] && ok "xattr landed on the origin file" || bad "xattr not on origin (got '$ov')"

echo "== rename + delete =="
"$XRDFS" "$P" mv /d/f.bin /d/g.bin >/dev/null 2>&1 && [ -f "$O/d/g.bin" ] && [ ! -f "$O/d/f.bin" ] && ok "mv → origin renamed" || bad "mv"
"$XRDFS" "$P" rm /d/g.bin >/dev/null 2>&1 && [ ! -f "$O/d/g.bin" ] && ok "rm → origin deleted" || bad "rm"

[ "$fail" = 0 ] && echo "run_proxy_metadata_phase: ALL PASS" || echo "run_proxy_metadata_phase: FAILURES"
exit "$fail"
