#!/usr/bin/env bash
# End-to-end: brix_cache_origin_family constrains the storage_backend root://
# origin connect. Origin binds 127.0.0.1 (IPv4) only.
#   inet  -> fill succeeds (byte-exact)
#   inet6 -> fill fails FAST (no AAAA/refused), well under the connect deadline
#   auto  -> fill succeeds (parity)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11940; NP=11941
PFX="$(mktemp -d /tmp/cache_af.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cache_af_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/cache" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; brix_root on; brix_export $PFX/o/root; brix_auth none; } }
EOF

node_conf() {  # $1 = family token
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NP}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:${OP};
    brix_cache_store posix:$PFX/n/cache; brix_cache_export /;
    brix_cache_origin_family $1;
} }
EOF
}

start_node(){ node_conf "$1"; "$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo node-start-fail; cat "$PFX/n/err"; exit 2; }; }
stop_node(){ [ -f "$PFX/n/pid" ] && kill "$(cat "$PFX/n/pid")" 2>/dev/null; rm -f "$PFX/n/pid"; sleep 0.3; }

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
sleep 1
head -c 600000 /dev/urandom > "$PFX/o/root/f.bin"

# inet -> success
start_node inet; sleep 1
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_4.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_4.got && ok "inet: IPv4 origin fill byte-exact" || bad "inet: fill mismatch"
stop_node; rm -rf "$PFX/n/cache"/*; mkdir -p "$PFX/n/cache"

# inet6 -> fail fast (origin has no IPv6 listener; ::1 connect refused immediately)
start_node inet6; sleep 1
t0=$(date +%s)
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_6.got 2>/dev/null
rc=$?; t1=$(date +%s); dt=$((t1 - t0))
{ [ $rc -ne 0 ] || ! cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_6.got; } && ok "inet6: fill fails (no IPv4 fallback)" || bad "inet6: unexpectedly succeeded"
[ $dt -lt 30 ] && ok "inet6: failed fast (${dt}s < 30s, no retransmit stall)" || bad "inet6: stalled ${dt}s"
stop_node; rm -rf "$PFX/n/cache"/*; mkdir -p "$PFX/n/cache"

# auto -> success (parity)
start_node auto; sleep 1
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_a.got && ok "auto: fill byte-exact (parity)" || bad "auto: fill mismatch"
stop_node
exit $fail
