#!/usr/bin/env bash
# run_ktls.sh — verify the brix_ktls (kernel-TLS) feature end to end.
#
# Three checks (project rule: success + error + security/edge):
#   1. success  : HTTPS GET is byte-identical with brix_ktls on.
#   2. error    : an invalid brix_ktls value is rejected by nginx -t.
#   3. edge     : brix_ktls off still serves byte-identical (userspace TLS).
# Plus a best-effort ENGAGEMENT probe via /proc/net/tls_stat TlsTxSw — reported,
# not asserted, because kernel kTLS TX support is environment-dependent (e.g.
# WSL2 6.18.6 has it broken; see docs/10-reference/ktls.md).
#
# Prereqs: run_load_test.sh has generated /tmp/xrd-load/pki + /tmp/xrd-perf-test/
# nginx.gen.conf (the perf WebDAV https server on :12792). NGINX_BIN overrides the
# nginx path.
set -u
NGINX="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
GEN=/tmp/xrd-perf-test/nginx.gen.conf
DATA=/tmp/xrd-load/data
CA=/tmp/xrd-load/pki/ca/ca.pem
PORT=12792
PASS=0; FAIL=0
ok(){ echo "  ok   $*"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL $*"; FAIL=$((FAIL+1)); }
cleanup(){ pkill -9 -f "objs/nginx.*xrd-perf-test" 2>/dev/null; rm -f "$DATA/ktls_t.bin" /tmp/ktls_t_dl.bin; }
trap cleanup EXIT

[ -f "$GEN" ] || { echo "SKIP: $GEN missing — run tests/run_load_test.sh first"; exit 0; }
head -c 4194304 /dev/urandom > "$DATA/ktls_t.bin"

mkconf(){ # $1=ktls value -> prints conf path
  local v="$1" out="/tmp/ktls_t_$1.conf"
  sed "s/\(brix_webdav[[:space:]]*on;\)/\1\n        brix_ktls $v;/" "$GEN" > "$out"
  echo "$out"
}
start(){ pkill -9 -f "objs/nginx.*xrd-perf-test" 2>/dev/null; sleep 1
         "$NGINX" -c "$1" -p /tmp/xrd-perf-test 2>/dev/null
         for _ in $(seq 1 30); do [ "$(ss -tlnH "sport = :$PORT" 2>/dev/null | wc -l)" -gt 0 ] && return 0; sleep 0.5; done
         return 1; }
get(){ curl -s -o /tmp/ktls_t_dl.bin -k --tls13-ciphers TLS_AES_128_GCM_SHA256 \
            "https://localhost:$PORT/ktls_t.bin"; }
txsw(){ awk '/^TlsTxSw/{print $2}' /proc/net/tls_stat 2>/dev/null || echo 0; }

# --- 2. error: invalid value rejected ---
if "$NGINX" -t -c "$(mkconf maybe)" -p /tmp/xrd-perf-test 2>&1 | grep -q 'must be "on" or "off"'; then
    ok "invalid brix_ktls value rejected by nginx -t"
else
    bad "invalid brix_ktls value NOT rejected"
fi

# --- 1. success: kTLS on -> byte-identical + engagement probe ---
if start "$(mkconf on)"; then
    b=$(txsw); get; a=$(txsw)
    if cmp -s "$DATA/ktls_t.bin" /tmp/ktls_t_dl.bin; then ok "brix_ktls on: HTTPS GET byte-identical"
    else bad "brix_ktls on: GET mismatch"; fi
    d=$((a-b)); echo "  info kTLS TX sessions this GET: $d $([ "$d" -gt 0 ] && echo '(kTLS ENGAGED)' || echo '(userspace fallback — kernel kTLS TX unavailable here)')"
else
    bad "nginx did not start (brix_ktls on)"
fi

# --- 3. edge: kTLS off -> byte-identical (userspace TLS) ---
if start "$(mkconf off)"; then
    get
    cmp -s "$DATA/ktls_t.bin" /tmp/ktls_t_dl.bin && ok "brix_ktls off: HTTPS GET byte-identical (userspace TLS)" \
        || bad "brix_ktls off: GET mismatch"
else
    bad "nginx did not start (brix_ktls off)"
fi

echo "run_ktls: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
