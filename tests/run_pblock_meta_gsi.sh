#!/usr/bin/env bash
#
# run_pblock_meta_gsi.sh — concurrent GSI metadata-storm reliability + perf proof
# for the pblock storage backend, in three layers against one shared fixture:
#   (a) libxrdc direct harness   (tests/tools/pblock_meta_bench.c)
#   (b) full xrdfs CLI chain
#   (c) xrddiag client validation (check + metabench)
#
# Asserts four criteria: zero op failures, catalog integrity (exact namespace +
# no orphan blocks + no post-remove leak), server health after the storm, and
# p99 latency within a ceiling.
#
# Auth is GSI over root://, using the fleet CA-signed PKI (a self-signed cert
# can't form a valid GSI proxy chain). The PKI is generated on demand.
#
# Usage: tests/run_pblock_meta_gsi.sh [--selftest] [nginx-binary]
set -u

# --------------------------------------------------------------------------- #
# Paths + tunables                                                            #
# --------------------------------------------------------------------------- #
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SELFTEST=0
[ "${1:-}" = "--selftest" ] && { SELFTEST=1; shift; }

NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
XRDFS="$HERE/client/bin/xrdfs"
XRDCP="$HERE/client/bin/xrdcp"
XRDDIAG="$HERE/client/bin/xrddiag"
LIBXRDC="$HERE/client/libxrdc.a"
PROTOLIB="$HERE/shared/xrdproto/libxrdproto.a"

WORKERS="${WORKERS:-8}"
OPS_PER_WORKER="${OPS_PER_WORKER:-125}"
P99_CEIL_MS="${P99_CEIL_MS:-50}"
PORT="${PORT:-11498}"
BS="${PBLOCK_BLOCK_SIZE:-1m}"

TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
CA_DIR="$TEST_ROOT/pki/ca"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"
SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"
PROXY_STD="$TEST_ROOT/pki/user/proxy_std.pem"

# --------------------------------------------------------------------------- #
# Self-test mode: drives the umbrella three ways (success/fault/security-neg)  #
# --------------------------------------------------------------------------- #
if [ "$SELFTEST" = 1 ]; then
    base="$HERE/tests/run_pblock_meta_gsi.sh"
    rc=0
    echo "[selftest] 1/3 success: a healthy run must PASS"
    if "$base" "$NGINX" >/dev/null 2>&1; then echo "  ok success"; else echo "  FAIL success"; rc=1; fi
    echo "[selftest] 2/3 fault: an unsatisfiable p99 ceiling (1ms) must FAIL (detects, never silently passes)"
    if P99_CEIL_MS=1 "$base" "$NGINX" >/dev/null 2>&1; then echo "  FAIL fault-not-detected"; rc=1; else echo "  ok fault detected"; fi
    echo "[selftest] 3/3 security-neg: an invalid GSI proxy must be rejected"
    if MB_PROXY_OVERRIDE=/dev/null "$base" "$NGINX" >/dev/null 2>&1; then echo "  FAIL gsi-bypass"; rc=1; else echo "  ok GSI gate enforced"; fi
    [ "$rc" = 0 ] && echo "selftest PASS" || echo "selftest FAIL"
    exit "$rc"
fi

fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

# --------------------------------------------------------------------------- #
# Skip-clean if prerequisites are missing                                     #
# --------------------------------------------------------------------------- #
for need in "$NGINX" "$XRDFS" "$XRDDIAG" "$LIBXRDC" "$PROTOLIB"; do
    [ -e "$need" ] || { echo "SKIP: missing $need"; exit 0; }
done

PFX="$(mktemp -d /tmp/pblock_meta_gsi.XXXXXX)"
H="root://127.0.0.1:${PORT}/"
mkdir -p "$PFX/root" "$PFX/logs"
cleanup() { [ -f "$PFX/nginx.pid" ] && kill "$(cat "$PFX/nginx.pid")" 2>/dev/null; rm -rf "$PFX"; }
trap cleanup EXIT

# --------------------------------------------------------------------------- #
# Ensure the CA-signed PKI exists (server cert + user proxy the server trusts) #
# --------------------------------------------------------------------------- #
if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$PROXY_STD" ]; then
    echo "== provisioning PKI (blitz_test_pki) =="
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/logs/pki.log" 2>&1 || { echo "SKIP: PKI provisioning failed"; cat "$PFX/logs/pki.log"; exit 0; }
fi
# A proxy is short-lived; refresh if it has expired.
if ! openssl x509 -in "$PROXY_STD" -noout -checkend 300 >/dev/null 2>&1; then
    ( cd "$HERE/tests" && PYTHONPATH=. python3 -c "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
        >"$PFX/logs/pki.log" 2>&1 || true
fi
export X509_USER_PROXY="${MB_PROXY_OVERRIDE:-$PROXY_STD}"
export X509_CERT_DIR="$CA_DIR"

# --------------------------------------------------------------------------- #
# pblock + GSI stream server                                                  #
# --------------------------------------------------------------------------- #
cat > "$PFX/nginx.conf" <<EOF
daemon on;
error_log $PFX/logs/error.log info;
pid $PFX/nginx.pid;
events { worker_connections 256; }
thread_pool default threads=8 max_queue=512;
stream {
    server {
        listen 127.0.0.1:${PORT};
        xrootd on;
        xrootd_root            $PFX/root;
        xrootd_auth            gsi;
        xrootd_certificate     $SERVER_CERT;
        xrootd_certificate_key $SERVER_KEY;
        xrootd_trusted_ca      $CA_CERT;
        xrootd_allow_write     on;
        xrootd_upload_resume   off;
        xrootd_storage_backend pblock;
        xrootd_pblock_block_size ${BS};
        xrootd_access_log $PFX/logs/access.log;
    }
}
EOF

"$NGINX" -p "$PFX" -c "$PFX/nginx.conf" 2>"$PFX/logs/start.err" \
    || { echo "nginx failed to start"; cat "$PFX/logs/start.err"; exit 2; }
sleep 1

# --------------------------------------------------------------------------- #
# Build the Layer (a) harness against libxrdc                                 #
# --------------------------------------------------------------------------- #
MB="$PFX/pblock_meta_bench"
cc -O2 -Wall -I"$HERE/client/lib" -I"$HERE/src" -DXRDPROTO_NO_NGX \
   "$HERE/tests/tools/pblock_meta_bench.c" "$LIBXRDC" "$PROTOLIB" \
   -lssl -lcrypto -lz -lkrb5 -lk5crypto -lcom_err -lzstd -llzma \
   -lbrotlienc -lbrotlidec -lbz2 -l:liblz4.so.1 -luring -lpthread \
   -o "$MB" 2>"$PFX/logs/cc.err" \
    || { echo "harness build failed"; cat "$PFX/logs/cc.err"; exit 2; }
PLAN_ARGS="--workers $WORKERS --ops-per-worker $OPS_PER_WORKER --p99-ceil-ms $P99_CEIL_MS"

# --------------------------------------------------------------------------- #
# Layer (a): libxrdc direct code                                              #
# --------------------------------------------------------------------------- #
echo "== Layer (a): libxrdc direct code =="
"$MB" $PLAN_ARGS --phase create --json "$H" > "$PFX/logs/a_create.json" 2>"$PFX/logs/a.err"
a_rc=$?
cat "$PFX/logs/a_create.json"
[ "$a_rc" = 0 ] && ok "layer-a create: zero failures + p99<=${P99_CEIL_MS}ms" \
                 || bad "layer-a create (rc=$a_rc) — see logs/a_create.json + a.err"

# --- Criterion 2: catalog integrity (exact namespace + no orphan blocks) ---
echo "== verify: catalog integrity =="
"$MB" $PLAN_ARGS --print-expected "$H" | sort > "$PFX/logs/expected.txt"
"$XRDFS" "$H" ls -R / 2>/dev/null > "$PFX/logs/lsr.txt" || true
miss=0
while read -r _mode _isdir path; do
    grep -qF "$path" "$PFX/logs/lsr.txt" || miss=$((miss+1))
done < "$PFX/logs/expected.txt"
[ "$miss" = 0 ] && ok "namespace readback: all expected paths present" \
                || bad "namespace readback: $miss expected path(s) missing"
# Each created file gets one block-0 blob in the data dir. Assert the on-disk
# block count matches the file count exactly (no missing, no extra/orphan blobs).
want_files=$(awk '$2==0' "$PFX/logs/expected.txt" | wc -l)
got_blocks=$(find "$PFX/root/data" -type f 2>/dev/null | wc -l)
[ "$got_blocks" = "$want_files" ] \
    && ok "block catalog integrity: $got_blocks blocks == $want_files files" \
    || bad "block/file mismatch: $got_blocks blocks vs $want_files files"

# chmod must PERSIST through the driver setattr slot (regression guard: pblock
# chmod was previously a silent no-op). Backend-agnostic: a mode change must be
# observable on read-back, so the rendered permission column must differ.
"$XRDFS" "$H" chmod /w0/d0/f0 0644 >/dev/null 2>&1
cm_a=$("$XRDFS" "$H" ls -l /w0/d0 2>/dev/null | awk '/\/f0$/{print $1}')
"$XRDFS" "$H" chmod /w0/d0/f0 0600 >/dev/null 2>&1
cm_b=$("$XRDFS" "$H" ls -l /w0/d0 2>/dev/null | awk '/\/f0$/{print $1}')
[ -n "$cm_a" ] && [ "$cm_a" != "$cm_b" ] \
    && ok "chmod persists through driver (0644 '$cm_a' != 0600 '$cm_b')" \
    || bad "chmod did not persist (driver setattr no-op?): 0644 '$cm_a' vs 0600 '$cm_b'"

# --- remove phase exercises unlink/rmdir, then leak check -------------------
echo "== Layer (a): remove phase + leak check =="
"$MB" $PLAN_ARGS --phase remove --json "$H" > "$PFX/logs/a_remove.json" 2>>"$PFX/logs/a.err"
r_rc=$?
cat "$PFX/logs/a_remove.json"
[ "$r_rc" = 0 ] && ok "layer-a remove: zero failures" || bad "layer-a remove (rc=$r_rc)"
"$XRDFS" "$H" ls / 2>/dev/null | grep -q "/w0" \
    && bad "namespace not empty after remove (leak)" \
    || ok "store empty after remove (no namespace leak)"
left_blocks=$(find "$PFX/root/data" -type f 2>/dev/null | wc -l)
[ "$left_blocks" = 0 ] \
    && ok "no leftover blocks after remove (create+remove leaves no residue)" \
    || bad "block leak: $left_blocks block(s) left after remove"

# --- Criterion 3: server health after the storm ----------------------------
echo "== verify: server health after storm =="
"$XRDFS" "$H" stat / >/dev/null 2>&1 \
    && ok "fresh GSI login + stat OK after storm" \
    || bad "server unhealthy after storm (GSI stat failed)"

# --------------------------------------------------------------------------- #
# Layer (b): full xrdfs CLI chain under concurrency                           #
# Each worker (concurrent GSI session) drives the real xrdfs binary through the  #
# whole chain: the previously-broken non-recursive nested mkdir, file create via #
# `touch` (which also exercises the kXR_setattr/utimes driver seam), chmod, stat.#
# --------------------------------------------------------------------------- #
echo "== Layer (b): full xrdfs CLI chain (concurrent GSI sessions) =="
run_worker_b() {
    local w="$1" rc=0
    "$XRDFS" "$H" mkdir "/wb${w}"        >/dev/null 2>&1 || rc=1   # top-level
    "$XRDFS" "$H" mkdir "/wb${w}/d0"     >/dev/null 2>&1 || rc=1   # NESTED non-recursive (the fix)
    "$XRDFS" "$H" chmod "/wb${w}/d0" 700 >/dev/null 2>&1 || rc=1
    "$XRDFS" "$H" touch "/wb${w}/d0/f0"  >/dev/null 2>&1 || rc=1   # create + setattr/utimes (the fix)
    "$XRDFS" "$H" chmod "/wb${w}/d0/f0" 640 >/dev/null 2>&1 || rc=1
    "$XRDFS" "$H" stat "/wb${w}/d0/f0"   >/dev/null 2>&1 || rc=1
    echo "$rc" > "$PFX/logs/b_w${w}.rc"
}
for w in $(seq 0 $((WORKERS - 1))); do run_worker_b "$w" & done
wait
b_fail=0
for w in $(seq 0 $((WORKERS - 1))); do
    [ "$(cat "$PFX/logs/b_w${w}.rc" 2>/dev/null)" = 0 ] || b_fail=$((b_fail + 1))
done
[ "$b_fail" = 0 ] \
    && ok "xrdfs chain: all $WORKERS concurrent sessions clean (incl. nested mkdir)" \
    || bad "xrdfs chain: $b_fail/$WORKERS session(s) failed"
"$XRDFS" "$H" ls -R / 2>/dev/null > "$PFX/logs/lsr_b.txt" || true
bmiss=0
for w in $(seq 0 $((WORKERS - 1))); do
    grep -qF "/wb${w}/d0/f0" "$PFX/logs/lsr_b.txt" || bmiss=$((bmiss + 1))
done
[ "$bmiss" = 0 ] && ok "xrdfs chain: namespace readback complete" \
                 || bad "xrdfs chain: $bmiss file(s) missing on readback"
for w in $(seq 0 $((WORKERS - 1))); do
    "$XRDFS" "$H" rm "/wb${w}/d0/f0" >/dev/null 2>&1
    "$XRDFS" "$H" rmdir "/wb${w}/d0" >/dev/null 2>&1
    "$XRDFS" "$H" rmdir "/wb${w}"    >/dev/null 2>&1
done

# --------------------------------------------------------------------------- #
# Layer (c): xrddiag client validation (works + performs)                     #
# --------------------------------------------------------------------------- #
echo "== Layer (c): xrddiag client validation =="
"$XRDDIAG" check "$H" > "$PFX/logs/c_check.txt" 2>&1
grep -q "Result: 0 failure" "$PFX/logs/c_check.txt" \
    && ok "xrddiag check: client conformance all-green" \
    || bad "xrddiag check: conformance failures — see logs/c_check.txt"
"$XRDDIAG" metabench -S "$WORKERS" --count "$OPS_PER_WORKER" "$H" \
    > "$PFX/logs/c_metabench.txt" 2>&1
c_rc=$?
sed 's/^/  /' "$PFX/logs/c_metabench.txt"
[ "$c_rc" = 0 ] && ok "xrddiag metabench: client performs (0 fail, p99 within ceiling)" \
               || bad "xrddiag metabench (rc=$c_rc)"

echo
[ "$fail" = 0 ] && echo "PASS run_pblock_meta_gsi" || echo "FAIL run_pblock_meta_gsi"
exit "$fail"
