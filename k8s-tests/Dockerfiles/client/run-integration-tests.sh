#!/usr/bin/env bash
# xrd-integration-tests — comprehensive XRootD integration test suite.
#
# Run from inside the client pod:
#   kubectl exec -it xrootd-client -n xrootd-integration -- xrd-integration-tests
#
# Or via the CI Job:
#   kubectl apply -f k8s-manifests/integration-job.yaml
#
# Environment variables:
#   XROOTD_SERVER   host:port of the XRootD server     (default: xrootd-reference:1094)
#   AUTH_MODE       anonymous | gsi | token | both      (default: anonymous)
#   CA_DIR          Trusted CA directory                (default: /etc/grid-security/certificates)
#   CLIENT_CERT     User certificate PEM                (default: /etc/grid-security/usercert.pem)
#   CLIENT_KEY      User private key PEM                (default: /etc/grid-security/userkey.pem)
#   PROXY_FILE      x509 proxy path                     (default: /tmp/x509up_u0)
#   BEARER_TOKEN    JWT bearer token (pre-generated)
#   WEBDAV_URL      Optional WebDAV endpoint for davix tests
#   SKIP_LARGE      Set to 1 to skip the 64 MB file tests
#   VERBOSE         Set to 1 to show full command output for failing tests
#   RESULTS_DIR     Directory for JUnit XML output      (default: /tmp/xrd-test-results)
#   TEST_TIMEOUT    Per-test timeout in seconds         (default: 120)

set -euo pipefail

SERVER="${XROOTD_SERVER:-xrootd-reference:1094}"
AUTH_MODE="${AUTH_MODE:-anonymous}"
CA_DIR="${CA_DIR:-/etc/grid-security/certificates}"
CLIENT_CERT="${CLIENT_CERT:-/etc/grid-security/usercert.pem}"
CLIENT_KEY="${CLIENT_KEY:-/etc/grid-security/userkey.pem}"
PROXY_FILE="${PROXY_FILE:-/tmp/x509up_u0}"
SKIP_LARGE="${SKIP_LARGE:-0}"
VERBOSE="${VERBOSE:-0}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/xrd-test-results}"
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"

ROOT_URL="root://${SERVER}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$RESULTS_DIR"

# ── Test accounting ───────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
ERRORS=()

# Timing
start_time=$(date +%s)

# JUnit XML state
JUNIT_CASES=""

pass_test() {
    local name="$1" elapsed_ms="$2"
    printf "  %-60s \033[32mPASS\033[0m (%dms)\n" "$name" "$elapsed_ms" >&2
    (( PASS++ )) || true
    JUNIT_CASES+="<testcase name=\"${name}\" time=\"$(( elapsed_ms / 1000 )).$(( elapsed_ms % 1000 ))\"/>"$'\n'
}

fail_test() {
    local name="$1" elapsed_ms="$2" output="$3"
    printf "  %-60s \033[31mFAIL\033[0m (%dms)\n" "$name" "$elapsed_ms" >&2
    (( FAIL++ )) || true
    ERRORS+=("$name")
    JUNIT_CASES+="<testcase name=\"${name}\" time=\"$(( elapsed_ms / 1000 )).$(( elapsed_ms % 1000 ))\"><failure message=\"test failed\"><![CDATA[${output}]]></failure></testcase>"$'\n'
    if [[ "$VERBOSE" == "1" ]]; then
        echo "  --- output ---" >&2
        echo "$output" | sed 's/^/    /' >&2
        echo "  --- end ---" >&2
    fi
}

skip_test() {
    local name="$1" reason="$2"
    printf "  %-60s \033[33mSKIP\033[0m (%s)\n" "$name" "$reason" >&2
    (( SKIP++ )) || true
    JUNIT_CASES+="<testcase name=\"${name}\"><skipped message=\"${reason}\"/></testcase>"$'\n'
}

# run_test NAME CMD [ARGS...]
# Runs CMD; records PASS/FAIL with timing.
run_test() {
    local name="$1"; shift
    local t0 t1 elapsed_ms output rc

    t0=$(date +%s%3N)
    if output=$(timeout "$TEST_TIMEOUT" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    t1=$(date +%s%3N)
    elapsed_ms=$(( t1 - t0 ))

    if [[ $rc -eq 0 ]]; then
        pass_test "$name" "$elapsed_ms"
    else
        fail_test "$name" "$elapsed_ms" "$output"
    fi
}

# run_fail_test NAME CMD [ARGS...]
# Expects CMD to exit non-zero; inverts the result.
run_fail_test() {
    local name="$1"; shift
    local t0 t1 elapsed_ms output rc

    t0=$(date +%s%3N)
    if output=$(timeout "$TEST_TIMEOUT" "$@" 2>&1); then
        rc=0
    else
        rc=$?
    fi
    t1=$(date +%s%3N)
    elapsed_ms=$(( t1 - t0 ))

    if [[ $rc -ne 0 ]]; then
        pass_test "$name" "$elapsed_ms"
    else
        fail_test "$name" "$elapsed_ms" "Expected failure but command succeeded"
    fi
}

section() { echo "" >&2; echo "── $* ──" >&2; }

# ── Auth setup ────────────────────────────────────────────────────────────────
# Build common xrdcp / xrdfs flags based on AUTH_MODE.
XRDCP_FLAGS=()
XRDFS_OPTS=()

setup_auth() {
    case "$AUTH_MODE" in
        gsi)
            # Create OpenSSL hash symlinks so GSI can find the CA.
            if [[ -d "$CA_DIR" ]]; then
                for cert in "$CA_DIR"/*.pem "$CA_DIR"/*.crt; do
                    [[ -f "$cert" ]] || continue
                    hash=$(openssl x509 -noout -hash -in "$cert" 2>/dev/null) || continue
                    ln -sf "$(basename "$cert")" "${CA_DIR}/${hash}.0" 2>/dev/null || true
                done
            fi

            # Generate a proxy certificate.
            if command -v voms-proxy-init &>/dev/null; then
                voms-proxy-init \
                    --cert "$CLIENT_CERT" \
                    --key  "$CLIENT_KEY" \
                    --out  "$PROXY_FILE" \
                    --hours 12 \
                    --rfc \
                    2>/dev/null || true
            elif command -v grid-proxy-init &>/dev/null; then
                grid-proxy-init \
                    -cert  "$CLIENT_CERT" \
                    -key   "$CLIENT_KEY" \
                    -out   "$PROXY_FILE" \
                    -hours 12 \
                    2>/dev/null || true
            else
                # Minimal self-signed proxy via openssl.
                openssl genrsa -out "${PROXY_FILE}.key" 1024 2>/dev/null
                openssl req -new \
                    -key "${PROXY_FILE}.key" \
                    -subj "/DC=test/DC=xrootd/CN=proxy" \
                    -out "${PROXY_FILE}.csr" 2>/dev/null
                openssl x509 -req \
                    -in "${PROXY_FILE}.csr" \
                    -CA "$CLIENT_CERT" \
                    -CAkey "$CLIENT_KEY" \
                    -CAcreateserial \
                    -out "${PROXY_FILE}.cert" \
                    -days 1 2>/dev/null
                cat "${PROXY_FILE}.cert" "$CLIENT_CERT" "${PROXY_FILE}.key" \
                    > "$PROXY_FILE"
                rm -f "${PROXY_FILE}.key" "${PROXY_FILE}.csr" "${PROXY_FILE}.cert"
            fi
            chmod 600 "$PROXY_FILE"
            export X509_USER_PROXY="$PROXY_FILE"
            XRDCP_FLAGS+=(--cadir "$CA_DIR")
            echo "[auth] GSI proxy ready at $PROXY_FILE" >&2
            ;;

        token)
            if [[ -z "${BEARER_TOKEN:-}" ]]; then
                if command -v xrd-gen-token &>/dev/null; then
                    BEARER_TOKEN="$(xrd-gen-token 2>/dev/null)" || true
                fi
            fi
            if [[ -n "${BEARER_TOKEN:-}" ]]; then
                export BEARER_TOKEN
                echo "[auth] Bearer token set." >&2
            else
                echo "[auth] WARNING: AUTH_MODE=token but no token available." >&2
            fi
            ;;

        both)
            # Set up both GSI and token; let the server choose.
            setup_auth_gsi_only || true
            if [[ -z "${BEARER_TOKEN:-}" ]] && command -v xrd-gen-token &>/dev/null; then
                BEARER_TOKEN="$(xrd-gen-token 2>/dev/null)" || true
                [[ -n "${BEARER_TOKEN:-}" ]] && export BEARER_TOKEN
            fi
            ;;

        anonymous|*)
            XRDCP_FLAGS+=(--nopbar --noProgressBar)
            ;;
    esac
}

setup_auth_gsi_only() {
    # Shared helper used by the 'both' branch.
    if [[ -d "$CA_DIR" ]]; then
        for cert in "$CA_DIR"/*.pem "$CA_DIR"/*.crt; do
            [[ -f "$cert" ]] || continue
            hash=$(openssl x509 -noout -hash -in "$cert" 2>/dev/null) || continue
            ln -sf "$(basename "$cert")" "${CA_DIR}/${hash}.0" 2>/dev/null || true
        done
    fi
    XRDCP_FLAGS+=(--cadir "$CA_DIR")
}

# ── Helper: generate a random file of given size ──────────────────────────────
gen_random_file() {
    local path="$1" size_bytes="$2"
    dd if=/dev/urandom bs=4096 count=$(( (size_bytes + 4095) / 4096 )) \
        2>/dev/null | head -c "$size_bytes" > "$path"
}

# ── Helper: verify adler32 checksum round-trips ───────────────────────────────
check_roundtrip() {
    local src="$1" dst="$2"
    # Use sha256sum if cksum --algorithm is unavailable.
    if command -v sha256sum &>/dev/null; then
        [[ "$(sha256sum < "$src")" == "$(sha256sum < "$dst")" ]]
    else
        cmp -s "$src" "$dst"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Tests start here
# ═══════════════════════════════════════════════════════════════════════════════

echo "" >&2
echo "╔══════════════════════════════════════════════════════════════╗" >&2
echo "║         XRootD Integration Test Suite                       ║" >&2
echo "╚══════════════════════════════════════════════════════════════╝" >&2
echo "" >&2
echo "  server    : $SERVER" >&2
echo "  auth mode : $AUTH_MODE" >&2
echo "  skip large: $SKIP_LARGE" >&2

setup_auth

# ── §1 Tool availability ──────────────────────────────────────────────────────
section "1. Tool availability"

for tool in xrdcp xrdfs; do
    run_test "tool: $tool in PATH" which "$tool"
done

for tool in openssl python3 curl; do
    run_test "tool: $tool in PATH" which "$tool"
done

# Optional tools — do not fail if absent.
for tool in gfal-copy davix-ls voms-proxy-init; do
    command -v "$tool" &>/dev/null \
        && run_test "tool: $tool in PATH" which "$tool" \
        || skip_test "tool: $tool in PATH" "not installed"
done

# ── §2 Basic connectivity ─────────────────────────────────────────────────────
section "2. Basic connectivity (xrdfs)"

run_test "xrdfs stat /" \
    xrdfs "$SERVER" stat /

run_test "xrdfs ls /" \
    xrdfs "$SERVER" ls /

run_test "xrdfs stat /hello.txt (seed file)" \
    xrdfs "$SERVER" stat /hello.txt

run_test "xrdfs ls -l / (long listing)" \
    xrdfs "$SERVER" ls -l /

run_test "xrdfs stat /subdir (seed directory)" \
    xrdfs "$SERVER" stat /subdir

run_test "xrdfs ls /subdir" \
    xrdfs "$SERVER" ls /subdir

# ── §3 Small file round-trip (4 KB, xrdcp) ───────────────────────────────────
section "3. Small file round-trip — 4 KB"

SMALL_SRC="${TMPDIR}/small-src.dat"
SMALL_DST="${TMPDIR}/small-dst.dat"
gen_random_file "$SMALL_SRC" 4096

run_test "xrdcp upload 4KB" \
    xrdcp "${XRDCP_FLAGS[@]}" "$SMALL_SRC" "${ROOT_URL}//it-small.dat"

run_test "xrdcp download 4KB" \
    xrdcp "${XRDCP_FLAGS[@]}" "${ROOT_URL}//it-small.dat" "$SMALL_DST"

run_test "4KB round-trip checksum" \
    check_roundtrip "$SMALL_SRC" "$SMALL_DST"

run_test "xrdfs stat it-small.dat" \
    xrdfs "$SERVER" stat /it-small.dat

# ── §4 Medium file with explicit checksum (4 MB) ──────────────────────────────
section "4. Medium file with checksum — 4 MB"

MED_SRC="${TMPDIR}/med-src.dat"
MED_DST="${TMPDIR}/med-dst.dat"
gen_random_file "$MED_SRC" $(( 4 * 1024 * 1024 ))

run_test "xrdcp upload 4MB --cksum adler32" \
    xrdcp "${XRDCP_FLAGS[@]}" --cksum adler32 "$MED_SRC" "${ROOT_URL}//it-medium.dat"

run_test "xrdcp download 4MB" \
    xrdcp "${XRDCP_FLAGS[@]}" "${ROOT_URL}//it-medium.dat" "$MED_DST"

run_test "4MB round-trip checksum" \
    check_roundtrip "$MED_SRC" "$MED_DST"

# ── §5 Parallel streams (-S 4) ────────────────────────────────────────────────
section "5. Parallel streams — 8 MB with -S 4"

PAR_SRC="${TMPDIR}/par-src.dat"
PAR_DST="${TMPDIR}/par-dst.dat"
gen_random_file "$PAR_SRC" $(( 8 * 1024 * 1024 ))

run_test "xrdcp upload 8MB -S 4" \
    xrdcp "${XRDCP_FLAGS[@]}" -S 4 "$PAR_SRC" "${ROOT_URL}//it-parallel.dat"

run_test "xrdcp download 8MB (parallel src)" \
    xrdcp "${XRDCP_FLAGS[@]}" "${ROOT_URL}//it-parallel.dat" "$PAR_DST"

run_test "parallel stream round-trip checksum" \
    check_roundtrip "$PAR_SRC" "$PAR_DST"

# ── §6 Large file (64 MB, skippable) ─────────────────────────────────────────
section "6. Large file — 64 MB"

if [[ "$SKIP_LARGE" == "1" ]]; then
    skip_test "xrdcp upload 64MB"   "SKIP_LARGE=1"
    skip_test "xrdcp download 64MB" "SKIP_LARGE=1"
    skip_test "64MB checksum"       "SKIP_LARGE=1"
else
    LARGE_SRC="${TMPDIR}/large-src.dat"
    LARGE_DST="${TMPDIR}/large-dst.dat"
    gen_random_file "$LARGE_SRC" $(( 64 * 1024 * 1024 ))

    run_test "xrdcp upload 64MB" \
        xrdcp "${XRDCP_FLAGS[@]}" -S 4 "$LARGE_SRC" "${ROOT_URL}//it-large.dat"

    run_test "xrdcp download 64MB" \
        xrdcp "${XRDCP_FLAGS[@]}" "${ROOT_URL}//it-large.dat" "$LARGE_DST"

    run_test "64MB round-trip checksum" \
        check_roundtrip "$LARGE_SRC" "$LARGE_DST"
fi

# ── §7 Namespace operations (xrdfs) ──────────────────────────────────────────
section "7. Namespace operations"

run_test "xrdfs mkdir /it-dir" \
    xrdfs "$SERVER" mkdir /it-dir

run_test "xrdfs stat /it-dir" \
    xrdfs "$SERVER" stat /it-dir

run_test "xrdfs mv it-small.dat → /it-dir/" \
    xrdfs "$SERVER" mv /it-small.dat /it-dir/moved.dat

run_test "xrdfs ls /it-dir (after mv)" \
    xrdfs "$SERVER" ls /it-dir

run_test "xrdfs stat /it-dir/moved.dat" \
    xrdfs "$SERVER" stat /it-dir/moved.dat

run_test "xrdfs chmod 0644 /it-dir/moved.dat" \
    xrdfs "$SERVER" chmod 0644 /it-dir/moved.dat

run_test "xrdfs rm /it-dir/moved.dat" \
    xrdfs "$SERVER" rm /it-dir/moved.dat

run_test "xrdfs mkdir /it-dir/nested" \
    xrdfs "$SERVER" mkdir /it-dir/nested

run_test "xrdfs rmdir /it-dir/nested" \
    xrdfs "$SERVER" rmdir /it-dir/nested

run_test "xrdfs rmdir /it-dir" \
    xrdfs "$SERVER" rmdir /it-dir

# ── §8 Query operations ───────────────────────────────────────────────────────
section "8. Query operations"

run_test "xrdfs query checksum /it-medium.dat" \
    xrdfs "$SERVER" query checksum /it-medium.dat

run_test "xrdfs query config max_chunk_size" \
    xrdfs "$SERVER" query config max_chunk_size

run_test "xrdfs locate /it-medium.dat" \
    xrdfs "$SERVER" locate -h /it-medium.dat

# ── §9 Error cases ────────────────────────────────────────────────────────────
section "9. Error cases (expected failures)"

run_fail_test "stat non-existent file returns error" \
    xrdfs "$SERVER" stat /definitely-does-not-exist-zzzz.dat

run_fail_test "download non-existent file returns error" \
    xrdcp "${XRDCP_FLAGS[@]}" "${ROOT_URL}//no-such-file.dat" "${TMPDIR}/nope.dat"

# ── §10 GSI auth ──────────────────────────────────────────────────────────────
section "10. GSI authentication"

if [[ "$AUTH_MODE" == "gsi" ]] || [[ "$AUTH_MODE" == "both" ]]; then
    GSI_SRC="${TMPDIR}/gsi-src.dat"
    GSI_DST="${TMPDIR}/gsi-dst.dat"
    gen_random_file "$GSI_SRC" $(( 1 * 1024 * 1024 ))

    run_test "GSI: xrdfs stat / with proxy" \
        env X509_USER_PROXY="$PROXY_FILE" \
        xrdfs "$SERVER" stat /

    run_test "GSI: xrdcp upload 1MB with proxy" \
        env X509_USER_PROXY="$PROXY_FILE" \
        xrdcp --cadir "$CA_DIR" "$GSI_SRC" "${ROOT_URL}//it-gsi.dat"

    run_test "GSI: xrdcp download with proxy" \
        env X509_USER_PROXY="$PROXY_FILE" \
        xrdcp --cadir "$CA_DIR" "${ROOT_URL}//it-gsi.dat" "$GSI_DST"

    run_test "GSI: round-trip checksum" \
        check_roundtrip "$GSI_SRC" "$GSI_DST"

    run_test "GSI: xrdfs rm /it-gsi.dat" \
        xrdfs "$SERVER" rm /it-gsi.dat
else
    skip_test "GSI tests" "AUTH_MODE=$AUTH_MODE (need gsi or both)"
fi

# ── §11 Token auth ────────────────────────────────────────────────────────────
section "11. Bearer token authentication"

if [[ "$AUTH_MODE" == "token" ]] || [[ "$AUTH_MODE" == "both" ]]; then
    if [[ -n "${BEARER_TOKEN:-}" ]]; then
        TOK_SRC="${TMPDIR}/tok-src.dat"
        TOK_DST="${TMPDIR}/tok-dst.dat"
        gen_random_file "$TOK_SRC" $(( 1 * 1024 * 1024 ))

        run_test "token: xrdfs stat / with BEARER_TOKEN" \
            env BEARER_TOKEN="$BEARER_TOKEN" \
            xrdfs "$SERVER" stat /

        run_test "token: xrdcp upload 1MB" \
            env BEARER_TOKEN="$BEARER_TOKEN" \
            xrdcp "$TOK_SRC" "${ROOT_URL}//it-token.dat"

        run_test "token: xrdcp download" \
            env BEARER_TOKEN="$BEARER_TOKEN" \
            xrdcp "${ROOT_URL}//it-token.dat" "$TOK_DST"

        run_test "token: round-trip checksum" \
            check_roundtrip "$TOK_SRC" "$TOK_DST"

        run_test "token: xrdfs rm /it-token.dat" \
            xrdfs "$SERVER" rm /it-token.dat
    else
        skip_test "token auth tests" "no BEARER_TOKEN available (is jwks-server running?)"
    fi
else
    skip_test "token auth tests" "AUTH_MODE=$AUTH_MODE (need token or both)"
fi

# ── §12 Python XRootD bindings ────────────────────────────────────────────────
section "12. Python XRootD bindings"

if python3 -c "from XRootD import client" 2>/dev/null; then
    PY_DST="${TMPDIR}/py-dst.dat"

    run_test "python3 XRootD: DFS stat /" bash -c "python3 - <<'PYEOF'
from XRootD import client as xrd
fs = xrd.FileSystem('root://${SERVER}')
status, info = fs.stat('/')
assert status.ok, f'stat failed: {status}'
PYEOF"

    run_test "python3 XRootD: DFS ls /" bash -c "python3 - <<'PYEOF'
from XRootD import client as xrd
fs = xrd.FileSystem('root://${SERVER}')
status, listing = fs.dirlist('/', flags=xrd.flags.DirListFlags.STAT)
assert status.ok, f'dirlist failed: {status}'
assert listing is not None
PYEOF"

    run_test "python3 XRootD: copy small file" bash -c "
python3 - <<'PYEOF'
from XRootD import client as xrd
proc = xrd.CopyProcess()
proc.add_job('root://${SERVER}//hello.txt', '${PY_DST}')
status, results = proc.prepare()
assert status.ok, f'prepare failed: {status}'
status, results = proc.run()
assert status.ok, f'run failed: {status}'
PYEOF"
else
    skip_test "python3 XRootD bindings" "python3-xrootd not available"
fi

# ── §13 gfal2 (if installed) ──────────────────────────────────────────────────
section "13. gfal2 (Grid File Access Library)"

if command -v gfal-ls &>/dev/null; then
    run_test "gfal-ls root:// /" \
        gfal-ls "${ROOT_URL}//"

    GFAL_SRC="${TMPDIR}/gfal-src.dat"
    GFAL_DST="${TMPDIR}/gfal-dst.dat"
    gen_random_file "$GFAL_SRC" $(( 2 * 1024 * 1024 ))

    run_test "gfal-copy upload 2MB" \
        gfal-copy "file://$GFAL_SRC" "${ROOT_URL}//it-gfal.dat"

    run_test "gfal-copy download 2MB" \
        gfal-copy "${ROOT_URL}//it-gfal.dat" "file://$GFAL_DST"

    run_test "gfal: round-trip checksum" \
        check_roundtrip "$GFAL_SRC" "$GFAL_DST"

    run_test "gfal-rm /it-gfal.dat" \
        gfal-rm "${ROOT_URL}//it-gfal.dat"
else
    skip_test "gfal tests" "gfal-ls not installed"
fi

# ── §14 davix / WebDAV (if WEBDAV_URL is set) ────────────────────────────────
section "14. WebDAV via davix"

if [[ -n "${WEBDAV_URL:-}" ]] && command -v davix-ls &>/dev/null; then
    run_test "davix-ls WebDAV root" \
        davix-ls "$WEBDAV_URL/"

    DAVIX_SRC="${TMPDIR}/davix-src.dat"
    DAVIX_DST="${TMPDIR}/davix-dst.dat"
    gen_random_file "$DAVIX_SRC" $(( 1 * 1024 * 1024 ))

    run_test "davix-put 1MB" \
        davix-put "$DAVIX_SRC" "${WEBDAV_URL}/it-davix.dat"

    run_test "davix-get 1MB" \
        davix-get "${WEBDAV_URL}/it-davix.dat" "$DAVIX_DST"

    run_test "davix: round-trip checksum" \
        check_roundtrip "$DAVIX_SRC" "$DAVIX_DST"

    run_test "davix-del /it-davix.dat" \
        davix-del "${WEBDAV_URL}/it-davix.dat"
else
    skip_test "WebDAV tests" "WEBDAV_URL not set or davix not installed"
fi

# ── §15 Concurrent uploads ────────────────────────────────────────────────────
section "15. Concurrent transfers"

CONC_PIDS=()
CONC_RESULTS=()
CONC_N=4

for i in $(seq 1 $CONC_N); do
    conc_src="${TMPDIR}/conc-${i}.dat"
    gen_random_file "$conc_src" $(( 2 * 1024 * 1024 ))
    (
        xrdcp "${XRDCP_FLAGS[@]}" "$conc_src" "${ROOT_URL}//it-conc-${i}.dat" \
            &>/dev/null && echo 0 || echo 1
    ) > "${TMPDIR}/conc-result-${i}.txt" &
    CONC_PIDS+=($!)
done

for i in "${!CONC_PIDS[@]}"; do
    wait "${CONC_PIDS[$i]}" || true
done

conc_fail=0
for i in $(seq 1 $CONC_N); do
    rc=$(cat "${TMPDIR}/conc-result-${i}.txt" 2>/dev/null || echo 1)
    [[ "$rc" == "0" ]] || (( conc_fail++ )) || true
done

if [[ $conc_fail -eq 0 ]]; then
    run_test "$CONC_N concurrent uploads: all succeeded" true
else
    run_test "$CONC_N concurrent uploads: all succeeded" false
fi

# Clean up concurrent test files.
for i in $(seq 1 $CONC_N); do
    xrdfs "$SERVER" rm "/it-conc-${i}.dat" &>/dev/null || true
done

# ── §16 Cleanup ───────────────────────────────────────────────────────────────
section "16. Cleanup"

for path in /it-medium.dat /it-parallel.dat /it-large.dat; do
    xrdfs "$SERVER" rm "$path" &>/dev/null || true
done

# ── Summary ───────────────────────────────────────────────────────────────────
end_time=$(date +%s)
total_secs=$(( end_time - start_time ))
total=$(( PASS + FAIL + SKIP ))

echo "" >&2
echo "╔══════════════════════════════════════════════════════════════╗" >&2
printf "║  Results: \033[32m%d passed\033[0m  \033[31m%d failed\033[0m  \033[33m%d skipped\033[0m  (%d total, %ds)%*s║\n" \
    "$PASS" "$FAIL" "$SKIP" "$total" "$total_secs" 0 "" >&2
echo "╚══════════════════════════════════════════════════════════════╝" >&2

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo "" >&2
    echo "Failed tests:" >&2
    for e in "${ERRORS[@]}"; do
        echo "  ✗ $e" >&2
    done
fi

# ── JUnit XML output ──────────────────────────────────────────────────────────
JUNIT_FILE="$RESULTS_DIR/integration-tests.xml"
cat > "$JUNIT_FILE" <<XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="xrootd-integration" tests="${total}" failures="${FAIL}" skipped="${SKIP}" time="${total_secs}">
${JUNIT_CASES}</testsuite>
XMLEOF
echo "" >&2
echo "JUnit XML written to $JUNIT_FILE" >&2

[[ $FAIL -eq 0 ]]
