#!/usr/bin/env bash
# run_load_test.sh — start servers, run load tests, stop servers
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ Isolated under /tmp/xrd-load — does NOT collide with the pytest suite.   │
# └─────────────────────────────────────────────────────────────────────────┘
# This sweep is fully self-contained under /tmp/xrd-load: it generates its own
# PKI/CA/CRL, JWKS, and test data there, and runs its perf servers on a distinct
# port range (12093/12094/12793/...).  The pytest functional suite lives entirely
# under a SEPARATE root (/tmp/xrd-test) on its own fixed ports
# (11094-11097/8443/8444/9001).  The two no longer share certificates, data, or
# ports, so this load sweep and the functional suite can coexist on the box.
# (Historically both used /tmp/xrd-test, so a load run would `rm -rf` the PKI out
# from under the running GSI fleet mid-handshake — that collision is now gone.)
#
# Usage:
#   ./tests/run_load_test.sh [nginx|xrootd|both] [--file load_1g.bin] [--concurrency 1,8,32,64,128,200]
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 128 --suite root-gsi
#   ./tests/run_load_test.sh both --file load_1g.bin --concurrency 200 --suite root-gsi --read-sink devnull
#
#   # read + write together (write suites upload load_write_* and clean up per level):
#   ./tests/run_load_test.sh both --suite root-gsi --mode both --concurrency 1,8,32 --read-sink devnull
#   ./tests/run_load_test.sh both --suite root-gsi --mode write --concurrency 1
#   NOTE: write peak disk = max_concurrency × file_size (e.g. 128 × 1 GiB = 128 GiB);
#         files land in /tmp/xrd-load/data and are removed after each level.
#
#   # fair data-plane comparison — same TLS posture on BOTH servers:
#   ./tests/run_load_test.sh both --suite root-gsi --data-tls off --concurrency 1  # cleartext (default)
#   ./tests/run_load_test.sh both --suite root-gsi --data-tls on  --concurrency 1  # TLS both sides
#   (default off = apples-to-apples; without it the GSI suite ran nginx-TLS vs xrootd-cleartext.)
#
# Requires:
#   • nginx built with nginx-xrootd module (./nginx -v should show the module)
#   • xrootd 5.x installed (/usr/bin/brix)
#   • Test PKI already generated under /tmp/xrd-load/pki/
#   • Python 3 with XRootD python bindings (from xrootd package)
#
# The script:
#   1. Creates /tmp/xrd-perf-test/  (nginx work dir)
#      Creates /tmp/xrd-perf-xrd/   (xrootd work dir)
#   2. Starts the selected server(s)
#   3. Waits for them to be ready
#   4. Runs load_test.py
#   5. Stops the servers
#   6. Prints a summary and optionally saves JSON


set -euo pipefail
set -x
setup_pki() {
    log "Generating test PKI under /tmp/xrd-load/pki ..."
    local CADIR=/tmp/xrd-load/pki/ca
    local SERVERDIR=/tmp/xrd-load/pki/server
    local USERDIR=/tmp/xrd-load/pki/user
    # Wipe any existing test PKI to ensure a fresh, self-contained run.
    rm -rf /tmp/xrd-load/pki || true
    mkdir -p "$CADIR" "$SERVERDIR" "$USERDIR"

    # CA key/cert (fresh)
    openssl genrsa -out "$CADIR/ca.key" 2048
    chmod 400 "$CADIR/ca.key"
    openssl req -x509 -new -nodes -key "$CADIR/ca.key" -sha256 -days 3650 \
        -subj "/C=XX/O=Test/CN=Test CA" -out "$CADIR/ca.pem"

    # Always generate a signing-policy file for the CA
    local CA_SUBJ="/C=XX/O=Test/CN=Test CA"
    cat > "$CADIR/signing-policy" <<EOF
access_id_CA   X509   '$CA_SUBJ'
pos_rights     globus CA:sign
cond_subjects  globus  '*'
EOF
    chmod 644 "$CADIR/signing-policy"

    # Create both new and old-style OpenSSL subject hash symlinks
    local NEW_HASH
    local OLD_HASH
    NEW_HASH=$(openssl x509 -in "$CADIR/ca.pem" -noout -subject_hash)
    OLD_HASH=$(openssl x509 -in "$CADIR/ca.pem" -noout -subject_hash_old 2>/dev/null || true)
    ln -sf "$CADIR/ca.pem" "$CADIR/${NEW_HASH}.0"
    ln -sf "$CADIR/signing-policy" "$CADIR/${NEW_HASH}.signing_policy"
    if [[ -n "$OLD_HASH" ]]; then
        ln -sf "$CADIR/ca.pem" "$CADIR/${OLD_HASH}.0"
        ln -sf "$CADIR/signing-policy" "$CADIR/${OLD_HASH}.signing_policy"
    fi

    # Server key/cert (fresh)
    openssl genrsa -out "$SERVERDIR/host.key" 2048
    openssl req -new -key "$SERVERDIR/host.key" -subj "/C=XX/O=Test/CN=localhost" -out "$SERVERDIR/host.csr"
    openssl x509 -req -in "$SERVERDIR/host.csr" -CA "$CADIR/ca.pem" -CAkey "$CADIR/ca.key" -CAcreateserial \
        -out "$SERVERDIR/hostcert.pem" -days 3650 -sha256
    ln -sf "$SERVERDIR/host.key" "$SERVERDIR/hostkey.pem"

    # User key/cert (fresh)
    openssl genrsa -out "$USERDIR/user.key" 2048
    openssl req -new -key "$USERDIR/user.key" -subj "/C=XX/O=Test/CN=Test User" -out "$USERDIR/user.csr"
    openssl x509 -req -in "$USERDIR/user.csr" -CA "$CADIR/ca.pem" -CAkey "$CADIR/ca.key" -CAcreateserial \
        -out "$USERDIR/usercert.pem" -days 3650 -sha256

    # User proxy (RFC3820, proper chain, no passphrase)
    openssl genrsa -out "$USERDIR/proxy.key" 2048
    openssl req -new -key "$USERDIR/proxy.key" -subj "/C=XX/O=Test/CN=Test User/CN=proxy" -out "$USERDIR/proxy.csr"
    openssl x509 -req -in "$USERDIR/proxy.csr" -CA "$USERDIR/usercert.pem" -CAkey "$USERDIR/user.key" -CAcreateserial \
        -out "$USERDIR/proxy_cert.pem" -days 365 -sha256 -extfile <(printf "[proxy]\nbasicConstraints=CA:FALSE\nproxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:1\n") -extensions proxy

    # Concatenate proxy cert, proxy key, EEC cert, EEC key (no passphrase)
    cat "$USERDIR/proxy_cert.pem" "$USERDIR/proxy.key" "$USERDIR/usercert.pem" "$USERDIR/user.key" > "$USERDIR/proxy_std.pem"
    chmod 400 "$USERDIR/proxy_std.pem"

    # Generate a CRL that revokes the test user cert so CRL-based tests can run.
    if command -v python3 >/dev/null 2>&1 && [[ -f "$ROOT_DIR/utils/make_crl.py" ]]; then
        log "Generating CRL via utils/make_crl.py"
        python3 "$ROOT_DIR/utils/make_crl.py" "/tmp/xrd-load/pki" || log "make_crl.py failed"
    else
        log "utils/make_crl.py not found or python3 missing; skipping CRL generation"
    fi
}

setup_test_data() {
    # Create data and PKI directories
    mkdir -p /tmp/xrd-load/data
    mkdir -p /tmp/xrd-load/pki
    mkdir -p /tmp/xrd-load/pki/ca
    mkdir -p /tmp/xrd-load/pki/user
    mkdir -p /tmp/xrd-load/pki/server
    mkdir -p /tmp/xrd-load/tokens

    # Generate 1GB test file if missing
    if [[ ! -f /tmp/xrd-load/data/load_1g.bin ]]; then
        log "Generating 1GB test file at /tmp/xrd-load/data/load_1g.bin ..."
        dd if=/dev/urandom of=/tmp/xrd-load/data/load_1g.bin bs=1M count=1024 status=progress
    else
        log "1GB test file already exists."
    fi

    # Always regenerate PKI/CA/CRL to keep the test run self-contained
    log "Regenerating test PKI and CRL for a clean test run..."
    setup_pki

    # Self-contained JWKS: nginx.perf.conf declares a token block that requires
    # /tmp/xrd-load/tokens/jwks.json to exist for `nginx -t` to pass, even though
    # the root:// suites never present a token.  Generate it here so the sweep
    # does not depend on the pytest suite having populated a shared tokens dir.
    if [[ ! -f /tmp/xrd-load/tokens/jwks.json ]]; then
        log "Generating token JWKS at /tmp/xrd-load/tokens ..."
        python3 "$ROOT_DIR/utils/make_token.py" init /tmp/xrd-load/tokens \
            >/dev/null 2>&1 || log "make_token.py init failed (token suites will skip)"
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

TARGET="${1:-nginx}"
shift || true

# Optional args forwarded to load_test.py
EXTRA_ARGS=("$@")

NGINX_BIN="${NGINX_BIN:-/tmp/nginx-1.28.3/objs/nginx}"
BRIX_BIN="${BRIX_BIN:-/usr/bin/brix}"
AUTHDB_FILE="/tmp/xrd-perf-xrd/authdb"

NGINX_PERF_DIR="/tmp/xrd-perf-test"
XRD_PERF_DIR="/tmp/xrd-perf-xrd"

# Generated (templated) configs — start the servers from these, not the static
# sources, so --data-tls can toggle the data-plane TLS posture symmetrically.
NGINX_GEN_CONF="$NGINX_PERF_DIR/nginx.gen.conf"
XRD_GEN_CONF="$XRD_PERF_DIR/brix.gen.conf"

# Second official-xrootd instance: anonymous root:// on 12093 (no GSI), so the
# anon read/write suites have a real xrootd peer to compare against (the primary
# perf.conf only serves GSI on 12094).  Separate admin/pid paths so the two
# daemons do not collide.
XRD_ANON_PERF_DIR="/tmp/xrd-perf-xrd-anon"
XRD_ANON_GEN_CONF="$XRD_ANON_PERF_DIR/brix.anon.gen.conf"

# --data-tls {on,off}: set the SAME data-stream TLS posture on BOTH servers for a
# fair data-plane comparison. Default off = cleartext-vs-cleartext (apples-to-
# apples). The old default compared nginx-TLS (brix_tls on) vs xrootd-cleartext,
# which is not like-for-like. Parsed out of the forwarded args so load_test.py
# never sees it.
DATA_TLS="off"
FWD_ARGS=()
_ai=0
while [[ $_ai -lt ${#EXTRA_ARGS[@]} ]]; do
    case "${EXTRA_ARGS[$_ai]}" in
        --data-tls)    _ai=$((_ai + 1)); DATA_TLS="${EXTRA_ARGS[$_ai]:-off}" ;;
        --data-tls=*)  DATA_TLS="${EXTRA_ARGS[$_ai]#*=}" ;;
        *)             FWD_ARGS+=("${EXTRA_ARGS[$_ai]}") ;;
    esac
    _ai=$((_ai + 1))
done
case "$DATA_TLS" in on|off) ;; *) log "bad --data-tls '$DATA_TLS' (use on|off)"; exit 2 ;; esac

# Generate the templated configs from the static sources.
gen_configs() {
    mkdir -p "$NGINX_PERF_DIR"/{logs,tmp} "$XRD_PERF_DIR"/logs
    local ntls="off"
    [[ "$DATA_TLS" == "on" ]] && ntls="on"
    # nginx: toggle the GSI block's data-stream TLS (the only `brix_tls`
    # directive in the file; the roots:// blocks use nginx-level `ssl`).
    sed "s/brix_tls on;/brix_tls ${ntls};/" \
        "$SCRIPT_DIR/nginx.perf.conf" > "$NGINX_GEN_CONF"
    # xrootd: cleartext data by default; add data-phase TLS for --data-tls on so
    # the native side encrypts too (parity with nginx brix_tls on).
    cp "$SCRIPT_DIR/brix.perf.conf" "$XRD_GEN_CONF"
    if [[ "$DATA_TLS" == "on" ]]; then
        cat >> "$XRD_GEN_CONF" <<EOF

# --data-tls on: require TLS for the root:// data phase (parity with nginx)
xrd.tls   /tmp/xrd-load/pki/server/hostcert.pem /tmp/xrd-load/pki/server/hostkey.pem
xrd.tlsca certdir /tmp/xrd-load/pki/ca
xrootd.tls data
EOF
    fi

    # Anonymous xrootd on 12093 — no security layer, no authz (matches nginx
    # `brix_auth none`).  Same namespace as the GSI instance so
    # root://host//load_1g.bin resolves identically.
    mkdir -p "$XRD_ANON_PERF_DIR"/{logs,admin,run}
    cat > "$XRD_ANON_GEN_CONF" <<EOF
# Generated by run_load_test.sh — official xrootd anonymous instance.
all.adminpath $XRD_ANON_PERF_DIR/admin
all.pidpath   $XRD_ANON_PERF_DIR/run
oss.localroot /tmp/xrd-load/data
all.export /
xrd.port 12093
xrd.network nodnr
xrd.allow host *
xrd.sched mint 8 avlt 16 maxt 256 idle 780
EOF
    if [[ "$DATA_TLS" == "on" ]]; then
        cat >> "$XRD_ANON_GEN_CONF" <<EOF
xrd.tls   /tmp/xrd-load/pki/server/hostcert.pem /tmp/xrd-load/pki/server/hostkey.pem
xrd.tlsca certdir /tmp/xrd-load/pki/ca
xrootd.tls data
EOF
    fi
    log "data-plane TLS posture: --data-tls=$DATA_TLS (nginx brix_tls=$ntls)"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo "  [run_load_test] $*" >&2; }

wait_port() {
    local host="${1}" port="${2}" label="${3}" retries=30
    while ! nc -z "$host" "$port" 2>/dev/null; do
        retries=$((retries - 1))
        if [[ $retries -le 0 ]]; then
            log "ERROR: $label did not come up on $host:$port"
            return 1
        fi
        sleep 0.5
    done
    log "$label ready on port $port"
}

# ---------------------------------------------------------------------------
# Pre-flight: clear stale/orphan perf nginx before a run so a previous crashed
# or incompletely-stopped run cannot poison this one.  nginx uses SO_REUSEPORT,
# so an ungraceful exit can leave worker processes alive still holding the listen
# sockets on the perf ports.  Each orphan keeps running every module timer (the
# FRM stage drain, the health-check scan, CMS/keepalive heartbeats), stealing CPU
# and scheduler time and skewing the benchmark's tail latency.  Both checks are
# scoped to the perf port range and the perf master's own children, so they never
# touch the shared dev test fleet running on other ports.
# ---------------------------------------------------------------------------

PERF_PORT_LO=12790
PERF_PORT_HI=12799

reap_perf_orphans() {
    # 1. Normal stop via the pidfile + process group (handles the common case).
    stop_nginx
    # 2. Hunt anything still bound to the perf ports — reuseport orphans whose
    #    master is already gone, so the pidfile/group reap above cannot find them.
    local pids
    pids="$(ss -tlnHp "sport >= $PERF_PORT_LO and sport <= $PERF_PORT_HI" 2>/dev/null \
            | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' ')"
    if [[ -n "${pids// /}" ]]; then
        log "pre-flight: reaping stale process(es) on perf ports" \
            "$PERF_PORT_LO-$PERF_PORT_HI: $pids"
        # shellcheck disable=SC2086
        kill -KILL $pids 2>/dev/null || true
        sleep 0.5
    fi
    # 3. Refuse to start if the ports are still held — the run would be invalid.
    local n
    n="$(ss -tlnH "sport >= $PERF_PORT_LO and sport <= $PERF_PORT_HI" 2>/dev/null | wc -l)"
    if [[ "$n" -gt 0 ]]; then
        log "ERROR: perf ports $PERF_PORT_LO-$PERF_PORT_HI still in use after the" \
            "orphan reap; a stale process is holding them and the benchmark would" \
            "be poisoned. Investigate:  ss -tlnp | grep -E ':1279'"
        return 1
    fi
    return 0
}

# Post-start sanity: the freshly-started perf master must own exactly the
# configured number of workers.  A mismatch means orphan workers survived (each
# runs every module timer) — surfaced as a WARN so the operator can discard the
# run rather than silently trust skewed numbers.
verify_worker_count() {
    local pidfile="$NGINX_PERF_DIR/logs/nginx.pid"
    [[ -f "$pidfile" ]] || { log "WARN: no perf nginx pidfile — cannot verify workers"; return 0; }
    local master expect actual
    master="$(cat "$pidfile" 2>/dev/null)"
    [[ -n "$master" ]] || return 0
    # `|| true`: with `worker_processes auto` the grep finds no digits and exits
    # non-zero, which under `set -euo pipefail` would abort the whole sweep. The
    # next line already falls back to nproc when expect is empty.
    expect="$(grep -oE '^[[:space:]]*worker_processes[[:space:]]+[0-9]+' \
              "$NGINX_GEN_CONF" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
    [[ -n "$expect" ]] || expect="$(nproc 2>/dev/null || echo 1)"   # 'auto' → all cores
    actual="$(pgrep -P "$master" 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$actual" -ne "$expect" ]]; then
        log "WARN: perf nginx has $actual worker(s) but expected $expect" \
            "(worker_processes) — possible orphan contamination; benchmark" \
            "numbers may be skewed."
    else
        log "pre-flight OK: perf worker count == expected ($expect)"
    fi
}

# ---------------------------------------------------------------------------
# nginx-xrootd
# ---------------------------------------------------------------------------

start_nginx() {
    log "Starting nginx-xrootd (perf config)..."
    mkdir -p "$NGINX_PERF_DIR"/{logs,tmp}

    # Pre-flight: clear any orphaned perf nginx left by a prior crashed run.
    reap_perf_orphans || return 1

    # Validate + launch from the generated (TLS-templated) config.
    "$NGINX_BIN" -c "$NGINX_GEN_CONF" \
                 -p "$NGINX_PERF_DIR" \
                 -t 2>&1 | grep -v "^$" >&2 || {
        log "nginx config test failed — is the module built?"
        return 1
    }

    "$NGINX_BIN" -c "$NGINX_GEN_CONF" \
                 -p "$NGINX_PERF_DIR"

    wait_port localhost 12795 "nginx XRootD+GSI"
    wait_port localhost 12796 "nginx XRootD+TLS"
    wait_port localhost 12792  "nginx WebDAV+GSI"
    log "nginx-xrootd started (pid: $(cat $NGINX_PERF_DIR/logs/nginx.pid))"
    verify_worker_count   # assert no orphan workers contaminate the run
}

stop_nginx() {
    local pidfile="$NGINX_PERF_DIR/logs/nginx.pid"
    local pid=""
    [[ -f "$pidfile" ]] && pid="$(cat "$pidfile" 2>/dev/null)"
    if [[ -n "$pid" ]]; then
        log "Stopping nginx (master $pid)..."
        # Graceful first.
        "$NGINX_BIN" -c "$NGINX_GEN_CONF" -p "$NGINX_PERF_DIR" -s quit 2>/dev/null || true
        # Wait up to ~3s for a clean exit.
        local i
        for i in $(seq 1 12); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
        # Reap the master AND its orphan-prone reuseport workers via the process
        # group. nginx daemonizes with setsid(), so the master is its own
        # process-group leader (PGID == master pid) and `kill -- -PGID` takes the
        # workers with it. `-s quit` alone leaves reuseport workers holding the
        # listen sockets across runs (they accumulate and poison later runs).
        kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Official xrootd
# ---------------------------------------------------------------------------

start_xrootd() {
    log "Starting official xrootd (perf config)..."
    # Pre-launch checks
    if [[ ! -x "$BRIX_BIN" ]]; then
        log "ERROR: xrootd binary not found or not executable at $BRIX_BIN"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_DIR/brix.perf.conf" ]]; then
        log "ERROR: xrootd config $SCRIPT_DIR/brix.perf.conf missing"
        exit 1
    fi
    mkdir -p "$XRD_PERF_DIR"/{logs,data,admin,run}
    if [[ ! -d /tmp/xrd-load/data ]]; then
        log "ERROR: Test data directory /tmp/xrd-load/data missing"
        exit 1
    fi
    if [[ ! -d /tmp/xrd-load/pki/ca ]]; then
        log "ERROR: CA directory /tmp/xrd-load/pki/ca missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-load/pki/ca/ca.pem ]]; then
        log "ERROR: CA certificate /tmp/xrd-load/pki/ca/ca.pem missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-load/pki/user/usercert.pem ]]; then
        log "ERROR: User certificate /tmp/xrd-load/pki/user/usercert.pem missing"
        exit 1
    fi
    if [[ ! -f /tmp/xrd-load/pki/user/user.key ]]; then
        log "ERROR: User key /tmp/xrd-load/pki/user/user.key missing"
        exit 1
    fi
    # Symlink the test data into the xrootd data dir
    [[ -d "$XRD_PERF_DIR/data/xrd-test" ]] || \
        ln -sf /tmp/xrd-load/data "$XRD_PERF_DIR/data/xrd-test"

    # Minimal authdb: allow authenticated users r/w on /
    # rwld: read + write(+create) + lookup + delete — write perms are required
    # for the write/stress suites (load_test.py --mode write|both); the read-only
    # suites only exercise r/l.
    cat > "$AUTHDB_FILE" <<'AUTHDB'
all.allow host any
u * / rwld
AUTHDB

    local xrd_cmd=("$BRIX_BIN" -c "$XRD_GEN_CONF" -l "$XRD_PERF_DIR/logs/brix.log" -n perf -b)
    log "xrootd launch command: ${xrd_cmd[*]}"
    # Capture stdout/stderr for debug
    "${xrd_cmd[@]}" > "$XRD_PERF_DIR/logs/brix.debug.log" 2>&1 &
    # xrootd -b double-forks; the parent exits immediately, so a fixed
    # `sleep 1 && ps | grep` race fails under load even though the daemon is
    # coming up fine. wait_port (polls the actual listen socket) is the real
    # readiness authority — use it, and only error if the data port never binds.
    if ! wait_port localhost 12094 "xrootd GSI"; then
        log "ERROR: xrootd failed to bind 12094. See xrootd.debug.log / xrootd.log:"
        cat "$XRD_PERF_DIR/logs/brix.debug.log" >&2 2>/dev/null || true
        cat "$XRD_PERF_DIR/logs/brix.log"       >&2 2>/dev/null || true
        exit 1
    fi
    # XrdHttp (12443) is not needed for the root:// suites — wait best-effort so
    # a missing/failed XrdHttp plugin does not abort a root-only benchmark.
    wait_port localhost 12443 "xrootd HTTPS/WebDAV" || \
        log "note: xrootd 12443 (XrdHttp) not up — fine for root:// suites"

    # Second instance: anonymous xrootd on 12093 for the root-anon suites.
    log "Starting official xrootd (anon, port 12093)..."
    local xrd_anon_cmd=("$BRIX_BIN" -c "$XRD_ANON_GEN_CONF" \
        -l "$XRD_ANON_PERF_DIR/logs/brix.log" -n perfanon -b)
    log "xrootd anon launch command: ${xrd_anon_cmd[*]}"
    "${xrd_anon_cmd[@]}" > "$XRD_ANON_PERF_DIR/logs/brix.debug.log" 2>&1 &
    if ! wait_port localhost 12093 "xrootd anon"; then
        log "ERROR: xrootd anon failed to bind 12093. See logs:"
        cat "$XRD_ANON_PERF_DIR/logs/brix.debug.log" >&2 2>/dev/null || true
        cat "$XRD_ANON_PERF_DIR/logs/brix.log"       >&2 2>/dev/null || true
        exit 1
    fi
    log "xrootd started"
}

stop_xrootd() {
    local pidfile
    pidfile="$(find "$XRD_PERF_DIR/logs" -name "*.pid" 2>/dev/null | head -1)"
    if [[ -n "$pidfile" && -f "$pidfile" ]]; then
        pid="$(cat "$pidfile")"
        log "Stopping xrootd (pid $pid)..."
        kill "$pid" 2>/dev/null || true
        sleep 2
    fi
    # Both the GSI (-n perf) and anon (-n perfanon) instances match this; the
    # fallback also covers a missing/stale pidfile.
    pkill -f "xrootd.*-n perf" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Cleanup on exit
# ---------------------------------------------------------------------------

cleanup() {
    [[ "$TARGET" == nginx || "$TARGET" == both ]] && stop_nginx  || true
    [[ "$TARGET" == xrootd || "$TARGET" == both ]] && stop_xrootd || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


# Setup test data and PKI
setup_test_data

# Generate the TLS-templated configs (depends on PKI from setup_test_data).
gen_configs

log "Target: $TARGET"
log "Extra args: ${FWD_ARGS[*]:-none}"

[[ "$TARGET" == nginx || "$TARGET" == both ]]   && start_nginx
[[ "$TARGET" == xrootd || "$TARGET" == both ]]  && start_xrootd

log "Running load_test.py ..."
python3 "$SCRIPT_DIR/load_test.py" \
    --target "$TARGET" \
    --json "/tmp/load_test_results.json" \
    "${FWD_ARGS[@]}"

log "Load test complete. Results at /tmp/load_test_results.json"
