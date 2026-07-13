# tests/lib/fwd_matrix.sh — credential-forwarding matrix helper library.
#
# Sourced (never executed) by the three driver scripts:
#   run_fwd_brix_xrootd.sh   (pairing A: brix-front  -> xrootd-back)
#   run_fwd_xrootd_brix.sh   (pairing B: xrootd-front -> brix-back)
#   run_fwd_brix_brix.sh     (pairing C: brix-front  -> brix-back)
#
# Design: docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md
#
# Proves GSI (x509 proxy) and WLCG-token (JWT) FORWARDING across a two-hop
# front->backend topology.  Each cell:
#   * positive: userA two-hop PUT+GET is byte-exact AND the backend's own log
#     shows userA's identity (DN / token sub), not the front's service identity;
#   * negative: userB (no backend credential) is denied on the backend leg and
#     no bytes land on the backend store.
#
# Five honest outcomes per cell (spec §3): PASS FAIL GAP UNSUPPORTED SKIP.
#
# SAFETY: every node uses ports from the reserved 21960-21999 block; teardown
# kills ONLY PIDs recorded in this run's node registry (no broad pkill, no
# manage_test_servers.sh, no writes under /tmp/xrd-test beyond reading the PKI).
#
# No side effects on source — this file only defines functions + a few
# read-only constants.

# ---------------------------------------------------------------------------
# Constants / environment
# ---------------------------------------------------------------------------
FWD_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# NOTE: `NGINX` is a RESERVED nginx env var (a list of inherited socket fds for
# hot-reload).  We must NOT let a `NGINX=<binary-path>` exported by the caller
# reach the child nginx process — it would be parsed as socket fds and emerg.
# So the harness keeps the binary path in NGINX_BIN (honoring a legacy `NGINX`
# value only as a path fallback), and every spawn runs `env -u NGINX ...`.
NGINX_BIN="${NGINX_BIN:-${NGINX:-/tmp/nginx-1.28.3/objs/nginx}}"
XROOTD_BIN="${XROOTD_BIN:-${BRIX_BIN:-/usr/bin/xrootd}}"
TEST_ROOT="${TEST_ROOT:-/tmp/xrd-test}"
BRIX_XRDCP="$FWD_HERE/client/bin/xrdcp"
BRIX_XRDFS="$FWD_HERE/client/bin/xrdfs"
SYS_XRDCP="$(command -v xrdcp 2>/dev/null || true)"

# Shared reserved port block (docs/10-reference/test-fleet-ports.md). Each
# driver picks two ports from the pool via fwd_port().
FWD_PORT_BASE="${FWD_PORT_BASE:-21960}"
FWD_PORT_NEXT="$FWD_PORT_BASE"

# PKI material (read-only reuse of the shared test PKI).
CA_CERT="$TEST_ROOT/pki/ca/ca.pem"
CA_DIR="$TEST_ROOT/pki/ca"
CA_KEY="$TEST_ROOT/pki/ca/ca.key"
SERVER_CERT="$TEST_ROOT/pki/server/hostcert.pem"
SERVER_KEY="$TEST_ROOT/pki/server/hostkey.pem"

# Per-run scratch prefix + node/temp registries for pidfile-scoped teardown.
FWD_PFX=""
FWD_NODE_PIDS=()      # pidfiles of started nginx/xrootd nodes
FWD_TOK_DIR=""        # token signing authority dir (make_token init)
FWD_OIDC_PID=""       # PID of the local HTTPS OIDC discovery server (mint_token)

# ---------------------------------------------------------------------------
# Outcome bookkeeping — drivers read FWD_RESULTS[] and FWD_ANY_FAIL.
# ---------------------------------------------------------------------------
FWD_RESULTS=()        # "<pairing> <hop1> <hop2> <cred>|<OUTCOME>|<detail>"
FWD_ANY_FAIL=0

fwd_record() {   # <cellkey> <outcome> [detail]
    local key="$1" outcome="$2" detail="${3:-}"
    FWD_RESULTS+=("$key|$outcome|$detail")
    case "$outcome" in
        FAIL) FWD_ANY_FAIL=1 ;;
    esac
    printf '  %-22s %-30s %s\n' "$outcome" "$key" "$detail"
}

# Allocate the next free port into the named variable (NOT via command
# substitution — that runs in a subshell and would never advance the counter).
# Usage: fwd_port bport   ->   sets $bport and advances FWD_PORT_NEXT.
fwd_port() { printf -v "$1" '%d' "$FWD_PORT_NEXT"; FWD_PORT_NEXT=$((FWD_PORT_NEXT + 1)); }

# Per-cell teardown: stop only the nodes started since the last mark so ports
# free between cells (prevents accumulation / bind clashes on long matrices).
FWD_CELL_MARK=0
fwd_cell_begin() { FWD_CELL_MARK=${#FWD_NODE_PIDS[@]}; }
fwd_cell_end() {
    local i pf
    for ((i=FWD_CELL_MARK; i<${#FWD_NODE_PIDS[@]}; i++)); do
        pf="${FWD_NODE_PIDS[$i]}"
        [ -f "$pf" ] && kill "$(cat "$pf" 2>/dev/null)" 2>/dev/null
    done
    sleep 0.4
    for ((i=FWD_CELL_MARK; i<${#FWD_NODE_PIDS[@]}; i++)); do
        pf="${FWD_NODE_PIDS[$i]}"
        [ -f "$pf" ] && kill -9 "$(cat "$pf" 2>/dev/null)" 2>/dev/null
    done
    FWD_NODE_PIDS=("${FWD_NODE_PIDS[@]:0:$FWD_CELL_MARK}")
}

# ---------------------------------------------------------------------------
# Environment preflight — returns 0 with FWD_PFX set on success, else prints
# a SKIP line and returns non-zero.  `need_xrootd` gates on the stock binary.
# ---------------------------------------------------------------------------
fwd_setup() {   # <scratch-name> [need_xrootd]
    local name="$1" need_xrootd="${2:-0}"
    FWD_PFX="$(mktemp -d "/tmp/fwd_${name}.XXXXXX")" || return 1
    local n
    for n in "$NGINX_BIN" "$BRIX_XRDCP" "$BRIX_XRDFS"; do
        [ -x "$n" ] || { echo "SKIP: missing $n"; return 1; }
    done
    if [ "$need_xrootd" = 1 ] && [ ! -x "$XROOTD_BIN" ]; then
        echo "SKIP: stock xrootd ($XROOTD_BIN) not present — pairing requires it"
        return 2
    fi
    return 0
}

fwd_cleanup() {
    local pf
    for pf in "${FWD_NODE_PIDS[@]}"; do
        [ -f "$pf" ] && kill "$(cat "$pf" 2>/dev/null)" 2>/dev/null
    done
    sleep 0.3
    for pf in "${FWD_NODE_PIDS[@]}"; do
        [ -f "$pf" ] && kill -9 "$(cat "$pf" 2>/dev/null)" 2>/dev/null
    done
    # The local HTTPS OIDC discovery server (mint_token) is a bare PID, not a
    # node pidfile — kill it explicitly.
    [ -n "$FWD_OIDC_PID" ] && kill "$FWD_OIDC_PID" 2>/dev/null
    [ -n "$FWD_PFX" ] && rm -rf "$FWD_PFX"
}

# ---------------------------------------------------------------------------
# mint_pki — ensure the shared PKI exists, then mint the three DISTINCT proxy
# identities (userA / userB / svc) this suite needs.  Sets:
#   PROXY_A  PROXY_B  SVC_PROXY   (RFC-3820 proxy PEMs, distinct DNs)
#   A_CN     B_CN     SVC_CN      (the leaf CN strings, for log matching)
# ---------------------------------------------------------------------------
A_CN="Fwd User A"
B_CN="Fwd User B"
SVC_CN="Fwd Service"
PROXY_A=""; PROXY_B=""; SVC_PROXY=""

mint_pki() {
    local need=0
    [ -f "$CA_CERT" ] || need=1
    [ -f "$CA_KEY" ]  || need=1
    if [ "$need" = 1 ]; then
        ( cd "$FWD_HERE/tests" && PYTHONPATH=. python3 -c \
            "import pki_helpers; pki_helpers.blitz_test_pki()" ) \
            >"$FWD_PFX/pki.log" 2>&1 \
            || { echo "SKIP: PKI provisioning failed"; cat "$FWD_PFX/pki.log"; return 1; }
    fi
    [ -f "$CA_KEY" ] || { echo "SKIP: CA key not found ($CA_KEY)"; return 1; }

    local minter="$FWD_HERE/tests/lib/fwd_mint_proxy.py"
    PROXY_A="$FWD_PFX/proxy_a.pem"
    PROXY_B="$FWD_PFX/proxy_b.pem"
    SVC_PROXY="$FWD_PFX/proxy_svc.pem"
    python3 "$minter" "$CA_CERT" "$CA_KEY" "$A_CN"   "$PROXY_A"  >>"$FWD_PFX/pki.log" 2>&1 || { echo "SKIP: userA proxy mint failed"; return 1; }
    python3 "$minter" "$CA_CERT" "$CA_KEY" "$B_CN"   "$PROXY_B"  >>"$FWD_PFX/pki.log" 2>&1 || { echo "SKIP: userB proxy mint failed"; return 1; }
    python3 "$minter" "$CA_CERT" "$CA_KEY" "$SVC_CN" "$SVC_PROXY" >>"$FWD_PFX/pki.log" 2>&1 || { echo "SKIP: svc proxy mint failed"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------
# mint_token — a local JWKS authority (make_token init) issuing userA/userB
# JWTs with storage.read+storage.modify scopes.  Sets:
#   TOK_JWKS   (jwks.json path — backend origin trusts this issuer)
#   TOKEN_A    TOKEN_B   (JWT files; distinct `sub` claims)
#   TOK_ISSUER TOK_AUD   (issuer + audience the origin must match)
#   A_SUB      B_SUB     (the sub claims, for backend-log matching)
# ---------------------------------------------------------------------------
A_SUB="fwd-user-a"
B_SUB="fwd-user-b"
# The token issuer is a LOCAL HTTPS OIDC discovery endpoint (mint_token stands it
# up).  Stock xrootd ztn + libXrdAccSciTokens rejects an http:// issuer and, for a
# valid token, fetches the issuer's ``.well-known/openid-configuration`` + JWKS
# over TLS — so the issuer MUST be https://localhost:<oidc-port>.  The brix front
# (pairings B/C) validates against the local jwks FILE by iss-string match (it
# does NOT fetch), so it only needs TOK_ISSUER to equal the string in the tokens.
FWD_OIDC_PORT="${FWD_OIDC_PORT:-21999}"
TOK_ISSUER="https://localhost:${FWD_OIDC_PORT}"
TOK_AUD="nginx-xrootd"
TOK_JWKS=""; TOKEN_A=""; TOKEN_B=""

# start_oidc_server — publish the signing authority's discovery document + JWKS
# over HTTPS (test hostcert, localhost/127.0.0.1 SANs) so a stock token origin can
# fetch keys for issuer https://localhost:FWD_OIDC_PORT.  Records the PID in
# FWD_OIDC_PID; fwd_cleanup kills it.  Returns 0 once the endpoint answers.
start_oidc_server() {
    local oidc_dir="$FWD_PFX/oidc"
    mkdir -p "$oidc_dir/.well-known"
    cat > "$oidc_dir/.well-known/openid-configuration" <<EOF
{"issuer":"${TOK_ISSUER}","jwks_uri":"${TOK_ISSUER}/jwks.json"}
EOF
    cp "$TOK_JWKS" "$oidc_dir/jwks.json"

    # Free the OIDC port from any prior run (scoped: this exact port only).
    fuser -k "${FWD_OIDC_PORT}/tcp" 2>/dev/null || true
    sleep 0.3
    python3 "$FWD_HERE/tests/lib/fwd_oidc_server.py" \
        "$oidc_dir" "$FWD_OIDC_PORT" "$SERVER_CERT" "$SERVER_KEY" \
        >"$FWD_PFX/oidc.log" 2>&1 &
    FWD_OIDC_PID=$!

    # Wait for it to answer over TLS (trusted by the test CA).
    local i
    for i in $(seq 1 20); do
        if curl -s --cacert "$CA_CERT" \
               "${TOK_ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "SKIP: local HTTPS OIDC discovery server did not come up on ${FWD_OIDC_PORT}"
    return 1
}

mint_token() {
    FWD_TOK_DIR="$FWD_PFX/tok"
    python3 "$FWD_HERE/utils/make_token.py" init "$FWD_TOK_DIR" \
        >"$FWD_PFX/tok.log" 2>&1 \
        || { echo "SKIP: make_token.py init failed (cryptography missing?)"; cat "$FWD_PFX/tok.log"; return 1; }
    TOK_JWKS="$FWD_TOK_DIR/jwks.json"
    TOKEN_A="$FWD_PFX/token_a.jwt"
    TOKEN_B="$FWD_PFX/token_b.jwt"

    # Bring up the HTTPS OIDC discovery endpoint BEFORE minting, so tokens carry
    # the reachable local issuer and a stock ztn origin can validate them.
    start_oidc_server || return 1

    python3 "$FWD_HERE/utils/make_token.py" gen --sub "$A_SUB" \
        --scope "storage.read:/ storage.modify:/" --issuer "$TOK_ISSUER" \
        -o "$TOKEN_A" "$FWD_TOK_DIR" \
        >>"$FWD_PFX/tok.log" 2>&1 || { echo "SKIP: token A gen failed"; return 1; }
    # userB gets a WRONG-ISSUER token so the backend genuinely rejects it —
    # the token negative control (there is no per-user token cred dir to omit).
    # --kind wrong-issuer forces iss=https://evil.example.com regardless of the
    # local issuer, so denial is genuine on both stock (pairing A) and brix
    # (pairing C) backends.
    python3 "$FWD_HERE/utils/make_token.py" gen --sub "$B_SUB" \
        --scope "storage.read:/ storage.modify:/" --kind wrong-issuer \
        -o "$TOKEN_B" "$FWD_TOK_DIR" \
        >>"$FWD_PFX/tok.log" 2>&1 || { echo "SKIP: token B gen failed"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------
# Node config emitters.  Each writes a heredoc config, starts the daemon, and
# registers its pidfile in FWD_NODE_PIDS for scoped teardown.
#
# spawn_brix_node <role> <proto> <port> [backend-url] [extra-conf-block]
#   <role>  : logical name (used for the scratch subdir + log path)
#   <proto> : root | roots | davs | http   (front listen wire)
#   <port>  : listen port
#   backend-url : brix_storage_backend value (empty => local export origin)
#   extra-conf-block : extra location/server directives (auth, creds, tokens…)
#
# Returns 0 on start; sets FWD_LAST_LOG to the node's error_log path.
# ---------------------------------------------------------------------------
FWD_LAST_LOG=""

spawn_brix_node() {
    local role="$1" proto="$2" port="$3" backend="${4:-}" extra="${5:-}"
    local d="$FWD_PFX/$role"
    mkdir -p "$d/export" "$d/logs" "$d/cache"
    local log="$d/logs/e.log"
    local pid="$d/nginx.pid"
    local backend_line=""
    [ -n "$backend" ] && backend_line="brix_storage_backend $backend;"

    case "$proto" in
        root|roots)
            local tls=""
            [ "$proto" = roots ] && tls="brix_certificate $SERVER_CERT; brix_certificate_key $SERVER_KEY;"
            cat > "$d/nginx.conf" <<EOF
daemon on;
error_log $log info;
pid $pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${port};
        brix_root on;
        brix_export $d/export;
        brix_allow_write on;
        brix_upload_resume off;
        $tls
        $backend_line
        $extra
    }
}
EOF
            ;;
        davs|http)
            local ssl="" tlsdir=""
            if [ "$proto" = davs ]; then
                ssl="listen 127.0.0.1:${port} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;"
            else
                ssl="listen 127.0.0.1:${port};"
            fi
            cat > "$d/nginx.conf" <<EOF
daemon on;
error_log $log info;
pid $pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
http {
    access_log $d/logs/access.log;
    client_body_temp_path $d/export;
    server {
        $ssl
        location / {
            brix_webdav on;
            brix_allow_write on;
            brix_export $d/export;
            brix_webdav_cafile $CA_CERT;
            $backend_line
            $extra
        }
    }
}
EOF
            ;;
        *)
            echo "spawn_brix_node: unknown proto $proto" >&2; return 1 ;;
    esac

    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (start failed for brix $role/$proto: $(cat "$d/start.err"))" >&2
        return 1
    }
    FWD_NODE_PIDS+=("$pid")
    FWD_LAST_LOG="$log"
    sleep 0.6
    return 0
}

# ---------------------------------------------------------------------------
# spawn_xrootd_node <role> <mode> <port> [backend-host:port] [cred]
#   <mode> : origin  (native GSI/token data server, pairing-A backend)
#            xrdhttp (stock XrdHttp origin over TLS w/ GSI client-cert auth —
#                     the pairing-A https backend node; cred is always gsi here)
#            pss     (forwarding proxy front, pairing-B front)
#   <cred> : gsi | token  (which sec.protocol the node offers/uses)
#
# Sets FWD_LAST_LOG to the node's -l log path.  Uses -crl:0 (our test PKI has
# no CRL distribution point; without this GSI fails with rc=52).
# ---------------------------------------------------------------------------
# fwd_trusted_ca_bundle — build (once per run) a CA bundle = the test CA prepended
# to a copy of the OS default bundle, and echo its path.  A stock token origin's
# libSciTokens JWKS fetch uses its own libcurl which trusts ONLY the OpenSSL
# default bundle (/etc/pki/tls/certs/ca-bundle.crt) and ignores CURL_CA_BUNDLE /
# SSL_CERT_FILE / TLS_CA_FILE in this build — so the token origin is launched
# under bwrap with THIS file bind-mounted over the default bundle path (see
# spawn_xrootd_node origin+token).
FWD_CA_BUNDLE=""
fwd_trusted_ca_bundle() {
    if [ -z "$FWD_CA_BUNDLE" ]; then
        FWD_CA_BUNDLE="$FWD_PFX/ca-bundle-trust.crt"
        local sysb="/etc/pki/tls/certs/ca-bundle.crt"
        [ -f "$sysb" ] || sysb="/etc/ssl/certs/ca-certificates.crt"
        cat "$CA_CERT" "$sysb" > "$FWD_CA_BUNDLE" 2>/dev/null \
            || cp "$CA_CERT" "$FWD_CA_BUNDLE"
    fi
    printf '%s\n' "$FWD_CA_BUNDLE"
}

# fwd_eec_dn <proxy.pem> — echo the end-entity (identity) certificate DN in the
# XRootD `/`-slash form (e.g. /DC=test/DC=xrootd/CN=Fwd User A).  A proxy PEM is a
# chain [proxy-leaf, EEC, ...]; the EEC is the FIRST cert whose subject does NOT
# end in a proxy `CN=<digits>` component.  http.gridmap keys on this exact DN.
fwd_eec_dn() {
    local pem="$1" subj
    # Walk every cert subject; pick the first that is not a proxy delegation
    # (proxy leaves append a CN=<number>).  openssl prints `subject=DC=..., CN=..`.
    while IFS= read -r subj; do
        subj="${subj#subject=}"; subj="${subj# }"
        case "$subj" in
            *,\ CN\ =\ [0-9]*|*,CN=[0-9]*) continue ;;   # a proxy delegation leaf
        esac
        # Convert "DC = test, DC = xrootd, CN = Fwd User A" -> "/DC=test/DC=xrootd/CN=Fwd User A"
        printf '/%s\n' "$(printf '%s' "$subj" | sed -E 's/ = /=/g; s/, /\//g')"
        return 0
    done < <(openssl crl2pkcs7 -nocrl -certfile "$pem" 2>/dev/null \
                 | openssl pkcs7 -print_certs -noout 2>/dev/null | grep '^subject=')
    return 1
}

spawn_xrootd_node() {
    local role="$1" mode="$2" port="$3" backend="${4:-}" cred="${5:-gsi}"
    local d="$FWD_PFX/$role"
    mkdir -p "$d/data" "$d/admin" "$d/run" "$d/scitok_cache"
    local cfg="$d/x.cfg" log="$d/x.log"
    : > "$log"

    local sec_lib="/usr/lib64/libXrdSec-5.so"
    [ -f "$sec_lib" ] || sec_lib="/usr/lib/libXrdSec-5.so"
    local sec_block=""
    if [ "$cred" = gsi ]; then
        sec_block="xrootd.seclib $sec_lib
sec.protocol gsi -certdir:$CA_DIR -cert:$SERVER_CERT -key:$SERVER_KEY -gridmap:none -gmapopt:10 -crl:0
sec.protbind * gsi"
    elif [ "$cred" = token ]; then
        # Proven-working stock v5.9.6 ztn + SciTokens directives.  ztn is
        # disallowed on cleartext links, so the origin advertises TLS (xrd.tls).
        # sec.protbind MUST come AFTER sec.protocol ztn.  ofs.authlib takes a
        # "config=" prefix (not a bare path).  The scitokens issuer is the local
        # HTTPS OIDC endpoint the origin fetches keys from.
        cat > "$d/scitokens.cfg" <<EOF
[Global]
audience = ${TOK_AUD}
[Issuer test]
issuer = ${TOK_ISSUER}
base_path = /
default_user = fwduser
EOF
        sec_block="xrd.tls   $SERVER_CERT $SERVER_KEY
xrd.tlsca certdir $CA_DIR
xrootd.seclib $sec_lib
sec.protocol ztn
sec.protbind * ztn
ofs.authorize 1
ofs.authlib libXrdAccSciTokens-5.so config=$d/scitokens.cfg"
    fi

    case "$mode" in
        origin)
            cat > "$cfg" <<EOF
xrd.port ${port}
xrd.network nodnr
xrd.allow host *
oss.localroot $d/data
all.export /
all.adminpath $d/admin
all.pidpath   $d/run
xrd.trace off
$sec_block
EOF
            ;;
        xrdhttp)
            # Stock XrdHttp origin over TLS, GSI client-cert auth.  Empirically
            # pinned on xrootd v5.9.6:
            #   * xrd.protocol http:PORT libXrdHttp.so  — the HTTP protocol plugin
            #   * xrd.tls / xrd.tlsca certdir           — server TLS + trust roots
            #   * http.cadir (dir of hashed CAs)        — trust + REQUEST a client
            #     cert; http.cert/http.key are the server leaf.
            #   * http.secxtractor libXrdHttpVOMS.so    — extract the client DN.
            #   * http.gridmap <file>                   — map userA's EEC DN to a
            #     stable username.  Stock XrdHttp COLLAPSES the DN to this mapped
            #     name BEFORE it logs anything, so the DN string itself never
            #     appears in the log — the mapped username IS the pinned identity
            #     marker (`XrootdBridge: <sess> login as <mapped>`).  We map
            #     userA's DN -> `fwd-user-a` so the login line proves userA.
            #   * ofs.authorize 1 + acc.authdb          — grant the mapped user
            #     `a` (all) on / so the write leg (PUT) succeeds; an unmapped
            #     client (userB) collapses to a cert-hash identity with no grant
            #     and is denied 403 (the negative control), no bytes stored.
            # userA's EEC DN in XRootD `/`-slash form, derived from PROXY_A.
            local a_dn
            a_dn="$(fwd_eec_dn "$PROXY_A")"
            printf '%s fwd-user-a\n' "\"$a_dn\"" > "$d/gridmap"
            printf 'u fwd-user-a / a\n' > "$d/authdb"
            chmod 777 "$d/data"
            cat > "$cfg" <<EOF
xrd.port ${port}
xrd.protocol http:${port} libXrdHttp.so
xrd.network nodnr
xrd.allow host *
xrd.tls   $SERVER_CERT $SERVER_KEY
xrd.tlsca certdir $CA_DIR
http.cadir $CA_DIR
http.cert  $SERVER_CERT
http.key   $SERVER_KEY
http.secxtractor libXrdHttpVOMS.so
http.gridmap $d/gridmap
oss.localroot $d/data
all.export /
all.adminpath $d/admin
all.pidpath   $d/run
acc.authdb $d/authdb
ofs.authorize 1
sec.protbind * none
xrd.trace off
EOF
            ;;
        pss)
            # Forwarding proxy: presents its own service identity to the origin
            # over root://.  Stock pss delegation of the END-USER credential is
            # attempted by adding pss.origin + (best-effort) forward directives;
            # whether the user identity actually reaches the backend is asserted
            # empirically by the caller (PASS vs GAP).
            cat > "$cfg" <<EOF
all.role server
all.export /
oss.localroot $d/data
all.adminpath $d/admin
all.pidpath   $d/run
xrd.port ${port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
ofs.osslib libXrdPss.so
pss.origin ${backend}
pss.setopt DebugLevel 0
$sec_block
EOF
            ;;
        *)
            echo "spawn_xrootd_node: unknown mode $mode" >&2; return 1 ;;
    esac

    if [ "$cred" = token ]; then
        # A stock token origin's libSciTokens JWKS fetch trusts only the OS
        # default CA bundle and cannot be redirected by env — so we run xrootd
        # under bwrap with a test-CA-augmented bundle bind-mounted over the
        # default path.  bwrap keeps the caller's real uid (xrootd refuses to run
        # as superuser, ruling out `unshare -r`).  XDG_CACHE_HOME points at a
        # fresh per-run dir so a stale negative JWKS cache cannot poison the run.
        if ! command -v bwrap >/dev/null 2>&1; then
            echo "  (token origin needs bwrap for rootless CA-bundle trust; absent)" >&2
            printf '' > "$log"
            FWD_LAST_LOG="$log"
            return 1
        fi
        local bundle real_bundle bwpid_file
        bundle="$(fwd_trusted_ca_bundle)"
        real_bundle="$(readlink -f /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null)"
        [ -n "$real_bundle" ] || real_bundle="/etc/pki/tls/certs/ca-bundle.crt"
        bwpid_file="$d/bwrap.pid"
        # Fresh scitokens cache each launch (avoid negative-cache poisoning).
        rm -rf "$d/scitok_cache"; mkdir -p "$d/scitok_cache"
        # Launch xrootd in the FOREGROUND inside bwrap (no -b); background the
        # bwrap parent and record its PID for scoped teardown.
        bwrap --dev-bind / / \
              --bind "$bundle" "$real_bundle" \
              --setenv XDG_CACHE_HOME "$d/scitok_cache" \
              "$XROOTD_BIN" -c "$cfg" -l "$log" >"$d/start.err" 2>&1 &
        echo $! > "$bwpid_file"
        FWD_NODE_PIDS+=("$bwpid_file")
        FWD_LAST_LOG="$log"
        # Wait for the listen socket (bwrap+ztn+SciTokens init is slower).
        local i
        for i in $(seq 1 25); do
            ss -tlnp 2>/dev/null | grep -q ":${port} " && break
            sleep 0.2
        done
        sleep 0.4
        return 0
    fi

    "$XROOTD_BIN" -c "$cfg" -l "$log" -b >/dev/null 2>"$d/start.err" || true
    # xrootd forks; record the pidpath file for teardown once it appears.
    local i
    for i in $(seq 1 20); do
        local p
        p="$(ls "$d"/run/*.pid 2>/dev/null | head -1)"
        [ -n "$p" ] && { FWD_NODE_PIDS+=("$p"); break; }
        sleep 0.2
    done
    FWD_LAST_LOG="$log"
    sleep 0.8
    return 0
}

# ---------------------------------------------------------------------------
# backend_leg_config <pairing> <hop2-proto> <cred>
#   Emits the brix storage-backend + credential wiring for a brix FRONT's
#   hop-2 leg (pairings A and C).  Prints an nginx directive fragment on stdout.
#
#   hop2-proto : root | https   (davs->https backend leg; root->root:// leg)
#   cred       : gsi | token
#
# Uses per-open per-user credentials via brix_storage_credential_dir with
# fallback=deny (so the negative control is a real refusal), plus a distinct
# service brix_credential.  Pairing C additionally enables
# brix_backend_delegation passthrough to exercise Phase-70 directly.
#
# Requires the caller to have set FWD_BACKEND_URL, FWD_CRED_DIR and (GSI)
# FWD_SVC_CTX_NAME / (token) nothing extra.
# ---------------------------------------------------------------------------
backend_leg_config() {
    local pairing="$1" hop2="$2" cred="$3"
    local frag="brix_storage_backend ${FWD_BACKEND_URL};"
    if [ "$cred" = gsi ]; then
        # GSI: select-not-delegate per-user proxy from the credential dir; deny
        # fallback makes the negative control a real refusal.  A distinct
        # service brix_credential handles pre-flight/fallback.  The `origin`
        # credential also carries ca_dir, so on an https backend leg the front
        # verifies the backend's server cert against the test CA.
        frag="$frag
            brix_storage_credential origin;
            brix_storage_credential_dir ${FWD_CRED_DIR};
            brix_storage_credential_fallback deny;"
    elif [ "$hop2" = https ]; then
        # Token + https backend leg: no per-user static credential (userB must
        # genuinely fail — no service-cred fallback), but the front's sd_http
        # origin still needs to VERIFY the backend's TLS server cert against the
        # test CA.  Attach a CA-ONLY credential (ca_dir, no x509/bearer) so
        # e->origin_ca_dir is set without providing any usable fallback identity.
        frag="$frag
            brix_storage_credential origin_ca;"
    else
        # Token + root:// backend leg (pairing A stock ztn origin, and any brix
        # root backend).  The front presents the CLIENT's bearer to the origin over
        # ztn — bearer passthrough carries t->cred_bearer into the native origin
        # session (sd_xroot).  A CA-only credential lets the front verify the
        # origin's TLS server cert (ztn requires roots://).  userB genuinely fails
        # because its (wrong-issuer) bearer is rejected at the origin — no service
        # fallback identity is provided.
        frag="$frag
            brix_storage_credential origin_ca;"
    fi
    # Pairings A(token) and C exercise Phase-70 live passthrough (bearer carry /
    # full-proxy carry).  GSI pairing A uses select-not-delegate (no passthrough).
    if [ "$pairing" = C ] || { [ "$pairing" = A ] && [ "$cred" = token ]; }; then
        frag="$frag
            brix_backend_delegation passthrough;"
    fi
    printf '%s\n' "$frag"
}

# ---------------------------------------------------------------------------
# assert_backend_identity <brix|stock> <logpath> <expect-id>
#   Returns 0 iff the backend's own log shows an auth line carrying expect-id
#   (a DN CN fragment for GSI, or a token `sub` for token).  Accepts the
#   brix_sanitize_log_string \x20-for-space form.
# ---------------------------------------------------------------------------
assert_backend_identity() {
    local kind="$1" log="$2" expect="$3"
    [ -f "$log" ] || return 1
    local esc="${expect// /\\\\x20}"     # "Fwd User A" -> "Fwd\\x20User\\x20A"
    case "$kind" in
        stock)
            # GSI root://: "XrootdXeq: ... login as /DC=.../CN=<name>"
            # stock XrdHttp (https backend node): the client DN is collapsed by
            #   http.gridmap to a username BEFORE any logging, so the DN string
            #   never appears — the pinned marker is the mapped username on the
            #   `XrootdBridge: <sess> login as <mapped>` line.  run_cell_A maps
            #   userA's DN -> `fwd-user-a`, so the caller passes expect=fwd-user-a
            #   (matched by the generic `login as <name>` clause below).
            # token: "XrootdXeq: ... TLSv1.3 login as <mapped-username>", where the
            #        SciTokens default_user is overridden by the token's subject —
            #        stock v5.9.6 logs `login as fwd-user-a` (the subject).  On
            #        this build there is no separate `scitokens_Access: New valid
            #        token mapped_username=...` log line, so the pinned success
            #        marker is the `login as <sub>` XrootdXeq line.
            grep 'login as ' "$log" 2>/dev/null | grep -qE "CN=(${expect}|${esc})" && return 0
            grep -qE "login as (${expect}|${esc})( |\$)" "$log" 2>/dev/null && return 0
            return 1
            ;;
        brix)
            # GSI:   root://  emits 'brix: GSI auth OK dn="...CN=<name>..."'
            #        webdav   emits 'brix_webdav: GSI auth OK source=<x> dn="..."'
            #        — tolerate the optional 'source=<x> ' segment between the
            #        'GSI auth OK' banner and the 'dn=' field so BOTH backend
            #        wire legs match on the same forwarded DN.
            # token: 'brix_token: valid token sub="<sub>"'
            grep -qE "GSI auth OK ([^ ]* )?dn=.*(${expect}|${esc})" "$log" 2>/dev/null && return 0
            grep -qE "valid token sub=\"?${expect}\"?" "$log" 2>/dev/null && return 0
            return 1
            ;;
        *) return 2 ;;
    esac
}

# assert_service_identity_only — GAP proof for pairing B: the backend log
# shows the SERVICE DN (svc) and NOT userA.
assert_service_identity_only() {
    local kind="$1" log="$2" svc="$3" user="$4"
    assert_backend_identity "$kind" "$log" "$svc" \
        && ! assert_backend_identity "$kind" "$log" "$user"
}

# ---------------------------------------------------------------------------
# assert_denied <proto> <observed>
#   Negative-control checker: 0 iff `observed` is a proper backend-leg refusal.
#   proto=https : observed is an HTTP status; want 403 (404 accepted soft — no
#                 bytes served either way).
#   proto=root  : observed is an xrdcp/xrdfs exit code; want non-zero.
# ---------------------------------------------------------------------------
assert_denied() {
    local proto="$1" observed="$2"
    case "$proto" in
        https) [ "$observed" = 403 ] || [ "$observed" = 404 ] ;;
        root)  [ "$observed" != 0 ] ;;
        *)     return 2 ;;
    esac
}

# ---------------------------------------------------------------------------
# feasibility_probe <pairing> <hop2> <cred>
#   Returns (on stdout) one of:  SUPPORTED | UNSUPPORTED:<why> | SKIP:<why>
#   Pure code-capability decision — no daemons started.
# ---------------------------------------------------------------------------
feasibility_probe() {
    local pairing="$1" hop2="$2" cred="$3"
    case "$pairing" in
        B)
            # Stock pss has only a root:// backend leg.
            [ "$hop2" = https ] && { echo "SKIP:stock xrootd proxy has no https backend leg"; return; }
            [ -x "$XROOTD_BIN" ] || { echo "SKIP:stock xrootd absent"; return; }
            echo "SUPPORTED"; return ;;
        A)
            [ -x "$XROOTD_BIN" ] || { echo "SKIP:stock xrootd absent"; return; }
            # Token forwarding to a stock xrootd roots:// backend is now WIRED and
            # exercised for real (run_cell_A spawns a stock ztn+SciTokens origin and
            # a brix root:// front that forwards userA's bearer over roots://).  The
            # backend is proven-working: stock xrootd v5.9.6 with a local HTTPS OIDC
            # discovery server + `sec.protocol ztn` + `ofs.authlib
            # libXrdAccSciTokens-5.so config=<scitokens.cfg>` authenticates userA
            # (origin logs `login as fwd-user-a`) and denies a wrong-issuer userB.
            #
            # The remaining question is the FRONT->BACK leg: stock xrootd hard-
            # requires TLS for ztn and speaks the XRootD cleartext handshake first,
            # then upgrades on the kXR_gotoTLS advert.  A brix native cache-origin
            # that lacks a cleartext->TLS upgrade path surfaces as `cache origin TLS
            # handshake failed (kXR 3028)`; a concurrent SOURCE change adds that
            # upgrade.  We no longer pre-judge the cell — run it and let the real
            # outcome stand (PASS if the upgrade lands, FAIL with the kXR-3028 detail
            # if the src fix is not yet built).  The token origin needs bwrap for
            # rootless CA-bundle trust of the OIDC fetch; without it, SKIP.
            if [ "$cred" = token ]; then
                command -v bwrap >/dev/null 2>&1 \
                    || { echo "SKIP:token origin needs bwrap for rootless OIDC CA-bundle trust; bwrap absent"; return; }
                echo "SUPPORTED"; return
            fi
            # An https backend leg for pairing A is now provisioned by a stock
            # XrdHttp origin node (spawn_xrootd_node ... xrdhttp): TLS + GSI
            # client-cert auth, http.gridmap userA's DN -> a username, authdb
            # grant.  The front (brix root:// or davs) forwards userA's proxy as a
            # TLS client cert to that origin (sd_http CURLOPT_SSLCERT — the same
            # path proven by pairing C HH gsi).  So the https-leg GSI cells are
            # run for real.  XrdHttp requires libXrdHttp.so; if the plugin is
            # absent the cell SKIPs.  (Token + https backend leg is still not a
            # stock-XrdHttp path here — SKIP.)
            if [ "$hop2" = https ]; then
                [ "$cred" = token ] && { echo "SKIP:pairing A https backend leg is GSI-only (stock XrdHttp ztn-over-http not provisioned)"; return; }
                [ -f /usr/lib64/libXrdHttp-5.so ] || [ -f /usr/lib/libXrdHttp-5.so ] \
                    || { echo "SKIP:stock XrdHttp plugin (libXrdHttp) not present — no https backend node"; return; }
                echo "SUPPORTED"; return
            fi
            echo "SUPPORTED"; return ;;
        C)
            # The brix HTTP backend driver has gained per-user credential
            # forwarding on BOTH the read and write legs, so hop2=https cells
            # (HH/RH) are now attempted for real: run_cell_C spawns the nodes and
            # lets the assertions (backend identity == userA, userB denied)
            # produce PASS/FAIL, or the front's own log surface a genuine
            # runtime UNSUPPORTED.  No canned verdict here.
            echo "SUPPORTED"; return ;;
        *) echo "SKIP:unknown pairing $pairing"; return ;;
    esac
}

# ---------------------------------------------------------------------------
# Wire-combo decoding: RR=(root,root) HH=(https,https) HR=(https,root)
# RH=(root,https).  hop1 is client->front; hop2 is front->backend.
# ---------------------------------------------------------------------------
fwd_hop1() { case "$1" in RR|RH) echo root ;; HH|HR) echo https ;; esac; }
fwd_hop2() { case "$1" in RR|HR) echo root ;; HH|RH) echo https ;; esac; }

# GSI client env for the brix/native clients.
fwd_run_as() { local proxy="$1"; shift; X509_USER_PROXY="$proxy" X509_CERT_DIR="$CA_DIR" XrdSecGSICADIR="$CA_DIR" XrdSecGSICRLCHECK=0 "$@"; }

# Install userA's proxy into a front's credential dir under the stem the front
# actually derives.  openssl's subject formatting does NOT reproduce the exact
# slash-form DN the front hashes, so we LEARN the stem from the front's own log:
# a probe request (no cred yet, deny-mode) emits 'key=<stem>'.  Falls back to a
# direct-hash guess only if the probe yields nothing.
#   fwd_install_gsi_cred <cred_dir> <front-log> <hop1> <front-port>
fwd_install_gsi_cred() {
    local cred_dir="$1" flog="$2" hop1="$3" port="$4"
    # Probe once with userA (no cred installed) to force the 'key=' log line.
    if [ "$hop1" = root ]; then
        fwd_run_as "$PROXY_A" "$BRIX_XRDCP" -f /dev/null \
            "root://127.0.0.1:${port}//_probe_key.bin" >/dev/null 2>/dev/null || true
    else
        fwd_curl_gsi "$PROXY_A" -o /dev/null -T "$PROXY_A" \
            "https://127.0.0.1:${port}/_probe_key.bin" >/dev/null 2>/dev/null || true
    fi
    sleep 0.3
    local stem
    stem=$(grep -oE 'key=x5h-[0-9a-f]+|key=[A-Za-z0-9@._-]+' "$flog" 2>/dev/null | head -1 | cut -d= -f2)
    if [ -z "$stem" ]; then
        local dn
        dn=$(openssl x509 -in "$PROXY_A" -noout -subject 2>/dev/null | sed 's|subject=||;s|^ *||')
        stem="x5h-$(printf '%s' "$dn" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $2}' | head -c 32)"
    fi
    install -m 644 "$PROXY_A" "$cred_dir/$stem.pem" 2>/dev/null
}

# curl helper for an https (davs) front leg with a GSI client proxy or a bearer.
fwd_curl_gsi()   { local px="$1"; shift; curl -sk --cert "$px" --key "$px" "$@"; }
fwd_curl_token() { local jwt="$1"; shift; curl -sk -H "Authorization: Bearer $(cat "$jwt")" "$@"; }

# ---------------------------------------------------------------------------
# Front-leg client drivers (hop-1: client -> front).  Each performs one PUT
# then one GET of a random payload against the front and reports:
#   - PUT ok?  -> $FWD_PUT_OK (0/1)
#   - GET byte-exact? -> $FWD_GET_OK (0/1)
# For the negative control they report the refusal signal in $FWD_DENY_OBS.
# The FRONT url + object are passed in; the credential selects userA/userB.
# ---------------------------------------------------------------------------
FWD_PUT_OK=0; FWD_GET_OK=0; FWD_DENY_OBS=""

# fwd_front_put_get <hop1> <cred> <front-port> <obj> <who>
#   hop1 : root | https      cred: gsi | token      who: A | B
fwd_front_put_get() {
    local hop1="$1" cred="$2" port="$3" obj="$4" who="$5"
    local payload="$FWD_PFX/payload_${who}.bin" back="$FWD_PFX/back_${who}.bin"
    head -c 65536 /dev/urandom > "$payload"
    FWD_PUT_OK=0; FWD_GET_OK=0; FWD_DENY_OBS=""

    if [ "$hop1" = root ]; then
        local url="root://127.0.0.1:${port}/${obj}"
        if [ "$cred" = gsi ]; then
            local px; [ "$who" = A ] && px="$PROXY_A" || px="$PROXY_B"
            fwd_run_as "$px" "$BRIX_XRDCP" -f "$payload" "$url" >/dev/null 2>"$FWD_PFX/put_${who}.err"
            [ $? = 0 ] && FWD_PUT_OK=1 || FWD_DENY_OBS=1
            fwd_run_as "$px" "$BRIX_XRDCP" -f "$url" "$back" >/dev/null 2>/dev/null
        else
            local jwt; [ "$who" = A ] && jwt="$TOKEN_A" || jwt="$TOKEN_B"
            BEARER_TOKEN="$(cat "$jwt")" X509_USER_PROXY=/dev/null XrdSecPROTOCOL=ztn \
                "$BRIX_XRDCP" -f "$payload" "$url" >/dev/null 2>"$FWD_PFX/put_${who}.err"
            [ $? = 0 ] && FWD_PUT_OK=1 || FWD_DENY_OBS=1
            BEARER_TOKEN="$(cat "$jwt")" X509_USER_PROXY=/dev/null XrdSecPROTOCOL=ztn \
                "$BRIX_XRDCP" -f "$url" "$back" >/dev/null 2>/dev/null
        fi
    else   # https (davs) front
        local url="https://127.0.0.1:${port}/${obj}"
        local code
        if [ "$cred" = gsi ]; then
            local px; [ "$who" = A ] && px="$PROXY_A" || px="$PROXY_B"
            code=$(fwd_curl_gsi "$px" -o /dev/null -w '%{http_code}' -T "$payload" "$url")
            case "$code" in 201|204|200) FWD_PUT_OK=1 ;; *) FWD_DENY_OBS="$code" ;; esac
            fwd_curl_gsi "$px" -o "$back" "$url" >/dev/null 2>/dev/null
        else
            local jwt; [ "$who" = A ] && jwt="$TOKEN_A" || jwt="$TOKEN_B"
            code=$(fwd_curl_token "$jwt" -o /dev/null -w '%{http_code}' -T "$payload" "$url")
            case "$code" in 201|204|200) FWD_PUT_OK=1 ;; *) FWD_DENY_OBS="$code" ;; esac
            fwd_curl_token "$jwt" -o "$back" "$url" >/dev/null 2>/dev/null
        fi
    fi
    if [ "$FWD_PUT_OK" = 1 ] && cmp -s "$payload" "$back" 2>/dev/null; then
        FWD_GET_OK=1
    fi
}
