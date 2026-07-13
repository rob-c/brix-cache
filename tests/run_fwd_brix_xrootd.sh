#!/usr/bin/env bash
# run_fwd_brix_xrootd.sh — credential-forwarding matrix, PAIRING A: brix-front
# -> stock-xrootd-back.  wire in {RR,HH,HR,RH} x cred in {gsi,token}.
#
# Backend identity is read from the STOCK xrootd log ("... login as /DC=.../CN=").
# Token-to-stock and https-backend-leg cells surface as UNSUPPORTED code gaps
# (feasibility_probe), never silent skips.  Binary gate: no /usr/bin/xrootd =>
# the whole pairing SKIPs.
#
# Design: docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md
set -u
source "$(dirname "$0")/lib/fwd_matrix.sh"
FWD_PORT_BASE="${FWD_PORT_BASE:-21960}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

fwd_setup fwd_a 1; rc=$?
if [ "$rc" != 0 ]; then
    echo "run_fwd_brix_xrootd: pairing A SKIPPED wholesale (see reason above)"
    exit 0
fi
trap fwd_cleanup EXIT
mint_pki || exit 0
mint_token || echo "  (token authority unavailable — token cells will SKIP)"

# One cell: bring up a stock-xrootd GSI origin (backend) + a brix front whose
# hop-2 storage_backend is that origin, per-user proxy provisioned for A.
run_cell_A() {
    local wire="$1" cred="$2"
    local hop1 hop2 key feas
    hop1=$(fwd_hop1 "$wire"); hop2=$(fwd_hop2 "$wire")
    key="A $wire $cred"
    feas="$(feasibility_probe A "$hop2" "$cred")"
    case "$feas" in
        SKIP:*)        fwd_record "$key" SKIP        "${feas#SKIP:}";        return ;;
        UNSUPPORTED:*) fwd_record "$key" UNSUPPORTED "${feas#UNSUPPORTED:}"; return ;;
    esac
    # GSI + root hop-2, and (now) token + root hop-2, are SUPPORTED for pairing A.
    local oport fport
    fwd_port oport; fwd_port fport

    # Backend + backend URL depend on the credential.  A token origin advertises
    # TLS (ztn requires it), so its backend leg MUST be roots://.  A GSI origin
    # uses cleartext root://.
    local burl
    if [ "$cred" = token ]; then
        spawn_xrootd_node "obk_${wire}_${cred}" origin "$oport" "" token || {
            fwd_record "$key" FAIL "stock token origin start failed"; return; }
        burl="roots://127.0.0.1:${oport}"
    elif [ "$hop2" = https ]; then
        # GSI + https backend leg: a stock XrdHttp origin (TLS + GSI client-cert
        # auth, gridmap userA's DN).  The brix front forwards userA's proxy as a
        # TLS client cert (sd_http CURLOPT_SSLCERT).
        spawn_xrootd_node "obk_${wire}_${cred}" xrdhttp "$oport" "" gsi || {
            fwd_record "$key" FAIL "stock XrdHttp origin start failed"; return; }
        burl="https://127.0.0.1:${oport}"
    else
        spawn_xrootd_node "obk_${wire}_${cred}" origin "$oport" "" gsi
        burl="root://127.0.0.1:${oport}"
    fi
    local blog="$FWD_LAST_LOG"

    # Provision userA's proxy under the front's credential dir keyed by DN stem.
    local cred_dir="$FWD_PFX/creds_${wire}_${cred}"; mkdir -p "$cred_dir"; chmod 777 "$cred_dir"
    FWD_BACKEND_URL="$burl"
    FWD_CRED_DIR="$cred_dir"

    # Front proto follows hop-1 for GSI cells: root (RR/RH) or davs (HH/HR).  The
    # davs front is what makes A HH gsi a real davs-front->https-back path.  TOKEN
    # cells keep the original root-front bearer-passthrough path (a stock ztn
    # backend is roots://-only and has no XrdHttp/davs analogue here), so their
    # front proto is pinned to root regardless of the wire's hop1 label.
    local fhop1="$hop1"; [ "$cred" = token ] && fhop1=root
    local leg="$(backend_leg_config A "$hop2" "$cred")"
    local aflog="$FWD_PFX/afront_${wire}_${cred}/logs/e.log"
    if [ "$fhop1" = root ]; then
        local svc_block auth_block
        if [ "$cred" = token ]; then
            # origin_ca: CA-only credential so the front verifies the stock
            # origin's TLS server cert (roots://) against the test CA.  The front
            # authenticates the CLIENT with brix_auth token and forwards the bearer.
            svc_block="brix_credential origin_ca { ca_dir $CA_DIR; }"
            auth_block="brix_auth token;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_token_jwks     $TOK_JWKS;
        brix_token_issuer   $TOK_ISSUER;
        brix_token_audience $TOK_AUD;"
        else
            svc_block="brix_credential origin { x509_proxy $SVC_PROXY; ca_dir $CA_DIR; }"
            auth_block="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
        fi
        spawn_brix_front_root_with_cred "afront_${wire}_${cred}" "$fport" "$svc_block" "$auth_block
        $leg" || { fwd_record "$key" FAIL "brix front start failed"; return; }
    else
        # davs front (hop1=https): terminates client GSI over TLS, forwards
        # userA's proxy to the XrdHttp origin (sd_http CURLOPT_SSLCERT).
        spawn_brix_front_davs_with_cred "afront_${wire}_${cred}" "$fport" "$leg" || {
            fwd_record "$key" FAIL "brix davs front start failed"; return; }
    fi

    # GSI: learn A's derived credential key + install A's proxy (probe-based).
    # Token: no per-user cred dir — the client presents the bearer directly.
    if [ "$cred" = gsi ]; then
        fwd_install_gsi_cred "$cred_dir" "$aflog" "$fhop1" "$fport"
    fi
    sleep 0.5

    # ---- positive: userA PUT+GET, backend sees A's identity (retry once past the
    # probe-connection cred-miss race) ----
    : > "$blog"
    fwd_front_put_get "$fhop1" "$cred" "$fport" "posA_${wire}.bin" A
    [ "$FWD_GET_OK" = 1 ] || { sleep 0.4; fwd_front_put_get "$fhop1" "$cred" "$fport" "posA2_${wire}.bin" A; }
    if [ "$FWD_GET_OK" != 1 ]; then
        # Token cell: a brix native-origin cleartext->TLS-upgrade gap surfaces as
        # `cache origin TLS handshake failed (kXR 3028)` — pin that detail so the
        # verdict names the pending concurrent SOURCE fix rather than a test bug.
        local detail="userA two-hop PUT/GET not byte-exact (put_ok=$FWD_PUT_OK)"
        if [ "$cred" = token ] && grep -qiE 'kXR 3028|origin TLS handshake failed|ztn' "$aflog" 2>/dev/null; then
            local ev; ev="$(grep -iE 'kXR 3028|origin TLS handshake failed|ztn' "$aflog" 2>/dev/null | tail -1)"
            detail="front->stock-origin ztn/TLS leg failed (put_ok=$FWD_PUT_OK): ${ev}"
        fi
        fwd_record "$key" FAIL "$detail"; return
    fi
    sleep 0.4
    # Backend identity marker on the stock origin log:
    #   GSI root:// origin -> userA DN (CN=Fwd User A)
    #   GSI XrdHttp origin -> mapped username (DN collapsed by http.gridmap to
    #                         `fwd-user-a` before logging — see fwd_matrix.sh)
    #   token origin       -> userA subject (login as <sub>)
    local expect_id="$A_CN"
    [ "$cred" = token ] && expect_id="$A_SUB"
    [ "$cred" = gsi ] && [ "$hop2" = https ] && expect_id="fwd-user-a"
    if ! assert_backend_identity stock "$blog" "$expect_id"; then
        fwd_record "$key" FAIL "backend log did not show userA ($expect_id)"; return
    fi
    # ---- negative: userB denied on the backend leg, no bytes ----
    local obdir="$FWD_PFX/obk_${wire}_${cred}/data"
    fwd_front_put_get "$fhop1" "$cred" "$fport" "negB_${wire}.bin" B
    if ! assert_denied "$fhop1" "$FWD_DENY_OBS"; then
        fwd_record "$key" FAIL "userB was NOT denied on backend leg (deny_obs=$FWD_DENY_OBS)"; return
    fi
    if [ -f "$obdir/negB_${wire}.bin" ]; then
        fwd_record "$key" FAIL "userB bytes reached the backend store"; return
    fi
    fwd_record "$key" PASS "userA DN at backend, userB denied, no leak"
}

# brix root:// front needing a stream-scope brix_credential block.
spawn_brix_front_root_with_cred() {
    local role="$1" port="$2" svc_block="$3" server_extra="$4"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
    cat > "$d/nginx.conf" <<EOF
daemon on;
error_log $log info;
pid $pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    $svc_block
    server {
        listen 127.0.0.1:${port};
        brix_root on;
        brix_export $d/export;
        brix_allow_write on;
        brix_upload_resume off;
        $server_extra
    }
}
EOF
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (front start failed: $(cat "$d/start.err"))" >&2; return 1; }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.6; return 0
}

# brix davs (https) front for the hop1=https + https-backend-leg GSI cell (A HH
# gsi).  Terminates the client's GSI proxy over TLS and forwards userA's proxy to
# the stock XrdHttp origin (sd_http CURLOPT_SSLCERT).  Mirrors pairing C's davs
# front: origin credential = userA proxy dir (select-not-delegate) + a service
# `origin` credential carrying ca_dir so the front verifies the origin's TLS cert.
spawn_brix_front_davs_with_cred() {
    local role="$1" port="$2" leg="$3"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
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
    brix_credential origin { x509_proxy $SVC_PROXY; ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${port} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {
            brix_webdav on;
            brix_allow_write on;
            brix_export $d/export;
            brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;
            $leg
        }
    }
}
EOF
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (davs front start failed: $(cat "$d/start.err"))" >&2; return 1; }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.6; return 0
}

echo "== credential-forwarding matrix — PAIRING A (brix-front -> xrootd-back) =="
for wire in RR HH HR RH; do
    for cred in gsi token; do
        fwd_cell_begin
        run_cell_A "$wire" "$cred"
        fwd_cell_end
    done
done

echo ""
echo "---- pairing A summary ----"
for r in "${FWD_RESULTS[@]}"; do
    printf '  %-30s %-14s %s\n' "${r%%|*}" "$(echo "$r" | cut -d'|' -f2)" "$(echo "$r" | cut -d'|' -f3-)"
done
[ "$FWD_ANY_FAIL" = 0 ] && echo "run_fwd_brix_xrootd: no FAIL cells" || echo "run_fwd_brix_xrootd: FAIL cells present"
exit "$FWD_ANY_FAIL"
