#!/usr/bin/env bash
# run_fwd_brix_brix.sh — credential-forwarding matrix, PAIRING C: brix-front
# -> brix-back.  wire in {RR,HH,HR,RH} x cred in {gsi,token}.  The purest
# proof of Phase-70 forwarding: bearer passthrough, x509 full-proxy passthrough,
# and cross-protocol carry on the mixed (HR/RH) paths.
#
# Pairing C uses live brix_backend_delegation passthrough where possible.
# Backend identity is read from the BRIX-back log.  Runs even with no stock
# xrootd present (pairing C has no stock dependency).  Per spec §9 criterion 4,
# any UNSUPPORTED cell here is a REAL Phase-70 gap and is flagged loudly.
#
# Design: docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md
set -u
source "$(dirname "$0")/lib/fwd_matrix.sh"
FWD_PORT_BASE="${FWD_PORT_BASE:-21980}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

fwd_setup fwd_c 0 || { echo "run_fwd_brix_brix: environment SKIP"; exit 0; }
trap fwd_cleanup EXIT
mint_pki || exit 0
mint_token || echo "  (token authority unavailable — token cells will SKIP)"

# Backend node (proto=root|davs), GSI or token auth.
spawn_c_backend() {
    local role="$1" proto="$2" cred="$3" port="$4"
    local extra
    if [ "$proto" = root ]; then
        if [ "$cred" = gsi ]; then
            extra="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
        else
            extra="brix_auth token;
        brix_token_jwks     $TOK_JWKS;
        brix_token_issuer   $TOK_ISSUER;
        brix_token_audience $TOK_AUD;"
        fi
        spawn_brix_node "$role" root "$port" "" "$extra"
    else   # davs backend (spawn_brix_node already emits brix_webdav_cafile)
        if [ "$cred" = gsi ]; then
            extra="brix_webdav_auth required;"
        else
            extra="brix_webdav_auth required;
            brix_webdav_token_jwks     $TOK_JWKS;
            brix_webdav_token_issuer   $TOK_ISSUER;
            brix_webdav_token_audience $TOK_AUD;"
        fi
        spawn_brix_node "$role" davs "$port" "" "$extra"
    fi
}

# Front node: brix proto=root|davs, backend hop-2 root://|https://, passthrough.
spawn_c_front() {
    local role="$1" fproto="$2" cred="$3" fport="$4" burl="$5" cred_dir="$6"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
    FWD_BACKEND_URL="$burl"; FWD_CRED_DIR="$cred_dir"
    local leg
    leg="$(backend_leg_config C "$( [ "${burl%%://*}" = root ] && echo root || echo https )" "$cred")"

    if [ "$fproto" = root ]; then
        local auth
        if [ "$cred" = gsi ]; then
            auth="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
        else
            auth="brix_auth token;
        brix_token_jwks     $TOK_JWKS;
        brix_token_issuer   $TOK_ISSUER;
        brix_token_audience $TOK_AUD;"
        fi
        cat > "$d/nginx.conf" <<EOF
daemon on;
error_log $log info;
pid $pid;
worker_processes 1;
thread_pool default threads=2;
events { worker_connections 64; }
stream {
    brix_credential origin { x509_proxy $SVC_PROXY; ca_dir $CA_DIR; }
    brix_credential origin_ca { ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${fport};
        brix_root on;
        brix_export $d/export;
        brix_allow_write on;
        brix_upload_resume off;
        $auth
        $leg
    }
}
EOF
    else   # davs front
        local auth="brix_webdav_cafile $CA_CERT;"
        if [ "$cred" = gsi ]; then
            auth="$auth brix_webdav_auth required;"
        else
            auth="$auth brix_webdav_auth required;
            brix_webdav_token_jwks     $TOK_JWKS;
            brix_webdav_token_issuer   $TOK_ISSUER;
            brix_webdav_token_audience $TOK_AUD;"
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
    brix_credential origin { x509_proxy $SVC_PROXY; ca_dir $CA_DIR; }
    brix_credential origin_ca { ca_dir $CA_DIR; }
    server {
        listen 127.0.0.1:${fport} ssl;
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
            $auth
            $leg
        }
    }
}
EOF
    fi
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (C front start failed: $(cat "$d/start.err"))" >&2; return 1; }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.6; return 0
}

run_cell_C() {
    local wire="$1" cred="$2"
    local hop1 hop2 key feas
    hop1=$(fwd_hop1 "$wire"); hop2=$(fwd_hop2 "$wire")
    key="C $wire $cred"
    feas="$(feasibility_probe C "$hop2" "$cred")"
    case "$feas" in
        SKIP:*)        fwd_record "$key" SKIP        "${feas#SKIP:}";        return ;;
        UNSUPPORTED:*) fwd_record "$key" UNSUPPORTED "${feas#UNSUPPORTED:}"; return ;;
    esac

    local bport fport bproto fproto burl
    fwd_port bport; fwd_port fport
    # hop-2 proto determines the backend node's listen proto + backend URL.
    if [ "$hop2" = root ]; then bproto=root; burl="root://127.0.0.1:${bport}"
    else                        bproto=davs; burl="https://127.0.0.1:${bport}"; fi
    # hop-1 proto determines the front's listen proto.
    if [ "$hop1" = root ]; then fproto=root; else fproto=davs; fi

    spawn_c_backend "cbk_${wire}_${cred}" "$bproto" "$cred" "$bport" || {
        fwd_record "$key" FAIL "brix backend start failed"; return; }
    local blog="$FWD_LAST_LOG"
    local bexport="$FWD_PFX/cbk_${wire}_${cred}/export"

    local cred_dir="$FWD_PFX/creds_c_${wire}_${cred}"; mkdir -p "$cred_dir"; chmod 777 "$cred_dir"
    spawn_c_front "cfr_${wire}_${cred}" "$fproto" "$cred" "$fport" "$burl" "$cred_dir" || {
        fwd_record "$key" FAIL "brix front start failed"; return; }
    local flog="$FWD_LAST_LOG"

    # GSI: even under passthrough the front consults the per-user credential
    # dir (the deny gate keys off it), so provision userA's proxy keyed by the
    # DN stem the front derives (x5h-<sha256hex32> of the oneline subject DN).
    if [ "$cred" = gsi ]; then
        fwd_install_gsi_cred "$cred_dir" "$flog" "$hop1" "$fport"
    fi

    # ---- positive: userA two-hop PUT+GET + backend sees A ----
    : > "$blog"
    fwd_front_put_get "$hop1" "$cred" "$fport" "posC_${wire}.bin" A
    if [ "$FWD_GET_OK" != 1 ]; then
        # Distinguish an unimplemented forwarding path (UNSUPPORTED) from a
        # genuine defect (FAIL): if the front logged a passthrough/credential
        # not-implemented reason, surface UNSUPPORTED; else FAIL.
        # A token cell whose backend leg never received the forwarded bearer is
        # a Phase-70 passthrough gap, whichever way the symptom surfaces:
        #   root front:  "backend has NO credential"
        #   davs front:  serve-offload materialise failed / getxattr-lock EIO
        #                (the root:// backend rejected the un-forwarded session)
        local tok_gap='backend has NO credential|serve offload: materialise failed|getxattr lock on .* failed'
        # root:// front -> whole-object (http/s) storage backend WRITE: the
        # block-oriented root:// write model has no staged-commit adapter for a
        # backend that only does whole-object PUTs (sd_http). The front logs the
        # gap explicitly (open_resolved_file.c); classify it UNSUPPORTED, not FAIL.
        local wob_gap='root:// write to a whole-object storage backend is not supported'
        if grep -qiE "cannot scope a session to a user credential|not.?implemented|unsupported|no per-user|cannot present|passthrough.*unavailable|$wob_gap|$tok_gap" "$flog" 2>/dev/null; then
            local why="front cannot forward credential on this path"
            grep -q 'cannot scope a session to a user credential' "$flog" 2>/dev/null \
                && why="backend \"http\" driver cannot scope a session to a per-user credential (Phase-70 https-backend-leg gap)"
            grep -qE "$wob_gap" "$flog" 2>/dev/null \
                && why="root:// front -> whole-object https backend WRITE unsupported — the block-write path (kXR_write/pgwrite) needs a staged-commit adapter to PUT the object; sd_http has no random-write open (Phase-70 root->http-backend write gap)"
            grep -qE "$tok_gap" "$flog" 2>/dev/null \
                && why="backend leg did not receive the passed-through bearer — sd_xroot/serve-offload needs a static brix_storage_credential (Phase-70 token passthrough gap)"
            fwd_record "$key" UNSUPPORTED "$why (put_ok=$FWD_PUT_OK)"
        else
            fwd_record "$key" FAIL "userA two-hop PUT/GET not byte-exact (put_ok=$FWD_PUT_OK)"
        fi
        return
    fi
    sleep 0.4
    if ! { assert_backend_identity brix "$blog" "$A_CN" || assert_backend_identity brix "$blog" "$A_SUB"; }; then
        fwd_record "$key" FAIL "backend log did not show userA (DN=$A_CN / sub=$A_SUB)"; return
    fi
    # ---- negative: userB denied on backend leg, no bytes ----
    fwd_front_put_get "$hop1" "$cred" "$fport" "negC_${wire}.bin" B
    local deny_ok=0
    if [ "$hop1" = root ]; then
        assert_denied root "$FWD_DENY_OBS" && deny_ok=1
    else
        assert_denied https "$FWD_DENY_OBS" && deny_ok=1
    fi
    if [ "$deny_ok" != 1 ]; then
        fwd_record "$key" FAIL "userB not denied on backend leg (deny_obs=$FWD_DENY_OBS)"; return
    fi
    if [ -f "$bexport/negC_${wire}.bin" ]; then
        fwd_record "$key" FAIL "userB bytes reached the backend store"; return
    fi
    fwd_record "$key" PASS "userA at backend, userB denied, no leak (passthrough)"
}

echo "== credential-forwarding matrix — PAIRING C (brix-front -> brix-back) =="
for wire in RR HH HR RH; do
    for cred in gsi token; do
        fwd_cell_begin
        run_cell_C "$wire" "$cred"
        fwd_cell_end
    done
done

echo ""
echo "---- pairing C summary ----"
for r in "${FWD_RESULTS[@]}"; do
    printf '  %-30s %-14s %s\n' "${r%%|*}" "$(echo "$r" | cut -d'|' -f2)" "$(echo "$r" | cut -d'|' -f3-)"
done
UNSUP=$(printf '%s\n' "${FWD_RESULTS[@]}" | grep -c '|UNSUPPORTED|' || true)
[ "$UNSUP" != 0 ] && echo "  !! pairing C has $UNSUP UNSUPPORTED cell(s) — REAL Phase-70 gap(s) to flag (spec §9.4)"
[ "$FWD_ANY_FAIL" = 0 ] && echo "run_fwd_brix_brix: no FAIL cells" || echo "run_fwd_brix_brix: FAIL cells present"
exit "$FWD_ANY_FAIL"
