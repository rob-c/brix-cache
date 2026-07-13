# tests/lib/tpc_fwd.sh — TPC credential-forwarding helper library.
#
# Sourced (never executed) by the two driver scripts:
#   run_tpc_fwd_webdav.sh   (WebDAV/HTTP third-party COPY, PULL)
#   run_tpc_fwd_root.sh     (native root:// TPC, `xrdcp --tpc delegate`, PULL)
#
# Design: docs/superpowers/specs/2026-07-11-tpc-credential-forwarding-tests-design.md
#
# HEAVILY reuses tests/lib/fwd_matrix.sh: mint_pki (userA/userB/svc proxies),
# mint_token (+ HTTPS OIDC discovery server on 21999), spawn_brix_node,
# spawn_xrootd_node, assert_backend_identity, pidfile-scoped teardown, and the
# constants (CA_*, SERVER_*, PROXY_*, TOKEN_*, A_CN/A_SUB, fwd_run_as, …).
#
# What THIS file adds is the TPC topology + the two PULL drivers:
#
#   drive_tpc_webdav  — curl -X COPY with Source: + (bearer) forwarding headers,
#                       PULL from a SOURCE node into a brix DEST that is the TPC
#                       puller (brix WebDAV TPC = curl COPY, src/protocols/webdav/tpc.c).
#   drive_tpc_root    — xrdcp --tpc delegate root://SRC//f root://DEST//f (native
#                       root:// TPC = SHM key registry / delegated-proxy pull,
#                       src/tpc/*).
#   assert_source_identity — wrap assert_backend_identity on the SOURCE log.
#   assert_tpc_denied      — negative: SOURCE refused + DEST file absent.
#   run_tpc_cell           — positive userA + negative userB → one outcome line.
#
# PROOF STANDARD (spec §2): a TPC PULL asks the DESTINATION to copy `file` from a
# SOURCE server; bytes flow source→dest.  Positive = byte-exact copy AND the
# SOURCE authenticated userA (source-log DN for GSI, sub for token) — the
# delegated end-user identity, not a service credential.  Negative = userB (no /
# wrong delegated cred) → SOURCE denies + DEST file absent.
#
# SAFETY: fresh reserved port block 21900-21959 (disjoint from the normal-access
# matrix's 21960-21999). Documented in docs/10-reference/test-fleet-ports.md.
# Teardown kills only PIDs recorded in fwd_matrix.sh's node registry; ports are
# freed with `fuser -k <port>/tcp` (never a broad `pkill -f`).

# ---------------------------------------------------------------------------
# Reserve the fresh TPC block.  fwd_matrix.sh defaults FWD_PORT_BASE to 21960;
# the two TPC drivers override it to a sub-range of 21900-21959 before sourcing
# is complete, so set a safe TPC default here too.
# ---------------------------------------------------------------------------
TPC_HOST="${TPC_HOST:-localhost}"   # a NAME (matches the cert DNS:localhost SAN)
                                    # so the GSI client does NOT fall back to
                                    # reverse-DNS, which forbids proxy delegation.

# ---------------------------------------------------------------------------
# Outcome bookkeeping (parallel to fwd_matrix's FWD_RESULTS/FWD_ANY_FAIL, kept
# separate so a TPC driver reports its own table).
# ---------------------------------------------------------------------------
TPC_RESULTS=()          # "<key>|<OUTCOME>|<detail>"
TPC_ANY_FAIL=0

tpc_record() {   # <cellkey> <outcome> [detail]
    local key="$1" outcome="$2" detail="${3:-}"
    TPC_RESULTS+=("$key|$outcome|$detail")
    case "$outcome" in
        FAIL) TPC_ANY_FAIL=1 ;;
    esac
    printf '  %-12s %-34s %s\n' "$outcome" "$key" "$detail"
}

tpc_summary() {   # <label>
    local label="$1" r
    echo ""
    echo "---- $label summary ----"
    for r in "${TPC_RESULTS[@]}"; do
        printf '  %-34s %-12s %s\n' "${r%%|*}" \
            "$(echo "$r" | cut -d'|' -f2)" "$(echo "$r" | cut -d'|' -f3-)"
    done
    local gaps
    gaps=$(printf '%s\n' "${TPC_RESULTS[@]}" | grep -c '|GAP|' || true)
    [ "$gaps" != 0 ] && echo "  ($gaps GAP cell(s) — documented delegation limitation, evidence attached)"
    [ "$TPC_ANY_FAIL" = 0 ] && echo "$label: no FAIL cells" || echo "$label: FAIL cells present"
}

# ===========================================================================
# SOURCE node emitters — a SOURCE is a plain single-export brix (or stock) node
# that authenticates the incoming pull leg.  It is NOT a TPC coordinator; it
# just serves bytes to whoever proves the right identity.  Because the proof is
# "the SOURCE authenticated userA", the source is configured with EXACTLY ONE
# credential path so an alternate (service) identity cannot mask the result.
# ===========================================================================

# spawn_brix_source_root <role> <cred> <port>
#   A brix root:// source. GSI: cert+key+trusted_ca, brix_auth gsi (only a valid
#   delegated proxy authenticates). token: brix_auth token, roots:// TLS advert.
#   Sets FWD_LAST_LOG to the source error_log. Seeds no file (caller does).
spawn_brix_source_root() {
    local role="$1" cred="$2" port="$3" extra
    if [ "$cred" = gsi ]; then
        extra="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
    else
        # ztn requires TLS on the wire; a brix root token source advertises its
        # certificate so the outbound TPC session can upgrade to roots://.
        extra="brix_auth token;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_token_jwks      $TOK_JWKS;
        brix_token_issuer    $TOK_ISSUER;
        brix_token_audience  $TOK_AUD;"
    fi
    spawn_brix_node "$role" root "$port" "" "$extra"
}

# spawn_brix_source_dav <role> <cred> <port> [authdb_file]
#   A brix WebDAV https source.  TOKEN source is deliberately TOKEN-ONLY (no
#   ssl_verify_client, no proxy_certs) so the ONLY credential that authenticates
#   the pull leg is the forwarded bearer — proving forwarding unambiguously.  A
#   GSI dav source verifies the client proxy (proxy_certs on).
#   authdb_file (GSI only): a native u/g/p authdb granting READ only to userA's
#   exact DN — so a pull that presents userB's proxy authenticates but is denied
#   (no matching rule), the genuine negative control for per-user forwarding.
spawn_brix_source_dav() {
    local role="$1" cred="$2" port="$3" authdb_file="${4:-}"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
    local sslblock authblock
    if [ "$cred" = gsi ]; then
        sslblock="listen 127.0.0.1:${port} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;"
        authblock="brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;"
        [ -n "$authdb_file" ] && authblock="$authblock
            brix_webdav_authdb $authdb_file;"
    else
        sslblock="listen 127.0.0.1:${port} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;"
        authblock="brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;
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
    server {
        $sslblock
        client_max_body_size 1g;
        location / {
            brix_webdav on;
            brix_allow_write on;
            brix_export $d/export;
            $authblock
        }
    }
}
EOF
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (dav source start failed for $role: $(cat "$d/start.err"))" >&2
        return 1
    }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.6; return 0
}

# ===========================================================================
# DESTINATION (TPC coordinator) emitters — a DEST receives the client's COPY /
# open-with-tpc.src request and PULLS from the SOURCE.  brix WebDAV TPC = curl
# COPY (tpc.c); brix native root:// TPC = delegated-proxy / bearer outbound pull
# (src/tpc/*).
# ===========================================================================

# spawn_brix_dest_root <role> <cred> <port> [bearer_mode]
#   A brix root:// TPC destination.
#     GSI  : brix_tpc_delegate on (capture client proxy → pull as the user),
#            brix_gsi_signed_dh require (the client only signs a proxy request
#            when the server's DH params are RSA-signed), cert+key+trusted_ca.
#     token: the per-transfer bearer the DEST presents to the source is chosen by
#            <bearer_mode> (4th arg):
#              passthrough  — brix_tpc_outbound_passthrough on: the DEST forwards
#                             the CLIENT's own inbound bearer JWT (validated at the
#                             DEST via brix_auth token) verbatim to the source, so
#                             the source authenticates the END USER.  This is the
#                             real client-driven forwarding path (phase-70).
#              <a file path> — brix_tpc_outbound_bearer_file <path>: a static
#                             configured bearer (legacy, not client-driven).
#              ""           — neither (anonymous outbound; the negative control).
spawn_brix_dest_root() {
    local role="$1" cred="$2" port="$3" bearer_mode="${4:-}"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
    local auth tpc
    if [ "$cred" = gsi ]; then
        auth="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
        tpc="brix_tpc_allow_local on;
        brix_tpc_allow_private on;
        brix_tpc_delegate on;
        brix_gsi_signed_dh require;"
    else
        auth="brix_auth token;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_token_jwks      $TOK_JWKS;
        brix_token_issuer    $TOK_ISSUER;
        brix_token_audience  $TOK_AUD;"
        tpc="brix_tpc_allow_local on;
        brix_tpc_allow_private on;
        brix_tpc_outbound_tls on;"
        if [ "$bearer_mode" = passthrough ]; then
            tpc="$tpc
        brix_tpc_outbound_passthrough on;"
        elif [ -n "$bearer_mode" ]; then
            tpc="$tpc
        brix_tpc_outbound_bearer_file $bearer_mode;"
        fi
    fi
    cat > "$d/nginx.conf" <<EOF
daemon on;
error_log $log info;
pid $pid;
worker_processes 1;
thread_pool default threads=4 max_queue=65536;
events { worker_connections 64; }
stream {
    server {
        listen 127.0.0.1:${port};
        brix_root on;
        brix_export $d/export;
        brix_allow_write on;
        brix_upload_resume off;
        $auth
        $tpc
    }
}
EOF
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (root dest start failed for $role: $(cat "$d/start.err"))" >&2
        return 1
    }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.7; return 0
}

# spawn_brix_dest_dav <role> <cred> <port> [static_mode]
#   A brix WebDAV TPC destination (the curl-COPY puller).
#     token: no per-request client cert — the forwarded bearer rides via
#            TransferHeaderAuthorization; only brix_webdav_tpc_cafile to verify
#            the source's TLS server cert.
#     gsi  : phase-70 per-user delegated proxy on the pull leg — the DEST is put
#            in brix_backend_delegation passthrough mode so it (1) captures the
#            requesting user's full proxy from the X-Brix-Delegate-Proxy header
#            (leaf DN bound to the authenticated identity) OR (2) resolves it from
#            the per-user delegation store <brix_storage_credential_dir>/<key>.pem,
#            and presents THAT proxy to the source instead of the static service
#            cert.  So a GSI HTTP-TPC pull authenticates the END USER at the
#            source.
#            static_mode (gsi only): "nostatic" omits brix_webdav_tpc_cert/key so
#            a non-delegated pull has NO credential to present (the negative
#            control); anything else keeps the static service cert as a fallback.
spawn_brix_dest_dav() {
    local role="$1" cred="$2" port="$3" static_mode="${4:-}"
    local d="$FWD_PFX/$role"; mkdir -p "$d/export" "$d/logs" "$d/cred"
    local log="$d/logs/e.log" pid="$d/nginx.pid"
    local auth tpc static_cert=""
    if [ "$cred" = gsi ]; then
        auth="brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;
            brix_backend_delegation passthrough;
            brix_storage_credential_dir $d/cred;"
        if [ "$static_mode" != nostatic ]; then
            static_cert="brix_webdav_tpc_cert   $SERVER_CERT;
            brix_webdav_tpc_key    $SERVER_KEY;"
        fi
        tpc="brix_webdav_tpc on;
            brix_webdav_tpc_allow_local on;
            $static_cert
            brix_webdav_tpc_cafile $CA_CERT;
            brix_webdav_tpc_timeout 15;"
    else
        auth="brix_webdav_cafile $CA_CERT;
            brix_webdav_auth required;
            brix_webdav_token_jwks     $TOK_JWKS;
            brix_webdav_token_issuer   $TOK_ISSUER;
            brix_webdav_token_audience $TOK_AUD;"
        tpc="brix_webdav_tpc on;
            brix_webdav_tpc_allow_local on;
            brix_webdav_tpc_cafile $CA_CERT;
            brix_webdav_tpc_timeout 15;"
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
        listen 127.0.0.1:${port} ssl;
        ssl_certificate     $SERVER_CERT;
        ssl_certificate_key $SERVER_KEY;
        ssl_client_certificate $CA_CERT;
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        client_max_body_size 1g;
        location / {
            brix_webdav on;
            brix_allow_write on;
            brix_export $d/export;
            $auth
            $tpc
        }
    }
}
EOF
    env -u NGINX "$NGINX_BIN" -p "$d" -c "$d/nginx.conf" 2>"$d/start.err" || {
        echo "  (dav dest start failed for $role: $(cat "$d/start.err"))" >&2
        return 1
    }
    FWD_NODE_PIDS+=("$pid"); FWD_LAST_LOG="$log"; sleep 0.6; return 0
}

# ===========================================================================
# Stock XRootD SOURCE — for the brix-dest ← stock-source endpoint pairing.
# GSI-only (stock delegates GSI proxies only). Reuses spawn_xrootd_node origin.
# The stock source logs `XrootdXeq: … login as /DC=…/CN=<name>` for the pulled
# session; assert_source_identity stock matches that.
# ===========================================================================

# ===========================================================================
# PULL drivers.  Each returns:
#   TPC_COPY_OK   (0/1)   — the copy completed and the dest file is byte-exact
#   TPC_DENY_OBS  (str)   — a refusal signal for the negative control
# The SOURCE-log identity assertion is done by the caller via
# assert_source_identity (positive) after a successful copy.
# ===========================================================================
TPC_COPY_OK=0
TPC_DENY_OBS=""

# drive_tpc_webdav <cred> <src_port> <dst_port> <obj> <who>
#   PULL: curl -X COPY the DEST, telling it to fetch Source: from the SOURCE.
#   token: forward userA/userB's bearer via TransferHeaderAuthorization.
#   gsi  : the client DELEGATES its own full x509 proxy to the DEST via the
#          X-Brix-Delegate-Proxy header (base64 PEM; leaf DN bound to the client
#          cert it authenticates with).  With the DEST in brix_backend_delegation
#          passthrough mode, the DEST presents THAT proxy to the source, so the
#          source authenticates the END USER (userA), not the static service cert.
#   The client authenticates to the DEST with its own credential (bearer/proxy).
drive_tpc_webdav() {
    local cred="$1" sport="$2" dport="$3" obj="$4" who="$5"
    local src_url="https://${TPC_HOST}:${sport}/tpcsrc.bin"
    local dst_url="https://${TPC_HOST}:${dport}/${obj}"
    local dexport="$FWD_PFX/dstdav/export"
    TPC_COPY_OK=0; TPC_DENY_OBS=""

    local code
    if [ "$cred" = token ]; then
        local jwt; [ "$who" = A ] && jwt="$TOKEN_A" || jwt="$TOKEN_B"
        code=$(curl -sk -H "Authorization: Bearer $(cat "$jwt")" \
            -X COPY "$dst_url" \
            -H "Credential: none" \
            -H "Source: $src_url" \
            -H "TransferHeaderAuthorization: Bearer $(cat "$jwt")" \
            -w '%{http_code}' -o /dev/null 2>/dev/null)
    else
        local px; [ "$who" = A ] && px="$PROXY_A" || px="$PROXY_B"
        if [ "$who" = A ]; then
            # userA DELEGATES its own full proxy to the DEST (base64 PEM, one line;
            # leaf DN bound to the client cert userA authenticates with).  The DEST
            # presents THAT proxy to the source → source authenticates userA.
            local deleg_b64; deleg_b64=$(base64 -w0 "$px" 2>/dev/null || base64 "$px" | tr -d '\n')
            code=$(curl -sk --cert "$px" --key "$px" \
                -X COPY "$dst_url" \
                -H "Credential: none" \
                -H "Source: $src_url" \
                -H "X-Brix-Delegate-Proxy: $deleg_b64" \
                -w '%{http_code}' -o /dev/null 2>/dev/null)
        else
            # userB authenticates to the DEST but does NOT delegate a proxy — the
            # negative control.  With no static service-cert fallback the DEST has
            # no credential for the outbound pull and the source denies it.
            code=$(curl -sk --cert "$px" --key "$px" \
                -X COPY "$dst_url" \
                -H "Credential: none" \
                -H "Source: $src_url" \
                -w '%{http_code}' -o /dev/null 2>/dev/null)
        fi
    fi
    TPC_DENY_OBS="$code"
    case "$code" in
        201|204|200)
            # Copy accepted end-to-end; verify byte-exactness at the dest store.
            if cmp -s "$FWD_PFX/tpcsrc.bin" "$dexport/$obj" 2>/dev/null; then
                TPC_COPY_OK=1
            fi
            ;;
    esac
}

# drive_tpc_root <cred> <src_port> <dst_port> <obj> <who>
#   PULL: xrdcp --tpc delegate root://SRC//f root://DEST//obj.
#   gsi  : userA sets XRDC_GSI_DELEGATE=1 so the client delegates its proxy to
#          the DEST, which then pulls from the SOURCE as userA.  userB does NOT
#          delegate (XRDC_GSI_DELEGATE unset) — the DEST cannot capture a proxy,
#          the outbound pull is anonymous, and the auth-required SOURCE denies.
#   token: userA/userB present a bearer to the DEST; the DEST forwards to the
#          SOURCE from its configured brix_tpc_outbound_bearer_file (see GAP).
drive_tpc_root() {
    local cred="$1" sport="$2" dport="$3" obj="$4" who="$5"
    local src_url="root://${TPC_HOST}:${sport}//tpcsrc.bin"
    local dst_url="root://${TPC_HOST}:${dport}//${obj}"
    local dexport="$FWD_PFX/dstroot/export"
    TPC_COPY_OK=0; TPC_DENY_OBS=""

    local rc
    if [ "$cred" = gsi ]; then
        local px; [ "$who" = A ] && px="$PROXY_A" || px="$PROXY_B"
        if [ "$who" = A ]; then
            # userA opts into delegation: the client signs the dest's proxy
            # request and the dest pulls from the source AS userA.
            XRDC_GSI_DELEGATE=1 \
                fwd_run_as "$px" "$BRIX_XRDCP" -f --tpc delegate \
                "$src_url" "$dst_url" >"$FWD_PFX/tpc_${who}.out" 2>"$FWD_PFX/tpc_${who}.err"
            rc=$?
        else
            # userB does NOT opt in: XRDC_GSI_DELEGATE MUST be truly UNSET (not
            # empty — getenv()!=NULL would still enable it).  The client then
            # refuses to sign the dest's proxy request, the dest captures no
            # proxy, the outbound pull cannot authenticate as the user, and the
            # auth-required source serves no bytes to the dest — the negative
            # control.  Run in a subshell so the unset does not leak.
            ( unset XRDC_GSI_DELEGATE
              fwd_run_as "$px" "$BRIX_XRDCP" -f --tpc delegate \
                "$src_url" "$dst_url" >"$FWD_PFX/tpc_${who}.out" 2>"$FWD_PFX/tpc_${who}.err" )
            rc=$?
        fi
    else
        local jwt; [ "$who" = A ] && jwt="$TOKEN_A" || jwt="$TOKEN_B"
        BEARER_TOKEN="$(cat "$jwt")" X509_USER_PROXY=/dev/null XrdSecPROTOCOL=ztn \
            "$BRIX_XRDCP" -f --tpc delegate \
            "$src_url" "$dst_url" >"$FWD_PFX/tpc_${who}.out" 2>"$FWD_PFX/tpc_${who}.err"
        rc=$?
    fi
    TPC_DENY_OBS="rc=$rc"
    if [ "$rc" = 0 ] && cmp -s "$FWD_PFX/tpcsrc.bin" "$dexport/$obj" 2>/dev/null; then
        TPC_COPY_OK=1
    fi
}

# ---------------------------------------------------------------------------
# assert_source_identity <brix|stock> <cred> <src-log>
#   0 iff the SOURCE log shows it authenticated userA on the pulled leg
#   (GSI DN CN=Fwd User A / token sub=fwd-user-a for brix; login-as for stock).
# ---------------------------------------------------------------------------
assert_source_identity() {
    local kind="$1" cred="$2" log="$3"
    if [ "$cred" = gsi ]; then
        assert_backend_identity "$kind" "$log" "$A_CN"
    else
        assert_backend_identity "$kind" "$log" "$A_SUB"
    fi
}

# assert_source_is_not_user — GAP evidence: the source authenticated SOMEONE
# (service) but NOT userA. 0 iff the copy landed yet the source log lacks userA.
assert_source_is_not_user() {
    local kind="$1" cred="$2" log="$3"
    ! assert_source_identity "$kind" "$cred" "$log"
}

# ---------------------------------------------------------------------------
# assert_tpc_denied <flavor> <dst_export_file>
#   Negative-control checker: 0 iff the pull was refused (TPC_COPY_OK==0 and the
#   dest file is absent).  `flavor` is informational (webdav|root).
# ---------------------------------------------------------------------------
assert_tpc_denied() {
    local flavor="$1" dstfile="$2"
    [ "$TPC_COPY_OK" = 1 ] && return 1
    [ -f "$dstfile" ] && return 1
    return 0
}
