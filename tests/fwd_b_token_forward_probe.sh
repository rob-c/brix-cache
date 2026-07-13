#!/usr/bin/env bash
# fwd_b_token_forward_probe.sh — EMPIRICAL probe of whether a stock xrootd
# front (pss forwarding proxy / pfc caching proxy / persona) forwards the
# END-USER's WLCG bearer token to a brix backend over roots:// (ztn).
#
# This is a standalone evidence-gathering harness for pairing B token
# forwarding.  It reuses tests/lib/fwd_matrix.sh helpers (PKI, token authority,
# OIDC server, brix node spawner) but drives the stock front with three
# candidate token-forwarding configs, in order of likelihood:
#
#   1. pss forwarding proxy  (pss.origin roots://<brix-back>) + ztn front door
#   2. pfc caching proxy     (ofs.osslib libXrdPfc.so + pss.origin roots://…)
#   3. pss persona client    (pss.persona client) — SSS identity mapping
#
# For each, the client presents TOKEN_A over ztn to the stock front; we then
# inspect the BRIX BACKEND log for `brix_token: valid token sub="fwd-user-a"`
# (proof the end-user token was forwarded) vs. anonymous/no-auth (proof it was
# not).  Nothing is faked: the exact stock behavior/log is reported either way.
#
# Ports 21980-21999; scoped teardown via fwd_matrix.  Do NOT git.
set -u
source "$(dirname "$0")/lib/fwd_matrix.sh"
FWD_PORT_BASE="${FWD_PORT_BASE:-21980}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

PROBE_RESULTS=()
probe_record() { PROBE_RESULTS+=("$1|$2|$3"); printf '  [%s] %-26s %s\n' "$2" "$1" "$3"; }

fwd_setup fwd_bprobe 1 || { echo "probe SKIPPED (setup)"; exit 0; }
trap fwd_cleanup EXIT
mint_pki   || exit 0
mint_token || { echo "probe SKIPPED (token authority)"; exit 0; }

# ---------------------------------------------------------------------------
# Backend: brix root:// (roots://, TLS) TOKEN origin advertising ztn, trusting
# the local OIDC issuer.  This is the node whose log is the source of truth.
# ---------------------------------------------------------------------------
start_brix_token_backend() {   # <port>  -> sets BBK_LOG, BBK_EXPORT
    local port="$1"
    # spawn_brix_node 'roots' already emits brix_certificate/_key (TLS listener);
    # bextra only adds the token auth wiring.
    local bextra="brix_auth token;
        brix_token_jwks     $TOK_JWKS;
        brix_token_issuer   $TOK_ISSUER;
        brix_token_audience $TOK_AUD;"
    spawn_brix_node "bbk_tok" roots "$port" "" "$bextra" || return 1
    BBK_LOG="$FWD_LAST_LOG"
    BBK_EXPORT="$FWD_PFX/bbk_tok/export"
    return 0
}

# ---------------------------------------------------------------------------
# Stock front spawner variants.  Each writes its own cfg (we don't reuse the
# library pss emitter — we want to try the caching/persona shapes it lacks).
# The front's ztn front door needs TLS + SciTokens authlib (same shape as the
# proven pairing-A origin) so the CLIENT can present TOKEN_A to it over ztn.
# ---------------------------------------------------------------------------
front_sec_block() {   # writes $1/scitokens.cfg, echoes the ztn sec block
    local d="$1"
    cat > "$d/scitokens.cfg" <<EOF
[Global]
audience = ${TOK_AUD}
[Issuer test]
issuer = ${TOK_ISSUER}
base_path = /
default_user = fwduser
EOF
    local sec_lib="/usr/lib64/libXrdSec-5.so"; [ -f "$sec_lib" ] || sec_lib="/usr/lib/libXrdSec-5.so"
    cat <<EOF
xrd.tls   $SERVER_CERT $SERVER_KEY
xrd.tlsca certdir $CA_DIR
xrootd.seclib $sec_lib
sec.protocol ztn
sec.protbind * ztn
ofs.authorize 1
ofs.authlib libXrdAccSciTokens-5.so config=$d/scitokens.cfg
EOF
}

# spawn_stock_front <role> <variant> <port> <brix-backhost:port>
#   variant: fwd | pfc | persona
spawn_stock_front() {
    local role="$1" variant="$2" port="$3" backhost="$4"
    local d="$FWD_PFX/$role"; mkdir -p "$d/data" "$d/admin" "$d/run" "$d/pfc" "$d/scitok_cache"
    local cfg="$d/x.cfg" log="$d/x.log"; : > "$log"
    local sec; sec="$(front_sec_block "$d")"
    local origin="roots://${backhost}/"     # ztn requires TLS to the origin

    case "$variant" in
        fwd)
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
pss.origin ${origin}
pss.setopt DebugLevel 0
$sec
EOF
            ;;
        pfc)
            # XCache caching-proxy shape: pss provides the origin, Pfc is the
            # oss cache layer.  This is the config known in the field to sit
            # between a client and an origin; we test whether it forwards the
            # client token to pss.origin.
            # Canonical XCache shape: Pfc is the ofs oss layer; Pss is Pfc's
            # backing oss (the origin fetcher); pss.origin names the brix backend.
            cat > "$cfg" <<EOF
all.role server
all.export /
oss.localroot $d/pfc
all.adminpath $d/admin
all.pidpath   $d/run
xrd.port ${port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
ofs.osslib libXrdPfc.so
pfc.osslib libXrdPss.so
pss.origin ${origin}
pss.setopt DebugLevel 0
pfc.blocksize 1M
$sec
EOF
            ;;
        persona)
            # pss.persona client: proxy the client's identity to the origin via
            # SSS.  Requires an origin (ManList) — pss.origin supplies it.
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
pss.origin ${origin}
pss.persona client
pss.setopt DebugLevel 0
$sec
EOF
            ;;
    esac

    # Front needs the OIDC CA trust for ztn/SciTokens JWKS fetch → bwrap, same
    # as the pairing-A token origin.
    local bundle real_bundle
    bundle="$(fwd_trusted_ca_bundle)"
    real_bundle="$(readlink -f /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null)"
    [ -n "$real_bundle" ] || real_bundle="/etc/pki/tls/certs/ca-bundle.crt"
    rm -rf "$d/scitok_cache"; mkdir -p "$d/scitok_cache"
    bwrap --dev-bind / / --bind "$bundle" "$real_bundle" \
          --setenv XDG_CACHE_HOME "$d/scitok_cache" \
          "$XROOTD_BIN" -c "$cfg" -l "$log" >"$d/start.err" 2>&1 &
    echo $! > "$d/bwrap.pid"; FWD_NODE_PIDS+=("$d/bwrap.pid")
    FRONT_LOG="$log"; FRONT_CFG="$cfg"
    local i; for i in $(seq 1 30); do ss -tlnp 2>/dev/null | grep -q ":${port} " && break; sleep 0.2; done
    sleep 0.5
    return 0
}

# ---------------------------------------------------------------------------
# Drive one variant: client TOKEN_A -> stock front (roots://, ztn) ; observe
# the brix backend log.  Also run the userB (wrong-issuer) negative.
# ---------------------------------------------------------------------------
run_variant() {
    local variant="$1"
    local bport fport; fwd_port bport; fwd_port fport
    start_brix_token_backend "$bport" || { probe_record "$variant" SKIP "brix token backend failed to start"; return; }
    spawn_stock_front "sf_$variant" "$variant" "$fport" "127.0.0.1:${bport}"

    # If the front never came up (config rejected), that IS the evidence.
    if ! ss -tlnp 2>/dev/null | grep -q ":${fport} "; then
        local why; why="$(grep -iE 'Config|error|persona|unsupported|unable' "$FRONT_LOG" 2>/dev/null | tail -3 | tr '\n' ';')"
        probe_record "$variant" BLOCKED "front did not listen: ${why:-see $FRONT_LOG}"
        return
    fi

    : > "$BBK_LOG"
    local payload="$FWD_PFX/pl_$variant.bin"; head -c 65536 /dev/urandom > "$payload"
    # Client presents TOKEN_A over ztn to the roots:// stock front.  X509_CERT_FILE
    # points at the test CA so the client's XrdCl TLS trusts the front's hostcert;
    # X509_CERT_DIR gives the hashed CA dir.  BEARER_TOKEN feeds the ztn client.
    BEARER_TOKEN="$(cat "$TOKEN_A")" XrdSecPROTOCOL=ztn \
        X509_CERT_DIR="$CA_DIR" X509_CERT_FILE="$CA_CERT" XrdSecGSICADIR="$CA_DIR" \
        XRD_CONNECTIONWINDOW=8 XRD_CONNECTIONRETRY=1 XRD_REQUESTTIMEOUT=12 \
        XRD_STREAMTIMEOUT=12 XRD_TIMEOUTRESOLUTION=1 \
        timeout 40 "$SYS_XRDCP" -f "$payload" \
        "roots://127.0.0.1:${fport}//probe_${variant}.bin" \
        >/dev/null 2>"$FWD_PFX/put_$variant.err" || true
    sleep 0.8

    # Evidence extraction from the BRIX BACKEND log.
    if grep -qE 'valid token sub="?fwd-user-a"?' "$BBK_LOG" 2>/dev/null; then
        if [ -f "$BBK_EXPORT/probe_${variant}.bin" ]; then
            probe_record "$variant" PASS "brix-back authenticated END USER (sub=fwd-user-a) AND bytes landed"
        else
            probe_record "$variant" PARTIAL "brix-back authenticated sub=fwd-user-a but no bytes"
        fi
    elif grep -qE 'valid token sub=' "$BBK_LOG" 2>/dev/null; then
        local sub; sub="$(grep -oE 'valid token sub="?[^" ]+' "$BBK_LOG" | tail -1)"
        probe_record "$variant" WRONG_ID "brix-back authenticated a NON-userA token: $sub"
    elif grep -qE 'token|auth|login|Auth' "$BBK_LOG" 2>/dev/null; then
        probe_record "$variant" NO_FWD "brix-back saw auth activity but NOT userA's token (see below)"
    else
        probe_record "$variant" NO_FWD "brix-back authenticated NOBODY — token NOT forwarded (anonymous)"
    fi

    # Dump the decisive lines for the report.
    echo "    --- brix-back auth-relevant log ($variant) ---"
    grep -iE 'token|auth|login|ztn|handshake|anonymous|entity|sub=' "$BBK_LOG" 2>/dev/null | sed 's/^/      /' | tail -8
    echo "    --- stock front auth/config log ($variant) ---"
    grep -iE 'ztn|token|persona|forward|Config|login|auth|error' "$FRONT_LOG" 2>/dev/null | sed 's/^/      /' | tail -8
    echo "    --- client PUT stderr ($variant) ---"
    sed 's/^/      /' "$FWD_PFX/put_$variant.err" 2>/dev/null | tail -4
}

echo "== PAIRING B token-forwarding EMPIRICAL PROBE (stock front -> brix-back roots://) =="
for v in fwd pfc persona; do
    fwd_cell_begin
    run_variant "$v"
    fwd_cell_end
done

echo ""
echo "---- probe summary ----"
for r in "${PROBE_RESULTS[@]}"; do
    printf '  %-10s %-10s %s\n' "${r%%|*}" "$(echo "$r"|cut -d'|' -f2)" "$(echo "$r"|cut -d'|' -f3-)"
done
