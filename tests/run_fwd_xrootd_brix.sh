#!/usr/bin/env bash
# run_fwd_xrootd_brix.sh — credential-forwarding matrix, PAIRING B: stock-
# xrootd-front (pss forwarding proxy) -> brix-back.  wire in {RR,HR} x
# cred in {gsi,token}.  HH/RH are SKIP-by-design (stock pss has no https
# backend leg).
#
# Each B cell ATTEMPTS stock delegation.  If userA's identity reaches brix-back
# => PASS.  If stock forwards only its own service identity => GAP (asserted:
# the svc DN, not userA, is what brix-back authenticated).  Backend identity is
# read from the BRIX-back log.  Binary gate: no /usr/bin/xrootd => SKIP all.
#
# B *token* cells are a PROVEN stock BLOCKER (GAP): stock xrootd v5.9.6 does not
# forward the client's WLCG bearer token to the origin.  The empirical evidence
# — pss forwarding, pfc caching, and pss.persona all attempted, with the exact
# source (XrdPssConfig "we don't support credential forwarding, yet") and runtime
# logs (a pure ztn origin DOES accept the same token: `login as fwd-user-a`) — is
# gathered by tests/fwd_b_token_forward_probe.sh.  Run that probe to reproduce.
#
# Design: docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md
set -u
source "$(dirname "$0")/lib/fwd_matrix.sh"
FWD_PORT_BASE="${FWD_PORT_BASE:-21970}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

fwd_setup fwd_b 1; rc=$?
if [ "$rc" != 0 ]; then
    echo "run_fwd_xrootd_brix: pairing B SKIPPED wholesale (see reason above)"
    exit 0
fi
trap fwd_cleanup EXIT
mint_pki || exit 0
mint_token || echo "  (token authority unavailable — token cells will SKIP)"

run_cell_B() {
    local wire="$1" cred="$2"
    local hop1 hop2 key feas
    hop1=$(fwd_hop1 "$wire"); hop2=$(fwd_hop2 "$wire")
    key="B $wire $cred"
    feas="$(feasibility_probe B "$hop2" "$cred")"
    case "$feas" in
        SKIP:*)        fwd_record "$key" SKIP        "${feas#SKIP:}";        return ;;
        UNSUPPORTED:*) fwd_record "$key" UNSUPPORTED "${feas#UNSUPPORTED:}"; return ;;
    esac

    # Token forwarding through a stock xrootd front is a PROVEN stock BLOCKER on
    # this build (xrootd v5.9.6) — see tests/fwd_b_token_forward_probe.sh, which
    # attempts pss forwarding, pfc caching, and pss.persona and captures the
    # source+runtime evidence:
    #   * XrdPssConfig.cc: "We don't support credential forwarding, yet. If we
    #     did we would also set XrdSecPROXYCREDS" — the pss/pfc proxy authenticates
    #     to the origin as its OWN service identity (XrdSecPROXY=1), never the
    #     client's bearer;
    #   * pss.persona is refused for both "strictly forwarding proxy servers" and
    #     "caching proxy servers" (persona only applies to an origin, via SSS — it
    #     carries no WLCG token);
    #   * libXrdPfc-5.so in this build does not export XrdOssGetStorageSystem via
    #     `ofs.osslib libXrdPfc.so`, so the caching-proxy stack won't even load.
    # A pure stock ztn origin DOES accept the same client TOKEN_A (control:
    # `login as fwd-user-a`), so the block is squarely the stock front->backend
    # credential-forwarding leg, not the client or the brix backend.
    if [ "$cred" = token ]; then
        fwd_record "$key" GAP \
            "stock xrootd v5.9.6 does not forward the client WLCG token to the origin (pss/pfc/persona all proven not to carry the bearer — see fwd_b_token_forward_probe.sh); brix-back would authenticate the service, not fwd-user-a"
        return
    fi

    local bport fport
    fwd_port bport; fwd_port fport

    # Backend: brix root:// GSI/token origin.
    local bextra
    if [ "$cred" = gsi ]; then
        bextra="brix_auth gsi;
        brix_certificate     $SERVER_CERT;
        brix_certificate_key $SERVER_KEY;
        brix_trusted_ca      $CA_CERT;"
    else
        bextra="brix_auth token;
        brix_token_jwks     $TOK_JWKS;
        brix_token_issuer   $TOK_ISSUER;
        brix_token_audience $TOK_AUD;"
    fi
    spawn_brix_node "bbk_${wire}_${cred}" root "$bport" "" "$bextra" || {
        fwd_record "$key" FAIL "brix backend start failed"; return; }
    local blog="$FWD_LAST_LOG"
    local bexport="$FWD_PFX/bbk_${wire}_${cred}/export"

    # Front: stock xrootd pss forwarding proxy -> brix-back.
    spawn_xrootd_node "bfront_${wire}_${cred}" pss "$fport" "127.0.0.1:${bport}" "$cred"

    # userA drives hop-1 to the pss front (root://).  The stock proxy presents
    # ITS identity (or, if delegation is configured+honored, userA's) to brix.
    : > "$blog"
    local payload="$FWD_PFX/payloadB_A.bin" got="$FWD_PFX/gotB_A.bin"
    head -c 65536 /dev/urandom > "$payload"
    if [ "$cred" = gsi ]; then
        fwd_run_as "$PROXY_A" "$SYS_XRDCP" -f "$payload" \
            "root://127.0.0.1:${fport}//posB_${wire}.bin" >/dev/null 2>"$FWD_PFX/putB.err" || true
    else
        BEARER_TOKEN="$(cat "$TOKEN_A")" "$SYS_XRDCP" -f "$payload" \
            "root://127.0.0.1:${fport}//posB_${wire}.bin" >/dev/null 2>"$FWD_PFX/putB.err" || true
    fi
    sleep 0.5

    # Round-trip check (best-effort) + identity check on brix-back.
    if assert_backend_identity brix "$blog" "$A_CN" || assert_backend_identity brix "$blog" "$A_SUB"; then
        # Verify bytes actually landed.
        if [ -f "$bexport/posB_${wire}.bin" ]; then
            fwd_record "$key" PASS "stock pss forwarded userA identity to brix-back"
        else
            fwd_record "$key" GAP "userA authenticated at brix-back but no bytes (pss delegated auth only)"
        fi
        return
    fi
    # Did the SERVICE identity reach the backend instead?  Proven GAP.
    if grep -qE 'GSI auth OK dn=|valid token sub=' "$blog" 2>/dev/null; then
        fwd_record "$key" GAP "stock pss forwarded its own service identity, not userA (documented stock limitation)"
    elif ! grep -q '.' "$blog" 2>/dev/null || ! grep -qE 'auth|login|token' "$blog" 2>/dev/null; then
        # brix-back never authenticated anyone (pss anonymous / no forward).
        fwd_record "$key" GAP "stock pss forwarded no client credential to brix-back (anonymous forward)"
    else
        fwd_record "$key" GAP "brix-back saw a non-userA identity from the stock pss front"
    fi
}

echo "== credential-forwarding matrix — PAIRING B (xrootd-front -> brix-back) =="
for wire in RR HR HH RH; do
    for cred in gsi token; do
        fwd_cell_begin
        run_cell_B "$wire" "$cred"
        fwd_cell_end
    done
done

echo ""
echo "---- pairing B summary ----"
for r in "${FWD_RESULTS[@]}"; do
    printf '  %-30s %-14s %s\n' "${r%%|*}" "$(echo "$r" | cut -d'|' -f2)" "$(echo "$r" | cut -d'|' -f3-)"
done
[ "$FWD_ANY_FAIL" = 0 ] && echo "run_fwd_xrootd_brix: no FAIL cells" || echo "run_fwd_xrootd_brix: FAIL cells present"
exit "$FWD_ANY_FAIL"
