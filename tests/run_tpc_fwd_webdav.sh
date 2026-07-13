#!/usr/bin/env bash
# run_tpc_fwd_webdav.sh — WebDAV/HTTP third-party-copy credential forwarding.
#
# Flavor: WebDAV/HTTP TPC — curl `-X COPY` with a `Source:` header, PULL (the
# destination fetches the object from the source).  brix WebDAV TPC = curl COPY
# (src/protocols/webdav/tpc.c).
#
# Cells: cred {gsi-proxy-delegation, bearer-token}
#      × endpoints {brix-src→brix-dest, stock-XrdHttp-src→brix-dest,
#                   brix-src→stock-XrdHttp-dest}
# The DEST is always the TPC coordinator (the puller).  A stock-XrdHttp DEST has
# no brix TPC puller of our shape, so brix-src→stock-dest is a SKIP (documented).
#
# PROOF (spec §2): positive = byte-exact copy AND the SOURCE authenticated userA
# (source-log token sub / GSI DN); negative = userB (wrong-issuer token / userB
# proxy) → source denies + dest file absent.
#
# FORWARDING (phase-70): the brix WebDAV puller now presents the REQUESTING
# USER's delegated x509 proxy on the pull leg (from the live X-Brix-Delegate-Proxy
# passthrough header OR the per-user delegation store), so a GSI HTTP-TPC pull
# authenticates the END USER at the source (evidence: the source logs the user DN
# CN=Fwd User A, not the service CN=localhost).  Enabled by brix_backend_delegation
# passthrough on the DEST (webdav_tpc_user_proxy_resolve → CURLOPT_SSLCERT).
#
# KNOWN LIMITATIONS asserted (not assumed):
#   * stock-XrdHttp SOURCE ← brix DEST GSI: exercising this against a STOCK
#     XrdHttp origin would additionally need that origin's http.gridmap to map the
#     forwarded userA proxy-leaf DN — a stock-provisioning step not stood up in
#     this harness — so that endpoint stays a documented GAP (the brix-src→brix-
#     dest gsi cell carries the brix forwarding proof for real).
#
# Design: docs/superpowers/specs/2026-07-11-tpc-credential-forwarding-tests-design.md
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/lib/fwd_matrix.sh"
source "$HERE/lib/tpc_fwd.sh"

# Fresh reserved block 21900-21959 (WebDAV flavor: 21900-21929).
FWD_PORT_BASE="${FWD_PORT_BASE:-21900}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

fwd_setup tpc_webdav 0 || { echo "run_tpc_fwd_webdav: environment SKIP"; exit 0; }
trap fwd_cleanup EXIT
mint_pki || exit 0
mint_token || echo "  (token authority unavailable — token cells will SKIP)"

# Seed the payload the source serves (all cells pull the same object name).
head -c 65536 /dev/urandom > "$FWD_PFX/tpcsrc.bin"

# ---------------------------------------------------------------------------
# run_cell_bb_gsi <key> <sport> <dport>  — the GSI WebDAV bb cell, now a real
# per-user delegated-proxy forwarding proof (phase-70):
#   * userA delegates its own full proxy to the DEST via the X-Brix-Delegate-Proxy
#     header; the DEST (brix_backend_delegation passthrough, NO static service
#     cert configured) presents THAT proxy to the source, so the source
#     authenticates the END USER (userA), never the service CN=localhost;
#   * userB does NOT delegate a proxy — with no static service-cert fallback the
#     DEST has NO client credential for the outbound pull, so the auth-required
#     source denies it (no cert presented) and no bytes land.  This mirrors the
#     native-root GSI negative control (no delegation → no credential → denied).
# ---------------------------------------------------------------------------
run_cell_bb_gsi() {
    local key="$1" sport="$2" dport="$3"

    spawn_brix_source_dav srcdav gsi "$sport" || {
        tpc_record "$key" FAIL "brix dav source start failed"; return; }
    local slog="$FWD_LAST_LOG"
    cp "$FWD_PFX/tpcsrc.bin" "$FWD_PFX/srcdav/export/tpcsrc.bin"

    # dest has NO static service cert (delegation-only) so a non-delegated pull
    # has no credential to present — the genuine negative control.
    spawn_brix_dest_dav dstdav gsi "$dport" nostatic || {
        tpc_record "$key" FAIL "brix dav dest start failed"; return; }

    # --- positive: userA delegates its proxy; source must authenticate userA. ---
    : > "$slog"
    drive_tpc_webdav gsi "$sport" "$dport" "posA.bin" A
    if [ "$TPC_COPY_OK" != 1 ]; then
        tpc_record "$key" FAIL "userA delegated-proxy pull did not complete (code=$TPC_DENY_OBS) — dest: $(grep -iE 'deleg|proxy|tpc|GSI|403' "$FWD_PFX/dstdav/logs/e.log" 2>/dev/null | tail -1)"
        return
    fi
    if ! assert_source_identity brix gsi "$slog"; then
        local seen_dn
        seen_dn=$(grep -oE 'dn="[^"]*"' "$slog" | tail -1)
        tpc_record "$key" FAIL "delegated-proxy pull landed but source authenticated $seen_dn, not userA (CN=$A_CN) — passthrough not engaged; dest: $(grep -iE 'deleg|proxy|tpc' "$FWD_PFX/dstdav/logs/e.log" 2>/dev/null | tail -1)"
        return
    fi

    # --- negative: userB does NOT delegate; no static fallback → no credential
    #     on the outbound pull → auth-required source denies, no bytes. ---
    drive_tpc_webdav gsi "$sport" "$dport" "negB.bin" B
    if assert_tpc_denied webdav "$FWD_PFX/dstdav/export/negB.bin"; then
        tpc_record "$key" PASS "source authenticated userA (delegated proxy, CN=$A_CN, NOT the service CN=localhost); userB (no delegation, no fallback) denied, no bytes"
    else
        tpc_record "$key" FAIL "userB not denied (code=$TPC_DENY_OBS) or bytes leaked to dest"
    fi
}

# ---------------------------------------------------------------------------
# run_cell_bb <cred>  — brix WebDAV source → brix WebDAV dest (the core proof).
# ---------------------------------------------------------------------------
run_cell_bb() {
    local cred="$1" key="webdav bb $cred"
    if [ "$cred" = token ] && [ -z "$TOK_JWKS" ]; then
        tpc_record "$key" SKIP "token authority unavailable"; return
    fi
    local sport dport
    fwd_port sport; fwd_port dport

    if [ "$cred" = gsi ]; then
        run_cell_bb_gsi "$key" "$sport" "$dport"; return
    fi

    spawn_brix_source_dav srcdav "$cred" "$sport" || {
        tpc_record "$key" FAIL "brix dav source start failed"; return; }
    local slog="$FWD_LAST_LOG"
    cp "$FWD_PFX/tpcsrc.bin" "$FWD_PFX/srcdav/export/tpcsrc.bin"

    spawn_brix_dest_dav dstdav "$cred" "$dport" || {
        tpc_record "$key" FAIL "brix dav dest start failed"; return; }

    # ---- positive: userA pull, source must authenticate userA ----
    : > "$slog"
    drive_tpc_webdav "$cred" "$sport" "$dport" "posA.bin" A

    # token flavor: the real forwarding proof.
    if [ "$TPC_COPY_OK" != 1 ]; then
        tpc_record "$key" FAIL "userA token pull not byte-exact (code=$TPC_DENY_OBS)"; return
    fi
    sleep 0.3
    if ! assert_source_identity brix token "$slog"; then
        tpc_record "$key" FAIL "source did not authenticate userA (sub=$A_SUB) on the pull leg"; return
    fi
    # ---- negative: userB (wrong-issuer token) denied at source, no bytes ----
    drive_tpc_webdav token "$sport" "$dport" "negB.bin" B
    if assert_tpc_denied webdav "$FWD_PFX/dstdav/export/negB.bin"; then
        tpc_record "$key" PASS "source authenticated userA (forwarded bearer); userB denied, no bytes"
    else
        tpc_record "$key" FAIL "userB not denied (code=$TPC_DENY_OBS) or bytes leaked to dest"
    fi
}

# ---------------------------------------------------------------------------
# run_cell_sb <cred>  — stock XrdHttp source → brix WebDAV dest.
#   Stock XrdHttp does GSI client-cert auth (http.gridmap maps userA's DN → a
#   username). For the brix dest to pull AS userA it would need to present
#   userA's proxy to the stock source — but HTTP-TPC has no per-request proxy
#   (same static-cert limitation). Token: stock XrdHttp ztn-over-http source is
#   not provisioned in this harness. Both resolve to SKIP/GAP with evidence.
# ---------------------------------------------------------------------------
run_cell_sb() {
    local cred="$1" key="webdav stock-src->brix-dest $cred"
    if [ ! -x "$XROOTD_BIN" ]; then
        tpc_record "$key" SKIP "stock xrootd absent"; return
    fi
    if [ "$cred" = token ]; then
        tpc_record "$key" SKIP "stock XrdHttp ztn-over-http source not provisioned (GSI-only stock XrdHttp node)"; return
    fi
    if [ ! -f /usr/lib64/libXrdHttp-5.so ] && [ ! -f /usr/lib/libXrdHttp-5.so ]; then
        tpc_record "$key" SKIP "stock XrdHttp plugin (libXrdHttp) absent — no stock https source"; return
    fi
    # GSI: the brix dest pull leg now DOES present userA's delegated proxy (proven
    # by the bb gsi cell), but authenticating that forwarded DN against a STOCK
    # XrdHttp origin additionally needs that origin's http.gridmap to map userA's
    # proxy-leaf DN — a stock-provisioning step this harness does not stand up.  So
    # the endpoint stays a documented GAP; the brix-src→brix-dest gsi cell carries
    # the forwarding proof.
    tpc_record "$key" GAP \
        "brix puller forwards userA's delegated proxy (see the bb gsi cell), but a stock XrdHttp source would need http.gridmap provisioned for the forwarded proxy-leaf DN — not stood up in this harness"
}

# ---------------------------------------------------------------------------
# run_cell_bs <cred>  — brix WebDAV source → stock XrdHttp dest.
#   A stock XrdHttp destination is an XrdHttpTPC coordinator, not a brix puller;
#   the spec scopes this suite to the brix TPC puller, and stock XrdHttpTPC pull
#   credential forwarding is upstream behavior, not a brix proof.  SKIP with a
#   precise reason (the brix-dest cells above carry the brix forwarding proof).
# ---------------------------------------------------------------------------
run_cell_bs() {
    local cred="$1" key="webdav brix-src->stock-dest $cred"
    tpc_record "$key" SKIP "stock XrdHttp dest is an upstream TPC coordinator, not the brix puller under test (brix forwarding proven by the brix-dest cells)"
}

echo "== TPC credential forwarding — WebDAV/HTTP flavor (PULL) =="
for cred in token gsi; do
    fwd_cell_begin; run_cell_bb "$cred"; fwd_cell_end
    fwd_cell_begin; run_cell_sb "$cred"; fwd_cell_end
    fwd_cell_begin; run_cell_bs "$cred"; fwd_cell_end
done

tpc_summary "run_tpc_fwd_webdav"
exit "$TPC_ANY_FAIL"
