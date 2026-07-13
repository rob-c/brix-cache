#!/usr/bin/env bash
# run_tpc_fwd_root.sh — native root:// third-party-copy credential forwarding.
#
# Flavor: native root:// TPC — `xrdcp --tpc delegate root://SRC//f root://DEST//f`,
# PULL (the destination pulls from the source). brix native TPC = SHM key
# registry + delegated-proxy / bearer outbound pull (src/tpc/*).
#
# Cells: cred {gsi-delegation, token}
#      × endpoints {brix-src→brix-dest, stock-xrootd-src→brix-dest,
#                   brix-src→stock-xrootd-dest}
#
# PROOF (spec §2): positive = byte-exact copy AND the SOURCE authenticated userA
# (source-log GSI DN / token sub); negative = userB (no delegated cred) → source
# denies + dest file absent.
#
# FORWARDING (phase-70): native root:// TPC now has verbatim inbound-bearer
# passthrough — with brix_tpc_outbound_passthrough on, the DEST forwards the
# CLIENT's own inbound bearer JWT (validated at the DEST) verbatim to the source,
# so the source authenticates the END USER (source logs sub="fwd-user-a").  The
# static brix_tpc_outbound_bearer_file and the OAuth2/OIDC exchange modes remain
# for non-client-driven setups.
#
# KNOWN LIMITATIONS asserted (not assumed):
#   * Stock xrootd delegates GSI only (docs/man/xrdcp.1) → stock+token cells GAP.
#
# Design: docs/superpowers/specs/2026-07-11-tpc-credential-forwarding-tests-design.md
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/lib/fwd_matrix.sh"
source "$HERE/lib/tpc_fwd.sh"

# Fresh reserved block 21900-21959 (native root flavor: 21930-21959).
FWD_PORT_BASE="${FWD_PORT_BASE:-21930}"; FWD_PORT_NEXT="$FWD_PORT_BASE"

fwd_setup tpc_root 0 || { echo "run_tpc_fwd_root: environment SKIP"; exit 0; }
trap fwd_cleanup EXIT
mint_pki || exit 0
mint_token || echo "  (token authority unavailable — token cells will SKIP)"

head -c 65536 /dev/urandom > "$FWD_PFX/tpcsrc.bin"

# ---------------------------------------------------------------------------
# run_cell_bb <cred>  — brix root:// source → brix root:// dest (core proof).
# ---------------------------------------------------------------------------
run_cell_bb() {
    local cred="$1" key="root bb $cred"
    if [ "$cred" = token ] && [ -z "$TOK_JWKS" ]; then
        tpc_record "$key" SKIP "token authority unavailable"; return
    fi
    local sport dport
    fwd_port sport; fwd_port dport

    # token dest: forward the CLIENT's own inbound bearer to the source via
    # brix_tpc_outbound_passthrough (phase-70).  The DEST validates the client's
    # inbound token (brix_auth token), captures it, and presents it verbatim on
    # the outbound ztn pull — so the source authenticates the END USER, not a
    # configured static file.
    local bearer_mode=""
    if [ "$cred" = token ]; then
        bearer_mode="passthrough"
    fi

    spawn_brix_source_root srcroot "$cred" "$sport" || {
        tpc_record "$key" FAIL "brix root source start failed"; return; }
    local slog="$FWD_LAST_LOG"
    cp "$FWD_PFX/tpcsrc.bin" "$FWD_PFX/srcroot/export/tpcsrc.bin"

    spawn_brix_dest_root dstroot "$cred" "$dport" "$bearer_mode" || {
        tpc_record "$key" FAIL "brix root dest start failed"; return; }
    local dlog="$FWD_LAST_LOG"

    if [ "$cred" = token ]; then
        # ---- inbound-bearer passthrough: the client drives the TPC authenticated
        #      with userA's own token; the DEST forwards it to the source. ----
        : > "$slog"
        drive_tpc_root token "$sport" "$dport" "posA.bin" A
        if [ "$TPC_COPY_OK" != 1 ]; then
            tpc_record "$key" FAIL "userA passthrough token pull did not complete ($TPC_DENY_OBS): $(grep -iE 'ztn|token|tls|3028|auth|passthrough' "$dlog" 2>/dev/null | tail -1)"
            return
        fi
        sleep 0.3
        if ! assert_source_identity brix token "$slog"; then
            tpc_record "$key" FAIL "source did not authenticate userA (sub=$A_SUB) on the forwarded pull leg — check $slog"
            return
        fi
        # ---- negative: userB presents a wrong-issuer token to the DEST; the
        #      DEST forwards it, and the source rejects the wrong issuer → denied.
        drive_tpc_root token "$sport" "$dport" "negB.bin" B
        if assert_tpc_denied root "$FWD_PFX/dstroot/export/negB.bin"; then
            tpc_record "$key" PASS "source authenticated userA (forwarded inbound bearer, passthrough); userB (wrong-issuer) denied, no bytes"
        else
            tpc_record "$key" FAIL "userB not denied ($TPC_DENY_OBS) or bytes leaked to dest"
        fi
        return
    fi

    # ---- GSI delegation: the real forwarding proof ----
    : > "$slog"
    drive_tpc_root gsi "$sport" "$dport" "posA.bin" A
    if [ "$TPC_COPY_OK" != 1 ]; then
        tpc_record "$key" FAIL "userA delegated GSI pull not byte-exact ($TPC_DENY_OBS): $(tail -1 "$FWD_PFX/tpc_A.err" 2>/dev/null)"
        return
    fi
    sleep 0.3
    if ! assert_source_identity brix gsi "$slog"; then
        tpc_record "$key" FAIL "source did not authenticate userA (DN=$A_CN) on the pull leg — check $slog"; return
    fi
    # ---- negative: userB does NOT delegate → dest can't capture a proxy →
    #      anonymous outbound pull → auth-required source denies, no bytes ----
    drive_tpc_root gsi "$sport" "$dport" "negB.bin" B
    if assert_tpc_denied root "$FWD_PFX/dstroot/export/negB.bin"; then
        tpc_record "$key" PASS "source authenticated userA (delegated proxy); userB (no delegation) denied, no bytes"
    else
        tpc_record "$key" FAIL "userB not denied ($TPC_DENY_OBS) or bytes leaked to dest"
    fi
}

# ---------------------------------------------------------------------------
# run_cell_sb <cred>  — stock xrootd source → brix root:// dest.
#   GSI: a stock xrootd GSI origin; the brix dest captures userA's delegated
#        proxy and pulls AS userA (the stock source logs `login as /…/CN=Fwd
#        User A`).  token: stock delegates GSI only → GAP.
# ---------------------------------------------------------------------------
run_cell_sb() {
    local cred="$1" key="root stock-src->brix-dest $cred"
    if [ ! -x "$XROOTD_BIN" ]; then
        tpc_record "$key" SKIP "stock xrootd absent"; return
    fi
    if [ "$cred" = token ]; then
        tpc_record "$key" GAP \
            "stock xrootd delegates GSI credentials only for TPC (docs/man/xrdcp.1) — token delegation to/from a stock peer is an upstream limitation"
        return
    fi
    local sport dport
    fwd_port sport; fwd_port dport

    # Stock GSI origin (reuses the pinned spawn_xrootd_node origin mode).
    spawn_xrootd_node stocksrc origin "$sport" "" gsi || {
        tpc_record "$key" SKIP "stock GSI origin did not come up"; return; }
    local slog="$FWD_LAST_LOG"
    # Seed the payload into the stock origin's data root (oss.localroot .../data).
    cp "$FWD_PFX/stocksrc/data" /dev/null 2>/dev/null || true
    mkdir -p "$FWD_PFX/stocksrc/data"
    cp "$FWD_PFX/tpcsrc.bin" "$FWD_PFX/stocksrc/data/tpcsrc.bin"

    spawn_brix_dest_root dstroot gsi "$dport" "" || {
        tpc_record "$key" FAIL "brix root dest start failed"; return; }

    : > "$slog"
    drive_tpc_root gsi "$sport" "$dport" "posA.bin" A
    if [ "$TPC_COPY_OK" != 1 ]; then
        tpc_record "$key" FAIL "userA delegated pull from stock source not byte-exact ($TPC_DENY_OBS): $(tail -1 "$FWD_PFX/tpc_A.err" 2>/dev/null)"
        return
    fi
    sleep 0.3
    if ! assert_source_identity stock gsi "$slog"; then
        tpc_record "$key" FAIL "stock source did not log userA (login as …CN=$A_CN) — check $slog"; return
    fi
    drive_tpc_root gsi "$sport" "$dport" "negB.bin" B
    if assert_tpc_denied root "$FWD_PFX/dstroot/export/negB.bin"; then
        tpc_record "$key" PASS "stock source authenticated userA (delegated proxy); userB denied, no bytes"
    else
        tpc_record "$key" FAIL "userB not denied ($TPC_DENY_OBS) or bytes leaked"
    fi
}

# ---------------------------------------------------------------------------
# run_cell_bs <cred>  — brix root:// source → stock xrootd dest.
#   The stock xrootd destination is the TPC coordinator; whether it forwards a
#   delegated proxy to a brix source is stock-client + stock-dest behavior, not
#   a brix-puller proof.  GSI is a supported stock feature but exercises stock
#   code, not brix; token is a stock GSI-only limitation.  Both SKIP/GAP with a
#   precise reason (the brix-dest cells carry the brix forwarding proof).
# ---------------------------------------------------------------------------
run_cell_bs() {
    local cred="$1" key="root brix-src->stock-dest $cred"
    if [ ! -x "$XROOTD_BIN" ]; then
        tpc_record "$key" SKIP "stock xrootd absent"; return
    fi
    if [ "$cred" = token ]; then
        tpc_record "$key" GAP \
            "stock xrootd delegates GSI only (docs/man/xrdcp.1) — a stock dest cannot forward a token to a brix source"
        return
    fi
    tpc_record "$key" SKIP \
        "stock xrootd dest is the TPC coordinator (upstream code); the brix puller under test is exercised by the stock-src->brix-dest and brix-src->brix-dest GSI cells"
}

echo "== TPC credential forwarding — native root:// flavor (PULL) =="
for cred in gsi token; do
    fwd_cell_begin; run_cell_bb "$cred"; fwd_cell_end
    fwd_cell_begin; run_cell_sb "$cred"; fwd_cell_end
    fwd_cell_begin; run_cell_bs "$cred"; fwd_cell_end
done

tpc_summary "run_tpc_fwd_root"
exit "$TPC_ANY_FAIL"
