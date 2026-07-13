# TPC Credential-Forwarding Test Suite — Design

**Date:** 2026-07-11
**Status:** design (scope approved: both flavors, both endpoint sets, GSI+token)
**Relates to:** the normal-access forwarding matrix (`docs/superpowers/specs/2026-07-09-credential-forwarding-matrix-tests-design.md`), Phase-70 delegation, `src/tpc/*`, `src/protocols/webdav/tpc*`.

## 1. Goal

Prove that a user's credential (GSI x509 proxy **and** WLCG bearer token) is **delegated/forwarded** through a **third-party copy (TPC)** so the **source** server authenticates the transfer as the **end user** — matching the guarantee the normal-access matrix already proves for direct access. No existing test asserts source-side end-user identity on a TPC pull (`test_tpc_delegation.py` checks it but is XFAIL); this suite closes that.

## 2. Proof standard (same as normal-access matrix)

TPC PULL: client tells the **destination** to copy `file` from a **source** server; bytes flow source→dest directly.

- **Positive:** the copy completes byte-exact, AND the **source** server's log shows it authenticated **userA** (GSI DN / token `sub`) on the pull leg — the delegated user identity, not a service credential.
- **Negative control:** userB (no/expired/wrong delegated cred) → the source **denies** the pull (401/403 https, kXR_NotAuthorized root) and **no bytes** are copied to the destination.

Source-identity scrape (established): brix source = `GSI auth OK [source=x ]dn=` / `brix_token: valid token sub=`; stock source = `login as <id>` / `XrootdXeq … login as`.

## 3. Dimensions & cells

- **Flavor:** WebDAV/HTTP TPC (curl `COPY` + `Source:` header, PULL) · Native root:// TPC (`xrdcp --tpc delegate`, PULL).
- **Endpoints (source ↔ dest):** brix↔brix · brix↔stock-xrootd (both roles: stock-source→brix-dest AND brix-source→stock-dest where the flavor allows).
- **Cred:** GSI x509 proxy delegation · WLCG bearer token delegation.

Nominal cross-product per flavor = 2 cred × (brix→brix, xrootd→brix, brix→xrootd) with dest always the TPC coordinator that pulls. Pruned by feasibility (below).

## 4. Delegation mechanics per flavor (from code)

**WebDAV/HTTP TPC** (`src/protocols/webdav/tpc.c`, `tpc_cred.c`, `tpc_headers.c`):
- dest pulls via curl; the user cred rides as `Authorization: Bearer <token>` (from `TransferHeaderAuthorization`, or obtained via `Credential: oidc-agent|token-exchange`), or a delegated x509 proxy. `webdav_tpc_add_bearer_header`, `webdav_tpc_cred_obtain_token`, `webdav_tpc_collect_transfer_headers`.

**Native root:// TPC** (`src/tpc/engine/launch.c`, `src/tpc/outbound/*`, `src/tpc/gsi/*`):
- dest's outbound source session authenticates with the delegated proxy (`t->deleg_cred_pem`, `gsi_outbound_certreq.c`) or a delegated token (`tpc_token.c` oidc-agent / RFC 8693 → `tpc_outbound_ztn`). Identity logged via `brix_sess_auth_once` (`launch.c:94`).

## 5. Expected outcomes / known constraints (5-outcome model: PASS/FAIL/GAP/UNSUPPORTED/SKIP)

- **brix↔brix, both flavors, both creds:** expected **PASS** (brix implements delegation on both legs). This is the core proof; any non-PASS here is a real brix gap to fix (like the normal-access matrix drove fixes).
- **stock-xrootd as source/dest, GSI:** delegation is a supported stock feature (`xrdcp --tpc delegate`, gsi-only). Expected PASS where the client actually delegates; `test_tpc_delegation.py` F6 was XFAIL — re-verify, PASS or precise GAP.
- **stock-xrootd, TOKEN delegation:** the XRootD docs state **only gsi credentials can be delegated** for TPC (`docs/man/xrdcp.1`), so stock token-delegation cells are expected **GAP** (documented upstream limitation, same evidence style as pairing B) — asserted, not assumed.
- **SKIP:** missing `/usr/bin/xrootd`, or a flavor a role can't serve.

## 6. Harness (mirror the normal-access suite)

```
tests/lib/tpc_fwd.sh          # helpers, REUSING tests/lib/fwd_matrix.sh where possible:
    mint_pki / mint_token / OIDC server (reuse), spawn brix/stock nodes (reuse),
    spawn a 3rd node (source), drive_tpc_webdav (curl COPY), drive_tpc_root (xrdcp --tpc delegate),
    assert_source_identity (reuse assert_backend_identity), assert_tpc_denied, run_tpc_cell (pos+neg → one outcome line)
tests/run_tpc_fwd_webdav.sh   # WebDAV/HTTP TPC: cred × endpoints
tests/run_tpc_fwd_root.sh     # native root:// TPC: cred × endpoints
```
Reuses `pki_helpers.blitz_test_pki`, `utils/make_token.py`, the HTTPS-OIDC server, the pinned stock ztn/SciTokens + XrdHttp/GSI configs, pidfile cleanup, `NGINX_BIN`, a fresh reserved port block (documented in `docs/10-reference/test-fleet-ports.md`), `fuser -k` cleanup (never `pkill -f` self-match). Each script prints a per-cell PASS/FAIL/GAP/UNSUPPORTED/SKIP table; exit non-zero only on FAIL.

## 7. Success criteria

1. Both scripts run to completion, emit full outcome tables.
2. Every brix↔brix cell (both flavors, both creds) PASS — source authenticated userA, userB denied with no bytes copied. Any non-PASS = a real brix TPC-delegation gap, fixed before done (mirroring the normal-access effort).
3. Stock-xrootd cells resolved to PASS or an evidence-backed GAP/SKIP (no silent skips).
4. A `root://+gsi` standalone smoke test still passes (no regression) after any src fix.

## 8. Out of scope

- TPC performance; multi-hop (>2 server) chains; PUSH-only edge cases (PULL is the WLCG-standard path — PUSH added only if trivial).
