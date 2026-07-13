# Credential-Forwarding Matrix Test Suite — Design

**Date:** 2026-07-09
**Status:** design (approved in brainstorming; spec under review)
**Relates to:** Phase-70 full credential delegation (`docs/refactor/phase-70-full-credential-delegation.md`), per-user backend credentials phases 1–3 (`docs/10-reference/per-user-backend-credentials.md`).

## 1. Goal

Prove GSI **and** WLCG-token **forwarding** across a two-hop front→backend topology, for every combination of:

- **Pairing** (which software is front vs backend): **A** brix→xrootd · **B** xrootd→brix · **C** brix→brix
- **Protocol path** (hop-1 client→front, hop-2 front→backend), each hop `root://` or `https://`:
  root-all `(root,root)` · https-all `(https,https)` · mixed `(https,root)` **and** `(root,https)`
- **Credential**: GSI (x509 proxy) · WLCG token (JWT)

Nominal cross-product = 4 wire combos (RR, HH, HR, RH) × 2 creds × 3 pairings = **24 cells**. Pairing B's two https-backend-leg combos (HH, RH) are architecturally impossible for a stock-XRootD `pss` proxy (§5) → 4 cells are `SKIP`-by-design, leaving **20 runnable positive cells** (A=8, B=4, C=8), each with a matched negative control. Mixed's two orderings (RH, HR) are both run and both reported.

## 2. What a cell proves (proof standard)

**Positive** — userA performs a two-hop `PUT` then `GET`:
1. round-trip is **byte-exact**, AND
2. the **backend node** authenticated **userA's identity** — userA's DN (GSI) or token `sub` (token) — read from the backend's own log, NOT the front node's service identity.

**Negative control** — userB (no backend credential provisioned / wrong DN):
1. request is **denied on the backend leg** (`403` over https, `kXR_NotAuthorized` over root), AND
2. userB's bytes never appear on the backend store.

Both together prove real per-user enforcement, not plumbing that would pass equally with a static service credential.

## 3. Cell outcomes (five, honest reporting)

Every cell resolves to exactly one:

| Outcome | Meaning |
|---|---|
| `PASS` | positive + negative assertions both held |
| `FAIL` | an assertion that should hold did not — a real defect |
| `GAP` | pairing B only: stock XRootD proxy forwarded its **own service** identity, not userA. Asserted as a *proven* outcome (the svc DN is the one that reaches brix-back). Documents stock software's limitation. |
| `UNSUPPORTED` | the combo is **wire-feasible but our code does not yet implement it** (e.g. a GSI-forwarding backend leg our client can't drive). Surfaced as an **actionable code gap**, never a silent skip. |
| `SKIP` | only for architecturally-impossible cells or a missing `/usr/bin/xrootd`. Always carries a reason. |

The three driver scripts together render a 24-cell capability map. `UNSUPPORTED` and `GAP` are printed prominently so the matrix doubles as a to-do list for Phase-70 follow-up.

## 4. Backend-observed identity (the load-bearing helper)

`assert_backend_identity(backend_kind, log_path, expect_id)` normalizes two mechanisms:

- **brix backend** (pairings B, C): grep the brix `error_log` for `GSI auth OK dn="<DN>"` (GSI) or the token-subject auth line (token); cross-check the xfer-audit ledger `principal=` field is non-dash and matches. (Established mechanism — see `run_user_backend_cred_root.sh`, `run_user_backend_cred_p2.sh`.)
- **stock-xrootd backend** (pairing A): scrape stock XRootD's security-layer auth log entry (the `XrootdXeq`/`Authenticated` line carrying the client DN / token subject). New in this suite; isolated in the helper.

DN normalization mirrors the existing tests: spaces may appear as `\x20` (via `brix_sanitize_log_string`) — the matcher accepts both forms.

## 5. Pairing-specific handling

### Pairing A — brix-front → xrootd-back
- hop-1 served by brix (`brix_root` for root, webdav for https).
- hop-2: brix client → **stock xrootd** origin. `root://` via `sd_xroot` (established). `https://` via the brix HTTP backend client to an XrdHttp origin.
- Backend identity read from **stock xrootd's** log (§4).
- hop-2 GSI-forwarding over an https backend leg to stock XrdHttp: if the current backend client cannot present a per-user proxy over that leg, the cell is `UNSUPPORTED (code gap: <what's missing>)`, not skipped.

### Pairing B — xrootd-front → brix-back
- Front is **stock XRootD as a forwarding proxy** (`pss`). Stock proxy realistically forwards only over a `root://` hop-2, so **B is limited to hop2=root → wire ∈ {RR, HR}** (2 combos × 2 creds = 4 cells). hop2=https for B is `SKIP: stock xrootd proxy has no https backend leg` (architectural).
- Each B cell **attempts** stock-XRootD credential delegation/forwarding configuration. If userA's identity reaches brix-back → `PASS`. If stock forwards only its service identity → `GAP` (asserted: the svc DN, not userA, is what brix-back authenticated).
- Backend identity read from **brix** log (§4).

### Pairing C — brix-front → brix-back
- Both hops brix. Full 4 wire combos × 2 creds = 8 cells. The purest proof of Phase-70 forwarding (bearer passthrough, x509 full-proxy passthrough, cross-protocol carry on mixed paths).
- Backend identity read from **brix** log (§4).

## 6. Cross-protocol credential carry (mixed paths)

Mixed cells specifically exercise a credential crossing a protocol boundary:
- `(https, root)`: client sends `Authorization: Bearer <jwt>` / TLS proxy to brix-front over https; brix-front presents it to the backend over `root://` (token → ztn; proxy → GSI cert response). Proves the raw credential survives the protocol change.
- `(root, https)`: client authenticates root:// front; front presents the forwarded credential to an https backend (Bearer header / cert).

These are the cells most likely to surface `UNSUPPORTED` code gaps, which is precisely their value.

## 7. Harness structure

```
tests/lib/fwd_matrix.sh          # sourced helper library (no side effects on source)
    mint_pki                     # -> reuse pki_helpers.blitz_test_pki (CA, userA, userB, svc)
    mint_token <sub>             # -> utils/make_token.py
    spawn_brix_node   <role> <proto> <port> [backend-url] [cred-opts]
    spawn_xrootd_node <role> <proto> <port> [backend-url] [deleg-opts]
    backend_leg_config <pairing> <hop2-proto> <cred>   # emits the storage_backend/cred wiring
    assert_backend_identity <brix|stock> <logpath> <expect-id>
    assert_denied <proto> <http-code|kXR>              # negative-control checker
    run_cell <pairing> <hop1> <hop2> <cred>            # positive + negative; prints one outcome line
    feasibility_probe <pairing> <hop2> <cred>          # returns SUPPORTED|UNSUPPORTED:<why>|SKIP:<why>

tests/run_fwd_brix_xrootd.sh     # pairing A: for wire in RR HH HR RH; for cred in gsi token
tests/run_fwd_xrootd_brix.sh     # pairing B: for wire in RR HR;       for cred in gsi token  (+GAP path)
tests/run_fwd_brix_brix.sh       # pairing C: for wire in RR HH HR RH; for cred in gsi token
```

- Reuses the proven standalone-bash pattern: heredoc-generated `nginx.conf` per node, pidfile-based cleanup via `trap cleanup EXIT` (no broad `pkill`), `NGINX=${NGINX:-/tmp/nginx-1.28.3/objs/nginx}`.
- Stock-xrootd `xrootd.cf` generation (native server for pairing-A backend; `pss` forwarding proxy for pairing-B front) is **new**, fully contained in `fwd_matrix.sh`.
- Fixtures reused: `tests/pki_helpers.py::blitz_test_pki`, `utils/make_token.py`.
- **Ports:** a fresh reserved contiguous block (documented in `docs/10-reference/test-fleet-ports.md`), disjoint from existing suites.
- **Binary gate:** `/usr/bin/xrootd` (override `XROOTD_BIN`) is hard-required for pairings A & B; if absent both `SKIP` wholesale with reason, pairing C still runs.

## 8. Credential provisioning per cell

- **GSI:** userA/userB/svc proxies minted under a per-front `creds/` dir keyed by the Phase-1 `brix_sd_ucred_key` convention; front configured with `brix_storage_credential_dir` + `brix_storage_credential_fallback deny` (deny mode makes the negative control assert a real refusal). For pairing C the forwarding may instead be live **passthrough** (`brix_backend_delegation passthrough`) to exercise Phase-70 directly — both provisioning modes are covered where the pairing allows.
- **Token:** a local JWKS authority (`make_token.py init`) issues userA/userB JWTs with `storage.read`/`storage.modify` scopes; backend origin configured to trust that issuer.

## 9. Success criteria

1. All three scripts run to completion on a box with `/usr/bin/xrootd` present, emitting a full 24-cell outcome table (20 runnable + 4 B-https `SKIP`-by-design).
2. Every `PASS` cell demonstrably: (a) byte-exact round-trip, (b) backend log shows userA, (c) userB denied on the backend leg with no bytes written.
3. No cell silently skipped: every non-PASS carries `FAIL` / `GAP:<reason>` / `UNSUPPORTED:<code-gap>` / `SKIP:<reason>`.
4. Pairing C (pure brix) has **zero** `UNSUPPORTED` cells for combos Phase-70 claims to support — any that appear are real regressions to fix before merge.

## 10. Out of scope

- S3/SigV4 forwarding (STS) — separate spec; this suite is GSI + token only.
- SSS / krb5 forwarding cells.
- Performance/load; this is a correctness matrix.
- Committing to CI gate wiring — added after the suite is green and stable.

## 11. Open implementation risks (resolved during build, not by guessing)

- Exact stock-XRootD `pss` delegation directives that (if any) forward the end-user credential — determined empirically in pairing B; whichever way it lands is asserted (`PASS` or `GAP`).
- Stock-xrootd auth log line format for the identity scraper — pinned by inspecting a live stock-xrootd run during helper development.
- Whether the brix HTTP backend client can present a per-user GSI proxy on an https hop-2 to stock XrdHttp — determined by `feasibility_probe`; a negative answer is an `UNSUPPORTED` code-gap finding, which is a valid and useful result.
