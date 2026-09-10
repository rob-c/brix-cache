# BriX-Cache Code-Level Security Audit — Round 4

**Scope:** Outbound GSI peer verification. The server acts as a GSI *client* on
three legs — cache-fill origin, TPC destination, transparent upstream — and each
agrees a shared session secret with the peer it dials. This round audits what
each leg does when its CA trust store is absent, and what it does with the peer
certificate when the store is present.

**Audit method:** Every caller of `brix_gsi_verify_peer_leaf()` was read against
that function's written contract in `src/auth/crypto/gsi_verify.h`, together with
the configuration path that populates each caller's `conf->gsi_store`. Trigger:
a phase-115 test (W2.4) that configured `brix_trusted_ca` and believed it had
armed outbound verification on the xroot cache→origin leg. It had not.

**Status:** OPEN — **undecided, not undiscovered.** Every behaviour below is
documented in the code that implements it, one of them explicitly as historical.
Tightening any of it changes which peers are refused in production, so it is an
owner's call and no code has been changed. Findings recorded 2026-09-07.

---

## Summary Table

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| [V-01](#v-01-tpc-destination-accepts-a-peer-that-presents-no-certificate) | **High** | TPC GSI | Destination presenting no `kXRS_x509` bucket is accepted against a configured store | ⏸ Undecided |
| [V-02](#v-02-tpc-destination-accepts-an-unparseable-leaf) | **Medium** | TPC GSI | Unparseable leaf (`-1`, "no verdict") falls through as success | ⏸ Undecided |
| [V-03](#v-03-two-of-three-opt-outs-are-silent) | **Medium** | All three legs | Two of three "no store, skipping verification" paths log nothing | ⏸ Undecided |
| [V-04](#v-04-the-xroot-origin-leg-never-consults-brix_trusted_ca) | **Medium** | Cache origin / config | Server-level `brix_trusted_ca` silently does not apply to this leg — no diagnostic, two surfaces left unarmed | ⏸ Undecided |

**Confirmed correct (no action needed):**

- `src/fs/cache/origin_auth_gsi.c:130-138` and `src/net/upstream/auth_gsi.c:76-84` both
  **refuse** a peer that omits its `kXRS_x509` bucket. ✅
- Both use `!= 1` against `brix_gsi_verify_peer_leaf()`, so "could not evaluate"
  (`-1`) fails closed, exactly as their comments state. ✅
- `src/net/upstream/auth_gsi.c:70-75` announces its opt-out at `NGX_LOG_WARN`. ✅
- `brix_trusted_ca` **is** honoured on the outbound legs that read it directly:
  `src/tpc/outbound/tls.c:56` (TLS CA dir, then `SSL_VERIFY_PEER`) and
  `src/fs/cache/origin/pelican_register.c:286` (`CURLOPT_CAPATH`). The original
  report framed the directive as inbound-only; that framing was wrong and V-04
  states the narrower, correct claim. ✅

---

## The contract being measured against

`src/auth/crypto/gsi_verify.h:87-90` states the requirement for all three callers:

> The server acts as a GSI client on three outbound paths (cache-fill origin,
> TPC destination, transparent upstream) and each must refuse to agree a
> session secret with an unverified peer.

and `:92-95` defines the tri-state every caller must interpret:

> Returns  1 when the PEM parses and X509_verify_cert accepts the chain,
>          0 when the certificate parsed but verification FAILED,
>         -1 when no verdict could be reached (unparseable PEM, or the store
>            context could not be created/initialised).

**One written contract, three implementations, four behaviours.** That is the
whole of this round:

| Leg | No store configured | Peer omits cert | Leaf unparseable (`-1`) | Leaf rejected (`0`) |
|---|---|---|---|---|
| `net/upstream/auth_gsi.c` | skip, **WARN** | refuse | refuse | refuse |
| `fs/cache/origin_auth_gsi.c` | skip, silent | refuse | refuse | refuse |
| `tpc/gsi/gsi_outbound_exchange.c` | skip, silent | **accept** | **accept** | refuse |
| `fs/backend/xroot/sd_xroot.c` | never attempted, never logged | — | — | — |

---

## V-01: TPC destination accepts a peer that presents no certificate

**Severity:** High
**File:** `src/tpc/gsi/gsi_outbound_exchange.c:92-96` — `tpc_gsi_verify_server_cert()`

### Vulnerability

With `conf->gsi_store` configured — that is, with the operator having provisioned
a CA anchor specifically to authenticate the peer — a destination that simply
omits its `kXRS_x509` bucket is accepted:

```c
/* src/tpc/gsi/gsi_outbound_exchange.c:92-96 */
if (gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                    &srv_pem, &srv_pem_len) != 0
    || srv_pem_len == 0)
{
    return 0;                       /* 0 == verification passed/skipped */
}
```

The two sibling legs refuse the identical input. `src/fs/cache/origin_auth_gsi.c:130-138`
answers `kXR_NotAuthorized` with *"cache origin gsi: server presented no
certificate to verify"*; `src/net/upstream/auth_gsi.c:76-84` logs the same
sentence and returns `NGX_ERROR`.

This is the sharper of the two TPC fall-throughs because it requires no malformed
input at all — only silence. An interposing peer does not need to produce a
certificate that fails to parse; it needs to produce nothing, and the exchange
proceeds to derive a session secret with it.

### Preconditions and limits

- Applies to the **TPC destination** leg only (the server pulling as a GSI client).
- Requires a peer able to answer the round-1 exchange — i.e. an active
  man-in-the-middle on the TPC leg, or a destination the operator did not intend.
- With **no** store configured this leg was never verifying anything, and the
  finding is V-03 instead. V-01 is specifically the case where the operator
  provisioned an anchor and believes the check is armed.

### Decision required

Making the missing bucket refuse would align this leg with the other two and with
`gsi_verify.h:87-90`. It is a behavioural change: any destination that currently
completes GSI *because* it presents no certificate would begin to be refused.
That population is unknown and is the reason this is an owner's call.

---

## V-02: TPC destination accepts an unparseable leaf

**Severity:** Medium
**File:** `src/tpc/gsi/gsi_outbound_exchange.c:97-106`

### Vulnerability

The caller refuses only on `== 0`, so `-1` — the helper's "no verdict could be
reached" — falls through as success. The code states the intent:

```c
/* -1 (unparseable leaf / no store ctx) keeps the historical fall-through;
 * only a parsed-and-rejected leaf (0) refuses the destination. */
if (brix_gsi_verify_peer_leaf(conf->gsi_store, srv_pem, srv_pem_len) == 0) {
```

Its docstring at `:70-73` says the same in prose ("is skipped (no store / no
bucket / unparseable leaf) … matching the original fall-through"). Both siblings
use `!= 1` and comment their choice as deliberate: *"Unparseable (-1) and failed
(0) both fail closed here: the cache origin is a credentialed peer, so 'could not
evaluate' is not 'verified'."*

Note that `-1` also covers the case where the store context could not be
created — a resource failure, not a peer property — so under memory pressure this
leg degrades to accepting whatever it is handed.

### Decision required

Same shape as V-01, smaller blast radius: changing `== 0` to `!= 1` is a two-token
edit whose risk is entirely in the peers it starts refusing.

---

## V-03: Two of three opt-outs are silent

**Severity:** Medium
**Files:** `src/fs/cache/origin_auth_gsi.c:127-129`, `src/tpc/gsi/gsi_outbound_exchange.c:89-91`

### Vulnerability

Running without a trust store is a supported, documented operator choice — every
one of the three legs describes it (`origin_auth_gsi.c:115`: *"No store =
operator opted out (unauthenticated origin)"*). The defect is not the opt-out; it
is that only one of the three **announces** it:

```c
/* src/net/upstream/auth_gsi.c:70-75 — the one that tells the operator */
if (conf->gsi_store == NULL) {
    ngx_log_error(NGX_LOG_WARN, up->conn->log, 0,
                  "brix: upstream gsi: no brix_trusted_ca configured; "
                  "upstream server certificate not verified");
    return NGX_OK;
}
```

The cache-origin and TPC legs take the same branch and return silently. From the
logs, an operator cannot distinguish a leg that verified its peer from one that
skipped the check. `src/fs/backend/xroot/sd_xroot.c:436-442` compounds this: it
logs when a store **build fails**, never when a build was never attempted, so the
most common misconfiguration is also the quietest.

### Decision required

This is the one candidate with no behavioural risk: a `NGX_LOG_WARN` at each of
the two silent skips, worded as the upstream leg words it, is log-only. It cannot
fail closed on anyone mid-transfer, and it makes the opt-out auditable. It is
recommended as the minimal shape regardless of what is decided for V-01/V-02.

---

## V-04: The xroot origin leg never consults `brix_trusted_ca`

**Severity:** Medium
**Files:** `src/fs/backend/xroot/sd_xroot.c:411-443`, `src/fs/vfs/vfs_backend_config.c:299-301`

### This is not a hole in the leg

Stated plainly, because the severity column invites the opposite reading: the
outbound origin leg does exactly what it was built to do. Credential-scoped trust
is deliberate isolation, and an absent store is a documented operator opt-out
(`src/fs/cache/origin_auth_gsi.c:127`). Nothing here is bypassable by a remote
party who has not already been named as the export's origin.

The defect is **silence plus confusability**: two spellings of "trust this CA"
that look interchangeable in a config file are not, and choosing the wrong one
produces no diagnostic at any log level. That is why V-04 sits beside V-01/V-02
in this round rather than in a configuration-reference note — and why its
recommended fix is a warning, not a behaviour change.

### Behaviour, and why it surprises

`brix_trusted_ca` is a stream-level directive (`src/core/config/stream_common.c:132`
→ `common.trusted_ca`). The xroot cache→origin leg does not run on the server's
`srv_conf`; it runs on a **synthetic** one, whose trust material is built solely
from the `ca_dir` inside the export's `brix_credential` block. That builder is a
no-op on an empty `ca_dir`:

```c
/* src/fs/backend/xroot/sd_xroot.c:420-422 */
if (ca_dir == NULL || ca_dir[0] == '\0') {
    return;
}
```

So an operator who writes `brix_trusted_ca` beside `brix_storage_credential`, and
omits `ca_dir`, gets a synthetic conf that inherits **neither** store — and no
diagnostic, because nothing failed; nothing was attempted.

The early return unarms **two** surfaces, not one. Lines 426-431 exist precisely
to make the origin CA double as the TLS anchor — *"Also expose the origin CA as
the generic trust anchor so the root:// TLS upgrade … verifies the origin's TLS
cert against THIS store … instead of falling back to the system CAs"* — and are
skipped by the same `return`. With no `ca_dir`, `synth->common.trusted_ca` stays
empty and the root:// TLS upgrade silently falls back to the system CA bundle.
One misconfiguration, two verification surfaces.

### Decision required

Three options, in ascending order of behavioural risk:

1. **Diagnostic only.** Warn at export setup when a credential names no `ca_dir`
   while the server has `brix_trusted_ca` configured — i.e. when the operator has
   most likely written the anchor in the wrong place. No runtime change.
2. **Inherit.** Fall back to the server-level `brix_trusted_ca` when the
   credential names no `ca_dir`. Makes the directive mean what operators appear to
   expect, but silently arms verification on deployments that currently run
   without it, which will refuse origins that work today.
3. **Leave as-is, document.** Treat credential-scoped trust as deliberate
   isolation and state it in the configuration reference.

Option 1 is the recommendation; 2 is a compatibility break wearing a bug fix's
clothes.

---

## Test coverage this round would need

None of the below exists yet; it is listed so that whatever is decided lands with
the three-tests-per-change rule satisfied (success + error + security-negative).

| Finding | Success | Error | Security negative |
|---|---|---|---|
| V-01 | destination presenting a valid leaf completes | destination presenting a rejected leaf is refused | destination presenting **no** bucket is refused (fails today) |
| V-02 | as above | store-ctx failure path refuses | unparseable PEM is refused (fails today) |
| V-03 | verified leg logs nothing new | — | each of the three legs emits its skip line when no store is configured |
| V-04 | ✅ landed | ✅ landed | ✅ landed |

**V-04 is already covered.** `tests/test_phase115_cache_origin_gsi.py` runs 5/5 on a
real fleet lane and pins today's behaviour as a positive assertion rather than an
absence:

- `test_brix_trusted_ca_does_not_anchor_the_outbound_origin_leg` (:266) — the rogue
  anchor written at server level as `brix_trusted_ca` is ignored on the xroot
  cache→origin leg: the fill succeeds and the origin logs a GSI login.
- `test_rogue_trust_anchor_refuses_the_origin_before_presenting_the_proxy` (:247) —
  the *identical* anchor written inside the credential's `ca_dir` produces the refusal.

Both caches (`lc-p115-co-rogue`, `lc-p115-co-outerca`) are built by one
`_rogue_fixture` factory from one shared rogue CA, so the only axis they differ on
is **where the anchor is written**; two separate CAs would have confounded it. That
suite previously read the two spellings as equivalent and was therefore running a
vacuous security-negative — which is how this round started.

Because the pin asserts today's behaviour, adopting option 2 below will turn it
red. That is intended: the decision is forced back through this document instead
of drifting.

---

## Provenance

Reported from the phase-115 W2.4 test defect, corrected and extended during the
phase-116 session. The V-01 missing-bucket accept and the four-behaviour tally
were found while verifying the original report; the original framing
("`brix_trusted_ca` is inbound-only") was withdrawn — see the "Confirmed correct"
note above. No source file has been modified for any finding in this round.
