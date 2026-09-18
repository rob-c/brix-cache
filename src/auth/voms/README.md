# voms — VO / FQAN extraction from verified X.509 proxies (native verifier)

## Overview

This subsystem turns the VOMS Attribute Certificates (ACs) embedded in an
X.509 grid proxy into the flat views the rest of the module authorizes on:
a single `primary_vo`, a comma-separated `vo_list`, and (2.0 F20) a
comma-separated `fqan_list`.  In HEP/grid deployments a user's proxy carries
VOMS extensions naming the virtual organisations the user belongs to (`cms`,
`atlas`, `lhcb`, …) and their Fully-Qualified Attribute Names
(`/cms/Production/Role=pilot`).  Those views drive `brix_require_vo`, the
authdb `v`/`l` selectors, the scvmfs `voms` authz mode and the VO-keyed
metrics.

After the GSI path has verified a proxy chain (`src/auth/gsi/auth.c` for
`root://`, `src/protocols/webdav/auth_cert.c` for `davs://`, the GridFTP and
cvmfs planes likewise) it calls `brix_extract_voms_fqans()` /
`brix_extract_voms_info()` here to populate the per-connection identity.

The verifier itself is **native and shared**: `shared/voms/` (plain C over
OpenSSL >= 3.0, no nginx types) decodes and verifies the ACs for the module
and for the native client alike.  No VOMS library is linked, `dlopen`ed or
required at runtime — `brix_voms_available()` is always 1 and there is no
"library missing" degradation path.  See
[`../../../shared/voms/README.md`](../../../shared/voms/README.md) for the
engine.

Extraction stays **fail-soft on the data path**: a proxy without a VOMS
extension (a plain grid proxy) yields `NGX_DECLINED`, which callers treat as
"no VOs".  An extension that is present but fails verification is logged at
WARN (one line per rejected AC — `VOMS attribute certificate for VO <vo>
rejected: <reason>`) and yields
`NGX_ERROR` with empty views — never a partial VO list.  Enforcement happens
downstream in the ACL layer, which denies VO-scoped paths to an identity
without the VO.

## Files

| File | Responsibility |
|------|----------------|
| `extract.c` | `brix_extract_voms_fqans()` (full form: VO views + FQAN view) and `brix_extract_voms_info()` (VO views only) — the public entry points, declared in `ngx_brix_module.h` and `voms_http.h`.  Pre-checks the inputs (`brix_voms_in_t`, non-empty `vomsdir` / `cert_dir`, paths `< PATH_MAX`), resets every output view, then calls `brix_voms_retrieve()` with the trust `{store, vomsdir, now = 0, skew 300 s}` — the store from `brix_voms_trust_store()` for `brix_voms_cert_dir`, the `vomsdir` the configured `brix_vomsdir`.  Only entries whose `verdict == BRIX_VOMS_OK` are handed to `collect.c`.  The trust store comes from `trust.c`. |
| `collect.c` | The CSV views.  `brix_collect_voms_vos()` walks every verified `brix_voms_entry_t`, taking the entry's `vo` and each VO derived from an FQAN (`brix_fqan_to_vo()`, the first path component), and appends into `vo_list` / `primary_vo` through `brix_append_vo_token()` (dedup, comma-join, `brix_vo_token_is_safe()` gate).  The FQAN view is appended raw and is never a log field or metric label (INVARIANT 8). |
| `trust.c` | `brix_voms_init(log)` (logs once that the native verifier is enabled), `brix_voms_available()` (constant 1 — the verifier is compiled in), `brix_voms_warm(log, cert_dir)` (builds the CA store for a `brix_voms_cert_dir` at configuration time through the module's CA-store cache, `auth/crypto/pki_build.c`, so workers inherit it) and `brix_voms_trust_store()` (the per-request lookup, returning an owned reference). One trust policy for every VOMS store: CRLs checked in "try" mode (where present), signing policy off — as libvoms behaved. |
| `voms_internal.h` | Private umbrella for the three `.c` files: pulls the stream module header, `shared/voms/voms_ac.h`, `voms_io.h` and declares `brix_voms_trust_store()` and the collector between `trust.c`, `extract.c` and `collect.c`. |
| `voms_io.h` | `brix_voms_in_t` (leaf + verified chain) and `brix_voms_out_t` (caller-owned `primary_vo` / `vo_list` / `fqan_list` buffers with sizes; any view may be NULL/0 = "not wanted").  ngx-free so both the stream and HTTP sides can include it. |
| `voms_http.h` | Thin re-declaration of the extraction entry points for **HTTP** handlers (`src/protocols/webdav/auth_cert.c`, cvmfs).  Uses only `<ngx_core.h>` + OpenSSL so HTTP code never includes `src/core/ngx_brix_module.h` (which drags in `ngx_stream.h`).  Never include both headers together. |
| `vo_token.h` | `brix_vo_token_is_safe()` — header-only, ngx-free predicate: 1 if a VO/FQAN token may enter the comma-separated VO list and later metric labels / access-log fields (rejects empty, control/space, non-ASCII, `,`, `/`, `\`). Shared with its unit test. |

The engine (compiled into the module through the repo-root `config` and into
the client through `client/Makefile`):

| File | Responsibility |
|------|----------------|
| `shared/voms/voms_ac.h` | Public API: `brix_voms_retrieve` / `brix_voms_find_extension` / `brix_voms_decode` / `brix_voms_verify` / `brix_voms_result_free` / `brix_voms_find_eec` / `brix_voms_strerror` / `brix_voms_dn_oneline`; `brix_voms_entry_t`, `brix_voms_result_t`, `brix_voms_trust_t`, `brix_voms_status_t`. |
| `shared/voms/voms_asn1.[ch]` | RFC 5755 / VOMS ASN.1 templates (strict DER decoder). Private. |
| `shared/voms/voms_decode.c` | AC_SEQ → entries (VO, URI, FQANs, generic attributes, validity, DNs). |
| `shared/voms/voms_verify.c` | The ordered verification (holder, validity, signer, algorithm, signature, issuer, targets, chain, vomsdir). |
| `shared/voms/voms_lsc.[ch]` | `vomsdir/<vo>/*.lsc` and legacy-certificate matching. |
| `shared/voms/voms_ac_fixture.h` | A genuine LHCb VOMS extension (DER) for the unit suite. |
| `shared/voms/voms_ac_unittest.c` | The C unit suite (`tests/test_voms_native_ac_unit.py` builds and runs it). |

## Key types & data structures

- **`brix_voms_in_t`** (`voms_io.h`) — `leaf` (the proxy leaf) and `chain`
  (the verified chain, leaf-first).  The engine searches the leaf and then
  every chain certificate for the VOMS extension and locates the end-entity
  certificate itself (`brix_voms_find_eec`), so callers pass the chain as
  OpenSSL handed it to them.
- **`brix_voms_out_t`** (`voms_io.h`) — the three caller-owned views with
  sizes.  They live in `brix_ctx_t` (`src/core/types/context.h`) for
  `root://` and in the request identity (`src/core/types/identity.c`) for
  HTTP.
- **`brix_voms_trust_t`** (`shared/voms/voms_ac.h`) — `store` (the cached
  `X509_STORE` for `brix_voms_cert_dir`, with the same CRL / signing-policy
  handling as the GSI identity chain), `vomsdir`, `now` (0 = wall clock) and
  `skew_seconds` (tolerance for a `notBefore` slightly in the future; never
  applied to `notAfter`).
- **`brix_voms_entry_t`** — one AC: `vo`, `uri`, `issuer_dn`,
  `issuer_ca_dn`, `holder_dn`, validity, `fqans[]`, `attrs[]` and the
  per-entry `verdict`.  `collect.c` reads `vo`, `fqans` and `verdict` only.

## Control & data flow

**Startup.** `src/core/config/postconfiguration.c` (and the WebDAV
postconfiguration when a location sets a vomsdir) calls `brix_voms_init()` and
`brix_voms_warm()` (`trust.c`), which builds the trust store for the
configured `brix_voms_cert_dir` once so workers inherit it.
The config gates (`src/core/config/policy.c`, the cvmfs and WebDAV merges)
still require `brix_vomsdir` and `brix_voms_cert_dir` whenever VO rules are
used, and now fail `nginx -t` when `brix_voms_cert_dir` cannot be loaded as
a CA store; there is no library-availability check and no mention of any
library.

**Per-connection.** Every caller runs *after* the proxy chain is
cryptographically verified and guards the call with non-empty `vomsdir` /
`voms_cert_dir`:

- `root://` stream — `src/auth/gsi/auth.c` fills `ctx->primary_vo` /
  `ctx->vo_list` / `ctx->fqan_list`.
- `davs://` HTTP — `src/protocols/webdav/auth_cert.c` (via `voms_http.h`)
  passes the peer chain from `SSL_get_peer_cert_chain()` and feeds the
  result into the request identity through `brix_identity_set_vos_csv()`;
  VOs are re-derived on both the TLS-cache hit and miss paths.
- cvmfs `brix_scvmfs_authz voms` — `src/protocols/cvmfs/secure_*.c` with
  `brix_scvmfs_vomsdir` / `brix_scvmfs_voms_cert_dir`.

**Internal flow.** `extract.c` → `brix_voms_retrieve(leaf, chain, &trust,
&res)` → for each entry with `verdict == BRIX_VOMS_OK`,
`collect.c::brix_collect_voms_vos()` builds the views → `extract.c` frees
the result (`brix_voms_result_free`).  A `BRIX_VOMS_ERR_NOEXT` return is
`NGX_DECLINED`; any other non-OK return logs each rejected entry's
`brix_voms_strerror(verdict)` at WARN and returns `NGX_ERROR` with empty
views.

**Downstream.** `src/auth/authz/acl.c` (`brix_vo_list_contains()`,
`brix_check_vo_acl()`), `src/auth/authz/auth_gate.c`, the authdb selectors
(`src/auth/authz/authdb.c`, which derives roles from `fqan_list`) and
`brix_track_vo_activity()` (VO-keyed, low-cardinality metrics).

## Invariants, security & gotchas

- **Every check libvoms made is made natively, in a fixed order** (see the
  shared README): an AC lifted from another user's proxy fails the holder
  binding, an expired AC is never tolerated, a tampered signature fails, an
  unknown signer fails the chain against `brix_voms_cert_dir`, and a signer
  not named in `vomsdir/<vo>/` fails the LSC match.  All-or-nothing per
  entry; a proxy carrying one good and one bad AC yields the good VO only.
- **Fail-soft on the data path, enforced by the ACL layer.**  No VOMS
  extension → `NGX_DECLINED` → "no VOs"; a failed extension → `NGX_ERROR` →
  empty views.  Either way `brix_require_vo` denies the VO-scoped paths.
- **VO-name injection hardening.**  Every VO token must pass
  `brix_vo_token_is_safe()`: no bytes `<= ' '`, none `>= 0x7f`, none of
  `, / \`.  Tokens failing the check are dropped, not errored.  `fqan_list`
  carries `/` and `=` by design and must never reach a log or label.
- **Comma-separated list semantics.**  `vo_list` uses `,` as the only
  delimiter; the first appended VO becomes `primary_vo`; duplicates are
  filtered; a full buffer returns 0 → `NGX_ERROR`; empty → `NGX_DECLINED`.
- **`ngx_str_t` → C-string bounds.**  `vomsdir`/`cert_dir` are
  length-checked against `PATH_MAX` before copy; oversized paths return
  `NGX_ERROR`, never truncate-and-use.
- **HTTP/stream header split.**  HTTP code includes `voms_http.h`, never
  `voms_internal.h` / `src/core/ngx_brix_module.h`.
- **Trust-store cache.**  Built once per `cert_dir` at configuration time
  (`brix_voms_warm()`, `trust.c`) and read-only afterward, so the per-request
  path needs no synchronization and no directory scan.
- **`vomsdir` lookup is path-confined.**  A VO name containing `/`, `\` or
  `..` never matches an LSC (`shared/voms/voms_lsc.c`), independently of
  the token gate above.

## Entry points / extending

- **Add a new VO-name source within an AC**: extend
  `brix_collect_voms_vos()` in `collect.c` and route the new string through
  `brix_append_vo_token()` so dedup, the comma-join and the safety gate apply
  uniformly.
- **Add a new caller of VOMS extraction**: call `brix_extract_voms_fqans()`
  (or `_info()`), guarded by non-empty `vomsdir` / `cert_dir`.  Stream code
  includes the prototype from `src/core/ngx_brix_module.h`; HTTP code
  includes `voms_http.h`.  Treat `NGX_DECLINED` and `NGX_ERROR` alike as
  "no VOs".
- **Change what is verified or how**: that is `shared/voms/` (engine),
  covered by `shared/voms/voms_ac_unittest.c`; keep this directory to
  nginx-facing glue.
- **Enforce a new VO policy directive**: `src/core/config/policy.c` and
  `src/auth/authz/acl.c`, not here — this subsystem only *produces* the
  views.

## See also

- [`../../../shared/voms/README.md`](../../../shared/voms/README.md) — the
  native verifier: files, verification order, unit suite, vomsdir semantics.
- [`../gsi/README.md`](../gsi/README.md) — X.509 proxy verification; primary
  stream caller.
- [`../../protocols/webdav/README.md`](../../protocols/webdav/README.md) —
  `auth_cert.c`, the HTTP caller (via `voms_http.h`).
- [`../../fs/path/README.md`](../../fs/path/README.md) — `acl.c` /
  `auth_gate.c` consume the VO views to enforce `brix_require_vo`.
- [`../../core/config/README.md`](../../core/config/README.md) —
  `postconfiguration.c` calls `brix_voms_init`; `policy.c` validates
  `brix_require_vo`, `brix_vomsdir`, `brix_voms_cert_dir`.
- [`../../core/types/README.md`](../../core/types/README.md) — `brix_ctx_t`
  and the request identity that store the views.
- [`../README.md`](../README.md) — master subsystem index.
