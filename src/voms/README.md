# voms — Optional VOMS virtual-organisation extraction from X.509 proxies

## Overview

This subsystem extracts **VO (Virtual Organisation) membership** from VOMS
Attribute Certificates (ACs) embedded inside an X.509 grid proxy. In HEP/grid
deployments, a user's proxy certificate carries VOMS extensions naming the
virtual organisations the user belongs to (e.g. `cms`, `atlas`, `alice`) and
their Fully-Qualified Attribute Names (FQANs, e.g. `/cms/Production/Role=pilot`).
This subsystem turns those ACs into two flat strings — a single `primary_vo`
and a comma-separated `vo_list` — that the rest of the module uses for VO-scoped
authorization (`xrootd_require_vo`).

It exists so that authorization can be driven by *VO membership* rather than
just the proxy's subject DN. After the GSI authentication path verifies a proxy
chain (`gsi/auth.c` for `root://`, `webdav/auth_cert.c` for `davs://`), it calls
`xrootd_extract_voms_info()` here to populate the per-connection identity. Those
VO strings then flow to the ACL layer (`../path/acl.c`, `../path/auth_gate.c`),
which enforces per-path `xrootd_require_vo` rules via `xrootd_vo_list_contains()`.

The defining design decision is **runtime, link-time-free dependency on
libvomsapi**. The module never links against `libvomsapi.so.1`; instead it
`dlopen`s it at nginx startup (`loader.c`). If the library is absent, the server
still starts — VOMS extraction is simply disabled and `xrootd_voms_available()`
returns false. This lets a single binary run on hosts with or without the grid
VOMS stack installed. (The three `.c` files are *always* compiled and linked;
they are registered unconditionally in the top-level `config` build script, lines
415-417. There is no `XROOTD_HAVE_VOMS` compile guard.)

VOMS extraction is **strictly optional and fail-soft on the data path**: a proxy
with no VOMS extensions (a plain grid proxy) yields `NGX_DECLINED`, which callers
treat as "no VOs" rather than an error. Hard enforcement happens elsewhere — at
config time, `xrootd_require_vo` is *rejected* if `libvomsapi` could not be loaded
(`../config/policy.c`), so an operator who asks for VO ACLs cannot silently get a
server that ignores them.

## Files

| File | Responsibility |
|------|----------------|
| `loader.c` | Runtime `dlopen("libvomsapi.so.1", RTLD_NOW \| RTLD_LOCAL)` at startup; resolves the four needed symbols (`VOMS_Init`/`VOMS_Retrieve`/`VOMS_Destroy`/`VOMS_ErrorMessage`) via a `LOAD_SYM` macro into the `xrootd_voms_api` table. Defines `xrootd_voms_init()` (returns `NGX_DECLINED` if lib absent — graceful degradation), `xrootd_voms_available()`, and the globals `xrootd_voms_api` / `xrootd_voms_loaded`. |
| `extract.c` | `xrootd_extract_voms_info()` — the public entry point. Four-phase pipeline: pre-checks (lib loaded? params present?) → copy `vomsdir`/`cert_dir` `ngx_str_t` to NUL-terminated `PATH_MAX` buffers → `init()` + duplicate the cert chain, strip the leaf, call `retrieve(..., VOMS_RECURSE_CHAIN, ...)` → delegate result harvesting to `xrootd_collect_voms_vos()`. Treats `VOMS_VERR_NOEXT`/`VOMS_VERR_NODATA` as benign; always cleans up the chain + `voms_data`. |
| `collect.c` | Converts the VOMS API result structs into the module's flat string format. `xrootd_collect_voms_vos()` walks every `voms_entry`, taking both the `voname` field and each VO derived from an FQAN. Helpers: `xrootd_fqan_to_vo()` (first path component of `/VO/Role=...`), `xrootd_append_vo_token()` (dedup + comma-join into `vo_list`, set `primary_vo` once), `xrootd_vo_token_safe()` (reject control chars, `,`, `/`, `\`, non-ASCII — injection hardening). |
| `voms_internal.h` | ABI-compatible struct layouts (`voms_data`, `voms_entry`, `voms_data_item`) matching the `voms-2.1.3`/EL9 library, the function-pointer typedefs + `xrootd_voms_api_t` table type, the VOMS error/flag constants, and `extern` globals. Field order is frozen — it is the `dlopen` ABI contract. Pulls the full stream umbrella header. |
| `voms_http.h` | Thin re-declaration of `xrootd_extract_voms_info()` for **HTTP** handlers (`webdav/auth_cert.c`). Uses only `<ngx_core.h>` + `<openssl/x509.h>` so HTTP code can call VOMS extraction *without* including `ngx_xrootd_module.h`, which drags in `ngx_stream.h` and conflicts with the HTTP layer. Never include both headers together. |

## Key types & data structures

- **`struct voms_data`** — top-level container returned by `VOMS_Init()` /
  populated by `VOMS_Retrieve()`. The field that matters is `data` — a
  NULL-terminated array of `voms_entry*`, one per VO AC found. `real` is opaque
  internal library state and must never be freed directly (only via `destroy()`).
- **`struct voms_entry`** — one VOMS Attribute Certificate. The subsystem reads
  only `voname` (the VO name, e.g. `cms`) and `fqan` (a NULL-terminated array of
  FQAN strings). All other fields (signatures, DNs, dates, raw AC pointers) are
  typed for byte-offset correctness but never dereferenced.
- **`struct voms_data_item`** — group/role/cap triple (the structured form of an
  FQAN). Present in the ABI but unused by this code; FQANs are parsed from the
  string `fqan[]` array instead.
- **`xrootd_voms_api_t`** — the dlopen handle plus four function pointers
  (`init`, `retrieve`, `destroy`, `error_message`). Written once during
  `xrootd_voms_init()` and read-only afterward, so it is lock-free.
- **Output strings (caller-owned, not a type here)** — `primary_vo` (single VO)
  and `vo_list` (comma-separated all VOs). They live in `xrootd_ctx_t`
  (`../types/context.h`) for `root://` and in the request `identity`
  (`../types/identity.c`) for HTTP, with caller-supplied buffer sizes
  (256 / 1024 bytes at the GSI and WebDAV call sites).

## Control & data flow

**Startup.** `../config/postconfiguration.c` calls `xrootd_voms_init(cf->log)`
once. It `dlopen`s the library and resolves symbols, or logs a notice and
declines. Later, `../config/policy.c` consults `xrootd_voms_available()` and the
configured `vomsdir`/`voms_cert_dir` to validate any `xrootd_require_vo` rules.

**Per-connection (entry into this subsystem).** Two callers, both *after* the
proxy chain is cryptographically verified:

- `root://` stream — `../gsi/auth.c` calls `xrootd_extract_voms_info()` and, on
  `NGX_OK`, fills `ctx->primary_vo` / `ctx->vo_list`.
- `davs://` HTTP — `../webdav/auth_cert.c` (via `voms_http.h`) calls it with the
  peer chain from `SSL_get_peer_cert_chain()` and feeds the result into the
  request identity through `xrootd_identity_set_vos_csv()`.

Both guard the call with `xrootd_voms_available() && vomsdir.len > 0 &&
voms_cert_dir.len > 0`, and both treat a non-`NGX_OK` result as "no VOs".

**Internal flow.** `extract.c` → `xrootd_voms_api.init/retrieve` → on success
`collect.c::xrootd_collect_voms_vos()` walks the entries and builds the strings →
`extract.c` frees the chain and calls `destroy()`.

**Downstream (calls out to).** The produced VO strings are consumed by
`../path/acl.c` (`xrootd_vo_list_contains()`, `xrootd_check_vo_acl()`) and
`../path/auth_gate.c` to enforce `xrootd_require_vo`, and by `../metrics`
indirectly via `xrootd_track_vo_activity()` (VO-keyed activity, low cardinality).

## Invariants, security & gotchas

- **No link-time VOMS dependency.** All VOMS access goes through the
  `xrootd_voms_api` function pointers; the symbols are resolved with `RTLD_NOW |
  RTLD_LOCAL` (`loader.c:39`) — `RTLD_LOCAL` prevents symbol pollution between
  nginx modules, `RTLD_NOW` forces eager resolution so a partial library fails
  fast. On any `dlsym` miss the handle is `dlclose`d and the table zeroed.
- **Fail-soft on the data path, fail-closed at config.** Missing VOMS extensions
  (`VOMS_VERR_NOEXT` / `VOMS_VERR_NODATA`, `voms_internal.h:89-90`) are silently
  skipped (`extract.c:94`). But an operator who configures `xrootd_require_vo`
  *without* a loadable `libvomsapi` is rejected at startup in `../config/policy.c`
  — you can't accidentally run with VO ACLs that never fire.
- **Leaf is stripped before `retrieve()`** (`extract.c:84-88`). VOMS needs the
  *parent* certificates in the chain to validate AC signatures, so the leaf is
  removed from the duplicated stack via `X509_cmp` + `sk_X509_delete`. The
  duplicate (`sk_X509_dup`) is freed with `sk_X509_free` (shallow — it does not
  free the underlying certs, which the caller owns).
- **VO-name injection hardening.** Every VO token must pass
  `xrootd_vo_token_safe()` (`collect.c:21`): no chars `<= ' '`, none `>= 0x7f`,
  and none of `, / \`. This blocks comma-injection into the `vo_list` (which is
  comma-delimited and later split by `xrootd_vo_list_contains()`) and stops path
  separators leaking into VO names. Tokens failing the check are dropped, not
  errored.
- **Comma-separated list semantics matter.** `vo_list` uses `,` as the only
  delimiter; the first appended VO also becomes `primary_vo`. Duplicates are
  filtered with `xrootd_vo_list_contains()` before append, and a full buffer
  returns 0 → `xrootd_collect_voms_vos()` reports `NGX_ERROR`. Empty result →
  `NGX_DECLINED`.
- **ABI layout is frozen** (`voms_internal.h`). Do not reorder or add/remove
  fields in `voms_data` / `voms_entry` / `voms_data_item` — byte offsets must
  match the real `libvomsapi` or `retrieve()` writes through bad pointers.
- **`ngx_str_t` → C-string bounds.** `vomsdir`/`cert_dir` are length-checked
  against `PATH_MAX` before `ngx_memcpy` + manual NUL (`extract.c:54-63`);
  oversized paths return `NGX_ERROR`, never truncate-and-use.
- **HTTP/stream header split.** HTTP code must include `voms_http.h`, never
  `voms_internal.h`/`ngx_xrootd_module.h` — the stream umbrella header redefines
  types that clash with nginx's HTTP layer.
- **Lock-free after startup.** `xrootd_voms_api` and `xrootd_voms_loaded` are set
  once during single-threaded postconfiguration and only read thereafter, so the
  per-request path needs no synchronization.

## Entry points / extending

- **Add a new VO-name source within an AC** (e.g. derive VOs from a different
  field): extend `xrootd_collect_voms_vos()` in `collect.c` and route the new
  string through `xrootd_append_vo_token()` so dedup, the comma-join, and
  `xrootd_vo_token_safe()` validation are applied uniformly. Do not hand-build
  the list.
- **Add a new caller of VOMS extraction**: call `xrootd_extract_voms_info()`,
  guarded by `xrootd_voms_available()` and non-empty `vomsdir`/`cert_dir`. Stream
  code includes the prototype from `ngx_xrootd_module.h`; HTTP code includes
  `voms_http.h`. Treat any non-`NGX_OK` return as "no VOs".
- **Bind to a different VOMS library symbol**: add a function-pointer typedef +
  field in `xrootd_voms_api_t` (`voms_internal.h`) and a matching `LOAD_SYM(...)`
  line in `xrootd_voms_init()` (`loader.c`). A new symbol that fails to resolve
  must abort the whole load (the macro already does this).
- **Enforce a new VO policy directive**: that work lives in `../config/policy.c`
  and `../path/acl.c`, not here — this subsystem only *produces* the VO strings.

## See also

- [`../gsi/README.md`](../gsi/README.md) — X.509 proxy verification; primary
  stream caller of `xrootd_extract_voms_info`.
- [`../webdav/README.md`](../webdav/README.md) — `auth_cert.c`, the HTTP caller
  (via `voms_http.h`).
- [`../path/README.md`](../path/README.md) — `acl.c` / `auth_gate.c` consume the
  VO strings to enforce `xrootd_require_vo`.
- [`../config/README.md`](../config/README.md) — `postconfiguration.c` calls
  `xrootd_voms_init`; `policy.c` validates `xrootd_require_vo`, `xrootd_vomsdir`,
  `xrootd_voms_cert_dir`.
- [`../types/README.md`](../types/README.md) — `xrootd_ctx_t` and the request
  identity that store `primary_vo` / `vo_list`.
- [`../README.md`](../README.md) — master subsystem index.
