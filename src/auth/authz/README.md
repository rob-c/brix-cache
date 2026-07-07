# authz — path-level authorization: ACL rules, authdb, and the auth gate

## Overview

This directory decides *whether an authenticated identity may perform an
operation on a path*. Identity establishment (GSI, tokens, SSS, krb5, …)
lives in the sibling directories; everything here runs after identity is
known. It is security-load-bearing: the auth gate is the SOLE authorization
checkpoint on the cached-serve path (the 2026-07-06 cache-authz fix made
`root/read/open_cache.c` run the FULL gate — serve and fill helpers are
deliberately auth-free so this gate cannot be bypassed).

Two rule sources are compiled at postconfig: VO ACL rules (`acl.c`) and
authdb rules (`authdb.c`), both resolved against the export root so runtime
matching is pure string work. `brix_auth_gate()` (`auth_gate.c`) centralizes
the three-tier authdb → VO ACL → token-scope sequence that every namespace
handler needs; on the first failing tier it sends `kXR_NotAuthorized` and
returns `NGX_DONE`. Runtime rule lookup is longest-prefix (`find_rule.c`).

When the operator enables the `brix_auth_cache` SHM verdict cache
(`auth_cache.c`), a per-worker lockless direct-mapped L1 (`auth_gate_l1.c`)
sits in front of it, mapping the 32-byte SHA-256 gate key to its verdict
without taking the per-zone `ngx_shmtx` spinlock — the lock otherwise
serializes auth decisions across workers on the GSI hot path.

## Files

| File | Responsibility |
|---|---|
| `auth_gate.c` / `auth_gate.h` | the three-tier gate entry point (authdb → VO ACL → token scope) + L1 counters |
| `acl.c` | postconfig finalization of the VO-rule array (resolved against the export root) |
| `authdb.c` | postconfig finalization of the authdb rule array |
| `find_rule.c` | longest-prefix rule matching for path policies |
| `group_policy.c` | parent-directory group-policy inheritance for mkdir |
| `auth_gate_l1.c` / `auth_gate_l1.h` | per-worker lockless direct-mapped L1 over the SHM verdict cache |
| `auth_cache.c` / `auth_cache.h` | the optional cross-worker SHM verdict cache (`brix_auth_cache` directive) |

## Invariants, security & gotchas

1. The gate is the sole authorization checkpoint on the cached-read path.
   Never add a serve path that skips it.
2. `conf->allow_write` is checked globally before token scope
   (CLAUDE.md INVARIANT 3).
3. Longest-prefix semantics: the most specific rule wins; config ordering
   must not matter.
4. The L1 is an L1 *over* `brix_auth_cache`, not an independent cache —
   with auth caching disabled every request is re-evaluated, and the L1
   inherits the L2 TTL. It is per-conf, so auth_level/rules/identity are
   implicitly part of the cache identity.
5. Callers of `brix_auth_gate()` must return `ctx->write_rc` immediately on
   `NGX_DONE` — the wire error has already been sent.

## See also

- [../gsi/README.md](../gsi/README.md), [../token/README.md](../token/README.md) — identity establishment
- [../../protocols/root/read/](../../protocols/root/read/) — `open_cache.c`, the hot caller
- [../../../docs/09-developer-guide/cache-authz-best-practice.md](../../../docs/09-developer-guide/cache-authz-best-practice.md)
