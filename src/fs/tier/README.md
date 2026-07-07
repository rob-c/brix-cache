# tier — composable storage tiers (cache/stage decorators over backends)

## Overview

The tier layer composes the storage stack declaratively: an export's
effective storage is built from up to three tiers (e.g. a cache store
decorating an origin backend, or a staging store in front of nearline
storage), each an SD driver from the registry, wrapped as decorators.
This is what makes `brix_cache_store`, `brix_stage*`, and friends
protocol-independent: all three protocols (root://, WebDAV, S3) declare
tiers through the same unified directives
(`src/core/config/http_common.c` + the shared tier X-macro), and the
composition happens here, once.

`tier.h` holds the POD types describing the stack; `tier_config.c`
translates directives into a tier spec (including export-root
preparation); `tier_build.c` instantiates and composes the SD decorators
via the driver registry.

## Files

| File | Responsibility |
|---|---|
| `tier.h` | POD types describing the storage stack (up to three tiers) |
| `tier_config.c` | directives → tier spec; export-root preparation |
| `tier_build.c` | instantiate + compose SD decorators via the fs registry |

## Invariants, security & gotchas

1. Tier composition is config-time only — no runtime re-composition; a
   reload builds a fresh stack (standard nginx drain semantics).
2. Driver identity comes from the central registry rows
   (`src/core/types/fs_list.h`, append-only) — never instantiate a driver
   by name string outside the registry.
3. Each protocol inits/merges its `common.*` conf manually — a new tier
   directive must be added to the shared table, not per-protocol.

## See also

- [../backend/README.md](../backend/README.md) — the SD drivers being composed
- [../cache/](../cache/) — the cache tier implementation
- [../xfer/](../xfer/) — the stage engine
