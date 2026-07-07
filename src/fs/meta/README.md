# meta — unified per-file metadata sidecar (xmeta)

## Overview

One record per stored file carries the cache/transfer state that must
survive restarts: the present-bitmap (which byte ranges of a partially
filled cache object are valid), file-level dirty state, flush generation,
and dirty-since timestamps. `xmeta.c` encodes/decodes the record —
byte-identical successor to the legacy `.cinfo`/`XCI1`/`.xrdt` formats,
with a v2-compat reader so existing caches survive upgrades without a
cold start.

Two carriers persist the record: `xmeta_path.c` loads/saves/removes it for
local files by absolute path, and `xmeta_carrier.c` composes the sidecar
object key (`<key>.cinfo`) for store objects, so object backends carry the
same metadata without a local filesystem. `xmeta_unittest.c` covers
encode/decode round-trips.

## Files

| File | Responsibility |
|---|---|
| `xmeta.c` / `xmeta.h` | record encode/decode; the on-disk format contract |
| `xmeta_path.c` / `xmeta_path.h` | load/save/remove by absolute local path |
| `xmeta_carrier.c` / `xmeta_carrier.h` | sidecar key composition + persist/load for store objects |
| `xmeta_unittest.c` | encode/decode round-trip unit tests |

## Invariants, security & gotchas

1. The encoding is an on-disk compatibility contract — never change the
   layout without a versioned reader (v2-compat exists precisely so
   upgrades don't cold-start caches).
2. Dirty/clean transitions are centralized in the write-through flush
   engine — handlers must not flip dirty bits directly.
3. The eviction guard skips dirty entries; a stale-dirty reaper removes
   records older than `brix_cache_dirty_max_age` — metadata correctness
   here directly gates data-loss safety.

## See also

- [../cache/](../cache/) — the cache engine that reads/writes these records
- `xrdcinfo` (client tooling) — dumps the present-bitmap as JSON for debugging
