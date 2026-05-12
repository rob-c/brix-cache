# manager — Cluster / Redirector Mode

This subsystem implements the server-side registry and redirect logic that allows
nginx-xrootd to act as an XRootD redirector or sub-manager in a multi-node
cluster, not just a leaf data server.

## Files

| File | Purpose |
|---|---|
| `registry.h` | Types (`xrootd_srv_entry_t`, `xrootd_srv_table_t`) and API declarations. |
| `registry.c` | 128-slot shared-memory server table (spinlock-protected). Implements `xrootd_srv_register`, `xrootd_srv_update_load`, `xrootd_srv_unregister`, and `xrootd_srv_select`. |

## How the registry is used

1. A CMS server handler (M2, not yet implemented) calls `xrootd_srv_register()`
   when a data server logs in via the CMS management protocol.
2. On each CMS heartbeat it calls `xrootd_srv_update_load()` to refresh free
   space and utilisation metrics.
3. On disconnect it calls `xrootd_srv_unregister()` to remove the entry.
4. `kXR_locate` and `kXR_open` call `xrootd_srv_select()` to find the best
   data server for a given path before falling back to the static `manager_map`.

## Selection policy

`xrootd_srv_select()` scans all occupied slots and applies longest-prefix
matching over each colon-delimited token in the entry's `paths` field.  Among
matching servers it picks:

- **Reads** (`for_write=0`): lowest `util_pct` (least loaded).
- **Writes** (`for_write=1`): highest `free_mb` (most free space).

## Thread safety

All mutations and reads are serialised by a single `ngx_shmtx_t` spinlock
embedded at the start of the shared region.  The lock is held only for the
duration of the linear scan — it is never held across I/O.

## See also

- `docs/cluster-mode.md` for the full architecture and implementation roadmap.
- `src/session/registry.c` for the session registry that uses the same pattern.
- `src/cms/` for the CMS client (existing) and future CMS server handler.
