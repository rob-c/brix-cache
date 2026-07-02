# Phase 5: Config Merge Consolidation

**Projected ΔLoC:** −300  
**Risk:** Low  
**Depends on:** Phase 1 (alloc macros)  
**Blocks:** nothing  
**Parallel-safe with:** Phases 2, 3, 4, 6 (touches only config/ subdirectory)

---

## ✅ Status: Implemented (Option A) — 2026-06-12

Phase 5 is complete. It was implemented via **Option A** (see "Existing nginx
Macros vs New Macros" below): merge functions standardise on nginx's built-in
`ngx_conf_merge_*` family, and a deliberately small header supplies the three
patterns nginx does **not** cover.

- **Implemented header:** `src/core/config/merge_macros.h` (~40 LoC), providing only
  `XROOTD_MERGE_PTR` (NULL-sentinel pointer inherit), `XROOTD_MERGE_HOSTPORT`
  (paired host+port inherit), and `XROOTD_MERGE_ENUM` (custom-enum sentinel).
  All three are in active use (`src/core/config/server_conf.c`, `src/webdav/config.c`).
- **Not implemented:** the six-macro sketch below (`XROOTD_MERGE_FLAG/SIZE/MSEC/
  UINT/STR/ARRAY_PTR`) was intentionally dropped — those cases are handled by
  nginx's own `ngx_conf_merge_value/size_value/msec_value/uint_value/
  str_value/off_value`, which Option A prefers.
- **Merge functions consolidated:** `ngx_stream_xrootd_merge_srv_conf`
  (`server_conf.c`), `webdav` (`config.c`), `s3` (`module.c`), `dashboard`
  (`module.c`), `cms` server (`server_module.c`), `metrics` (`module.c`),
  `webdav/tpc_config.c`. No hand-rolled `== NGX_CONF_UNSET` merge blocks remain
  (the lone occurrence in `src/fs/cache/directives.c` is a scheme-default inside a
  *directive parser*, not a merge function). Genuinely custom inherits —
  struct-copy caches keyed on a `.kv` sentinel, the three-field `upstream_*`
  block, char-array `proxy_login_user_name`, and the `wt_origin →
  cache_origin` fallback — are correctly left inline, as Option A intends.

### Obsolete component removed

An earlier, superseded attempt at this same goal (the root-level "Phase 2 /
Code Consolidation" reports dated 2026-06-05) added `src/core/config/conf_helpers.h`
— a competing set of `MERGE_VALUE` / `MERGE_*_VALUE` wrapper macros — and wired
`#include "conf_helpers.h"` into six modules. Adopting Option A removed every one
of those includes and macro usages, leaving `conf_helpers.h` orphaned (no
include, no usage, absent from the build and from `src/core/config/README.md`).

`src/core/config/conf_helpers.h` has been **deleted**. Verified: zero code
references before removal, and an incremental `make` relinks cleanly afterward
(no `./configure` needed — header-only deletion of an unreferenced file).

> Note: the former root-level `PHASE_2_SUMMARY.md`, `PHASE_2_COMPLETE.md`,
> `PHASE_2_FINAL_REPORT.md`, and `CODE_CONSOLIDATION_IMPLEMENTATION.md` described
> `conf_helpers.h` (and the already-deleted `src/core/compat/alloc_helpers.h`) as
> current infrastructure. As stale reports of the superseded approach they have
> been moved to [`docs/_archive/`](../_archive/).

---

## Goal

Condense the ~14 config merge functions scattered across the codebase.  Every `merge_srv_conf` or `merge_loc_conf` function is structurally identical: for each field, check `NGX_CONF_UNSET*`, then copy from parent or apply default.  After Phase 5, a small set of macros reduces this to one line per field.

---

## The Repeated Merge Pattern

Every config merge function contains blocks like this:

```c
/* String field */
if (conf->root.len == 0) {
    conf->root = (prev->root.len > 0) ? prev->root : default_root;
}

/* Flag field */
if (conf->allow_write == NGX_CONF_UNSET) {
    conf->allow_write = (prev->allow_write != NGX_CONF_UNSET)
                        ? prev->allow_write : 0;
}

/* Numeric (msec) field */
if (conf->idle_timeout == NGX_CONF_UNSET_MSEC) {
    conf->idle_timeout = (prev->idle_timeout != NGX_CONF_UNSET_MSEC)
                         ? prev->idle_timeout : 30000;
}

/* Size field */
if (conf->max_body_size == NGX_CONF_UNSET_SIZE) {
    conf->max_body_size = (prev->max_body_size != NGX_CONF_UNSET_SIZE)
                          ? prev->max_body_size : (size_t) 1024 * 1024;
}
```

Each block is 3–4 lines.  A merge function with 20 fields is 60–80 lines of near-mechanical pattern.

---

## New Macros: `src/core/config/merge_macros.h` (new, ~60 LoC)

```c
/*
 * merge_macros.h — config merge helpers.
 *
 * Each macro merges one field: if the child is unset, use parent value;
 * if parent is also unset, use the provided default.
 *
 * Naming convention mirrors nginx's own ngx_conf_merge_* pattern.
 */
#pragma once
#include <ngx_core.h>

/* Flag: NGX_CONF_UNSET (-1) */
#define XROOTD_MERGE_FLAG(conf, prev, field, def)                       \
    if ((conf)->field == NGX_CONF_UNSET) {                              \
        (conf)->field = ((prev)->field != NGX_CONF_UNSET)               \
                        ? (prev)->field : (def);                        \
    }

/* Size_t: NGX_CONF_UNSET_SIZE */
#define XROOTD_MERGE_SIZE(conf, prev, field, def)                       \
    if ((conf)->field == NGX_CONF_UNSET_SIZE) {                         \
        (conf)->field = ((prev)->field != NGX_CONF_UNSET_SIZE)          \
                        ? (prev)->field : (size_t)(def);                \
    }

/* Msec: NGX_CONF_UNSET_MSEC */
#define XROOTD_MERGE_MSEC(conf, prev, field, def)                       \
    if ((conf)->field == NGX_CONF_UNSET_MSEC) {                         \
        (conf)->field = ((prev)->field != NGX_CONF_UNSET_MSEC)          \
                        ? (prev)->field : (ngx_msec_t)(def);            \
    }

/* Uint: NGX_CONF_UNSET_UINT */
#define XROOTD_MERGE_UINT(conf, prev, field, def)                       \
    if ((conf)->field == NGX_CONF_UNSET_UINT) {                         \
        (conf)->field = ((prev)->field != NGX_CONF_UNSET_UINT)          \
                        ? (prev)->field : (ngx_uint_t)(def);            \
    }

/* ngx_str_t: empty string (len == 0) as sentinel */
#define XROOTD_MERGE_STR(conf, prev, field, def_data, def_len)          \
    if ((conf)->field.len == 0) {                                       \
        if ((prev)->field.len > 0) {                                    \
            (conf)->field = (prev)->field;                              \
        } else {                                                        \
            (conf)->field.data = (u_char *)(def_data);                  \
            (conf)->field.len  = (def_len);                             \
        }                                                               \
    }

/* ngx_array_t pointer: NULL as sentinel — only copy ref, no deep clone */
#define XROOTD_MERGE_ARRAY_PTR(conf, prev, field)                       \
    if ((conf)->field == NULL) {                                        \
        (conf)->field = (prev)->field;                                  \
    }
```

---

## Inventory of Merge Functions to Simplify

| File | Current merge LoC | Projected after | ΔLoC |
|---|---|---|---|
| `src/core/config/merge_stream.c` | ~120 | 60 | −60 |
| `src/core/config/merge_http.c` | ~90 | 45 | −45 |
| `src/webdav/postconfig.c` (merge section) | ~70 | 35 | −35 |
| `src/s3/config.c` (merge section) | ~60 | 30 | −30 |
| `src/fs/cache/config.c` (merge section) | ~50 | 25 | −25 |
| `src/net/proxy/config.c` (merge section) | ~45 | 22 | −23 |
| `src/metrics/config.c` (merge section) | ~30 | 15 | −15 |
| `src/net/upstream/config.c` (merge section) | ~35 | 17 | −18 |
| `src/core/config/merge_macros.h` (new) | 0 | +60 | +60 |
| **Net** | | | **−191** |

Estimated −191 to −250 LoC depending on actual merge function sizes (files need to be read precisely before each conversion).

---

## Concrete Before/After

**Before** (typical block in `merge_stream.c`):

```c
if (conf->idle_timeout == NGX_CONF_UNSET_MSEC) {
    conf->idle_timeout = (prev->idle_timeout != NGX_CONF_UNSET_MSEC)
                         ? prev->idle_timeout : (ngx_msec_t) 30000;
}
if (conf->allow_write == NGX_CONF_UNSET) {
    conf->allow_write = (prev->allow_write != NGX_CONF_UNSET)
                        ? prev->allow_write : 0;
}
if (conf->max_read_size == NGX_CONF_UNSET_SIZE) {
    conf->max_read_size = (prev->max_read_size != NGX_CONF_UNSET_SIZE)
                          ? prev->max_read_size : (size_t)(256 * 1024 * 1024);
}
if (conf->root.len == 0) {
    conf->root = (prev->root.len > 0) ? prev->root : ngx_null_string;
}
```

**After** (4 lines → 4 lines, but far more scannable):

```c
XROOTD_MERGE_MSEC(conf, prev, idle_timeout,   30000);
XROOTD_MERGE_FLAG(conf, prev, allow_write,    0);
XROOTD_MERGE_SIZE(conf, prev, max_read_size,  256 * 1024 * 1024);
XROOTD_MERGE_STR (conf, prev, root,           NULL, 0);
```

The reduction is not in line count per field (3-line block → 1 macro line = −2 per field) but in cognitive load: the 20-field merge function becomes immediately auditable — any field that deviates from the standard pattern is immediately visible.

For a 20-field merge function: 60 lines → 20 lines = −40 lines.  Multiply by ~8 merge functions = −320 lines.  Subtract the new macro header (+60) = **net −260 LoC**.

---

## Existing nginx Macros vs New Macros

nginx already provides `ngx_conf_merge_str_value`, `ngx_conf_merge_msec_value`, etc. in `ngx_conf_file.h`.  These are usable and many merge functions already use them for some fields but not others (inconsistency).

Phase 5 has two options:

**Option A (preferred):** Standardise on nginx's built-in macros where they apply; write `XROOTD_MERGE_*` only for fields that are xrootd-specific (e.g., pointer arrays, ngx_str_t with specific defaults).

**Option B:** Write all `XROOTD_MERGE_*` from scratch for consistency.

Option A is preferred because it reduces the Phase 1 surface area and leverages nginx's own tested macros.  The existing config files should be audited for which fields can be migrated to nginx macros and which need custom xrootd ones.

---

## Verification

```bash
# No configure needed (header-only changes)
make -j$(nproc) 2>&1 | grep "^error:" | wc -l
# Expected: 0

# Config loading under all test nginx instances
tests/manage_test_servers.sh restart
sleep 2
PYTHONPATH=tests pytest tests/conftest.py -v  # server startup as fixture

# Config directive tests
PYTHONPATH=tests pytest tests/ -k "config" -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Low.**  Config merge functions are called only at nginx startup (`ngx_conf_t` phase), not in the hot path.  A bug in merge produces a misconfigured server that fails at startup (visible in error.log) rather than a silent runtime regression.

The main risk is silently changing a default value.  For each field converted, verify the default in the macro call matches the original default in the inline code.  A mismatch produces the same behaviour as before — just a wrong default that may have been wrong all along.

## Rollback

```bash
git revert <phase-5-commit>
make -j$(nproc)
```

No `./configure` needed since no new `.c` files are added.
