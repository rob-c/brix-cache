# Next steps: contributor experience and code structure

The XRootD data-server opcode set is implemented and the module is functionally complete for WLCG-style POSIX data-server deployments. This page maps the next wave of work: making the codebase easier for contributors to read, navigate, extend, and debug.

Items are ordered by risk and payoff. **Start with Phase 1 — documentation
changes have zero build risk and give the highest value per hour.**

Each item is self-contained: a contributor can pick up any single checkbox,
make the change, confirm the build still passes (`make -j$(nproc)` in the nginx
source tree), run the test suite (`pytest tests/`), and open a PR.

---

## Phase 1 — Documentation ✓ DONE

All documentation phases are complete. The following items were implemented
as part of the current documentation expansion effort:

- [x] **`docs/architecture.md`** — End-to-end request lifecycle: native XRootD
  state machine, WebDAV dispatch path, S3 routing path, AIO detour, auth flow,
  backpressure model. Includes ASCII-art state diagram and file handle lifecycle.

- [x] **`docs/contributing.md`** — Step-by-step guides: adding a native opcode
  (7 steps with worked example for `kXR_ping`), adding a directive (4 steps),
  code style, test requirements, dispatch routing table, adding a WebDAV method,
  adding an S3 endpoint.

- [x] **`docs/reference/types.md`** — Core type reference: `xrootd_ctx_t` field groups,
  `xrootd_file_t` fd/path/ckp_path ownership, `ngx_stream_xrootd_srv_conf_t`
  read-only vs mutable fields, nginx pool allocation patterns.

- [x] **`docs/getting-started.md`** — Expanded with WebDAV quickstart (step 7),
  S3 quickstart (step 8), Prometheus metrics setup (step 9), expanded
  troubleshooting for all three protocol families.

- [x] **`docs/reference/handler-reference.md`** — Added WebDAV handler building blocks
  (path resolution, lock enforcement, auth checks, header helpers, metrics
  wrapper, I/O engine, fd cache) and S3 handler building blocks (SigV4 auth,
  XML response helpers, path construction helpers).

- [x] **`docs/comparison-with-xrootd.md`** — Added "Developer investment —
  estimated hours" section covering per-subsystem hour estimates for
  nginx-xrootd (~4,500–6,250 hours, $680K–$1.56M replacement cost),
  official XRootD cumulative investment (~141K–256K hours, $14M–$46M), and a
  contributor comparison table. Fixed stale production replacement checklist:
  kXR_bind, Macaroon tokens, LOCK/UNLOCK, server-side COPY all now marked as
  implemented.

- [x] **`docs/reference/quirks.md`** — Added WebDAV COPY routing disambiguation (§15),
  LOCK token mechanics (§16), fd cache TLS scoping (§17), S3 multipart upload ID
  uniqueness (§18), S3 ListObjectsV2 gaps (§19), TPC credential delegation
  subprocess design (§20).

- [x] **`AGENTS.md`** — Rewritten from 485 to 914 lines with: three mandatory
  pre-task questions, build recipe with configure-vs-make table, full test
  runbook, operation-to-file index for all three protocol families, test-to-
  feature map for all 57 test files, five implementation recipes, key API quick
  reference with C signatures, disambiguation patterns, and per-pitfall list.

- [x] **Per-subsystem READMEs** — Data flow sections added to `handshake/`,
  `connection/`, `read/`, `write/`, `aio/`.

---

## Phase 2 — Config directory cleanup ✓ DONE

`config/` has 15 files. Eight of them are subsystem-specific directive parsers
that live away from the subsystem code they configure. A contributor looking at
`gsi/` for everything GSI-related will not find the directive declarations —
they are in `config/gsi.c`. This split is the single biggest navigability
problem in the codebase.

**Rule of thumb:** A config file belongs in the same directory as the code it
configures. Cross-cutting concerns (config struct allocation, merge, post-config
hooks, process init) stay in `config/`.

Move the following files. Each move requires:
1. `git mv src/config/X.c src/Y/config.c`
2. Update the `config` build file: change the source path in `ngx_module_srcs`
3. Verify the file's `#include` path for `config.h` is still correct
   (`../config/config.h` becomes `config/config.h` in the new location)
4. `make -j$(nproc)` must produce zero errors

| Move from | Move to | Why |
|---|---|---|
| `config/gsi.c` | `gsi/config.c` | GSI directive parsing belongs with GSI auth code |
| `config/token.c` | `token/config.c` | JWT directive parsing belongs with token validation |
| `config/sss.c` | `sss/config.c` | SSS keytab parsing belongs with SSS auth |
| `config/cms.c` | `cms/config.c` | CMS manager directives belong with CMS heartbeat |
| `config/metrics.c` | `metrics/config.c` | Metrics zone directive belongs with metrics code |
| `config/threads.c` | `aio/config.c` | Thread-pool directive belongs with AIO code |
| `config/tls.c` | `session/tls_config.c` | TLS cert/key directives are session-layer concerns |

**`config/backend_directives.c` (449 lines) — split by directive group:**
This one file contains three unrelated directive groups: manager-map, upstream
redirector, and cache. Split into:

| New file | Directives it contains |
|---|---|
| `config/manager_map.c` | `xrootd_manager_map` and related directives |
| `upstream/directives.c` | `xrootd_upstream_*` directives |
| `cache/directives.c` | `xrootd_cache_*` directives |

After the moves, `config/` should contain only:
`config.h`, `helpers.c`, `server_conf.c`, `policy.c`, `postconfiguration.c`,
`process.c`, `runtime_server.c`, `manager_map.c`

Update the per-subsystem READMEs for `gsi/`, `token/`, `sss/`, `cms/`,
`metrics/`, and `aio/` to add the new config file to their file tables.

---

## Phase 3 — File splitting ✓ DONE

Each file listed here contains two or more clearly separable concepts. The goal
is: a contributor can open a file and immediately understand its single
responsibility from its name and the first function signature.

**Target: no file longer than ~300 lines** (except `ngx_xrootd_module.h` and
the wire-format headers, which are reference material).

### `read/open.c` (587 lines) → split into two files

`read/open.c` handles the main `kXR_open` request — mode/flag parsing, path
resolution, ACL checks, retstat building — and also contains the cache
integration path (checking the cache, falling back to origin fill). The cache
path is long enough to stand alone.

- `read/open.c` — kXR_open handler: mode parsing, path resolution, ACL, open(2),
  retstat body assembly. No cache logic.
- `read/open_cache.c` — cache-aware open path: cache hit check, cache-miss fill
  trigger, cache_fd setup, kXR_cachersp flag. Include as a static helper called
  from `open.c`.

Add `open_cache.c` to `config` build file; update `read/README.md` file table.

### `dirlist/dirlist.c` (484 lines) → split into three files

The handler reads the directory (one concept), formats dStat stat lines
(second concept), and formats dcksm per-entry checksums (third concept).

- `dirlist/handler.c` — `xrootd_handle_dirlist`: open dir, iterate, dispatch to
  formatters, send chunked kXR_oksofar / kXR_ok responses.
- `dirlist/dstat.c` — `xrootd_dirlist_format_dstat`: build the
  `"id size flags mtime"` stat string for a single entry.
- `dirlist/dcksm.c` — `xrootd_dirlist_format_dcksm`: build the extended stat
  string with checksum token for a single entry.

Rename `dirlist/dirlist.c` → `dirlist/handler.c` with `git mv`.
Add new files to `config` build file; update `dirlist/README.md`.

### `write/chkpoint.c` (588 lines) → split into two files

The file has a clean internal boundary: `ckp_begin`, `ckp_commit`,
`ckp_rollback`, `ckp_query` are straightforward state operations on the
checkpoint file, while `ckp_xeq` is a mini-dispatcher that re-executes write
sub-operations (write, pgwrite, truncate, writev) under checkpoint protection —
a significantly more complex piece of logic.

- `write/chkpoint.c` — `ckp_copy_range`, `ckp_clear_path`, `ckp_begin`,
  `ckp_commit`, `ckp_rollback`, `ckp_query`, and the top-level
  `xrootd_handle_chkpoint` dispatcher.
- `write/chkpoint_xeq.c` — `ckp_xeq` and all `ckp_xeq_*` sub-functions
  (ckp_xeq_write, ckp_xeq_pgwrite, ckp_xeq_truncate, ckp_xeq_writev).
  Declare the `ckp_xeq` prototype in a small static header or as a forward
  declaration in `chkpoint.c`.

Add `chkpoint_xeq.c` to `config` build file; update `write/README.md`.

### `metrics/export.c` (547 lines) → split into two files

The stream-protocol counters (XRootD ops, connections, bytes) and the WebDAV
HTTP counters (method, status, TPC, CORS, PROPFIND) have no interdependency.
Splitting them makes each file entirely self-contained.

- `metrics/stream.c` — Prometheus export for stream-protocol counters
  (`op_ok`, `op_err`, `connections_*`, `bytes_*`, cache eviction).
- `metrics/webdav.c` — Prometheus export for WebDAV counters
  (`webdav_requests_total`, `webdav_responses_total`, TPC events, CORS, etc.).

Both are called from the same HTTP handler endpoint; that routing function stays
in whichever file is larger after the split, or in a new small `metrics/handler.c`.
Add files to `config` build file; update `metrics/README.md`.

---

## Phase 4 — `pki/` consolidation ✓ DONE

`src/pki/` has exactly two files totalling ~44 lines:
- `pki/stream.c` — loads PKI certs/CRL for the stream (XRootD) listener
- `pki/webdav.c` — loads PKI certs/CRL for the WebDAV HTTP listener

Both are thin adapters that call `crypto/pki_load.c` and `crypto/pki_check.c`.
The `pki/` directory exists only as a naming layer between module-specific config
and the generic crypto helpers. Eliminating it removes one unnecessary indirection.

- `git mv src/pki/stream.c src/gsi/pki.c` — stream PKI loading belongs with GSI auth
- `git mv src/pki/webdav.c src/webdav/pki.c` — WebDAV PKI loading belongs with WebDAV
- Delete `src/pki/` directory
- Update `config` build file: remove old paths, add new paths
- Update `config` deps list: remove `pki/` header references (there are none; `pki/`
  has no header of its own)
- Update `gsi/README.md` and `webdav/README.md` file tables

---

## Phase 5 — Repeated-pattern extraction ✓ DONE

Nearly every handler ends with the same three-line sequence:

```c
xrootd_log_access(ctx, c, "VERB", path, detail, 1, kXR_ok, NULL, bytes);
XROOTD_OP_OK(ctx, XROOTD_OP_FOO);
return xrootd_send_ok(ctx, c, NULL, 0);
```

And errors follow:

```c
xrootd_log_access(ctx, c, "VERB", path, detail, 0, errcode, msg, 0);
XROOTD_OP_ERR(ctx, XROOTD_OP_FOO);
return xrootd_send_error(ctx, c, errcode, msg);
```

This appears in ~30 handler callsites. A macro pair can collapse each to one
line while keeping the same observable behaviour:

```c
#define XROOTD_RETURN_OK(ctx, c, op, verb, path, detail, bytes)          \
    do {                                                                   \
        xrootd_log_access(ctx, c, verb, path, detail, 1, kXR_ok, NULL,   \
                          bytes);                                          \
        XROOTD_OP_OK(ctx, op);                                            \
        return xrootd_send_ok(ctx, c, NULL, 0);                           \
    } while (0)

#define XROOTD_RETURN_ERR(ctx, c, op, verb, path, detail, code, msg)     \
    do {                                                                   \
        xrootd_log_access(ctx, c, verb, path, detail, 0, code, msg, 0);  \
        XROOTD_OP_ERR(ctx, op);                                           \
        return xrootd_send_error(ctx, c, code, msg);                      \
    } while (0)
```

Add these to `ngx_xrootd_module.h` alongside `XROOTD_OP_OK`/`XROOTD_OP_ERR`.
Apply consistently across `write/`, `read/`, and `query/` — handlers that
return a body other than `kXR_ok` (e.g., pgwrite status, read data) should not
use these macros.

**Risk note:** This is a non-trivial search-and-replace across ~30 callsites.
Do it subsystem-by-subsystem and verify the build and access-log output after
each subsystem. Do not mix other changes in the same commit.

---

## Phase 6 — Master header decomposition ✓ DONE

`src/ngx_xrootd_module.h` (719 lines) is included by every `.c` file. Any edit
to it triggers a full rebuild. Long-term, split it into focused sub-headers:

| New file | Contents |
|---|---|
| `src/types/tunables.h` | `XROOTD_*` size limits, `XROOTD_OP_OK/ERR` macros |
| `src/types/state.h` | `xrootd_state_t` enum, forward declarations |
| `src/types/file.h` | `xrootd_file_t` struct |
| `src/types/context.h` | `xrootd_ctx_t` struct (includes the above) |
| `src/types/config.h` | `ngx_stream_xrootd_srv_conf_t` struct |

Keep `src/ngx_xrootd_module.h` as the umbrella include (include all of the
above plus subsystem public headers). Files that only need `xrootd_file_t` can
include `types/file.h` directly for faster incremental builds.

**Defer this until Phases 1–4 are complete.** It touches every `.c` file and
the only payoff is incremental build speed (not readability). The documentation
and file-split work above has higher human value at lower mechanical risk.

---

## Verification checklist (for any phase)

Before opening a PR for any item above:

```bash
# Build must be clean
cd /tmp/nginx-1.28.3
make -j$(nproc) 2>&1 | grep -E "error:|warning:"

# Full test suite must be green
cd /path/to/nginx-xrootd
pytest tests/ -x -q

# xrdcp round-trip smoke test
xrdcp /etc/hostname root://localhost:1094//tmp/test-smoke.txt
xrdcp root://localhost:1094//tmp/test-smoke.txt /tmp/out.txt
diff /etc/hostname /tmp/out.txt
```

For documentation-only changes (Phase 1), only the build check is required.
For source moves (Phases 2–4), all three checks are required.
