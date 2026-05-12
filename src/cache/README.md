# Cache Sources

Read-through cache support is split by the job each file owns:

| File | Responsibility |
|---|---|
| `open_or_fill.c` | Public open-on-hit / schedule-fill entry point |
| `thread.c` | nginx thread-pool fill worker and completion callback |
| `fetch.c` | Whole-file origin fetch into `.part` and atomic rename; admission filter |
| `evict.c` | High-water cache eviction: large files first, then oldest-first |
| `origin_connection.c` | TCP/TLS connection setup and teardown |
| `origin_protocol.c` | XRootD handshake, login, open (with kXR_retstat), read, and close |
| `origin_response.c` | Server response parsing and origin error translation |
| `io.c` | Blocking socket/TLS send/receive and fd write loops |
| `lock.c` | Per-file fill lock acquisition and wait loop |
| `paths.c` | Cache path suffix, parent-directory, and ready-file checks |
| `errors.c` | Shared fill error formatting |

## Admission filter

Two directives control which files are admitted to the cache:

- **`xrootd_cache_max_file_size`** (bytes, with optional `k`/`m`/`g` suffix; `0` = no limit):
  Files whose size exceeds this limit are _not_ cached unless they also match the
  include regex.  The file size is obtained from the `kXR_retstat` flag appended to
  the `kXR_open` response, so no extra round-trip is needed.
- **`xrootd_cache_include_regex`** (POSIX ERE matched against the path basename):
  Any file whose basename matches this pattern is always admitted, regardless of size.

When a file is rejected by the admission filter the client receives a `kXR_redirect`
pointing at the configured `xrootd_cache_origin`, so the transfer proceeds directly
without returning an error.

## Eviction priority

When the filesystem occupancy exceeds `xrootd_cache_eviction_threshold` the eviction
pass runs in two stages, both sorted oldest-access-time first:

1. **Large files** (`size > xrootd_cache_max_file_size`): evicted first because they
   consume the most space and are not worth keeping in the cache long-term.
2. **Remaining files**: evicted if still over the threshold.

When `xrootd_cache_max_file_size` is `0` (no limit) the two-stage logic is bypassed
and all files are evicted in a single oldest-first pass (original behaviour).
