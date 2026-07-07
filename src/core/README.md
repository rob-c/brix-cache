# core — platform primitives shared by every plane

The foundation layer: nothing here speaks a wire protocol or touches
storage policy. It provides the compat/utility surface (safe sizes,
checksums, sanitized logging), the type universe (`brix_ctx_t`, conf
structs, the append-only proto/fs registries), configuration machinery,
shared-memory tables with safe mutexes, async I/O, and the shared HTTP
semantics engine used by every HTTP-facing protocol.

| Dir / file | What |
|---|---|
| [compat/](compat/) | ngx-free utilities: CRC32c/CRC64, safe_size, staged files, sanitized log strings, SHM slot tables |
| [types/](types/) | `brix_ctx_t` + sub-structs, conf structs, `proto_list.h` / `fs_list.h` central registries (append-only) |
| [config/](config/) | directive machinery, conf create/merge, unified storage directives (`http_common.c`), runtime server setup |
| [http/](http/) | shared HTTP semantics: header lookup, conditionals/ETag, query, XML, file responses — security-load-bearing, one engine for webdav/s3/cvmfs |
| [shm/](shm/) | shared-memory KV + table primitives |
| [aio/](aio/) | thread-pool async I/O (+ optional io_uring backend) |
| `ngx_brix_module.h` | the module's central include |
| `feature_flags.h`, `ident.h` | build-time feature gates, identity constants |

**Invariants:** SHM mutexes are spin+yield via `brix_shm_table_alloc()` —
never POSIX-semaphore mode (INVARIANT 10). Protocols must consume the
[http/](http/) helpers instead of regrowing private copies — enforced by
`tools/ci/check_http_helper_reimpl.sh`.
