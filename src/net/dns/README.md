# net/dns — runtime DNS (phase 116)

**WHAT.** Everything that turns a hostname in the configuration into an address
*after* the master has started: the `resolv.conf` reader, the resolver policy
directives, the asynchronous resolve driver and the per-worker target registry.

**WHY.** nginx OSS resolves every hostname in a directive once, with libc, while
parsing the configuration, and refuses to start when a name does not resolve.
nginx Plus re-resolves at runtime. BriX closes that gap: a dead
`brix_cms_manager`, `brix_upstream`, `brix_mirror_url`, `brix_http_handoff` or
`brix_transparent_proxy` name never blocks start-up; the name is registered here
and resolved (and re-resolved on TTL expiry) from the worker's event loop.

**HOW.**

| file | role |
|---|---|
| `resolv_conf.[ch]` | dependency-free `resolv.conf` parser (`nameserver`, `search`/`domain`, `options ndots/timeout/attempts/rotate`) with glibc clamps; unit test `resolv_conf_unittest.c` |
| `directive.c` | `brix_resolver`, `brix_dns_retry`, `brix_dns_cache_max`, `brix_dns_status_zone` — builds `brix_dns_policy_t` at parse time |
| `resolver_build.c` | turns the policy into the `ngx_resolver_t` seeded into the core `resolver` slot of the enclosing http location / stream server (only when the operator wrote no explicit `resolver`) |
| `resolve.c` + `resolve_thread.c` | `brix_dns_resolve()`: nginx-resolver path when a resolver is usable, otherwise `getaddrinfo` on the thread pool — never on the event loop |
| `cache.c` | bounded positive/negative forward cache keyed by `(name, af)` — addresses are stored port-less and the caller's port is stamped on read — honouring `min_ttl`/`max_ttl`/`negative_ttl` and the `brix_dns_cache_max` bound; also holds the in-flight marker that stops one fill per probe |
| `prefetch.c` | the never-blocking forward probe: `brix_dns_lookup_cached()` answers from the literal parser or the cache and otherwise starts one background fill (`brix_dns_prefetch()`), reporting `NGX_AGAIN` |
| `reverse.c` | the PTR driver — `brix_dns_reverse()` (async `ngx_resolve_addr`, else `getnameinfo` on the thread pool: the only such call in `src/`), the loop-side `brix_dns_reverse_cached()` probe, the accept/login `brix_dns_reverse_prefetch()` warm-up and the blocking `brix_dns_reverse_sync()` |
| `reverse_cache.c` | the PTR answer cache, keyed by the peer's raw address (port ignored), with negative and in-flight markers; bounded by the same `brix_dns_cache_max` because its key space is remote-controlled |
| `resolve_bridge.c` | thread-pool → event-loop bridge: a blocking caller resolves through the worker's own `ngx_resolver_t` and waits on a condition variable; returns `NGX_DECLINED` ("use libc") when the caller IS the event loop, when the bridge is unarmed, or when the policy has no usable resolver |
| `curl_pin.[ch]` | `CURLOPT_RESOLVE` pinning — libcurl never resolves for itself; every `CURLOPT_URL` site hands it addresses this module formatted (`CURLOPT_FOLLOWLOCATION` is banned for the same reason: a redirect would resolve behind our back) |
| `targets.c` | the target registry: `brix_dns_target_register()` at parse time, `brix_dns_targets_init_worker()` arms the per-worker timers, consumers read a registry-owned `ngx_addr_t` (`socklen == 0` = not yet resolved) |
| `metrics.c` | `brix_dns_targets{state}` gauge + resolution/failure counters (`/metrics`) |

The dashboard panel lives in `observability/dashboard/api_snapshot_dns.c`.

**Per-process statics.** The registry and cache are file-static, per-worker
tables (the same justification as `protocols/cvmfs/origin_probe.c` and
`protocols/webdav/proxy_pool.c`): addresses are process-local by nature — each
worker owns its own connections — and a shared-memory copy would only add a lock
on a hot connect path for no cross-worker benefit.

**Seam rule — one DNS path, no waivers.** There is exactly one forward
resolver call site (`resolve_thread.c`), one reverse one (`reverse.c`) and one
in the client (`client/lib/net/resolve.c`). Nothing else under `src/`,
`client/` or `shared/` may call `getaddrinfo`, `gethostbyname*`,
`gethostbyaddr*`, `res_*query`/`res_*search`, `getnameinfo` or
`ngx_inet_resolve_host`, or include `<netdb.h>`; libcurl callers must pin
(`CURLOPT_RESOLVE`) and `ngx_parse_url()` callers must set `no_resolve = 1`.
`tools/ci/check_dns_seam.py` enforces this (`--root <dir>` scans another tree,
which is how its own negative tests damage a `tmp_path` copy instead of the
real one). There is deliberately **no waiver marker and no backlog file**: a
new call site is a regression, not an entry to grandfather.

**Ordering caveat.** `brix_resolver auto` seeds the core `resolver` slot of the
block it appears in; an explicit `resolver` written *after* it in the same
block is reported by nginx as a duplicate. Write the explicit `resolver` first
(it then wins and `brix_resolver` leaves it alone) or drop one of the two.
