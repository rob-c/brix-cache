# cvmfs:// — the CVMFS site-cache protocol plane (phase-68)

`cvmfs://` is a dedicated protocol in this module's sense of the word — the
same sense in which S3 is one: HTTP on the wire, but with its own directory
(`src/protocols/cvmfs/`), its own nginx HTTP module and content handler
(`ngx_http_xrootd_cvmfs_module`), its own directive family, and its own
test suites. A `cvmfs://` location is NOT a WebDAV location: `xrootd_cvmfs
on` alone activates it, and none of WebDAV's methods, auth modes, or
dispatch exist on it. What IS shared sits below the protocol seam: the
VFS/tier storage plane (`src/fs/`), the `sd_http` origin driver, and the
`src/core/http/` shared HTTP semantics.

Deployment runbook (sizing, topology, client config, pilot procedure):
[deploy/cvmfs/README.md](../../deploy/cvmfs/README.md). Implementation
plan: [docs/refactor/phase-68-cvmfs-site-cache.md](../refactor/phase-68-cvmfs-site-cache.md).

## Traffic classes

Every request is classified by the pure-C classifier
(`src/protocols/cvmfs/classify.c`) and policed by the gate; anything that
is not a CVMFS traffic shape is rejected with 403 and one stable
`cvmfs-reject:` WARN line.

| Class | Shape | Policy |
|---|---|---|
| CAS | `/cvmfs/<repo>/data/<2hex>/<hex38+>[C\|H\|X\|M\|L\|P]` | cached ~forever (content-addressed, self-verifying with `xrootd_cache_verify cvmfs-cas`) |
| MANIFEST | `.cvmfspublished` / `.cvmfswhitelist` / `.cvmfsreflog` | cached with `xrootd_cvmfs_manifest_ttl`; expired entries revalidate; failed revalidation serves stale inside a 10×TTL bound |
| GEO | `/cvmfs/<repo>/api/v1.0/geo/…` | never cached — relayed to the origin (the answer depends on the caller) |
| REJECT | everything else | 403 + guard signal + fail2ban-parsable log line |

Methods: GET and HEAD only; anything else is 405.

## Directive reference

| Directive | Default | Meaning |
|---|---|---|
| `xrootd_cvmfs on\|off` | off | makes the location a dedicated CVMFS endpoint |
| `xrootd_cvmfs_storage_backend "http://s1a[\|http://s1b…]"` | — | ordered Stratum-1 origin set (pipe = `CVMFS_SERVER_URL` syntax); first is the write side, reads fail over by health |
| `xrootd_cvmfs_cache_store posix:<dir>` | — | the cache tier's physical store |
| `xrootd_cache_verify off\|cvmfs-cas` | off | CAS verify-on-fill: the object NAME is its sha1 (raw served bytes); a mismatch is quarantined and never admitted |
| `xrootd_cvmfs_quarantine_dir <dir>` | "" (unlink) | where verify-mismatch parts land (operator evidence) |
| `xrootd_cvmfs_manifest_ttl <sec>` | 61 | MANIFEST-class cache TTL |
| `xrootd_cvmfs_negative_ttl <sec>` | 10 | per-worker 404 memo TTL |
| `xrootd_cvmfs_upstream_allow <host>…` | unset | proxy-mode authority allowlist (unset = proxy mode off) |
| `xrootd_cvmfs_upstream_max <n>` | 8 | max distinct proxy-mode upstreams per worker |
| `xrootd_cvmfs_origin_select static\|geo\|rtt` | static | origin selection policy |
| `xrootd_cvmfs_origin_coords <host[:port]> <lat>:<lon>` | — | one origin's coordinates (geo mode; one per origin, `nginx -t` enforced) |
| `xrootd_cvmfs_here <lat>:<lon>` | — | this cache's coordinates (geo mode) |
| `xrootd_cvmfs_rtt_interval <sec>` | 60 | RTT probe period (first probe < 500 ms after worker start) |
| `xrootd_cvmfs_client_hold <sec>` | 25 | never-drop hold: keep retrying the origins this long while a client waits, then 504+Retry-After on a kept-alive connection. MUST stay below the WN's `CVMFS_TIMEOUT` |
| `xrootd_cvmfs_fill_max_life <sec>` | 300 | detached-fill retry budget after every client has gone |
| `xrootd_cvmfs_thread_pool <name>` | default | async fill/relay pool |

## Deployment modes

**Reverse mode** (`CVMFS_SERVER_URL=http://cache:PORT/cvmfs/@fqrn@`,
`CVMFS_HTTP_PROXY=DIRECT`): the location carries
`xrootd_cvmfs_storage_backend` and requests are origin-form.

**Proxy mode** (`CVMFS_HTTP_PROXY=http://cache:3128`): clients send
absolute-form request lines; the authority is checked against
`xrootd_cvmfs_upstream_allow` and served against a per-upstream cache
subtree (`<host>_<port>/` — upstreams can never alias). https authorities
are refused on `cvmfs://` (WLCG proxy traffic is plain HTTP).

## Connection durability

The CVMFS client (libcurl under the hood) reuses pooled connections to its
proxy and tracks per-proxy failures. Every avoidable close forces a
reconnect (SYN through a possibly-lossy site network); every *unclean*
close risks being counted against the proxy's health and triggering group
failover or DIRECT — after which every worker node hammers the WAN
individually. Kernel keepalive makes the *cache* the side that detects
dead peers, while middleboxes see steady probes and keep NAT/conntrack
state alive.

The canonical listener block (proven on the wire by
`tests/run_cvmfs_keepalive.sh`):

```nginx
    # so_keepalive=idle:intvl:cnt → SO_KEEPALIVE + TCP_KEEPIDLE/KEEPINTVL/KEEPCNT
    # 60s idle probe start beats typical stateful-firewall idle drops (300s+)
    # and keeps NAT/conntrack entries warm on the WN side.
    listen 3128 so_keepalive=60s:10s:6 backlog=2048;

    keepalive_timeout  3600s;      # hold WN connections for an hour idle
    keepalive_requests 1000000;    # never recycle a healthy connection early
    send_timeout          300s;    # slow WN ≠ dead WN
    client_header_timeout 300s;
    reset_timedout_connection off; # a FIN, never an RST, if we must close
```

Never-drop semantics complete the contract: origin trouble while a client
waits is absorbed by hold+retry (`xrootd_cvmfs_client_hold`), surfacing as
**504 + Retry-After on the kept-alive connection** — never a broken socket,
never a fast 5xx storm. **502** is reserved for definitive origin badness
(a CAS mismatch after the retry budget); **404** is the origin's answer and
is never retried. A client abort never cancels a fill: the fill completes
detached (`xrootd_cvmfs_fill_max_life`) so the retry is a hit.

## Test suites

`tests/run_cvmfs_{classify,reverse,verify,failover,manifest,proxy,select,holdopen,keepalive}.sh`
— each self-contained against the mock Stratum-1
(`tests/cvmfs/mock_stratum1.py`). Comparison matrix:
`tests/cvmfs/run_matrix.sh` (root; tc-netem lab).

## scvmfs:// (EXPERIMENTAL)

A secure variant layered ON `cvmfs://` (T22): the same handler core behind
a TLS listener with an optional client-authz gate. Structurally severable —
its own directives (`xrootd_scvmfs*`), its own suite (`tests/run_scvmfs.sh`),
excluded from the acceptance gate and the pilot. See the runbook appendix.
