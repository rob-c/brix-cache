# Config Sources

These files cover nginx directive parsing, merged server config, and startup
validation for the native XRootD stream module:

- `server_conf.c`: create, merge, and enable callbacks for stream server config
- `helpers.c`: shared config string and filesystem validation helpers
- `policy.c`: VO/group policy directives and policy finalization
- `backend_directives.c`: manager-map, upstream redirector, and cache-origin directives
- `cms.c`: CMS manager directive parsing
- `gsi.c`: GSI certificate/key/CA/CRL setup and CRL store rebuilds
- `tls.c`: in-protocol XRootD TLS context setup
- `token.c`: native token/JWKS auth setup
- `runtime_server.c`: root/cache/access-log validation for enabled servers
- `metrics.c`: metrics shared-memory setup and init callback
- `threads.c`: thread-pool resolution for async I/O
- `process.c`: worker-process CMS startup and CRL reload timers
- `postconfiguration.c`: postconfiguration pass ordering
