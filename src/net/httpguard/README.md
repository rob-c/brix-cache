# net/httpguard — HTTP adapter for the bad-actor guard

`ngx_http_xrootd_guard_module`: puts nginx in front of an ARC CE or an
XrdHttp/WebDAV server as a credential-preserving reverse proxy that bounces
obvious junk **before** the backend sees it (ACCESS phase) and emits one
fail2ban audit line per bad-actor signal (LOG phase). All classification
lives in the pure-C core [`src/net/guard/`](../guard/README.md); stock
`ngx_http_proxy_module` moves the bytes. The `root://` equivalent is the
stream relay sink [`src/protocols/root/relay/relay_guard.c`](../../protocols/root/relay/relay_guard.c)
(`xrootd_guard_stream on;` — enforcement = connection drop).

| File | Responsibility |
|---|---|
| `guard_http.h` | Module decl, loc-conf + request-ctx structs, scratch sizes. |
| `module.c` | Directive table, conf create/merge (ruleset built once at merge), ACCESS+LOG phase registration. |
| `classify_handler.c` | ACCESS phase: build `guard_request_t`, `guard_classify_pre`, bounce 403/444 pre-backend. |
| `audit_handler.c` | LOG phase: final status → outcome, `guard_classify_post`, audit line (skips ACCESS-bounced requests). |
| `guard_http_req.c` | Shared `guard_request_t` builder (method→op, cred detection, sanitized path/ip) + atomic audit-log writer. |

## Directives

| Directive | Default | Meaning |
|---|---|---|
| `xrootd_guard on\|off` | off | enable classification on this location |
| `xrootd_guard_profile arc\|xrdhttp` | — | grammar defaults (ARC REST prefixes + job ops / export-root data ops) |
| `xrootd_guard_default_signatures on\|off` | on | built-in junk-scanner set (.php/.asp/wp-/.git/.env/…) |
| `xrootd_guard_bounce_status 403\|444` | 444 | 444 = drop connection without response (best vs scanners) |
| `xrootd_guard_audit_log <path>` | — | fail2ban audit line destination (O_APPEND, USR1-rotated) |
| `xrootd_guard_signature <substr>` | — | extra blocklist substring (repeatable) |
| `xrootd_guard_valid_prefix <prefix>` | profile | narrow the legitimate namespace (repeatable) |
| `xrootd_guard_valid_method <m> [m…]` | profile | restrict allowed HTTP methods |

## ARC deployment recipe

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/grid-security/hostcert.pem;
    ssl_certificate_key /etc/grid-security/hostkey.pem;
    # accept the client's proxy cert without CA termination — ARC validates it
    ssl_verify_client optional_no_ca;

    location / {
        xrootd_guard on;
        xrootd_guard_profile arc;
        xrootd_guard_audit_log /var/log/xrootd-guard-audit.log;

        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
        proxy_pass https://arc_backend;
    }
}
```

For XrdHttp/WebDAV swap `xrootd_guard_profile xrdhttp;` and add
`xrootd_guard_valid_prefix /store;` (or your export roots).

## fail2ban wiring

Install [`deploy/fail2ban/filter.d/xrootd-guard-*.conf`](../../../deploy/fail2ban/filter.d/)
and [`deploy/fail2ban/jail.d/xrootd-guard.conf`](../../../deploy/fail2ban/jail.d/xrootd-guard.conf),
point `logpath` at the `xrootd_guard_audit_log` file. Per-signal jails:
signature = 1 hit → 24h ban; grammar = 2/10min → 12h; notfound = 20/min → 1h;
authfail = 5/2min → 2h (nftables banaction).

## Tests

```bash
TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest \
    tests/test_arc_guard.py tests/test_xrdhttp_guard.py \
    tests/test_stream_guard.py tests/test_fail2ban_regex.py -v -p no:xdist
```
