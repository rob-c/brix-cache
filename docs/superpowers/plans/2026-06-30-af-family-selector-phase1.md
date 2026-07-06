# Address-Family Selector (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a dual-stack/IPv6 cache node reach an IPv4-only *or* IPv6-only origin by constraining the address family of the outbound origin connect via a `xrootd_cache_origin_family auto|inet|inet6;` directive — covering both the read-fill and write-through cache paths, with no ~2-minute connect stall when an incompatible family is forced.

**Architecture:** A pure `xrootd_af_policy_t` enum + a standalone string parser become the shared vocabulary. The shared event-loop resolver `xrootd_resolve_connect_socket()` gains an `af_policy` parameter (existing callers pass `AUTO`, no behavior change). The cache origin connect (`xrootd_cache_origin_connect_addr`) — the single seam both the legacy `xrootd_cache_origin` path and the modern `xrootd_storage_backend root://` (`sd_xroot`) path funnel through — reads a new `cache_origin_family` config field and sets `hints.ai_family`. For the `sd_xroot` path the field is threaded from the merged server conf (in `runtime_server.c`) through the VFS backend registry into the synthetic origin conf, so directive order does not matter.

**Tech Stack:** C (nginx module), nginx stream config directives, bash+xrdfs integration tests, standalone gcc unit test.

## Global Constraints

- **NO `goto`** anywhere in `src/` — early-return + helper decomposition (verbatim from CLAUDE.md HARD BLOCKS).
- **Functional/modular**: one job per function, pass state explicitly, no new globals.
- **HELPERS — never reimplement**: reuse `xrootd_resolve_connect_socket`, the existing non-blocking connect deadline, the existing directive/merge machinery.
- **Build governance**: a new `.c` requires registration in the top-level `./config` then `./configure`; header-only additions and edits to existing `.c` need only `make -j$(nproc)`. Live stream directive table is `src/protocols/root/stream/module.c` (the `module_*_directives.c` fragments are NOT compiled).
- **Default must be backward-compatible**: absent directive ⇒ `AUTO` ⇒ today's `AF_UNSPEC` behavior, byte-for-byte.
- **3 tests per change**: success + error + security/parity.
- Build: `make -j$(nproc)`; validate: `/tmp/nginx-1.28.3/objs/nginx -t -c <conf>`.

---

### Task 1: `xrootd_af_policy_t` type + string parser (header-only, pure)

**Files:**
- Create: `src/core/compat/af_policy.h`
- Test: `tests/af_policy_unittest.c` (standalone gcc, no nginx deps)

**Interfaces:**
- Produces: `typedef enum { XROOTD_AF_AUTO=AF_UNSPEC, XROOTD_AF_INET=AF_INET, XROOTD_AF_INET6=AF_INET6 } xrootd_af_policy_t;` and `static inline int xrootd_af_policy_parse(const char *s, size_t len)` → returns the enum value, or `-1` on an unknown token.

- [ ] **Step 1: Write the failing test**

Create `tests/af_policy_unittest.c`:

```c
/* Standalone unit test for src/core/compat/af_policy.h — gcc, no nginx. */
#include <assert.h>
#include <stdio.h>
#include "../src/core/compat/af_policy.h"

int main(void)
{
    assert(xrootd_af_policy_parse("auto", 4)  == XROOTD_AF_AUTO);
    assert(xrootd_af_policy_parse("inet", 4)  == XROOTD_AF_INET);
    assert(xrootd_af_policy_parse("inet6", 5) == XROOTD_AF_INET6);
    /* unknown / partial / wrong-length tokens reject */
    assert(xrootd_af_policy_parse("ipv4", 4)  == -1);
    assert(xrootd_af_policy_parse("inet", 3)  == -1);   /* "ine" */
    assert(xrootd_af_policy_parse("inet64", 6) == -1);
    assert(xrootd_af_policy_parse("", 0)      == -1);
    /* the enum values must equal the AF_* constants (assignable to ai_family) */
    assert(XROOTD_AF_AUTO  == AF_UNSPEC);
    assert(XROOTD_AF_INET  == AF_INET);
    assert(XROOTD_AF_INET6 == AF_INET6);
    printf("af_policy_unittest: all checks passed\n");
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -o /tmp/af_policy_unittest tests/af_policy_unittest.c && /tmp/af_policy_unittest`
Expected: FAIL — compile error, `src/core/compat/af_policy.h: No such file or directory`.

- [ ] **Step 3: Write minimal implementation**

Create `src/core/compat/af_policy.h`:

```c
#ifndef NGX_XROOTD_COMPAT_AF_POLICY_H
#define NGX_XROOTD_COMPAT_AF_POLICY_H

/*
 * af_policy.h — outbound address-family policy for cache/proxy origin connects.
 *
 * WHAT: a 3-value policy (auto/inet/inet6) plus a string parser. The enum values
 *   ARE the AF_* constants, so a policy assigns straight into a getaddrinfo
 *   hints.ai_family with no mapping table.
 * WHY: a dual-stack/IPv6 cache node must be able to reach an IPv4-only or
 *   IPv6-only origin. Constraining the family of the OUTBOUND resolve is the whole
 *   mechanism — the listen side stays dual-stack via nginx `listen`.
 * HOW: header-only, pure, no nginx deps, so it is shared by the directive handler,
 *   the resolver, and a standalone unit test.
 */

#include <sys/socket.h>   /* AF_UNSPEC / AF_INET / AF_INET6 */
#include <stddef.h>
#include <string.h>

typedef enum {
    XROOTD_AF_AUTO  = AF_UNSPEC,   /* try every family (legacy default) */
    XROOTD_AF_INET  = AF_INET,     /* IPv4-only origin */
    XROOTD_AF_INET6 = AF_INET6     /* IPv6-only origin */
} xrootd_af_policy_t;

/* Parse "auto" | "inet" | "inet6" → policy value; -1 on any other token. */
static inline int
xrootd_af_policy_parse(const char *s, size_t len)
{
    if (len == 4 && memcmp(s, "auto", 4) == 0)  { return XROOTD_AF_AUTO; }
    if (len == 4 && memcmp(s, "inet", 4) == 0)  { return XROOTD_AF_INET; }
    if (len == 5 && memcmp(s, "inet6", 5) == 0) { return XROOTD_AF_INET6; }
    return -1;
}

#endif /* NGX_XROOTD_COMPAT_AF_POLICY_H */
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -Wall -Wextra -o /tmp/af_policy_unittest tests/af_policy_unittest.c && /tmp/af_policy_unittest`
Expected: PASS — `af_policy_unittest: all checks passed`, exit 0, no warnings.

- [ ] **Step 5: Commit**

```bash
git add src/core/compat/af_policy.h tests/af_policy_unittest.c
git commit -m "feat(net): add xrootd_af_policy_t + parser for outbound address-family selection"
```

---

### Task 2: Thread `af_policy` through the shared resolver (callers pass AUTO)

**Files:**
- Modify: `src/protocols/root/connection/netconnect.h` (the `xrootd_resolve_connect_socket` signature + `hints.ai_family`)
- Modify: `src/net/proxy/connect_upstream.c:269` (caller → `XROOTD_AF_AUTO`)
- Modify: `src/net/upstream/start.c:111` (caller → `XROOTD_AF_AUTO`)

**Interfaces:**
- Consumes: `xrootd_af_policy_t` (Task 1).
- Produces: `xrootd_resolve_connect_socket(const char *host, unsigned port, xrootd_af_policy_t af_policy, struct sockaddr_storage *addr_out, socklen_t *addrlen_out, xrootd_resolve_status_t *status_out)` — new 3rd parameter `af_policy`.

- [ ] **Step 1: Write the failing test (build is the test)**

There is no standalone harness for this header-only ngx-inline function; the test is that the module still compiles AND the existing proxy/cache integration suites are unchanged (parity). Capture the pre-change baseline:

Run: `tests/run_cache_xroot_origin.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS (all `ok` lines) — this is the parity baseline we must preserve.

- [ ] **Step 2: Add the parameter to the resolver**

In `src/protocols/root/connection/netconnect.h`, include the policy header near the top includes:

```c
#include "../compat/af_policy.h"
```

Change the signature and the `ai_family` line in `xrootd_resolve_connect_socket`:

```c
static ngx_inline int
xrootd_resolve_connect_socket(const char *host, unsigned port,
    xrootd_af_policy_t af_policy,
    struct sockaddr_storage *addr_out, socklen_t *addrlen_out,
    xrootd_resolve_status_t *status_out)
{
    struct addrinfo  hints;
    struct addrinfo *res;
    struct addrinfo *rp;
    char             port_str[16];
    int              fd = (int) NGX_INVALID_FILE;

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = (int) af_policy;   /* AUTO==AF_UNSPEC keeps legacy behaviour */
    snprintf(port_str, sizeof(port_str), "%u", port);
```

Also update the function's doc comment to note the new parameter (one line: `af_policy constrains getaddrinfo's family — AUTO/AF_UNSPEC = try all`).

- [ ] **Step 3: Update both callers to pass AUTO**

In `src/net/proxy/connect_upstream.c` (~line 269):

```c
        fd = xrootd_resolve_connect_socket((const char *) use_host->data,
                                           (unsigned) use_port,
                                           XROOTD_AF_AUTO,
                                           &chosen_addr, &chosen_addrlen,
                                           &rstatus);
```

In `src/net/upstream/start.c` (~line 111):

```c
        fd = xrootd_resolve_connect_socket((char *) conf->upstream_host.data,
                                           (unsigned) conf->upstream_port,
                                           XROOTD_AF_AUTO,
                                           &chosen_addr, &chosen_addrlen,
                                           &rstatus);
```

- [ ] **Step 4: Build and verify parity**

Run: `make -j$(nproc) 2>&1 | tail -5`
Expected: clean build, exit 0 (the build is `-Werror`; no warnings).

Run: `tests/run_cache_xroot_origin.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — identical to the Step 1 baseline (resolver behavior unchanged because every caller passes `AUTO`).

- [ ] **Step 5: Commit**

```bash
git add src/protocols/root/connection/netconnect.h src/net/proxy/connect_upstream.c src/net/upstream/start.c
git commit -m "refactor(net): thread af_policy through xrootd_resolve_connect_socket (callers AUTO, no behaviour change)"
```

---

### Task 3: `xrootd_cache_origin_family` directive + connect-site enforcement

**Files:**
- Modify: `src/core/types/config.h:429` area (add `cache_origin_family` field)
- Modify: `src/core/config/server_conf.c:110` area (create default `NGX_CONF_UNSET_UINT`) and `:530` area (merge to `XROOTD_AF_AUTO`)
- Modify: `src/protocols/root/stream/module.c:1177` area (register directive in the live command table)
- Modify: `src/fs/cache/directives.c` (add `xrootd_conf_set_cache_origin_family` handler)
- Modify: `src/core/config/config.h` (declare the handler prototype, next to `xrootd_conf_set_cache_origin`)
- Modify: `src/fs/cache/origin_connection.c:70` (read the policy into `hints.ai_family`)

**Interfaces:**
- Consumes: `xrootd_af_policy_parse` (Task 1), `xrootd_resolve_connect_socket` af_policy (Task 2 — not directly used here; the cache uses its own connect path).
- Produces: config field `ngx_uint_t cache_origin_family;` on `ngx_stream_xrootd_srv_conf_t`; directive `xrootd_cache_origin_family auto|inet|inet6;`; handler `char *xrootd_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)`.

- [ ] **Step 1: Write the failing test (config accept/reject)**

Create `tests/run_af_family_conf.sh`:

```bash
#!/usr/bin/env bash
# Config-grammar test for xrootd_cache_origin_family: valid tokens accepted,
# bad token rejected at nginx -t.
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
PFX="$(mktemp -d /tmp/af_conf.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
trap 'rm -rf "$PFX"' EXIT
mkdir -p "$PFX/root" "$PFX/cache"

mkconf() {  # $1 = family token
cat > "$PFX/nginx.conf" <<EOF
daemon off; error_log $PFX/e.log info; pid $PFX/pid;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:11939; brix_root on; xrootd_auth none;
    xrootd_storage_backend root://127.0.0.1:11940;
    xrootd_cache_store posix:$PFX/cache; xrootd_cache_root /;
    xrootd_cache_origin_family $1;
} }
EOF
}

for tok in auto inet inet6; do
    mkconf "$tok"
    if "$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1; then
        ok "accepts xrootd_cache_origin_family $tok"
    else
        bad "rejected valid token $tok"
    fi
done

mkconf "ipv4"
if "$NGINX" -t -c "$PFX/nginx.conf" >/dev/null 2>&1; then
    bad "accepted bogus token ipv4"
else
    ok "rejects bogus token ipv4"
fi

exit $fail
```

`chmod +x tests/run_af_family_conf.sh`.

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_af_family_conf.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: FAIL — every `auto/inet/inet6` line FAILs with `unknown directive "xrootd_cache_origin_family"`.

- [ ] **Step 3a: Add the config field**

In `src/core/types/config.h`, immediately after the `cache_origin_tls` line (~429):

```c
    ngx_uint_t  cache_origin_family; /* [xrootd_cache_origin_family auto|inet|inet6]
                                        xrootd_af_policy_t for the origin connect;
                                        default XROOTD_AF_AUTO (AF_UNSPEC). */
```

- [ ] **Step 3b: Create-default + merge**

In `src/core/config/server_conf.c`, next to `conf->cache_origin_tls = NGX_CONF_UNSET;` (~110):

```c
    conf->cache_origin_family = NGX_CONF_UNSET_UINT;
```

Next to the `cache_origin_tls` merge (~530):

```c
    ngx_conf_merge_uint_value(conf->cache_origin_family,
                              prev->cache_origin_family, XROOTD_AF_AUTO);
```

Ensure `server_conf.c` sees the enum: add `#include "../compat/af_policy.h"` with its other includes if not already reachable via `config.h`.

- [ ] **Step 3c: Add the directive handler**

In `src/fs/cache/directives.c`, add (with `#include "../compat/af_policy.h"` at the top):

```c
/* xrootd_conf_set_cache_origin_family — parse auto|inet|inet6 into the origin
 * connect's address-family policy (xrootd_af_policy_t stored as ngx_uint_t). */
char *
xrootd_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    int                           pol;

    (void) cmd;

    pol = xrootd_af_policy_parse((const char *) value[1].data, value[1].len);
    if (pol < 0) {
        return "must be one of: auto, inet, inet6";
    }
    xcf->cache_origin_family = (ngx_uint_t) pol;
    return NGX_CONF_OK;
}
```

Declare its prototype in `src/core/config/config.h` next to `xrootd_conf_set_cache_origin`:

```c
char *xrootd_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
```

- [ ] **Step 3d: Register the directive in the live table**

In `src/protocols/root/stream/module.c`, immediately after the `xrootd_cache_origin_tls` command block (~1183):

```c
    { ngx_string("xrootd_cache_origin_family"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_origin_family,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
```

- [ ] **Step 3e: Enforce at the connect site**

In `src/fs/cache/origin_connection.c` (`xrootd_cache_origin_connect_addr`, ~line 70), replace `hints.ai_family = AF_UNSPEC;` with a read of the policy:

```c
    ngx_memzero(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    {
        ngx_uint_t fam = (t->conf != NULL)
            ? t->conf->cache_origin_family : (ngx_uint_t) XROOTD_AF_AUTO;
        if (fam == NGX_CONF_UNSET_UINT) {
            fam = (ngx_uint_t) XROOTD_AF_AUTO;
        }
        hints.ai_family = (int) fam;   /* AUTO==AF_UNSPEC tries every family */
    }
```

Add `#include "../compat/af_policy.h"` to `origin_connection.c` includes.

- [ ] **Step 4: Run test to verify it passes**

Run: `make -j$(nproc) 2>&1 | tail -5`
Expected: clean build, exit 0.

Run: `tests/run_af_family_conf.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — `auto/inet/inet6` accepted, `ipv4` rejected.

- [ ] **Step 5: Commit**

```bash
git add src/core/types/config.h src/core/config/server_conf.c src/protocols/root/stream/module.c \
        src/fs/cache/directives.c src/core/config/config.h src/fs/cache/origin_connection.c \
        tests/run_af_family_conf.sh
git commit -m "feat(cache): xrootd_cache_origin_family directive constrains origin connect address family"
```

---

### Task 4: Thread the family into the `storage_backend` (sd_xroot) synth conf + end-to-end test

The `xrootd_storage_backend root://` path builds a **synthetic** origin conf inside
`sd_xroot` (calloc'd ⇒ family defaults to `AF_UNSPEC`/AUTO). To honor the directive
on that path, carry the merged `cache_origin_family` from `runtime_server.c` →
backend registry entry → `sd_xroot` synth.

**Files:**
- Modify: `src/fs/vfs/vfs_backend_registry.c` (entry field `origin_family`; `set_xroot`, `config_xroot`, and the storage-backend dispatcher gain a `family` arg; pass `e->origin_family` to `create_origin`)
- Modify: `src/fs/vfs/vfs_backend_registry.h` (updated `xrootd_vfs_backend_config_xroot` + dispatcher prototypes)
- Modify: `src/core/config/runtime_server.c:383,402` (pass `xcf->cache_origin_family`)
- Modify: `src/fs/backend/xroot/sd_xroot.c` (`create_origin` gains `int af_policy`; set `synth->cache_origin_family`)
- Modify: `src/fs/backend/xroot/sd_xroot.h:57` (updated `xrootd_sd_xroot_create_origin` prototype)
- Test: `tests/run_cache_af_family.sh` (new, end-to-end)

**Interfaces:**
- Consumes: `cache_origin_family` field (Task 3), `xrootd_cache_origin_connect_addr` family read (Task 3).
- Produces: `xrootd_sd_xroot_create_origin(const char *host, int port, int tls, int af_policy, const char *bearer, const char *x509_proxy, const char *ca_dir, ngx_log_t *log)`; `xrootd_vfs_backend_config_xroot(const char *root_canon, const char *host, int port, int tls, int family)`; registry entry field `int origin_family;`.

- [ ] **Step 1: Write the failing end-to-end test**

Create `tests/run_cache_af_family.sh` (models `run_cache_xroot_origin.sh`):

```bash
#!/usr/bin/env bash
# End-to-end: xrootd_cache_origin_family constrains the storage_backend root://
# origin connect. Origin binds 127.0.0.1 (IPv4) only.
#   inet  -> fill succeeds (byte-exact)
#   inet6 -> fill fails FAST (no AAAA/refused), well under the connect deadline
#   auto  -> fill succeeds (parity)
set -u
NGINX="${1:-/tmp/nginx-1.28.3/objs/nginx}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
XRDFS="$HERE/client/bin/xrdfs"
OP=11940; NP=11941
PFX="$(mktemp -d /tmp/cache_af.XXXXXX)"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }
cleanup(){ for r in o n; do [ -f "$PFX/$r/pid" ] && kill "$(cat "$PFX/$r/pid")" 2>/dev/null; done; rm -rf "$PFX" /tmp/cache_af_*.got; }
trap cleanup EXIT
mkdir -p "$PFX/o/root" "$PFX/o/logs" "$PFX/n/cache" "$PFX/n/logs"

cat > "$PFX/o/nginx.conf" <<EOF
daemon on; error_log $PFX/o/logs/e.log info; pid $PFX/o/pid;
events { worker_connections 64; }
stream { server { listen 127.0.0.1:${OP}; brix_root on; xrootd_root $PFX/o/root; xrootd_auth none; } }
EOF

node_conf() {  # $1 = family token
cat > "$PFX/n/nginx.conf" <<EOF
daemon on; error_log $PFX/n/logs/e.log info; pid $PFX/n/pid;
thread_pool default threads=2;
events { worker_connections 64; }
stream { server {
    listen 127.0.0.1:${NP}; brix_root on; xrootd_auth none;
    xrootd_storage_backend root://127.0.0.1:${OP};
    xrootd_cache_store posix:$PFX/n/cache; xrootd_cache_root /;
    xrootd_cache_origin_family $1;
} }
EOF
}

start_node(){ node_conf "$1"; "$NGINX" -p "$PFX/n" -c "$PFX/n/nginx.conf" 2>"$PFX/n/err" || { echo node-start-fail; cat "$PFX/n/err"; exit 2; }; }
stop_node(){ [ -f "$PFX/n/pid" ] && kill "$(cat "$PFX/n/pid")" 2>/dev/null; rm -f "$PFX/n/pid"; sleep 0.3; }

"$NGINX" -p "$PFX/o" -c "$PFX/o/nginx.conf" 2>"$PFX/o/err" || { echo origin-fail; cat "$PFX/o/err"; exit 2; }
sleep 1
head -c 600000 /dev/urandom > "$PFX/o/root/f.bin"

# inet -> success
start_node inet; sleep 1
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_4.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_4.got && ok "inet: IPv4 origin fill byte-exact" || bad "inet: fill mismatch"
stop_node; rm -rf "$PFX/n/cache"/*; mkdir -p "$PFX/n/cache"

# inet6 -> fail fast (origin has no IPv6 listener; ::1 connect refused immediately)
start_node inet6; sleep 1
t0=$(date +%s)
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_6.got 2>/dev/null
rc=$?; t1=$(date +%s); dt=$((t1 - t0))
{ [ $rc -ne 0 ] || ! cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_6.got; } && ok "inet6: fill fails (no IPv4 fallback)" || bad "inet6: unexpectedly succeeded"
[ $dt -lt 30 ] && ok "inet6: failed fast (${dt}s < 30s, no retransmit stall)" || bad "inet6: stalled ${dt}s"
stop_node; rm -rf "$PFX/n/cache"/*; mkdir -p "$PFX/n/cache"

# auto -> success (parity)
start_node auto; sleep 1
"$XRDFS" root://127.0.0.1:${NP} cat /f.bin > /tmp/cache_af_a.got 2>/dev/null
cmp -s "$PFX/o/root/f.bin" /tmp/cache_af_a.got && ok "auto: fill byte-exact (parity)" || bad "auto: fill mismatch"
stop_node
exit $fail
```

`chmod +x tests/run_cache_af_family.sh`.

- [ ] **Step 2: Run test to verify it fails**

Run: `tests/run_cache_af_family.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: FAIL — the `inet6` case still fills successfully because the synth conf ignores the family (defaults AUTO ⇒ falls back to IPv4). `inet6: unexpectedly succeeded` FAILs.

- [ ] **Step 3a: Registry entry field + setters**

In `src/fs/vfs/vfs_backend_registry.c`, add to the entry struct after `int origin_tls;` (~line 25):

```c
    int                   origin_family;  /* xrootd_af_policy_t for origin connect */
```

Update `xrootd_vfs_backend_set_xroot` (signature + body):

```c
static void
xrootd_vfs_backend_set_xroot(xrootd_vfs_backend_entry_t *e, const char *host,
    int port, int tls, int family)
{
    ngx_memcpy(e->backend, "xroot", sizeof("xroot"));
    ngx_cpystrn((u_char *) e->origin_host, (u_char *) host,
                sizeof(e->origin_host));
    e->origin_port   = port;
    e->origin_tls    = tls;
    e->origin_family = family;
    e->inst          = NULL;                /* rebuilt on next resolve */
}
```

Update `xrootd_vfs_backend_config_xroot` (signature + both `set_xroot` call sites pass `family`):

```c
void
xrootd_vfs_backend_config_xroot(const char *root_canon, const char *host,
    int port, int tls, int family)
{
    ngx_uint_t i;

    if (root_canon == NULL || root_canon[0] == '\0' || host == NULL
        || host[0] == '\0' || port <= 0 || port > 65535)
    {
        return;
    }
    for (i = 0; i < xrootd_vfs_backend_count; i++) {
        if (ngx_strcmp(xrootd_vfs_backends[i].root_canon, root_canon) == 0) {
            xrootd_vfs_backend_set_xroot(&xrootd_vfs_backends[i], host, port,
                                         tls, family);
            return;
        }
    }
    if (xrootd_vfs_backend_count >= XROOTD_VFS_BACKEND_MAX) {
        return;
    }
    {
        xrootd_vfs_backend_entry_t *e =
            &xrootd_vfs_backends[xrootd_vfs_backend_count++];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->root_canon, (u_char *) root_canon,
                    sizeof(e->root_canon));
        xrootd_vfs_backend_set_xroot(e, host, port, tls, family);
    }
}
```

Update the prototype in `src/fs/vfs/vfs_backend_registry.h` to match (add `, int family`).

- [ ] **Step 3b: Pass family at the storage-backend dispatcher**

In `src/fs/vfs/vfs_backend_registry.c` (~line 724) update the call:

```c
        xrootd_vfs_backend_config_xroot(root_canon, host, (int) portnum,
                                        is_roots, family);
```

The dispatcher (the function containing line 724) must accept and forward a `family`
argument. Add `int family` to its signature and its prototype in
`vfs_backend_registry.h`; the no-remote branch (`xrootd_vfs_backend_config(...)` at
~695) is unaffected (local backends have no origin connect).

- [ ] **Step 3c: Source the family from the merged conf**

In `src/core/config/runtime_server.c`, the two `xrootd_vfs_backend_config(...)` call sites
(~383, ~402) reach the storage-backend dispatcher with `xcf` in scope. Pass
`(int) xcf->cache_origin_family` as the new `family` argument through the dispatch
chain. (At this point — server runtime setup — all directives are parsed and merged,
so the value is final regardless of directive order.)

- [ ] **Step 3d: Accept + store the family in the sd_xroot synth conf**

In `src/fs/backend/xroot/sd_xroot.h` (~line 57) update the prototype:

```c
xrootd_sd_instance_t *xrootd_sd_xroot_create_origin(const char *host, int port,
    int tls, int af_policy, const char *bearer, const char *x509_proxy,
    const char *ca_dir, ngx_log_t *log);
```

In `src/fs/backend/xroot/sd_xroot.c`, update the definition signature to match and set
the synth field next to the other synth assignments (~line 788):

```c
    synth->cache_origin_port      = (uint16_t) port;
    synth->cache_origin_tls       = tls ? 1 : 0;
    synth->cache_origin_family    = (ngx_uint_t) af_policy;
```

Update the caller in `src/fs/vfs/vfs_backend_registry.c` (~line 853) to pass the entry's
family in the new slot:

```c
        inst = xrootd_sd_xroot_create_origin(e->origin_host, e->origin_port,
                 e->origin_tls, e->origin_family,
                 (e->origin_token[0] != '\0') ? e->origin_token : NULL,
                 (e->origin_x509_proxy[0] != '\0') ? e->origin_x509_proxy : NULL,
                 (e->origin_ca_dir[0] != '\0') ? e->origin_ca_dir : NULL,
                 log);
```

- [ ] **Step 4: Build and run the end-to-end test**

Run: `make -j$(nproc) 2>&1 | tail -5`
Expected: clean build, exit 0.

Run: `tests/run_cache_af_family.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — `inet` byte-exact, `inet6` fails fast (<30s), `auto` byte-exact.

Run (regression): `tests/run_cache_xroot_origin.sh /tmp/nginx-1.28.3/objs/nginx`
Expected: PASS — unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/fs/vfs/vfs_backend_registry.c src/fs/vfs/vfs_backend_registry.h \
        src/core/config/runtime_server.c src/fs/backend/xroot/sd_xroot.c \
        src/fs/backend/xroot/sd_xroot.h tests/run_cache_af_family.sh
git commit -m "feat(cache): honor xrootd_cache_origin_family on the storage_backend root:// (sd_xroot) origin path"
```

---

## Notes / Deferred

- **Proxy upstream family (`xrootd_proxy_upstream_family` + per-upstream `family=`):** deferred — the legacy `xrootd_proxy*` stream directive surface is currently DISABLED (`src/protocols/root/stream/module.c:1603`) ahead of the proxy rebuild. The resolver already accepts `af_policy` (Task 2), so the proxy knob is a thin add once the proxy directive surface returns in the Phase 2/3 work.
- **HTTP/Pelican + S3 origins:** this plan covers the `root://`/`sd_xroot` origin connect. The libcurl-based HTTP/S3 origin transports resolve inside libcurl; constraining their family (`CURLOPT_IPRESOLVE`) is a small follow-up if needed, tracked with the proxy phase.

## Self-Review

- **Spec coverage:** Phase 1 (§3 of the spec) = address-family selector for caches → Tasks 1–4. Spec §3.2 named both resolver seams; the cache seam is fully implemented (Tasks 3–4), the `xrootd_resolve_connect_socket` seam is parameterized (Task 2) with the proxy directive consciously deferred (documented above, matching the spec's "proxy directive belongs with the proxy rebuild" finding). Spec §3.3 directives: `xrootd_cache_origin_family` done; `xrootd_proxy_upstream_family` deferred with rationale. Spec §3.4 tests: success/error/parity realized in `run_cache_af_family.sh` + `run_af_family_conf.sh` + `af_policy_unittest.c`.
- **Placeholder scan:** none — every step carries real code/commands.
- **Type consistency:** `xrootd_af_policy_t`/`xrootd_af_policy_parse` (Task 1) used unchanged in Tasks 2–3; `cache_origin_family` is `ngx_uint_t` everywhere (field, merge, handler cast, connect read); `create_origin`'s new `int af_policy` is the 4th arg consistently in proto (Task 4 Step 3d), definition, and caller.
