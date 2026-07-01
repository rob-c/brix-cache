# SSI Phase 1 — Session + RRTable Multiplex Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Promote `src/ssi/`'s one-request-per-handle engine into a session object holding an RRTable, so a single open SSI handle multiplexes many concurrent requests keyed by `reqId` — a pure refactor that preserves existing single-request behavior and adds no new wire features.

**Architecture:** The fd-table `.ssi` slot (already `void *`) points at a new `xrootd_ssi_session_t` instead of a bare `xrootd_ssi_req_t`. The session owns the resolved provider and a fixed-size table of per-`reqId` request slots. The `open`/`write`/`query`/`read` hooks decode the `reqId` from the `XrdSsiRRInfo` and route to the matching slot. Service resolution moves behind a small provider registry (the no-plugin-ABI stand-in for `XrdSsiProvider`). The client-poll (`kXR_query`) delivery path is unchanged.

**Tech Stack:** C (nginx stream module), nginx pool allocation (`ngx_pcalloc`/`ngx_palloc`), standalone-gcc unit tests (`ssi_*_unittest.c`), pytest raw-wire integration tests.

## Global Constraints

- **NO `goto`** anywhere in `src/` — early-return + helper decomposition only.
- **Functional + modular** — one responsibility per function; pass state explicitly; no new globals.
- **Use existing helpers** — never reimplement path/auth/metrics/framing. Wire codec stays in `ssi_rrinfo`; reply framing in `ssi_reply`; responses via `xrootd_send_ok`/`xrootd_send_error`/`xrootd_queue_response`.
- **Allocation:** stream path uses `ngx_pcalloc(c->pool, …)` / `ngx_palloc(c->pool, …)` — never raw `malloc`. `ngx_str_t` uses `.len`, never `strlen`/`strcpy`.
- **3 tests per change:** success + error + security/edge-negative.
- **Build governance:** new `.c` files register in the top-level `./config` (`$ngx_addon_dir/src/...` lists), then re-run `./configure` over a clean `objs/` before `make`. Incremental `make -j$(nproc)` otherwise. (A new source added without a clean reconfigure risks mixed-ABI garbage.)
- **Behavior invariant:** a non-SSI handle's data path stays byte-for-byte unchanged; SSI hooks remain clean early-returns keyed on `ctx->files[idx].ssi`.

---

### Task 1: SSI provider registry

Introduce a tiny service-name → implementation registry so `open` no longer calls `xrootd_ssi_service_lookup` directly. Returned **by value** (caller copies into the session) so it is reentrant.

**Files:**
- Create: `src/ssi/provider.h`
- Create: `src/ssi/provider.c`
- Create: `src/ssi/provider_unittest.c`
- Modify: `config` (register `src/ssi/provider.c`)

**Interfaces:**
- Consumes: `xrootd_ssi_process_fn` (from `src/ssi/ssi_service.h`), `xrootd_ssi_service_lookup()` (existing, resolves built-in `echo`).
- Produces:
  - `typedef struct { const char *name; xrootd_ssi_process_fn process; } xrootd_ssi_provider_t;`
  - `int xrootd_ssi_provider_lookup(const char *name, xrootd_ssi_provider_t *out);` → returns 1 and fills `*out` if known, else 0.

- [ ] **Step 1: Write the failing test**

Create `src/ssi/provider_unittest.c`:

```c
/*
 * provider_unittest.c — standalone unit test for the SSI provider registry.
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_provider_ut \
 *       src/ssi/provider_unittest.c src/ssi/provider.c src/ssi/ssi_service.c \
 *       && /tmp/ssi_provider_ut
 */
#include "provider.h"
#include <stdio.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_known_service(void)
{
    xrootd_ssi_provider_t p;
    CHECK(xrootd_ssi_provider_lookup("echo", &p) == 1);
    CHECK(p.process != NULL);
    CHECK(strcmp(p.name, "echo") == 0);
}

static void test_unknown_service(void)
{
    xrootd_ssi_provider_t p;
    memset(&p, 0xff, sizeof(p));
    CHECK(xrootd_ssi_provider_lookup("nope", &p) == 0);
}

static void test_null_name(void)
{
    xrootd_ssi_provider_t p;
    CHECK(xrootd_ssi_provider_lookup(NULL, &p) == 0);
}

int main(void)
{
    test_known_service();
    test_unknown_service();
    test_null_name();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_provider_ut src/ssi/provider_unittest.c src/ssi/provider.c src/ssi/ssi_service.c && /tmp/ssi_provider_ut`
Expected: FAIL to compile — `provider.h`/`provider.c` do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Create `src/ssi/provider.h`:

```c
#ifndef XROOTD_SSI_PROVIDER_H
#define XROOTD_SSI_PROVIDER_H

/*
 * provider.h — SSI service-name → implementation registry.
 *
 * WHAT: resolves the service name parsed from "/.ssi/<service>" to a handler.
 * WHY:  the no-plugin-ABI stand-in for XrdSsiProvider/XrdSsiService; lets the
 *       open path bind a session to a service without a C++ plugin.
 * HOW:  a compiled-in table delegating to the built-in service handlers; the
 *       descriptor is returned by value so callers copy it into their session
 *       (reentrant — no shared static state).
 */

#include "ssi_service.h"

typedef struct {
    const char            *name;
    xrootd_ssi_process_fn  process;
} xrootd_ssi_provider_t;

/* Fill *out for a known service name; returns 1 if found, 0 otherwise. */
int xrootd_ssi_provider_lookup(const char *name, xrootd_ssi_provider_t *out);

#endif /* XROOTD_SSI_PROVIDER_H */
```

Create `src/ssi/provider.c`:

```c
/*
 * provider.c — SSI provider registry. See provider.h.
 *
 * Phase 1 ships only the built-in services reachable through
 * xrootd_ssi_service_lookup (the reference "echo"). New native services (e.g.
 * the CTA tape service) register here as the framework grows.
 */

#include "provider.h"
#include <stddef.h>

int
xrootd_ssi_provider_lookup(const char *name, xrootd_ssi_provider_t *out)
{
    xrootd_ssi_process_fn fn;

    if (name == NULL || out == NULL) {
        return 0;
    }
    fn = xrootd_ssi_service_lookup(name);
    if (fn == NULL) {
        return 0;
    }
    out->name    = name;
    out->process = fn;
    return 1;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gcc -Wall -Wextra -Werror -I src -o /tmp/ssi_provider_ut src/ssi/provider_unittest.c src/ssi/provider.c src/ssi/ssi_service.c && /tmp/ssi_provider_ut`
Expected: `OK`

- [ ] **Step 5: Register the new source in `./config`**

Find the line registering `src/ssi/ssi.c` (e.g. `grep -n "ssi/ssi.c" config`) and add `provider.c` to the same `NGX_ADDON_SRCS`-style list, on its own line matching the surrounding `$ngx_addon_dir/src/ssi/...` entries. Example pattern to match the file's style:

```
    $ngx_addon_dir/src/ssi/provider.c \
```

- [ ] **Step 6: Commit**

```bash
git add src/ssi/provider.h src/ssi/provider.c src/ssi/provider_unittest.c config
git commit -m "feat(ssi): provider registry (service-name → handler)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: SSI session object + RRTable

Add the session struct holding the provider (by value) and a fixed table of per-`reqId` request slots, with find-or-create and drop. The per-request struct is the existing `xrootd_ssi_req_t` body, now table-resident and tagged with `reqId` + `in_use`.

**Files:**
- Create: `src/ssi/session.h`
- Create: `src/ssi/session.c`
- Create: `src/ssi/session_unittest.c`
- Modify: `src/ssi/ssi.h:34-59` (move per-request struct fields; add `reqId`/`in_use`; drop `service`/`handler` which move to the session)
- Modify: `config` (register `src/ssi/session.c`)

**Interfaces:**
- Consumes: `xrootd_ssi_provider_t` (Task 1); `xrootd_ssi_req_t` (existing struct, amended here).
- Produces:
  - `#define XROOTD_SSI_MAX_INFLIGHT 8`
  - `typedef struct { char service[64]; xrootd_ssi_provider_t provider; ngx_pool_t *pool; xrootd_ssi_req_t rr[XROOTD_SSI_MAX_INFLIGHT]; } xrootd_ssi_session_t;`
  - `xrootd_ssi_session_t *xrootd_ssi_session_create(ngx_pool_t *pool, const char *service, size_t service_len, const xrootd_ssi_provider_t *provider);`
  - `xrootd_ssi_req_t *xrootd_ssi_session_req(xrootd_ssi_session_t *s, uint32_t req_id, int create);` — returns the slot for `req_id`; with `create=1` allocates a free slot if absent (NULL if table full); with `create=0` returns NULL if absent.
  - `void xrootd_ssi_session_drop(xrootd_ssi_session_t *s, uint32_t req_id);`

- [ ] **Step 1: Amend the per-request struct in `ssi.h`**

In `src/ssi/ssi.h`, change the `xrootd_ssi_req_t` definition: remove `char service[64];`, `xrootd_ssi_process_fn handler;` (these move to the session), and add identity/occupancy fields at the top. Resulting struct:

```c
/* Per-reqId SSI request state; lives in the session's rrtable. */
typedef struct {
    uint32_t   req_id;                 /* reqId from the RRInfo (slot key) */
    unsigned   in_use:1;               /* slot occupied */

    u_char    *req;                    /* accumulated request bytes */
    size_t     req_len;
    size_t     req_expected;           /* total request size from the RRInfo */
    unsigned   have_size:1;            /* req_expected is known */
    unsigned   dispatched:1;           /* service has been invoked */

    u_char    *resp;                   /* response bytes (responder-filled) */
    size_t     resp_len;
    u_char    *meta;                   /* metadata bytes (responder-filled) */
    size_t     meta_len;
    size_t     read_cursor;            /* kXR_read stream position */

    int        err_code;               /* SSI error code (0 = none) */
    char       err_text[128];
    unsigned   error:1;
    unsigned   responded:1;            /* response (or error) is ready */
    unsigned   streaming:1;            /* service delivered multi-chunk (read-pull) */

    ngx_pool_t *pool;                  /* connection pool for responder allocs */
} xrootd_ssi_req_t;
```

Leave the `xrootd_ssi_open/_write/_query/_read` prototypes unchanged.

- [ ] **Step 2: Write the failing test**

Create `src/ssi/session_unittest.c`:

```c
/*
 * session_unittest.c — standalone unit test for the SSI session RRTable.
 *
 *   gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src \
 *       -o /tmp/ssi_session_ut \
 *       src/ssi/session_unittest.c src/ssi/session.c && /tmp/ssi_session_ut
 */
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

static void test_create_and_lookup(void)
{
    xrootd_ssi_provider_t prov = { "echo", (xrootd_ssi_process_fn) 0x1 };
    xrootd_ssi_session_t *s = xrootd_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(s != NULL);
    CHECK(strcmp(s->service, "echo") == 0);
    CHECK(s->provider.process == (xrootd_ssi_process_fn) 0x1);

    xrootd_ssi_req_t *a = xrootd_ssi_session_req(s, 7, 1);
    CHECK(a != NULL && a->req_id == 7 && a->in_use);
    /* same reqId returns the same slot */
    CHECK(xrootd_ssi_session_req(s, 7, 0) == a);
    /* a different reqId is a distinct slot (multiplex) */
    xrootd_ssi_req_t *b = xrootd_ssi_session_req(s, 9, 1);
    CHECK(b != NULL && b != a && b->req_id == 9);

    free(s);
}

static void test_lookup_absent(void)
{
    xrootd_ssi_provider_t prov = { "echo", (xrootd_ssi_process_fn) 0x1 };
    xrootd_ssi_session_t *s = xrootd_ssi_session_create(NULL, "echo", 4, &prov);
    CHECK(xrootd_ssi_session_req(s, 42, 0) == NULL);   /* not created */
    free(s);
}

static void test_table_full(void)
{
    xrootd_ssi_provider_t prov = { "echo", (xrootd_ssi_process_fn) 0x1 };
    xrootd_ssi_session_t *s = xrootd_ssi_session_create(NULL, "echo", 4, &prov);
    for (uint32_t i = 0; i < XROOTD_SSI_MAX_INFLIGHT; i++) {
        CHECK(xrootd_ssi_session_req(s, 100 + i, 1) != NULL);
    }
    CHECK(xrootd_ssi_session_req(s, 999, 1) == NULL);  /* full → NULL */
    xrootd_ssi_session_drop(s, 100);                   /* free one slot */
    CHECK(xrootd_ssi_session_req(s, 999, 1) != NULL);  /* now fits */
    free(s);
}

int main(void)
{
    test_create_and_lookup();
    test_lookup_absent();
    test_table_full();
    printf(g_fail ? "FAILED (%d)\n" : "OK\n", g_fail);
    return g_fail ? 1 : 0;
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_session_ut src/ssi/session_unittest.c src/ssi/session.c && /tmp/ssi_session_ut`
Expected: FAIL to compile — `session.h`/`session.c` do not exist yet.

- [ ] **Step 4: Write minimal implementation**

Create `src/ssi/session.h`:

```c
#ifndef XROOTD_SSI_SESSION_H
#define XROOTD_SSI_SESSION_H

/*
 * session.h — SSI session + RRTable.
 *
 * WHAT: one open "/.ssi/<service>" handle becomes a session multiplexing many
 *       concurrent requests, each keyed by the reqId carried in the RRInfo.
 * WHY:  real libXrdSsi clients pipeline several requests on one resource handle.
 * HOW:  a fixed-size table of per-reqId request slots; find-or-create on write,
 *       lookup on query/read, drop on cancel/complete. Pool-allocated under the
 *       connection pool so teardown is automatic.
 *
 * Standalone unit tests compile this file with -DSSI_UT_STANDALONE and a libc
 * malloc/free shim instead of the nginx pool.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef SSI_UT_STANDALONE
typedef struct ngx_pool_s ngx_pool_t;   /* opaque in unit tests */
#else
#include <ngx_config.h>
#include <ngx_core.h>
#endif

#include "ssi.h"        /* xrootd_ssi_req_t */
#include "provider.h"   /* xrootd_ssi_provider_t */

#define XROOTD_SSI_MAX_INFLIGHT 8

typedef struct {
    char                   service[64];
    xrootd_ssi_provider_t  provider;
    ngx_pool_t            *pool;
    xrootd_ssi_req_t       rr[XROOTD_SSI_MAX_INFLIGHT];
} xrootd_ssi_session_t;

/* Allocate a session bound to a service + resolved provider. pool may be NULL in
 * standalone unit tests (libc malloc is used). */
xrootd_ssi_session_t *xrootd_ssi_session_create(ngx_pool_t *pool,
    const char *service, size_t service_len, const xrootd_ssi_provider_t *provider);

/* Find the slot for req_id. create=1 allocates a free slot if absent (NULL if the
 * table is full); create=0 returns NULL if absent. */
xrootd_ssi_req_t *xrootd_ssi_session_req(xrootd_ssi_session_t *s,
    uint32_t req_id, int create);

/* Release the slot for req_id (idempotent). */
void xrootd_ssi_session_drop(xrootd_ssi_session_t *s, uint32_t req_id);

#endif /* XROOTD_SSI_SESSION_H */
```

Create `src/ssi/session.c`:

```c
/*
 * session.c — SSI session + RRTable. See session.h.
 */

#include "session.h"
#include <string.h>

#ifdef SSI_UT_STANDALONE
#include <stdlib.h>
#define SSI_ALLOC(pool, n) calloc(1, (n))
#else
#define SSI_ALLOC(pool, n) ngx_pcalloc((pool), (n))
#endif

xrootd_ssi_session_t *
xrootd_ssi_session_create(ngx_pool_t *pool, const char *service,
                          size_t service_len, const xrootd_ssi_provider_t *provider)
{
    xrootd_ssi_session_t *s;

    if (service_len >= sizeof(((xrootd_ssi_session_t *) 0)->service)) {
        return NULL;
    }
    s = SSI_ALLOC(pool, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    memcpy(s->service, service, service_len);
    s->service[service_len] = '\0';
    if (provider != NULL) {
        s->provider = *provider;
    }
    s->pool = pool;
    return s;
}

xrootd_ssi_req_t *
xrootd_ssi_session_req(xrootd_ssi_session_t *s, uint32_t req_id, int create)
{
    int i, free_slot = -1;

    if (s == NULL) {
        return NULL;
    }
    for (i = 0; i < XROOTD_SSI_MAX_INFLIGHT; i++) {
        if (s->rr[i].in_use && s->rr[i].req_id == req_id) {
            return &s->rr[i];
        }
        if (!s->rr[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (!create || free_slot < 0) {
        return NULL;
    }
    memset(&s->rr[free_slot], 0, sizeof(s->rr[free_slot]));
    s->rr[free_slot].in_use = 1;
    s->rr[free_slot].req_id = req_id;
    s->rr[free_slot].pool   = s->pool;
    return &s->rr[free_slot];
}

void
xrootd_ssi_session_drop(xrootd_ssi_session_t *s, uint32_t req_id)
{
    int i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < XROOTD_SSI_MAX_INFLIGHT; i++) {
        if (s->rr[i].in_use && s->rr[i].req_id == req_id) {
            s->rr[i].in_use = 0;
            return;
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `gcc -Wall -Wextra -Werror -DSSI_UT_STANDALONE -I src -o /tmp/ssi_session_ut src/ssi/session_unittest.c src/ssi/session.c && /tmp/ssi_session_ut`
Expected: `OK`

- [ ] **Step 6: Register the new source in `./config`**

Add to the `src/ssi/` source list (same place as Task 1, Step 5):

```
    $ngx_addon_dir/src/ssi/session.c \
```

- [ ] **Step 7: Commit**

```bash
git add src/ssi/session.h src/ssi/session.c src/ssi/session_unittest.c src/ssi/ssi.h config
git commit -m "feat(ssi): session object + RRTable (reqId-keyed multiplex)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Route the wire hooks through the session

Refactor `src/ssi/ssi.c` so `open` binds a session (resolving the provider), and `write`/`query`/`read` decode the `reqId` from the `RRInfo` and operate on that slot. Dispatch calls `session->provider.process`. The poll reply path and the synchronous responder are unchanged in shape — only their state source moves from a single `rq` to `session_req(...)`.

**Files:**
- Modify: `src/ssi/ssi.c` (all four hooks + `ssi_dispatch`)
- Test: `src/ssi/session_unittest.c` (already covers the table); wire behavior covered by Task 4.

**Interfaces:**
- Consumes: `xrootd_ssi_session_create`, `xrootd_ssi_session_req`, `xrootd_ssi_session_drop` (Task 2); `xrootd_ssi_provider_lookup` (Task 1); `xrootd_ssi_rrinfo_decode` (existing).
- Produces: no new public symbols; `ctx->files[idx].ssi` now holds an `xrootd_ssi_session_t *`.

- [ ] **Step 1: Update includes and `open` to bind a session**

In `src/ssi/ssi.c`, add `#include "session.h"` and `#include "provider.h"`. Replace the body of `xrootd_ssi_open` so it resolves the provider and stores a session in the slot:

```c
    xrootd_ssi_provider_t   prov;
    xrootd_ssi_session_t   *sess;
    /* ... keep idx alloc + /dev/null open exactly as before ... */

    if (!xrootd_ssi_provider_lookup(svc, &prov)) {
        close(devnull);
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
    }

    sess = xrootd_ssi_session_create(conn->pool, service, service_len, &prov);
    if (sess == NULL) {
        close(devnull);
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi alloc");
    }

    ctx->files[idx].fd         = devnull;
    ctx->files[idx].ssi        = sess;     /* now a session, not a req */
    ctx->files[idx].readable   = 1;
    ctx->files[idx].writable   = 1;
    ctx->files[idx].is_regular = 0;
```

(Move the provider lookup before `xrootd_alloc_fhandle` if you prefer failing earlier; the order above keeps the existing alloc/`/dev/null` block intact. Keep the `want_stat`/`ServerOpenBody` reply block exactly as it is today.)

- [ ] **Step 2: Make `ssi_dispatch` take the provider explicitly**

Change `ssi_dispatch` to receive the process fn (the req no longer carries `handler`):

```c
static void
ssi_dispatch(xrootd_ssi_req_t *rq, xrootd_ssi_process_fn process)
{
    xrootd_ssi_responder_t r;

    r.set_metadata = ssi_resp_set_metadata;
    r.set_response = ssi_resp_set_response;
    r.alert        = ssi_resp_alert;
    r.error        = ssi_resp_error;
    r.state        = rq;

    rq->dispatched = 1;
    if (process(rq->req, rq->req_len, &r) != 0 && !rq->responded) {
        rq->error = 1;
        rq->err_code = kXR_ServerError;
        rq->responded = 1;
    }
}
```

- [ ] **Step 3: Route `xrootd_ssi_write` through the session**

Replace the head of `xrootd_ssi_write` to resolve the session + per-reqId slot, and call the new `ssi_dispatch` signature:

```c
ngx_int_t
xrootd_ssi_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char off8[8])
{
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    size_t                n = ctx->cur_dlen;

    xrootd_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        xrootd_ssi_session_drop(sess, id);          /* request-phase cancel */
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    rq = xrootd_ssi_session_req(sess, id, 1);
    if (rq == NULL) {
        return xrootd_send_error(ctx, c, kXR_Overloaded,
                                 "too many concurrent SSI requests");
    }
    if (rq->dispatched) {
        return xrootd_send_error(ctx, c, kXR_FileLocked,
                                 "SSI request already dispatched");
    }
    if (!rq->have_size) {
        rq->req_expected = size;
        rq->have_size = 1;
    }
    /* ... keep the existing accumulate block (req buffer grow + memcpy) ... */

    if (rq->req_expected > 0 && rq->req_len >= rq->req_expected) {
        ssi_dispatch(rq, sess->provider.process);
    }
    return xrootd_send_ok(ctx, c, NULL, 0);
}
```

(Drop the old `rq->req_id = id;` assignment — the slot key is set by `session_req`. Keep the `XROOTD_SSI_REQ_MAX` cap and the `ctx->payload` copy exactly as today.)

- [ ] **Step 4: Route `xrootd_ssi_query` through the session**

```c
ngx_int_t
xrootd_ssi_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char *body, size_t body_len)
{
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    /* ... keep buf/total locals ... */

    if (body_len < XROOTD_SSI_RRINFO_LEN) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "short SSI control");
    }
    xrootd_ssi_rrinfo_decode(body, &cmd, &id, &size);

    if (cmd == XROOTD_SSI_CMD_CAN) {
        xrootd_ssi_session_drop(sess, id);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    rq = xrootd_ssi_session_req(sess, id, 0);
    if (rq == NULL || !rq->responded) {
        return xrootd_send_error(ctx, c, kXR_InvalidRequest,
                                 "no SSI response pending");
    }
    /* ... keep the existing error / streaming-PEND / full-reply blocks verbatim,
     *     operating on rq ... */
}
```

- [ ] **Step 5: Route `xrootd_ssi_read` through the session (reqId from the offset)**

The read offset field is the 8-byte big-endian `RRInfo`. Re-serialize the incoming `offset` to 8 BE bytes and decode the `reqId`; no change to `read.c` is needed.

```c
ngx_int_t
xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                uint64_t offset, uint32_t rlen)
{
    xrootd_ssi_session_t *sess = ctx->files[idx].ssi;
    xrootd_ssi_req_t     *rq;
    unsigned char         off8[8];
    int                   cmd;
    uint32_t              id, size;
    size_t                avail, n;

    off8[0] = (u_char)(offset >> 56); off8[1] = (u_char)(offset >> 48);
    off8[2] = (u_char)(offset >> 40); off8[3] = (u_char)(offset >> 32);
    off8[4] = (u_char)(offset >> 24); off8[5] = (u_char)(offset >> 16);
    off8[6] = (u_char)(offset >> 8);  off8[7] = (u_char)(offset);
    xrootd_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    rq = xrootd_ssi_session_req(sess, id, 0);
    if (rq == NULL) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* unknown reqId → nothing */
    }
    if (!rq->dispatched) {
        ssi_dispatch(rq, sess->provider.process); /* write-until-read dispatch */
    }
    if (!rq->responded || rq->error) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    if (rq->read_cursor >= rq->resp_len) {
        return xrootd_send_ok(ctx, c, NULL, 0);   /* EOF */
    }
    avail = rq->resp_len - rq->read_cursor;
    n = (rlen < avail) ? rlen : avail;
    {
        u_char *p = rq->resp + rq->read_cursor;
        rq->read_cursor += n;
        return xrootd_send_ok(ctx, c, p, n);
    }
}
```

> Note: the legacy "write-until-read" single-request fallback (`req_expected == 0` → dispatch on first read) is preserved here, but with no explicit `reqId` from the client the offset decodes `id`; the native test client (Task 4) always supplies a `reqId`, so this fallback only matters for the existing single-request callers and stays behavior-compatible.

- [ ] **Step 6: Build the module**

Run (clean reconfigure because Tasks 1–2 added source files):
```bash
cd /home/rcurrie/HEP-x/nginx-xrootd && \
rm -rf /tmp/nginx-1.28.3/objs && \
( cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module \
  --with-http_ssl_module --with-http_dav_module --with-threads \
  --add-module=/home/rcurrie/HEP-x/nginx-xrootd ) && \
make -j"$(nproc)" -C /tmp/nginx-1.28.3
```
Expected: build succeeds, exit 0. (Use the project's actual configure invocation if it differs — see CLAUDE.md BUILD & TEST.)

- [ ] **Step 7: Commit**

```bash
git add src/ssi/ssi.c
git commit -m "refactor(ssi): route open/write/query/read through session+RRTable

One open /.ssi/ handle now multiplexes concurrent requests keyed by reqId.
Provider resolves the service; per-reqId slot holds the request/response state.
Poll delivery path unchanged.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Wire integration test — multiplex + regression

Prove two concurrent `reqId`s on one handle resolve independently, and that the existing single-request behavior still passes. Model the raw-wire client on `tests/test_ssi_wire.py` (reuse its `_handshake_login`, `_read_response`, `_rrinfo`, opcode constants).

**Files:**
- Create: `tests/test_ssi_multiplex.py`
- Test: existing `tests/test_ssi_wire.py` and `tests/test_ssi.py` must still pass (regression).

**Interfaces:**
- Consumes: the running module's SSI engine on the SSI test port; `echo` service (returns the request bytes verbatim).
- Produces: no code symbols.

- [ ] **Step 1: Write the failing test**

Create `tests/test_ssi_multiplex.py`:

```python
"""
tests/test_ssi_multiplex.py — two concurrent reqIds on one /.ssi/ handle resolve
independently (Phase-1 session/RRTable multiplex).

Run:
    PYTHONPATH=tests pytest tests/test_ssi_multiplex.py -v
"""
import struct
import pytest

from test_ssi_wire import (
    _handshake_login, _read_response, _rrinfo,
    kXR_open, kXR_write, kXR_query, kXR_ok, kXR_Qopaqug,
    SSI_CMD_RXQ, SSI_CMD_RWT, SSI_PORT,
)
from settings import HOST


def _open_ssi(sock, service=b"/.ssi/echo"):
    # kXR_open with kXR_retstat; minimal options/mode per test_ssi_wire helper.
    # Reuse the same open framing test_ssi_wire uses (import if factored out there).
    from test_ssi_wire import _open as _wire_open      # if available
    return _wire_open(sock, service)


def _submit(sock, fh, req_id, payload):
    off = _rrinfo(SSI_CMD_RXQ, req_id, len(payload))
    # kXR_write: fhandle + offset(=RRInfo) + dlen + payload, per test_ssi_wire.
    from test_ssi_wire import _write as _wire_write
    _wire_write(sock, fh, off, payload)


def _wait(sock, fh, req_id):
    body = _rrinfo(SSI_CMD_RWT, req_id, 0)
    from test_ssi_wire import _query as _wire_query
    return _wire_query(sock, fh, body)


def test_two_concurrent_reqids_resolve_independently():
    sock = _handshake_login(HOST, SSI_PORT)
    fh = _open_ssi(sock)
    _submit(sock, fh, req_id=1, payload=b"alpha")
    _submit(sock, fh, req_id=2, payload=b"bravo")
    status1, body1 = _wait(sock, fh, req_id=1)
    status2, body2 = _wait(sock, fh, req_id=2)
    assert status1 == kXR_ok and b"alpha" in body1
    assert status2 == kXR_ok and b"bravo" in body2


def test_wait_unknown_reqid_errors():
    sock = _handshake_login(HOST, SSI_PORT)
    fh = _open_ssi(sock)
    status, _ = _wait(sock, fh, req_id=777)        # never submitted
    assert status != kXR_ok                         # kXR_InvalidRequest


def test_overflow_reqids_rejected():
    # XROOTD_SSI_MAX_INFLIGHT (8) concurrent submits succeed; the 9th is rejected.
    sock = _handshake_login(HOST, SSI_PORT)
    fh = _open_ssi(sock)
    for i in range(8):
        _submit(sock, fh, req_id=10 + i, payload=b"x")
    off = _rrinfo(SSI_CMD_RXQ, 99, 1)
    from test_ssi_wire import _write_raw_expect_status as _wire_write_status
    status = _wire_write_status(sock, fh, off, b"x")
    assert status != kXR_ok                         # kXR_Overloaded
```

> If `test_ssi_wire.py` does not already factor out `_open`/`_write`/`_query`/`_write_raw_expect_status` helpers, add them there as thin wrappers first (small, shared, DRY) and import them here. Do not duplicate the framing inline.

- [ ] **Step 2: Run test to verify it fails (or errors on missing helpers)**

Run: `tests/manage_test_servers.sh restart && PYTHONPATH=tests pytest tests/test_ssi_multiplex.py -v`
Expected: failures/errors until the module is built with Task 3 and the shared helpers exist.

- [ ] **Step 3: Factor shared helpers into `test_ssi_wire.py` if missing**

Add `_open`, `_write`, `_query`, and `_write_raw_expect_status` to `tests/test_ssi_wire.py` as small functions wrapping the framing the file already builds inline in its existing tests. (No behavior change to existing tests — just extraction.)

- [ ] **Step 4: Run the new test + regression**

Run:
```bash
PYTHONPATH=tests pytest tests/test_ssi_multiplex.py -v
PYTHONPATH=tests pytest tests/test_ssi_wire.py tests/test_ssi.py -v
```
Expected: all PASS. The two reqIds return their own payloads; unknown/overflow are rejected; existing single-request SSI tests are unchanged.

- [ ] **Step 5: Commit**

```bash
git add tests/test_ssi_multiplex.py tests/test_ssi_wire.py
git commit -m "test(ssi): wire multiplex (2 concurrent reqIds) + overflow/unknown-reqId

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Update `src/ssi/README.md`

Document that an SSI handle is now a session with an RRTable, the provider registry, and the `XROOTD_SSI_MAX_INFLIGHT` cap. Keep "async push / alerts / streaming" listed as the next phases (still non-goals in Phase 1).

**Files:**
- Modify: `src/ssi/README.md`

- [ ] **Step 1: Edit the README**

Update the Overview to state: one open `/.ssi/<service>` handle is an `xrootd_ssi_session_t` that multiplexes up to `XROOTD_SSI_MAX_INFLIGHT` concurrent requests keyed by `reqId`; service resolution goes through `provider.c`. Update the Files table to add `session.{c,h}` and `provider.{c,h}`. Keep the non-goals note but change "session multiplexing" from a non-goal to "Phase 1: implemented"; leave streaming/alerts/async-push as upcoming phases.

- [ ] **Step 2: Commit**

```bash
git add src/ssi/README.md
git commit -m "docs(ssi): document session/RRTable multiplex + provider registry

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (Phase 1 scope only):**
- Session object + RRTable → Task 2 ✓
- Multiplex (many reqIds per handle) → Task 2 (table) + Task 3 (routing) + Task 4 (wire proof) ✓
- Provider registry (no-plugin-ABI service resolution) → Task 1 ✓
- "Poll path only; no new wire features" → Task 3 preserves the existing `kXR_query` reply path; no `kXR_attn` push introduced ✓
- Caps/backpressure (`max_inflight`) → Task 2 (`XROOTD_SSI_MAX_INFLIGHT`) + Task 4 overflow test ✓
- Out of Phase 1 (deferred to later plans): async `kXR_attn` push, alerts delivery, true streaming, CTA protobuf/service, config directives, metrics. Explicitly not covered here by design.

**Placeholder scan:** No TBD/TODO/"add error handling" — every code step shows complete code; the one conditional (`if test_ssi_wire helpers missing`) is resolved by Task 4 Step 3 with concrete instructions.

**Type consistency:**
- `xrootd_ssi_provider_t { const char *name; xrootd_ssi_process_fn process; }` — defined Task 1, consumed by value in `xrootd_ssi_session_t` (Task 2) and `xrootd_ssi_provider_lookup(name, out)` (Task 1), called in `open` (Task 3) ✓
- `xrootd_ssi_session_req(s, req_id, create)` returns `xrootd_ssi_req_t *` — same signature in Task 2 header, Task 2 test, and all three Task 3 call sites ✓
- `ssi_dispatch(rq, process)` — new 2-arg form defined Task 3 Step 2, called in Task 3 Steps 3 and 5 ✓
- `xrootd_ssi_req_t` loses `service`/`handler`, gains `req_id`/`in_use` — amended once (Task 2 Step 1); `ssi.c` no longer references the removed fields after Task 3 ✓

---

## Execution Handoff

This is the **Phase 1** plan (of the 6 phases in the design spec). Phases 2–6 (async `kXR_attn` push, alerts/streaming, CTA protobuf codec, CTA queue/executor, config+metrics+conformance) each get their own plan written against the *real* interfaces Phase 1 lands.
