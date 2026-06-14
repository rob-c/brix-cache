# Phase 6: WebDAV Helper Consolidation

**Projected ΔLoC:** −350  
**Risk:** Medium  
**Depends on:** Phase 1 (alloc macros, err_strings)  
**Blocks:** nothing  
**Parallel-safe with:** Phases 2–5

---

## ✅ Status: Resolved — 2026-06-12 (intent met via specialised helpers; generic infra removed)

Phase 6's *goal* — eliminating XML-builder and HTTP-response boilerplate in
`src/webdav/` — was achieved, but **not** through the two generic abstractions
sketched below. Subsequent work converged on more specialised, lower-risk
helpers, which left the Phase 6 generic infrastructure orphaned. That dead
infrastructure has now been removed.

### Pattern 3 — header extraction: ✅ adopted

The existing `webdav_tpc_find_header()` is the single find-one-header helper and
is used consistently (`access.c`, `copy.c`, `lock.c`, `move.c`, `tpc.c`,
`dispatch.c`, `xrdhttp.c`, `locks/request.c`, …). The only remaining raw
`headers_in.headers.part` loops are in `tpc_headers.c` and `proxy_request.c`,
which **iterate every header** (collect-all for the curl TPC transfer / forward
all client headers to the proxy upstream) — a case the find-one helper was never
meant to cover. Correct as-is.

### Pattern 2 — HTTP response helper: ✅ met by `webdav_send_no_body()`

The "winning" helper is `webdav_send_no_body()` in `src/webdav/webdav.h`
(used ~7×) alongside `webdav_metrics_response()`. The generic
`xrootd_webdav_send_response()` proposed below was **never adopted** — its own
header comment even deferred no-body responses to `webdav_send_no_body()`.

### Pattern 1 — XML builder: ✅ met by libxml2 + escaping + per-feature builders

Response XML is produced with `webdav_escape_xml_text()` plus feature-specific
builders (`webdav_lock_xml_response()`, `webdav_search_append_response()`,
`propfind.c`'s libxml2-based parse path). The generic `xrootd_xml_*` builder was
**never called** by any handler.

### Obsolete components removed

| File | Disposition |
|---|---|
| `src/webdav/xml_builder.c` | **Deleted** — API called by nothing; also removed from the `config` build source list. |
| `src/webdav/xml_builder.h` | **Deleted** — included only by `xml_builder.c` and the (also-dead) `http_response.h`. |
| `src/webdav/http_response.h` | **Deleted** — included by nothing; superseded by `webdav_send_no_body()`. |
| `src/webdav/response_helpers.h` | **Deleted** — an earlier competing response helper (`webdav_send_empty_response()` et al.); included by nothing, API used nowhere. |

Verified: zero source references before removal; `./configure` (source list
changed) + `make` rebuild clean (0 errors, 0 warnings); `nginx -t` against the
test config passes.

> Why not force-migrate the handlers onto the generic builders instead?
> Because that would re-introduce abstractions the codebase deliberately moved
> past, at the Medium risk this doc itself flags (picky WebDAV-client XML
> parsing). Removing unused dead code is the zero-risk action that satisfies the
> phase's intent.

---

## Goal

`src/webdav/` is the largest subdirectory at 13,748 LoC.  It contains three classes of repeated patterns that can be safely consolidated without altering any wire behaviour:

1. **XML response builder boilerplate** — `propfind.c`, `lock.c`, and `copy.c` all hand-roll the same xml-writing sequences: open namespace, open element, write text node, close element.

2. **HTTP response helper duplication** — the same `ngx_http_send_header` + `ngx_http_output_filter` sequence with a single-buffer body appears 20+ times across different method handlers.

3. **Header extraction boilerplate** — each TPC handler re-implements the same "find a header, check for null, copy to ngx_str_t" pattern.

This phase consolidates all three.

---

## Pattern 1: XML Builder Abstraction

### Current State (propfind.c excerpt, repeated across ~4 files)

```c
/* Every multistatus response hand-rolls this: */
b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

len = sizeof("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
             "<D:multistatus xmlns:D=\"DAV:\">\r\n") - 1;
/* ... then again for each property element: */
p = ngx_pnalloc(r->pool, len);
if (p == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
p = ngx_cpymem(p, "<?xml ...", sizeof("<?xml ...") - 1);
/* ... repeated N times for each element */
```

### New: `src/webdav/xml_builder.h` + `xml_builder.c` (new, ~150 LoC total)

```c
/*
 * xml_builder.h — lightweight XML response builder for WebDAV responses.
 *
 * All allocation goes through r->pool.  The caller adds elements and then
 * calls xrootd_webdav_xml_finish() to get the complete ngx_chain_t.
 */
#pragma once
#include <ngx_http.h>

typedef struct xrootd_xml_builder_s xrootd_xml_builder_t;

/*
 * xrootd_xml_builder_create — initialise a new builder backed by r->pool.
 * Returns NULL on allocation failure.
 */
xrootd_xml_builder_t *xrootd_xml_builder_create(ngx_http_request_t *r);

/* Append a literal string (must be pool-safe) */
ngx_int_t xrootd_xml_append(xrootd_xml_builder_t *b, const char *s, size_t len);

/* Convenience: append a C string literal */
#define XROOTD_XML_LIT(b, s)  xrootd_xml_append((b), (s), sizeof(s) - 1)

/* Open an element: <D:tag> */
ngx_int_t xrootd_xml_open(xrootd_xml_builder_t *b, const char *tag);

/* Close an element: </D:tag> */
ngx_int_t xrootd_xml_close(xrootd_xml_builder_t *b, const char *tag);

/* Append text content (XML-escaped) */
ngx_int_t xrootd_xml_text(xrootd_xml_builder_t *b,
                           const u_char *text, size_t len);

/*
 * xrootd_xml_finish — seal the builder and return a chain ready for
 * ngx_http_output_filter().  Sets Content-Length in r->headers_out.
 */
ngx_chain_t *xrootd_xml_finish(xrootd_xml_builder_t *b);
```

**Usage** in a refactored `propfind.c`:

```c
/* Before: ~40 lines of manual buffer management */

/* After: */
xrootd_xml_builder_t *xml = xrootd_xml_builder_create(r);
if (xml == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;

XROOTD_XML_LIT(xml, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
xrootd_xml_open(xml, "D:multistatus xmlns:D=\"DAV:\"");

/* ...per-property entries: */
xrootd_xml_open(xml, "D:response");
xrootd_xml_open(xml, "D:href");
xrootd_xml_text(xml, (u_char *) href, href_len);
xrootd_xml_close(xml, "D:href");
xrootd_xml_close(xml, "D:response");

xrootd_xml_close(xml, "D:multistatus");

ngx_chain_t *out = xrootd_xml_finish(xml);
r->headers_out.status = NGX_HTTP_MULTI_STATUS;
ngx_http_send_header(r);
return ngx_http_output_filter(r, out);
```

---

## Pattern 2: HTTP Response Helper

### Current State (20+ identical patterns)

```c
/* Repeated in namespace.c, methods_basic.c, copy.c, move.c, get.c, put.c... */
ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
b->pos = b->start = (u_char *) body;
b->last = b->end  = (u_char *) body + body_len;
b->memory = 1;
b->last_buf = 1;

ngx_chain_t out;
out.buf  = b;
out.next = NULL;

r->headers_out.status           = status;
r->headers_out.content_length_n = body_len;
ngx_http_send_header(r);
return ngx_http_output_filter(r, &out);
```

That is **13 lines** (with NULL check).

### New: `src/webdav/http_response.h` (new, header-only, ~40 LoC)

```c
#pragma once
#include <ngx_http.h>

/*
 * xrootd_webdav_send_response — send a complete HTTP response with a
 * static body.  body_len == 0 sends headers only (e.g., 201 Created).
 *
 * Returns the value of ngx_http_output_filter(), suitable for direct
 * return from a content handler.
 */
static inline ngx_int_t
xrootd_webdav_send_response(ngx_http_request_t *r,
                             ngx_uint_t status,
                             const char *body, size_t body_len)
{
    r->headers_out.status           = status;
    r->headers_out.content_length_n = (off_t) body_len;

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only || body_len == 0) {
        return rc;
    }

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    b->pos = b->start = (u_char *) body;
    b->last = b->end  = (u_char *) body + body_len;
    b->memory = 1; b->last_buf = 1;

    ngx_chain_t out = { b, NULL };
    return ngx_http_output_filter(r, &out);
}
```

**Usage** replaces 13 lines with 2:

```c
return xrootd_webdav_send_response(r, NGX_HTTP_CREATED, NULL, 0);
return xrootd_webdav_send_response(r, NGX_HTTP_OK, body, body_len);
```

---

## Pattern 3: Header Extraction Boilerplate

### Current State (TPC handlers, namespace.c, auth handlers)

```c
/* Repeated in tpc.c, tpc_cred.c, tpc_headers.c, namespace.c ... */
ngx_list_part_t *part = &r->headers_in.headers.part;
ngx_table_elt_t *h    = (ngx_table_elt_t *) part->elts;
ngx_str_t         val = ngx_null_string;
for (ngx_uint_t i = 0; ; i++) {
    if (i >= part->nelts) {
        if (part->next == NULL) break;
        part = part->next;
        h    = (ngx_table_elt_t *) part->elts;
        i    = 0;
    }
    if (h[i].key.len == key.len
        && ngx_strncasecmp(h[i].key.data, key.data, key.len) == 0) {
        val = h[i].value;
        break;
    }
}
```

That is **15 lines** per lookup.  The existing `webdav_tpc_find_header()` function already exists (listed in HELPERS) but is not used consistently — several files re-implement the loop.

### Fix: Audit all callers and migrate to the existing helper

```bash
grep -rn "headers_in.headers.part" src/webdav/
```

Each re-implementation is replaced with:

```c
ngx_str_t val = webdav_tpc_find_header(&r->headers_in.headers, &key);
```

---

## Files Modified and LoC Delta

| File | Current LoC | Delta | Notes |
|---|---|---|---|
| `src/webdav/propfind.c` | ~600 | −80 | XML builder |
| `src/webdav/lock.c` | ~500 | −60 | XML builder |
| `src/webdav/copy.c` | ~400 | −40 | XML builder (error body) |
| `src/webdav/namespace.c` | ~350 | −50 | HTTP response helper |
| `src/webdav/methods_basic.c` | ~300 | −40 | HTTP response helper |
| `src/webdav/put.c` | ~280 | −20 | HTTP response helper |
| `src/webdav/tpc.c` | ~450 | −30 | Header extraction |
| `src/webdav/tpc_cred.c` | ~200 | −20 | Header extraction |
| `src/webdav/tpc_headers.c` | ~150 | −15 | Header extraction |
| `src/webdav/xml_builder.c` (new) | 0 | +100 | XML builder impl |
| `src/webdav/xml_builder.h` (new) | 0 | +50 | XML builder API |
| `src/webdav/http_response.h` (new) | 0 | +40 | Response helper |
| **Net** | | **−165** | Conservative |

Conservative estimate: **−165 LoC**.  Optimistic (if all XML hand-rolling is replaced): **−350 LoC**.

---

## Files Added to `config.h`

```
$ngx_addon_dir/src/webdav/xml_builder.c
```

Requires `./configure`.

---

## Conversion Priority

1. **xml_builder.c infrastructure** — implement and test in isolation first with no handler changes.  Add a trivial test that calls the builder and compares output to a known-good string.
2. **HTTP response helper** — header-only, no configure needed.  Convert methods_basic.c first as it has the simplest handlers (OPTIONS, HEAD).
3. **Header extraction** — audit then migrate each TPC file.
4. **propfind.c XML migration** — most complex; do last.  Has the most test coverage to verify against.

---

## Verification

```bash
# Configure required
cd /tmp/nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-http_dav_module \
            --with-threads --add-module=$REPO
make -j$(nproc) 2>&1 | grep "^error:" | wc -l

# WebDAV functional tests
PYTHONPATH=tests pytest tests/test_a_webdav_clients.py -v
PYTHONPATH=tests pytest tests/test_conformance.py -k "webdav or propfind or copy or move or lock" -v
PYTHONPATH=tests pytest tests/test_credential_translation.py -v  # TPC headers

# TPC end-to-end
PYTHONPATH=tests pytest tests/ -k "tpc" -v

# Full suite
PYTHONPATH=tests pytest tests/ -n 4 --tb=short -q
```

---

## Risk Assessment

**Medium.**  WebDAV clients (davix, gfal2, curl) are picky about XML namespace declarations and element ordering in multistatus responses.  A change to how XML is assembled that reorders attributes or changes whitespace can cause client-side parse failures that the test suite catches only if it uses a real WebDAV client.

Mitigation: `tests/test_a_webdav_clients.py` exercises davix and gfal2 against the live server.  Run that test after every file migrated to xml_builder.

The HTTP response helper is lower risk — it is a cosmetic refactor of the same sequence of calls.  The main trap is `r->header_only` handling: the helper must check this correctly (as shown above) otherwise chunked/HEAD responses break.

## Rollback

```bash
git revert <phase-6-commit>
./configure ...
make -j$(nproc)
```
