/*
 * lock.c - WebDAV LOCK and UNLOCK handler (RFC 4918 §9.10, §9.11).
 *
 * WHAT: Implements WebDAV locking mechanism for optimistic concurrency control — prevents concurrent
 *       modifications to locked resources. Supports exclusive and shared write locks with configurable
 *       depth (single resource or recursive infinity), automatic expiration, and inter-worker coordination
 *       via shared memory mutex. Provides LOCK creation/refresh, UNLOCK deletion, PROPFIND discovery/supportedlock
 *       XML generation, and pre-operation lock checking for DEL/MOVE/COPY on collections.
 *
 * WHY: WebDAV clients require locking to prevent conflicting modifications during file editing workflows.
 *      Without locks, concurrent DELETE/MOVE/COPY operations can produce data loss — INVARIANT #5 requires
 *      recursive child lock checking on collection operations (DEL/MOVE/COPY on directories must check all
 *      locked descendants). Shared memory architecture enables cross-worker coordination in nginx multiprocess
 *      deployment without requiring distributed locking infrastructure.
 *
 * HOW: Lock table stored in shared memory zone (`conf->lock_shm_zone`) with `ngx_shmtx_t` mutex for inter-process
 *      serialization. UUID generation uses OpenSSL RAND_bytes (Version 4 format) for unique `opaquelocktoken:` values.
 *      Lock entries track path, token, owner DN/identity, exclusive/shared scope, depth (0 or infinity), and expiration
 *      timestamp (milliseconds). RFC 4918 §7.5 conflict rules: exclusive locks block all existing locks; shared locks only
 *      block other exclusive locks (multiple shared permits concurrent read access). Check function implements two matching
 *      strategies: exact path match + parent-path recursive child lock detection.
 */

#include "webdav.h"
#include "locks/request.h"
#include "../compat/http_xml.h"
#include "../compat/shm_slots.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* RFC 4918 §11.1: 423 Locked */
#ifndef NGX_HTTP_LOCKED
#define NGX_HTTP_LOCKED 423
#endif

static ngx_shmtx_t  webdav_lock_mutex;

/*
 * WHAT: Generate Version 4 UUID for WebDAV lock token (`opaquelocktoken:` prefix).
 *
 * WHY: RFC 4918 §9.10 requires opaque lock tokens uniquely identifying each active lock.
 *      Version 4 UUID provides collision-resistant identifiers generated from cryptographic random bytes.
 *      The `opaquelocktoken:` URI scheme is mandatory per WebDAV specification — clients cannot interpret token contents.
 *
 * HOW: OpenSSL RAND_bytes generates 16 random bytes, then applies Version 4 format constraints:
 *      bits 12-15 set to `0x4` (version), bits 64-65 set to `0x8` (variant). sprintf formats into
 *      canonical hex string with hyphen separators matching RFC 4122 §4.4 layout.
 */
static void
webdav_generate_uuid(char *buf, size_t bufsz)
{
    u_char bytes[16];
    (void) RAND_bytes(bytes, 16);
    /* Version 4 UUID: bits 12-15 are 0100 */
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    /* Variant: bits 64-65 are 10 */
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    snprintf(buf, bufsz,
             "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

ngx_int_t
webdav_lock_init_shm(ngx_shm_zone_t *shm_zone, void *data)
{
    /*
     * WHAT: Initialize WebDAV lock table shared memory zone — allocate lock slots array and create inter-process mutex.
     *
     * WHY: nginx multi-worker deployment requires shared memory for cross-process coordination. Lock table stored in
     *      shm_zone enables all workers to read/write the same lock state without distributed locking infrastructure.
     *      The `ngx_shmtx_t` mutex serializes concurrent access across worker processes — prevents race conditions during
     *      LOCK creation/refresh, UNLOCK deletion, and pre-operation lock checking (INVARIANT #5).
     *
     * HOW: Called twice by nginx lifecycle: first invocation with `data=NULL` creates fresh table from shm.addr with zero-fill,
     *      mutex via `ngx_shmtx_create()`; second invocation with `data=tbl` (already-initialized pointer) registers shm_zone->data
     *      and re-creates the mutex for worker processes. The two-slot pattern ensures all workers share identical lock state.
     */
    webdav_lock_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (webdav_lock_table_t *) data;
        if (ngx_shmtx_create(&webdav_lock_mutex, &tbl->lock,
                             shm_zone->shm.name.data) != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (webdav_lock_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&webdav_lock_mutex, &tbl->lock,
                         shm_zone->shm.name.data) != NGX_OK)
    {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

ngx_int_t
webdav_check_locks(ngx_http_request_t *r, const char *path, int need_write)
{
    /*
     * WHAT: Check whether the target resource is locked by another client — returns NGX_HTTP_LOCKED(423) if any active lock
     *       blocks this operation. Implements two matching strategies for INVARIANT #5 compliance: exact path match + recursive
     *      child lock detection (DEL/MOVE/COPY on collections must check all locked descendants).
     *
     * WHY: Critical security function preventing concurrent modification conflicts. Without checks, DELETE/MOVE/COPY operations
     *      on directories can silently overwrite locked children — INVARIANT #5 mandates recursive checking for collection ops.
     *      Also protects individual resources from unauthorized modifications when locks are active. The `need_write` parameter
     *      signals intent (though current implementation applies to all operations equally; future optimization may narrow scope).
     *
     * HOW: Acquire shared memory mutex, iterate WEBDAV_LOCK_TABLE_SIZE slots filtering expired entries (`expires <= ngx_current_msec`),
     *      then apply two matching strategies: Case 1 — target resource matches locked path (exact equality OR depth_infinity parent-child);
     *      Case 2 — target directory contains locked child path (lock_len > path_len prefix match with slash boundary). Both cases require
     *      `webdav_lock_if_header_matches()` token verification before returning NGX_HTTP_LOCKED(423). Automatic expiration cleanup prevents
     *      stale lock entries from blocking operations indefinitely.
     */
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    ngx_uint_t                         i;
    size_t                             path_len;
    ngx_int_t                          rc = NGX_OK;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_OK;
    }

    tbl = conf->lock_shm_zone->data;
    path_len = strlen(path);

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        webdav_lock_entry_t *e = &tbl->slots[i];

        if (!e->in_use) {
            continue;
        }

        if (xrootd_shm_slot_expired(ngx_current_msec, e->expires)) {
            e->in_use = 0;
            continue;
        }

        size_t lock_len = strlen(e->path);

        /* Case 1: The resource we are checking is under a locked path.
         * Match exact path or parent path (for deep locks). */
        if (path_len >= lock_len && ngx_strncmp(path, e->path, lock_len) == 0) {
            if (lock_len == path_len) {
                if (!webdav_lock_if_header_matches(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            } else if (e->depth_infinity && (e->path[lock_len - 1] == '/'
                       || path[lock_len] == '/'))
            {
                if (!webdav_lock_if_header_matches(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            }
        }

        /* Case 2: The resource we are checking is a directory that contains 
         * a locked path (recursive check).  This is required for DELETE, 
         * MOVE, and COPY (when overwriting). */
        if (lock_len > path_len && ngx_strncmp(e->path, path, path_len) == 0) {
            if (path[path_len - 1] == '/' || e->path[path_len] == '/') {
                if (!webdav_lock_if_header_matches(r, e->token)) {
                    rc = NGX_HTTP_LOCKED;
                    break;
                }
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    return rc;
}

/*
 * WHAT: Generate XML response body and headers for LOCK/UNLOCK operations — active lock discovery with timeout calculation.
 *
 * WHY: RFC 4918 §9.10 requires LOCK responses to include full `activelock` XML structure in `lockdiscovery` element. The response
 *      must report locktype (write only), scope (exclusive/shared), depth, owner identity, remaining timeout duration, and the opaque
 *      locktoken URI. Content-Type is application/xml per WebDAV specification; Lock-Token header wraps token in `<opaquelocktoken:...>` format.
 *
 * HOW: Calculate remaining seconds from `expires - ngx_current_msec` for `Second-X` timeout format (RFC 4918 §9.10.3). Build XML chain
 *      via `xrootd_http_chain_appendf()` with template string including scope/depth/owner variables interpolated into `%s` placeholders.
 *      Accumulate total length from all chain buffers for Content-Length header. Push two headers: Content-Type (application/xml) and Lock-Token
 *      (`<opaquelocktoken:...>` format wrapping the raw token). Send via `ngx_http_send_header()` + `ngx_http_output_filter()`.
 */
static void
webdav_lock_xml_response(ngx_http_request_t *r, webdav_lock_entry_t *e)
{
    ngx_chain_t     *head = NULL, *tail = NULL;
    char             timeout_buf[32];
    char            *safe_owner;
    ngx_msec_t       now = ngx_current_msec;
    ngx_uint_t       remaining;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;

    remaining = (e->expires > now) ? (ngx_uint_t) ((e->expires - now) / 1000) : 0;
    ngx_sprintf((u_char *) timeout_buf, "Second-%ui", remaining);

    /* GSI DNs can contain '<' / '>' — escape before embedding in XML. */
    safe_owner = webdav_escape_xml_text(r->pool, e->owner);
    if (safe_owner == NULL) {
        safe_owner = "anonymous";
    }

    xrootd_http_chain_appendf(r->pool, &head, &tail,
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:prop xmlns:D=\"DAV:\">"
        "<D:lockdiscovery>"
        "<D:activelock>"
        "<D:locktype><D:write/></D:locktype>"
        "<D:lockscope>%s</D:lockscope>"
        "<D:depth>%s</D:depth>"
        "<D:owner>%s</D:owner>"
        "<D:timeout>%s</D:timeout>"
        "<D:locktoken><D:href>opaquelocktoken:%s</D:href></D:locktoken>"
        "</D:activelock>"
        "</D:lockdiscovery>"
        "</D:prop>",
        e->exclusive ? "<D:exclusive/>" : "<D:shared/>",
        e->depth_infinity ? "infinity" : "0",
        safe_owner, timeout_buf, e->token);

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Type");
        ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h != NULL) {
        h->hash = 1;
        ngx_str_set(&h->key, "Lock-Token");
        h->value.len = strlen(e->token) + 2;
        h->value.data = ngx_pnalloc(r->pool, h->value.len);
        if (h->value.data != NULL) {
            ngx_sprintf(h->value.data, "<%s>", e->token);
        }
    }

    ngx_http_send_header(r);
    ngx_http_output_filter(r, head);
}

void
webdav_handle_lock(ngx_http_request_t *r)
{
    /*
     * WHAT: Handle WebDAV LOCK request — create new lock or refresh existing one per RFC 4918 §9.10. Returns NGX_HTTP_OK for successful
     *      refresh, NGX_HTTP_CREATED(201) for new lock creation, NGX_HTTP_LOCKED(423) for conflict rejection, NGX_HTTP_INSUFFICIENT_STORAGE(507)
     *      when lock table is full. Implements RFC 4918 §9.10.1: automatic zero-byte resource creation on LOCK targeting non-existent path.
     *
     * WHY: WebDAV clients require explicit locking to prevent concurrent modifications during file editing workflows. The handler supports two
     *      modes: refresh (renewing existing lock when client holds matching token) and create (allocating new slot for fresh lock). RFC 4918 §7.5
     *      conflict rules govern acceptance: exclusive locks reject all existing locks; shared locks only reject other exclusive locks (multiple
     *      shared permits concurrent read access). Lock expiration tracking prevents indefinite blocking — entries with `expires <= ngx_current_msec`
     *      are automatically cleared and reused as free slots.
     *
     * HOW: Parse path via resolve_path, depth via parse_depth, body XML for owner + exclusive flag. Pre-check existence: if ENOENT, create zero-byte
     *      resource with O_CREAT|O_EXCL to prevent race condition (EEXIST fallback). Acquire shm mutex, scan table for existing lock match or conflicts
     *      using RFC 4918 §7.5 rules, track free slot candidates during scan. Refresh updates expires timestamp only; create allocates new entry with
     *      UUID token, owner DN from GSI ctx (or body XML value or "anonymous" fallback), exclusive flag, depth_infinity, and parsed timeout expiration.
     *      Release mutex before generating XML response to avoid deadlock. Local copy `res = *e` prevents shm lock contention during response generation.
     */
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_uint_t                         i, free_slot = WEBDAV_LOCK_TABLE_SIZE;
    webdav_lock_entry_t               *e = NULL;
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    int                                depth_infinity = 1;
    char                               owner[WEBDAV_LOCK_OWNER_LEN];
    int                                exclusive = 1;  /* default to exclusive per RFC 4918 §9.10 */

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    tbl = conf->lock_shm_zone->data;

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    rc = webdav_lock_parse_depth(r, &depth_infinity);
    if (rc != NGX_OK) {
        webdav_metrics_finalize_request(r, rc);
        return;
    }

    webdav_lock_parse_body(r, owner, sizeof(owner), &exclusive);

    /* RFC 4918 §9.10.1: LOCK on non-existent resource MUST create zero-byte resource */
    {
        struct stat sb;
        if (stat(path, &sb) != 0) {
            if (errno == ENOENT) {
                int fd = xrootd_open_confined_canon(r->connection->log,
                                                    conf->common.root_canon, path,
                                                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                                                    0644);
                if (fd < 0) {
                    if (errno != EEXIST) {
                        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                } else {
                    (void) close(fd);
                }
            }
        }
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    ngx_shmtx_lock(&webdav_lock_mutex);

    /* Look for existing lock to refresh or conflicts */
    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        if (!tbl->slots[i].in_use) {
            xrootd_shm_remember_free_slot(&free_slot, WEBDAV_LOCK_TABLE_SIZE,
                                          i);
            continue;
        }

        if (xrootd_shm_slot_expired(ngx_current_msec, tbl->slots[i].expires)) {
            tbl->slots[i].in_use = 0;
            xrootd_shm_remember_free_slot(&free_slot, WEBDAV_LOCK_TABLE_SIZE,
                                          i);
            continue;
        }

        if (strcmp(tbl->slots[i].path, path) == 0) {
            if (webdav_lock_if_header_matches(r, tbl->slots[i].token)) {
                e = &tbl->slots[i];
                break;
            }
            /*
             * RFC 4918 §7.5 conflict rules:
             *   - An exclusive lock request conflicts with ANY existing lock.
             *   - A shared lock request conflicts only with an exclusive lock.
             * (Multiple shared locks on the same path are permitted.)
             */
            if (exclusive || tbl->slots[i].exclusive) {
                ngx_shmtx_unlock(&webdav_lock_mutex);
                webdav_metrics_finalize_request(r, NGX_HTTP_LOCKED);
                return;
            }
        }
    }

    if (e != NULL) {
        /* Refresh existing lock */
        e->expires = webdav_lock_parse_timeout(r, conf);
        r->headers_out.status = NGX_HTTP_OK;
    } else {
        /* Create new lock */
        if (free_slot == WEBDAV_LOCK_TABLE_SIZE) {
            ngx_shmtx_unlock(&webdav_lock_mutex);
            webdav_metrics_finalize_request(r, NGX_HTTP_INSUFFICIENT_STORAGE);
            return;
        }

        e = &tbl->slots[free_slot];
        ngx_memzero(e, sizeof(*e));
        ngx_cpystrn((u_char *) e->path, (u_char *) path, sizeof(e->path));
        webdav_generate_uuid(e->token, sizeof(e->token));
        
        if (owner[0] != '\0') {
            ngx_cpystrn((u_char *) e->owner, (u_char *) owner, sizeof(e->owner));
        } else if (ctx != NULL && ctx->dn[0] != '\0') {
            ngx_cpystrn((u_char *) e->owner, (u_char *) ctx->dn, sizeof(e->owner));
        } else {
            ngx_cpystrn((u_char *) e->owner, (u_char *) "anonymous", sizeof(e->owner));
        }
        
        e->exclusive = exclusive;
        e->depth_infinity = depth_infinity;
        e->expires = webdav_lock_parse_timeout(r, conf);
        e->in_use = 1;

        r->headers_out.status = NGX_HTTP_CREATED;
    }

    /* We need a local copy for the response after releasing the shm lock */
    webdav_lock_entry_t res = *e;

    ngx_shmtx_unlock(&webdav_lock_mutex);

    webdav_lock_xml_response(r, &res);
}

ngx_int_t
webdav_handle_unlock(ngx_http_request_t *r)
{
    /*
     * WHAT: Handle WebDAV UNLOCK request — release an active lock by matching Lock-Token header against the target resource path. Returns
     *      NGX_HTTP_NO_CONTENT(204) for successful unlock, NGX_HTTP_BAD_REQUEST(400) when Lock-Token missing, NGX_HTTP_CONFLICT(409) when
     *      no matching lock found or token mismatch. Implements RFC 4918 §9.11: UNLOCK must reference the exact Lock-Token issued by LOCK.
     *
     * WHY: UNLOCK is required to prevent indefinite resource blocking — locks expire but clients may also explicitly release via UNLOCK before
     *      expiration timeout. The header `Lock-Token` contains `<opaquelocktoken:...>` format wrapping the opaque token; matching uses substring
     *      search (`ngx_strstr`) to handle both raw and wrapped formats without requiring exact prefix stripping. Token mismatch returns 409 Conflict
     *      per RFC 4918 §9.11: UNLOCK against wrong token must fail, not silently unlock unrelated locks (security invariant).
     *
     * HOW: Acquire shm mutex, scan WEBDAV_LOCK_TABLE_SIZE slots filtering `in_use` entries only, then exact path match + substring token comparison
     *      (`ngx_strstr(h->value.data, tbl->slots[i].token)` handles `<token>` wrapper format). On match: set `in_use = 0`, release mutex, send 204 No Content.
     *      No match after full scan returns 409 Conflict — prevents unauthorized unlock of other clients' locks (security invariant per AGENTS.md).
     */
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    char                               path[WEBDAV_MAX_PATH];
    ngx_int_t                          rc;
    ngx_uint_t                         i;
    ngx_table_elt_t                   *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    tbl = conf->lock_shm_zone->data;

    h = webdav_tpc_find_header(r, "Lock-Token", sizeof("Lock-Token") - 1);
    if (h == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->common.root_canon,
                                              path, sizeof(path));
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        if (!tbl->slots[i].in_use) continue;

        if (strcmp(tbl->slots[i].path, path) == 0) {
            /* Constant-time token comparison.  RFC 4918 Lock-Token headers arrive
             * as either the raw token or wrapped in angle brackets: <token>.
             * Strip the brackets before comparing to prevent timing oracle on
             * the 51-byte opaquelocktoken: UUID value. */
            const u_char *lock_val = h->value.data;
            size_t        lock_len = (size_t) h->value.len;
            size_t        token_len;

            if (lock_len > 0 && lock_val[0] == '<') {
                lock_val++;
                lock_len--;
                if (lock_len > 0 && lock_val[lock_len - 1] == '>') {
                    lock_len--;
                }
            }

            token_len = strlen(tbl->slots[i].token);
            if (lock_len == token_len
                && CRYPTO_memcmp(lock_val, (u_char *) tbl->slots[i].token,
                                 token_len) == 0) {
                tbl->slots[i].in_use = 0;
                ngx_shmtx_unlock(&webdav_lock_mutex);

                r->headers_out.status = NGX_HTTP_NO_CONTENT;
                r->headers_out.content_length_n = 0;
                ngx_http_send_header(r);
                return ngx_http_send_special(r, NGX_HTTP_LAST);
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    return NGX_HTTP_CONFLICT; /* Lock not found or token mismatch */
}

/*
 * WHAT: Append `supportedlock` XML element to PROPFIND response — advertises supported lock types for this WebDAV resource. Reports exclusive
 *      and shared write locks as per RFC 4918 §9.10 client discovery requirements.
 *
 * WHY: PROPFIND clients need to discover what lock types the server supports before attempting LOCK requests. RFC 4918 §9.10 requires servers
 *      to advertise supportedlock capabilities in PROPFIND responses so clients can select appropriate lock scope (exclusive for single-writer,
 *      shared for multi-reader). This implementation reports write-only locks with both exclusive and shared scopes — the standard WebDAV pattern.
 *
 * HOW: Build XML string via `xrootd_http_chain_appendf()` appending two `<D:lockentry>` blocks within `<D:supportedlock>` container. Each entry declares
 *      one scope (exclusive/shared) paired with write locktype per RFC 4918 §9.10 specification. Returns NGX_ERROR on append failure, NGX_OK otherwise.
 */
ngx_int_t
webdav_lock_append_supported(ngx_http_request_t *r,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    if (xrootd_http_chain_appendf(r->pool, head, tail,
            "<D:supportedlock>"
            "<D:lockentry>"
            "<D:lockscope><D:exclusive/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "<D:lockentry>"
            "<D:lockscope><D:shared/></D:lockscope>"
            "<D:locktype><D:write/></D:locktype>"
            "</D:lockentry>"
            "</D:supportedlock>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Append `lockdiscovery` XML element to PROPFIND response — reports active locks on the specified resource path. Provides lock type, scope, depth, owner identity, remaining timeout, and opaque locktoken URI for each active lock entry.
 *
 * WHY: RFC 4918 §9.10 requires PROPFIND responses to include lockdiscovery information so clients can discover what locks exist on a resource before attempting operations that would conflict with existing locks. This enables pre-operation planning — clients know whether they need to acquire their own lock or wait for existing locks to expire/UNLOCK before proceeding with DEL/MOVE/COPY operations.
 *
 * HOW: Open `<D:lockdiscovery>` container via xrootd_http_chain_appendf, then scan WEBDAV_LOCK_TABLE_SIZE slots under shm mutex filtering `in_use` + expiration (`expires <= now`). For matching path entries (exact strcmp), generate `<D:activelock>` XML with scope/depth/owner/timeout/token variables interpolated. Calculate remaining seconds as `(expires - now) / 1000`. Owner fallback to "anonymous" when empty. Close `</D:lockdiscovery>` container after scan completes. Returns NGX_ERROR on append failure or mutex lock contention.
 */
ngx_int_t
webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
                             ngx_chain_t **head, ngx_chain_t **tail)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    webdav_lock_table_t              *tbl;
    ngx_uint_t                         i;
    ngx_msec_t                         now = ngx_current_msec;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (conf->lock_shm_zone == NULL) {
        return NGX_OK;
    }
    tbl = conf->lock_shm_zone->data;

    if (xrootd_http_chain_appendf(r->pool, head, tail, "<D:lockdiscovery>") == NULL) {
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&webdav_lock_mutex);

    for (i = 0; i < WEBDAV_LOCK_TABLE_SIZE; i++) {
        webdav_lock_entry_t *entry = &tbl->slots[i];

        if (!entry->in_use || xrootd_shm_slot_expired(now, entry->expires)) {
            continue;
        }

        if (strcmp(entry->path, path) == 0) {
            char       *safe_disc_owner;
            ngx_uint_t  remaining;

            remaining = (ngx_uint_t) ((entry->expires - now) / 1000);

            safe_disc_owner = webdav_escape_xml_text(r->pool,
                (entry->owner[0] != '\0') ? entry->owner : "anonymous");
            if (safe_disc_owner == NULL) {
                safe_disc_owner = "anonymous";
            }

            if (xrootd_http_chain_appendf(r->pool, head, tail,
                    "<D:activelock>"
                    "<D:locktype><D:write/></D:locktype>"
                    "<D:lockscope>%s</D:lockscope>"
                    "<D:depth>%s</D:depth>"
                    "<D:owner>%s</D:owner>"
                    "<D:timeout>Second-%ui</D:timeout>"
                    "<D:locktoken><D:href>opaquelocktoken:%s</D:href></D:locktoken>"
                    "</D:activelock>",
                    entry->exclusive ? "<D:exclusive/>" : "<D:shared/>",
                    entry->depth_infinity ? "infinity" : "0",
                    safe_disc_owner,
                    remaining,
                    entry->token) == NULL)
            {
                ngx_shmtx_unlock(&webdav_lock_mutex);
                return NGX_ERROR;
            }
        }
    }

    ngx_shmtx_unlock(&webdav_lock_mutex);

    if (xrootd_http_chain_appendf(r->pool, head, tail, "</D:lockdiscovery>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
