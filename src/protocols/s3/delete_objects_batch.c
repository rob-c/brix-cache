/*
 * delete_objects_batch.c - the S3 DeleteObjects two-phase batch stages
 * (phase-107 C4): collect every key, dispose them in ONE
 * brix_vfs_delete_many() call, render per-key results in client order.
 *
 * WHAT: s3_delete_collect_one() extracts, validates and CONFINES one <Object>
 *       key (s3_resolve_key_ex before any delete - security-load-bearing);
 *       s3_delete_execute() hands the confinable subset to the VFS batch
 *       entry; s3_delete_render() turns per-key verdicts into
 *       <Deleted>/<Error> elements.
 * WHY:  The old handler called brix_vfs_unlink once per key: 1,000 policy
 *       checks, 1,000 metric lines and - over a remote backend - 1,000 signed
 *       round trips for one request whose purpose was to avoid exactly that.
 *       Collect-then-execute also means a malformed <Object> is now rejected
 *       BEFORE anything is deleted, where the old parse-and-delete loop had
 *       already removed the keys ahead of it.
 * HOW:  Per-key error vocabulary is unchanged (AccessDenied, BucketNotEmpty,
 *       InternalError; ENOENT renders as <Deleted> per S3 idempotency; a
 *       RESERVED key reads exactly as an absent one). EROFS fails the WHOLE
 *       request 403 before any key is examined - a read-only export discloses
 *       nothing about which keys exist. ECANCELED (pre-filled by the VFS)
 *       marks a key the batch never reached; it renders as an <Error>, never
 *       as <Deleted>.
 */

#include "s3.h"
#include "core/http/http_headers.h"   /* brix_http_request_is_tls */
#include "fs/vfs/vfs.h"                 /* brix_vfs_delete_many */

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <errno.h>
#include <string.h>
#include <limits.h>

#include "delete_objects_internal.h"

/*
 * s3_delete_collect_one - phase 1 for one <Object> node: extract and
 * length-validate its <Key>, copy the key text onto the request pool (the
 * parsed document is freed before rendering), then confine it.
 *
 * Verdicts land in *it: err.code set = pre-disposed <Error> (bad key, escape);
 * fs set = confined, goes to the batch; neither = pre-disposed <Deleted> (a
 * RESERVED key must read exactly as an absent one, and DeleteObjects is
 * idempotent - an <Error> of any code would single the name out).
 *
 * Returns NGX_OK (verdict recorded - continue), or NGX_ABORT (malformed
 * object: missing <Key>, unreadable content, or allocation failure; the
 * *malformed_500 out-flag separates client MalformedXML from a 500).
 */
ngx_int_t
s3_delete_collect_one(s3_del_ctx_t *dc, xmlNodePtr obj, s3_del_item_t *it,
    int *malformed_500)
{
    xmlNodePtr key_node;
    xmlChar   *key_text;
    size_t     key_len;
    char       key_str[S3_MAX_KEY];
    char       fs_path[PATH_MAX];
    int        rrc;

    *malformed_500 = 0;
    ngx_memzero(it, sizeof(*it));

    key_node = s3_delete_xml_find_child(obj, "Key");
    if (key_node == NULL) {
        return NGX_ABORT;   /* missing <Key> -> MalformedXML */
    }

    key_text = xmlNodeGetContent(key_node);
    if (key_text == NULL) {
        *malformed_500 = 1;
        return NGX_ABORT;   /* unreadable content -> 500 */
    }
    key_len = (size_t) xmlStrlen(key_text);

    it->key = ngx_pnalloc(dc->r->pool, key_len + 1);
    if (it->key == NULL) {
        xmlFree(key_text);
        *malformed_500 = 1;
        return NGX_ABORT;
    }
    ngx_memcpy(it->key, key_text, key_len);
    it->key[key_len] = '\0';
    it->key_len = key_len;
    xmlFree(key_text);

    if (key_len == 0 || key_len >= S3_MAX_KEY) {
        it->err.code    = "InvalidArgument";
        it->err.message = "Object key is empty or too long.";
        return NGX_OK;
    }

    /* Confinement BEFORE any delete: a key that resolves outside the export
     * root is rejected here without ever touching the filesystem, and the
     * refusal does not leak whether the escaped path exists. */
    ngx_memcpy(key_str, it->key, key_len + 1);
    rrc = s3_resolve_key_ex(dc->cf->common.root_canon, key_str, fs_path,
                            sizeof(fs_path),
                            dc->cf->common.cache_store_endpoint);
    if (rrc == 404) {
        return NGX_OK;   /* pre-disposed <Deleted>: reserved reads as absent */
    }
    if (rrc != 0) {
        s3_key_error_t kerr;

        s3_resolve_key_error(rrc, &kerr);
        it->err.code    = kerr.code;
        it->err.message = kerr.message;
        return NGX_OK;
    }

    it->fs = ngx_pnalloc(dc->r->pool, ngx_strlen(fs_path) + 1);
    if (it->fs == NULL) {
        *malformed_500 = 1;
        return NGX_ABORT;
    }
    ngx_memcpy(it->fs, fs_path, ngx_strlen(fs_path) + 1);
    return NGX_OK;
}

/*
 * s3_delete_execute - phase 2: ONE brix_vfs_delete_many() call for every key
 * that survived collection (one write gate, one OP_DELETE observation, one
 * driver batch where the leaf has unlink_many).
 *
 * WHAT: Builds the confinable subset (fs != NULL) with a batch->item index
 *       map, runs the VFS batch, writes each per-key errno back into its
 *       item's batch_err, and emits a CNS retraction per actually-removed key.
 * WHY:  EROFS is the one whole-request refusal: it is raised BEFORE any key is
 *       examined, so answering 403 for the request as a whole discloses
 *       nothing per key (the doc's security-negative). Every other batch
 *       failure keeps the per-key vocabulary - untried keys hold the
 *       ECANCELED the VFS pre-filled.
 * HOW:  Returns NGX_OK (per-key verdicts recorded - render next) or NGX_DONE
 *       (response finalised here: EROFS 403 or allocation 500).
 */
ngx_int_t
s3_delete_execute(s3_del_ctx_t *dc, s3_del_item_t *items, size_t count)
{
    ngx_http_request_t     *r = dc->r;
    ngx_http_s3_req_ctx_t  *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    brix_vfs_ctx_t        vctx;
    const char           **fs;
    int                    *errs;
    size_t                 *map;
    size_t                  i, m = 0, done = 0;
    ngx_int_t               rc;

    fs   = ngx_palloc(r->pool, count * sizeof(*fs));
    errs = ngx_palloc(r->pool, count * sizeof(*errs));
    map  = ngx_palloc(r->pool, count * sizeof(*map));
    if (fs == NULL || errs == NULL || map == NULL) {
        s3_metrics_finalize_request_method(r, dc->method_slot,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }

    for (i = 0; i < count; i++) {
        if (items[i].fs != NULL) {
            fs[m]  = items[i].fs;
            map[m] = i;
            m++;
        }
    }
    if (m == 0) {
        return NGX_OK;   /* every key was pre-disposed at collection */
    }

    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        dc->cf->common.root_canon, dc->cf->common.cache_root_canon,
        brix_vfs_policy_from_write_enable(dc->cf->common.allow_write),
        brix_http_request_is_tls(r),
        (s3ctx != NULL) ? s3ctx->identity : NULL,
        dc->cf->common.root_canon);
    s3_vfs_bind_deleg(r, dc->cf, &vctx);

    rc = brix_vfs_delete_many(&vctx, fs, m, errs, &done);
    if (rc != NGX_OK && errno == EROFS) {
        s3_metrics_finalize_request_method(r, dc->method_slot,
            s3_send_xml_error(r, NGX_HTTP_FORBIDDEN, "AccessDenied",
                              "The export is read-only."));
        return NGX_DONE;
    }
    if (rc != NGX_OK && errno == EBUSY) {
        /* phase-107 C7: the per-key lock gate refused BEFORE any arm ran, so
         * the refusal is atomic - no key was attempted (errs all ECANCELED).
         * Answer the whole request with the same 409 OperationAborted the
         * single-key DELETE gives a locked key (§5.0); per-key InternalError
         * rows would hide the lock and imply a server fault. */
        s3_metrics_finalize_request_method(r, dc->method_slot,
            s3_send_xml_error(r, NGX_HTTP_CONFLICT, "OperationAborted",
                              "A conflicting conditional operation is "
                              "currently in progress against this "
                              "resource."));
        return NGX_DONE;
    }

    for (i = 0; i < m; i++) {
        items[map[i]].batch_err = errs[i];
        if (errs[i] == 0) {
            /* phase-97 §5: a real removal - retract it from the manager
             * inventory. ENOENT removed nothing and emits nothing. */
            brix_cns_emit_at(dc->cf->common.root_canon, BRIX_CNS_DEL,
                               fs[i], 0, 0);
        }
    }
    return NGX_OK;
}

/* Map a batch per-key errno onto the S3 error pair - the same vocabulary the
 * per-key handler used, plus ECANCELED for a key the batch never reached
 * (which must never render as <Deleted>). */
static void
s3_delete_batch_err_pair(int e, s3_del_err_t *err)
{
    if (e == EACCES || e == EPERM) {
        err->code    = "AccessDenied";
        err->message = "Access Denied.";
    } else if (e == ENOTEMPTY) {
        err->code    = "BucketNotEmpty";
        err->message = "The directory is not empty.";
    } else if (e == ECANCELED) {
        err->code    = "InternalError";
        err->message = "The key was not attempted because the batch failed.";
    } else {
        err->code    = "InternalError";
        err->message = "Internal server error.";
    }
}

/*
 * s3_delete_render - phase 3: one <Deleted> or <Error> element per item, in
 * the client's original order. <Deleted> covers: pre-disposed at collection
 * (reserved-absent), removed (batch_err 0), and idempotent-missing (ENOENT).
 * Returns NGX_ERROR only on output-buffer overflow (caller maps to 500).
 */
ngx_int_t
s3_delete_render(s3_del_ctx_t *dc, const s3_del_item_t *items, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        const s3_del_item_t *it = &items[i];
        s3_del_err_t          err;
        ngx_int_t             rc;

        if (it->err.code != NULL) {
            rc = s3_delete_xml_append_error(dc->xml_buf, dc->xml_len,
                                            it->key, it->key_len, &it->err);
        } else if (it->fs == NULL || it->batch_err == 0
                   || it->batch_err == ENOENT)
        {
            rc = s3_delete_xml_append_deleted(dc->xml_buf, dc->xml_len,
                                              it->key, it->key_len);
        } else {
            s3_delete_batch_err_pair(it->batch_err, &err);
            rc = s3_delete_xml_append_error(dc->xml_buf, dc->xml_len,
                                            it->key, it->key_len, &err);
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
