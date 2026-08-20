/*
 * oci_referrers.c — the referrers graph (D15.1).
 *
 * WHAT: write one descriptor per (subject, referrer) edge at push time, drop
 *       it at delete time, and assemble the edges of one subject into an
 *       image index on GET.
 * WHY:  a referrer is an ordinary manifest whose `subject` field points at
 *       another manifest — that is the whole of the artifact model, and the
 *       registry's job is to make the reverse direction answerable. Storing
 *       the DESCRIPTOR rather than a bare digest is what keeps the read path
 *       from re-opening and re-parsing every referring manifest to rebuild
 *       fields (mediaType, artifactType, size) that were already known to
 *       the push that created the edge.
 * HOW:  <repo>/referrers/<alg>/<subject>/<referrer> holds the descriptor
 *       JSON, and <repo>/manifests/<alg>/<referrer>.subject holds the
 *       subject hex, so DELETE cuts the edge with one read instead of a scan
 *       over every subject in the repository. Both names are 64-hex by
 *       grammar (§0.7.2), so neither can spell a path component of its own.
 */

#include "oci_referrers.h"

#include "core/http/http_headers.h"
#include "oci/mediatypes.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The assembled listing. 512 descriptors of at most 4 KiB would overrun this,
 * so the walk stops on whichever bound it reaches first — a truncated index
 * is a listing the client can still act on, an unbounded one is not. */
#define OCI_REFERRERS_BODY_MAX  (256 * 1024)

/* The filter the spec defines. Only one exists, and a client that asks for an
 * unknown one gets an unfiltered answer WITHOUT the applied-filters header,
 * which is precisely how it learns the filter was ignored. */
static const char  oci_referrers_filter[] = "artifactType";


/* <root>/repos/<name>/referrers/<alg>/<subject-hex>[/<referrer-hex>].
 * `referrer` may be NULL to name the subject's directory itself. The
 * algorithm component is the SUBJECT's: the directory answers "what refers to
 * this subject", so it is the subject that names it. A referrer's own
 * algorithm rides in the width of its filename. */
static int
oci_referrers_path(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *subject,
    const brix_oci_digest_t *referrer, char *out, size_t outsz)
{
    char        rest[2 * BRIX_OCI_HEXLEN_MAX + 32];
    const char *alg = brix_oci_alg_name(subject->alg);
    int         n;

    if (alg == NULL) {
        return -1;
    }
    n = snprintf(rest, sizeof(rest), "referrers/%s/%s%s%s", alg, subject->hex,
                 (referrer != NULL) ? "/" : "",
                 (referrer != NULL) ? referrer->hex : "");
    if (n < 0 || (size_t) n >= sizeof(rest)) {
        return -1;
    }
    return brix_oci_store_repo_path(st, name, name_len, rest, out, outsz);
}


/* What a client sees in the index for this referrer. `artifactType` is the
 * manifest's own when it declares one and its config media type otherwise —
 * the fallback the image spec mandates, and the reason a cosign signature
 * (which sets only the config type) is still filterable. */
static json_t *
oci_referrers_descriptor(json_t *doc, const char *dg, const char *ctype,
    off_t size)
{
    const char  *atype;
    json_t      *desc;
    json_t      *ann;

    atype = json_string_value(json_object_get(doc, "artifactType"));
    if (atype == NULL) {
        atype = json_string_value(
            json_object_get(json_object_get(doc, "config"), "mediaType"));
    }

    desc = json_pack("{s:s, s:s, s:I}", "mediaType", ctype, "digest", dg,
                     "size", (json_int_t) size);
    if (desc == NULL) {
        return NULL;
    }
    if (atype != NULL
        && json_object_set_new(desc, "artifactType",
                               json_string(atype)) != 0)
    {
        json_decref(desc);
        return NULL;
    }

    /* Annotations ride along because that is where the tooling puts the
     * signature's own metadata — but they are attacker-sized, so they are
     * included only when the whole descriptor still fits the per-edge cap,
     * checked below by the caller after the dump. */
    ann = json_object_get(doc, "annotations");
    if (json_is_object(ann)
        && json_object_set(desc, "annotations", ann) != 0)
    {
        json_decref(desc);
        return NULL;
    }
    return desc;
}


/* Serialise `desc` into `out`, dropping the annotations rather than the whole
 * edge when the result would exceed the per-edge cap. Length, or -1. */
static int
oci_referrers_dump(json_t *desc, char *out, size_t outsz)
{
    char  *text;
    size_t len;

    text = json_dumps(desc, JSON_COMPACT);
    if (text == NULL) {
        return -1;
    }
    len = ngx_strlen(text);

    if (len >= outsz) {
        free(text);
        if (json_object_del(desc, "annotations") != 0) {
            return -1;
        }
        text = json_dumps(desc, JSON_COMPACT);
        if (text == NULL) {
            return -1;
        }
        len = ngx_strlen(text);
        if (len >= outsz) {
            free(text);
            return -1;
        }
    }

    ngx_memcpy(out, text, len + 1);
    free(text);
    return (int) len;
}


int
brix_oci_referrers_subject_ok(json_t *doc, const char **why)
{
    brix_oci_digest_t  subject;
    const char        *sd;
    json_t            *subject_node;

    subject_node = json_object_get(doc, "subject");
    if (subject_node == NULL) {
        return 0;
    }
    if (!json_is_object(subject_node)) {
        *why = "subject must be a descriptor object";
        return -1;
    }
    sd = json_string_value(json_object_get(subject_node, "digest"));
    if (sd == NULL) {
        *why = "subject carries no digest";
        return -1;
    }
    if (brix_oci_digest_parse(sd, ngx_strlen(sd), &subject) != 0) {
        *why = "subject digest is not a digest this registry stores";
        return -1;
    }
    return 0;
}


ngx_int_t
brix_oci_referrers_index(const brix_oci_store_t *st,
    const brix_oci_req_t *req, json_t *doc, const brix_oci_digest_t *d,
    const char *ctype, off_t size, char *subj, size_t subjsz, ngx_log_t *log)
{
    brix_oci_digest_t  subject;
    char               desc_text[BRIX_OCI_REFERRER_DESC_MAX];
    char               path[PATH_MAX];
    char               dg[BRIX_OCI_DIGEST_STRLEN];
    const char        *sd;
    json_t            *desc;
    int                len;

    subj[0] = '\0';

    sd = json_string_value(
        json_object_get(json_object_get(doc, "subject"), "digest"));
    if (sd == NULL) {
        return NGX_OK;                     /* not a referrer: nothing to index */
    }
    /* Unreachable by way of the PUT path — brix_oci_referrers_subject_ok()
     * has already refused a subject that does not parse — and checked anyway,
     * because this hex is about to name a directory. */
    if (brix_oci_digest_parse(sd, ngx_strlen(sd), &subject) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "oci: manifest declares an unparsable subject digest");
        return NGX_ERROR;
    }

    if (brix_oci_digest_format(d, dg, sizeof(dg)) < 0) {
        return NGX_ERROR;
    }

    desc = oci_referrers_descriptor(doc, dg, ctype, size);
    if (desc == NULL) {
        return NGX_ERROR;
    }
    len = oci_referrers_dump(desc, desc_text, sizeof(desc_text));
    json_decref(desc);
    if (len < 0) {
        return NGX_ERROR;
    }

    if (oci_referrers_path(st, req->name, req->name_len, &subject, d,
                           path, sizeof(path)) != 0
        || brix_oci_store_put_text(path, desc_text, (size_t) len, log)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* OCI-Subject reports the SUBJECT's digest — the thing the client asked
     * us to attach to — not the referrer it just pushed. The same string is
     * the back-pointer's payload: a self-describing digest, so the reader
     * validates it through the ordinary grammar rather than trusting that
     * whatever wrote the file meant sha256. */
    if (brix_oci_digest_format(&subject, subj, subjsz) < 0) {
        return NGX_ERROR;
    }

    /* The back-pointer is written second: an edge whose descriptor exists but
     * whose back-pointer does not is merely undeletable-by-shortcut, while the
     * reverse would be a DELETE that removes a descriptor never written. */
    if (brix_oci_store_manifest_path(st, req->name, req->name_len, d,
                                     ".subject", path, sizeof(path)) != 0
        || brix_oci_store_put_text(path, subj, ngx_strlen(subj), log) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}


void
brix_oci_referrers_forget(const brix_oci_store_t *st, const char *name,
    size_t name_len, const brix_oci_digest_t *d, ngx_log_t *log)
{
    brix_oci_digest_t  subject;
    char               path[PATH_MAX];
    char               subject_str[BRIX_OCI_DIGEST_STRLEN];
    ssize_t            n;

    if (brix_oci_store_manifest_path(st, name, name_len, d, ".subject",
                                     path, sizeof(path)) != 0)
    {
        return;
    }
    n = brix_oci_store_get_text(path, subject_str, sizeof(subject_str));
    if (n < 0) {
        return;                            /* not a referrer: no edge to cut */
    }
    (void) brix_oci_store_remove(path, log);

    /* The stored hex was written by the indexer above, but it is re-validated
     * before it names a directory: a store an operator has edited by hand is
     * still not allowed to build a path. */
    if (brix_oci_digest_parse(subject_str, (size_t) n, &subject) != 0) {
        return;
    }
    if (oci_referrers_path(st, name, name_len, &subject, d,
                           path, sizeof(path)) == 0)
    {
        (void) brix_oci_store_remove(path, log);
    }
}


/* Does this stored descriptor pass the requested artifactType filter? A
 * descriptor with no artifactType matches nothing but the unfiltered case —
 * the spec's filter selects, it does not merely order. */
static int
oci_referrers_matches(const char *desc_text, const ngx_str_t *want)
{
    json_error_t  jerr;
    const char   *atype;
    json_t       *desc;
    int           ok;

    if (want->len == 0) {
        return 1;
    }
    desc = json_loads(desc_text, 0, &jerr);
    if (desc == NULL) {
        return 0;
    }
    atype = json_string_value(json_object_get(desc, "artifactType"));
    ok = (atype != NULL
          && ngx_strlen(atype) == want->len
          && ngx_strncmp(atype, want->data, want->len) == 0);
    json_decref(desc);

    return ok;
}


/* Walk the subject's directory, appending each descriptor that passes the
 * filter into `body` as an array element. Entries written, and `*used` grown
 * by what was appended. */
static int
oci_referrers_collect(const char *dir, const ngx_str_t *filter, u_char *body,
    size_t *used)
{
    char            desc_text[BRIX_OCI_REFERRER_DESC_MAX];
    char            path[PATH_MAX];
    struct dirent  *ent;
    DIR            *dh;
    int             count = 0;

    dh = opendir(dir);                     /* vfs-seam-allow: registry's own referrers index, not a VFS export listing */
    if (dh == NULL) {
        return 0;                          /* unknown subject: an empty graph */
    }

    while (count < BRIX_OCI_REFERRERS_MAX
           && (ent = readdir(dh)) != NULL)  /* vfs-seam-allow: registry's own referrers index, not a VFS export listing */
    {
        size_t  len;

        if (ngx_strlen(ent->d_name) != BRIX_OCI_SHA256_HEXLEN
            || snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name)
               >= (int) sizeof(path))
        {
            continue;
        }
        if (brix_oci_store_get_text(path, desc_text, sizeof(desc_text)) <= 0
            || !oci_referrers_matches(desc_text, filter))
        {
            continue;
        }

        len = ngx_strlen(desc_text);
        if (*used + len + 2 >= OCI_REFERRERS_BODY_MAX) {
            break;
        }
        if (count > 0) {
            body[(*used)++] = ',';
        }
        ngx_memcpy(body + *used, desc_text, len);
        *used += len;
        count++;
    }
    (void) closedir(dh);

    return count;
}


ngx_int_t
brix_oci_referrers_get(ngx_http_request_t *r, ngx_http_brix_oci_ctx_t *ctx,
    brix_oci_store_t *st)
{
    ngx_str_t  filter = ngx_null_string;
    char       dir[PATH_MAX];
    u_char    *body;
    size_t     used;

    if (ngx_http_arg(r, (u_char *) oci_referrers_filter,
                     sizeof(oci_referrers_filter) - 1, &filter) != NGX_OK)
    {
        ngx_str_null(&filter);
    }

    if (oci_referrers_path(st, ctx->req.name, ctx->req.name_len,
                           &ctx->req.digest, NULL, dir, sizeof(dir)) != 0)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    body = ngx_palloc(r->pool, OCI_REFERRERS_BODY_MAX);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    used = (size_t) snprintf((char *) body, OCI_REFERRERS_BODY_MAX,
                             "{\"schemaVersion\":2,\"mediaType\":\"%s\","
                             "\"manifests\":[", OCI_MT_INDEX);

    (void) oci_referrers_collect(dir, &filter, body, &used);

    body[used++] = ']';
    body[used++] = '}';

    /* Declaring the filter is mandatory when one was honoured: without this
     * header a client cannot tell a filtered answer from a registry that
     * ignored the parameter, and would treat "no signatures of this type" as
     * "no signatures at all". */
    if (filter.len > 0
        && brix_http_set_header(r, "OCI-Filters-Applied",
                                oci_referrers_filter, NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->disp = BRIX_OCI_OUT_LOCAL;
    return brix_oci_send_body(r, NGX_HTTP_OK, OCI_MT_INDEX, body, used);
}
