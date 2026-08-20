/*
 * oci_meta.c — the `.ocimeta` sidecar (Appendix B.1).
 *
 * WHAT: read and write the small flat-file record that rides beside every
 *       cached OCI object: the media type to echo, the content digest to
 *       advertise, the upstream ETag, when it was fetched, and whether the
 *       fill was digest-verified.
 * WHY:  a registry client does not accept an object on its bytes alone. Podman
 *       and docker both branch on the manifest's `Content-Type` (an OCI index
 *       and a Docker manifest list are different objects with the same shape)
 *       and both read `Docker-Content-Digest` to pin what they just pulled.
 *       Neither value is recoverable from a TAG-addressed cache entry's path,
 *       and re-deriving them per hit would mean hashing the manifest on the
 *       event loop for every pull. So they are memoized here, next to the
 *       bytes they describe, and the record is treated as a CACHE of a pure
 *       function of those bytes: absent or unparsable simply means "derive it
 *       again", never "serve something wrong".
 * HOW:  one `key=value` line per field, LF-separated, written to a `.tmp`
 *       sibling and renamed into place so a reader never sees a torn record.
 *       Deliberately not JSON: the record is machine-written and
 *       machine-read, an operator greps it, and a parser that cannot fail in
 *       interesting ways is worth more here than a schema.
 *
 * The raw file calls below are marked vfs-seam-allow (invariant #12): this is
 * cache BOOKKEEPING beside the object, not object data. Routing it through
 * brix_vfs_* would hand it to the cache decorator, which would treat a missing
 * sidecar as a miss and try to FILL it from the upstream registry — an
 * endpoint that has never heard of `.ocimeta`.
 */

#include "oci.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OCI_META_SUFFIX      ".ocimeta"
#define OCI_META_LINE_MAX    512

/* Build "<body_path>.ocimeta" (or its ".tmp" staging sibling). */
static int
oci_meta_path(const char *body_path, const char *extra, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%s%s%s", body_path, OCI_META_SUFFIX,
                     (extra != NULL) ? extra : "");

    return (n < 0 || (size_t) n >= outsz) ? -1 : 0;
}

/* Copy a field value, stripping the trailing LF. Silently truncates: a field
 * longer than its slot is a corrupt record, and the caller's "derive it
 * again" path is the right answer for that. */
static void
oci_meta_field(char *dst, size_t dstsz, const char *val)
{
    size_t n = strlen(val);

    while (n > 0 && (val[n - 1] == '\n' || val[n - 1] == '\r')) {
        n--;
    }
    if (n >= dstsz) {
        n = dstsz - 1;
    }
    memcpy(dst, val, n);
    dst[n] = '\0';
}

static void
oci_meta_apply(brix_oci_meta_t *out, const char *key, const char *val)
{
    if (strcmp(key, "content_type") == 0) {
        oci_meta_field(out->content_type, sizeof(out->content_type), val);

    } else if (strcmp(key, "digest") == 0) {
        oci_meta_field(out->digest, sizeof(out->digest), val);

    } else if (strcmp(key, "etag") == 0) {
        oci_meta_field(out->etag, sizeof(out->etag), val);

    } else if (strcmp(key, "fetched_at") == 0) {
        out->fetched_at = (time_t) strtoll(val, NULL, 10);

    } else if (strcmp(key, "size") == 0) {
        out->size = (off_t) strtoll(val, NULL, 10);

    } else if (strcmp(key, "mtime") == 0) {
        out->mtime = (time_t) strtoll(val, NULL, 10);

    } else if (strcmp(key, "verified") == 0) {
        out->verified = (strtol(val, NULL, 10) != 0);
    }
}

/* Does this record describe THESE bytes? A refill leaves the body's mtime
 * later and (nearly always) its size different; either disagreement means the
 * memo predates the object it sits beside. */
static int
oci_meta_describes(const brix_oci_meta_t *m, off_t size, time_t mtime)
{
    if (m->size != size) {
        return 0;
    }
    return (m->mtime == 0 || mtime <= 0 || m->mtime == mtime);
}

ngx_int_t
brix_oci_meta_load(const char *body_path, off_t size, time_t mtime,
    brix_oci_meta_t *out, ngx_log_t *log)
{
    char   path[PATH_MAX];
    char   line[OCI_META_LINE_MAX];
    FILE  *fp;

    ngx_memzero(out, sizeof(*out));

    if (oci_meta_path(body_path, NULL, path, sizeof(path)) != 0) {
        return NGX_ERROR;
    }

    fp = fopen(path, "re");
    if (fp == NULL) {
        return NGX_DECLINED;               /* absent: derive and re-store */
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq = strchr(line, '=');

        if (eq == NULL) {
            continue;                      /* not a field: ignore */
        }
        *eq = '\0';
        oci_meta_apply(out, line, eq + 1);
    }

    if (ferror(fp)) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "oci: unreadable sidecar \"%s\"", path);
        (void) fclose(fp);
        return NGX_ERROR;
    }
    (void) fclose(fp);

    if (!oci_meta_describes(out, size, mtime)) {
        ngx_memzero(out, sizeof(*out));
        return NGX_DECLINED;               /* superseded: derive and re-store */
    }

    return NGX_OK;
}

ngx_int_t
brix_oci_meta_store(const char *body_path, off_t size, time_t mtime,
    brix_oci_meta_t *meta, ngx_log_t *log)
{
    char   final[PATH_MAX];
    char   tmp[PATH_MAX];
    FILE  *fp;
    int    rc;

    meta->size  = size;
    meta->mtime = mtime;

    if (oci_meta_path(body_path, NULL, final, sizeof(final)) != 0
        || oci_meta_path(body_path, ".tmp", tmp, sizeof(tmp)) != 0)
    {
        return NGX_ERROR;
    }

    fp = fopen(tmp, "we");
    if (fp == NULL) {
        /* A read-only or full store must never fail the pull: the sidecar is
         * a memo, and its absence costs one derivation per hit, not an
         * error. Log once at INFO so the condition is visible without
         * turning a healthy cache into a noisy one. */
        ngx_log_error(NGX_LOG_INFO, log, ngx_errno,
                      "oci: sidecar not written \"%s\"", tmp);
        return NGX_DECLINED;
    }

    rc = fprintf(fp,
                 "content_type=%s\n"
                 "digest=%s\n"
                 "etag=%s\n"
                 "fetched_at=%lld\n"
                 "size=%lld\n"
                 "mtime=%lld\n"
                 "verified=%d\n",
                 meta->content_type, meta->digest, meta->etag,
                 (long long) meta->fetched_at, (long long) meta->size,
                 (long long) meta->mtime, meta->verified ? 1 : 0);

    /* fflush before the rename: a rename of a file whose bytes are still in
     * the stdio buffer publishes an empty record. fclose flushes too, but its
     * failure would then be indistinguishable from a close failure. */
    if (rc < 0 || fflush(fp) != 0) {
        (void) fclose(fp);
        (void) unlink(tmp);                /* vfs-seam-allow: sidecar staging file, not object data */
        return NGX_ERROR;
    }
    if (fclose(fp) != 0) {
        (void) unlink(tmp);                /* vfs-seam-allow: sidecar staging file, not object data */
        return NGX_ERROR;
    }

    if (rename(tmp, final) != 0) {         /* vfs-seam-allow: sidecar publish, not object data */
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "oci: sidecar rename failed \"%s\"", final);
        (void) unlink(tmp);                /* vfs-seam-allow: sidecar staging file, not object data */
        return NGX_ERROR;
    }

    return NGX_OK;
}
