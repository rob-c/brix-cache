/*
 * sd_s3_list.c — S3 ListObjectsV2 (delimited, paged) for the shared S3 driver.
 *
 * WHAT: sd_s3_list_page() — one signed GET against the bucket root asking for a
 *       single directory level (delimiter '/'): <Contents> under the prefix are
 *       files, <CommonPrefixes> are sub-directories. Drives the sd_remote
 *       opendir/readdir namespace slots (finding #4).
 * WHY:  S3 has no readdir; a "directory listing" is a prefix+delimiter LIST. The
 *       logic lives here (once, ngx-free) rather than in the remote adapter so a
 *       future server-side lister reuses it.
 * HOW:  Ask sd_s3_list_scan.c for the signed page, then walk the body's
 *       <Contents>/<CommonPrefixes> blocks in document order, reporting each
 *       entry's BASENAME. The flat sibling (sd_s3_list_flat.c) shares every
 *       request-side primitive and differs only in the walk.
 */

#include "sd_s3_list_internal.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

/* Emit one entry from a raw <Key>/<Prefix> value [vs,ve) to cb, stripping the
 * request prefix and (for dirs) the trailing '/'. Skips the directory-marker
 * object and anything that does not sit directly under the prefix. Returns cb's
 * stop signal (non-zero) or 0. */
static int
s3l_emit(const char *vs, const char *ve, const char *prefix, size_t plen,
    int is_dir, sd_s3_list_cb cb, void *ud)
{
    char   name[256];
    char   base[256];
    int    n;
    size_t blen;

    n = sd_s3l_xml_unescape(vs, ve, name, sizeof(name));
    if (n < 0) {
        return 0;                            /* unrepresentable name — skip */
    }
    if ((size_t) n < plen || memcmp(name, prefix, plen) != 0) {
        return 0;                            /* not under the request prefix */
    }
    blen = (size_t) n - plen;                 /* basename (dirs keep trailing /) */
    if (is_dir) {
        if (blen == 0 || name[n - 1] != '/') {
            return 0;
        }
        blen--;                               /* drop the trailing '/' */
    }
    if (blen == 0) {
        return 0;                            /* the directory-marker object */
    }
    if (blen >= sizeof(base)) {
        return 0;                            /* longer than a dirent can hold */
    }
    memcpy(base, name + plen, blen);
    base[blen] = '\0';
    if (memchr(base, '/', blen) != NULL) {
        return 0;                            /* not a direct child (defensive) */
    }
    return cb(ud, base, is_dir);
}

/* Walk <Contents>/<CommonPrefixes> in document order; the top-level <Prefix>
 * precedes both, so per-block extraction never mistakes it for an entry. */
static void
s3l_walk(const char *body, const char *end, const char *prefix, size_t plen,
    sd_s3_list_cb cb, void *ud)
{
    const char *scan = body;
    int         stopped = 0;

    while (!stopped && scan < end) {
        const char *c  = sd_s3l_find(scan, (size_t) (end - scan), "<Contents>");
        const char *cp = sd_s3l_find(scan, (size_t) (end - scan),
                                  "<CommonPrefixes>");
        const char *ts;
        const char *te;
        const char *block;
        const char *tag;
        const char *open_tag;
        const char *close_tag;
        int         is_dir;

        if (c == NULL && cp == NULL) {
            break;
        }
        is_dir    = (c == NULL) || (cp != NULL && cp < c);
        block     = is_dir ? cp : c;
        tag       = is_dir ? "<CommonPrefixes>" : "<Contents>";
        open_tag  = is_dir ? "<Prefix>" : "<Key>";
        close_tag = is_dir ? "</Prefix>" : "</Key>";

        if (sd_s3l_first_text(block, end, open_tag, close_tag, &ts, &te)) {
            stopped = s3l_emit(ts, te, prefix, plen, is_dir, cb, ud);
            scan    = te;
        } else {
            scan = block + strlen(tag);
        }
    }
}

int
sd_s3_list_page(const sd_s3_open_params *p, const char *prefix,
    const char *cont_in, sd_s3_list_cb cb, void *ud, int *truncated,
    char *cont_out, size_t cont_cap, char *errbuf, size_t errcap)
{
    char             qs[S3L_QS_CAP];
    brix_s3_resp_t   resp;
    sd_s3_file      *f = NULL;
    const char      *body;
    size_t           blen = 0;
    size_t           plen;
    int              rc;

    if (p == NULL || prefix == NULL || cb == NULL || truncated == NULL
        || cont_out == NULL || cont_cap == 0)
    {
        errno = EINVAL;
        sd_s3_set_err(errbuf, errcap, "s3 list: bad parameters");
        return -1;
    }
    *truncated  = 0;
    cont_out[0] = '\0';
    plen = strlen(prefix);

    if (sd_s3l_build_query(prefix, plen, cont_in, 1 /* delimited */, qs,
            sizeof(qs), errbuf, errcap) != 0) {
        return -1;
    }
    rc = sd_s3l_fetch(p, qs, &f, &resp, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    if (f == NULL) {
        /* sd_s3l_fetch's contract is rc == 0 ⇒ *f_out set.  Checked rather than
         * assumed: every failure arm there closes the handle, so a future arm
         * that returns 0 without publishing one would land as a null deref on
         * the very next line. */
        errno = EIO;
        sd_s3_set_err(errbuf, errcap, "s3 list: fetch returned no handle");
        return -1;
    }

    body = f->transport->resp_body(&resp, &blen);
    if (body == NULL) {
        blen = 0;
        body = "";
    }
    sd_s3l_page_meta(body, body + blen, truncated, cont_out, cont_cap);
    s3l_walk(body, body + blen, prefix, plen, cb, ud);

    f->transport->resp_free(&resp);
    sd_s3_close(f);
    return 0;
}
