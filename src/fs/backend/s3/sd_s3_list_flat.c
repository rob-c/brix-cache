/*
 * sd_s3_list_flat.c — S3 ListObjectsV2 without a delimiter: the flat, recursive
 *                     object listing behind the backend-catalog verb.
 *
 * WHAT: sd_s3_list_flat_page() — one signed GET returning up to 1000 keys under
 *       a prefix at ANY depth, each with its <Size> and <LastModified>.
 * WHY:  driver->enumerate asks what objects an export holds, not what a
 *       directory contains. Building that from the delimited lister costs one
 *       signed request per pseudo-directory, which is precisely the
 *       amplification the catalog verb exists to avoid; and because S3 reports
 *       size and mtime in the listing itself, a stat-bearing enumeration costs
 *       no extra request at all.
 * HOW:  the same canonical query as the delimited page minus `delimiter`, then a
 *       single <Contents> tag walk. Every request-side primitive is shared with
 *       sd_s3_list.c through sd_s3_list_scan.c.
 */

#include "sd_s3_list_internal.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Parse an S3 <LastModified> ("2009-10-12T17:50:30.000Z", always UTC) to a
 * time_t. Returns 0 on any malformed value — an unparsable timestamp must not
 * become a plausible-looking epoch date that an inventory would then treat as a
 * real mtime, and the caller reports it as "no stat" instead. */
static time_t
s3l_parse_iso8601(const char *s, const char *e)
{
    char      buf[40];
    struct tm tm;
    int       y, mo, d, h, mi, sec;
    size_t    n = (size_t) (e - s);

    if (n < 19 || n >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, s, n);
    buf[n] = '\0';
    if (sscanf(buf, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &sec) != 6) {
        return 0;
    }
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31
        || h < 0 || h > 23 || mi < 0 || mi > 59 || sec < 0 || sec > 60)
    {
        return 0;      /* field-validate before timegm, which would normalise */
    }
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = sec;
    tm.tm_isdst = 0;
    return timegm(&tm);
}

/* Read one <Contents> block's <Size>, rejecting a non-numeric or negative body.
 * Returns 1 with *out set, or 0. */
static int
s3l_block_size(const char *block, const char *end, uint64_t *out)
{
    const char   *ss;
    const char   *se;
    char          num[32];
    char         *endp;
    unsigned long long v;
    size_t        n;

    if (!sd_s3l_first_text(block, end, "<Size>", "</Size>", &ss, &se)) {
        return 0;
    }
    n = (size_t) (se - ss);
    if (n == 0 || n >= sizeof(num)) {
        return 0;
    }
    memcpy(num, ss, n);
    num[n] = '\0';
    errno = 0;
    v = strtoull(num, &endp, 10);
    if (errno != 0 || endp != num + n) {
        return 0;
    }
    *out = (uint64_t) v;
    return 1;
}

/* Emit one <Contents> block as a catalog entry. `bend` bounds the block so a
 * missing <Size>/<LastModified> cannot be satisfied from the NEXT object's
 * fields — the scanner is positional, and an unbounded sd_s3l_first_text would
 * happily attribute a neighbour's size to this key. Returns cb's stop signal. */
static int
s3l_emit_flat(const char *block, const char *bend, sd_s3_list_flat_cb cb,
    void *ud)
{
    char        key[SD_S3_KEY_MAX];
    const char *ks;
    const char *ke;
    uint64_t    size = 0;
    time_t      mtime = 0;
    int         n;

    if (!sd_s3l_first_text(block, bend, "<Key>", "</Key>", &ks, &ke)) {
        return 0;
    }
    n = sd_s3l_xml_unescape(ks, ke, key, sizeof(key));
    if (n <= 0) {
        return 0;                  /* unrepresentable or empty key — skip */
    }
    if (!s3l_block_size(block, bend, &size)) {
        size = 0;
    }
    if (sd_s3l_first_text(block, bend, "<LastModified>", "</LastModified>",
            &ks, &ke))
    {
        mtime = s3l_parse_iso8601(ks, ke);
    }
    return cb(ud, key, size, mtime);
}

/* Walk every <Contents> block in the page. There are no <CommonPrefixes> in an
 * undelimited listing, so the flat walk is a single tag scan. */
static void
s3l_walk_flat(const char *body, const char *end, sd_s3_list_flat_cb cb,
    void *ud)
{
    const char *scan = body;

    while (scan < end) {
        const char *c = sd_s3l_find(scan, (size_t) (end - scan), "<Contents>");
        const char *bend;

        if (c == NULL) {
            break;
        }
        c += sizeof("<Contents>") - 1;
        bend = sd_s3l_find(c, (size_t) (end - c), "</Contents>");
        if (bend == NULL) {
            bend = end;            /* truncated final block — scan what we have */
        }
        if (s3l_emit_flat(c, bend, cb, ud) != 0) {
            return;                /* caller asked to stop */
        }
        scan = bend;
    }
}

int
sd_s3_list_flat_page(const sd_s3_open_params *p, const char *prefix,
    const char *cont_in, sd_s3_list_flat_cb cb, void *ud, int *truncated,
    char *cont_out, size_t cont_cap, char *errbuf, size_t errcap)
{
    char            qs[S3L_QS_CAP];
    brix_s3_resp_t  resp;
    sd_s3_file     *f = NULL;
    const char     *body;
    size_t          blen = 0;
    int             rc;

    if (p == NULL || prefix == NULL || cb == NULL || truncated == NULL
        || cont_out == NULL || cont_cap == 0)
    {
        errno = EINVAL;
        sd_s3_set_err(errbuf, errcap, "s3 list-flat: bad parameters");
        return -1;
    }
    *truncated  = 0;
    cont_out[0] = '\0';

    if (sd_s3l_build_query(prefix, strlen(prefix), cont_in, 0 /* flat */, qs,
            sizeof(qs), errbuf, errcap) != 0) {
        return -1;
    }
    rc = sd_s3l_fetch(p, qs, &f, &resp, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    if (f == NULL) {
        /* Same defensive check the delimited page makes: sd_s3l_fetch's contract is
         * rc == 0 ⇒ *f_out set, and a future arm breaking it would land here as
         * a null deref rather than an error. */
        errno = EIO;
        sd_s3_set_err(errbuf, errcap, "s3 list-flat: fetch returned no handle");
        return -1;
    }

    body = f->transport->resp_body(&resp, &blen);
    if (body == NULL) {
        blen = 0;
        body = "";
    }
    sd_s3l_page_meta(body, body + blen, truncated, cont_out, cont_cap);
    s3l_walk_flat(body, body + blen, cb, ud);

    f->transport->resp_free(&resp);
    sd_s3_close(f);
    return 0;
}

