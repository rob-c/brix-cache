/*
 * sd_s3_list_internal.h — private seam between the two S3 ListObjectsV2 listers
 *                         and the scanner/request plumbing they share.
 *
 * The delimited lister (sd_s3_list.c, one directory level) and the flat one
 * (sd_s3_list_flat.c, the backend-catalog verb) issue the SAME signed request
 * differing only in whether `delimiter` is present, and read the same response
 * schema. Everything common lives in sd_s3_list_scan.c and is declared here.
 *
 * Private to src/fs/backend/s3/ — nothing outside the S3 driver includes this;
 * the public entry points are sd_s3_list_page / sd_s3_list_flat_page in sd_s3.h.
 */
#ifndef BRIX_SD_S3_LIST_INTERNAL_H
#define BRIX_SD_S3_LIST_INTERNAL_H

#include "sd_s3_internal.h"

#include <stddef.h>

/* The canonical-query buffer size; also bounds the request line. */
#define S3L_QS_CAP 4096

/* Locate `needle` in [hay, hay+hlen); NULL when absent. A tiny memmem so the
 * TUs do not depend on _GNU_SOURCE. */
const char *sd_s3l_find(const char *hay, size_t hlen, const char *needle);

/* Unescape XML text [s,e) (named + numeric entities) into out[cap], NUL-
 * terminated. Returns the byte length, or -1 on overflow or a malformed
 * numeric entity. */
int sd_s3l_xml_unescape(const char *s, const char *e, char *out, size_t cap);

/* Bracket the text of the FIRST <tag>…</tag> within [scan,end) as
 * [*out_s,*out_e) (raw bytes, unescaped by the caller). 1 when found, else 0. */
int sd_s3l_first_text(const char *scan, const char *end, const char *open_tag,
    const char *close_tag, const char **out_s, const char **out_e);

/* Build the canonical query for one page (see the definition for the sort-order
 * contract and what `delimited` selects). 0, or -1 with errno + errbuf. */
int sd_s3l_build_query(const char *prefix, size_t plen, const char *cont_in,
    int delimited, char *qs, size_t qscap, char *errbuf, size_t errcap);

/* Run one signed ListObjectsV2 GET. On success 0 with *f_out bound and *resp
 * filled (the caller releases both); on failure -1 with errno + errbuf set and
 * nothing left to release. */
int sd_s3l_fetch(const sd_s3_open_params *p, const char *qs,
    sd_s3_file **f_out, brix_s3_resp_t *resp, char *errbuf, size_t errcap);

/* IsTruncated / NextContinuationToken (best-effort; a page with neither is a
 * complete, final page). */
void sd_s3l_page_meta(const char *body, const char *end, int *truncated,
    char *cont_out, size_t cont_cap);

#endif /* BRIX_SD_S3_LIST_INTERNAL_H */
