/* stargz_internal.h — seam between the eStargz writer (stargz.c) and its
 * TOC serializer (stargz_toc.c), phase-104 D15.8.
 *
 * WHAT: the growable TOC JSON buffer and the entry-append call.
 * WHY:  the framing writer and the JSON document have nothing to say to
 *       each other beyond "here is one entry and where its payload landed";
 *       splitting them keeps each TU inside the size cap and lets the JSON
 *       escaping be reviewed on its own.
 * HOW:  one malloc'd buffer that only ever grows; every append goes through
 *       sgz_toc_put so a single OOM check at the end covers the document.
 */
#ifndef BRIX_OCI_STARGZ_INTERNAL_H
#define BRIX_OCI_STARGZ_INTERNAL_H

#include "oci/stargz.h"
#include "oci/tar.h"

typedef struct {
    char   *buf;
    size_t  len, cap;
    int64_t n;          /* entries appended */
    int     failed;     /* sticky: an append ran out of memory */
} sgz_toc_t;

/* Start the document. 0 / -1 (out of memory). */
int  sgz_toc_begin(sgz_toc_t *t);

/* Append one TOCEntry. `offset` is the blob offset of the gzip member the
 * entry's payload starts at, and is written only for a non-empty regular
 * file; `content` is that payload's "<alg>:<hex>" digest, or NULL. */
int  sgz_toc_add(sgz_toc_t *t, const brix_tar_entry_t *e, long long offset,
                 const char *content);

/* Close the document; the JSON bytes are then [t->buf, t->buf + t->len). */
int  sgz_toc_end(sgz_toc_t *t);

void sgz_toc_free(sgz_toc_t *t);

#endif /* BRIX_OCI_STARGZ_INTERNAL_H */
