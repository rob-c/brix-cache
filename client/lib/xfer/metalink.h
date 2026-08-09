/*
 * metalink.h — parsed metalink (RFC 5854 v4 + legacy v3) mirror-list contract.
 *
 * WHAT: One concept: the brix_metalink result struct (ranked mirror URLs +
 *       optional size/digest) and the pure parser/detector API over it.
 * WHY:  Metalink files are the client's "virtual redirector" input (phase-100):
 *       the copy engine fails over across the ranked mirrors and can feed them
 *       to the extreme-copy engine. The parser is pure (bytes in, struct out,
 *       no I/O) so it is unit-testable against hostile documents.
 * HOW:  copy_metalink.c loads the document (local read or a bounded remote
 *       fetch) and calls brix_metalink_parse; consumers walk urls[0..n_urls)
 *       which is already sorted best-first.
 *
 * Requires: nothing beyond brix.h (included here for brix_status). Not a
 * public API: include only from client/lib/ and client/tests/c/.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "brix.h"   /* brix_status */

/* Hard caps against hostile documents (see phase-100 doc §2.1). */
#define XRDC_METALINK_MAX_BYTES (4u * 1024u * 1024u)   /* refuse larger docs   */
#define XRDC_METALINK_MAX_URLS  16                     /* mirrors kept (ranked) */
#define XRDC_METALINK_URL_MAX   2304                   /* per-URL byte cap      */
#define XRDC_METALINK_HEX_MAX   129                    /* digest hex + NUL      */
#define XRDC_METALINK_ALGO_MAX  16                     /* digest name + NUL     */

/* One ranked mirror: the absolute URL and the rank it sorted under (ascending =
 * better; v4 priority used as-is, v3 preference mapped to 101-preference). */
typedef struct {
    char rank_url[XRDC_METALINK_URL_MAX];
    int  rank;
} brix_metalink_url;

typedef struct {
    brix_metalink_url urls[XRDC_METALINK_MAX_URLS];
    size_t            n_urls;
    size_t            n_skipped;   /* mirrors dropped: bad scheme/length/overflow */
    int64_t           size;        /* <size> of the file, -1 when absent          */
    /* Strongest client-supported digest found (md5 > crc32c > adler32), or
     * empty strings when the document carries none we can verify. */
    char              hash_algo[XRDC_METALINK_ALGO_MAX];
    char              hash_hex[XRDC_METALINK_HEX_MAX];
} brix_metalink;

/* 1 if the URL/path `s` names a metalink document by suffix (.meta4/.metalink,
 * case-insensitive, any "?opaque" stripped first); 0 otherwise. Pure. */
int brix_metalink_is_name(const char *s);

/* Parse a metalink v4/v3 document (first <file> entry) into *out. Returns 0
 * with at least one usable mirror kept, or -1 with *st set. Pure: no I/O, no
 * allocation, single pass, bounded by the caps above. */
int brix_metalink_parse(const char *xml, size_t len, brix_metalink *out,
                        brix_status *st);
