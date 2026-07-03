/*
 * range.h — HTTP Range header parser shared by WebDAV and S3.
 *
 * Pure C, no nginx headers.
 */

#ifndef BRIX_COMPAT_RANGE_H
#define BRIX_COMPAT_RANGE_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    off_t  start;
    off_t  end;
    int    present;     /* 1 if a Range header was found and parsed */
    int    satisfiable; /* 0 → caller should return 416 */
} brix_http_range_t;

/*
 * WHAT: Parse an RFC 7233 "bytes=" Range header value into brix_http_range_t.
 *
 * WHY: WebDAV GET and S3 GET handlers both need to honour HTTP Range headers for partial content
 *      responses. Delegates complex parsing logic to range_vector.c while providing a simple API
 *      that returns satisfiability status (416 when the requested range exceeds file size).
 *
 * HOW: Set defaults — present=0, full-file range. Reject NULL or short headers not starting with
 *       "bytes=". Delegate actual parsing to brix_http_parse_range_vector() in range_vector.c
 *       (single-range mode, max_ranges=1). If vector parser succeeds → copy start/end into out.
 *       If it fails → present=1, satisfiable=0. Caller checks these fields: 416 when
 *       present==1 && satisfiable==0.
 *
 * Input: hdr_val/hdr_len — raw Range header value (e.g. "bytes=0-499"). Pass NULL/0 if no
 *        Range header is present. file_size — st_size of the file for clamping/satisfiability.
 */
void brix_http_parse_range(const unsigned char *hdr_val, size_t hdr_len,
    off_t file_size, brix_http_range_t *out);

typedef struct {
    off_t  start;
    off_t  end;        /* inclusive */
    off_t  total;      /* declared total size, or -1 if "*" (unknown) */
    int    present;    /* 1 if a well-formed Content-Range was parsed */
} brix_http_content_range_t;

/*
 * WHAT: Parse a request "Content-Range: bytes <start>-<end>/<total>" header
 *       (the resumable-PUT form; <total> may be "*").  Used by WebDAV PUT to
 *       place a chunk at an absolute offset for upload resume.
 *
 * HOW:  Strict grammar — optional "bytes " prefix, decimal start, '-', decimal
 *       end (>= start), '/', then decimal total or '*'.  On any deviation
 *       out->present stays 0 (caller treats the PUT as a whole-body upload).
 *
 * Input: hdr_val/hdr_len — raw header value; NULL/0 = absent.
 */
void brix_http_parse_content_range(const unsigned char *hdr_val,
    size_t hdr_len, brix_http_content_range_t *out);

#endif /* BRIX_COMPAT_RANGE_H */
