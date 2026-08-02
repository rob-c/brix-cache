/* bundle.h — CVMFS chunk-bundle wire framing (pure C, no ngx deps).
 *
 * WHAT: the phase-87 G2 batch-fetch frame format shared by the proxy endpoint
 *       (POST /cvmfs/<repo>/.cvmfs-bundle, src/protocols/cvmfs/bundle.c), the
 *       client-side ingest (fetch_bundle.c) and the standalone unit tests.
 * WHY:  one pure encoder/decoder keeps the two sides byte-identical and makes
 *       the parser testable without nginx or a network; integrity stays
 *       PER-OBJECT (each member is CAS-verified by the consumer against its
 *       own path-derived hash), so the framing itself carries no trust — a
 *       malformed stream aborts the parse and the caller falls back to
 *       single GETs.
 * HOW:  fixed little-endian encoding.  Stream:
 *         "BXB1" | u32 item_count
 *       then per item:
 *         u32 path_len | path bytes | u64 data_len | data bytes
 *       where data_len == CVMFS_BUNDLE_MISS (UINT64_MAX) marks a member the
 *       server did NOT include (absent / over budget) — no data bytes follow
 *       and the client fetches that object individually.
 */
#ifndef BRIX_CVMFS_BUNDLE_H
#define BRIX_CVMFS_BUNDLE_H

#include <stddef.h>
#include <stdint.h>

#define CVMFS_BUNDLE_MAGIC      "BXB1"
#define CVMFS_BUNDLE_HDR_LEN    8u            /* magic + u32 count            */
#define CVMFS_BUNDLE_MISS       UINT64_MAX    /* data_len marker: not included */

/* Policy caps, shared so client and server agree on "reasonable".  The bundle
 * is an RTT optimization for many small objects — anything large is better
 * served (ranged, sendfile) as a single GET. */
#define CVMFS_BUNDLE_MAX_ITEMS  512u          /* want-list lines per request  */
#define CVMFS_BUNDLE_MAX_PATH   512u          /* repo-relative path length    */
#define CVMFS_BUNDLE_MAX_OBJ    (8u << 20)    /* per-member stored-form bytes */
#define CVMFS_BUNDLE_MAX_TOTAL  (32u << 20)   /* whole-response data budget   */
#define CVMFS_BUNDLE_MAX_WANT   (64u << 10)   /* want-list request body bytes */

/* -- little-endian scalar codec (shared by both sides) -- */
void     cvmfs_bundle_put_u32(unsigned char *p, uint32_t v);
void     cvmfs_bundle_put_u64(unsigned char *p, uint64_t v);
uint32_t cvmfs_bundle_get_u32(const unsigned char *p);
uint64_t cvmfs_bundle_get_u64(const unsigned char *p);

/* Write the 8-byte stream header. `out` must hold CVMFS_BUNDLE_HDR_LEN. */
void cvmfs_bundle_hdr_encode(unsigned char *out, uint32_t item_count);

/* Write one item header (u32 path_len | path | u64 data_len) into `out`.
 * Returns the bytes written, or -1 if `cap` is too small or the path is
 * over CVMFS_BUNDLE_MAX_PATH.  Data bytes (when data_len is not the miss
 * marker) are appended by the caller — the server streams them from its
 * own buffers. */
int cvmfs_bundle_item_encode(unsigned char *out, size_t cap,
                             const char *path, size_t path_len,
                             uint64_t data_len);

/* One decoded member.  `data` points into the caller's stream buffer
 * (no copy); it is NULL for a miss marker. */
typedef struct {
    const char          *path;      /* NOT NUL-terminated                */
    size_t               path_len;
    const unsigned char *data;      /* NULL iff miss                     */
    uint64_t             data_len;  /* valid only when data != NULL      */
    int                  miss;      /* 1 = miss marker                   */
} cvmfs_bundle_item_t;

typedef struct {
    const unsigned char *p;         /* parse cursor                      */
    size_t               n;         /* bytes remaining                   */
    uint32_t             remaining; /* items still expected              */
} cvmfs_bundle_iter_t;

/* Bind an iterator over a complete stream.  Returns 0, or -1 on a bad
 * magic / truncated header / item count over CVMFS_BUNDLE_MAX_ITEMS. */
int cvmfs_bundle_iter_init(cvmfs_bundle_iter_t *it,
                           const unsigned char *stream, size_t len);

/* Next member: 1 = item filled, 0 = clean end of stream, -1 = malformed
 * (truncation, oversize path/member, trailing garbage).  Fail-closed: any
 * -1 means the whole stream is untrusted and the caller falls back to
 * single-object fetches. */
int cvmfs_bundle_next(cvmfs_bundle_iter_t *it, cvmfs_bundle_item_t *item);

#endif /* BRIX_CVMFS_BUNDLE_H */
