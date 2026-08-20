/* rpm_classify.h — the RPM/dnf repository route classifier (phase-104 D15.9).
 *
 * WHAT: turn one decoded request URI into a typed repository route — which of
 *       the four object classes a dnf client is asking for, and, for the
 *       digest-named metadata files, the checksum their own name carries.
 * WHY:  an RPM repository is static HTTP with exactly one interesting
 *       property: the file NAMES say which objects are immutable. repomd.xml
 *       is the mutable freshness root; everything createrepo writes beside it
 *       is `<checksum>-<name>`, so its name IS its digest; packages are
 *       immutable in practice and verified client-side. Every cache decision
 *       the mirror makes — TTL vs forever, verify-at-edge vs trust — is that
 *       one distinction, so it is read exactly once, here, at the edge. The
 *       traversal defense rides along: a path that classifies cannot escape
 *       the store, because the grammar rejects every component that could.
 * HOW:  pure C over the decoded URI — no nginx types, no allocation, spans
 *       point into the caller's buffer. That is what lets the fill-side
 *       verify (src/fs/cache/verify.c) and the cache TTL policy
 *       (sd_cache_policy.c) re-read a cache key with the SAME grammar the
 *       gate used, rather than each growing its own idea of what a repodata
 *       path looks like.
 */
#ifndef BRIX_PROTOCOLS_RPM_CLASSIFY_H
#define BRIX_PROTOCOLS_RPM_CLASSIFY_H

#include <stddef.h>

/* The canonical key is the request URI verbatim (§D15.9.3), so the cap is a
 * path cap: mirror trees nest deep (dist/version/repo/arch/os/Packages/x/…)
 * but never past this, and an over-long path is refused rather than truncated
 * into a different object's name. */
#define BRIX_RPM_PATH_MAX 1024

typedef enum {
    BRIX_RPM_REQ_REPOMD = 0,  /* …/repodata/repomd.xml[.asc|.key] — mutable  */
    BRIX_RPM_REQ_METADATA,    /* …/repodata/<hex>-<name> — self-addressing   */
    BRIX_RPM_REQ_PACKAGE,     /* …/<pkg>.rpm | .drpm — immutable             */
    BRIX_RPM_REQ_AUX,         /* every other legal repo file — mutable       */
    BRIX_RPM_REQ_BAD,         /* refused; `err` says why                     */
    BRIX_RPM_REQ_COUNT
} brix_rpm_class_t;

typedef enum {
    BRIX_RPM_ERR_NONE = 0,
    BRIX_RPM_ERR_PATH_INVALID,   /* traversal, empty component, bad byte    */
    BRIX_RPM_ERR_PATH_TOO_LONG,  /* past BRIX_RPM_PATH_MAX                  */
    BRIX_RPM_ERR_NOT_A_FILE      /* directory-shaped: a mirror serves files */
} brix_rpm_err_t;

typedef struct {
    brix_rpm_class_t  cls;
    brix_rpm_err_t    err;                    /* set iff cls == _BAD        */
    const char       *file;   size_t file_len; /* the last component        */
    const char       *hex;    size_t hex_len;  /* METADATA: its own checksum */
} brix_rpm_req_t;

/* Classify `uri` (DECODED, NUL-termination not required). Returns 0 with
 * out->cls naming a route, or -1 with out->cls == BRIX_RPM_REQ_BAD and
 * out->err naming the refusal. `uri` must outlive `*out`: the spans point
 * into it. */
int brix_rpm_classify(const char *uri, size_t len, brix_rpm_req_t *out);

/* The checksum algorithm a digest-named metadata file is named under, decided
 * by the hex length createrepo wrote — sha1 (40), sha256 (64), sha384 (96),
 * sha512 (128). NULL for any other length, which is what keeps a file merely
 * BEGINNING with hex digits from being verified against the wrong function. */
const char *brix_rpm_alg_for_hexlen(size_t hex_len);

/* Stable lowercase token for the route — metric label and log field. */
const char *brix_rpm_class_str(brix_rpm_class_t cls);

/* 1 iff this class is MUTABLE and must therefore expire on a TTL rather than
 * live in the cache forever. The mirror, the cache TTL policy and the docs
 * all ask this question; asking it in one place is what stops them drifting. */
int brix_rpm_class_is_mutable(brix_rpm_class_t cls);

#endif /* BRIX_PROTOCOLS_RPM_CLASSIFY_H */
