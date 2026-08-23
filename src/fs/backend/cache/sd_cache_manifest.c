/*
 * sd_cache_manifest.c — CVMFS manifest/whitelist signature verify on fill
 * (phase-85 F1: the verifying proxy).
 *
 * WHAT: Before a MANIFEST-class staged fill commits, verify the full CVMFS
 *       trust chain against the operator-configured repo master public key:
 *         .cvmfswhitelist  — signature vs master key + expiry;
 *         .cvmfspublished  — whitelist sig vs master → whitelist not expired →
 *                            manifest cert fingerprint ∈ whitelist → manifest
 *                            sig vs cert → repo-name cross-check.
 *       A failed chain never publishes: the caller quarantines the part,
 *       aborts the fill, emits signal=cvmfs_tamper and reports EBADMSG.
 *
 * WHY:  cvmfs-cas already makes every CAS object self-certifying at the edge,
 *       but the CAS *names* flow from the manifest — an origin (or MITM) that
 *       forges .cvmfspublished redirects every client to attacker-named
 *       content. Verifying the signature chain ONCE here protects every
 *       downstream client of this proxy, exactly as the FUSE client's mount
 *       path (shared/cvmfs/client/client.c load_trust_and_catalog) protects
 *       one mount. The verify primitives are the same shared pure-C code.
 *
 * HOW:  Runs on the blocking fill THREAD (like the cvmfs-cas verify), so the
 *       sibling fetches (.cvmfswhitelist, certificate CAS object) go straight
 *       through the source tier with plain blocking preads. All buffers are
 *       malloc'd (fill threads carry small stacks). The staged part is read
 *       from its posix staged_path — enforced at config time.
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"
#include "protocols/cvmfs/classify.h"
#include "cvmfs/grammar/hash.h"
#include "cvmfs/object/object.h"
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/verify.h"
#include "cvmfs/signature/whitelist.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Signed-metadata artifacts are small (manifest ~400B, whitelist ~1KB, cert
 * ~2KB); 64KB matches the FUSE client's raw_fetch bound and caps a hostile
 * origin's memory cost. */
#define SD_CACHE_META_MAX  65536

enum {
    META_UNSIGNED = 0,
    META_PUBLISHED,
    META_WHITELIST
};

/*
 * WHAT: Classify the signed metadata names handled by the cache trust gate.
 * WHY:  Keeping exact-name recognition separate makes the verifier linear.
 * HOW:  Compare the already-classified relative path against both wire names.
 */
static int
meta_signed_kind(const cvmfs_url_info_t *info)
{
    if (info->rel == NULL)
        return META_UNSIGNED;
    if (info->rel_len == sizeof(".cvmfspublished") - 1
        && memcmp(info->rel, ".cvmfspublished", info->rel_len) == 0)
        return META_PUBLISHED;
    if (info->rel_len == sizeof(".cvmfswhitelist") - 1
        && memcmp(info->rel, ".cvmfswhitelist", info->rel_len) == 0)
        return META_WHITELIST;
    return META_UNSIGNED;
}

/* Read the whole staged part at `pp` into a malloc'd buffer (cap
 * SD_CACHE_META_MAX). Returns the byte count, or -1 (oversize/unreadable). */
static ssize_t
meta_read_part(const char *pp, unsigned char **out)
{
    unsigned char *buf;
    ssize_t        n, off = 0;
    int            fd;

    fd = open(pp, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return -1;
    }
    buf = malloc(SD_CACHE_META_MAX);
    if (buf == NULL) {
        (void) close(fd);
        return -1;
    }
    for ( ;; ) {
        n = read(fd, buf + off, (size_t) (SD_CACHE_META_MAX - off));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {                          /* clean EOF within the cap */
            (void) close(fd);
            *out = buf;
            return off;
        }
        off += n;
        if (off >= SD_CACHE_META_MAX) {        /* oversize for signed meta */
            break;
        }
    }
    (void) close(fd);
    free(buf);
    return -1;
}

/* Fetch `key` COMPLETE from the source tier into a malloc'd buffer (cap
 * SD_CACHE_META_MAX). Blocking — fill-thread only. Returns the byte count,
 * or -1 on any failure (open, read, oversize). */
static ssize_t
meta_fetch_source(sd_cache_inst_state *st, const char *key,
    unsigned char **out)
{
    brix_sd_obj_t *so;
    unsigned char   *buf;
    ssize_t          n, off = 0;
    int              err = 0;

    if (st->source == NULL || st->source->driver->open == NULL) {
        return -1;
    }
    so = brix_sd_open_maybe_cred(st->source, key, BRIX_SD_O_READ, 0, NULL,
                                   &err);
    if (so == NULL || so->driver->pread == NULL) {
        if (so != NULL) {
            brix_sd_obj_release(so);
        }
        return -1;
    }
    buf = malloc(SD_CACHE_META_MAX);
    if (buf == NULL) {
        brix_sd_obj_release(so);
        return -1;
    }
    for ( ;; ) {
        n = so->driver->pread(so, buf + off,
                              (size_t) (SD_CACHE_META_MAX - off), off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            brix_sd_obj_release(so);
            *out = buf;
            return off;
        }
        off += n;
        if (off >= SD_CACHE_META_MAX) {
            break;
        }
    }
    brix_sd_obj_release(so);
    free(buf);
    return -1;
}

/* Parse `buf` as a whitelist and verify it against the policy master key +
 * wall-clock expiry. 0 on success; fills *out for the caller's fingerprint
 * check. */
static int
meta_check_whitelist(sd_cache_inst_state *st, const unsigned char *buf,
    size_t len, const char *key, cvmfs_whitelist_t *out)
{
    if (cvmfs_whitelist_parse(buf, len, out) != 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs whitelist for \"%s\" is malformed", key);
        return -1;
    }
    if (cvmfs_verify_whitelist(out, st->policy.cvmfs_master_pub,
                               st->policy.cvmfs_master_pub_len) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs whitelist for \"%s\" FAILED master-key "
            "signature verification", key);
        return -1;
    }
    if (cvmfs_whitelist_expired(out, (long) time(NULL))) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs whitelist for \"%s\" is EXPIRED", key);
        return -1;
    }
    return 0;
}

/*
 * WHAT: Verify that a signed manifest names the repository in its request key.
 * WHY:  A valid signature from repository A must not authorize a splice into B.
 * HOW:  Permit an omitted name, otherwise require exact length and bytes.
 */
static int
meta_manifest_repo_matches(const cvmfs_manifest_t *manifest,
    const cvmfs_url_info_t *info)
{
    if (manifest->repo_name[0] == '\0')
        return 1;
    return strlen(manifest->repo_name) == info->repo_len
           && strncmp(manifest->repo_name, info->repo, info->repo_len) == 0;
}

/*
 * WHAT: Check that the manifest certificate is admitted by the whitelist.
 * WHY:  Fingerprint calculation and membership form one trust-chain decision.
 * HOW:  Calculate the fingerprint and require its exact whitelist presence.
 */
static int
meta_certificate_allowed(const cvmfs_whitelist_t *whitelist,
    const unsigned char *pem, size_t pem_len, char *fingerprint,
    size_t fingerprint_cap)
{
    return cvmfs_cert_fingerprint(pem, pem_len, fingerprint,
                                  fingerprint_cap) == 0
           && cvmfs_whitelist_lists_fp(whitelist, fingerprint);
}

/* Verify a staged .cvmfspublished: parse, cross-check the repo name against
 * the fill key, fetch the live whitelist + signing cert through the source,
 * and run the full chain. 0 = verified, -1 = definitive reject (tamper),
 * -2 = the chain could not be evaluated (sibling fetch failed — an origin
 * fault, not evidence of tampering). */
static int
meta_check_manifest(sd_cache_inst_state *st, const char *key,
    const cvmfs_url_info_t *info, const unsigned char *buf, size_t len)
{
    cvmfs_manifest_t   m;
    cvmfs_whitelist_t  wl;
    unsigned char     *wlbuf = NULL, *cert = NULL, *pem = NULL;
    ssize_t            wln, certn;
    size_t             pemn = 0;
    char               fp[64];
    char               sib[1024];
    char               objp[160];
    int                n, rc = -1;

    if (cvmfs_manifest_parse(buf, len, &m) != 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs manifest \"%s\" is malformed", key);
        return -1;
    }
    /* The signed 'N' must name the repo the key claims — a valid manifest for
     * repo A must not publish under repo B's namespace (cross-repo splice). */
    if (!meta_manifest_repo_matches(&m, info)) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs manifest \"%s\" names repo \"%s\" — "
            "cross-repo splice rejected", key, m.repo_name);
        return -1;
    }

    /* Trust anchor: the repo's live whitelist, fetched through the SAME
     * source tier (ranked failover applies). */
    n = snprintf(sib, sizeof(sib), "/cvmfs/%.*s/.cvmfswhitelist",
                 (int) info->repo_len, info->repo);
    if (n <= 0 || (size_t) n >= sizeof(sib)) {
        return -1;
    }
    wln = meta_fetch_source(st, sib, &wlbuf);
    if (wln < 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cannot fetch \"%s\" to verify \"%s\"", sib, key);
        return -2;                           /* origin fault, not tamper */
    }
    if (meta_check_whitelist(st, wlbuf, (size_t) wln, key, &wl) != 0) {
        free(wlbuf);
        return -1;
    }

    /* Signing cert: the manifest's 'X' CAS object, inflated to PEM/DER. */
    if (cvmfs_hash_to_object_path(&m.certificate, 'X', objp,
                                  sizeof(objp)) < 0)
    {
        free(wlbuf);
        return -1;
    }
    n = snprintf(sib, sizeof(sib), "/cvmfs/%.*s/data/%s",
                 (int) info->repo_len, info->repo, objp);
    if (n <= 0 || (size_t) n >= sizeof(sib)) {
        free(wlbuf);
        return -1;
    }
    certn = meta_fetch_source(st, sib, &cert);
    if (certn < 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cannot fetch cert \"%s\" to verify \"%s\"", sib, key);
        free(wlbuf);
        return -2;                           /* origin fault, not tamper */
    }
    /* Stored cert objects are zlib-deflated; fall back to the raw bytes for
     * an uncompressed store (cvmfs_cert_fingerprint takes PEM or DER). */
    pem = malloc(SD_CACHE_META_MAX);
    if (pem == NULL
        || cvmfs_object_inflate(cert, (size_t) certn, pem,
                                SD_CACHE_META_MAX, &pemn) != 0)
    {
        free(pem);
        pem  = cert;
        pemn = (size_t) certn;
        cert = NULL;
    }

    if (!meta_certificate_allowed(&wl, pem, pemn, fp, sizeof(fp)))
    {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs manifest \"%s\" signing cert is NOT in the "
            "whitelist — rejected", key);
    } else if (cvmfs_verify_manifest(&m, pem, pemn) != 0) {
        ngx_log_error(NGX_LOG_WARN, st->log, 0,
            "sd_cache: cvmfs manifest \"%s\" FAILED certificate signature "
            "verification", key);
    } else {
        rc = 0;
    }

    free(cert);
    free(pem);
    free(wlbuf);
    return rc;
}

/* Verify a MANIFEST-class staged fill before commit (phase-85 F1). See the
 * declaration in sd_cache_internal.h for the contract; NGX_OK also covers
 * "not a signed-metadata shape" (.cvmfsreflog is unsigned) and "verify not
 * configured". */
ngx_int_t
sd_cache_verify_manifest(sd_cache_inst_state *st, const char *key,
    const char *pp)
{
    cvmfs_url_info_t   info;
    cvmfs_whitelist_t  wl;
    unsigned char     *buf = NULL;
    ssize_t            len;
    int                kind;
    ngx_int_t          rc;

    if (st->policy.cvmfs_master_pub == NULL
        || st->policy.cvmfs_master_pub_len == 0)
    {
        return NGX_OK;
    }
    (void) cvmfs_classify_url(key, strlen(key), &info);
    if (info.cls != CVMFS_URL_MANIFEST) {
        return NGX_OK;                       /* CAS/GEO — not this gate */
    }
    kind = meta_signed_kind(&info);
    if (kind == META_UNSIGNED) {
        return NGX_OK;                       /* .cvmfsreflog etc. — unsigned */
    }

    if (pp == NULL) {
        ngx_log_error(NGX_LOG_ERR, st->log, 0,
            "sd_cache: cvmfs manifest verify has no staged path for \"%s\" "
            "- failing the fill closed", key);
        return NGX_DECLINED;
    }
    len = meta_read_part(pp, &buf);
    if (len < 0) {
        ngx_log_error(NGX_LOG_ERR, st->log, errno,
            "sd_cache: cvmfs manifest verify cannot read the staged part "
            "for \"%s\" - failing the fill closed", key);
        return NGX_DECLINED;
    }

    if (kind == META_WHITELIST) {
        rc = (meta_check_whitelist(st, buf, (size_t) len, key, &wl) == 0)
           ? NGX_OK : NGX_ERROR;             /* every whitelist fail is
                                              * evaluated on the artifact
                                              * itself — definitive */
    } else {
        switch (meta_check_manifest(st, key, &info, buf, (size_t) len)) {
        case 0:   rc = NGX_OK;       break;
        case -2:  rc = NGX_DECLINED; break;
        default:  rc = NGX_ERROR;    break;
        }
    }
    free(buf);
    return rc;
}
