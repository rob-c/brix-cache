/* sd_remote_dir.c — S3 ListObjectsV2 directory listing for the remote backend.
 *
 * WHAT: opendir/readdir/closedir over the object catalog as a POSIX-shaped
 *       single directory level: <Contents> under the prefix are files,
 *       <CommonPrefixes> are sub-directories (phase-92 finding #4).
 *
 * WHY:  Split out of sd_remote.c, which crossed the 600-line cap
 *       (coding-standards §1). Paged listing carries its own state machine and
 *       page buffer, independent of the object read/write slots.
 *
 * HOW:  opendir derives the S3 key prefix with no I/O; readdir pages
 *       ListObjectsV2 lazily through the shared sd_s3_list_page, buffering one
 *       decoded page at a time; closedir frees the malloc-owned handle (this
 *       driver runs off the event loop, so there is no pool to hang it on). */


#include "sd_remote.h"
#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>


/* ---- directory listing (S3 ListObjectsV2, delimited + paged) --------------
 *
 * WHAT: opendir/readdir/closedir over the object catalog as a POSIX-shaped
 *       single directory level — <Contents> under the prefix are files,
 *       <CommonPrefixes> are sub-directories (finding #4).
 * WHY:  S3 has no readdir; a WebDAV PROPFIND / xrdfs ls / recursive walk over an
 *       s3:// export previously hit the NULL opendir slot and reported ENOTSUP.
 * HOW:  opendir derives the S3 key prefix from the export-relative path (no I/O)
 *       and readdir pages ListObjectsV2 lazily via the shared sd_s3_list_page,
 *       buffering one page of decoded basenames at a time; closedir frees the
 *       malloc-owned handle (this driver runs off the event loop with no pool).
 *       Object stores expose no per-object owner/mode, so d_type is DT_DIR for a
 *       CommonPrefixes entry and DT_REG otherwise — the VFS stats on anything it
 *       cannot classify, so a coarse d_type is a cheap hint, never authority. */
typedef struct {
    char           name[256];
    unsigned char  d_type;
} sd_remote_dirent;

/* Upper bounds for the copied per-user SigV4 credential below. ak/sk/region
 * match the ucred store's own limits; the STS session token has no small bound
 * in the API, so 4 KiB with a REFUSAL (never a truncation) on overflow — a
 * clipped session token would surface as an inscrutable SignatureDoesNotMatch
 * pages into the listing rather than as an error at opendir. */
#define SD_REMOTE_DIR_AK_MAX       128
#define SD_REMOTE_DIR_SK_MAX       256
#define SD_REMOTE_DIR_REGION_MAX    64
#define SD_REMOTE_DIR_SESSION_MAX  4096

typedef struct {
    brix_sd_instance_t *inst;
    char                prefix[768];   /* S3 key prefix, "" or "dir/" */
    char                cont[2048];    /* NextContinuationToken for the next page */
    int                 started;       /* fetched at least one page */
    int                 truncated;     /* more pages remain */
    sd_remote_dirent   *ents;          /* current page, grown on demand */
    size_t              n;
    size_t              cap;
    size_t              cursor;
    /* Per-user SigV4 credential, COPIED at opendir. The listing is paged lazily
     * from readdir, so the signing material has to outlive the opendir call that
     * borrowed *cred — the same lifetime trap sd_http_obj_state's bearer copy
     * documents. `have_cred` distinguishes "this handle signs as a user" from
     * "no credential" so an empty string is never mistaken for one. */
    int                 have_cred;
    char                ak     [SD_REMOTE_DIR_AK_MAX];
    char                sk     [SD_REMOTE_DIR_SK_MAX];
    char                region [SD_REMOTE_DIR_REGION_MAX];
    char                session[SD_REMOTE_DIR_SESSION_MAX];
} sd_remote_dir_state;

/* sd_s3_list_page callback: append one decoded entry to the page buffer. A
 * realloc failure stops the page (returns 1) and surfaces as a short page. */
static int
sd_remote_dir_add(void *ud, const char *name, int is_dir)
{
    sd_remote_dir_state *ds = ud;

    if (ds->n == ds->cap) {
        size_t nc = (ds->cap != 0) ? ds->cap * 2 : 64;
        void  *nb = realloc(ds->ents, nc * sizeof(*ds->ents));

        if (nb == NULL) {
            return 1;
        }
        ds->ents = nb;
        ds->cap  = nc;
    }
    snprintf(ds->ents[ds->n].name, sizeof(ds->ents[ds->n].name), "%s", name);
    ds->ents[ds->n].d_type = (unsigned char) (is_dir ? DT_DIR : DT_REG);
    ds->n++;
    return 0;
}

/* Fetch the next ListObjectsV2 page into the (reset) buffer. 0 / -1 (errno). */
static int
sd_remote_dir_fetch(sd_remote_dir_state *ds)
{
    const brix_sd_remote_cfg_t *cfg = ds->inst->state;
    sd_s3_open_params           p;
    char                        root[300];
    char                        cont_out[2048];
    char                        errbuf[256];
    int                         truncated = 0;

    snprintf(root, sizeof(root), "/%s/", cfg->bucket);  /* bucket-root canon URI */
    sd_remote_s3_params(cfg, root, &p);
    if (ds->have_cred) {
        /* Every page of this listing signs as the identity that opened it, not
         * as the export — including the continuation pages fetched long after
         * opendir returned. */
        sd_remote_params_cred(&p, ds->ak, ds->sk,
                              (ds->region[0] != '\0')  ? ds->region  : NULL,
                              (ds->session[0] != '\0') ? ds->session : NULL);
    }

    ds->n      = 0;
    ds->cursor = 0;
    errno      = 0;
    if (sd_s3_list_page(&p, ds->prefix, ds->started ? ds->cont : "",
            sd_remote_dir_add, ds, &truncated, cont_out, sizeof(cont_out),
            errbuf, sizeof(errbuf)) != 0)
    {
        if (errno == 0) { errno = EIO; }
        return -1;
    }
    ds->truncated = truncated;
    snprintf(ds->cont, sizeof(ds->cont), "%s", cont_out);
    ds->started = 1;
    return 0;
}

/* Copy one credential string into a fixed handle buffer. Returns 0, or -1 when
 * the value does not fit: a SILENTLY truncated key or session token signs a
 * request that the store rejects with an opaque SignatureDoesNotMatch, so the
 * only safe answer is to refuse the open. NULL/empty leaves the slot empty. */
static int
sd_remote_dir_copy_str(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (src == NULL || *src == '\0') {
        dst[0] = '\0';
        return 0;
    }
    n = strlen(src);
    if (n >= cap) {
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

/* Latch the requesting user's SigV4 material onto the handle. Returns 0 (signs
 * as the user), 1 (no credential to apply — sign as the export) or -1 with
 * *err_out set. */
static int
sd_remote_dir_take_cred(sd_remote_dir_state *ds, const brix_sd_cred_t *cred,
    int *err_out)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate < 0) {
        if (err_out != NULL) { *err_out = EACCES; }
        return -1;
    }
    if (gate == 0) {
        return 1;
    }
    if (sd_remote_dir_copy_str(ds->ak, sizeof(ds->ak), cred->s3_ak) != 0
        || sd_remote_dir_copy_str(ds->sk, sizeof(ds->sk), cred->s3_sk) != 0
        || sd_remote_dir_copy_str(ds->region, sizeof(ds->region),
                                  cred->s3_region) != 0
        || sd_remote_dir_copy_str(ds->session, sizeof(ds->session),
                                  cred->s3_session) != 0)
    {
        if (err_out != NULL) { *err_out = E2BIG; }
        return -1;
    }
    ds->have_cred = 1;
    return 0;
}

/* Wipe the copied secret before the handle's memory goes back to the allocator:
 * a freed page holding a live secret key is one heap re-use away from another
 * request's buffer. */
static void
sd_remote_dir_wipe_cred(sd_remote_dir_state *ds)
{
    OPENSSL_cleanse(ds->sk, sizeof(ds->sk));
    OPENSSL_cleanse(ds->session, sizeof(ds->session));
}

/* Shared body of opendir/opendir_cred: derive the key prefix (no I/O) and, when
 * a usable credential came in, latch it for the lazy pages readdir will fetch. */
static brix_sd_dir_t *
sd_remote_opendir_impl(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_remote_dir_state *ds;
    brix_sd_dir_t       *dir;
    const char          *rel = (path != NULL) ? path : "/";
    size_t               n;

    ds  = calloc(1, sizeof(*ds));
    dir = calloc(1, sizeof(*dir));
    if (ds == NULL || dir == NULL) {
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ds->inst = inst;

    if (cred != NULL && sd_remote_dir_take_cred(ds, cred, err_out) < 0) {
        sd_remote_dir_wipe_cred(ds);
        free(ds);
        free(dir);
        return NULL;
    }

    /* export-relative path -> S3 key prefix: drop the leading '/', ensure a
     * trailing '/' so LIST returns children of THIS level (root -> ""). */
    while (*rel == '/') { rel++; }
    n = strlen(rel);
    if (n + 1 >= sizeof(ds->prefix)) {
        sd_remote_dir_wipe_cred(ds);
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENAMETOOLONG; }
        return NULL;
    }
    memcpy(ds->prefix, rel, n);
    if (n > 0 && ds->prefix[n - 1] != '/') { ds->prefix[n++] = '/'; }
    ds->prefix[n] = '\0';

    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

brix_sd_dir_t *
sd_remote_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_remote_opendir_impl(inst, path, NULL, err_out);
}

/* Cred-scoped opendir: the whole listing runs as the requesting user.
 *
 * WHY: this driver already signed every namespace op (stat/mkdir/rename/unlink)
 *      and, since the metadata-read fix, every xattr read under the caller's own
 *      SigV4 keys — but opendir had no *_cred sibling, so brix_sd_opendir's
 *      forwarder fell through to the plain slot and LISTED THE BUCKET AS THE
 *      EXPORT. A user whose keys are scoped to one prefix saw every sibling
 *      prefix in the bucket, and the entries came back looking perfectly normal.
 * HOW: sd_remote_cred_gate classifies the credential exactly as the other slots
 *      do (usable keypair / unusable-under-deny / no S3 material), and the
 *      material is COPIED, because ListObjectsV2 is paged lazily from readdir
 *      long after *cred stops being ours to hold. */
brix_sd_dir_t *
sd_remote_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    return sd_remote_opendir_impl(inst, path, cred, err_out);
}

ngx_int_t
sd_remote_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_remote_dir_state *ds = d->state;

    for ( ;; ) {
        if (ds->cursor < ds->n) {
            snprintf(out->name, sizeof(out->name), "%s",
                     ds->ents[ds->cursor].name);
            out->d_type = ds->ents[ds->cursor].d_type;
            ds->cursor++;
            return NGX_OK;
        }
        if (ds->started && !ds->truncated) {
            return NGX_DONE;
        }
        if (sd_remote_dir_fetch(ds) != 0) {
            return NGX_ERROR;
        }
    }
}

ngx_int_t
sd_remote_closedir(brix_sd_dir_t *d)
{
    sd_remote_dir_state *ds;

    if (d == NULL || d->state == NULL) {
        return NGX_OK;
    }
    ds = d->state;
    sd_remote_dir_wipe_cred(ds);
    free(ds->ents);
    free(ds);
    d->state = NULL;
    free(d);           /* malloc-owned shell (no pool off the event loop) */
    return NGX_OK;
}
