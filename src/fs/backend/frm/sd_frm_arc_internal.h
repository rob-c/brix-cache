/*
 * sd_frm_arc_internal.h — shared state of the dataset archiver adapter
 * (sd_frm_arc.c: vtable + key grammar; sd_frm_arc_store.c: sidecar, seal,
 * extract). Not for use outside src/fs/backend/frm/.
 */

#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_ARC_INTERNAL_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_ARC_INTERNAL_H

#include "sd_frm_arc.h"
#include "sd_frm_mss.h"
#include "frm_zip.h"

#include <limits.h>

typedef struct {
    const brix_mss_adapter_t *inner;
    void                     *ictx;
    ngx_log_t                *log;      /* may be NULL (C harness) */
    unsigned                  depth;
    char                      base[PATH_MAX];
} arc_ctx_t;

typedef enum {
    ARC_KEY_PLAIN = 0,      /* at most `depth` components: per-file, as before */
    ARC_KEY_MEMBER,         /* inside a dataset */
    ARC_KEY_MARKER,         /* <dataset>/.brix-dataset-complete */
    ARC_KEY_RESERVED        /* ends in .brixarc.zip: the adapter's own object */
} arc_kind_t;

typedef struct {
    arc_kind_t  kind;
    const char *key;                    /* the key exactly as the driver passed it */
    const char *member;                 /* MEMBER/MARKER: name inside the dataset  */
    char        ds[BRIX_ZIP_NAME_MAX];  /* "/<first depth components>"             */
} arc_key_t;

#define ARC_LOG(c, level, err, ...)                                          \
    do {                                                                     \
        if ((c)->log != NULL) {                                              \
            ngx_log_error(level, (c)->log, err, __VA_ARGS__);                \
        }                                                                    \
    } while (0)

/* key grammar (sd_frm_arc.c) */
arc_kind_t arc_classify(const arc_ctx_t *c, const char *key, arc_key_t *out);
int  arc_is_dataset_dir(const arc_ctx_t *c, const char *key);
int  arc_archive_key(const arc_key_t *k, char *out, size_t cap);
int  arc_sidecar_path(const arc_ctx_t *c, const char *ds, char *out, size_t cap);
int  arc_sealed(const arc_ctx_t *c, const char *ds);
/* 2.0 F3 (sd_frm_arc_seal.c): a marker is in the online buffer and the
 * dataset is not sealed yet -- members are frozen, the seal is queued. */
int  arc_pending(const arc_ctx_t *c, const char *ds);
/* the write-side vtable slots (sd_frm_arc_seal.c) */
int  arc_migrate(void *mss, const char *key);
int  arc_create_online(void *mss, const char *key, mode_t mode);
int  arc_seal(void *mss, const char *key);

/* sidecar + archive I/O (sd_frm_arc_store.c) */
/* 1 found (e, sealed_at filled) / 0 sealed but not a member / -1 errno
 * (ENOENT: no sidecar — the dataset is unsealed or its index was lost). */
int  arc_sidecar_lookup(const arc_ctx_t *c, const char *ds, const char *member,
         brix_zip_entry_t *e, time_t *sealed_at);
int  arc_sidecar_write(const arc_ctx_t *c, const char *ds,
         brix_zip_entry_t *ents, unsigned n);
int  arc_sidecar_names(const arc_ctx_t *c, const char *ds,
         int (*cb)(void *ud, const char *name), void *ud);
/* Seal dataset k->ds (k is its MARKER): 0 / -1 errno (EEXIST already sealed,
 * EFBIG too many members, EIO/ENOSPC/... from the copy or the inner migrate). */
int  arc_compose(arc_ctx_t *c, const arc_key_t *k);
/* Extract MEMBER k from the dataset's ONLINE archive into the online buffer
 * through inner->create_online; rebuilds a lost sidecar on the way. 0 / -1
 * errno (ENOENT: not in the archive). */
int  arc_extract(arc_ctx_t *c, const arc_key_t *k);
/* sync_publish vtable slot (W3.1 barrier fix; body in sd_frm_arc_store.c). */
int  arc_sync_publish(void *mss, const char *key);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_ARC_INTERNAL_H */
