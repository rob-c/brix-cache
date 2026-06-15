#ifndef NGX_XROOTD_FRM_INTERNAL_H
#define NGX_XROOTD_FRM_INTERNAL_H

/*
 * frm_internal.h — internal contract shared by the FRM engine files
 * (reqfile.c, index.c, reconcile.c, compact.c, reqid.c, queue.c). Not included
 * outside src/frm/.
 *
 * Layering: queue.c is the façade; it orchestrates reqfile.c (the durable file =
 * truth) and index.c (the SHM hot index = cache) in authority order — mutate the
 * file under the fcntl lock first, then patch the index. reconcile.c rebuilds the
 * index from the file at master start; compact.c rewrites the file densely.
 *
 * Phase 0 supports a SINGLE configured queue (the common gateway case). The SHM
 * index zone + its mutex are file-static in index.c; frm_queue_s carries only the
 * process-local file descriptors + cached host. The frm_queue_t * parameter is
 * threaded through for forward-compatibility with multi-queue support.
 */

#include "frm.h"
/* The engine .c files need the module symbol (ngx_stream_xrootd_module), the
 * event/timer API, and ngx_worker — pull the full umbrella here. Safe because
 * frm_internal.h is included ONLY by the src/frm engine units, never config.h. */
#include "../ngx_xrootd_module.h"

#include <time.h>

#define NGX_XROOTD_FRM_PATH_MAX  4096

/* ---- per-process queue handle ---------------------------------------------*/
struct frm_queue_s {
    ngx_str_t   path;          /* queue file path (NUL-terminated data)       */
    int         fd;            /* O_RDWR fd on the queue file (per-process)    */
    int         lock_fd;       /* fd on <path>.lock for the fcntl whole-file lock*/
    ngx_uint_t  max_inflight;  /* admission cap (QUEUED+STAGING)               */
    ngx_uint_t  max_per_source;/* per-requester_dn admission cap (0 = off, F4) */
    char        host[40];      /* cached short hostname for reqid             */
    unsigned    inited:1;      /* frm_queue_init() has run                     */
};

/* ---- SHM hot index (index.c) ----------------------------------------------*/
typedef struct {
    char        reqid[FRM_REQID_LEN];
    uint64_t    lfn_hash;     /* FNV-1a of lfn — dedup-by-path                */
    int64_t     file_off;     /* byte offset of the record in the file        */
    int64_t     tod_added;
    int64_t     tod_expire;
    ngx_msec_t  last_seen;    /* LRU reaper bookkeeping                       */
    uint8_t     status;       /* frm_status_t mirror                         */
    int8_t      priority;
    uint8_t     queue;
    uint8_t     in_use;
} frm_index_entry_t;

typedef struct {
    ngx_shmtx_sh_t     lock;        /* MUST be first (ngx_shmtx_create)       */
    uint64_t           generation;  /* must equal the file header generation  */
    ngx_uint_t         capacity;
    ngx_uint_t         count;
    uint64_t           reconcile_full_total;
    frm_index_entry_t  slots[];
} frm_index_table_t;

frm_index_table_t *frm_index_table(void);
ngx_shmtx_t       *frm_index_mutex(void);
void               frm_index_insert(const frm_record_t *rec);
int                frm_index_lookup(const char *reqid, int64_t *file_off_out);
int                frm_index_lookup_path(uint64_t lfn_hash, int wantlive,
                                         int64_t *file_off_out);
void               frm_index_remove(const char *reqid);
void               frm_index_update(const char *reqid, uint8_t status,
                                    int64_t tod_expire);
void               frm_index_clear(void);
ngx_uint_t         frm_index_count(void);
uint64_t           frm_lfn_hash(const char *lfn);

/* ---- reqfile.c (durable file engine) --------------------------------------*/
typedef enum { FRM_LK_NONE = 0, FRM_LK_SHARE, FRM_LK_EXCL } frm_lock_t;

ngx_int_t  frm_file_open(frm_queue_t *q, ngx_log_t *log);   /* per-process open */
void       frm_file_close(frm_queue_t *q);
ngx_int_t  frm_file_lock(frm_queue_t *q, frm_lock_t mode);
void       frm_file_unlock(frm_queue_t *q);

ngx_int_t  frm_hdr_read(frm_queue_t *q, frm_file_hdr_t *hdr, ngx_log_t *log);
ngx_int_t  frm_hdr_write(frm_queue_t *q, frm_file_hdr_t *hdr, ngx_log_t *log);
void       frm_hdr_init_blank(frm_file_hdr_t *hdr, time_t now);

ngx_int_t  frm_rec_read(frm_queue_t *q, int64_t off, frm_record_t *rec,
                        ngx_log_t *log);
ngx_int_t  frm_rec_write(frm_queue_t *q, int64_t off, frm_record_t *rec,
                         ngx_log_t *log);

int64_t    frm_file_size(frm_queue_t *q);
int        frm_rec_valid(const frm_record_t *rec, int64_t expect_off);
void       frm_rec_stamp_crc(frm_record_t *rec);

/* offset of record N (N>=0): the header is slot 0, records start at slot 1. */
#define FRM_REC_OFF(n)   ((int64_t) FRM_REC_SIZE * ((int64_t) (n) + 1))

/* ---- queue.c (façade) ------------------------------------------------------*/
/* The Phase-0 single configured queue (NULL until frm_queue_get). Used by the
 * index zone-init callback to drive reconciliation. */
frm_queue_t *frm_singleton_queue(void);

/* ---- reqid.c ---------------------------------------------------------------*/
/* Pure formatter: "<seq>.<pid>@<host>" into buf (NUL-terminated, truncated). */
void       frm_reqid_format(const char *host, uint64_t seq,
                            char *buf, size_t buf_sz);

/* ---- reconcile.c / compact.c ----------------------------------------------*/
ngx_int_t  frm_reconcile(frm_queue_t *q, ngx_log_t *log);
ngx_int_t  frm_compact(frm_queue_t *q, ngx_log_t *log);
int        frm_compact_needed(const frm_file_hdr_t *hdr, int64_t file_size);

#endif /* NGX_XROOTD_FRM_INTERNAL_H */
