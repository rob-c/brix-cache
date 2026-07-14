/*
 * stage_request_registry.c — durable tape/prepare request registry (Task 4):
 * the durable-store SUBSTRATE + lifecycle.
 *
 * See stage_request_registry.h for the contract. This is the FRM-dissolution
 * re-home of the FRM queue (former src/frm/queue.c + reqfile.c + reqid.c): a
 * fixed-slot, crash-durable request file keyed by reqid, backing kXR_prepare and
 * the WebDAV Tape REST API. The recall/stage TRANSFER is the stage_engine's job;
 * this store owns only the client-facing request METADATA + lifecycle.
 *
 * This translation unit owns the low-level substrate (durable file I/O, whole-
 * store locking, the fixed-slot scan/alloc, reqid/status/view translation) and
 * the lifecycle (singleton + init). The client-facing ops were split out at
 * phase-79 to hold every file under the 500-line cap and are reached back into
 * this substrate through stage_request_registry_internal.h:
 *   - stage_request_registry_mutate.c — add / set_status / cancel / delete /
 *     reap / reqid_generate (the write side)
 *   - stage_request_registry_query.c  — get / find_by_path / owner_check /
 *     list_active / list_files / pin_release (the read side)
 * The substrate helpers those files call were formerly static and are now extern
 * (declared in the internal header); nothing else changed — the lock/unlock
 * boundaries, WAL ordering, and slot math are identical.
 *
 * DESIGN (inherited verbatim from the proven FRM reqfile, so the on-disk math and
 * crash semantics are unchanged):
 *   - The file is a flat array of SRQ_REC_SIZE slots; slot 0 is the header, record
 *     N is at (N+1)*SRQ_REC_SIZE. A fixed size => O(1) pwrite by offset.
 *   - Per-record CRC32c + a self-offset field make a torn write DETECTABLE.
 *   - COMMIT POINT is the header write: a record body is pwritten+fdatasync'd, then
 *     the header (seq) is pwritten+fsync'd to publish it (WAL ordering).
 *   - Serialization: a per-worker pthread mutex (threads of this worker) then a
 *     whole-file fcntl lock on a <path>.lock sidecar (cross-worker). Order is
 *     always mutex -> fcntl.
 *   - Lookups are a linear slot scan (the FRM SHM index was a rebuildable cache;
 *     it is intentionally NOT relocated — admissions/cancels are rare and the file
 *     is bounded to the high-water-mark of concurrent requests).
 */

#include "stage_request_registry.h"
#include "stage_request_registry_internal.h"

#include "core/compat/crc32c.h"
#include "fs/backend/sd.h"   /* route the journal byte I/O through the SD seam */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* Layout pins — a negative array size is a hard error if the struct drifts. The
 * on-disk format itself now lives in stage_request_registry_internal.h. */
typedef char srq_hdr_size_check[(sizeof(srq_hdr_t) == SRQ_REC_SIZE) ? 1 : -1];
typedef char srq_rec_size_check[(sizeof(srq_rec_t) == SRQ_REC_SIZE) ? 1 : -1];


/* Process-wide singleton (one durable store per server). */
static brix_stage_registry_t  srq_singleton;
static int                      srq_singleton_used;

/*
 * In-process serialization. POSIX fcntl locks are owned by the PROCESS, so they do
 * not mutually exclude threads of the same worker; this mutex does. Lock order is
 * always pthread-mutex -> fcntl.
 */
static pthread_mutex_t  srq_file_mtx = PTHREAD_MUTEX_INITIALIZER;


/* CRC helpers */

static uint32_t
srq_rec_compute_crc(const srq_rec_t *rec)
{
    srq_rec_t tmp = *rec;
    tmp.rec_crc32c = 0;
    return brix_crc32c_value(&tmp, sizeof(tmp));
}

static uint32_t
srq_hdr_compute_crc(const srq_hdr_t *hdr)
{
    srq_hdr_t tmp = *hdr;
    tmp.hdr_crc32c = 0;
    return brix_crc32c_value(&tmp, sizeof(tmp));
}

static void
srq_rec_stamp_crc(srq_rec_t *rec)
{
    rec->rec_crc32c = (uint64_t) srq_rec_compute_crc(rec);
}

int
srq_rec_valid(const srq_rec_t *rec, int64_t expect_off)
{
    if (expect_off >= 0 && rec->self != expect_off) {
        return 0;
    }
    return rec->rec_crc32c == (uint64_t) srq_rec_compute_crc(rec);
}

static void
srq_hdr_init_blank(srq_hdr_t *hdr, time_t now)
{
    ngx_memzero(hdr, sizeof(*hdr));
    hdr->magic       = SRQ_MAGIC;
    hdr->version     = SRQ_VERSION;
    hdr->rec_size    = SRQ_REC_SIZE;
    hdr->seq         = 0;
    hdr->generation  = 1;
    hdr->created_tod = (int64_t) now;
}


/* full-buffer pread / pwrite (plain fd — this journal file is svc-owned, not an
 * export object, so it is a vfs-seam-allow raw site like the FRM journal was) */

static ngx_int_t
srq_pread_all(int fd, void *buf, size_t len, off_t off, ngx_log_t *log)
{
    u_char         *p = buf;
    brix_sd_obj_t obj;

    /* Route the journal byte read through the Storage Driver seam so the syscall
     * stays in the backend (src/fs/backend/), same as the former FRM reqfile. */
    brix_sd_posix_wrap(&obj, fd);
    while (len > 0) {
        ssize_t n = obj.driver->pread(&obj, p, len, off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "stage-req: pread failed");
            return NGX_ERROR;
        }
        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "stage-req: short pread");
            return NGX_ERROR;
        }
        p += n; len -= (size_t) n; off += n;
    }
    return NGX_OK;
}

static ngx_int_t
srq_pwrite_all(int fd, const void *buf, size_t len, off_t off, ngx_log_t *log)
{
    const u_char   *p = buf;
    brix_sd_obj_t obj;

    brix_sd_posix_wrap(&obj, fd);
    while (len > 0) {
        ssize_t n = obj.driver->pwrite(&obj, p, len, off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "stage-req: pwrite failed");
            return NGX_ERROR;
        }
        p += n; len -= (size_t) n; off += n;
    }
    return NGX_OK;
}


/* header + record I/O */

ngx_int_t
srq_hdr_read(brix_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log)
{
    if (srq_pread_all(reg->fd, hdr, sizeof(*hdr), 0, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (hdr->magic != SRQ_MAGIC || hdr->version > SRQ_VERSION
        || hdr->rec_size != SRQ_REC_SIZE
        || hdr->hdr_crc32c != srq_hdr_compute_crc(hdr))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "stage-req: \"%s\" is not a valid request store "
                      "(bad magic/version/crc)", reg->path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
srq_hdr_write(brix_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log)
{
    hdr->magic    = SRQ_MAGIC;
    hdr->version  = SRQ_VERSION;
    hdr->rec_size = SRQ_REC_SIZE;
    hdr->hdr_crc32c = srq_hdr_compute_crc(hdr);
    if (srq_pwrite_all(reg->fd, hdr, sizeof(*hdr), 0, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (fsync(reg->fd) != 0) {          /* the commit point — make it durable */
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "stage-req: header fsync");
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
srq_rec_read(brix_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
             ngx_log_t *log)
{
    if (off < (int64_t) SRQ_REC_SIZE) {
        return NGX_ERROR;
    }
    return srq_pread_all(reg->fd, rec, sizeof(*rec), (off_t) off, log);
}

ngx_int_t
srq_rec_write(brix_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
              ngx_log_t *log)
{
    if (off < (int64_t) SRQ_REC_SIZE) {
        return NGX_ERROR;
    }
    rec->self = off;
    srq_rec_stamp_crc(rec);
    if (srq_pwrite_all(reg->fd, rec, sizeof(*rec), (off_t) off, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (fdatasync(reg->fd) != 0) {      /* body durable before the header (WAL) */
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "stage-req: record fdatasync");
        return NGX_ERROR;
    }
    return NGX_OK;
}

int64_t
srq_file_size(brix_stage_registry_t *reg)
{
    struct stat st;
    if (reg->fd < 0 || fstat(reg->fd, &st) != 0) {
        return -1;
    }
    return (int64_t) st.st_size;
}


/* locking */

ngx_int_t
srq_lock(brix_stage_registry_t *reg, srq_lock_t mode)
{
    struct flock fl;
    int          rc;

    pthread_mutex_lock(&srq_file_mtx);
    if (reg->lock_fd < 0) {
        return NGX_OK;                  /* no file lock; mutex still held */
    }
    ngx_memzero(&fl, sizeof(fl));
    fl.l_type   = (mode == SRQ_LK_EXCL) ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    do {
        rc = fcntl(reg->lock_fd, F_SETLKW, &fl);
    } while (rc < 0 && errno == EINTR);
    if (rc != 0) {
        pthread_mutex_unlock(&srq_file_mtx);
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
srq_unlock(brix_stage_registry_t *reg)
{
    struct flock fl;

    if (reg->lock_fd >= 0) {
        ngx_memzero(&fl, sizeof(fl));
        fl.l_type   = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start  = 0;
        fl.l_len    = 0;
        (void) fcntl(reg->lock_fd, F_SETLK, &fl);
    }
    pthread_mutex_unlock(&srq_file_mtx);
}


/* reqid + record <-> view translation */

void
srq_reqid_format(const char *host, uint64_t seq, char *buf, size_t buf_sz)
{
    u_char *p;

    if (buf == NULL || buf_sz == 0) {
        return;
    }
    /* ngx_snprintf (not libc) truncates safely; the host is deliberately clipped
     * to fit — uniqueness rests on the durable seq, not the host string. */
    p = ngx_snprintf((u_char *) buf, buf_sz - 1, "%uL.%P@%s",
                     seq, ngx_pid, (host && host[0]) ? host : "localhost");
    *p = '\0';
}

/* On-disk SRQ_ST_* -> public status. FREE has no public value (never surfaced). */
static brix_stage_req_status_t
srq_status_public(uint8_t on_disk)
{
    switch (on_disk) {
    case SRQ_ST_QUEUED:    return BRIX_STAGE_REQ_QUEUED;
    case SRQ_ST_STAGING:   return BRIX_STAGE_REQ_ACTIVE;
    case SRQ_ST_ONLINE:    return BRIX_STAGE_REQ_DONE;
    case SRQ_ST_FAILED:    return BRIX_STAGE_REQ_FAILED;
    case SRQ_ST_CANCELLED: return BRIX_STAGE_REQ_CANCELLED;
    default:               return BRIX_STAGE_REQ_QUEUED;
    }
}

uint8_t
srq_status_on_disk(brix_stage_req_status_t pub)
{
    switch (pub) {
    case BRIX_STAGE_REQ_QUEUED:    return SRQ_ST_QUEUED;
    case BRIX_STAGE_REQ_ACTIVE:    return SRQ_ST_STAGING;
    case BRIX_STAGE_REQ_DONE:      return SRQ_ST_ONLINE;
    case BRIX_STAGE_REQ_FAILED:    return SRQ_ST_FAILED;
    case BRIX_STAGE_REQ_CANCELLED: return SRQ_ST_CANCELLED;
    default:                         return SRQ_ST_QUEUED;
    }
}

void
srq_rec_to_view(const srq_rec_t *rec, brix_stage_request_t *out)
{
    ngx_memzero(out, sizeof(*out));
    ngx_cpystrn((u_char *) out->reqid, (u_char *) rec->reqid, sizeof(out->reqid));
    ngx_cpystrn((u_char *) out->lfn, (u_char *) rec->lfn, sizeof(out->lfn));
    ngx_cpystrn((u_char *) out->requester_dn, (u_char *) rec->requester_dn,
                sizeof(out->requester_dn));
    out->cs_type    = (brix_stage_cstype_t) rec->cs_type;
    out->status     = srq_status_public(rec->status);
    out->tod_added  = rec->tod_added;
    out->tod_expire = rec->tod_expire;
}

/* Resolve a reqid -> file offset by a linear slot scan. -1 on miss/error. */
int64_t
srq_offset_by_reqid(brix_stage_registry_t *reg, const char *reqid,
                    ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off, size = srq_file_size(reg);

    for (off = SRQ_REC_OFF(0);
         size > 0 && off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            return -1;
        }
        if (srq_rec_valid(&rec, off) && rec.status != SRQ_ST_FREE
            && ngx_strcmp(rec.reqid, reqid) == 0)
        {
            return off;
        }
    }
    return -1;
}

/* First FREE/torn slot, else EOF (grow). Caller holds the excl lock. */
int64_t
srq_alloc_slot(brix_stage_registry_t *reg, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   size = srq_file_size(reg);
    int64_t   off;

    if (size < 0) {
        return -1;
    }
    for (off = SRQ_REC_OFF(0);
         off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            return -1;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE) {
            return off;
        }
    }
    return (size < SRQ_REC_OFF(0)) ? SRQ_REC_OFF(0) : size;
}


/* lifecycle */

brix_stage_registry_t *
brix_stage_registry_singleton(void)
{
    return srq_singleton_used ? &srq_singleton : NULL;
}

ngx_int_t
brix_stage_registry_init(const char *journal_dir, ngx_log_t *log)
{
    brix_stage_registry_t *reg = &srq_singleton;
    char                     lockpath[NGX_MAX_PATH];
    struct stat              st;
    size_t                   dlen;

    if (reg->inited) {
        return NGX_OK;                  /* idempotent */
    }
    if (journal_dir == NULL) {
        return NGX_ERROR;
    }
    dlen = ngx_strlen(journal_dir);
    if (dlen == 0 || dlen + sizeof("/stage_requests.dat") >= sizeof(reg->path)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "stage-req: journal dir too long");
        return NGX_ERROR;
    }
    *ngx_snprintf((u_char *) reg->path, sizeof(reg->path) - 1,
                  "%s/stage_requests.dat", journal_dir) = '\0';
    reg->fd      = -1;
    reg->lock_fd = -1;
    if (gethostname(reg->host, sizeof(reg->host)) != 0) {
        ngx_memcpy(reg->host, "localhost", sizeof("localhost"));
    }
    reg->host[sizeof(reg->host) - 1] = '\0';

    reg->fd = open(reg->path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (reg->fd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "stage-req: cannot open \"%s\"", reg->path);
        return NGX_ERROR;
    }
    *ngx_snprintf((u_char *) lockpath, sizeof(lockpath) - 1,
                  "%s.lock", reg->path) = '\0';
    reg->lock_fd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (reg->lock_fd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "stage-req: cannot open \"%s\"", lockpath);
        close(reg->fd);
        reg->fd = -1;
        return NGX_ERROR;
    }
    if (fstat(reg->fd, &st) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "stage-req: fstat");
        close(reg->fd); close(reg->lock_fd); reg->fd = reg->lock_fd = -1;
        return NGX_ERROR;
    }
    if (st.st_size == 0) {
        srq_hdr_t hdr;
        srq_hdr_init_blank(&hdr, time(NULL));
        if (srq_hdr_write(reg, &hdr, log) != NGX_OK) {
            close(reg->fd); close(reg->lock_fd); reg->fd = reg->lock_fd = -1;
            return NGX_ERROR;
        }
    }
    reg->inited      = 1;
    srq_singleton_used = 1;
    return NGX_OK;
}
