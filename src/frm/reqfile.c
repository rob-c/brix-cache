/*
 * reqfile.c — the durable queue file engine (the source of truth).
 *
 * WHAT: Low-level read/write of the fixed-record queue file: open/close, the
 *   fcntl whole-file lock (on a <path>.lock sidecar), header and record
 *   pread/pwrite with CRC32c + fsync, and the torn-write validity check. Higher
 *   layers (queue.c, reconcile.c, compact.c) call these; they never touch the fd
 *   directly.
 *
 * WHY: A tape recall outlives the connection and the worker, so the request must
 *   land on disk durably. Fixed-size slots make the file a flat array: record N
 *   at FRM_REC_OFF(N); the header (slot 0) carries the active/free chain offsets.
 *   Per-record CRC32c + a self-offset field make a crash mid-write *detectable*
 *   on reconciliation (the official XrdFrcReqFile format has neither).
 *
 * HOW: The COMMIT POINT is the header write — a record body is pwritten +
 *   fdatasync'd first, then the header is pwritten + fsync'd to publish it. A
 *   crash between leaves an orphan body unreferenced by any chain (harmless; the
 *   slot is reclaimed by the next compaction). Locking uses POSIX F_SETLKW
 *   process locks on a per-worker lock fd, so distinct workers serialise; the
 *   master reconciles then drops its fds, so no inherited-fd lock hazard.
 */

#include "frm_internal.h"
#include "../fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "../compat/crc32c.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * In-process serialization. POSIX fcntl locks are owned by the PROCESS, so they
 * do NOT mutually exclude threads of the same process — but Phase 1 runs queue
 * mutations from the stage-worker thread-pool concurrently with the event loop.
 * This mutex serializes threads of THIS worker; the fcntl lock (below) adds
 * cross-process (cross-worker / cross-instance) serialization. Lock order is
 * always pthread-mutex → fcntl.
 */
static pthread_mutex_t frm_file_mtx = PTHREAD_MUTEX_INITIALIZER;


/* CRC32c of a record image with the rec_crc32c field treated as zero. */
static uint32_t
frm_rec_compute_crc(const frm_record_t *rec)
{
    frm_record_t tmp = *rec;
    tmp.rec_crc32c = 0;
    return xrootd_crc32c_value(&tmp, sizeof(tmp));
}

/* CRC32c of a header image with the hdr_crc32c field treated as zero. */
static uint32_t
frm_hdr_compute_crc(const frm_file_hdr_t *hdr)
{
    frm_file_hdr_t tmp = *hdr;
    tmp.hdr_crc32c = 0;
    return xrootd_crc32c_value(&tmp, sizeof(tmp));
}

void
frm_rec_stamp_crc(frm_record_t *rec)
{
    rec->rec_crc32c = (uint64_t) frm_rec_compute_crc(rec);
}

int
frm_rec_valid(const frm_record_t *rec, int64_t expect_off)
{
    if (expect_off >= 0 && rec->self != expect_off) {
        return 0;
    }
    return rec->rec_crc32c == (uint64_t) frm_rec_compute_crc(rec);
}

void
frm_hdr_init_blank(frm_file_hdr_t *hdr, time_t now)
{
    ngx_memzero(hdr, sizeof(*hdr));
    hdr->magic       = FRM_MAGIC;
    hdr->version     = FRM_VERSION;
    hdr->rec_size    = FRM_REC_SIZE;
    hdr->first       = 0;      /* empty active chain */
    hdr->last        = 0;
    hdr->free        = 0;      /* empty free list → grow at EOF */
    hdr->seq         = 0;
    hdr->generation  = 1;
    hdr->created_tod = (int64_t) now;
}


/* ---- open / close ---------------------------------------------------------*/

ngx_int_t
frm_file_open(frm_queue_t *q, ngx_log_t *log)
{
    char        lockpath[NGX_XROOTD_FRM_PATH_MAX];
    struct stat st;

    if (q->fd >= 0) {
        return NGX_OK;                  /* already open in this process */
    }
    if (q->path.len == 0 || q->path.len + 6 >= sizeof(lockpath)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "frm: invalid queue path");
        return NGX_ERROR;
    }

    q->fd = open((const char *) q->path.data,
                 O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (q->fd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "frm: open(\"%V\") failed", &q->path);
        return NGX_ERROR;
    }

    (void) ngx_snprintf((u_char *) lockpath, sizeof(lockpath) - 1,
                        "%V.lock%Z", &q->path);
    q->lock_fd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (q->lock_fd < 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "frm: open(\"%s\") failed", lockpath);
        close(q->fd);
        q->fd = -1;
        return NGX_ERROR;
    }

    /* Initialise a brand-new (zero-length) file with a blank header. */
    if (fstat(q->fd, &st) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "frm: fstat failed");
        frm_file_close(q);
        return NGX_ERROR;
    }
    if (st.st_size == 0) {
        frm_file_hdr_t hdr;
        frm_hdr_init_blank(&hdr, time(NULL));
        if (frm_hdr_write(q, &hdr, log) != NGX_OK) {
            frm_file_close(q);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

void
frm_file_close(frm_queue_t *q)
{
    if (q->fd >= 0)      { close(q->fd);      q->fd = -1; }
    if (q->lock_fd >= 0) { close(q->lock_fd); q->lock_fd = -1; }
}


/* ---- whole-file lock (on the .lock sidecar) -------------------------------*/

ngx_int_t
frm_file_lock(frm_queue_t *q, frm_lock_t mode)
{
    struct flock fl;
    int          rc;

    if (mode == FRM_LK_NONE) {
        return NGX_OK;
    }

    /* In-process serialization first (threads of this worker). */
    pthread_mutex_lock(&frm_file_mtx);

    if (q->lock_fd < 0) {
        return NGX_OK;                 /* no file lock; mutex still held */
    }
    ngx_memzero(&fl, sizeof(fl));
    fl.l_type   = (mode == FRM_LK_EXCL) ? F_WRLCK : F_RDLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;                    /* whole file */

    do {
        rc = fcntl(q->lock_fd, F_SETLKW, &fl);
    } while (rc < 0 && errno == EINTR);

    if (rc != 0) {
        pthread_mutex_unlock(&frm_file_mtx);
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
frm_file_unlock(frm_queue_t *q)
{
    struct flock fl;

    if (q->lock_fd >= 0) {
        ngx_memzero(&fl, sizeof(fl));
        fl.l_type   = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start  = 0;
        fl.l_len    = 0;
        (void) fcntl(q->lock_fd, F_SETLK, &fl);
    }
    pthread_mutex_unlock(&frm_file_mtx);
}


/* ---- full-buffer pread / pwrite -------------------------------------------*/

static ngx_int_t
frm_pread_all(int fd, void *buf, size_t len, off_t off, ngx_log_t *log)
{
    u_char         *p = buf;
    xrootd_sd_obj_t obj;

    xrootd_sd_posix_wrap(&obj, fd);   /* phase-55: SD seam */
    while (len > 0) {
        ssize_t n = xrootd_sd_posix_driver.pread(&obj, p, len, off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: pread failed");
            return NGX_ERROR;
        }
        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "frm: short pread (truncated)");
            return NGX_ERROR;
        }
        p += n; len -= (size_t) n; off += n;
    }
    return NGX_OK;
}

static ngx_int_t
frm_pwrite_all(int fd, const void *buf, size_t len, off_t off, ngx_log_t *log)
{
    const u_char   *p = buf;
    xrootd_sd_obj_t obj;

    xrootd_sd_posix_wrap(&obj, fd);   /* phase-55: SD seam */
    while (len > 0) {
        ssize_t n = xrootd_sd_posix_driver.pwrite(&obj, p, len, off);
        if (n < 0) {
            if (errno == EINTR) { continue; }
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: pwrite failed");
            return NGX_ERROR;
        }
        p += n; len -= (size_t) n; off += n;
    }
    return NGX_OK;
}


/* ---- header ---------------------------------------------------------------*/

ngx_int_t
frm_hdr_read(frm_queue_t *q, frm_file_hdr_t *hdr, ngx_log_t *log)
{
    if (frm_pread_all(q->fd, hdr, sizeof(*hdr), 0, log) != NGX_OK) {
        return NGX_ERROR;
    }
    if (hdr->magic != FRM_MAGIC) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "frm: bad magic 0x%08xD in \"%V\" — not an FRM queue",
                      hdr->magic, &q->path);
        return NGX_ERROR;
    }
    if (hdr->version > FRM_VERSION) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "frm: queue \"%V\" version %ud newer than supported %ud",
                      &q->path, hdr->version, FRM_VERSION);
        return NGX_ERROR;
    }
    if (hdr->rec_size != FRM_REC_SIZE) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "frm: queue \"%V\" rec_size %ud != %ud",
                      &q->path, hdr->rec_size, (ngx_uint_t) FRM_REC_SIZE);
        return NGX_ERROR;
    }
    if (hdr->hdr_crc32c != frm_hdr_compute_crc(hdr)) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "frm: queue \"%V\" header CRC mismatch", &q->path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
frm_hdr_write(frm_queue_t *q, frm_file_hdr_t *hdr, ngx_log_t *log)
{
    hdr->magic    = FRM_MAGIC;
    hdr->version  = FRM_VERSION;
    hdr->rec_size = FRM_REC_SIZE;
    hdr->hdr_crc32c = frm_hdr_compute_crc(hdr);
    if (frm_pwrite_all(q->fd, hdr, sizeof(*hdr), 0, log) != NGX_OK) {
        return NGX_ERROR;
    }
    /* The header write is the commit point — make it durable. */
    if (fsync(q->fd) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: header fsync failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}


/* ---- record ---------------------------------------------------------------*/

ngx_int_t
frm_rec_read(frm_queue_t *q, int64_t off, frm_record_t *rec, ngx_log_t *log)
{
    if (off < (int64_t) FRM_REC_SIZE) {
        return NGX_ERROR;               /* offset 0 is the header */
    }
    return frm_pread_all(q->fd, rec, sizeof(*rec), (off_t) off, log);
}

ngx_int_t
frm_rec_write(frm_queue_t *q, int64_t off, frm_record_t *rec, ngx_log_t *log)
{
    if (off < (int64_t) FRM_REC_SIZE) {
        return NGX_ERROR;
    }
    rec->self = off;
    frm_rec_stamp_crc(rec);
    if (frm_pwrite_all(q->fd, rec, sizeof(*rec), (off_t) off, log) != NGX_OK) {
        return NGX_ERROR;
    }
    /* Record body durable before the publishing header write (WAL ordering). */
    if (fdatasync(q->fd) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "frm: record fdatasync failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}


int64_t
frm_file_size(frm_queue_t *q)
{
    struct stat st;
    if (q->fd < 0 || fstat(q->fd, &st) != 0) {
        return -1;
    }
    return (int64_t) st.st_size;
}
