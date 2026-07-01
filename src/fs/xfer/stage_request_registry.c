/*
 * stage_request_registry.c — durable tape/prepare request registry (Task 4).
 *
 * See stage_request_registry.h for the contract. This is the FRM-dissolution
 * re-home of the FRM queue (former src/frm/queue.c + reqfile.c + reqid.c): a
 * fixed-slot, crash-durable request file keyed by reqid, backing kXR_prepare and
 * the WebDAV Tape REST API. The recall/stage TRANSFER is the stage_engine's job;
 * this store owns only the client-facing request METADATA + lifecycle.
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

#include "../../compat/crc32c.h"
#include "../backend/sd.h"   /* route the journal byte I/O through the SD seam */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* on-disk format (private; the exact FRM layout so the size asserts hold) */

#define SRQ_MAGIC       0x53525131u   /* "SRQ1" */
#define SRQ_VERSION     1u

#define SRQ_REQID_LEN   40            /* on-disk width ("<seq>.<pid>@<host>")    */
#define SRQ_LFN_LEN     3072
#define SRQ_DN_LEN      256
#define SRQ_USER_LEN    256

#define SRQ_REC_SIZE    4608u         /* fixed slot size (header == record)      */
#define SRQ_REC_OFF(n)  (((int64_t) (n) + 1) * (int64_t) SRQ_REC_SIZE)

/* On-disk status (kept distinct from the public enum so the wire/JSON mapping is
 * explicit and a FREE slot is representable). */
enum {
    SRQ_ST_FREE      = 0,
    SRQ_ST_QUEUED    = 1,
    SRQ_ST_STAGING   = 2,
    SRQ_ST_ONLINE    = 3,
    SRQ_ST_FAILED    = 4,
    SRQ_ST_CANCELLED = 5
};

typedef struct {
    uint32_t  magic;
    uint32_t  version;
    uint32_t  rec_size;
    uint32_t  hdr_crc32c;
    int64_t   first;          /* reserved (chain head; unused by linear scan)    */
    int64_t   last;           /* reserved                                        */
    int64_t   free;           /* reserved                                        */
    uint64_t  seq;            /* monotonic reqid sequence (survives restart)     */
    uint64_t  generation;
    int64_t   created_tod;
    uint8_t   reserved[SRQ_REC_SIZE - 64];
} srq_hdr_t;

typedef struct {
    int64_t   self;           /* byte offset of THIS record (torn-write check)   */
    int64_t   next;           /* reserved (chain link; unused)                   */
    uint64_t  rec_crc32c;     /* CRC32c of the whole record with this == 0       */
    int64_t   tod_added;
    int64_t   tod_status;
    int64_t   tod_expire;     /* hard expiry; 0 = never                          */
    uint32_t  options;        /* reserved bitmask                                */
    int32_t   fail_code;
    uint32_t  attempts;
    int16_t   opaque_off;
    int16_t   lfn_url_off;
    uint8_t   cs_type;        /* xrootd_stage_cstype_t (opaque here)             */
    uint8_t   status;         /* SRQ_ST_*                                        */
    int8_t    priority;
    uint8_t   queue;
    char      reqid[SRQ_REQID_LEN];
    char      lfn[SRQ_LFN_LEN];
    char      requester_dn[SRQ_DN_LEN];
    char      user[SRQ_USER_LEN];
    char      notify[512];
    char      selector[32];
    char      cs_value[64];
    uint8_t   xfer_kind;
    uint8_t   xfer_pad;
    uint16_t  xfer_mode_bits;
    uint8_t   reserved[SRQ_REC_SIZE - 4304];
} srq_rec_t;

/* Layout pins — a negative array size is a hard error if the struct drifts. */
typedef char srq_hdr_size_check[(sizeof(srq_hdr_t) == SRQ_REC_SIZE) ? 1 : -1];
typedef char srq_rec_size_check[(sizeof(srq_rec_t) == SRQ_REC_SIZE) ? 1 : -1];


struct xrootd_stage_registry_s {
    char   path[NGX_MAX_PATH];
    char   host[256];
    int    fd;
    int    lock_fd;
    int    inited;
};

/* Process-wide singleton (one durable store per server). */
static xrootd_stage_registry_t  srq_singleton;
static int                      srq_singleton_used;

/*
 * In-process serialization. POSIX fcntl locks are owned by the PROCESS, so they do
 * not mutually exclude threads of the same worker; this mutex does. Lock order is
 * always pthread-mutex -> fcntl.
 */
static pthread_mutex_t  srq_file_mtx = PTHREAD_MUTEX_INITIALIZER;

typedef enum { SRQ_LK_SHARE, SRQ_LK_EXCL } srq_lock_t;


/* CRC helpers */

static uint32_t
srq_rec_compute_crc(const srq_rec_t *rec)
{
    srq_rec_t tmp = *rec;
    tmp.rec_crc32c = 0;
    return xrootd_crc32c_value(&tmp, sizeof(tmp));
}

static uint32_t
srq_hdr_compute_crc(const srq_hdr_t *hdr)
{
    srq_hdr_t tmp = *hdr;
    tmp.hdr_crc32c = 0;
    return xrootd_crc32c_value(&tmp, sizeof(tmp));
}

static void
srq_rec_stamp_crc(srq_rec_t *rec)
{
    rec->rec_crc32c = (uint64_t) srq_rec_compute_crc(rec);
}

static int
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
    xrootd_sd_obj_t obj;

    /* Route the journal byte read through the Storage Driver seam so the syscall
     * stays in the backend (src/fs/backend/), same as the former FRM reqfile. */
    xrootd_sd_posix_wrap(&obj, fd);
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
    xrootd_sd_obj_t obj;

    xrootd_sd_posix_wrap(&obj, fd);
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

static ngx_int_t
srq_hdr_read(xrootd_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log)
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

static ngx_int_t
srq_hdr_write(xrootd_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log)
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

static ngx_int_t
srq_rec_read(xrootd_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
             ngx_log_t *log)
{
    if (off < (int64_t) SRQ_REC_SIZE) {
        return NGX_ERROR;
    }
    return srq_pread_all(reg->fd, rec, sizeof(*rec), (off_t) off, log);
}

static ngx_int_t
srq_rec_write(xrootd_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
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

static int64_t
srq_file_size(xrootd_stage_registry_t *reg)
{
    struct stat st;
    if (reg->fd < 0 || fstat(reg->fd, &st) != 0) {
        return -1;
    }
    return (int64_t) st.st_size;
}


/* locking */

static ngx_int_t
srq_lock(xrootd_stage_registry_t *reg, srq_lock_t mode)
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

static void
srq_unlock(xrootd_stage_registry_t *reg)
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

static void
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
static xrootd_stage_req_status_t
srq_status_public(uint8_t on_disk)
{
    switch (on_disk) {
    case SRQ_ST_QUEUED:    return XROOTD_STAGE_REQ_QUEUED;
    case SRQ_ST_STAGING:   return XROOTD_STAGE_REQ_ACTIVE;
    case SRQ_ST_ONLINE:    return XROOTD_STAGE_REQ_DONE;
    case SRQ_ST_FAILED:    return XROOTD_STAGE_REQ_FAILED;
    case SRQ_ST_CANCELLED: return XROOTD_STAGE_REQ_CANCELLED;
    default:               return XROOTD_STAGE_REQ_QUEUED;
    }
}

static uint8_t
srq_status_on_disk(xrootd_stage_req_status_t pub)
{
    switch (pub) {
    case XROOTD_STAGE_REQ_QUEUED:    return SRQ_ST_QUEUED;
    case XROOTD_STAGE_REQ_ACTIVE:    return SRQ_ST_STAGING;
    case XROOTD_STAGE_REQ_DONE:      return SRQ_ST_ONLINE;
    case XROOTD_STAGE_REQ_FAILED:    return SRQ_ST_FAILED;
    case XROOTD_STAGE_REQ_CANCELLED: return SRQ_ST_CANCELLED;
    default:                         return SRQ_ST_QUEUED;
    }
}

static void
srq_rec_to_view(const srq_rec_t *rec, xrootd_stage_request_t *out)
{
    ngx_memzero(out, sizeof(*out));
    ngx_cpystrn((u_char *) out->reqid, (u_char *) rec->reqid, sizeof(out->reqid));
    ngx_cpystrn((u_char *) out->lfn, (u_char *) rec->lfn, sizeof(out->lfn));
    ngx_cpystrn((u_char *) out->requester_dn, (u_char *) rec->requester_dn,
                sizeof(out->requester_dn));
    out->cs_type    = (xrootd_stage_cstype_t) rec->cs_type;
    out->status     = srq_status_public(rec->status);
    out->tod_added  = rec->tod_added;
    out->tod_expire = rec->tod_expire;
}

/* Resolve a reqid -> file offset by a linear slot scan. -1 on miss/error. */
static int64_t
srq_offset_by_reqid(xrootd_stage_registry_t *reg, const char *reqid,
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
static int64_t
srq_alloc_slot(xrootd_stage_registry_t *reg, ngx_log_t *log)
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

xrootd_stage_registry_t *
xrootd_stage_registry_singleton(void)
{
    return srq_singleton_used ? &srq_singleton : NULL;
}

ngx_int_t
xrootd_stage_registry_init(const char *journal_dir, ngx_log_t *log)
{
    xrootd_stage_registry_t *reg = &srq_singleton;
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


/* reqid generation */

ngx_int_t
xrootd_stage_request_reqid_generate(xrootd_stage_registry_t *reg,
    char *reqid_out, size_t reqid_out_sz, ngx_log_t *log)
{
    srq_hdr_t hdr;
    uint64_t  seq;

    if (reg == NULL || reg->fd < 0 || reqid_out == NULL
        || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (srq_hdr_read(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;
    if (srq_hdr_write(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    srq_reqid_format(reg->host, seq, reqid_out, reqid_out_sz);
    return NGX_OK;
}


/* mutating ops */

ngx_int_t
xrootd_stage_request_add(xrootd_stage_registry_t *reg,
    const xrootd_stage_request_view_t *view, char *reqid_out,
    size_t reqid_out_sz, ngx_log_t *log)
{
    srq_hdr_t hdr;
    srq_rec_t rec;
    int64_t   off;
    uint64_t  seq;
    time_t    now;

    if (reg == NULL || reg->fd < 0 || view == NULL || view->lfn == NULL
        || reqid_out == NULL || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (ngx_strlen(view->lfn) >= SRQ_LFN_LEN) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "stage-req: lfn exceeds %d bytes",
                      SRQ_LFN_LEN);
        return NGX_ERROR;
    }
    now = time(NULL);

    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (srq_hdr_read(reg, &hdr, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    off = srq_alloc_slot(reg, log);
    if (off < 0) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;

    ngx_memzero(&rec, sizeof(rec));
    rec.self        = off;
    rec.status      = SRQ_ST_QUEUED;
    rec.cs_type     = (uint8_t) view->cs_type;
    rec.tod_added   = (int64_t) now;
    rec.tod_status  = (int64_t) now;
    rec.tod_expire  = view->tod_expire;
    rec.opaque_off  = -1;
    rec.lfn_url_off = -1;
    srq_reqid_format(reg->host, seq, rec.reqid, sizeof(rec.reqid));
    ngx_cpystrn((u_char *) rec.lfn, (u_char *) view->lfn, sizeof(rec.lfn));
    if (view->requester_dn) {
        ngx_cpystrn((u_char *) rec.requester_dn,
                    (u_char *) view->requester_dn, sizeof(rec.requester_dn));
    }
    if (view->user) {
        ngx_cpystrn((u_char *) rec.user, (u_char *) view->user, sizeof(rec.user));
    }
    if (view->cs_value) {
        ngx_cpystrn((u_char *) rec.cs_value, (u_char *) view->cs_value,
                    sizeof(rec.cs_value));
    }

    if (srq_rec_write(reg, off, &rec, log) != NGX_OK
        || srq_hdr_write(reg, &hdr, log) != NGX_OK)
    {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);

    ngx_cpystrn((u_char *) reqid_out, (u_char *) rec.reqid, reqid_out_sz);
    return NGX_OK;
}

ngx_int_t
xrootd_stage_request_set_status(xrootd_stage_registry_t *reg,
    const char *reqid, xrootd_stage_req_status_t status, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_DECLINED;
    }
    rec.status     = srq_status_on_disk(status);
    rec.tod_status = (int64_t) time(NULL);
    if (srq_rec_write(reg, off, &rec, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    return NGX_OK;
}

ngx_int_t
xrootd_stage_request_delete(xrootd_stage_registry_t *reg, const char *reqid,
                            ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_OK;                  /* already gone — idempotent */
    }
    ngx_memzero(&rec, sizeof(rec));
    rec.status = SRQ_ST_FREE;
    if (srq_rec_write(reg, off, &rec, log) != NGX_OK) {
        srq_unlock(reg);
        return NGX_ERROR;
    }
    srq_unlock(reg);
    return NGX_OK;
}

ngx_int_t
xrootd_stage_request_cancel(xrootd_stage_registry_t *reg, const char *reqid,
                            ngx_log_t *log)
{
    /* Mark CANCELLED (kept so a later status query reports it), not deleted. */
    ngx_int_t rc = xrootd_stage_request_set_status(reg, reqid,
                       XROOTD_STAGE_REQ_CANCELLED, log);
    return (rc == NGX_DECLINED) ? NGX_OK : rc;   /* unknown reqid is idempotent */
}


/* read ops */

ngx_int_t
xrootd_stage_request_get(xrootd_stage_registry_t *reg, const char *reqid,
                         xrootd_stage_request_t *out, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off;

    if (reg == NULL || reg->fd < 0 || reqid == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    off = srq_offset_by_reqid(reg, reqid, log);
    if (off < 0 || srq_rec_read(reg, off, &rec, log) != NGX_OK
        || !srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE)
    {
        srq_unlock(reg);
        return NGX_DECLINED;
    }
    srq_unlock(reg);
    srq_rec_to_view(&rec, out);
    return NGX_OK;
}

ngx_int_t
xrootd_stage_request_find_by_path(xrootd_stage_registry_t *reg, const char *lfn,
    char *reqid_out, size_t reqid_out_sz, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off, size, best_off = -1, best_tod = -1;
    char      best_reqid[SRQ_REQID_LEN];

    if (reg == NULL || reg->fd < 0 || lfn == NULL || reqid_out == NULL
        || reqid_out_sz < SRQ_REQID_LEN)
    {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = srq_file_size(reg);
    for (off = SRQ_REC_OFF(0);
         size > 0 && off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            srq_unlock(reg);
            return NGX_ERROR;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE) {
            continue;
        }
        if (ngx_strcmp(rec.lfn, lfn) == 0 && rec.tod_added >= best_tod) {
            best_tod = rec.tod_added;
            best_off = off;
            ngx_cpystrn((u_char *) best_reqid, (u_char *) rec.reqid,
                        sizeof(best_reqid));
        }
    }
    srq_unlock(reg);
    if (best_off < 0) {
        return NGX_DECLINED;
    }
    ngx_cpystrn((u_char *) reqid_out, (u_char *) best_reqid, reqid_out_sz);
    return NGX_OK;
}

ngx_int_t
xrootd_stage_request_owner_check(xrootd_stage_registry_t *reg, const char *reqid,
    const char *requester_dn, ngx_log_t *log)
{
    xrootd_stage_request_t rec;

    if (requester_dn == NULL || requester_dn[0] == '\0') {
        return NGX_OK;                  /* anonymous caller: nothing to enforce */
    }
    if (xrootd_stage_request_get(reg, reqid, &rec, log) != NGX_OK) {
        return NGX_OK;                  /* absent/gone: idempotent, no oracle */
    }
    if (rec.requester_dn[0] == '\0'
        || ngx_strcmp(rec.requester_dn, requester_dn) == 0)
    {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "stage-req: cancel of reqid \"%s\" denied — owned by a "
                  "different principal", reqid);
    return NGX_DECLINED;
}

ngx_int_t
xrootd_stage_request_list_active(xrootd_stage_registry_t *reg,
    ngx_uint_t *cursor, xrootd_stage_request_t *out, ngx_log_t *log)
{
    srq_rec_t rec;
    int64_t   off, size;

    if (reg == NULL || reg->fd < 0 || cursor == NULL || out == NULL) {
        return NGX_ERROR;
    }
    if (srq_lock(reg, SRQ_LK_SHARE) != NGX_OK) {
        return NGX_ERROR;
    }
    size = srq_file_size(reg);
    for ( ;; ) {
        off = SRQ_REC_OFF(*cursor);
        if (size <= 0 || off + (int64_t) SRQ_REC_SIZE > size) {
            srq_unlock(reg);
            return NGX_DONE;
        }
        (*cursor)++;
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            srq_unlock(reg);
            return NGX_ERROR;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE) {
            continue;
        }
        srq_unlock(reg);
        srq_rec_to_view(&rec, out);
        return NGX_OK;
    }
}

ngx_int_t
xrootd_stage_request_list_files(xrootd_stage_registry_t *reg, const char *reqid,
    ngx_uint_t *cursor, xrootd_stage_request_t *out, ngx_log_t *log)
{
    /* One request id maps to exactly one lfn (bulk grouping deferred): yield the
     * single record on cursor 0, then NGX_DONE. */
    if (cursor == NULL) {
        return NGX_ERROR;
    }
    if (*cursor > 0) {
        return NGX_DONE;
    }
    (*cursor)++;
    return xrootd_stage_request_get(reg, reqid, out, log);
}

ngx_int_t
xrootd_stage_request_pin_release(xrootd_stage_registry_t *reg,
    const char *abs_path, ngx_log_t *log)
{
    char      reqid[SRQ_REQID_LEN];
    ngx_int_t rc;

    if (reg == NULL || abs_path == NULL) {
        return NGX_ERROR;
    }
    /* Record the release intent by cancelling any live request for the path; real
     * disk reclamation is delegated to the MSS/backend. */
    rc = xrootd_stage_request_find_by_path(reg, abs_path, reqid, sizeof(reqid), log);
    if (rc != NGX_OK) {
        return NGX_DECLINED;            /* not tracked / not pinned */
    }
    ngx_log_error(NGX_LOG_INFO, log, 0, "stage-req: pin released \"%s\"", abs_path);
    return xrootd_stage_request_cancel(reg, reqid, log);
}

ngx_uint_t
xrootd_stage_request_reap_expired(xrootd_stage_registry_t *reg, time_t now,
                                  ngx_log_t *log)
{
    srq_rec_t  rec;
    int64_t    off, size;
    ngx_uint_t reaped = 0;

    if (reg == NULL || reg->fd < 0) {
        return 0;
    }
    if (srq_lock(reg, SRQ_LK_EXCL) != NGX_OK) {
        return 0;
    }
    size = srq_file_size(reg);
    for (off = SRQ_REC_OFF(0);
         size > 0 && off + (int64_t) SRQ_REC_SIZE <= size;
         off += (int64_t) SRQ_REC_SIZE)
    {
        if (srq_rec_read(reg, off, &rec, log) != NGX_OK) {
            break;
        }
        if (!srq_rec_valid(&rec, off) || rec.status == SRQ_ST_FREE
            || rec.tod_expire == 0 || rec.tod_expire > (int64_t) now)
        {
            continue;
        }
        ngx_memzero(&rec, sizeof(rec));
        rec.status = SRQ_ST_FREE;
        if (srq_rec_write(reg, off, &rec, log) == NGX_OK) {
            reaped++;
        }
    }
    srq_unlock(reg);
    return reaped;
}
