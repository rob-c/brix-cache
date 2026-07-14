/*
 * stage_request_registry_internal.h — private on-disk layout + substrate seam
 * shared across the three halves of the durable stage-request registry after the
 * phase-79 file-size split.
 *
 * WHAT: Declares the private on-disk format (constants, header/record structs,
 *       the registry handle, the lock-mode enum) and the substrate entry points
 *       — durable file I/O, whole-file locking, slot scan/alloc, and reqid /
 *       status / view translation — that the mutating and read op files call
 *       across the file boundary.
 * WHY:  stage_request_registry.c was one 956-line file owning three concerns:
 *       the durable-store substrate + lifecycle, the mutating client ops, and
 *       the read/query ops. Splitting the two op groups into sibling files keeps
 *       each translation unit under the 500-line cap and focused; the substrate
 *       they both build on stays in stage_request_registry.c and is reached only
 *       through the entry points declared here. The exact SHM-free fcntl+mutex
 *       lock/unlock boundaries and the fixed-slot scan are unchanged — the split
 *       is purely a re-home, not a behavior change.
 * HOW:  stage_request_registry.c defines every symbol declared here (the former
 *       static substrate helpers, now extern); stage_request_registry_mutate.c
 *       and stage_request_registry_query.c include this header and call them.
 *       None of these symbols is exported beyond the stage-request module — the
 *       public contract stays in stage_request_registry.h.
 *
 * Requires: stage_request_registry.h (public types) before inclusion.
 */
#ifndef BRIX_STAGE_REQUEST_REGISTRY_INTERNAL_H
#define BRIX_STAGE_REQUEST_REGISTRY_INTERNAL_H

#include "stage_request_registry.h"

#include <stdint.h>
#include <time.h>


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
    uint8_t   cs_type;        /* brix_stage_cstype_t (opaque here)             */
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


struct brix_stage_registry_s {
    char   path[NGX_MAX_PATH];
    char   host[256];
    int    fd;
    int    lock_fd;
    int    inited;
};

typedef enum { SRQ_LK_SHARE, SRQ_LK_EXCL } srq_lock_t;


/*
 * Substrate seam — defined in stage_request_registry.c, called by the mutating
 * (stage_request_registry_mutate.c) and read (stage_request_registry_query.c)
 * op files. Every lock/unlock boundary and slot scan lives on the far side of
 * these entry points, unchanged by the split.
 */

/* whole-store serialization: pthread mutex then fcntl file lock (order fixed) */
ngx_int_t srq_lock(brix_stage_registry_t *reg, srq_lock_t mode);
void      srq_unlock(brix_stage_registry_t *reg);

/* durable header + record I/O (WAL ordering: record fdatasync, then header fsync) */
ngx_int_t srq_hdr_read(brix_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log);
ngx_int_t srq_hdr_write(brix_stage_registry_t *reg, srq_hdr_t *hdr, ngx_log_t *log);
ngx_int_t srq_rec_read(brix_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
                       ngx_log_t *log);
ngx_int_t srq_rec_write(brix_stage_registry_t *reg, int64_t off, srq_rec_t *rec,
                        ngx_log_t *log);
int64_t   srq_file_size(brix_stage_registry_t *reg);

/* torn-write / self-offset + CRC32c validity check for a record */
int       srq_rec_valid(const srq_rec_t *rec, int64_t expect_off);

/* fixed-slot scan/alloc + reqid/status/view translation */
int64_t   srq_offset_by_reqid(brix_stage_registry_t *reg, const char *reqid,
                              ngx_log_t *log);
int64_t   srq_alloc_slot(brix_stage_registry_t *reg, ngx_log_t *log);
void      srq_reqid_format(const char *host, uint64_t seq, char *buf,
                           size_t buf_sz);
uint8_t   srq_status_on_disk(brix_stage_req_status_t pub);
void      srq_rec_to_view(const srq_rec_t *rec, brix_stage_request_t *out);

#endif /* BRIX_STAGE_REQUEST_REGISTRY_INTERNAL_H */
