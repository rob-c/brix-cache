#ifndef XROOTD_MANAGER_PENDING_H
#define XROOTD_MANAGER_PENDING_H

#include <ngx_core.h>
#include <ngx_shmtx.h>
#include "core/ngx_xrootd_module.h"

/*
 * Shared-memory table of in-flight kYR_locate requests.
 *
 * When a worker sends kYR_locate to the CMS manager it inserts an entry here
 * keyed by the per-worker streamid.  When kYR_select arrives on that worker's
 * CMS socket, recv.c looks up the entry, writes the redirect host/port into
 * it, and wakes the suspended XRootD session.
 *
 * Entries expire after cms_locate_timeout milliseconds so that a lost reply
 * does not strand a slot forever.
 */

#define XROOTD_PENDING_LOCATE_SLOTS  32   /* concurrent in-flight locates */

typedef struct {
    uint32_t    streamid;       /* CMS streamid used for correlation          */
    ngx_pid_t   worker_pid;     /* pid of the worker that inserted this entry */
    int         conn_fd;        /* fd of the waiting XRootD client connection */
    ngx_atomic_uint_t conn_number; /* nginx connection generation guard       */
    u_char      client_streamid[2]; /* original XRootD client stream id       */
    ngx_msec_t  expires;        /* ngx_current_msec + timeout_ms at insert    */
    char        redir_host[256];/* filled by recv.c when kYR_select arrives   */
    uint16_t    redir_port;     /* filled by recv.c when kYR_select arrives   */
    ngx_uint_t  in_use;         /* 1 when slot is occupied                    */
} xrootd_pending_locate_t;

typedef struct {
    ngx_shmtx_sh_t           lock;
    xrootd_pending_locate_t  slots[XROOTD_PENDING_LOCATE_SLOTS];
} xrootd_pending_table_t;

extern ngx_shm_zone_t *xrootd_pending_shm_zone;

ngx_int_t xrootd_pending_configure(ngx_conf_t *cf);

/*
 * Insert a new in-flight locate entry.  Returns NGX_OK on success,
 * NGX_AGAIN if the table is full, or NGX_ERROR on a locking failure.
 */
ngx_int_t xrootd_pending_insert(uint32_t streamid, ngx_pid_t worker_pid,
    int conn_fd, ngx_atomic_uint_t conn_number,
    const u_char client_streamid[2], ngx_msec_t timeout_ms);

/*
 * Find the entry matching streamid and worker_pid.  Returns a pointer into
 * shared memory (still holding the lock) so the caller can read redir_host
 * and redir_port.  The caller MUST call xrootd_pending_unlock() afterwards.
 * Returns NULL if not found.
 */
xrootd_pending_locate_t *xrootd_pending_lookup(uint32_t streamid,
    ngx_pid_t worker_pid);

/* Release the lock acquired by xrootd_pending_lookup(). */
void xrootd_pending_unlock(void);

/*
 * Remove the entry matching streamid and worker_pid.  No-op if not found.
 */
void xrootd_pending_remove(uint32_t streamid, ngx_pid_t worker_pid);

/*
 * Phase 51 (A4): sweep the table and free every expired slot, returning the
 * count reaped.  The insert path already reaps opportunistically; this lets a
 * periodic timer reclaim abandoned locates (a manager that never answered)
 * promptly even when no new locates arrive.  Safe no-op when the zone is absent.
 */
ngx_uint_t xrootd_pending_reap_expired(void);

/* A4: how often the worker-0 reaper sweeps (ms). */
#define XROOTD_PENDING_REAP_INTERVAL_MS  5000

#endif /* XROOTD_MANAGER_PENDING_H */
