#ifndef XROOTD_DASHBOARD_H
#define XROOTD_DASHBOARD_H

/*
 * dashboard/dashboard.h — live transfer monitor: shared-memory types and public API.
 *
 * A self-contained admin dashboard that lets site operators watch every active
 * transfer in real time: who, which file, which protocol, how many bytes, how fast.
 *
 * ARCHITECTURE:
 *   Stream workers update a shared-memory transfer table via lock-free atomics.
 *   An HTTP worker reads the same table and emits JSON at GET /xrootd/transfers.
 *   A small embedded HTML page polls that endpoint every two seconds and renders
 *   the result client-side, computing instantaneous rates from consecutive snapshots.
 *
 * CONCURRENCY:
 *   Slot allocation/free holds the table mutex briefly.
 *   Per-slot byte/timestamp updates use atomic operations — no lock held.
 *   The JSON exporter does a lock-free scan; it tolerates torn reads gracefully
 *   because the dashboard is display-only and eventual consistency is fine.
 *
 * SLOT LIFECYCLE:
 *   kXR_open  → xrootd_transfer_slot_alloc()  (store index in fh->dashboard_slot)
 *   kXR_read /
 *   kXR_write → xrootd_transfer_slot_update() (atomic byte/timestamp increment)
 *   kXR_close → xrootd_transfer_slot_free()   (reset index to -1)
 *   disconnect → xrootd_transfer_slot_free_all_for_session()  (catch dropped clients)
 */

#include <stdint.h>
#include <ngx_core.h>

/* Maximum simultaneous tracked transfers. */
#define XROOTD_DASHBOARD_MAX_TRANSFERS   512

/* Field width constants — kept small to bound SHM size. */
#define XROOTD_DASHBOARD_PATH_LEN        512
#define XROOTD_DASHBOARD_IDENTITY_LEN    128
#define XROOTD_DASHBOARD_IP_LEN           64
#define XROOTD_DASHBOARD_OP_LEN           32
#define XROOTD_DASHBOARD_REASON_LEN       96
#define XROOTD_DASHBOARD_HOST_LEN        128
#define XROOTD_DASHBOARD_VO_LEN           32

/* Protocol tag values stored in xrootd_transfer_slot_t.proto */
#define XROOTD_XFER_PROTO_ROOT    1   /* native XRootD stream (root://)   */
#define XROOTD_XFER_PROTO_WEBDAV  2   /* WebDAV over HTTPS (davs://)      */
#define XROOTD_XFER_PROTO_S3      3   /* S3-compatible REST API           */

/* Direction tag values stored in xrootd_transfer_slot_t.direction */
#define XROOTD_XFER_DIR_READ   1   /* client downloading (egress)        */
#define XROOTD_XFER_DIR_WRITE  2   /* client uploading (ingress)         */
#define XROOTD_XFER_DIR_TPC    3   /* third-party copy (no client data)  */

/* State tag values stored in xrootd_transfer_slot_t.state */
#define XROOTD_XFER_STATE_ACTIVE    1
#define XROOTD_XFER_STATE_IDLE      2
#define XROOTD_XFER_STATE_STALLED   3
#define XROOTD_XFER_STATE_CLOSING   4
#define XROOTD_XFER_STATE_ERROR     5
/*
 * THROTTLED is a *derived* display state (never stored in slot->state): the JSON
 * exporter reports it instead of "stalled" for a transfer that has moved data
 * overall but is momentarily between client-imposed rate-limit bursts (e.g.
 * xrdcp --xrate, which sleeps then bursts).  Such a transfer is making forward
 * progress on a schedule, not stuck, so flagging it "stalled" is misleading.
 */
#define XROOTD_XFER_STATE_THROTTLED 6

/*
 * EWMA sampling window for slot->instant_bps.  The owning worker re-folds the
 * smoothed rate at most once per this interval inside slot_update_bytes (see
 * transfer_table.c); the exporter decays the published value by the same window
 * for read-only display while a transfer is idle between bursts.
 */
#define XROOTD_XFER_SAMPLE_MS       1000

#define XROOTD_DASHBOARD_MAX_EVENTS          512
#define XROOTD_DASHBOARD_EVENT_MSG_LEN       160
#define XROOTD_DASHBOARD_HISTORY_BUCKETS     360
#define XROOTD_DASHBOARD_HISTORY_INTERVAL_MS 5000

typedef enum {
    XROOTD_DASH_EVENT_AUTH = 1,
    XROOTD_DASH_EVENT_NAMESPACE,
    XROOTD_DASH_EVENT_IO,
    XROOTD_DASH_EVENT_TPC,
    XROOTD_DASH_EVENT_DASHBOARD
} xrootd_dashboard_event_class_e;

/*
 * One active-transfer record.
 *
 * Lives in shared memory.  The lock in xrootd_transfer_table_t is held only
 * during slot allocation — per-slot byte/timestamp updates are lock-free.
 *
 * Field notes:
 *   in_use    — 0 = free slot; 1 = active transfer.  Written under table lock.
 *   serial    — monotonic ID so the JS dashboard can detect row churn without
 *               comparing every field; incremented each time a slot is reused.
 *   sessid    — session ID copied from ctx->sessid; used for cleanup-by-sessid
 *               during disconnect (worker that opened the file may not be the
 *               worker that notices the drop).
 *   bytes     — cumulative bytes transferred; updated atomically during I/O.
 *   start_ms  — epoch milliseconds at transfer open; written once at alloc time.
 *   last_ms   — epoch milliseconds of the most recent I/O; atomic word write.
 */
typedef struct {
    ngx_atomic_t  in_use;       /* 0=free, 1=active; written under table lock */
    uint32_t      serial;       /* monotonic ID — lets JS detect row churn    */
    u_char        sessid[16];   /* session ID for cleanup-by-sessid on disconnect */
    ngx_pid_t     worker_pid;
    char          client_ip[XROOTD_DASHBOARD_IP_LEN];
    char          identity[XROOTD_DASHBOARD_IDENTITY_LEN]; /* DN or "anonymous" */
    char          vo[XROOTD_DASHBOARD_VO_LEN];
    char          path[XROOTD_DASHBOARD_PATH_LEN];
    char          op[XROOTD_DASHBOARD_OP_LEN];
    uint8_t       direction;    /* XROOTD_XFER_DIR_*  */
    uint8_t       proto;        /* XROOTD_XFER_PROTO_* */
    uint8_t       state;        /* XROOTD_XFER_STATE_* */
    uint8_t       flags;
    ngx_atomic_t  bytes;        /* bytes transferred so far (atomic increment) */
    ngx_atomic_t  bytes_last_sample;  /* slot->bytes at the last EWMA sample   */
    ngx_atomic_t  last_sample_ms;     /* epoch ms of the last EWMA sample       */
    ngx_atomic_t  instant_bps;        /* EWMA-smoothed bytes/sec (owner writes)  */
    int64_t       expected_bytes;
    int64_t       start_ms;     /* epoch ms at transfer start (written once)   */
    ngx_atomic_t  last_ms;      /* epoch ms of last I/O (atomic word write)    */
    ngx_atomic_t  state_since_ms;
    ngx_atomic_t  read_ops;
    ngx_atomic_t  write_ops;
    ngx_atomic_t  sync_ops;
    ngx_atomic_t  close_ops;
    char          last_error[XROOTD_DASHBOARD_REASON_LEN];
    char          tpc_remote_host[XROOTD_DASHBOARD_HOST_LEN];
    char          tpc_remote_path_hint[XROOTD_DASHBOARD_PATH_LEN];
    int           tpc_remote_status;
    int           tpc_curl_exit;
} xrootd_transfer_slot_t;

/*
 * Root shared-memory object for the transfer table.
 *
 * lock must be the first field — ngx_shmtx_create() requires the ngx_shmtx_sh_t
 * to be at the start of the shared region (same requirement as the session registry).
 */
typedef struct {
    ngx_shmtx_sh_t           lock;         /* held only during alloc/free      */
    uint32_t                 next_serial;   /* monotonic counter for slot IDs   */
    xrootd_transfer_slot_t  slots[XROOTD_DASHBOARD_MAX_TRANSFERS];
} xrootd_transfer_table_t;

typedef struct {
    ngx_atomic_t  sequence;
    int64_t       time_ms;
    uint8_t       class_id;
    uint8_t       proto;
    uint16_t      status;
    char          message[XROOTD_DASHBOARD_EVENT_MSG_LEN];
    char          path_hint[128];
} xrootd_dashboard_event_t;

typedef struct {
    ngx_shmtx_sh_t            lock;
    ngx_atomic_t              next_sequence;
    xrootd_dashboard_event_t  events[XROOTD_DASHBOARD_MAX_EVENTS];
} xrootd_dashboard_event_table_t;

typedef struct {
    int64_t       bucket_start_ms;
    ngx_atomic_t  active_root;
    ngx_atomic_t  active_webdav;
    ngx_atomic_t  active_s3;
    ngx_atomic_t  active_tpc;
    ngx_atomic_t  bytes_rx;
    ngx_atomic_t  bytes_tx;
    ngx_atomic_t  errors;
    ngx_atomic_t  auth_failures;
    ngx_atomic_t  write_stalls;
    uint32_t      cache_occupancy_ppm;
} xrootd_dashboard_history_bucket_t;

typedef struct {
    ngx_shmtx_sh_t                   lock;
    int64_t                          last_bucket_start_ms;
    xrootd_dashboard_history_bucket_t buckets[XROOTD_DASHBOARD_HISTORY_BUCKETS];
} xrootd_dashboard_history_t;

/*
 * Global SHM zone pointer — set by the stream module during postconfiguration;
 * read by the HTTP dashboard module at request time.  NULL if the dashboard
 * feature was not compiled or no stream listeners are configured.
 */
extern ngx_shm_zone_t *ngx_xrootd_dashboard_shm_zone;
extern ngx_shm_zone_t *ngx_xrootd_dashboard_events_shm_zone;
extern ngx_shm_zone_t *ngx_xrootd_dashboard_history_shm_zone;

/*
 * SHM zone setup — called from stream postconfiguration, after metrics zone.
 * Registers the xrootd_dashboard zone.  Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t xrootd_configure_dashboard(ngx_conf_t *cf);

/*
 * SHM zone init callback — implemented in transfer_table.c.
 * Called by nginx when the zone is first mapped (or re-attached on reload).
 */
ngx_int_t ngx_xrootd_dashboard_shm_init(ngx_shm_zone_t *shm_zone, void *data);
/*
 * SHM zone init callback for the events ring (events.c).
 * data != NULL on reload (re-creates the mutex over the inherited region);
 * data == NULL on first start (zeroes the region, then creates the mutex).
 * Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t ngx_xrootd_dashboard_events_shm_init(ngx_shm_zone_t *shm_zone,
    void *data);
/*
 * SHM zone init callback for the history ring (history.c).
 * Same reload/first-start contract as the events init above; NGX_OK/NGX_ERROR.
 */
ngx_int_t ngx_xrootd_dashboard_history_shm_init(ngx_shm_zone_t *shm_zone,
    void *data);

/* transfer_table.c — the four public slot operations */

/*
 * Allocate a slot for a new transfer.  Returns the slot index (>= 0) on
 * success, -1 if the table is full (silently; the transfer is untracked).
 * now_ms is ngx_current_msec cast to int64_t.
 */
int xrootd_transfer_slot_alloc(
    xrootd_transfer_table_t *t,
    const u_char             sessid[16],
    const char              *client_ip,
    const char              *identity,
    const char              *path,
    uint8_t                  direction,
    uint8_t                  proto,
    int64_t                  now_ms);

/*
 * Extended slot allocation — superset of xrootd_transfer_slot_alloc() that also
 * records vo, op label, and expected_bytes (use -1 if the size is unknown).
 * All string args are copied into the SHM slot (no ownership taken); NULL
 * identity becomes "anonymous" and NULL op becomes "transfer".  Acquires the
 * table mutex for an O(512) free-slot scan.  Returns the slot index (>= 0), or
 * -1 if the table is full (logs a dashboard event; the transfer runs untracked).
 * now_ms is epoch/current milliseconds; stored as start_ms.
 */
int xrootd_transfer_slot_alloc_ex(
    xrootd_transfer_table_t *t,
    const u_char             sessid[16],
    const char              *client_ip,
    const char              *identity,
    const char              *vo,
    const char              *path,
    const char              *op,
    uint8_t                  direction,
    uint8_t                  proto,
    int64_t                  expected_bytes,
    int64_t                  now_ms);

/*
 * Increment the byte counter and refresh the last-active timestamp for a slot.
 * No-op if slot_idx is negative or the slot is no longer in use.
 */
void xrootd_transfer_slot_update(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    ngx_atomic_int_t         nbytes,
    int64_t                  now_ms);

/*
 * Add nbytes to the slot's cumulative byte counter (only if nbytes > 0),
 * force state back to ACTIVE, and stamp last_ms = now_ms.  Lock-free; this is
 * the underlying implementation that xrootd_transfer_slot_update() forwards to.
 * No-op if slot_idx is out of range or the slot is not in use.
 */
void xrootd_transfer_slot_update_bytes(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    ngx_atomic_int_t         nbytes,
    int64_t                  now_ms);

/*
 * Set the slot's display state to one of XROOTD_XFER_STATE_* and stamp both
 * state_since_ms and last_ms with now_ms.  Lock-free; no-op if slot_idx is out
 * of range or the slot is not in use.
 */
void xrootd_transfer_slot_set_state(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    uint8_t                  state,
    int64_t                  now_ms);

/*
 * Copy reason into the slot's last_error field (NULL becomes "error"; string is
 * copied, not borrowed), set state to XROOTD_XFER_STATE_ERROR, stamp
 * state_since_ms/last_ms, and emit a dashboard IO event for the activity feed.
 * Lock-free; no-op if slot_idx is out of range or the slot is not in use.
 */
void xrootd_transfer_slot_set_error(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    const char              *reason,
    int64_t                  now_ms);

/*
 * Record the remote endpoint of a third-party copy: remote_host and path_hint
 * are copied into the slot (not borrowed), and remote_status/curl_exit are
 * stored verbatim for display.  Lock-free; no-op if slot_idx is out of range or
 * the slot is not in use.
 */
void xrootd_transfer_slot_set_tpc_remote(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    const char              *remote_host,
    const char              *path_hint,
    int                      remote_status,
    int                      curl_exit);

/*
 * Atomically increment one of the slot's per-op counters based on the op label
 * (case-insensitive): read/GET/GetObject -> read_ops; write/PUT/PutObject/
 * UploadPart -> write_ops; sync/commit -> sync_ops; close -> close_ops.
 * Unrecognised labels are ignored.  Lock-free; no-op if slot_idx is out of
 * range, the slot is not in use, or op is NULL.
 */
void xrootd_transfer_slot_count_op(
    xrootd_transfer_table_t *t,
    int                      slot_idx,
    const char              *op);

/*
 * Mark a single slot as free.  Called from kXR_close.
 * Atomic CAS — no lock held.
 */
void xrootd_transfer_slot_free(
    xrootd_transfer_table_t *t,
    int                      slot_idx);

/*
 * Free all slots belonging to a session.  Called from xrootd_on_disconnect()
 * to clean up handles that never received kXR_close.
 */
void xrootd_transfer_slot_free_all_for_session(
    xrootd_transfer_table_t *t,
    const u_char             sessid[16]);

/*
 * Push one entry onto the SHM event ring (overwriting the oldest if full).
 * class_id is XROOTD_DASH_EVENT_*; message/path_hint are copied and sanitised
 * (control bytes -> '?'), and path_hint is truncated at the first '?'/'#' to
 * drop query strings.  Takes the events mutex briefly; silently no-ops if the
 * events SHM zone is not configured.
 */
void xrootd_dashboard_event_add(uint8_t class_id, uint8_t proto,
    uint16_t status, const char *message, const char *path_hint);
/*
 * Copy up to max_events of the most recent events into caller-owned out[],
 * oldest-first.  Takes the events mutex; returns the number actually written
 * (0 if no events or the zone is unconfigured).  out must hold max_events slots.
 */
ngx_uint_t xrootd_dashboard_events_snapshot(xrootd_dashboard_event_t *out,
    ngx_uint_t max_events);

/*
 * Sample the current history bucket from live state: snaps now_ms down to the
 * INTERVAL_MS boundary, zero-fills any buckets skipped since the last sample,
 * then tallies active transfers from the dashboard table and cumulative
 * byte/error/auth-failure totals from the metrics SHM zone.  Takes the history
 * mutex; no-op if the history zone is unconfigured.  Call periodically (timer).
 */
void xrootd_dashboard_history_sample(int64_t now_ms);
/*
 * Copy up to max_buckets recent history buckets into caller-owned out[],
 * chronological (oldest-first); buckets with no matching start time are skipped
 * so n may be less than the window.  Takes the history mutex; returns the count
 * written (0 if no history yet or the zone is unconfigured).
 */
ngx_uint_t xrootd_dashboard_history_snapshot(
    xrootd_dashboard_history_bucket_t *out, ngx_uint_t max_buckets);

#endif /* XROOTD_DASHBOARD_H */
