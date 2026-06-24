#pragma once

/* Number of committed-write entries kept per open handle for replay detection. */
#define XROOTD_WRTS_JOURNAL_SLOTS 64

/*
 * One entry in the per-handle write-recovery ring buffer.
 * Tracks the file offset and byte count of a single committed pwrite().
 */
typedef struct {
    int64_t  offset;   /* file byte offset of the write */
    uint32_t length;   /* byte count (0 = slot unused) */
    uint32_t gen;      /* monotonically increasing generation counter */
} xrootd_wrts_entry_t;

/* ---- pgwrite CSE (checksum-error) uncorrected-page registry (the "Fob") ----
 *
 * Per-open-file set of pages that failed CRC32c on a kXR_pgwrite and have NOT
 * yet been corrected by a kXR_pgRetry resend.  kXR_close fails with
 * kXR_ChkSumErr while any page remains uncorrected — this is what preserves
 * data integrity once corrupt bytes are written to disk (accept-then-correct).
 * Capacity is kXR_pgMaxEos (256); a fixed array keyed by the stock encoding
 * key = (offset << kXR_pgPageBL) | (dlen < pgPageSZ ? dlen : 0). */
#define XROOTD_PGW_FOB_SLOTS 256   /* == kXR_pgMaxEos */

typedef struct {
    int64_t  key;      /* encoded (offset,dlen) — valid only when used == 1 */
    uint8_t  used;     /* 1 = slot occupied (key 0 is a legal member)       */
} xrootd_pgw_fob_entry_t;

/* ---- File: file.h — Per-open-file bookkeeping type (xrootd_file_t) ----
 *
 * WHAT: Defines xrootd_file_t — one slot per open XRootD file handle where array index IS the handle value (0..XROOTD_MAX_FILES-1). Fields: fd (OS descriptor; -1 = free), path (resolved absolute allocated on open), bytes_read/bytes_written cumulative counters, open_time timestamp for throughput log, writable/readable permission flags, from_cache flag drives kXR_cachersp in stat. Immutable over handle lifetime: is_regular S_ISREG at open, device/ino captured at open validates bound reopens, cached_size st_size valid for read-only. Read tracking: read_last_end previous read end offset (-1=none), read_ahead_end WILLNEED hint farthest byte. kXR_chkpoint state: ckp_path checkpoint temp file (NULL=no active checkpoint), ckp_size bytes captured at kXR_ckpBegin. kXR_posc persist-on-successful-close lifecycle: write open with posc → staged to temporary path → clean kXR_close renames temp to posc_final_path → disconnect/error close unlinks temp via path field (set to temp path at open). Native root:// TPC destination state: tpc_destination=1 pending target, tpc_armed first sync acknowledged rendezvous setup, tpc_started pull task posted, tpc_done completed successfully, tpc_key[128] shared rendezvous key, tpc_org[256] origin identity sent to source as tpc.org, tpc_src_host/tpc_src_port/tpc_src_path[PATH_MAX] source address + path, tpc_token_mode[32] OAuth2/OIDC delegation mode for source auth. Write-through state (mirrors XrdPfcFile::m_dirtyOffset/m_bytesWritten): wt_enabled=1 eligible for WT flush on close, wt_policy cached decision at open time (XROOTD_WT_*), wt_mode_bits POSIX mode sent to origin write-open, wt_dirty_offset last dirty write offset (-1=no pending writes), wt_bytes_written cumulative writes since last sync for metrics. Async flush state: wt_flush_task pending async flush task heap allocated before ngx_thread_task_post freed in completion callback after result consumed on main thread, wt_flush_pending=1 flush posted but not confirmed.
 *
 * WHY: Array index directly = XRootD file handle — clients echo back this opaque 4-byte value in kXR_read/kXR_write/kXR_close etc., server uses index directly so handles are sequential 0..N-1. Slot "in use" when fd >= 0, reset to -1 via xrootd_free_fhandle() on close or disconnect. Bound connections validate device/inode against values captured at open time (nginx workers cannot share post-fork fd integers safely). POSC lifecycle ensures atomic rename-on-success: temp file created at open, renamed to final path only on clean close, unlinked on error/disconnect preventing orphaned temps. TPC destination mirrors XrdCl's full sequence: open target → sync arm rendezvous → open source with tpc.dst → sync run copy. Write-through dirty semantics: wt_enabled=1 eligible for flush on close, wt_dirty_offset > -1 means data written since last sync point, actual write-back happens synchronously (wt_mode==SYNC) or asynchronously via ngx_thread_task_post (WT_ASYNC).
 *
 * HOW: Struct layout — fd/path/bytes_read/bytes_written/open_time/writable/readable/from_cache (lines 17-25) → is_regular/device/inode/cached_size/read_last_end/read_ahead_end (lines 27-32) → ckp_path/ckp_size chkpoint state (lines 35-36) → posc_final_path POSC state (line 47) → TPC destination tpc_destination/tpc_armed/tpc_started/tpc_done + tpc_key[128]/tpc_org[256]/tpc_src_host[256]/tpc_src_port/tpc_src_path[PATH_MAX]/tpc_token_mode[32] (lines 57-66) → write-through wt_enabled/wt_policy/wt_mode_bits/wt_dirty_offset/wt_bytes_written (lines 81-85) → async flush wt_flush_task/wt_flush_pending (lines 91-92). */

/*
 * Per-open-file bookkeeping (xrootd_file_t).
 *
 * One slot per open file handle.  The array index IS the XRootD "file
 * handle" — a 4-byte opaque value the client echoes back in kXR_read,
 * kXR_write, kXR_close, etc.  We use the index directly, so handle
 * values are 0..XROOTD_MAX_FILES-1.
 *
 * A slot is "in use" when fd >= 0.  On kXR_close (or disconnect), fd
 * is closed and reset to -1 via xrootd_free_fhandle().
 *
 * Requires: ngx_msec_t (ngx_config.h + ngx_core.h) before inclusion.
 */
typedef struct {
    int        fd;              /* OS file descriptor; -1 means slot is free */
    char      *path;            /* resolved absolute path (allocated on open) */
    size_t     bytes_read;      /* cumulative bytes read via this handle */
    size_t     bytes_written;   /* cumulative bytes written via this handle */
    ngx_msec_t open_time;       /* timestamp of kXR_open (for throughput log) */
    int        writable;        /* 1 = opened with write permission */
    int        readable;        /* 1 = opened with read permission */
    int        from_cache;      /* 1 = fd points into cache_root (not export root);
                                   drives kXR_cachersp in handle-based kXR_stat */

    int        is_regular;       /* 1 = S_ISREG at open time; immutable over handle lifetime */
    dev_t      device;           /* st_dev captured at open; validates bound reopens */
    ino_t      inode;            /* st_ino captured at open; validates bound reopens */
    off_t      cached_size;      /* st_size captured at open; valid for read-only handles */
    off_t      read_last_end;    /* end offset of the previous read, or -1 */
    off_t      read_ahead_end;   /* farthest byte covered by WILLNEED hint */

    /*
     * Phase-42 W4 — root:// inline read compression.  Holds the negotiated
     * codec ordinal (xrootd_codec_id_t) when the client opened this read handle
     * with "?xrootd.compress=<codec>" AND the server has xrootd_read_compress
     * on.  0 (XROOTD_CODEC_IDENTITY) means no compression — the default, byte-
     * identical hot read path.  kXR_read responses for a non-zero codec are
     * codec-framed; pgread/readv ignore this field and always serve plaintext
     * (preserving the pgread kXR_status + per-page CRC32c invariant).  Stored as
     * a plain uint8_t so file.h needs no codec_core.h dependency.
     */
    uint8_t    read_codec;

    /*
     * Phase-42 W5 — root:// inline write decompression.  Negotiated codec ordinal
     * (xrootd_codec_id_t) when a WRITE handle was opened with "?xrootd.compress="
     * AND xrootd_write_compress is on.  0 = no compression (the default, byte-
     * identical write path).  Each kXR_write payload on such a handle is a
     * self-contained codec frame the server decompresses (bomb-guarded) before
     * storing plaintext; pgwrite ignores this field and stays plaintext.
     */
    uint8_t    write_codec;

    /*
     * Phase 26 slice-cache state.  When slice_mode is set this read handle has
     * NO backing fd (fd == -1); kXR_read is served from per-slice cache files
     * named off slice_cache_path, filling missing slices from the origin and
     * answering kXR_wait in the meantime.  slice_clean_path is the client path
     * sent to the origin for fills; slice_size is the configured slice width.
     */
    unsigned   slice_mode:1;
    char      *slice_cache_path;  /* whole-file cache path (slice naming + meta) */
    char      *slice_clean_path;  /* origin clean path for slice fills */
    size_t     slice_size;        /* bytes per slice (from cache_slice_size) */

    /* kXR_chkpoint state: non-NULL ckp_path means a checkpoint is active. */
    char      *ckp_path;        /* absolute path to the checkpoint temp file */
    int64_t    ckp_size;        /* file size (bytes) captured at kXR_ckpBegin */

    /*
     * kXR_posc (persist-on-successful-close) state.
     *
     * When a write open carries kXR_posc the file is staged to a temporary
     * path.  On a clean kXR_close the temp is renamed to posc_final_path.
     * On disconnect / error close xrootd_free_fhandle() unlinks the temp
     * (via the path field, which was set to the temp path at open time).
     * posc_final_path is heap-allocated (ngx_alloc / ngx_free), like path.
     */
    char      *posc_final_path; /* target path for POSC rename; NULL if not POSC */

    /*
     * Upload-resume staging (xrootd_upload_resume on).  When set, `path` is a
     * DETERMINISTIC identity-keyed partial (xrootd_make_resume_path) and
     * posc_final_path is the destination, so the close-time POSC rename commits
     * it.  The difference from plain POSC: xrootd_free_fhandle() must NOT unlink
     * the partial on a disconnect/abort — it is preserved on disk so the same
     * client reconnecting (re-open in place, no truncate) resumes from its
     * offset.  Cleared once committed (close) so the free path leaves the renamed
     * final file alone.
     */
    unsigned   is_resume:1;

    /*
     * Native root:// TPC destination state.
     *
     * A destination-side TPC open creates a normal writable handle, then
     * delays the outbound source fetch until the client drives the rendezvous
     * with kXR_sync.  This mirrors XrdCl's full TPC sequence: open target,
     * sync to arm, open source with tpc.dst, sync again to run the copy.
     */
    int        tpc_destination;  /* 1 = handle represents a pending TPC target */
    int        tpc_armed;        /* first kXR_sync acknowledged rendezvous setup */
    int        tpc_started;      /* pull task has been posted */
    int        tpc_done;         /* pull completed successfully */
    char       tpc_key[128];     /* shared TPC rendezvous key */
    char       tpc_org[256];     /* origin identity sent to source as tpc.org */
    char       tpc_src_host[256];
    uint16_t   tpc_src_port;     /* 0 means default XRootD port */
    char       tpc_src_path[PATH_MAX];
    char       tpc_token_mode[32]; /* OAuth2/OIDC delegation mode for source auth */
    uint64_t   tpc_transfer_id; /* shared TPC registry entry, 0 if not tracked */

    /* ---- write-through state (mirrors XrdPfcFile::m_dirtyOffset, m_bytesWritten) ----
     *
     * These fields track whether a handle has written dirty data that needs to be
     * propagated back to the origin server at close time. The decision callback is
     * evaluated once at kXR_open and cached in wt_policy; the actual write-back
     * happens either synchronously (wt_mode == SYNC) or asynchronously (WT_ASYNC).
     *
     * Dirty state semantics:
     *   wt_enabled = 1 → handle is eligible for WT flush on close()
     *   wt_dirty_offset > -1 → data has been written since last sync point
     *   wt_bytes_written tracks cumulative writes between sync points (for metrics)
     */

    int              wt_enabled;      /* 1 = write-back enabled for this handle */
    uint8_t          wt_policy;       /* cached decision at open time — XROOTD_WT_* */
    uint16_t         wt_mode_bits;    /* POSIX mode sent to the origin write-open */
    off_t            wt_dirty_offset; /* last dirty write offset; -1 = no pending writes */
    size_t           wt_bytes_written;/* cumulative writes since last sync (metrics) */

    /* Async flush state — only used when wt_mode == WT_ASYNC.
     * wt_flush_task is allocated before ngx_thread_task_post(); freed in the
     * completion callback after the result is consumed on the main thread.
     * wt_flush_pending = 1 means a flush has been posted but not yet confirmed. */
    ngx_thread_task_t   *wt_flush_task; /* pending async flush task (heap) */
    int                  wt_flush_pending; /* 1 = flush not yet confirmed by origin */

    /* ---- kXR_recoverWrts write-recovery journal -------------------------------
     *
     * A fixed-size ring buffer of committed (offset, length) write ranges.
     * When a client reconnects and replays an in-flight write, the server
     * checks this ring via xrootd_wrts_is_replay() and short-circuits the
     * pwrite() when the range is already covered — making the replay idempotent
     * and preventing data corruption (double-write).
     *
     * wrts_enabled  = 1 when the journal is active (writable open + recover_writes on)
     * wrts_head     = next write slot (mod XROOTD_WRTS_JOURNAL_SLOTS)
     * wrts_count    = number of valid entries (capped at XROOTD_WRTS_JOURNAL_SLOTS)
     * wrts_gen      = per-handle write generation counter (incremented per record)
     */
    int                  wrts_enabled;
    uint32_t             wrts_head;
    uint32_t             wrts_count;
    uint32_t             wrts_gen;
    xrootd_wrts_entry_t  wrts_journal[XROOTD_WRTS_JOURNAL_SLOTS];

    /* ---- pgwrite CSE uncorrected-page registry (the "Fob") ----
     * pgw_fob_enabled = 1 once a writable handle has taken the pgwrite path.
     * pgw_fob_count   = number of pages currently uncorrected (gates close).
     * pgw_fob_errs    = cumulative bad pages ever recorded (stats).
     * pgw_fob_fixes   = cumulative pages corrected via kXR_pgRetry (stats). */
    int                     pgw_fob_enabled;
    uint32_t                pgw_fob_count;
    uint32_t                pgw_fob_errs;
    uint32_t                pgw_fob_fixes;
    xrootd_pgw_fob_entry_t  pgw_fob[XROOTD_PGW_FOB_SLOTS];

    /* Live transfer monitor slot index — index into xrootd_transfer_table_t.slots[].
     * -1 means this handle is not currently tracked (table full, or dashboard disabled). */
    int32_t  dashboard_slot;

    /* Phase 33 C2 — bound-secondary SHM handle-table slot hint.
     * For a bound stream, xrootd_ensure_read_handle() re-validates the published
     * handle under xrootd_handle_mutex on EVERY read.  Caching the slot index
     * matched on the first lookup turns the per-read linear scan of the handle
     * table into an O(1) direct check (still under the lock, still re-validating
     * sessid/handle_index/in_use + device/inode, so a primary close/reuse is
     * detected exactly as before).  -1 = no cached slot (cold or just-freed);
     * the hinted lookup falls back to a full scan and refreshes the hint. */
    int      shared_handle_slot_hint;

} xrootd_file_t;
