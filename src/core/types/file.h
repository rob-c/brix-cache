#ifndef BRIX_TYPES_FILE_H
#define BRIX_TYPES_FILE_H

#include "fs/backend/sd.h"   /* brix_sd_obj_t — per-handle storage object */
#include "fs/vfs/vfs_policy.h"   /* brix_vfs_mutation_policy_t (phase-105) */
#include "observability/sesslog/sesslog.h"

/* Opaque VFS staged-write handle (whole-object staged-commit adapter, phase-70).
 * Full type in fs/vfs/vfs_internal.h; here only ever a pointer field. Guarded so
 * co-inclusion with vfs.h (which also forward-declares it) is a single typedef. */
#ifndef BRIX_VFS_STAGED_T_DECLARED
#define BRIX_VFS_STAGED_T_DECLARED
typedef struct brix_vfs_staged_s brix_vfs_staged_t;
#endif

/* Opaque unified write session (brix_vfs_writer) — the whole-object staged-write
 * handle for a root:// upload to a non-random-write backend. Full type in
 * fs/vfs/vfs_writer.c; here only ever a pointer field. Guard matches vfs_ops.h. */
#ifndef BRIX_VFS_WRITER_T_DECLARED
#define BRIX_VFS_WRITER_T_DECLARED
typedef struct brix_vfs_writer_s brix_vfs_writer_t;
#endif

/* Number of committed-write entries kept per open handle for replay detection. */
#define BRIX_WRTS_JOURNAL_SLOTS 64

/*
 * One entry in the per-handle write-recovery ring buffer.
 * Tracks the file offset and byte count of a single committed pwrite().
 */
typedef struct {
    int64_t  offset;   /* file byte offset of the write */
    uint32_t length;   /* byte count (0 = slot unused) */
    uint32_t gen;      /* monotonically increasing generation counter */
} brix_wrts_entry_t;

/* ---- pgwrite CSE (checksum-error) uncorrected-page registry (the "Fob") ----
 *
 * Per-open-file set of pages that failed CRC32c on a kXR_pgwrite and have NOT
 * yet been corrected by a kXR_pgRetry resend.  kXR_close fails with
 * kXR_ChkSumErr while any page remains uncorrected — this is what preserves
 * data integrity once corrupt bytes are written to disk (accept-then-correct).
 * Capacity is kXR_pgMaxEos (256); a fixed array keyed by the stock encoding
 * key = (offset << kXR_pgPageBL) | (dlen < pgPageSZ ? dlen : 0). */
#define BRIX_PGW_FOB_SLOTS 256   /* == kXR_pgMaxEos */

typedef struct {
    int64_t  key;      /* encoded (offset,dlen) — valid only when used == 1 */
    uint8_t  used;     /* 1 = slot occupied (key 0 is a legal member)       */
} brix_pgw_fob_entry_t;

/* ---- File: file.h — Per-open-file bookkeeping type (brix_file_t) ----
 *
 * PURPOSE:
 *   One brix_file_t per open XRootD file handle.
 *   Array index IS the handle value (0..BRIX_MAX_FILES-1).
 *   Clients echo this 4-byte opaque value in kXR_read/write/close.
 *
 * LIFECYCLE:
 *   - Open: fd set, path allocated, device/inode captured
 *   - Read: bytes_read accumulated, read tracking updated
 *   - Write: bytes_written accumulated, posc/TPC state managed
 *   - Close: fd closed, slot reset to -1 via brix_free_fhandle()
 *
 * KEY FEATURES:
 * - Immutable fields: is_regular, device, inode (captured at open)
 * - Read tracking: read_last_end, read_ahead_end (WILLNEAD hints)
 * - Checkpoint: ckp_path, ckp_size (kXR_chkpoint state)
 * - POSC: posc_final_path (persist-on-successful-close)
 * - TPC Destination: tpc_*, rendezvous state for native root:// pulls
 * - Write-through: wt_*, XrdPfcFile dirty semantics mirror
 * - Async Flush: wt_flush_task, wt_flush_pending
 *
 * DESIGN DECISIONS:
 * 1. Array index = handle value — direct O(1) lookup, no hash table
 * 2. Bound connections validate device/inode — nginx workers cannot share
 *    post-fork fd integers safely
 * 3. POSC atomic rename — temp at open, rename on clean close, unlink on error
 * 4. TPC mirrors XrdCl: open target → sync arm → open source → sync copy
 * 5. Write-through dirty semantics: wt_dirty_offset tracks pending writes
 *
 * THREAD SAFETY: Single worker thread owns handle — no locks needed.
 *
 * MEMORY:
 *   - path: ngx_palloc'd on open, freed on close
 *   - ckp_path, posc_final_path: heap allocated, freed on close
 *   - tpc_src_path: PATH_MAX stack buffer
 *   - wt_flush_task: heap allocated, freed in completion callback
 */

/*
 * Per-open-file bookkeeping (brix_file_t).
 *
 * One slot per open file handle.  The array index IS the XRootD "file
 * handle" — a 4-byte opaque value the client echoes back in kXR_read,
 * kXR_write, kXR_close, etc.  We use the index directly, so handle
 * values are 0..BRIX_MAX_FILES-1.
 *
 * A slot is "in use" when fd >= 0.  On kXR_close (or disconnect), fd
 * is closed and reset to -1 via brix_free_fhandle().
 *
 * Requires: ngx_msec_t (ngx_config.h + ngx_core.h) before inclusion.
 */
typedef struct {
    int        fd;              /* OS file descriptor; -1 means slot is free */
    char      *path;            /* resolved absolute path (allocated on open) */
    size_t     bytes_read;      /* cumulative bytes read via this handle */
    size_t     bytes_written;   /* cumulative bytes written via this handle */
    ngx_msec_t open_time;       /* timestamp of kXR_open (for throughput log) */
    brix_sess_xfer_t sess_xfer; /* session lifecycle transfer record */
    int        writable;        /* 1 = opened with write permission */
    /*
     * Phase-105: the ENDPOINT's write posture, copied by value when the handle
     * was opened. `writable` records what the client asked for and the open
     * granted; this records whether the export may be written at all. They are
     * separate because a handle outlives the request that opened it — a reload
     * can flip the endpoint to read-only under a still-open write handle, and
     * every later write/truncate/sync must decide from the generation that
     * opened it (Appendix D.5 / I.2). Zero is READ_ONLY, so a slot that never
     * ran the open-time initializer cannot be written through.
     */
    brix_vfs_mutation_policy_t mutation_policy;
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
     * codec ordinal (brix_codec_id_t) when the client opened this read handle
     * with "?xrootd.compress=<codec>" AND the server has brix_read_compress
     * on.  0 (BRIX_CODEC_IDENTITY) means no compression — the default, byte-
     * identical hot read path.  kXR_read responses for a non-zero codec are
     * codec-framed; pgread/readv ignore this field and always serve plaintext
     * (preserving the pgread kXR_status + per-page CRC32c invariant).  Stored as
     * a plain uint8_t so file.h needs no codec_core.h dependency.
     */
    uint8_t    read_codec;

    /*
     * Phase-42 W5 — root:// inline write decompression.  Negotiated codec ordinal
     * (brix_codec_id_t) when a WRITE handle was opened with "?xrootd.compress="
     * AND brix_write_compress is on.  0 = no compression (the default, byte-
     * identical write path).  Each kXR_write payload on such a handle is a
     * self-contained codec frame the server decompresses (bomb-guarded) before
     * storing plaintext; pgwrite ignores this field and stays plaintext.
     */
    uint8_t    write_codec;
    size_t     slice_size;        /* bytes per slice (from cache_slice_size) */

    /*
     * Phase-57 W2 ZIP member access.  When zip_mode is set this read handle's
     * fd is the ARCHIVE fd, and the handle serves one member of it: stored
     * members (zip_method 0) by pure offset translation (fd read at
     * zip_data_off + request offset), deflate members (zip_method 8) by
     * streaming inflate through zip_inflate (a brix_codec_stream_t*, lazily
     * created on first read).  cached_size holds the member's UNCOMPRESSED size
     * (the logical file size reported to clients).  Read-only: write/pgwrite/
     * truncate/sync on a zip_mode handle are rejected.  pgread/readv reject
     * deflate members (the per-page CRC32c invariant can't span a reconstructed
     * stream); stored members are fine.
     */
    unsigned   zip_mode:1;
    uint16_t   zip_method;        /* 0 = stored, 8 = deflate */
    uint64_t   zip_data_off;      /* archive offset of the member's first data byte */
    uint64_t   zip_comp_size;     /* compressed bytes in the archive */
    uint64_t   zip_uncomp_size;   /* uncompressed (logical) size == cached_size */
    uint32_t   zip_crc32;         /* expected IEEE CRC-32 of the uncompressed data */
    void      *zip_inflate;       /* brix_codec_stream_t* (deflate); NULL until used */
    uint64_t   zip_logical_pos;   /* next uncompressed offset the inflate stream will emit */
    uint64_t   zip_comp_pos;      /* next compressed offset consumed from the archive */

    /* kXR_chkpoint state: non-NULL ckp_path means a checkpoint is active. */
    char      *ckp_path;        /* absolute path to the checkpoint temp file */
    int64_t    ckp_size;        /* file size (bytes) captured at kXR_ckpBegin */

    /*
     * kXR_posc (persist-on-successful-close) state.
     *
     * When a write open carries kXR_posc the file is staged to a temporary
     * path.  On a clean kXR_close the temp is renamed to posc_final_path.
     * On disconnect / error close brix_free_fhandle() unlinks the temp
     * (via the path field, which was set to the temp path at open time).
     * posc_final_path is heap-allocated (ngx_alloc / ngx_free), like path.
     */
    char      *posc_final_path; /* target path for POSC rename; NULL if not POSC */

    /*
     * Upload-resume staging (brix_upload_resume on).  When set, `path` is a
     * DETERMINISTIC identity-keyed partial (brix_make_resume_path) and
     * posc_final_path is the destination, so the close-time POSC rename commits
     * it.  The difference from plain POSC: brix_free_fhandle() must NOT unlink
     * the partial on a disconnect/abort — it is preserved on disk so the same
     * client reconnecting (re-open in place, no truncate) resumes from its
     * offset.  Cleared once committed (close) so the free path leaves the renamed
     * final file alone.
     */
    unsigned   is_resume:1;

    /* ---- Native root:// TPC destination state ----
     *
     * PURPOSE: Destination-side TPC open with delayed source fetch.
     * Client drives rendezvous via kXR_sync.
     *
     * SEQUENCE (mirrors XrdCl):
     * 1. Open target (writable handle)
     * 2. kXR_sync → arm rendezvous (tpc_armed=1)
     * 3. Open source with tpc.dst
     * 4. kXR_sync → run copy (tpc_started=1)
     * 5. Copy completes (tpc_done=1)
     *
     * FIELDS:
     * - tpc_destination: 1 = pending TPC target
     * - tpc_armed: first kXR_sync acknowledged rendezvous
     * - tpc_started: pull task posted
     * - tpc_done: pull completed successfully
     * - tpc_key[128]: shared rendezvous key
     * - tpc_org[256]: origin identity sent to source
     * - tpc_src_host/port/path: remote source address
     * - tpc_token_mode[32]: OAuth2/OIDC delegation mode
     * - tpc_streams: parallel source read streams (F7)
     * - tpc_transfer_id: shared TPC registry entry
     *
     * F16 PUSH: When tpc_push=1, this handle is SOURCE of push.
     * tpc_src_* triple names remote destination. Reused for both
     * pull and push — exactly one "remote peer" per TPC handle.
     */
    int        tpc_armed;        /* first kXR_sync acknowledged rendezvous setup */
    int        tpc_started;      /* pull task has been posted */
    int        tpc_done;         /* pull completed successfully */
    char       tpc_key[128];     /* shared TPC rendezvous key */
    char       tpc_org[256];     /* origin identity sent to source as tpc.org */
    int        tpc_org_unresolved; /* tpc_org holds the numeric fallback: the
                                    * client PTR was pending at open (origin_id.c) */
    /*
     * F16 push. When tpc_push is set this handle is the SOURCE of a push
     * (tpc.stage=push): it was opened for READ, and the tpc_src_* triple below
     * names the remote DESTINATION this server will dial and write to. The
     * triple is reused rather than duplicated so there is exactly one "remote
     * peer" address on a TPC handle, and exactly one place the egress guard
     * has to cover; tpc_push is the only bit that says which way bytes move.
     */
    int        tpc_push;         /* 1 = source side of an F16 push */

    char       tpc_src_host[256];/* remote peer: source (pull) or dest (push) */
    uint16_t   tpc_src_port;     /* 0 means default XRootD port */
    char       tpc_src_path[PATH_MAX]; /* remote path at that peer */
    char       tpc_token_mode[32]; /* OAuth2/OIDC delegation mode for source auth */
    int        tpc_streams;     /* parallel source read streams (F7), >= 1 */
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

    int              wt_enabled;      /* 1 = legacy run_flush write-back for this handle */
    int              wt_stage_flush;  /* 1 = write routed through the wt sd_stage decorator
                                       * (Option A): flush happens on the storage path (sync
                                       * job / close); close does an explicit fsync-and-check
                                       * so a failed flush still fails the close (durability). */
    uint8_t          wt_policy;       /* cached decision at open time — BRIX_WT_* */
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
     * checks this ring via brix_wrts_is_replay() and short-circuits the
     * pwrite() when the range is already covered — making the replay idempotent
     * and preventing data corruption (double-write).
     *
     * wrts_enabled  = 1 when the journal is active (writable open + recover_writes on)
     * wrts_head     = next write slot (mod BRIX_WRTS_JOURNAL_SLOTS)
     * wrts_count    = number of valid entries (capped at BRIX_WRTS_JOURNAL_SLOTS)
     * wrts_gen      = per-handle write generation counter (incremented per record)
     */
    int                  wrts_enabled;
    uint32_t             wrts_head;
    uint32_t             wrts_count;
    uint32_t             wrts_gen;
    brix_wrts_entry_t  wrts_journal[BRIX_WRTS_JOURNAL_SLOTS];

    /* ---- pgwrite CSE uncorrected-page registry (the "Fob") ----
     * pgw_fob_enabled = 1 once a writable handle has taken the pgwrite path.
     * pgw_fob_count   = number of pages currently uncorrected (gates close).
     * pgw_fob_errs    = cumulative bad pages ever recorded (stats).
     * pgw_fob_fixes   = cumulative pages corrected via kXR_pgRetry (stats). */
    int                     pgw_fob_enabled;
    uint32_t                pgw_fob_count;
    uint32_t                pgw_fob_errs;
    uint32_t                pgw_fob_fixes;
    brix_pgw_fob_entry_t  pgw_fob[BRIX_PGW_FOB_SLOTS];

    /* Live transfer monitor slot index — index into brix_transfer_table_t.slots[].
     * -1 means this handle is not currently tracked (table full, or dashboard disabled). */
    int32_t  dashboard_slot;

    /* Phase 33 C2 — bound-secondary SHM handle-table slot hint.
     * For a bound stream, brix_ensure_read_handle() re-validates the published
     * handle under brix_handle_mutex on EVERY read.  Caching the slot index
     * matched on the first lookup turns the per-read linear scan of the handle
     * table into an O(1) direct check (still under the lock, still re-validating
     * sessid/handle_index/in_use + device/inode, so a primary close/reuse is
     * detected exactly as before).  -1 = no cached slot (cold or just-freed);
     * the hinted lookup falls back to a full scan and refreshes the hint. */
    int      shared_handle_slot_hint;

    /* §7 XrdSsi: non-NULL marks this handle as an SSI request/response channel
     * (no real fd). Points to an brix_ssi_req_t (connection-pool allocated); the
     * read/write handlers branch on it and brix_free_fhandle clears it. */
    void    *ssi;

    /* phase-59 W2: non-NULL when CSI page-checksum integrity is active for this
     * handle. Points to a heap-allocated brix_csi_t (its own tag-file fd);
     * read verifies, write/pgwrite update, brix_free_fhandle closes+frees it. */
    void    *csi;

    /* Layer-3 storage-driver object for this handle.  When a non-POSIX backend
     * (block-striped / object store) is bound to the export, sd_obj.driver is
     * non-NULL and all byte I/O for this handle routes through it; the bare `fd`
     * above is then a driver-managed descriptor (block-0 fd or -1).  When
     * sd_obj.driver == NULL (the default POSIX export) data I/O POSIX-wraps `fd`,
     * byte-for-byte the pre-Layer-3 path. */
    brix_sd_obj_t  sd_obj;

    /* ---- root:// block-write → whole-object staged-commit adapter (phase-70) ----
     *
     * PURPOSE: Enables root:// uploads to whole-object backends (S3, HTTP).
     * Same unified verified-write session as GridFTP STOR / WebDAV/S3 PUT.
     *
     * PROBLEM: Block-oriented root:// (kXR_open → kXR_write → kXR_sync/close)
     * cannot open session-writable handle on non-random-write backends.
     *
     * SOLUTION: STAGED mode with brix_vfs_writer:
     * - kXR_write/pgwrite: APPEND block via brix_vfs_writer_write
     * - kXR_sync/close: COMMIT whole object via brix_vfs_writer_commit
     * - Result: Single whole-object PUT (with optional CRC check)
     *
     * SEMANTICS:
     * - Sequential-append only (out-of-order offset → kXR_Unsupported)
     * - writer != NULL = "staged mode" flag
     * - writer tracks sequential cursor (brix_vfs_writer_expected_off)
     * - staged_committed guards against double commit
     * - brix_free_fhandle releases session (abort if not committed)
     *
     * FIELDS:
     * - writer: brix_vfs_writer_t* (non-NULL = staged mode)
     * - staged_committed: 1 = object already committed (sync/close)
     * - staged_excl: 1 = kXR_new (commit must publish ABSENT-only)
     */
    unsigned           staged_committed:1;  /* 1 = object already committed (sync/close) */
    unsigned           staged_excl:1;       /* 1 = kXR_new (no kXR_delete): commit must
                                             * publish ABSENT-only — the storage decides
                                             * at publish time (phase-107 C1), the open-
                                             * time existence check is only a fast path */

    /* phase-92: XrdBwm-style bandwidth reservation (net/ratelimit/reservation.c).
     * Bytes this handle reserved against the configured brix_throttle_bandwidth_zone
     * at open (0 = none held). Released by the exact amount at close/disconnect so
     * concurrent reads free their own budget. */
    uint64_t           bwm_reserved;

} brix_file_t;

#endif /* BRIX_TYPES_FILE_H */
