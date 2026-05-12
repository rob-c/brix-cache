#pragma once

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
} xrootd_file_t;
