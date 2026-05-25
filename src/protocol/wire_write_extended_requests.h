/* ------------------------------------------------------------------ */
/* kXR_pgwrite (3026) — paged write with per-page CRC32 checksums      */
/* ------------------------------------------------------------------ */

/*
 * Payload: a 4-byte big-endian CRC32c checksum followed by each page
 * fragment's data. The first and last fragments may be shorter when the file
 * offset is unaligned or the write ends mid-page.
 * Layout per fragment: [ crc32c_be[4] ][ data[0..N-1] ]
 */
typedef struct {
    kXR_char  streamid[2];
    kXR_unt16 requestid;    /* kXR_pgwrite */
    kXR_char  fhandle[4];   /* file handle from open */
    kXR_int64 offset;       /* file byte offset for first page */
    kXR_char  pathid;       /* path ID (0 = primary) */
    kXR_char  reqflags;     /* kXR_pgRetry (0x01) or 0 */
    kXR_char  reserved[2];
    kXR_int32 dlen;         /* total payload length (pages + checksums) */
    /* payload: interleaved 4-byte CRC32c checksums and page data */
} ClientPgWriteRequest;     /* 24 bytes */

/* ---- kXR_write (3019) — sequential write section ----
 *
 * WHAT: Request structure for writing contiguous data to a file. Unlike kXR_pgwrite, no per-page CRC32c integrity checking.
 *       Used by legacy clients or simple write operations without checksum verification. */

/* ------------------------------------------------------------------ */
/* kXR_write (3019)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_write */
    kXR_char   fhandle[4];   /* file handle from open */
    kXR_int64  offset;       /* byte offset to write at */
    kXR_char   pathid;       /* path ID (0 for primary) */
    kXR_char   reserved[3];
    kXR_int32  dlen;         /* number of data bytes in payload */
    /* payload: raw file data, dlen bytes */
} ClientWriteRequest;        /* 24 bytes */

/* ---- kXR_sync (3016) — filesystem sync section ----
 *
 * WHAT: Request structure for fsyncing an open file handle to disk. Ensures all buffered writes are committed to storage. */

/* ------------------------------------------------------------------ */
/* kXR_sync (3016)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_sync */
    kXR_char   fhandle[4];   /* file handle to sync */
    kXR_char   reserved[12];
    kXR_int32  dlen;         /* 0 */
} ClientSyncRequest;         /* 24 bytes */

/* ---- kXR_truncate (3028) — file length reduction section ----
 *
 * WHAT: Request structure for reducing a file to a specified length. ClientTruncateRequest can use either path or handle-based approach. */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_truncate */
    kXR_char   fhandle[4];   /* file handle (if dlen==0) */
    kXR_int64  offset;       /* target file length */
    kXR_char   reserved[4];
    kXR_int32  dlen;         /* path length (path-based) or 0 (handle-based) */
    /* null-terminated path follows as payload when dlen > 0 */
} ClientTruncateRequest;     /* 24 bytes */

/* ---- kXR_mkdir (3008) — directory creation section ----
 *
 * WHAT: Request structure for creating a new directory. ClientMkdirRequest specifies path, POSIX permission mode, and mkdirpath option for parent creation. */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_mkdir */
    kXR_char   options[1];   /* kXR_mkdirpath (0x01) to create parents */
    kXR_char   reserved[13];
    kXR_unt16  mode;         /* POSIX permission bits */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientMkdirRequest;        /* 24 bytes */

/* ---- kXR_rm (3014) — file removal section ----
 *
 * WHAT: Request structure for deleting a regular file by path. Uses null-terminated path payload. */

/* ------------------------------------------------------------------ */
/* kXR_rm (3014)                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_rm */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientRmRequest;           /* 24 bytes */

/* ---- kXR_rmdir (3015) — directory removal section ----
 *
 * WHAT: Request structure for removing an empty directory by path. Unlike kXR_rm, only removes directories (not files). */

/* ------------------------------------------------------------------ */
/* kXR_rmdir (3015)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_rmdir */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientRmdirRequest;        /* 24 bytes */

/* ---- kXR_mv (3009) — rename/move section ----
 *
 * WHAT: Request structure for renaming or moving a file/directory. Payload contains source path followed by destination path, both null-terminated. */

/* ------------------------------------------------------------------ */
/* kXR_mv (3009)                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_mv */
    kXR_char   reserved[14];
    kXR_int16  arg1len;      /* byte length of source path in payload */
    kXR_int32  dlen;         /* total payload length (src + '\0' + dst) */
    /* payload: source path (arg1len bytes, null-terminated) followed
     *          immediately by dest path (null-terminated) */
} ClientMvRequest;           /* 24 bytes */

/* ---- kXR_chmod (3002) — permission modification section ----
 *
 * WHAT: Request structure for changing POSIX permission bits of a file/directory. Payload is null-terminated path with target mode in header. */

/* ------------------------------------------------------------------ */
/* kXR_chmod (3002)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_chmod */
    kXR_char   reserved[14];
    kXR_unt16  mode;         /* POSIX permission bits */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientChmodRequest;        /* 24 bytes */

/* ---- kXR_endsess (3023) — session termination section ----
 *
 * WHAT: Request structure for gracefully closing an XRootD session. The client sends its sessid to tell the server which session to terminate. */

/* ------------------------------------------------------------------ */
/* kXR_bind (3024)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_bind */
    kXR_char   sessid[16];   /* session to bind to */
    kXR_int32  dlen;         /* 0 */
} ClientBindRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_endsess (3023)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_endsess */
    kXR_char   sessid[16];   /* session to terminate */
    kXR_int32  dlen;         /* 0 */
} ClientEndsessRequest;      /* 24 bytes */

/* ---- kXR_locate (3027) — file replica location query section ----
 *
 * WHAT: Request structure for asking the server to list available replicas of a file. Server responds with space-separated "XY<host:port>" tokens indicating replica locations and access modes. */

/* ------------------------------------------------------------------ */
/* kXR_locate (3027) — file replica location query                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_locate */
    kXR_unt16  options;        /* kXR_refresh, kXR_compress, ... */
    kXR_char   reserved[14];
    kXR_int32  dlen;
} ClientLocateRequest;         /* 24 bytes */
/* Response body: space-separated "XY<host:port>" tokens, NUL-terminated.
 * X = S (server online) | M (manager) | s/m (pending)
 * Y = r (read-only) | w (read-write) */

/* ------------------------------------------------------------------ */
/* kXR_sigver (3029) — request signing verification                    */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_sigver */
    kXR_unt16  expectrid;      /* opcode of the NEXT (signed) request */
    kXR_char   version;        /* kXR_Ver_00 = 0 */
    kXR_char   flags;          /* kXR_nodata_sig = 0x01 */
    kXR_unt64  seqno;          /* monotonically increasing sequence number */
    kXR_char   crypto;         /* kXR_SHA256_sig | kXR_rsaKey_sig */
    kXR_char   rsvd2[3];
    kXR_int32  dlen;
} ClientSigverRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_statx (3022) — multi-path stat                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_statx */
    kXR_char   options;        /* kXR_vfs or 0 */
    kXR_char   reserved[11];
    kXR_char   fhandle[4];
    kXR_int32  dlen;
} ClientStatxRequest;          /* 24 bytes */
/* Response body: NUL-separated stat lines; one line per path:
 *   "<id> <size> <flags> <mtime>\n"  (last entry ends with \0) */

/* ------------------------------------------------------------------ */
/* kXR_fattr (3020) — file extended attributes                         */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_fattr */
    kXR_char   fhandle[4];  /* open file handle (0 if path-based)           */
    kXR_char   subcode;     /* one of kXR_fattrDel/Get/List/Set             */
    kXR_char   numattr;     /* number of attributes in request (0 for list) */
    kXR_char   options;     /* kXR_fa_isNew | kXR_fa_aData                  */
    kXR_char   reserved[9];
    kXR_int32  dlen;
    /*
     * Payload layout for path-based (payload[0] != 0):
     *   [path\0][nvec][vvec]
     *
     * Payload layout for handle-based (payload[0] == 0 or dlen == 0):
     *   [0x00][nvec][vvec]   or   (empty for list with dlen=0)
     *
     * nvec entry: [kXR_unt16 = 0x0000][name\0]   (numattr entries)
     * vvec entry: [kXR_int32 vlen BE][value]      (numattr entries, set only)
     */
} ClientFattrRequest;    /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_set (3018) — set server-side configuration option               */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_set */
    kXR_char   modifier;    /* kXR_set_appid=0x00, kXR_set_clttl=0x01 */
    kXR_char   reserved[15];
    kXR_int32  dlen;        /* payload length (NUL-terminated value string) */
    /* NUL-terminated value string follows as payload */
} ClientSetRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_writev (3025)                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_writev */
    kXR_char   options;     /* kXR_wv_doSync = 0x01 */
    kXR_char   reserved[15];
    kXR_int32  dlen;
    /* followed by array of write_list entries */
} ClientWriteVRequest;       /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_pgread (3031)                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_pgread */
    kXR_char   fhandle[4];  /* file handle */
    kXR_int64  offset;      /* file byte offset */
    kXR_int32  rlen;        /* read length */
    kXR_int32  dlen;        /* 0 unless args present */
} ClientPgReadRequest;      /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_clone (3032) — server-side range copy                           */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_clone */
    kXR_char   dst_fhandle[4];
    kXR_char   reserved[12];
    kXR_int32  dlen;
} ClientCloneRequest;        /* 24 bytes */

/* clone_item: one entry in kXR_clone payload (32 bytes, big-endian) */
typedef struct {
    kXR_char   src_fhandle[4];
    kXR_char   reserved[4];
    kXR_int64  src_offset;
    kXR_int64  src_len;
    kXR_int64  dst_offset;
} clone_item;                /* 32 bytes */

/* ------------------------------------------------------------------ */
/* kXR_chkpoint (3033)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_chkpoint */
    kXR_char   fhandle[4];
    kXR_char   reserved[11];
    kXR_char   opcode;      /* kXR_ckpBegin/Commit/Query/Rollback/Xeq */
    kXR_int32  dlen;
} ClientChkPointRequest;    /* 24 bytes */

/* kXR_chkpoint query response body */
typedef struct {
    kXR_unt32  maxCkpSize;  /* max checkpoint bytes */
    kXR_unt32  useCkpSize;  /* bytes already in use */
} ServerResponseBody_ChkPoint;  /* 8 bytes */

/* ------------------------------------------------------------------ */
/* readahead_list and write_list: readv/writev payload element structs  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   fhandle[4];
    kXR_int32  rlen;
    kXR_int64  offset;
} readahead_list;            /* 16 bytes */

typedef struct {
    kXR_char   fhandle[4];
    kXR_int32  wlen;
    kXR_int64  offset;
} write_list;                /* 16 bytes */

#pragma pack(pop)
