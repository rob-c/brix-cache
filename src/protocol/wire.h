#pragma once

/*
 * Packed wire structures for the XRootD root:// protocol.
 * All multi-byte integers are big-endian (network byte order).
 * Use htonl/ntohl/htons/ntohs when reading/writing these structs.
 *
 * The structs must match the on-the-wire byte layout exactly; any
 * compiler-inserted padding would corrupt request parsing immediately.
 */

#include "types.h"
#include "opcodes.h"

#pragma pack(push, 1)

/* ------------------------------------------------------------------ */
/* Initial handshake                                                    */
/* ------------------------------------------------------------------ */

/*
 * ClientInitHandShake — 20 bytes sent by the client on connect.
 * Validate: third==0, fourth==htonl(4), fifth==htonl(ROOTD_PQ==2012).
 */
typedef struct {
    kXR_int32  first;    /* 0x00000000 */
    kXR_int32  second;   /* 0x00000000 */
    kXR_int32  third;    /* 0x00000000 */
    kXR_int32  fourth;   /* htonl(4)   */
    kXR_int32  fifth;    /* htonl(2012 = ROOTD_PQ) */
} ClientInitHandShake;   /* 20 bytes */

/*
 * ServerInitHandShake — legacy 12-byte server handshake response.
 *
 * This is NOT standard ServerResponseHdr framing — it has its own layout:
 *   msglen[4] + protover[4] + msgval[4]
 *
 * DO NOT USE for XRootD v5 clients.  v5 clients send handshake + kXR_protocol
 * as a single 44-byte segment and expect EACH server reply to be a standard
 * 8-byte ServerResponseHdr + body.  Sending this old 12-byte frame parses as
 * status=0x0008 / dlen=1312, causing the client to stall.
 *
 * This struct is kept for reference only.  The module responds to the
 * handshake with a standard ServerResponseHdr{streamid={0,0}, status=kXR_ok,
 * dlen=8} followed by 8 bytes of protover+msgval.
 */
typedef struct {
    kXR_unt32  msglen;   /* htonl(8): 8 more bytes follow */
    kXR_unt32  protover; /* server protocol version       */
    kXR_unt32  msgval;   /* kXR_LBalServer=0 or kXR_DataServer=1 */
} ServerInitHandShake;   /* 12 bytes — legacy, not used */

/* ------------------------------------------------------------------ */
/* Common request / response framing                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];  /* client-chosen, echoed in response */
    kXR_unt16  requestid;    /* one of the kXR_* constants        */
    kXR_char   body[16];     /* request-specific parameters       */
    kXR_int32  dlen;         /* payload length following header   */
} ClientRequestHdr;          /* 24 bytes; payload follows inline  */

typedef struct {
    kXR_char   streamid[2];  /* echoed from request */
    kXR_unt16  status;       /* kXR_ok / kXR_error / ... */
    kXR_int32  dlen;         /* response body length */
} ServerResponseHdr;         /* 8 bytes; body follows inline */

/*
 * kXR_status (4007) extended response — used for kXR_pgwrite and kXR_pgread.
 * The server sends kXR_status instead of kXR_ok; the body carries a
 * ServerResponseBody_Status (16 bytes) with a CRC32c integrity field,
 * followed by the request-specific body (ServerResponseBody_pgWrite, 8 bytes).
 *
 * Wire layout for kXR_pgwrite success (no bad pages), 32 bytes total:
 *   [ServerResponseHdr 8B] status=kXR_status, dlen=24
 *   [ServerResponseBody_Status 16B] crc32c, streamID, requestid, resptype,
 *                                   reserved, dlen=0 (no bad pages)
 *   [ServerResponseBody_pgWrite 8B] offset (last written)
 */
typedef struct {
    kXR_unt32  crc32c;      /* CRC32c of everything from &streamID to end */
    kXR_char   streamID[2]; /* echo of request streamid                   */
    kXR_char   requestid;   /* requestcode - kXR_1stRequest               */
    kXR_char   resptype;    /* 0=kXR_FinalResult, 1=kXR_PartialResult     */
    kXR_char   reserved[4];
    kXR_int32  dlen;        /* size of bad-page list (0 = no bad pages)   */
} ServerResponseBody_Status;   /* 16 bytes */

typedef struct {
    kXR_int64  offset;      /* file offset of written data */
} ServerResponseBody_pgWrite;  /* 8 bytes */

/* Full kXR_status response for pgwrite (sent as one contiguous buffer) */
typedef struct {
    ServerResponseHdr          hdr; /* status=kXR_status, dlen=24 */
    ServerResponseBody_Status  bdy;
    ServerResponseBody_pgWrite pgw;
} ServerStatusResponse_pgWrite; /* 32 bytes */

typedef struct {
    kXR_int32  errnum;    /* XRootD error code; one of kXR_* in opcodes.h */
    char       errmsg[1]; /* null-terminated human-readable message;
                           * actual length = dlen - 4 bytes */
} ServerErrorBody;

typedef struct {
    kXR_int32  port;      /* TCP port of the redirect target, big-endian */
    char       host[1];   /* null-terminated target hostname or IP;
                           * actual length = dlen - 4 bytes */
} ServerRedirectBody;

/* ------------------------------------------------------------------ */
/* kXR_protocol (3006)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_protocol */
    kXR_int32  clientpv;     /* client protocol version */
    kXR_char   flags;        /* kXR_secreqs, kXR_ableTLS, etc. */
    kXR_char   expect;       /* kXR_ExpLogin = 0x03            */
    kXR_char   reserved[10];
    kXR_int32  dlen;         /* 0 */
} ClientProtocolRequest;     /* 24 bytes */

typedef struct {
    kXR_int32  pval;         /* server protocol version */
    kXR_int32  flags;        /* kXR_isServer | ... */
} ServerProtocolBody;        /* 8 bytes, dlen=8 */

/* ------------------------------------------------------------------ */
/* kXR_login (3007)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_login */
    kXR_int32  pid;          /* client process ID (informational) */
    kXR_char   username[8];  /* client username, NUL-padded, not NUL-terminated
                              * if exactly 8 chars; use strnlen() not strlen() */
    kXR_char   ability2;     /* extended ability flags (kXR_ableTLS etc.) */
    kXR_char   ability;      /* ability flags (kXR_fullurl, kXR_multipr, etc.) */
    kXR_char   capver;       /* protocol version byte | kXR_asyncap if capable */
    kXR_char   reserved;
    kXR_int32  dlen;         /* byte length of auth token payload following hdr;
                              * 0 for unauthenticated (anonymous) login.
                              * dlen is untrusted input — validate before
                              * allocating or reading dlen bytes */
} ClientLoginRequest;        /* 24 bytes */

typedef struct {
    kXR_char   sessid[XROOTD_SESSION_ID_LEN];  /* 16 opaque bytes assigned by
                              * the server; echoed by kXR_bind and kXR_endsess.
                              * The login ctx is connection-scoped — multiple
                              * requests on one TCP connection share it. */
    /* optional: security info follows if dlen > 16 */
} ServerLoginBody;

/* ------------------------------------------------------------------ */
/* kXR_open (3010)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_open */
    kXR_unt16  mode;         /* POSIX permission bits (e.g. 0644 = 0x01B4) */
    kXR_unt16  options;      /* kXR_open_read | kXR_retstat | ... */
    kXR_unt16  optiont;      /* extended open flags */
    kXR_char   reserved[6];
    kXR_char   fhtemplt[4];  /* file handle template (usually 0) */
    kXR_int32  dlen;         /* length of path payload */
    /* null-terminated path follows as payload */
} ClientOpenRequest;         /* 24 bytes */

typedef struct {
    kXR_char   fhandle[4];   /* opaque file handle for subsequent ops */
    kXR_int32  cpsize;       /* compression page size (0 = uncompressed) */
    kXR_char   cptype[4];    /* compression type (e.g. "adl\0") */
    /* if kXR_retstat set: ASCII stat string follows */
} ServerOpenBody;            /* 12 bytes minimum */

/* ------------------------------------------------------------------ */
/* kXR_prepare (3021)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_prepare */
    kXR_char   options;      /* kXR_stage, kXR_cancel, kXR_notify, ... */
    kXR_char   prty;         /* request priority */
    kXR_unt16  port;         /* notification port when kXR_notify is set */
    kXR_unt16  optionX;      /* extended prepare flags, e.g. kXR_evict */
    kXR_char   reserved[10];
    kXR_int32  dlen;         /* newline-separated paths or cancel token */
} ClientPrepareRequest;      /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_read (3013)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_read */
    kXR_char   fhandle[4];   /* file handle from open */
    kXR_int64  offset;       /* byte offset to read from */
    kXR_int32  rlen;         /* bytes to read */
    kXR_int32  dlen;         /* 0 for basic read */
} ClientReadRequest;         /* 24 bytes */
/* Response body: raw file bytes, dlen bytes */

/* ------------------------------------------------------------------ */
/* kXR_stat (3017)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_stat */
    kXR_char   options;      /* kXR_vfs or 0 */
    kXR_char   reserved[7];
    kXR_unt32  wants;        /* 0 */
    kXR_char   fhandle[4];   /* 0 if path-based stat, else open handle */
    kXR_int32  dlen;         /* path length (0 if using fhandle) */
    /* null-terminated path follows as payload */
} ClientStatRequest;         /* 24 bytes */
/*
 * Response body: ASCII string (null-terminated):
 *   "<id> <size> <flags> <modtime>"
 * e.g. "1234567 16 65536 1700000000"
 */

/* ------------------------------------------------------------------ */
/* kXR_close (3003)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_close */
    kXR_char   fhandle[4];   /* file handle to close */
    kXR_char   reserved[12];
    kXR_int32  dlen;         /* 0 */
} ClientCloseRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_ping (3011)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_ping */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* 0 */
} ClientPingRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_dirlist (3004)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_dirlist */
    kXR_char   reserved[15];
    kXR_char   options;      /* kXR_online | kXR_dstat | kXR_dcksm */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientDirlistRequest;      /* 24 bytes */
/*
 * Response body: newline-separated entries (null-terminated at end):
 *   "name\n[id flags size mtime\n]..."
 * Last chunk uses kXR_ok; intermediate chunks use kXR_oksofar.
 *
 * kXR_dstat wire format:
 * When kXR_dstat is set the server MUST prepend the 10-byte sentinel
 *   ".\n0 0 0 0\n"
 * to the response body before any real entries.  The XRootD client checks
 * for the 9-byte prefix ".\n0 0 0 0" (DirectoryList::dStatPrefix) and only
 * enters stat-pairing mode if it is present.  Without it the client treats
 * every newline-delimited line (including stat lines) as a plain filename.
 *
 * Body layout (after the lead-in):
 *   "<name1>\n<id1> <size1> <flags1> <mtime1>\n"   ← pair
 *   "<name2>\n<id2> <size2> <flags2> <mtime2>\n"   ← pair
 *   ...
 * kXR_dcksm implies kXR_dstat and uses the reference extended stat shape so
 * XRootD clients can recognize the checksum token:
 *   "<id> <size> <flags> <mtime> <ctime> <atime> <mode> <uid> <gid> [ adler32:01234567 ]"
 *
 * The final '\n' is replaced by '\0' (NUL-terminator).
 * Intermediate kXR_oksofar chunks do NOT carry the lead-in or a NUL;
 * they are raw newline-delimited data that the client accumulates.
 */

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

/* ------------------------------------------------------------------ */
/* kXR_truncate (3028)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_truncate */
    kXR_char   fhandle[4];   /* file handle (if dlen==0) */
    kXR_int64  offset;       /* target file length */
    kXR_char   reserved[4];
    kXR_int32  dlen;         /* path length (path-based) or 0 (handle-based) */
    /* null-terminated path follows as payload when dlen > 0 */
} ClientTruncateRequest;     /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_mkdir (3008)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_mkdir */
    kXR_char   options[1];   /* kXR_mkdirpath (0x01) to create parents */
    kXR_char   reserved[13];
    kXR_unt16  mode;         /* POSIX permission bits */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientMkdirRequest;        /* 24 bytes */

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

/* ------------------------------------------------------------------ */
/* kXR_readv (3025) — scatter-gather / vector read                     */
/* ------------------------------------------------------------------ */

/*
 * Each entry describes one read segment.  The response body is the same
 * structure (with actual rlen filled in) followed immediately by rlen bytes
 * of file data, repeated N times.
 *
 * Wire sizes (all big-endian):
 *   fhandle  4 bytes  open file handle
 *   rlen     4 bytes  requested / actual byte count
 *   offset   8 bytes  file byte offset
 *   -------- 16 bytes per segment   (XROOTD_READV_SEGSIZE)
 *
 * Source: XProtocol.hh  struct readahead_list / read_list
 */
typedef struct {
    kXR_char   fhandle[4];  /* open file handle from kXR_open               */
    kXR_int32  rlen;        /* request: bytes wanted; response: bytes given  */
    kXR_int64  offset;      /* file byte offset                              */
} readahead_list;           /* 16 bytes; network byte order                  */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_readv */
    kXR_char   reserved[15];
    kXR_char   pathid;      /* 0 for primary path */
    kXR_int32  dlen;        /* N * sizeof(readahead_list) */
    /* payload: N readahead_list structs */
} ClientReadVRequest;       /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_query (3001)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_query */
    kXR_unt16  infotype;    /* one of kXR_Q* in opcodes.h                 */
    kXR_char   reserved1[2];
    kXR_char   fhandle[4];  /* open file handle (for handle-based queries) */
    kXR_char   reserved2[8];
    kXR_int32  dlen;        /* path length (0 for handle-based queries)   */
    /* null-terminated path follows as payload when dlen > 0              */
} ClientQueryRequest;       /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_endsess (3023)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_endsess */
    kXR_char   sessid[16];   /* session to terminate */
    kXR_int32  dlen;         /* 0 */
} ClientEndsessRequest;      /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_bind (3024)                                                      */
/* ------------------------------------------------------------------ */

/*
 * kXR_bind attaches a secondary TCP connection ("data channel") to an
 * existing session.  The client sends the primary session's sessid so the
 * server can link the two connections.  The server responds with a 1-byte
 * pathid that the client echoes back in kXR_read/kXR_write pathid fields
 * to tell the server which data channel carries that request.
 *
 * Pathid 0 is reserved for the primary connection.
 */
typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_bind */
    kXR_char   sessid[16];   /* primary connection session ID */
    kXR_int32  dlen;         /* 0 */
} ClientBindRequest;         /* 24 bytes */
/* Response body: 1 byte — pathid assigned to this data channel (1–253). */

/* ------------------------------------------------------------------ */
/* kXR_pgread (3030) — paged read with per-page CRC32c checksums       */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_pgread */
    kXR_char   fhandle[4];
    kXR_int64  offset;
    kXR_int32  rlen;
    kXR_int32  dlen;           /* 0, 1 (pathid), or 2 (pathid+reqflags) */
} ClientPgReadRequest;         /* 24 bytes */

typedef struct {
    kXR_char   pathid;         /* kXR_AnyPath = 0xff = server chooses */
    kXR_char   reqflags;       /* kXR_pgRetry = 0x01 */
} ClientPgReadReqArgs;

typedef struct {
    kXR_int64  offset;         /* file offset of first byte of returned data */
} ServerResponseBody_pgRead;   /* 8 bytes */

typedef struct {
    ServerResponseHdr          hdr;
    ServerResponseBody_Status  bdy;
    ServerResponseBody_pgRead  pgr;
} ServerStatusResponse_pgRead; /* 32 bytes; interleaved data+crc follows */

/* ------------------------------------------------------------------ */
/* kXR_chkpoint (3012) — checkpoint / transaction write semantics      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_chkpoint */
    kXR_char   fhandle[4];   /* target file handle */
    kXR_char   reserved[11];
    kXR_char   opcode;       /* kXR_ckpBegin=0, kXR_ckpCommit=1, kXR_ckpQuery=2,
                                kXR_ckpRollback=3, kXR_ckpXeq=4 */
    kXR_int32  dlen;         /* 0 for Begin/Commit/Rollback/Query; 24+ for Xeq */
} ClientChkPointRequest;     /* 24 bytes */

typedef struct {
    kXR_unt32  maxCkpSize;   /* maximum checkpoint data size (htonl'd) */
    kXR_unt32  useCkpSize;   /* current checkpoint usage in bytes (htonl'd) */
} ServerResponseBody_ChkPoint;  /* 8 bytes; returned by kXR_ckpQuery */

/* ------------------------------------------------------------------ */
/* kXR_writev (3031) — scatter-gather / vector write                   */
/* ------------------------------------------------------------------ */

/*
 * write_list — one segment descriptor for kXR_writev.
 *
 * Field order: fhandle[4], wlen(int32), offset(int64).
 *
 * CAUTION — struct packing trap: the Python/ctypes equivalent is
 *   struct.pack("!4siq", fhandle, wlen, offset)
 * NOT "!4sqi" — offset is int64 (q) and wlen is int32 (i), in that
 * order after fhandle.  Swapping i/q silently produces wrong offsets.
 */
typedef struct {
    kXR_char   fhandle[4];  /* open file handle from kXR_open */
    kXR_int32  wlen;        /* byte count to write at this segment */
    kXR_int64  offset;      /* file byte offset for this segment */
} write_list;                  /* 16 bytes; network byte order */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_writev */
    kXR_char   options;        /* kXR_wv_doSync = 0x01 — fsync after all segs */
    kXR_char   reserved[15];
    kXR_int32  dlen;           /* N * sizeof(write_list) payload length */
    /* payload: N write_list structs (see write_list comment for field order) */
} ClientWriteVRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_clone (3032) — server-side range copy (protocol v5.2.0)         */
/* ------------------------------------------------------------------ */
/*
 * Header body carries the destination file handle (open for writing).
 * Payload is an array of clone_item entries, each 32 bytes, describing
 * one source→destination copy operation.  All fields are big-endian.
 *
 * Wire layout matches XrdProto::clone_list from XProtocol.hh.
 */

typedef struct {
    kXR_char   src_fhandle[4];  /* source file handle */
    kXR_char   reserved[4];
    kXR_unt64  src_offset;      /* source byte offset */
    kXR_unt64  src_len;         /* bytes to copy (0 = to EOF) */
    kXR_unt64  dst_offset;      /* destination byte offset */
} clone_item;                   /* 32 bytes; network byte order */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;        /* kXR_clone */
    kXR_char   dst_fhandle[4];  /* destination file handle */
    kXR_char   reserved[12];
    kXR_int32  dlen;             /* payload = n * sizeof(clone_item) */
} ClientCloneRequest;            /* 24 bytes */

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

#pragma pack(pop)
