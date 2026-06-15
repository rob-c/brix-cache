#pragma once

/* ------------------------------------------------------------------ */
/* Protocol version and server identity                                 */
/* ------------------------------------------------------------------ */

#define XROOTD_DEFAULT_PORT     1094
#define kXR_PROTOCOLVERSION     0x00000520u  /* current (5.2.0) */
#define kXR_PROTOCOLVERSION_3   0x00000300u  /* stable v3 */

/* Initial handshake magic — fifth field of the client's 20-byte hello.
 * "ROOTD_PQ" is a legacy name; the value 2012 (0x7DC) has no special meaning
 * beyond being the agreed magic number that confirms this is an XRootD client. */
#define ROOTD_PQ  2012

/* Server type — carried in the handshake response msgval field */
#define kXR_LBalServer  0  /* load-balancer / redirector (does not serve files) */
#define kXR_DataServer  1  /* data server — this module always advertises this */

/* ------------------------------------------------------------------ */
/* Fixed wire sizes                                                     */
/* ------------------------------------------------------------------ */

#define XRD_HANDSHAKE_LEN      20  /* client → server, initial hello */
#define XRD_HANDSHAKE_RSP_LEN  12  /* server → client, initial hello (legacy) */
#define XRD_REQUEST_HDR_LEN    24  /* all requests: 2B streamid + 2B reqid + 16B body + 4B dlen */
#define XRD_RESPONSE_HDR_LEN   8   /* all responses: 2B streamid + 2B status + 4B dlen */
#define XRD_FHANDLE_LEN        4   /* opaque file handle from kXR_open */
#define XROOTD_SESSION_ID_LEN  16  /* opaque session ID from kXR_login response */

/* ---- Request IDs (kXR_*) — all client-opcode constants ----
 *
 * WHAT: Numeric opcodes carried in ClientRequestHdr.requestid field of wire.h.
 *       Agents can answer "what opcode does X?" by referring to this section.
 *
 * WHY: Standardizes opcode lookup — all dispatch logic uses these constants from opcodes.h.
 *      Values start at 3000 (legacy ROOTD < 3000 unsupported). Gap at 3026/3031 intentional in spec history.
 *
 * HOW: All opcodes implemented; unrecognised ones get kXR_Unsupported error. Dispatch via xrootd_dispatch_opcode(). */

/* ------------------------------------------------------------------ */
/* Request IDs (kXR_*)                                                  */
/* ------------------------------------------------------------------ */
#define kXR_auth      3000  /* authentication (GSI, token, or negotiation) */
#define kXR_query     3001  /* server/file information query (checksum, space, config…) */
#define kXR_chmod     3002  /* change file permission bits */
#define kXR_close     3003  /* close an open file handle */
#define kXR_dirlist   3004  /* list directory entries (with optional per-entry stat) */
#define kXR_gpfile    3005  /* get/put a file (legacy, unused) */
#define kXR_protocol  3006  /* capability negotiation and TLS handshake */
#define kXR_login     3007  /* session start: send username, receive session ID */
#define kXR_mkdir     3008  /* create a directory */
#define kXR_mv        3009  /* rename / move a file or directory */
#define kXR_open      3010  /* open a file for reading, writing, or creating */
#define kXR_ping      3011  /* liveness check — no payload, just an ack */
#define kXR_chkpoint  3012  /* checkpoint/transaction writes: begin/commit/rollback/query/xeq */
#define kXR_read      3013  /* read bytes from an open file handle */
#define kXR_rm        3014  /* delete a file */
#define kXR_rmdir     3015  /* remove an empty directory */
#define kXR_sync      3016  /* fsync an open file handle to disk */
#define kXR_stat      3017  /* stat a path or open handle; returns id/size/flags/mtime */
#define kXR_set       3018  /* set server-side configuration option */
#define kXR_write     3019  /* write bytes to an open file handle (v3/v4 style) */
#define kXR_fattr     3020  /* get, set, delete, or list file extended attributes */
#define kXR_prepare   3021  /* stage files from tape, cancel a staging request */
#define kXR_statx     3022  /* stat multiple paths in one request */
#define kXR_endsess   3023  /* graceful session termination */
#define kXR_bind      3024  /* bind a secondary data channel to a session (parallel streams) */
#define kXR_readv     3025  /* scatter-gather read: fetch multiple file segments */
#define kXR_pgwrite   3026  /* paged write with per-page CRC32 integrity (xrdcp v5) */
#define kXR_locate    3027  /* locate file replicas (returns host:port list) */
#define kXR_truncate  3028  /* truncate file by path or open handle */
#define kXR_sigver    3029  /* request-signing envelope (HMAC-SHA256) */
#define kXR_pgread    3030  /* paged read with per-page CRC32c integrity */
#define kXR_writev    3031  /* scatter-gather write */
#define kXR_clone     3032  /* server-side range copy (protocol v5.2.0) */

/* ------------------------------------------------------------------ */
/* Vendor extension opcodes (nginx-xrootd local — NOT standard XRootD)  */
/* ------------------------------------------------------------------ */
/*
 * These opcodes close POSIX gaps the base XRootD protocol has no wire op for
 * (set-mtime / chown / symlink / hard-link), so a FUSE mount can honour
 * `cp -p`, `touch -d`, and `ln`/`ln -s`. They are deliberately placed well above
 * the standard range (max real opcode is kXR_clone=3032) to avoid any future
 * collision, and are CAPABILITY-NEGOTIATED: the server advertises support via
 * kXR_Qconfig "xrdfs.ext" and the native client only emits them when advertised,
 * so a stock XRootD server never receives one. The client-side per-opcode RTT
 * table (frame.c) bounds-checks reqid-kXR_1stRequest < XRDC_NOP, so these high
 * ids simply skip RTT accounting — no out-of-bounds access.
 */
#define kXR_setattr   3500  /* set times (utimens) and/or owner (chown) on a path */
#define kXR_symlink   3501  /* create a symbolic link */
#define kXR_readlink  3502  /* read a symbolic link's target */
#define kXR_link      3503  /* create a hard link */

/* ------------------------------------------------------------------ */
/* Response status codes  (ServerResponseHdr.status)                   */
/* ------------------------------------------------------------------ */
/*
 * kXR_ok and kXR_oksofar are success paths; everything above 4000 carries
 * additional data in the response body.  kXR_oksofar means "there is more
 * data coming for this request — keep listening for the next response frame
 * with the same streamid".
 */
#define kXR_ok       0     /* request succeeded; body (if any) is the result */
#define kXR_oksofar  4000  /* partial result — more response frames follow */
#define kXR_attn     4001  /* unsolicited server push notification */
#define kXR_authmore 4002  /* authentication needs another round-trip;
                              body contains the next auth challenge */
#define kXR_error    4003  /* request failed; body = errnum[4] + errmsg (NUL-terminated) */
#define kXR_redirect 4004  /* client should retry at another server;
                              body = port[4] + host (NUL-terminated) */
#define kXR_wait     4005  /* try again after N seconds (body carries N as uint32) */
#define kXR_waitresp 4006  /* async result is coming in a future kXR_attn frame */

/* ------------------------------------------------------------------ */
/* kXR_attn action codes  (body field actnum, big-endian)              */
/* ------------------------------------------------------------------ */
/*
 * These are carried in the 4-byte actnum field at the start of a kXR_attn
 * body.  All values 5000-5007 are deprecated ("No longer supported" in the
 * v5 spec); only kXR_asyncms and kXR_asynresp are still active.
 *
 *   kXR_asyncms  — server-push text notification (unsolicited).
 *                  Body layout: actnum[4] + reserved[4] +
 *                               ServerResponseHdr[8] + message[dlen].
 *                  Outer kXR_attn streamid is {0,0}.
 *
 *   kXR_asynresp — deferred response to a kXR_waitresp-acknowledged request.
 *                  Same body layout; inner ServerResponseHdr carries the
 *                  original request's streamid and actual status.
 *                  Outer kXR_attn streamid mirrors the deferred streamid.
 */
#define kXR_asyncms   5002  /* active: unsolicited server notification message */
#define kXR_asynresp  5008  /* active: deferred response completion */
#define kXR_status   4007  /* extended status with CRC32c integrity check;
                              used for kXR_pgwrite and kXR_pgread responses */

/* ------------------------------------------------------------------ */
/* Error codes  (ServerErrorBody.errnum, carried inside kXR_error)     */
/* ------------------------------------------------------------------ */
/*
 * These are distinct from POSIX errno values.  The module maps errno → kXR_*
 * in the response helpers.  When in doubt, use kXR_FSError for unexpected
 * I/O failures, kXR_ServerError for internal programming errors.
 */
#define kXR_ArgInvalid      3000  /* an argument has an illegal value */
#define kXR_ArgMissing      3001  /* a required argument is absent */
#define kXR_ArgTooLong      3002  /* a path or argument exceeds the allowed length */
#define kXR_FileLocked      3003  /* file is locked by another operation */
#define kXR_FileNotOpen     3004  /* operation attempted on a handle that is not open */
#define kXR_FSError         3005  /* generic filesystem error (check errmsg for detail) */
#define kXR_InvalidRequest  3006  /* the request is malformed or not allowed now */
#define kXR_IOError         3007  /* I/O error reading or writing file data */
#define kXR_NoMemory        3008  /* server ran out of memory */
#define kXR_NoSpace         3009  /* filesystem has no space left */
#define kXR_NotAuthorized   3010  /* caller does not have permission */
#define kXR_NotFound        3011  /* path does not exist */
#define kXR_ServerError     3012  /* unexpected internal server error */
#define kXR_Unsupported     3013  /* the requested operation is not implemented */
#define kXR_noserver        3014  /* no server is available to handle the request */
#define kXR_NotFile         3015  /* path exists but is not a regular file */
#define kXR_isDirectory     3016  /* path is a directory, not a file */
#define kXR_Cancelled       3017  /* the request was cancelled by the client */
#define kXR_ItExists        3018  /* file already exists (raised by kXR_new flag) */
#define kXR_ChkSumErr       3019  /* CRC32c checksum mismatch in pgwrite payload */
#define kXR_inProgress      3020  /* a conflicting operation is already in progress */
#define kXR_overQuota       3021  /* caller has exceeded their storage quota */
#define kXR_Overloaded      3024  /* server is too busy; client should try later */
#define kXR_fsReadOnly      3025  /* filesystem is mounted read-only */
#define kXR_AttrNotFound    3027  /* named extended attribute does not exist */
#define kXR_TLSRequired     3028  /* this operation requires TLS to be active */
#define kXR_AuthFailed      3030  /* authentication credentials were rejected */
#define kXR_Impossible      3031  /* request is logically impossible */
#define kXR_Conflict        3032  /* conflicting options or state */
#define kXR_TooManyErrs     3033  /* too many errors — server giving up */

/* ------------------------------------------------------------------ */
/* kXR_status encoding base                                             */
/* ------------------------------------------------------------------ */
/*
 * ServerResponseBody_Status.requestid stores (original_requestcode - kXR_1stRequest)
 * so that a 1-byte field can identify which request triggered this status frame.
 * Example: kXR_pgwrite (3026) → stored as 3026 - 3000 = 26.
 */
#define kXR_1stRequest  3000

/* ------------------------------------------------------------------ */
/* kXR_query infotype codes (kXR_Q*)                                   */
/* ------------------------------------------------------------------ */
/*
 * Sent in ClientQueryRequest.infotype to select what kind of information
 * the server should return.  The response body is always a text string.
 */
#define kXR_QStats   1   /* server-wide statistics (human-readable text) */
#define kXR_QPrep    2   /* state of a pending prepare/staging request */
#define kXR_Qcksum   3   /* compute a file checksum; body = "adler32 <hex>" */
#define kXR_Qxattr   4   /* query extended attributes (legacy; prefer kXR_fattr) */
#define kXR_Qspace   5   /* storage space stats: "oss.space=<n> oss.free=<n>..." */
#define kXR_Qckscan  6   /* initiate or cancel a checksum scan */
#define kXR_Qconfig  7   /* retrieve server configuration values by key */
#define kXR_Qvisa    8   /* visa / authorization string */
#define kXR_QFinfo   9   /* file information (internal format) */
#define kXR_QFSinfo  10  /* filesystem layout information */
#define kXR_Qopaque  16  /* unstructured implementation-defined query */
#define kXR_Qopaquf  32  /* implementation-defined path/opaque query */
#define kXR_Qopaqug  64  /* implementation-defined query against an open file */

/* ------------------------------------------------------------------ */
/* kXR_fattr suboperation codes                                         */
/* ------------------------------------------------------------------ */
/*
 * Carried in ClientFattrRequest.subcode to select the operation.
 * All attributes are stored as Linux xattrs with the "user.U." prefix
 * stripped before they reach the client.
 */
#define kXR_fattrDel   0  /* delete the named attributes */
#define kXR_fattrGet   1  /* retrieve values for the named attributes */
#define kXR_fattrList  2  /* enumerate all attribute names on the file */
#define kXR_fattrSet   3  /* create or overwrite named attributes */
#define kXR_fattrMaxSC 3  /* highest valid subcode (use for bounds checks) */
