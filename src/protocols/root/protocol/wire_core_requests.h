#ifndef BRIX_PROTOCOL_WIRE_CORE_REQUESTS_H
#define BRIX_PROTOCOL_WIRE_CORE_REQUESTS_H

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

/* ---- Initial handshake section — client/server connection negotiation ----
 *
 * WHAT: Two handshake structures for establishing the initial TCP connection.
 *   - ClientInitHandShake (20B): sent by client on connect
 *   - ServerInitHandShake (12B): legacy server response format
 */

/*---- ClientInitHandShake — client connection negotiation header ----
 *
 * WHAT: 20-byte structure sent by client when establishing new TCP connection.
 *   - Contains version constants for server validation
 *   - Server validates to ensure protocol compatibility before auth
 */

/*---- ClientInitHandShake validation invariant ----
 *
 * WHY: Server must validate to reject incompatible clients:
 *   - first==0, fourth==htonl(BRIX_XRD_HANDSHAKE_FOURTH), fifth==htonl(BRIX_XRD_PROTOCOL_ID)
 *   - Constants identify client as valid XRootD protocol (PQ 2012)
 *   - See src/core/types/tunables.h for BRIX_XRD_* constant definitions
 */

/*---- ClientInitHandShake struct ----
 *
 * HOW: Fixed layout, all big-endian:
 *   - 4B first + 4B second + 4B third + 4B fourth + 4B fifth = 20 bytes
 */

/* ------------------------------------------------------------------ */
/* Initial handshake                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_int32  first;    /* 0x00000000 */
    kXR_int32  second;   /* 0x00000000 */
    kXR_int32  third;    /* 0x00000000 */
    kXR_int32  fourth;   /* htonl(4)   */
    kXR_int32  fifth;    /* htonl(BRIX_XRD_PROTOCOL_ID) — XRootD protocol identifier (2012) */
} ClientInitHandShake;   /* 20 bytes */

/* ---- ServerInitHandShake — legacy server handshake response (deprecated) ----
 *
 * WHAT: Legacy 12-byte server handshake response format.
 *   - NOT standard ServerResponseHdr framing — has own layout
 *   - Deprecated for XRootD v5 clients
 *   - v5 clients use standard ServerResponseHdr + kXR_protocol
 */

/*---- ServerInitHandShake deprecation warning ----
 *
 * WHY: Using legacy format with v5 clients causes parsing errors:
 *   - status=0x0008 / dlen=1312 causes client to stall
 *   - Module responds with standard ServerResponseHdr:
 *     - streamid={0,0}, status=kXR_ok, dlen=8 + 8 bytes
 */

/*---- ServerInitHandShake struct ----
 *
 * HOW: Fixed layout, 12 bytes total, all big-endian:
 *   - 4B msglen: indicates 8 more bytes follow
 *   - 4B protover: server protocol version
 *   - 4B msgval: server type (0=LB, 1=DataServer)
 */

/*
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

/* ---- ClientRequestHdr — all client requests share this header ----
 *
 * WHAT: Universal 24-byte request header for every XRootD opcode.
 *   - Payload follows inline after header (no separate buffer)
 *
 * WHY: Standardizes all request parsing:
 *   - Single struct reference for "what's the request format?"
 *   - Plus opcodes.h for specific opcode ID
 *
 * HOW: Fixed layout, always big-endian:
 *   - 2B streamid + 2B reqid (kXR_*) + 16B body + 4B dlen
 *   - Use brix_dispatch_opcode() to route by requestid
 */

typedef struct {
    kXR_char   streamid[2];  /* client-chosen, echoed in response */
    kXR_unt16  requestid;    /* one of the kXR_* constants        */
    kXR_char   body[16];     /* request-specific parameters       */
    kXR_int32  dlen;         /* payload length following header   */
} ClientRequestHdr;          /* 24 bytes; payload follows inline  */

/* ---- ServerResponseHdr — all server responses share this header ----
 *
 * WHAT: Universal 8-byte response header.
 *   - Status field determines body type:
 *     - kXR_ok → result body
 *     - kXR_error → errnum[4] + errmsg
 *     - kXR_status → CRC32c body
 *
 * WHY: Standardizes all response parsing:
 *   - Single struct + opcodes.h for status codes
 *   - Plus wire.h for body definitions
 *
 * HOW: Fixed layout, always big-endian:
 *   - 2B streamid (echoed) + 2B status + 4B dlen
 *   - Use brix_build_resp_hdr() / brix_queue_response()
 */

typedef struct {
    kXR_char   streamid[2];  /* echoed from request */
    kXR_unt16  status;       /* kXR_ok / kXR_error / ... */
    kXR_int32  dlen;         /* response body length */
} ServerResponseHdr;         /* 8 bytes; body follows inline */

/* ---- kXR_status (BRIX_XRD_STATUS=4007) extended response — pgwrite/pgread integrity ----
 *
 * WHAT: Extended status frame for kXR_pgwrite and kXR_pgread only.
 *   - Provides CRC32c integrity verification for all page transfers
 *   - Status code defined in src/core/types/tunables.h:BRIX_XRD_STATUS
 *
 * WHY: Ensures data integrity in paged operations:
 *   - CRC covers streamID to end of body
 *   - Any bit corruption detected
 *
 * HOW: Full wire layout for pgwrite success (32 bytes):
 *   - [ServerResponseHdr 8B] status=kXR_status, dlen=24
 *   - [ServerResponseBody_Status 16B] crc32c, streamID, requestid,
 *     resptype, reserved, dlen=0
 *   - [ServerResponseBody_pgWrite 8B] offset (last written)
 *
 * INVARIANT: kXR_pgwrite MUST use this framing + per-page CRC32c.
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
    kXR_int64  offset;      /* file offset of read data */
} ServerResponseBody_pgRead;   /* 8 bytes */

typedef struct {
    kXR_int64  offset;      /* file offset of written data */
} ServerResponseBody_pgWrite;  /* 8 bytes */

/* ---- kXR_pgwrite CSE (checksum-error) retransmit trailer ----
 *
 * Appended to ServerResponseBody_pgWrite when one or more pages failed CRC32c
 * verification. The server replies with a SUCCESS kXR_status frame (not an
 * error) whose bdy.dlen = sizeof(pgWrCSE) + n*8, then the client resends each
 * listed page with reqflags |= kXR_pgRetry. Followed inline by a big-endian
 * vector `kXR_int64 bof[n]` of the corrupt pages' file offsets.
 *
 * Wire layout for a CSE reply (n bad pages) — stock srsComplete convention:
 * hdr.dlen counts ONLY the fixed status body (24); the CSE trailer follows as
 * separate `data` of length bdy.dlen, exactly like pgread page data.
 *   [ServerResponseHdr 8B]       status=kXR_status, dlen = 24
 *   [ServerResponseBody_Status]  dlen = 8 + n*8 (size of the CSE trailer below)
 *   [ServerResponseBody_pgWrite] offset
 *   ---- the following bytes are NOT counted in hdr.dlen ----
 *   [ServerResponseBody_pgWrCSE 8B] cseCRC, dlFirst, dlLast
 *   [kXR_int64 bof[n]]           corrupt-page file offsets (big-endian)
 *
 * body crc32c covers only the 20-byte fixed head (streamID..pgw.offset);
 * cseCRC = CRC32c of every byte AFTER cseCRC (dlFirst..end of bof[]). */
typedef struct {
    kXR_unt32  cseCRC;      /* CRC32c of all following bytes (dlFirst..bof end) */
    kXR_int16  dlFirst;     /* fragment length of the first bad page  */
    kXR_int16  dlLast;      /* fragment length of the last  bad page  */
} ServerResponseBody_pgWrCSE;  /* 8 bytes; kXR_int64 bof[n] follows */

/* Full kXR_status response for pgread (header only; data follows in chain) */
typedef struct {
    ServerResponseHdr         hdr; /* status=kXR_status, dlen=24+data */
    ServerResponseBody_Status bdy;
    ServerResponseBody_pgRead pgr;
} ServerStatusResponse_pgRead; /* 32 bytes */

/* Full kXR_status response for pgwrite (sent as one contiguous buffer) */
typedef struct {
    ServerResponseHdr          hdr; /* status=kXR_status, dlen=24 */
    ServerResponseBody_Status  bdy;
    ServerResponseBody_pgWrite pgw;
} ServerStatusResponse_pgWrite; /* 32 bytes */

/* ---- Error body and redirect body — server error/redirect response bodies ----
 *
 * WHAT: Two response body structures used when the server returns non-success status.
 *       ServerErrorBody for kXR_error responses (error code + human-readable message);
 *       ServerRedirectBody for kXR_redirect responses (target host + port). */

/*---- Error body — kXR_error response payload ----
 *
 * WHAT: 4-byte error code from opcodes.h followed by null-terminated error message.
 *       Actual message length = dlen - 4 bytes (dlen includes the errnum field). */

/*---- Error body struct ----
 *
 * HOW: Layout is fixed: 4B errnum + variable errmsg[1] (null-terminated) = dlen bytes total. */

typedef struct {
    kXR_int32  errnum;    /* XRootD error code; one of kXR_* in opcodes.h */
    char       errmsg[1]; /* null-terminated human-readable message;
                            * actual length = dlen - 4 bytes */
} ServerErrorBody;

/*---- Redirect body — server redirect response payload ----
 *
 * WHAT: 4-byte TCP port (big-endian) followed by null-terminated host hostname or IP address.
 *       Used when the server redirects the client to a different endpoint for file access. */

/*---- Redirect body struct ----
 *
 * HOW: Layout is fixed: 4B port + variable host[1] (null-terminated) = dlen bytes total. */

typedef struct {
    kXR_int32  port;      /* TCP port of the redirect target, big-endian */
    char       host[1];   /* null-terminated target hostname or IP;
                            * actual length = dlen - 4 bytes */
} ServerRedirectBody;

/* ---- kXR_protocol (BRIX_XRD_OPCODE_PROTOCOL=3006) — protocol version negotiation section ----
 *
 * WHAT: Request/response structures for establishing the protocol version between client and server.
 *       ClientProtocolRequest sent by client to announce its capabilities; ServerProtocolBody returned by server. */

/*---- kXR_protocol request — client capability announcement ----
 *
 * WHAT: 24-byte structure sent by client to announce:
 *   - Protocol version
 *   - Flags (TLS support)
 *   - Expected response type
 */

/*---- kXR_protocol request struct ----
 *
 * HOW: Fixed layout:
 *   - 2B streamid + 2B reqid(kXR_protocol)
 *   - 4B clientpv + 1B flags + 1B expect + 10B reserved + 4B dlen(0)
 */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_protocol */
    kXR_int32  clientpv;     /* client protocol version */
    kXR_char   flags;        /* kXR_secreqs, kXR_ableTLS, etc. */
    kXR_char   expect;       /* kXR_ExpLogin = 0x03            */
    kXR_char   reserved[10];
    kXR_int32  dlen;         /* 0 */
} ClientProtocolRequest;     /* 24 bytes */

/*---- Server protocol response — server capability announcement ----
 *
 * WHAT: 8-byte structure returned by server indicating:
 *   - Protocol version
 *   - Type flags (kXR_isServer, etc.)
 */

typedef struct {
    kXR_int32  pval;         /* server protocol version */
    kXR_int32  flags;        /* kXR_isServer | ... */
} ServerProtocolBody;        /* 8 bytes, dlen=8 */

/* ---- kXR_login (BRIX_XRD_OPCODE_LOGIN=3007) — session login section ----
 *
 * WHAT: Request/response structures for establishing login session:
 *   - ClientLoginRequest: sends username and capabilities
 *   - ServerLoginBody: returns opaque session ID for context
 */

/*---- kXR_login request — client session initiation ----
 *
 * WHAT: 24-byte structure sent by client to initiate session:
 *   - Username
 *   - Process ID (informational)
 *   - Capability flags
 */

/*---- kXR_login request struct ----
 *
 * HOW: Fixed layout:
 *   - 2B streamid + 2B reqid(kXR_login)
 *   - 4B pid + 8B username(NUL-padded)
 *   - 1B ability2 + 1B ability + 1B capver + 1B reserved + 4B dlen
 */

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

/* ---- kXR_auth (BRIX_XRD_OPCODE_AUTH=3000) — authentication credential exchange ----
 *
 * WHAT: Sent in response to kXR_authmore when server requests credential type.
 *   - For "ztn" (WLCG JWT): payload is:
 *     - credtype[4] = "ztn\0"
 *     - Raw JWT token bytes (dlen - 4 bytes)
 *
 * HOW: Fixed layout:
 *   - 2B streamid + 2B reqid(kXR_auth) + 12B reserved
 *   - 4B credtype + 4B dlen
 *   - Payload (dlen bytes) immediately follows
 */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_auth */
    kXR_char   reserved[12];
    kXR_char   credtype[4];  /* e.g. "ztn\0", "gsi\0", "unix\0" */
    kXR_int32  dlen;         /* byte length of credential payload */
} ClientAuthRequest;         /* 24 bytes */

/*---- kXR_login response — session ID assignment ----
 *
 * WHAT: Server returns 16-byte opaque session ID (sessid):
 *   - Identifies login context across all subsequent requests
 */

typedef struct {
    kXR_char   sessid[BRIX_SESSION_ID_LEN];  /* 16 opaque bytes assigned by
                              * the server; echoed by kXR_bind and kXR_endsess.
                              * The login ctx is connection-scoped — multiple
                              * requests on one TCP connection share it. */
    /* optional: security info follows if dlen > 16 */
} ServerLoginBody;

/* ---- kXR_open (BRIX_XRD_OPCODE_OPEN=3010) — file open section ----
 *
 * WHAT: Request/response structures for opening files:
 *   - ClientOpenRequest: specifies mode, flags, path
 *   - ServerOpenBody: returns opaque file handle for I/O ops
 */

/*---- kXR_open request — client file access initiation ----
 *
 * WHAT: 24-byte structure sent by client to open file:
 *   - POSIX permission mode (0644 = 0x01B4)
 *   - Options flags
 *   - Path payload
 */

/*---- kXR_open request struct ----
 *
 * HOW: Fixed layout:
 *   - 2B streamid + 2B reqid(kXR_open)
 *   - 2B mode(POSIX perms) + 2B options + 2B optiont
 *   - 6B reserved + 4B fhtemplt + 4B dlen(path)
 */

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

/*---- kXR_open response — file handle assignment ----
 *
 * WHAT: Server returns:
 *   - Opaque file handle (fhandle[4]) for subsequent ops
 *   - Compression info (cpsize/cptype)
 *   - Optional stat string
 */

typedef struct {
    kXR_char   fhandle[4];   /* opaque file handle for subsequent ops */
    kXR_int32  cpsize;       /* compression page size (0 = uncompressed) */
    kXR_char   cptype[4];    /* compression type (e.g. "adl\0") */
    /* if kXR_retstat set: ASCII stat string follows */
} ServerOpenBody;            /* 12 bytes minimum */

/* ---- kXR_prepare (BRIX_XRD_OPCODE_PREPARE=3021) — staging/prepare section ----
 *
 * WHAT: Request structure for file preparation operations:
 *   - Staging, cancellation, notification
 *   - ClientPrepareRequest: options, priority, paths
 */

/*---- kXR_prepare request — client staging initiation ----
 *
 * WHAT: 24-byte structure sent by client to initiate staging:
 *   - Options (kXR_stage/kXR_cancel/kXR_notify)
 *   - Priority level
 *   - Path list or cancel token
 */

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
/* kXR_read (BRIX_XRD_OPCODE_READ=3013)                                         */
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
/* kXR_stat (BRIX_XRD_OPCODE_STAT=3017)                                         */
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
/* kXR_close (BRIX_XRD_OPCODE_CLOSE=3003)                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_close */
    kXR_char   fhandle[4];   /* file handle to close */
    kXR_char   reserved[12];
    kXR_int32  dlen;         /* 0 */
} ClientCloseRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_ping (BRIX_XRD_OPCODE_PING=3011)                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_ping */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* 0 */
} ClientPingRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_query (BRIX_XRD_OPCODE_QUERY=3001)                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_query */
    kXR_unt16  infotype;     /* XQueryType — kXR_Qcksum, kXR_QSpace, etc. */
    kXR_char   reserved1[2];
    kXR_char   fhandle[4];   /* open file handle (for per-file queries) */
    kXR_char   reserved2[8];
    kXR_int32  dlen;         /* payload length */
} ClientQueryRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_dirlist (BRIX_XRD_OPCODE_DIRLIST=3004)                                   */
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

/* Restore the caller's struct alignment. This fragment is self-balanced:
 * it owns both the pack(push,1) at the top and this matching pop, so it no
 * longer leaks a modified #pragma pack state into the sibling fragments that
 * wire.h includes after it (clang -Wpragma-pack flags such cross-file leaks). */
#pragma pack(pop)

#endif /* BRIX_PROTOCOL_WIRE_CORE_REQUESTS_H */
