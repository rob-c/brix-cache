/* ROOT protocol identifiers, frame geometry, and wire values.
 *
 * Requires: include through core/types/tunables.h; sibling constants
 * and the caller-provided nginx/protocol/metrics types remain available
 * when dependent expressions and completion macros are expanded.
 */
#pragma once

/*
 * XRootD page size for paged I/O (kXR_pgread/kXR_pgwrite).
 * Standard XRootD page size is 4096 bytes. Used for CRC32c framed I/O.
 * Per AGENTS.md INVARIANT #1: pgread/pgwrite → kXR_status(4007) + per-page CRC32c
 */
#define BRIX_ROOT_PAGE_SIZE                    4096

/*
 * XRootD page checksum size (CRC32c).
 * Each page in paged I/O carries a 4-byte CRC32c checksum.
 */
#define BRIX_ROOT_PAGE_CKSIZE                  4

/*
 * XRootD page record size (data + checksum).
 * Total size of one paged I/O record: 4096 bytes data + 4 bytes CRC32c = 4100 bytes.
 */
#define BRIX_ROOT_PAGE_RECORD_SIZE             4100

/*
 * Default XRootD root protocol port number.
 * IANA-assigned port for XRootD file access protocol.
 * Used when port is not specified in root:// URLs.
 */
#define BRIX_ROOT_DEFAULT_PORT                 1094

/*
 * XRootD protocol version for GSI signed DH requirement.
 * Clients advertising version >= 10400 support signed DH handshake.
 */
#define BRIX_ROOT_GSI_SIGNED_DH_MIN_VERSION    10400

/*
 * XRootD protocol handshake constant (ROOTD_PQ).
 * Value 2012 (0x7DC) identifies valid XRootD protocol client in handshake.
 * Used in ClientInitHandShake.fifth = htonl(2012) for protocol validation.
 * Reference: src/protocols/root/protocol/opcodes.h:15
 */
#define BRIX_XRD_PROTOCOL_ID             2012

/*
 * XRootD handshake fourth field constant.
 * ClientInitHandShake.fourth = htonl(4) validates protocol compatibility.
 * Part of the 20-byte initial handshake structure.
 */
#define BRIX_XRD_HANDSHAKE_FOURTH        4

/* kXR_ok (0) — request succeeded, body carries result data */
#define BRIX_XRD_STATUS_OK               0

/* kXR_oksofar (4000) — partial result, more response frames follow */
#define BRIX_XRD_STATUS_OKSOFAR          4000

/* kXR_attn (4001) — unsolicited server push notification */
#define BRIX_XRD_STATUS_ATTN             4001

/* kXR_authmore (4002) — authentication needs another round-trip */
#define BRIX_XRD_STATUS_AUTHMORE         4002

/* kXR_error (4003) — request failed, body = errnum[4] + errmsg */
#define BRIX_XRD_STATUS_ERROR            4003

/* kXR_redirect (4004) — client should retry at different server */
#define BRIX_XRD_STATUS_REDIRECT         4004

/* kXR_wait (4005) — try again after N seconds (body carries wait time) */
#define BRIX_XRD_STATUS_WAIT             4005

/* kXR_waitresp (4006) — async result coming in future kXR_attn frame */
#define BRIX_XRD_STATUS_WAITRESP         4006

/* kXR_status (4007) — extended response with CRC32c (pgread/pgwrite) */
#define BRIX_XRD_STATUS                  4007

/* kXR_auth (3000) — authentication credential exchange */
#define BRIX_XRD_OPCODE_AUTH             3000

/* kXR_query (3001) — server/file information query */
#define BRIX_XRD_OPCODE_QUERY            3001

/* kXR_chmod (3002) — change file permission bits */
#define BRIX_XRD_OPCODE_CHMOD            3002

/* kXR_close (3003) — close an open file handle */
#define BRIX_XRD_OPCODE_CLOSE            3003

/* kXR_dirlist (3004) — list directory entries */
#define BRIX_XRD_OPCODE_DIRLIST          3004

/* kXR_protocol (3006) — protocol version negotiation */
#define BRIX_XRD_OPCODE_PROTOCOL         3006

/* kXR_login (3007) — session login with username */
#define BRIX_XRD_OPCODE_LOGIN            3007

/* kXR_open (3010) — open a file for I/O */
#define BRIX_XRD_OPCODE_OPEN             3010

/* kXR_ping (3011) — liveness check (no payload) */
#define BRIX_XRD_OPCODE_PING             3011

/* kXR_read (3013) — read bytes from open file handle */
#define BRIX_XRD_OPCODE_READ             3013

/* kXR_stat (3017) — stat a path or open handle */
#define BRIX_XRD_OPCODE_STAT             3017

/* kXR_prepare (3021) — stage files from tape */
#define BRIX_XRD_OPCODE_PREPARE          3021

/* kXR_pgwrite (3026) — paged write with per-page CRC32c */
#define BRIX_XRD_OPCODE_PGWRITE          3026

/* kXR_pgread (3030) — paged read with per-page CRC32c */
#define BRIX_XRD_OPCODE_PGREAD           3030

/* kXR_LBalServer (0) — load-balancer/redirector (does not serve files) */
#define BRIX_XRD_SERVER_LB               0

/* kXR_DataServer (1) — data server (serves files) */
#define BRIX_XRD_SERVER_DATA             1

/* kXR_FinalResult (0) — this is the final response */
#define BRIX_XRD_RESP_FINAL              0

/* kXR_PartialResult (1) — more response data follows */
#define BRIX_XRD_RESP_PARTIAL            1

/* kXR_ExpLogin (0x03) — client expects login response */
#define BRIX_XRD_EXPECT_LOGIN            0x03

/*
 * Minimum ROOT protocol version supporting signed DH handshake.
 * Clients advertising version >= this value must use signed DH variant.
 * Matches XrdSecgsiVersDHsigned in the reference implementation.
 */
#define BRIX_ROOT_MIN_SIGNED_DH_VERSION    10400

/*
 * Minimum ROOT protocol version supporting signed DH handshake.
 * Clients advertising version >= this value must use signed DH variant.
 * Matches XrdSecgsiVersDHsigned in the reference implementation.
 */
#define BRIX_ROOT_MIN_SIGNED_DH_VERSION    10400

/*
 * XRootD protocol version for unsigned DH (default, universally compatible).
 * Used when client does not advertise version or uses legacy protocol.
 * All clients support this baseline version.
 */
#define BRIX_ROOT_PROTO_UNSIGNED               10000

/*
 * XRootD protocol version threshold for RSA-signed DH.
 * Clients advertising >= 10400 support signed DH for enhanced security.
 * Used in login handshake to negotiate DH variant (auto mode).
 */
#define BRIX_ROOT_PROTO_DHSIGNED_THRESHOLD   10400

/*
 * XRootD protocol version for signed DH with explicit requirement.
 * Used when server requires signed DH and rejects legacy clients.
 * Provides man-in-the-middle protection for DH key exchange.
 */
#define BRIX_ROOT_PROTO_DHSIGNED_REQUIRED    10600

/*
 * XRootD protocol version for password auth capability.
 * Clients advertising >= 10100 support XrdSecpwd authentication.
 * Opt-in feature for environments requiring password-based auth.
 */
#define BRIX_ROOT_PROTO_PWD_AUTH             10100

/*
 * XRootD async action code: attention frame (server push).
 * Used for kXR_attn frames carrying async notifications.
 * See the protocol spec for the async frame format.
 */
#define BRIX_ROOT_ATTN_FRAME                 4001

/*
 * XRootD async action code: unsolicited message notification.
 * Server-initiated text messages to clients (status, warnings).
 * Deprecated in favor of asynresp for structured notifications.
 */
#define BRIX_ROOT_ASYNCMS                    5002

/*
 * XRootD async action code: deferred response delivery.
 * Used after kXR_waitresp to deliver delayed operation results.
 * Primary mechanism for long-running operation completion.
 */
#define BRIX_ROOT_ASYNCRESP                  5008

/*
 * XRootD async action code: abort notification (deprecated).
 * Legacy code 5000 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNCAB                    5000

/*
 * XRootD async action code: disconnect notification (deprecated).
 * Legacy code 5001 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNCDI                    5001

/*
 * XRootD async action code: read notification (deprecated).
 * Legacy code 5003 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_RD                   5003

/*
 * XRootD async action code: write notification (deprecated).
 * Legacy code 5004 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_WT                   5004

/*
 * XRootD async action code: availability notification (deprecated).
 * Legacy code 5005 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_AV                   5005

/*
 * XRootD async action code: unavailability notification (deprecated).
 * Legacy code 5006 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_UNAV                 5006

/*
 * XRootD async action code: go notification (deprecated).
 * Legacy code 5007 — no longer supported, returns error.
 * Kept for reference and backward-compatibility logging.
 */
#define BRIX_ROOT_ASYNC_GO                   5007

/*
 * XRootD first request opcode base (3000).
 * All standard opcodes are offset from this base.
 * Used for opcode normalization and dispatch table indexing.
 */
#define BRIX_ROOT_OPCODE_BASE                3000

/*
 * XRootD query opcode (kXR_query = 2012).
 * Used for CMS queries, checksums, and metadata operations.
 * Legacy opcode predates the 3000+ range.
 */
#define BRIX_ROOT_QUERY_OPCODE               2012

/*
 * Default XRootD port.
 * IANA-assigned port for XRootD services.
 */
#define BRIX_XRD_DEFAULT_PORT  1094

/*
 * TAP protocol constants.
 * Used for XRootD TAP streaming protocol.
 */
#define BRIX_TAP_WRITEV_MAXSEGS       1024  /* Maximum writev segments */
#define BRIX_TAP_WRITEV_SEGSIZE       16    /* Segment size multiplier */
#define BRIX_TAP_WRITEV_MAX_PAYLOAD   (BRIX_TAP_WRITEV_MAXSEGS * BRIX_TAP_WRITEV_SEGSIZE)
