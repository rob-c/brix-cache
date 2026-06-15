#ifndef NGX_XROOTD_FRM_FORMAT_H
#define NGX_XROOTD_FRM_FORMAT_H

/*
 * frm_format.h — on-disk layout for the FRM durable stage-request queue.
 *
 * WHAT: Pure layout (no code): the magic/version constants, the fixed-size file
 *   header (frm_file_hdr_t) and request record (frm_record_t), the status /
 *   option / checksum-type enums, and compile-time size asserts. Modeled on the
 *   official XRootD XrdFrcReqFile/XrdFrcRequest layout (free-list header + fixed
 *   records) but adds per-record CRC32c + a self-offset check so a torn write is
 *   *detectable* on reconciliation.
 *
 * WHY: The queue file is the crash-durable source of truth (the SHM index is a
 *   rebuildable cache). A FIXED record size makes the file a flat array — pwrite
 *   to `off`, no parsing, O(1) random access by byte offset, and a free-list of
 *   recycled slots. All integers are stored little-endian (the only supported
 *   build target is x86-64); foreign/newer files are rejected via magic+version.
 *
 * INVARIANT: sizeof(frm_file_hdr_t) == sizeof(frm_record_t) == FRM_REC_SIZE, so
 *   record N lives at byte offset (N+1) * FRM_REC_SIZE and the header occupies
 *   slot 0. Enforced by the typedef-array static asserts at the bottom.
 */

#include <stdint.h>

#define FRM_MAGIC          0x46524d31u   /* "FRM1" */
#define FRM_VERSION        1u

/* Field widths (reqid/lfn match XrdFrcRequest::ID[40]/LFN[3072]). */
#define FRM_REQID_LEN      40
#define FRM_LFN_LEN        3072
#define FRM_USER_LEN       256
#define FRM_DN_LEN         256
#define FRM_NOTIFY_LEN     512
#define FRM_CSVAL_LEN      64
#define FRM_SELECTOR_LEN   32

/* Fixed on-disk slot size: header and every record are exactly this many bytes
 * (≈1.125 pages). Chosen > sizeof(frm_record_t); the reserved[] tail + the
 * static asserts below pin it. */
#define FRM_REC_SIZE       4608u

typedef enum {
    FRM_ST_FREE      = 0,   /* slot is on the free list                       */
    FRM_ST_QUEUED    = 1,   /* admitted, awaiting a transfer worker           */
    FRM_ST_STAGING   = 2,   /* a copycmd is running                           */
    FRM_ST_ONLINE    = 3,   /* file is now resident (terminal success)        */
    FRM_ST_FAILED    = 4,   /* recall failed (terminal, see fail_code)        */
    FRM_ST_CANCELLED = 5     /* cancelled by client/operator (terminal)        */
} frm_status_t;

/* Option bits — low bits mirror XrdFrcRequest::Options, high bits are ours. */
#define FRM_OPT_MSG_FAIL   0x00000001u   /* notify on failure                 */
#define FRM_OPT_MSG_SUCC   0x00000002u   /* notify on success                 */
#define FRM_OPT_MAKE_RW    0x00000004u   /* stage for write                   */
#define FRM_OPT_MIGRATE    0x00000010u
#define FRM_OPT_PURGE      0x00000020u   /* eligible for purge (kXR_evict)    */
#define FRM_OPT_REGISTER   0x00000040u
#define FRM_OPT_COLOC      0x00010000u   /* kXR_coloc hint                    */
#define FRM_OPT_STAGE      0x00020000u   /* kXR_stage                         */

typedef enum {
    FRM_CS_NONE = 0, FRM_CS_SHA1 = 1, FRM_CS_SHA2 = 2, FRM_CS_SHA3 = 3,
    FRM_CS_ADLER32 = 4, FRM_CS_MD5 = 5, FRM_CS_CRC32 = 6
} frm_cstype_t;

/*
 * File header — occupies the first FRM_REC_SIZE bytes (slot 0). The header write
 * is the COMMIT POINT: a record body is pwritten+fdatasync'd first, then the
 * header (first/last/free/seq) is pwritten+fsync'd to publish it. A crash
 * between the two leaves an orphan body that reconciliation's free-list walk
 * never reaches — harmless.
 */
typedef struct {
    /* 4-byte scalars (16 bytes) */
    uint32_t  magic;        /* FRM_MAGIC — reject foreign files               */
    uint32_t  version;      /* FRM_VERSION — refuse newer formats            */
    uint32_t  rec_size;     /* FRM_REC_SIZE this file was written with        */
    uint32_t  hdr_crc32c;   /* CRC32c of the header with this field == 0      */
    /* 8-byte scalars (48 bytes) */
    int64_t   first;        /* byte offset of head active record (0 = empty)  */
    int64_t   last;         /* byte offset of tail active record (0 = empty)  */
    int64_t   free;         /* byte offset of free-list head (0 = grow @EOF)  */
    uint64_t  seq;          /* monotonic reqid sequence (survives restart)    */
    uint64_t  generation;   /* bumped on each compaction (.new swap)          */
    int64_t   created_tod;  /* unix seconds the file was created              */
    uint8_t   reserved[FRM_REC_SIZE - 64];
} frm_file_hdr_t;

/*
 * Request record — a fixed slot. Scalars are grouped largest-first so the
 * struct packs with zero internal padding; reserved[] pads to FRM_REC_SIZE.
 */
typedef struct {
    /* linkage + integrity (8-byte, 24 bytes) */
    int64_t   self;         /* byte offset of THIS record (torn-write check)  */
    int64_t   next;         /* next in active OR free chain (0 = end)         */
    uint64_t  rec_crc32c;   /* CRC32c of whole record with this field == 0    */
    /* timestamps (8-byte, 24 bytes) */
    int64_t   tod_added;    /* unix seconds admitted                          */
    int64_t   tod_status;   /* unix seconds of last status change             */
    int64_t   tod_expire;   /* hard expiry; 0 = never (reaper)                */
    /* 4-byte scalars (12 bytes) */
    uint32_t  options;      /* FRM_OPT_* bitmask                              */
    int32_t   fail_code;    /* errno-style reason when FAILED                 */
    uint32_t  attempts;     /* stage attempts so far                          */
    /* 2-byte scalars (4 bytes) */
    int16_t   opaque_off;   /* offset of '?' in lfn, -1 if none               */
    int16_t   lfn_url_off;  /* offset past a scheme://host/ prefix, -1 if none*/
    /* 1-byte scalars (4 bytes) */
    uint8_t   cs_type;      /* frm_cstype_t                                   */
    uint8_t   status;       /* frm_status_t                                   */
    int8_t    priority;     /* -1..2 (XRootD Prty range)                      */
    uint8_t   queue;        /* stgQ/migQ/getQ/putQ selector                   */
    /* char arrays (4232 bytes) */
    char      reqid[FRM_REQID_LEN];        /* "<seq>.<pid>@<host>" NUL-term   */
    char      lfn[FRM_LFN_LEN];            /* logical (client-facing) path    */
    char      requester_dn[FRM_DN_LEN];    /* GSI DN or token "sub"           */
    char      user[FRM_USER_LEN];
    char      notify[FRM_NOTIFY_LEN];      /* notify target, "" = none        */
    char      selector[FRM_SELECTOR_LEN];
    char      cs_value[FRM_CSVAL_LEN];
    /* pad to FRM_REC_SIZE */
    uint8_t   reserved[FRM_REC_SIZE - 4300];
} frm_record_t;

/*
 * Compile-time size pins (portable: a negative array size is a hard error if
 * the layout ever drifts off FRM_REC_SIZE — adjust the reserved[] tails above).
 */
typedef char frm_hdr_size_check[(sizeof(frm_file_hdr_t) == FRM_REC_SIZE) ? 1 : -1];
typedef char frm_rec_size_check[(sizeof(frm_record_t)   == FRM_REC_SIZE) ? 1 : -1];

#endif /* NGX_XROOTD_FRM_FORMAT_H */
