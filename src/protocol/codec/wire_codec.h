/*
 * wire_codec.h — shared per-opcode XRootD wire-body codec (xrdwire).
 *
 * WHAT: Decoded structs + paired pack/unpack functions for the fixed-layout
 *       request bodies (and fixed response bodies) of each XRootD opcode. The
 *       client uses the *_pack (request) / *_unpack (response) halves; the server
 *       uses the mirror halves — one definition of every wire offset, shared via
 *       libxrdproto so the two cannot drift.
 * WHY:  The 16-byte ClientRequestHdr body and the fixed response bodies were
 *       hand-marshalled twice (client builds, server parses; and vice-versa).
 *       That implicit "offsets must match" contract is the largest remaining
 *       cross-component duplication and the classic wire-bug class. This codec
 *       generalises the proven pgio / vendor_ext / fattr_codec pattern to every
 *       opcode and makes the contract round-trip-testable with no process running.
 * HOW:  Pure C, ngx-free, big-endian fixed-offset copies over a caller buffer —
 *       the codec owns ONLY the fixed-offset fields. The shared framing header
 *       (streamid/requestid/dlen) stays in frame_hdr.h; the variable tail (path,
 *       payload, dirlist/stat strings) is appended/consumed by the caller. The
 *       codec never touches a socket, nginx, or the client's poll machinery.
 *
 * See docs/superpowers/specs/2026-06-27-xrdwire-codec-design.md.
 */
#ifndef XROOTD_WIRE_CODEC_H
#define XROOTD_WIRE_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>   /* ssize_t */

/* Result codes (consumers map onto kXR_* / XRDC_* at the edge). */
#define XRDW_OK       0
#define XRDW_EINVAL  (-1)   /* NULL argument / bad field */
#define XRDW_ETRUNC  (-2)   /* input shorter than the fixed region */

/* The fixed request-body region of ClientRequestHdr (between requestid and dlen). */
#define XRDW_BODY_LEN     16
#define XRDW_FHANDLE_LEN  4

/* ---- big-endian (network order) field helpers ------------------------- */

static inline void xrdw_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) v;
}

static inline void xrdw_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static inline uint16_t xrdw_get_u16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static inline uint32_t xrdw_get_u32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)  | (uint32_t) p[3];
}

static inline void xrdw_put_u64(uint8_t *p, uint64_t v)
{
    xrdw_put_u32(p, (uint32_t) (v >> 32));
    xrdw_put_u32(p + 4, (uint32_t) v);
}

static inline uint64_t xrdw_get_u64(const uint8_t *p)
{
    return ((uint64_t) xrdw_get_u32(p) << 32) | xrdw_get_u32(p + 4);
}

/* ====================================================================== *
 * Metadata family (wire_codec_meta.c): stat, statx, dirlist, query,       *
 * locate. These bodies carry only fixed fields; the path/payload tail and  *
 * the ASCII stat/dirlist response strings are handled by the caller.       *
 * ====================================================================== */

/* kXR_stat (3017) — body: options(1) reserved(7) wants(4) fhandle(4). */
typedef struct {
    uint8_t  options;                      /* kXR_vfs or 0 */
    uint32_t wants;                        /* feature-request mask (usually 0) */
    uint8_t  fhandle[XRDW_FHANDLE_LEN];    /* 0 if path-based, else open handle */
} xrdw_stat_req_t;

int xrdw_stat_req_pack(const xrdw_stat_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_stat_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_stat_req_t *r);

/* kXR_statx (3022) — body: options(1) reserved(11) fhandle(4). */
typedef struct {
    uint8_t  options;
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
} xrdw_statx_req_t;

int xrdw_statx_req_pack(const xrdw_statx_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_statx_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_statx_req_t *r);

/* kXR_dirlist (3004) — body: reserved(15) options(1). */
typedef struct {
    uint8_t  options;                      /* kXR_online | kXR_dstat | kXR_dcksm */
} xrdw_dirlist_req_t;

int xrdw_dirlist_req_pack(const xrdw_dirlist_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_dirlist_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_dirlist_req_t *r);

/* kXR_query (3001) — body: infotype(2) reserved(2) fhandle(4) reserved(8). */
typedef struct {
    uint16_t infotype;                     /* XQueryType (kXR_Qcksum, kXR_QSpace…) */
    uint8_t  fhandle[XRDW_FHANDLE_LEN];    /* open handle for per-file queries */
} xrdw_query_req_t;

int xrdw_query_req_pack(const xrdw_query_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_query_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_query_req_t *r);

/* kXR_locate (3027) — body: options(2) reserved(14). */
typedef struct {
    uint16_t options;                      /* kXR_refresh, kXR_compress, … */
} xrdw_locate_req_t;

int xrdw_locate_req_pack(const xrdw_locate_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_locate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_locate_req_t *r);

/* kXR_fattr (3020) — body: fhandle(4) subcode(1) numattr(1) options(1) reserved(9). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];    /* open handle (0 if path-based) */
    uint8_t  subcode;                      /* kXR_fattrDel/Get/List/Set */
    uint8_t  numattr;                      /* attribute count (0 for list) */
    uint8_t  options;                      /* kXR_fa_isNew | kXR_fa_aData */
} xrdw_fattr_req_t;

int xrdw_fattr_req_pack(const xrdw_fattr_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_fattr_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_fattr_req_t *r);

/* ====================================================================== *
 * File family (wire_codec_file.c): open, close, read, pgread, write,      *
 * pgwrite, sync, truncate, writev, clone, chkpoint. These carry the hot-  *
 * path multi-byte fields (i64 offsets, i32 lengths) where the byte-order   *
 * contract matters most.                                                   *
 * ====================================================================== */

/* kXR_open (3010) — body: mode(2) options(2) optiont(2) reserved(6) fhtemplt(4). */
typedef struct {
    uint16_t mode;                         /* POSIX permission bits */
    uint16_t options;                      /* kXR_open_read | kXR_retstat | … */
    uint16_t optiont;                      /* extended open flags */
    uint8_t  fhtemplt[XRDW_FHANDLE_LEN];   /* file handle template (usually 0) */
} xrdw_open_req_t;

int xrdw_open_req_pack(const xrdw_open_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_open_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_open_req_t *r);

/* kXR_close (3003) — body: fhandle(4) reserved(12). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
} xrdw_close_req_t;

int xrdw_close_req_pack(const xrdw_close_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_close_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_close_req_t *r);

/* kXR_read (3013) — body: fhandle(4) offset(8) rlen(4). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    int64_t  offset;
    int32_t  rlen;
} xrdw_read_req_t;

int xrdw_read_req_pack(const xrdw_read_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_read_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_read_req_t *r);

/* kXR_pgread (3030) — body: fhandle(4) offset(8) rlen(4). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    int64_t  offset;
    int32_t  rlen;
} xrdw_pgread_req_t;

int xrdw_pgread_req_pack(const xrdw_pgread_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_pgread_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgread_req_t *r);

/* kXR_write (3019) — body: fhandle(4) offset(8) pathid(1) reserved(3). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    int64_t  offset;
    uint8_t  pathid;
} xrdw_write_req_t;

int xrdw_write_req_pack(const xrdw_write_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_write_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_write_req_t *r);

/* kXR_pgwrite (3026) — body: fhandle(4) offset(8) pathid(1) reqflags(1) reserved(2). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    int64_t  offset;
    uint8_t  pathid;
    uint8_t  reqflags;                     /* kXR_pgRetry or 0 */
} xrdw_pgwrite_req_t;

int xrdw_pgwrite_req_pack(const xrdw_pgwrite_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_pgwrite_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_pgwrite_req_t *r);

/* kXR_sync (3016) — body: fhandle(4) reserved(12). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
} xrdw_sync_req_t;

int xrdw_sync_req_pack(const xrdw_sync_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_sync_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sync_req_t *r);

/* kXR_truncate (3028) — body: fhandle(4) offset(8) reserved(4). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    int64_t  offset;                       /* target file length */
} xrdw_truncate_req_t;

int xrdw_truncate_req_pack(const xrdw_truncate_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_truncate_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_truncate_req_t *r);

/* kXR_writev (3031) — body: options(1) reserved(15). */
typedef struct {
    uint8_t  options;                      /* kXR_wv_doSync or 0 */
} xrdw_writev_req_t;

int xrdw_writev_req_pack(const xrdw_writev_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_writev_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_writev_req_t *r);

/* kXR_clone (3032) — body: dst_fhandle(4) reserved(12). */
typedef struct {
    uint8_t  dst_fhandle[XRDW_FHANDLE_LEN];
} xrdw_clone_req_t;

int xrdw_clone_req_pack(const xrdw_clone_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_clone_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_clone_req_t *r);

/* kXR_chkpoint (3012) — body: fhandle(4) reserved(11) opcode(1). */
typedef struct {
    uint8_t  fhandle[XRDW_FHANDLE_LEN];
    uint8_t  opcode;                       /* kXR_ckpBegin/Commit/Query/… */
} xrdw_chkpoint_req_t;

int xrdw_chkpoint_req_pack(const xrdw_chkpoint_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_chkpoint_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chkpoint_req_t *r);

/* ====================================================================== *
 * Namespace family (wire_codec_ns.c): mkdir, mv, rm, rmdir, chmod, set,   *
 * setattr, symlink, readlink, link. Mostly path-only bodies; the variable  *
 * path/payload tail (incl. the setattr 44-byte prefix → vendor_ext) stays  *
 * at the edge.                                                             *
 * ====================================================================== */

/* kXR_mkdir (3008) — body: options(1) reserved(13) mode(2). */
typedef struct {
    uint8_t  options;                      /* kXR_mkdirpath or 0 */
    uint16_t mode;                         /* POSIX permission bits */
} xrdw_mkdir_req_t;

int xrdw_mkdir_req_pack(const xrdw_mkdir_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_mkdir_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_mkdir_req_t *r);

/* kXR_chmod (3002) — body: reserved(14) mode(2). */
typedef struct {
    uint16_t mode;                         /* POSIX permission bits */
} xrdw_chmod_req_t;

int xrdw_chmod_req_pack(const xrdw_chmod_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_chmod_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_chmod_req_t *r);

/* kXR_set (3018) — body: modifier(1) reserved(15). */
typedef struct {
    uint8_t  modifier;                     /* kXR_set_appid / kXR_set_clttl */
} xrdw_set_req_t;

int xrdw_set_req_pack(const xrdw_set_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_set_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_set_req_t *r);

/*
 * kXR_mv (3009) / kXR_symlink (3501) / kXR_link (3503) — body: reserved(14)
 * arg1len(2). Same shape: the payload is "<arg1>SEP<arg2>" and arg1len is the
 * byte length of the first argument. One codec serves all three.
 */
typedef struct {
    int16_t  arg1len;
} xrdw_twopath_req_t;

int xrdw_twopath_req_pack(const xrdw_twopath_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_twopath_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_twopath_req_t *r);

/*
 * Path-only bodies (all 16 bytes reserved/zero): kXR_rm, kXR_rmdir,
 * kXR_readlink, kXR_setattr (its fixed prefix lives in the payload, see
 * vendor_ext), and kXR_ping. pack zeroes the body; unpack is a validated no-op.
 * One codec serves them all.
 */
int xrdw_empty_req_pack(uint8_t body[XRDW_BODY_LEN]);
int xrdw_empty_req_unpack(const uint8_t body[XRDW_BODY_LEN]);

/* ====================================================================== *
 * Session family (wire_codec_session.c): login, auth, protocol, bind,     *
 * endsess, sigver, prepare. (ping uses xrdw_empty_req_*.)                  *
 * ====================================================================== */

/* kXR_login (3007) — body: pid(4) username(8) ability2(1) ability(1) capver(1) reserved(1). */
typedef struct {
    int32_t  pid;
    char     username[8];                  /* NUL-padded, NOT NUL-terminated if 8 */
    uint8_t  ability2;
    uint8_t  ability;
    uint8_t  capver;
} xrdw_login_req_t;

int xrdw_login_req_pack(const xrdw_login_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_login_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_login_req_t *r);

/* kXR_auth (3000) — body: reserved(12) credtype(4). */
typedef struct {
    char     credtype[4];                  /* e.g. "ztn\0", "gsi\0" */
} xrdw_auth_req_t;

int xrdw_auth_req_pack(const xrdw_auth_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_auth_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_auth_req_t *r);

/* kXR_protocol (3006) — body: clientpv(4) flags(1) expect(1) reserved(10). */
typedef struct {
    int32_t  clientpv;
    uint8_t  flags;
    uint8_t  expect;
} xrdw_protocol_req_t;

int xrdw_protocol_req_pack(const xrdw_protocol_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_protocol_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_protocol_req_t *r);

/* kXR_bind (3024) / kXR_endsess (3023) — body: sessid(16). Same shape. */
typedef struct {
    uint8_t  sessid[16];
} xrdw_sessid_req_t;

int xrdw_sessid_req_pack(const xrdw_sessid_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_sessid_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sessid_req_t *r);

/* kXR_sigver (3029) — body: expectrid(2) version(1) flags(1) seqno(8) crypto(1) reserved(3). */
typedef struct {
    uint16_t expectrid;                    /* opcode of the next (signed) request */
    uint8_t  version;
    uint8_t  flags;                        /* kXR_nodata_sig or 0 */
    uint64_t seqno;
    uint8_t  crypto;                       /* kXR_SHA256_sig | kXR_rsaKey_sig */
} xrdw_sigver_req_t;

int xrdw_sigver_req_pack(const xrdw_sigver_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_sigver_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_sigver_req_t *r);

/* kXR_prepare (3021) — body: options(1) prty(1) port(2) optionX(2) reserved(10). */
typedef struct {
    uint8_t  options;                      /* kXR_stage | kXR_cancel | … */
    uint8_t  prty;                         /* request priority */
    uint16_t port;                         /* notification port (kXR_notify) */
    uint16_t optionX;                      /* extended prepare flags */
} xrdw_prepare_req_t;

int xrdw_prepare_req_pack(const xrdw_prepare_req_t *r, uint8_t body[XRDW_BODY_LEN]);
int xrdw_prepare_req_unpack(const uint8_t body[XRDW_BODY_LEN], xrdw_prepare_req_t *r);

#endif /* XROOTD_WIRE_CODEC_H */
