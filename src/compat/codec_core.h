/*
 * codec_core.h — pure (ngx-free) streaming compression/decompression abstraction.
 *
 * WHAT: One uniform streaming API over every compression codec the project
 *       supports (gzip/deflate via zlib, zstd, xz/lzma, brotli, bzip2). A caller
 *       opens a stream for one codec + direction, pumps input through step() and
 *       drains output, then closes — never touching z_stream / ZSTD_CCtx /
 *       lzma_stream / Brotli* / bz_stream directly. A descriptor table makes
 *       codec selection (by id / canonical name / HTTP Content-Encoding token)
 *       branch-free.
 * WHY:  All four compression surfaces (inbound PUT decode, outbound GET encode,
 *       ZIP member inflate, root:// inline) and BOTH consumers — the nginx module
 *       (src/) and the native client (client/) — must share one implementation.
 *       Like checksum_core.c / crc32c.c / gsi_core.c, this is an ngx-free kernel
 *       carried by libxrdproto (build-in-place), linked by module + libxrdc.
 * HOW:  Each codec is a backend (init/step/end vtable) in its own codec_<name>.c,
 *       compiled only when its library is present (-DXROOTD_HAVE_<NAME>); an
 *       absent backend leaves a descriptor with available=0 so the table never
 *       has holes. A shared bomb guard (output cap + expansion-ratio ceiling) is
 *       enforced centrally in xrootd_codec_step() so every untrusted decode path
 *       is protected uniformly.
 *
 * No nginx, no logging, no errno semantics — the caller maps result codes to its
 * own HTTP/wire errors and logs at the edge.
 */
#ifndef XROOTD_CODEC_CORE_H
#define XROOTD_CODEC_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Stable ordinals — used as wire/config identifiers; APPEND ONLY. */
typedef enum {
    XROOTD_CODEC_IDENTITY = 0,  /* passthrough; always available            */
    XROOTD_CODEC_GZIP     = 1,  /* zlib, gzip wrapper     (token "gzip")    */
    XROOTD_CODEC_DEFLATE  = 2,  /* zlib, zlib wrapper     (token "deflate") */
    XROOTD_CODEC_ZSTD     = 3,  /* libzstd                (token "zstd")    */
    XROOTD_CODEC_BROTLI   = 4,  /* libbrotli              (token "br")      */
    XROOTD_CODEC_XZ       = 5,  /* liblzma (.xz)          (token "xz")      */
    XROOTD_CODEC_BZIP2    = 6,  /* libbz2                 (token "bzip2")   */
    XROOTD_CODEC_LZ4      = 7,  /* liblz4 (LZ4 Frame)     (token "lz4")     */
    XROOTD_CODEC_MAX
} xrootd_codec_id_t;

typedef enum {
    XROOTD_CODEC_DIR_COMPRESS   = 0,
    XROOTD_CODEC_DIR_DECOMPRESS = 1
} xrootd_codec_dir_t;

/* step()/xrootd_codec_step() result codes. */
typedef enum {
    XROOTD_CODEC_OK      =  0,  /* progress made; call again to continue       */
    XROOTD_CODEC_END     =  1,  /* stream finished (decompress: end marker;    */
                                /*   compress: finish flush fully emitted)     */
    XROOTD_CODEC_ERR_DATA     = -1,  /* malformed/corrupt/hostile input        */
    XROOTD_CODEC_ERR_MEM      = -2,  /* allocation / backend init failure      */
    XROOTD_CODEC_ERR_BOMB     = -3,  /* decompression-bomb guard tripped       */
    XROOTD_CODEC_ERR_PARAM    = -4,  /* bad args / codec unavailable           */
    XROOTD_CODEC_ERR_INTERNAL = -5   /* unexpected backend state               */
} xrootd_codec_rc_t;

/*
 * Decompression-bomb guard. Bounds total produced bytes and the output:input
 * expansion ratio. Pass NULL to xrootd_codec_open() for compress streams or any
 * trusted decode; ALWAYS pass a populated guard for untrusted decode (PUT, ZIP).
 * total_in/total_out are running counters maintained by xrootd_codec_step().
 */
typedef struct {
    uint64_t  out_cap;     /* hard ceiling on TOTAL produced bytes; 0 = unbounded */
    uint32_t  max_ratio;   /* reject once total_out/total_in exceeds this; 0 = off */
    uint64_t  total_in;    /* init 0 */
    uint64_t  total_out;   /* init 0 */
} xrootd_codec_guard_t;

/* Ratio check only engages once this many OUTPUT bytes have been produced, so a
 * tiny stream doesn't trip a false positive on its first expansion. It MUST gate
 * on output, not input: a compression bomb has tiny compressed input, so gating
 * on input would disable the ratio guard for exactly the most dangerous streams. */
#define XROOTD_CODEC_RATIO_FLOOR  (64u * 1024u)

/*
 * root:// inline read compression (phase-42 W4) wire signalling.
 *
 * When a read handle is opened with the opaque "?xrootd.compress=<codec>" AND
 * the server has xrootd_read_compress on, the server sets the (otherwise
 * vestigial) kXR_open reply fields ServerResponseBody_Open.cpsize =
 * XROOTD_INLINE_CMP_MAGIC and cptype[0] = <codec id ordinal>.  Each subsequent
 * kXR_read response is then a single self-contained codec frame of the requested
 * plaintext range (offset-addressable + resumable because every request is an
 * independent whole-range frame).  pgread/readv ALWAYS stay plaintext so the
 * pgread kXR_status + per-page CRC32c invariant is preserved byte-for-byte.
 *
 * A stock client never sends the opaque, so cpsize stays 0 and the uncompressed
 * path is byte-identical; a stock server ignores the opaque, so cpsize stays 0
 * and our client falls back to plaintext.  cptype[0] carries the codec ordinal
 * (1..XROOTD_CODEC_MAX-1) rather than a 4-char name so both ends agree without
 * string parsing — only our own client interprets it.
 */
#define XROOTD_INLINE_CMP_MAGIC  0x5A  /* 'Z'; nonzero, fits kXR_int32 cpsize */

/* ---- backend-author interface (implemented by codec_<name>.c) ---- */

typedef struct {
    /* Allocate + initialise native state for (id, dir, level). level is clamped
     * to [level_min,level_max] by the core before this call (compress only;
     * ignored for decompress). Returns 0 on success, <0 (xrootd_codec_rc_t) on
     * failure (no state leaked). */
    int (*init)(void **state, xrootd_codec_id_t id, xrootd_codec_dir_t dir,
                int level);
    /* Consume in[*in_pos..in_len), produce into out[*out_pos..out_size),
     * advancing both cursors by the amount processed/produced. finish!=0 => the
     * caller will supply no input after the current buffer; flush/finalise.
     * Returns OK / END / ERR_*. Must make forward progress when given room. */
    xrootd_codec_rc_t (*step)(void *state,
                              const uint8_t *in, size_t in_len, size_t *in_pos,
                              uint8_t *out, size_t out_size, size_t *out_pos,
                              int finish);
    void (*end)(void *state);   /* free native state; tolerate NULL */
} xrootd_codec_backend_t;

typedef struct {
    xrootd_codec_id_t              id;
    const char                    *name;        /* canonical, e.g. "zstd"   */
    const char                    *http_token;  /* Content-Encoding, e.g. "br" */
    int                            available;   /* 1 if its lib was built in   */
    int                            level_min, level_max, level_default;
    const xrootd_codec_backend_t  *backend;     /* NULL when !available         */
} xrootd_codec_desc_t;

/* ---- public API ---- */

const xrootd_codec_desc_t *xrootd_codec_by_id(xrootd_codec_id_t id);
const xrootd_codec_desc_t *xrootd_codec_by_name(const char *name, size_t len);
const xrootd_codec_desc_t *xrootd_codec_by_http_token(const char *tok, size_t len);
int  xrootd_codec_available(xrootd_codec_id_t id);

/* Opaque per-stream state (heap; backend handle lives inside). */
typedef struct xrootd_codec_stream_s xrootd_codec_stream_t;

/* Open a stream. guard is copied (may be NULL). level<0 => codec default.
 * Returns NULL on bad/unavailable codec or allocation failure. */
xrootd_codec_stream_t *xrootd_codec_open(xrootd_codec_id_t id,
                                         xrootd_codec_dir_t dir, int level,
                                         const xrootd_codec_guard_t *guard);

/* Pump one input buffer. See backend step() contract; additionally enforces the
 * bomb guard and updates its counters. */
xrootd_codec_rc_t xrootd_codec_step(xrootd_codec_stream_t *s,
                                    const uint8_t *in, size_t in_len, size_t *in_pos,
                                    uint8_t *out, size_t out_size, size_t *out_pos,
                                    int finish);

void xrootd_codec_close(xrootd_codec_stream_t *s);

#endif /* XROOTD_CODEC_CORE_H */
