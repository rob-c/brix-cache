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
 *       compiled only when its library is present (-DBRIX_HAVE_<NAME>); an
 *       absent backend leaves a descriptor with available=0 so the table never
 *       has holes. A shared bomb guard (output cap + expansion-ratio ceiling) is
 *       enforced centrally in brix_codec_step() so every untrusted decode path
 *       is protected uniformly.
 *
 * No nginx, no logging, no errno semantics — the caller maps result codes to its
 * own HTTP/wire errors and logs at the edge.
 */
#ifndef BRIX_CODEC_CORE_H
#define BRIX_CODEC_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Stable ordinals — used as wire/config identifiers; APPEND ONLY. */
typedef enum {
    BRIX_CODEC_IDENTITY = 0,  /* passthrough; always available            */
    BRIX_CODEC_GZIP     = 1,  /* zlib, gzip wrapper     (token "gzip")    */
    BRIX_CODEC_DEFLATE  = 2,  /* zlib, zlib wrapper     (token "deflate") */
    BRIX_CODEC_ZSTD     = 3,  /* libzstd                (token "zstd")    */
    BRIX_CODEC_BROTLI   = 4,  /* libbrotli              (token "br")      */
    BRIX_CODEC_XZ       = 5,  /* liblzma (.xz)          (token "xz")      */
    BRIX_CODEC_BZIP2    = 6,  /* libbz2                 (token "bzip2")   */
    BRIX_CODEC_LZ4      = 7,  /* liblz4 (LZ4 Frame)     (token "lz4")     */
    BRIX_CODEC_MAX
} brix_codec_id_t;

typedef enum {
    BRIX_CODEC_DIR_COMPRESS   = 0,
    BRIX_CODEC_DIR_DECOMPRESS = 1
} brix_codec_dir_t;

/* step()/brix_codec_step() result codes. */
typedef enum {
    BRIX_CODEC_OK      =  0,  /* progress made; call again to continue       */
    BRIX_CODEC_END     =  1,  /* stream finished (decompress: end marker;    */
                                /*   compress: finish flush fully emitted)     */
    BRIX_CODEC_ERR_DATA     = -1,  /* malformed/corrupt/hostile input        */
    BRIX_CODEC_ERR_MEM      = -2,  /* allocation / backend init failure      */
    BRIX_CODEC_ERR_BOMB     = -3,  /* decompression-bomb guard tripped       */
    BRIX_CODEC_ERR_PARAM    = -4,  /* bad args / codec unavailable           */
    BRIX_CODEC_ERR_INTERNAL = -5   /* unexpected backend state               */
} brix_codec_rc_t;

/*
 * Decompression-bomb guard. Bounds total produced bytes and the output:input
 * expansion ratio. Pass NULL to brix_codec_open() for compress streams or any
 * trusted decode; ALWAYS pass a populated guard for untrusted decode (PUT, ZIP).
 * total_in/total_out are running counters maintained by brix_codec_step().
 */
typedef struct {
    uint64_t  out_cap;     /* hard ceiling on TOTAL produced bytes; 0 = unbounded */
    uint32_t  max_ratio;   /* reject once total_out/total_in exceeds this; 0 = off */
    uint64_t  total_in;    /* init 0 */
    uint64_t  total_out;   /* init 0 */
} brix_codec_guard_t;

/* Ratio check only engages once this many OUTPUT bytes have been produced, so a
 * tiny stream doesn't trip a false positive on its first expansion. It MUST gate
 * on output, not input: a compression bomb has tiny compressed input, so gating
 * on input would disable the ratio guard for exactly the most dangerous streams. */
#define BRIX_CODEC_RATIO_FLOOR  (64u * 1024u)

/*
 * root:// inline read compression (phase-42 W4) wire signalling.
 *
 * When a read handle is opened with the opaque "?xrootd.compress=<codec>" AND
 * the server has brix_read_compress on, the server sets the (otherwise
 * vestigial) kXR_open reply fields ServerResponseBody_Open.cpsize =
 * BRIX_INLINE_CMP_MAGIC and cptype[0] = <codec id ordinal>.  Each subsequent
 * kXR_read response is then a single self-contained codec frame of the requested
 * plaintext range (offset-addressable + resumable because every request is an
 * independent whole-range frame).  pgread/readv ALWAYS stay plaintext so the
 * pgread kXR_status + per-page CRC32c invariant is preserved byte-for-byte.
 *
 * A stock client never sends the opaque, so cpsize stays 0 and the uncompressed
 * path is byte-identical; a stock server ignores the opaque, so cpsize stays 0
 * and our client falls back to plaintext.  cptype[0] carries the codec ordinal
 * (1..BRIX_CODEC_MAX-1) rather than a 4-char name so both ends agree without
 * string parsing — only our own client interprets it.
 */
#define BRIX_INLINE_CMP_MAGIC  0x5A  /* 'Z'; nonzero, fits kXR_int32 cpsize */

/* ---- backend-author interface (implemented by codec_<name>.c) ---- */

typedef struct {
    /* Allocate + initialise native state for (id, dir, level). level is clamped
     * to [level_min,level_max] by the core before this call (compress only;
     * ignored for decompress). Returns 0 on success, <0 (brix_codec_rc_t) on
     * failure (no state leaked). */
    int (*init)(void **state, brix_codec_id_t id, brix_codec_dir_t dir,
                int level);
    /* Consume in[*in_pos..in_len), produce into out[*out_pos..out_size),
     * advancing both cursors by the amount processed/produced. finish!=0 => the
     * caller will supply no input after the current buffer; flush/finalise.
     * Returns OK / END / ERR_*. Must make forward progress when given room. */
    brix_codec_rc_t (*step)(void *state,
                              const uint8_t *in, size_t in_len, size_t *in_pos,
                              uint8_t *out, size_t out_size, size_t *out_pos,
                              int finish);
    void (*end)(void *state);   /* free native state; tolerate NULL */
} brix_codec_backend_t;

typedef struct {
    brix_codec_id_t              id;
    const char                    *name;        /* canonical, e.g. "zstd"   */
    const char                    *http_token;  /* Content-Encoding, e.g. "br" */
    int                            available;   /* 1 if its lib was built in   */
    int                            level_min, level_max, level_default;
    const brix_codec_backend_t  *backend;     /* NULL when !available         */
} brix_codec_desc_t;

/* ---- public API ---- */

const brix_codec_desc_t *brix_codec_by_id(brix_codec_id_t id);
const brix_codec_desc_t *brix_codec_by_name(const char *name, size_t len);
const brix_codec_desc_t *brix_codec_by_http_token(const char *tok, size_t len);
int  brix_codec_available(brix_codec_id_t id);

/* Opaque per-stream state (heap; backend handle lives inside). */
typedef struct brix_codec_stream_s brix_codec_stream_t;

/* Open a stream. guard is copied (may be NULL). level<0 => codec default.
 * Returns NULL on bad/unavailable codec or allocation failure. */
brix_codec_stream_t *brix_codec_open(brix_codec_id_t id,
                                         brix_codec_dir_t dir, int level,
                                         const brix_codec_guard_t *guard);

/* Pump one input buffer. See backend step() contract; additionally enforces the
 * bomb guard and updates its counters. */
brix_codec_rc_t brix_codec_step(brix_codec_stream_t *s,
                                    const uint8_t *in, size_t in_len, size_t *in_pos,
                                    uint8_t *out, size_t out_size, size_t *out_pos,
                                    int finish);

void brix_codec_close(brix_codec_stream_t *s);

#endif /* BRIX_CODEC_CORE_H */
