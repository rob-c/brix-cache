/*
 * codec_core.c — codec descriptor table + stream lifecycle + bomb guard.
 *
 * WHAT: Implements brix_codec_open/step/close and the by_id/by_name/
 *       by_http_token lookups over a static descriptor table, plus the always-on
 *       IDENTITY (passthrough) backend. Per-codec backends live in codec_<name>.c
 *       and are referenced here by extern descriptor.
 * WHY:  Single dispatch + single place to enforce the decompression-bomb guard,
 *       so every untrusted decode path is protected identically (see codec_core.h).
 * HOW:  Backends always define their descriptor (available=0 when their lib is
 *       absent), so the table is dense and dispatch is a bounds-checked index.
 *       brix_codec_step() wraps the backend step and updates/enforces the guard.
 */

#include "codec_core.h"

#include <stdlib.h>
#include <string.h>

struct brix_codec_stream_s {
    const brix_codec_desc_t  *desc;
    void                       *state;
    brix_codec_dir_t          dir;
    brix_codec_guard_t        guard;
};

/* IDENTITY backend (passthrough; always available) */
static int
identity_init(void **state, brix_codec_id_t id, brix_codec_dir_t dir, int level)
{
    (void) id; (void) dir; (void) level;
    *state = NULL;
    return 0;
}

static brix_codec_rc_t
identity_step(void *state, const uint8_t *in, size_t in_len, size_t *in_pos,
              uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    size_t avail = in_len - *in_pos;
    size_t room  = out_size - *out_pos;
    size_t n     = (avail < room) ? avail : room;

    (void) state;
    if (n) {
        memcpy(out + *out_pos, in + *in_pos, n);
        *in_pos += n;
        *out_pos += n;
    }
    if (*in_pos == in_len && finish) {
        return BRIX_CODEC_END;
    }
    return BRIX_CODEC_OK;
}

static void
identity_end(void *state)
{
    (void) state;
}

static const brix_codec_backend_t identity_backend = {
    identity_init, identity_step, identity_end
};

const brix_codec_desc_t brix_codec_identity_desc = {
    BRIX_CODEC_IDENTITY, "identity", "identity", 1, 0, 0, 0, &identity_backend
};

/* per-codec descriptors (always defined; available=0 when lib absent) */
extern const brix_codec_desc_t brix_codec_gzip_desc;
extern const brix_codec_desc_t brix_codec_deflate_desc;
extern const brix_codec_desc_t brix_codec_zstd_desc;
extern const brix_codec_desc_t brix_codec_brotli_desc;
extern const brix_codec_desc_t brix_codec_xz_desc;
extern const brix_codec_desc_t brix_codec_bzip2_desc;
extern const brix_codec_desc_t brix_codec_lz4_desc;

static const brix_codec_desc_t *const codec_table[BRIX_CODEC_MAX] = {
    [BRIX_CODEC_IDENTITY] = &brix_codec_identity_desc,
    [BRIX_CODEC_GZIP]     = &brix_codec_gzip_desc,
    [BRIX_CODEC_DEFLATE]  = &brix_codec_deflate_desc,
    [BRIX_CODEC_ZSTD]     = &brix_codec_zstd_desc,
    [BRIX_CODEC_BROTLI]   = &brix_codec_brotli_desc,
    [BRIX_CODEC_XZ]       = &brix_codec_xz_desc,
    [BRIX_CODEC_BZIP2]    = &brix_codec_bzip2_desc,
    [BRIX_CODEC_LZ4]      = &brix_codec_lz4_desc,
};

/* lookups */
const brix_codec_desc_t *
brix_codec_by_id(brix_codec_id_t id)
{
    if (id < 0 || id >= BRIX_CODEC_MAX) {
        return NULL;
    }
    return codec_table[id];
}

static int
codec_ci_eq(const char *a, const char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char) a[i];
        unsigned char cb = (unsigned char) b[i];
        if (ca >= 'A' && ca <= 'Z') { ca = (unsigned char) (ca + 32); }
        if (cb >= 'A' && cb <= 'Z') { cb = (unsigned char) (cb + 32); }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

static const brix_codec_desc_t *
codec_match(const char *s, size_t len, int by_token)
{
    size_t i;

    if (s == NULL || len == 0) {
        return NULL;
    }
    /* HTTP Content-Encoding tokens are case-insensitive; canonical names match
     * exactly (config values). */
    for (i = 0; i < BRIX_CODEC_MAX; i++) {
        const brix_codec_desc_t *d = codec_table[i];
        const char *key = by_token ? d->http_token : d->name;
        if (key != NULL && strlen(key) == len
            && (by_token ? codec_ci_eq(key, s, len) : memcmp(key, s, len) == 0)) {
            return d;
        }
    }
    return NULL;
}

const brix_codec_desc_t *
brix_codec_by_name(const char *name, size_t len)
{
    return codec_match(name, len, 0);
}

const brix_codec_desc_t *
brix_codec_by_http_token(const char *tok, size_t len)
{
    return codec_match(tok, len, 1);
}

int
brix_codec_available(brix_codec_id_t id)
{
    const brix_codec_desc_t *d = brix_codec_by_id(id);
    return (d != NULL && d->available && d->backend != NULL);
}

/* stream lifecycle */
brix_codec_stream_t *
brix_codec_open(brix_codec_id_t id, brix_codec_dir_t dir, int level,
                  const brix_codec_guard_t *guard)
{
    const brix_codec_desc_t *d = brix_codec_by_id(id);
    brix_codec_stream_t     *s;
    int                        lvl;

    if (d == NULL || !d->available || d->backend == NULL) {
        return NULL;
    }

    lvl = (level < 0) ? d->level_default : level;
    if (lvl < d->level_min) { lvl = d->level_min; }
    if (lvl > d->level_max) { lvl = d->level_max; }

    s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->desc = d;
    s->dir  = dir;
    if (guard != NULL) {
        s->guard = *guard;
    }
    if (d->backend->init(&s->state, id, dir, lvl) != 0) {
        free(s);
        return NULL;
    }
    return s;
}

brix_codec_rc_t
brix_codec_step(brix_codec_stream_t *s,
                  const uint8_t *in, size_t in_len, size_t *in_pos,
                  uint8_t *out, size_t out_size, size_t *out_pos, int finish)
{
    size_t            in0, out0;
    brix_codec_rc_t rc;

    if (s == NULL || in_pos == NULL || out_pos == NULL
        || *in_pos > in_len || *out_pos > out_size) {
        return BRIX_CODEC_ERR_PARAM;
    }

    in0  = *in_pos;
    out0 = *out_pos;
    rc = s->desc->backend->step(s->state, in, in_len, in_pos,
                                out, out_size, out_pos, finish);
    if (rc < 0) {
        return rc;
    }

    s->guard.total_in  += (uint64_t) (*in_pos - in0);
    s->guard.total_out += (uint64_t) (*out_pos - out0);

    if (s->dir == BRIX_CODEC_DIR_DECOMPRESS) {
        if (s->guard.out_cap != 0 && s->guard.total_out > s->guard.out_cap) {
            return BRIX_CODEC_ERR_BOMB;
        }
        if (s->guard.max_ratio != 0
            && s->guard.total_in > 0
            && s->guard.total_out >= BRIX_CODEC_RATIO_FLOOR
            && s->guard.total_out / s->guard.total_in > (uint64_t) s->guard.max_ratio) {
            return BRIX_CODEC_ERR_BOMB;
        }
    }
    return rc;
}

void
brix_codec_close(brix_codec_stream_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->desc != NULL && s->desc->backend != NULL
        && s->desc->backend->end != NULL) {
        s->desc->backend->end(s->state);
    }
    free(s);
}
