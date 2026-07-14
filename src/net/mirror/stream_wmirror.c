/*
 * stream_wmirror.c — Phase 24 W3: XRootD stream DATA-write mirroring —
 * per-connection accumulation and the public on_open / observe / cleanup hooks.
 *
 * See stream_wmirror.h.  This file owns the first of the mirror's two halves:
 *
 *   Per-connection accumulation.  A write-open's bytes are gathered into a
 *   bounded per-file buffer hanging off the client connection context
 *   (brix_ctx_t.wmirror).  Only sequential kXR_write data is captured; a
 *   kXR_pgwrite (CRC-interleaved payload), a non-sequential offset, or a buffer
 *   that exceeds the per-file / per-connection cap aborts that file's mirror
 *   (counted) — never blocking the client.  On kXR_close a complete sequential
 *   file is handed to wmir_launch, which starts a self-contained detached shadow
 *   replay (open(create) -> write -> close).
 *
 * The two other halves of the mirror live in siblings after the phase-79
 * file-size split (see stream_wmirror_internal.h):
 *   stream_wmirror_replay.c — detached-replay lifecycle (socket, event handlers,
 *                             flush, teardown, wmir_launch)
 *   stream_wmirror_state.c  — replay protocol state machine (frame build/send +
 *                             per-phase step decisions + dispatch)
 *
 * The shadow MUST be an isolated namespace — replaying writes onto the primary's
 * backing store would corrupt it (see brix_mirror_writes).
 */
#include "stream_wmirror.h"
#include "stream_wmirror_internal.h"
#include "mirror.h"

#include <endian.h>

/* Caps: data-write mirroring is best-effort validation, not a data path. */
#define BRIX_WMIRROR_FILE_CAP  (4u * 1024u * 1024u)   /* 4 MiB per file        */
#define BRIX_WMIRROR_CONN_CAP  (16u * 1024u * 1024u)  /* 16 MiB per connection */


typedef struct {
    size_t                 total_buffered;
    brix_wmirror_file_t  files[BRIX_MAX_FILES];
} brix_wmirror_conn_t;


/*
 * Free a per-file accumulator slot and return it to the empty state.  WHAT:
 * releases the two heap buffers (accumulated data + open payload) and zeroes the
 * struct.  WHY the guarded subtract: the connection-wide byte counter must be
 * decremented by exactly this file's contribution; the `<=` guard defends
 * against any accounting drift so total_buffered can never underflow.  Safe to
 * call on an already-empty slot (NULL buffers, data_len 0) and after launch has
 * stolen f->data (set to NULL).
 */
static void
wmir_file_reset(brix_wmirror_conn_t *wm, brix_wmirror_file_t *f)
{
    if (f->data != NULL)         { ngx_free(f->data); }
    if (f->open_payload != NULL) { ngx_free(f->open_payload); }
    if (wm != NULL && f->data_len <= wm->total_buffered) {
        wm->total_buffered -= f->data_len;
    }
    ngx_memzero(f, sizeof(*f));
}

/*
 * Is data-write mirroring active for this server?  Returns 1 only if ALL gates
 * pass: mirroring enabled with a target, the explicit mirror_writes opt-in is on
 * (writes are off by default — replaying them needs an isolated namespace), and
 * the OP_WRITE bit is in the allowlist and not in the exclude mask.  Every entry
 * point re-checks this so config can disable the feature mid-connection.
 */
static int
wmir_gate(ngx_stream_brix_srv_conf_t *conf)
{
    if (!conf->mirror.enabled || conf->mirror.targets == NULL) { return 0; }
    if (!conf->mirror.mirror_writes) { return 0; }
    if ((conf->mirror.opcode_mask & BRIX_MIRROR_OP_WRITE) == 0) { return 0; }
    if ((conf->mirror.opcode_exclude_mask & BRIX_MIRROR_OP_WRITE) != 0) {
        return 0;
    }
    return 1;
}


/*
 * Hook: a write-open succeeded on the primary — begin accumulating this file.
 *
 * WHAT: snapshot the client's open request (header + path/cgi payload) into the
 * per-connection slot keyed by the primary's file handle index, so kXR_close can
 * later replay it to the shadow.  Called only for write opens; read opens are
 * ignored.  HOW: lazily allocate the per-connection accumulator from the client
 * connection pool on first use; reset any prior open occupying this slot (handle
 * indices are reused across opens).  The payload is copied (own heap buffer)
 * because ctx->recv.payload is transient and reused by later requests; an oversize
 * open payload or OOM marks the slot aborted so it is never replayed.
 */
void
brix_stream_wmirror_on_open(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int client_idx, int is_write)
{
    brix_wmirror_conn_t *wm;
    brix_wmirror_file_t *f;

    if (!is_write || !wmir_gate(conf)) { return; }
    if (client_idx < 0 || client_idx >= BRIX_MAX_FILES) { return; }

    wm = ctx->wmirror;
    if (wm == NULL) {
        wm = ngx_pcalloc(c->pool, sizeof(*wm));
        if (wm == NULL) { return; }
        ctx->wmirror = wm;
    }

    f = &wm->files[client_idx];
    wmir_file_reset(wm, f);                  /* drop any prior open on this slot */

    ngx_memcpy(f->open_hdr, ctx->recv.hdr_buf, 24);
    if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL
        && ctx->recv.cur_dlen <= BRIX_WMIRROR_FILE_CAP)
    {
        f->open_payload = ngx_alloc(ctx->recv.cur_dlen, ngx_cycle->log);
        if (f->open_payload == NULL) { f->aborted = 1; }
        else {
            ngx_memcpy(f->open_payload, ctx->recv.payload, ctx->recv.cur_dlen);
            f->open_dlen = ctx->recv.cur_dlen;
        }
    }
    f->active   = 1;
    f->next_off = 0;
}

/*
 * Hook: observe each write/pgwrite/close on an accumulating file.
 *
 * WHAT: drives the per-file accumulator forward as the client streams writes,
 * and fires the detached replay on a clean close.  The slot is located by the
 * file-handle index carried in the request header (byte 4, the first byte of the
 * 4-byte fhandle the open hook keyed on).  This is best-effort: any condition we
 * can't faithfully replay just marks the slot aborted and is silently dropped —
 * the client is never blocked or affected.
 *
 * Abort triggers (file will NOT be mirrored): kXR_pgwrite (CRC-interleaved, not
 * plain bytes), a non-sequential offset, exceeding the per-file or per-connection
 * cap, an OOM on grow, or the primary itself failing the write.
 */
/*
 * Append one sequential kXR_write's payload to a file accumulator.
 *
 * WHAT: validate contiguity and the caps, then grow-by-copy the captured bytes.
 * WHY split out: keeps the observe dispatcher a thin switch while this holds the
 * whole plain-write accumulation policy in one focused place.  HOW: the write
 * offset is an 8-byte big-endian field at header byte 8 — only a strictly
 * contiguous stream (off == expected next offset) can collapse into the single
 * offset-0 replay write, so a gap/seek aborts.  Enforce the per-file and
 * connection-wide caps before growing (a cap hit is counted, not an error), then
 * allocate old+new, copy the existing prefix, free the old buffer, and append the
 * new bytes (not ngx_realloc, so old contents are explicitly preserved).  Any
 * failure marks the slot aborted; primary_rc==NGX_ERROR aborts up front.
 */
static void
wmir_accumulate_write(brix_wmirror_conn_t *wm, brix_wmirror_file_t *f,
    brix_ctx_t *ctx, ngx_int_t primary_rc)
{
    uint64_t off_be;
    off_t    off;
    size_t   len = ctx->recv.cur_dlen;
    u_char  *ndata;

    if (f->aborted) { return; }
    if (primary_rc == NGX_ERROR) { f->aborted = 1; return; }

    ngx_memcpy(&off_be, ctx->recv.hdr_buf + 8, 8);
    off = (off_t) be64toh(off_be);
    if (off != f->next_off) { f->aborted = 1; return; }   /* non-sequential */
    if (len == 0) { return; }

    if (f->data_len + len > BRIX_WMIRROR_FILE_CAP
        || wm->total_buffered + len > BRIX_WMIRROR_CONN_CAP)
    {
        f->aborted = 1;
        BRIX_WMIR_METRIC_INC(mirror_stream_dropped_total);
        return;
    }

    ndata = ngx_alloc(f->data_len + len, ngx_cycle->log);
    if (ndata == NULL) { f->aborted = 1; return; }
    if (f->data_len) {
        ngx_memcpy(ndata, f->data, f->data_len);
        ngx_free(f->data);
    }
    ngx_memcpy(ndata + f->data_len, ctx->recv.payload, len);
    f->data = ndata;
    f->data_len += len;
    f->next_off += (off_t) len;            /* advance expected contiguous offset */
    wm->total_buffered += len;
}

/*
 * kXR_close handler: fire the detached replay for a clean file, then reset.
 * WHAT: replay only a non-empty, non-aborted file whose primary close also
 * succeeded.  HOW: wmir_launch steals f->data, so the unconditional
 * wmir_file_reset that follows safely clears the (now-nulled) slot.
 */
static void
wmir_observe_close(ngx_stream_brix_srv_conf_t *conf, brix_wmirror_conn_t *wm,
    brix_wmirror_file_t *f, ngx_int_t primary_rc)
{
    f->active = 0;
    if (!f->aborted && f->data_len > 0 && primary_rc != NGX_ERROR) {
        wmir_launch(conf, f);              /* transfers f->data ownership */
    }
    wmir_file_reset(wm, f);
}

void
brix_stream_wmirror_observe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, ngx_int_t primary_rc)
{
    brix_wmirror_conn_t *wm;
    brix_wmirror_file_t *f;
    int                    idx;

    (void) c;
    wm = ctx->wmirror;
    if (wm == NULL || !wmir_gate(conf)) { return; }

    idx = (int) (unsigned char) ctx->recv.hdr_buf[4];   /* fhandle byte 0 */
    if (idx < 0 || idx >= BRIX_MAX_FILES) { return; }
    f = &wm->files[idx];
    if (!f->active) { return; }

    switch (ctx->recv.cur_reqid) {

    case kXR_pgwrite:
        f->aborted = 1;        /* CRC-interleaved payload — not a plain write */
        return;

    case kXR_write:
        wmir_accumulate_write(wm, f, ctx, primary_rc);
        return;

    case kXR_close:
        wmir_observe_close(conf, wm, f, primary_rc);
        return;

    default:
        return;
    }
}

/*
 * Hook: client connection is going away — free any still-open accumulators.
 *
 * WHY this matters: f->data / f->open_payload are heap buffers (ngx_alloc), NOT
 * pool memory, so they would leak if the connection dies mid-upload (no close
 * ever observed).  Resetting every slot frees them.  The accumulator struct (wm)
 * itself lives in the connection pool and is reclaimed automatically, so we only
 * drop the pointer.  Any replay already launched is fully detached and unaffected
 * (it owns its own copy of the data).
 */
void
brix_stream_wmirror_cleanup(brix_ctx_t *ctx)
{
    brix_wmirror_conn_t *wm = ctx->wmirror;
    int                    i;

    if (wm == NULL) { return; }
    for (i = 0; i < BRIX_MAX_FILES; i++) {
        wmir_file_reset(wm, &wm->files[i]);
    }
    ctx->wmirror = NULL;   /* wm itself is connection-pool memory */
}
