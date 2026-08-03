/*
 * brix_fault_tls.c — pure TLS record-layer surgery.  See brix_fault_tls.h.
 */
#include "brix_fault_tls.h"
#include "brix_fault_buf.h"

void
fp_tls_cfg_init(fp_tls_cfg *c)
{
    c->frag_max = 0;
    c->set_type = -1;
    c->set_ver_major = -1;
    c->set_ver_minor = -1;
    c->inflate_len = 0;
    c->flip_payload = 0;
    c->drop_type = -1;
    c->alert_level = -1;
    c->alert_desc = 0;
}

int
fp_tls_active(const fp_tls_cfg *c)
{
    return c->frag_max > 0 || c->set_type >= 0 || c->set_ver_major >= 0 ||
           c->set_ver_minor >= 0 || c->inflate_len != 0 || c->flip_payload ||
           c->drop_type >= 0 || c->alert_level >= 0;
}

/* Emit one record: a 5-byte header declaring `declared_len` (clamped to a legal
 * uint16) then `blen` body bytes, optionally flipping the first payload byte. */
static void
emit_record(unsigned char *out, size_t cap, size_t *o,
            unsigned char type, unsigned char v0, unsigned char v1,
            int declared_len, const unsigned char *body, size_t blen,
            int flip_first)
{
    unsigned char hdr[5];
    if (declared_len < 0) {
        declared_len = 0;
    }
    if (declared_len > 0xFFFF) {
        declared_len = 0xFFFF;
    }
    hdr[0] = type;
    hdr[1] = v0;
    hdr[2] = v1;
    hdr[3] = (unsigned char) (declared_len >> 8);
    hdr[4] = (unsigned char) (declared_len & 0xFF);
    fp_bufcat(out, cap, o, hdr, 5);
    if (blen > 0) {
        size_t start = *o;
        size_t w = fp_bufcat(out, cap, o, body, blen);
        if (flip_first && w > 0) {
            out[start] ^= 0xFF;
        }
    }
}

/* The 5-byte header a rewritten record carries: each field is overridden when
 * its lever is armed, and passed through otherwise. */
typedef struct { unsigned char type, v0, v1; } tls_hdr;

static tls_hdr
tls_out_header(const fp_tls_cfg *c, const tls_hdr *in, fp_tls_stats *st)
{
    tls_hdr h;
    h.type = (c->set_type >= 0)      ? (unsigned char) c->set_type      : in->type;
    h.v0   = (c->set_ver_major >= 0) ? (unsigned char) c->set_ver_major : in->v0;
    h.v1   = (c->set_ver_minor >= 0) ? (unsigned char) c->set_ver_minor : in->v1;
    if (h.type != in->type) {
        st->retyped++;
    }
    return h;
}

/* One-shot forged alert record, injected ahead of the stream. */
static void
tls_forge_alert(unsigned char *out, size_t outcap, size_t *o,
                fp_tls_cfg *c, fp_tls_stats *st)
{
    unsigned char v0 = (c->set_ver_major >= 0) ? (unsigned char) c->set_ver_major : 3;
    unsigned char v1 = (c->set_ver_minor >= 0) ? (unsigned char) c->set_ver_minor : 3;
    unsigned char body[2] = { (unsigned char) c->alert_level,
                              (unsigned char) c->alert_desc };

    emit_record(out, outcap, o, 21, v0, v1, 2, body, 2, 0);
    st->alerts++;
    c->alert_level = -1;
}

/* Re-emit one record's payload as a run of frag_max-sized records — the peer
 * must reassemble across record boundaries. */
static void
tls_emit_fragments(unsigned char *out, size_t outcap, size_t *o, const tls_hdr *h,
                   const unsigned char *body, size_t avail,
                   const fp_tls_cfg *c, fp_tls_stats *st)
{
    size_t off = 0;
    int    first = 1;

    while (off < avail) {
        size_t piece = avail - off;
        if (piece > (size_t) c->frag_max) {
            piece = (size_t) c->frag_max;
        }
        int flip = first && c->flip_payload;
        emit_record(out, outcap, o, h->type, h->v0, h->v1,
                    (int) piece, body + off, piece, flip);
        if (flip) {
            st->flipped++;
        }
        off += piece;
        first = 0;
        st->fragmented++;
    }
}

/* Re-emit one record whole, honouring the declared-length inflation lever. */
static void
tls_emit_whole(unsigned char *out, size_t outcap, size_t *o, const tls_hdr *h,
               const unsigned char *body, size_t avail,
               const fp_tls_cfg *c, fp_tls_stats *st)
{
    int flip = c->flip_payload && avail > 0;

    emit_record(out, outcap, o, h->type, h->v0, h->v1,
                (int) avail + c->inflate_len, body, avail, flip);
    if (flip) {
        st->flipped++;
    }
}

size_t
fp_tls_rewrite(const unsigned char *in, size_t n,
               unsigned char *out, size_t outcap,
               fp_tls_cfg *c, fp_tls_stats *st)
{
    size_t o = 0, pos = 0;

    if (c->alert_level >= 0) {
        tls_forge_alert(out, outcap, &o, c, st);
    }

    while (pos < n) {
        if (pos + 5 > n) {                        /* partial header: pass tail through */
            fp_bufcat(out, outcap, &o, in + pos, n - pos);
            break;
        }
        tls_hdr hin = { in[pos], in[pos + 1], in[pos + 2] };
        size_t  len   = ((size_t) in[pos + 3] << 8) | in[pos + 4];
        size_t  avail = (len < n - pos - 5) ? len : (n - pos - 5);
        st->records++;

        if (c->drop_type >= 0 && hin.type == (unsigned char) c->drop_type) {
            st->dropped++;
            pos += 5 + avail;
            continue;
        }
        tls_hdr              hout = tls_out_header(c, &hin, st);
        const unsigned char *body = in + pos + 5;

        if (c->frag_max > 0 && avail > (size_t) c->frag_max) {
            tls_emit_fragments(out, outcap, &o, &hout, body, avail, c, st);
        } else {
            tls_emit_whole(out, outcap, &o, &hout, body, avail, c, st);
        }
        pos += 5 + avail;
    }
    return o;
}
