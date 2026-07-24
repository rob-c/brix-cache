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

size_t
fp_tls_rewrite(const unsigned char *in, size_t n,
               unsigned char *out, size_t outcap,
               fp_tls_cfg *c, fp_tls_stats *st)
{
    size_t o = 0, pos = 0;
    unsigned char dv0 = (c->set_ver_major >= 0) ? (unsigned char) c->set_ver_major : 3;
    unsigned char dv1 = (c->set_ver_minor >= 0) ? (unsigned char) c->set_ver_minor : 3;

    if (c->alert_level >= 0) {                    /* one-shot forged alert record */
        unsigned char body[2] = { (unsigned char) c->alert_level,
                                  (unsigned char) c->alert_desc };
        emit_record(out, outcap, &o, 21, dv0, dv1, 2, body, 2, 0);
        st->alerts++;
        c->alert_level = -1;
    }

    while (pos < n) {
        if (pos + 5 > n) {                        /* partial header: pass tail through */
            fp_bufcat(out, outcap, &o, in + pos, n - pos);
            break;
        }
        unsigned char type = in[pos], v0 = in[pos + 1], v1 = in[pos + 2];
        size_t len   = ((size_t) in[pos + 3] << 8) | in[pos + 4];
        size_t avail = (len < n - pos - 5) ? len : (n - pos - 5);
        st->records++;

        if (c->drop_type >= 0 && type == (unsigned char) c->drop_type) {
            st->dropped++;
            pos += 5 + avail;
            continue;
        }

        unsigned char otype = (c->set_type >= 0) ? (unsigned char) c->set_type : type;
        unsigned char ov0   = (c->set_ver_major >= 0) ? (unsigned char) c->set_ver_major : v0;
        unsigned char ov1   = (c->set_ver_minor >= 0) ? (unsigned char) c->set_ver_minor : v1;
        if (c->set_type >= 0 && otype != type) {
            st->retyped++;
        }
        const unsigned char *body = in + pos + 5;

        if (c->frag_max > 0 && avail > (size_t) c->frag_max) {
            size_t off = 0;
            int    first = 1;
            while (off < avail) {
                size_t piece = avail - off;
                if (piece > (size_t) c->frag_max) {
                    piece = (size_t) c->frag_max;
                }
                int flip = first && c->flip_payload;
                emit_record(out, outcap, &o, otype, ov0, ov1,
                            (int) piece, body + off, piece, flip);
                if (flip) {
                    st->flipped++;
                }
                off += piece;
                first = 0;
                st->fragmented++;
            }
        } else {
            int declared = (int) avail + c->inflate_len;
            int flip = c->flip_payload && avail > 0;
            emit_record(out, outcap, &o, otype, ov0, ov1, declared, body, avail, flip);
            if (flip) {
                st->flipped++;
            }
        }
        pos += 5 + avail;
    }
    return o;
}
