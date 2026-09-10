/*
 * ssi_client.c — native SSI request/response client. See ssi_client.h for the
 * two facts that shape this file: one control word with TWO carriers, and two
 * reply paths that a caller must not be able to tell apart.
 *
 * Everything wire-facing is delegated: the control word to the SHARED codec in
 * libxrdproto (src/protocols/ssi/ssi_rrinfo.c — the same object the server
 * links), the request bodies to the shared per-opcode packers (wire_codec.h),
 * and the asynresp envelope to brix_recv_next_asynresp (frame.c). Nothing here
 * lays out a byte by hand.
 */

#include "ssi_client.h"
#include "protocols/root/protocol/frame_hdr.h"          /* xrd_get_u64_be */
#include "protocols/root/protocol/open_flags.h"         /* brix_open_options_build */
#include "protocols/root/protocol/codec/wire_codec.h"   /* xrdw_*_req_pack */
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* ServerOpenBody: fhandle(4) cpsize(4) cptype(4). A retstat open appends a
 * NUL-terminated StatInfo string after it. */
#define SSI_OPENBODY_LEN 12

/*
 * WHAT: turn a control word into the int64 the kXR offset field carries.
 * WHY:  the read/write bodies are packed by the shared codec, whose offset is a
 *       signed 64-bit field — so the 8 RRInfo bytes have to become an int64
 *       somewhere. Doing it here, once, keeps the byte order owned by
 *       frame_hdr.h instead of being re-derived at each call site.
 * HOW:  encode, then load big-endian, which is exactly how the server reverses
 *       it (brix_ssi_read re-serializes the offset back to 8 bytes before
 *       decoding). The cast cannot lose or misrepresent a bit: the RRInfo's
 *       leading byte is the command (Rxq/Rwt/Can = 0/1/2), so it is the offset's
 *       most-significant byte and the value is always a small positive int64 —
 *       never the negative offset a naive reader would fear.
 */
static int64_t
ssi_ctl_offset(int cmd, uint32_t id, uint32_t size)
{
    unsigned char off8[BRIX_SSI_RRINFO_LEN];

    brix_ssi_rrinfo_encode(cmd, id, size, off8);
    return (int64_t) xrd_get_u64_be(off8);
}

/*
 * WHAT: map an XrdSsiRRInfoAttn tag byte to the event the caller sees.
 * WHY:  this IS the discriminator — the transport builds an identical envelope
 *       for an alert and for the terminal response, so a wrong or unknown tag
 *       must fail loudly here rather than be guessed at. Both reply paths funnel
 *       through this one function so the decision exists exactly once.
 */
static int
ssi_tag_to_ev(char tag, brix_ssi_ev *ev, brix_status *st)
{
    if (tag == BRIX_SSI_ATTN_ALRT) { *ev = BRIX_SSI_EV_ALERT;    return 0; }
    if (tag == BRIX_SSI_ATTN_FULL) { *ev = BRIX_SSI_EV_RESPONSE; return 0; }
    if (tag == BRIX_SSI_ATTN_PEND) { *ev = BRIX_SSI_EV_PENDING;  return 0; }

    brix_status_set(st, XRDC_EPROTO, 0, "unknown SSI attn tag 0x%02x",
                    (unsigned) (unsigned char) tag);
    return -1;
}

/*
 * WHAT: split a delivered payload into prefix / metadata / data.
 * WHY:  the data length is stated NOWHERE on the wire — it is only recoverable
 *       as total - pfx_len - md_len — so both server-declared lengths must be
 *       validated against the frame we actually received before either is used
 *       as an offset. A server that overstates md_len would otherwise walk the
 *       data pointer past the allocation.
 * HOW:  `raw` is adopted on success (the reply owns it) and left untouched on
 *       failure, so the caller's free is unambiguous either way.
 */
static int
ssi_reply_split(uint8_t *raw, uint32_t rawlen, brix_ssi_reply *r,
                brix_status *st)
{
    char     tag;
    uint16_t pfx;
    uint32_t md;

    if (raw == NULL || rawlen < BRIX_SSI_ATTN_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI reply shorter than its attn prefix (%u < %d)",
                        rawlen, (int) BRIX_SSI_ATTN_LEN);
        return -1;
    }
    brix_ssi_attn_decode(raw, &tag, NULL, &pfx, &md);

    if (pfx < BRIX_SSI_ATTN_LEN || pfx > rawlen || md > rawlen - pfx) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI reply lengths do not fit the frame "
                        "(pfx %u + md %u of %u)", (unsigned) pfx, md, rawlen);
        return -1;
    }
    if (ssi_tag_to_ev(tag, &r->ev, st) != 0) {
        return -1;
    }

    r->raw      = raw;
    r->meta_len = md;
    r->meta     = (md > 0) ? raw + pfx : NULL;
    r->data_len = rawlen - pfx - md;
    r->data     = (r->data_len > 0) ? raw + pfx + md : NULL;
    return 0;
}

/*
 * WHAT: send one control word on the QUERY carrier and hand back the reply body.
 * WHY:  response-wait (Rwt) and cancel (Can) are the same request shape and
 *       differ only in the command byte; the server routes both through
 *       brix_ssi_query, which reads the RRInfo from the query PAYLOAD — not from
 *       an offset field, which this opcode does not have.
 * HOW:  brix_roundtrip (not brix_send/brix_recv) so a clustered endpoint's
 *       redirect is followed, matching every other path-addressed op.
 */
static int
ssi_query_ctl(brix_ssi_sess *s, int cmd, uint8_t **body, uint32_t *blen,
              brix_status *st)
{
    ClientQueryRequest req;
    unsigned char      off8[BRIX_SSI_RRINFO_LEN];
    uint16_t           status;

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_query);
    {
        xrdw_query_req_t q = { .infotype = (uint16_t) kXR_Qopaqug };
        memcpy(q.fhandle, s->fhandle, XRDW_FHANDLE_LEN);
        xrdw_query_req_pack(&q, ((ClientRequestHdr *) &req)->body);
    }
    brix_ssi_rrinfo_encode(cmd, s->req_id, 0, off8);

    {
        brix_payload  pl  = { off8, (uint32_t) BRIX_SSI_RRINFO_LEN };
        brix_resp_out out = { &status, body, blen };
        return brix_roundtrip(s->conn, &req, &pl, &out, st);
    }
}

void
brix_ssi_reply_free(brix_ssi_reply *r)
{
    if (r == NULL) {
        return;
    }
    free(r->raw);
    memset(r, 0, sizeof(*r));
}

int
brix_ssi_sess_open(brix_ssi_sess *s, brix_conn *c, const char *service,
                   brix_status *st)
{
    ClientOpenRequest req;
    char             *path;
    size_t            need;
    uint16_t          status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;

    memset(s, 0, sizeof(*s));
    s->conn   = c;
    s->req_id = 1;   /* any nonzero 24-bit id; one request in flight per session */

    need = BRIX_SSI_PREFIX_LEN + strlen(service) + 1;
    path = (char *) malloc(need);
    if (path == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory (%zu)", need);
        return -1;
    }
    snprintf(path, need, "%s%s", BRIX_SSI_PREFIX, service);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_open);
    {
        /* Read-only + retstat. brix_open_options_build() cannot produce
         * kXR_retstat — nothing else in this client sets it — so it is OR-ed on
         * here rather than added to that helper, whose four callers all mean
         * "ordinary file open". */
        xrdw_open_req_t o = {
            .options = (uint16_t) (brix_open_options_build(0, 0, 0, 0)
                                   | (uint16_t) kXR_retstat)
        };
        xrdw_open_req_pack(&o, ((ClientRequestHdr *) &req)->body);
    }
    {
        brix_payload  pl  = { path, (uint32_t) (need - 1) };
        brix_resp_out out = { &status, &body, &blen };
        if (brix_roundtrip(c, &req, &pl, &out, st) != 0) {
            free(path);
            return -1;
        }
    }
    free(path);

    if (blen < XRDC_FHANDLE_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI open reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    /* We asked for retstat, so a StatInfo string MUST follow the 12-byte
     * ServerOpenBody. Enforcing it is the point of setting the bit: this is the
     * requirement that makes stock's libXrdSsi accept an SSI open at all, and a
     * server that answers without one would fail that client while quietly
     * satisfying a lenient one. */
    if (blen <= SSI_OPENBODY_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI open reply carries no StatInfo despite kXR_retstat "
                        "(%u bytes, need > %d)", blen, SSI_OPENBODY_LEN);
        free(body);
        return -1;
    }
    memcpy(s->fhandle, body, XRDC_FHANDLE_LEN);
    free(body);
    return 0;
}

int
brix_ssi_submit(brix_ssi_sess *s, const void *req_bytes, size_t len,
                brix_status *st)
{
    ClientWriteRequest req;
    uint16_t           sid = 0, status = 0;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    brix_resp_out      out = { &status, &body, &blen };
    int                saved, rc;

    if (len > BRIX_SSI_ID_MAX) {
        /* reqSize is a u32 on the wire, but a request that large is a caller
         * bug long before it is a wire limit; refuse rather than truncate. */
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI request too large (%zu bytes)", len);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_write);
    {
        xrdw_write_req_t w = {
            .offset = ssi_ctl_offset(BRIX_SSI_CMD_RXQ, s->req_id,
                                     (uint32_t) len),
            .pathid = 0
        };
        memcpy(w.fhandle, s->fhandle, XRDW_FHANDLE_LEN);
        xrdw_write_req_pack(&w, ((ClientRequestHdr *) &req)->body);
    }

    /* A deferring service answers kXR_waitresp here and then PUSHES its reply
     * frames. Without defer_surfaces, brix_recv would block and swallow the
     * first of them — an alert, whose tag the caller would never see. Scoped to
     * this one exchange: the conn is borrowed, and await() pulls the pushed
     * frames itself, so the flag has no business outliving the submit. */
    saved = s->conn->defer_surfaces;
    s->conn->defer_surfaces = 1;
    {
        brix_payload pl = { req_bytes, (uint32_t) len };
        rc = brix_send(s->conn, &req, &pl, &sid, st);
        if (rc == 0) {
            rc = brix_recv(s->conn, sid, &out, st);
        }
    }
    s->conn->defer_surfaces = saved;

    if (rc != 0) {
        return -1;
    }
    free(body);
    s->sid      = sid;
    s->deferred = (status == kXR_waitresp) ? 1 : 0;
    return 0;
}

int
brix_ssi_await(brix_ssi_sess *s, brix_ssi_reply *r, brix_status *st)
{
    uint8_t *body = NULL;
    uint32_t blen = 0;

    memset(r, 0, sizeof(*r));

    if (s->deferred) {
        uint16_t      status;
        brix_resp_out out = { &status, &body, &blen };
        if (brix_recv_next_asynresp(s->conn, s->sid, &out, st) != 0) {
            return -1;
        }
    } else if (ssi_query_ctl(s, BRIX_SSI_CMD_RWT, &body, &blen, st) != 0) {
        return -1;
    }

    if (ssi_reply_split(body, blen, r, st) != 0) {
        free(body);
        return -1;
    }
    if (r->ev == BRIX_SSI_EV_ALERT && ++s->alerts_seen > BRIX_SSI_ALERT_MAX) {
        brix_ssi_reply_free(r);
        brix_status_set(st, XRDC_EPROTO, 0,
                        "SSI service sent more than %d alerts without a response",
                        BRIX_SSI_ALERT_MAX);
        return -1;
    }
    return 0;
}

int
brix_ssi_read(brix_ssi_sess *s, void *buf, size_t len, brix_status *st)
{
    ClientReadRequest req;
    uint16_t          sid = 0, status = 0;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    brix_resp_out     out = { &status, &body, &blen };

    if (len > 0x7fffffffu) {
        brix_status_set(st, XRDC_EPROTO, 0, "SSI read too large (%zu)", len);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_read);
    {
        xrdw_read_req_t rr = {
            .offset = ssi_ctl_offset(BRIX_SSI_CMD_RXQ, s->req_id, 0),
            .rlen   = (int32_t) len
        };
        memcpy(rr.fhandle, s->fhandle, XRDW_FHANDLE_LEN);
        xrdw_read_req_pack(&rr, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_send(s->conn, &req, NULL, &sid, st) != 0) {
        return -1;
    }
    if (brix_recv(s->conn, sid, &out, st) != 0) {
        return -1;
    }
    /* The server clamps to what it has; clamp again so a buggy or hostile
     * server's over-long body cannot overrun the caller's buffer. */
    if (blen > len) {
        blen = (uint32_t) len;
    }
    if (blen > 0) {
        memcpy(buf, body, blen);
    }
    free(body);
    return (int) blen;
}

int
brix_ssi_cancel(brix_ssi_sess *s, brix_status *st)
{
    uint8_t *body = NULL;
    uint32_t blen = 0;

    if (ssi_query_ctl(s, BRIX_SSI_CMD_CAN, &body, &blen, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}

void
brix_ssi_close(brix_ssi_sess *s)
{
    brix_file   f;
    brix_status st;

    if (s == NULL || s->conn == NULL) {
        return;
    }
    memset(&f, 0, sizeof(f));
    memcpy(f.fhandle, s->fhandle, XRDC_FHANDLE_LEN);
    (void) brix_file_close(s->conn, &f, &st);
    s->conn = NULL;
}
