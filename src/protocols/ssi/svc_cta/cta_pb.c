/*
 * cta_pb.c — CTA SSI message codec. See cta_pb.h.
 *
 * ==========================================================================
 * PINNED CTA FIELD-NUMBER TABLE — the entire external-contract surface.
 * Sourced from CERN eos/xrootd-ssi-protobuf-interface (eos_cta/protobuf/):
 *   cta_frontend.proto, cta_eos.proto, cta_common.proto.
 * Re-verify these (and re-capture golden vectors) when CTA's schema bumps.
 * ==========================================================================
 *   cta.xrd.Request           field 1  notification   (cta.eos.Notification)
 *                             field 2  admincmd       (cta.admin.AdminCmd)
 *   cta.eos.Notification      field 1  wf             (Workflow)
 *                             field 2  cli            (Client)
 *                             field 4  file           (Metadata)
 *   cta.eos.Workflow          field 1  event          (EventType varint)
 *                             field 5  instance       (cta.common.Service)
 *     EventType: CLOSEW=4, PREPARE=6, ABORT_PREPARE=8
 *   cta.eos.Client            field 1  user           (cta.common.RequesterId)
 *   cta.eos.Metadata          field 11 lpath          (string)
 *                             field 15 archive_file_id(uint64)
 *                             field 999 request_objectstore_id (string)
 *   cta.common.Service        field 1  name           (string)
 *   cta.common.RequesterId    field 1  username       (string)
 *                             field 2  groupname      (string)
 *   cta.xrd.Response          field 1  type           (ResponseType varint)
 *                             field 3  message_txt    (string)
 *                             field 5  archive_file_id(string)
 *   cta.xrd.StreamResponse    field 1  header         (cta.xrd.Response)
 * ==========================================================================
 */

#include "cta_pb.h"
#include "pb_wire.h"
#include <string.h>

/* CTA field numbers (see the pinned table above). */
#define F_REQ_NOTIFICATION   1
#define F_REQ_ADMINCMD       2
#define F_NOTIF_WF           1
#define F_NOTIF_CLI          2
#define F_NOTIF_FILE         4
#define F_WF_EVENT           1
#define F_WF_INSTANCE        5
#define F_CLIENT_USER        1
#define F_META_LPATH         11
#define F_META_ARCHIVE_ID    15
#define F_META_REQUEST_ID    999
#define F_SERVICE_NAME       1
#define F_REQUESTER_USERNAME 1
#define F_REQUESTER_GROUPNAME 2
#define F_RSP_TYPE           1
#define F_RSP_MESSAGE_TXT    3
#define F_RSP_ARCHIVE_ID     5
#define F_STREAM_HEADER      1

/* cta.eos.Workflow.EventType values we act on. */
#define EV_CLOSEW        4
#define EV_PREPARE       6
#define EV_ABORT_PREPARE 8

/* Copy a length-delimited protobuf string into a fixed buffer (truncate, NUL). */
static void
copy_str(char *dst, size_t dst_sz, const unsigned char *src, size_t n)
{
    if (n >= dst_sz) {
        n = dst_sz - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ---- table-driven request decoder ---------------------------------------
 * Every message in the pinned table is the same flat shape — match a field
 * number, else skip — so a single generic loop walks one row table; the
 * per-message differences live entirely in pbf_rows[]. */

typedef enum {
    PBF_STR,     /* LEN    → copy_str into the cta_request_t buffer at off */
    PBF_MSG,     /* LEN    → recurse into the rows of message `sub`        */
    PBF_U64,     /* VARINT → raw value into the uint64_t at off            */
    PBF_EVENT,   /* VARINT → map cta.eos.Workflow.EventType onto out->op   */
    PBF_QUERY,   /* LEN    → consume; mark the request as CTA_OP_QUERY     */
} pbf_kind_t;

enum {
    M_REQUEST, M_NOTIF, M_WF, M_CLIENT, M_META, M_SERVICE, M_REQUESTER,
};

static const struct {
    unsigned char msg;     /* message this row belongs to (M_*)     */
    uint32_t      field;   /* CTA field number                      */
    pbf_kind_t    kind;
    size_t        off;     /* PBF_STR / PBF_U64 destination         */
    size_t        sz;      /* PBF_STR destination capacity          */
    unsigned char sub;     /* PBF_MSG nested message id (M_*)       */
} pbf_rows[] = {

#define PBF_STR_ROW(m, fld, member) \
    { m, fld, PBF_STR, offsetof(cta_request_t, member), \
      sizeof(((cta_request_t *) 0)->member), 0 }

    { M_REQUEST,   F_REQ_NOTIFICATION, PBF_MSG,   0, 0, M_NOTIF },
    { M_REQUEST,   F_REQ_ADMINCMD,     PBF_QUERY, 0, 0, 0 },
    { M_NOTIF,     F_NOTIF_WF,         PBF_MSG,   0, 0, M_WF },
    { M_NOTIF,     F_NOTIF_CLI,        PBF_MSG,   0, 0, M_CLIENT },
    { M_NOTIF,     F_NOTIF_FILE,       PBF_MSG,   0, 0, M_META },
    { M_WF,        F_WF_EVENT,         PBF_EVENT, 0, 0, 0 },
    { M_WF,        F_WF_INSTANCE,      PBF_MSG,   0, 0, M_SERVICE },
    { M_CLIENT,    F_CLIENT_USER,      PBF_MSG,   0, 0, M_REQUESTER },
    PBF_STR_ROW(M_META,      F_META_LPATH,          path),
    PBF_STR_ROW(M_META,      F_META_REQUEST_ID,     request_id),
    { M_META,      F_META_ARCHIVE_ID,  PBF_U64,
      offsetof(cta_request_t, archive_id), 0, 0 },
    PBF_STR_ROW(M_SERVICE,   F_SERVICE_NAME,        instance),
    PBF_STR_ROW(M_REQUESTER, F_REQUESTER_USERNAME,  owner_user),
    PBF_STR_ROW(M_REQUESTER, F_REQUESTER_GROUPNAME, owner_group),
};

#define PBF_NROWS (sizeof(pbf_rows) / sizeof(pbf_rows[0]))

static int decode_msg(pb_reader *r, unsigned char msg, cta_request_t *out);

/* Wire type a row's kind expects on the wire. */
static int
pbf_wire_type(pbf_kind_t kind)
{
    return (kind == PBF_U64 || kind == PBF_EVENT) ? PB_WT_VARINT : PB_WT_LEN;
}

/* Consume the value of matched row `i` from the reader into `out`. */
static int
decode_field(pb_reader *r, size_t i, cta_request_t *out)
{
    const unsigned char *d;
    size_t               n;
    uint64_t             ev;
    pb_reader            sub;

    switch (pbf_rows[i].kind) {

    case PBF_EVENT:
        if (pb_read_varint(r, &ev) != 0) {
            return -1;
        }
        out->op = ev == EV_CLOSEW        ? CTA_OP_ARCHIVE
                : ev == EV_PREPARE       ? CTA_OP_RETRIEVE
                : ev == EV_ABORT_PREPARE ? CTA_OP_CANCEL
                                         : CTA_OP_UNKNOWN;
        return 0;

    case PBF_U64:
        return pb_read_varint(r,
            (uint64_t *) ((char *) out + pbf_rows[i].off));

    default:
        break;
    }

    if (pb_read_len_delim(r, &d, &n) != 0) {
        return -1;
    }

    switch (pbf_rows[i].kind) {

    case PBF_STR:
        copy_str((char *) out + pbf_rows[i].off, pbf_rows[i].sz, d, n);
        return 0;

    case PBF_MSG:
        sub.p = d; sub.end = d + n;
        return decode_msg(&sub, pbf_rows[i].sub, out);

    default:
        /* PBF_QUERY — admin command (query/listing). The full AdminCmd parse
         * is deferred; for routing it is enough to mark the op. */
        out->op = CTA_OP_QUERY;
        return 0;
    }
}

/* Decode message `msg` (M_*): dispatch known fields, skip the rest. */
static int
decode_msg(pb_reader *r, unsigned char msg, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        size_t i;

        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        for (i = 0; i < PBF_NROWS; i++) {
            if (pbf_rows[i].msg == msg && pbf_rows[i].field == f
                && wt == pbf_wire_type(pbf_rows[i].kind))
            {
                break;
            }
        }
        if (i == PBF_NROWS) {
            if (pb_skip_field(r, wt) != 0) {
                return -1;
            }
        } else if (decode_field(r, i, out) != 0) {
            return -1;
        }
    }
    return 0;
}

int
cta_pb_decode_request(const unsigned char *buf, size_t len, cta_request_t *out)
{
    pb_reader r;

    memset(out, 0, sizeof(*out));
    out->op = CTA_OP_UNKNOWN;
    r.p = buf; r.end = buf + len;
    return decode_msg(&r, M_REQUEST, out);
}

int
cta_pb_encode_response(cta_rsp_type_t type, const char *message_txt,
                       uint64_t archive_id,
                       unsigned char *out, size_t cap, size_t *out_len)
{
    pb_writer w = { out, 0, cap };

    if (pb_write_varint_field(&w, F_RSP_TYPE, (uint64_t) type) != 0) {
        return -1;
    }
    if (message_txt != NULL && message_txt[0] != '\0') {
        if (pb_write_string(&w, F_RSP_MESSAGE_TXT, message_txt) != 0) {
            return -1;
        }
    }
    if (archive_id != 0) {
        /* Response.archive_file_id is a string xattr; render the number. */
        char idbuf[24];
        int  m = 0;
        uint64_t v = archive_id;
        char rev[24];
        int  k = 0;
        while (v > 0) { rev[k++] = (char) ('0' + (v % 10)); v /= 10; }
        while (k > 0) { idbuf[m++] = rev[--k]; }
        idbuf[m] = '\0';
        if (pb_write_string(&w, F_RSP_ARCHIVE_ID, idbuf) != 0) {
            return -1;
        }
    }
    *out_len = w.len;
    return 0;
}

int
cta_pb_encode_stream_header(const unsigned char *response, size_t response_len,
                            unsigned char *out, size_t cap, size_t *out_len)
{
    pb_writer w = { out, 0, cap };

    if (pb_write_len_delim(&w, F_STREAM_HEADER, response, response_len) != 0) {
        return -1;
    }
    *out_len = w.len;
    return 0;
}
