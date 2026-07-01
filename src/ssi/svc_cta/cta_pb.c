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

/* cta.common.Service{ name=1 } → out->instance */
static int
decode_service(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (f == F_SERVICE_NAME && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            copy_str(out->instance, sizeof(out->instance), d, n);
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

/* cta.eos.Workflow{ event=1, instance=5 } → out->op, out->instance */
static int
decode_workflow(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (f == F_WF_EVENT && wt == PB_WT_VARINT) {
            uint64_t ev;
            if (pb_read_varint(r, &ev) != 0) {
                return -1;
            }
            out->op = ev == EV_CLOSEW        ? CTA_OP_ARCHIVE
                    : ev == EV_PREPARE       ? CTA_OP_RETRIEVE
                    : ev == EV_ABORT_PREPARE ? CTA_OP_CANCEL
                                             : CTA_OP_UNKNOWN;
        } else if (f == F_WF_INSTANCE && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n; pb_reader sub;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            sub.p = d; sub.end = d + n;
            if (decode_service(&sub, out) != 0) {
                return -1;
            }
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

/* cta.common.RequesterId{ username=1, groupname=2 } → owner_user/group */
static int
decode_requester(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (wt == PB_WT_LEN && (f == F_REQUESTER_USERNAME ||
                                f == F_REQUESTER_GROUPNAME)) {
            const unsigned char *d; size_t n;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            if (f == F_REQUESTER_USERNAME) {
                copy_str(out->owner_user, sizeof(out->owner_user), d, n);
            } else {
                copy_str(out->owner_group, sizeof(out->owner_group), d, n);
            }
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

/* cta.eos.Client{ user=1 } → RequesterId */
static int
decode_client(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (f == F_CLIENT_USER && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n; pb_reader sub;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            sub.p = d; sub.end = d + n;
            if (decode_requester(&sub, out) != 0) {
                return -1;
            }
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

/* cta.eos.Metadata{ lpath=11, archive_file_id=15, request_objectstore_id=999 } */
static int
decode_metadata(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (f == F_META_LPATH && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            copy_str(out->path, sizeof(out->path), d, n);
        } else if (f == F_META_REQUEST_ID && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            copy_str(out->request_id, sizeof(out->request_id), d, n);
        } else if (f == F_META_ARCHIVE_ID && wt == PB_WT_VARINT) {
            if (pb_read_varint(r, &out->archive_id) != 0) {
                return -1;
            }
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

/* cta.eos.Notification{ wf=1, cli=2, file=4 } */
static int
decode_notification(pb_reader *r, cta_request_t *out)
{
    uint32_t f; int wt;

    while (r->p < r->end) {
        if (pb_read_tag(r, &f, &wt) != 0) {
            return -1;
        }
        if (wt == PB_WT_LEN && (f == F_NOTIF_WF || f == F_NOTIF_CLI ||
                                f == F_NOTIF_FILE)) {
            const unsigned char *d; size_t n; pb_reader sub;
            int rc;
            if (pb_read_len_delim(r, &d, &n) != 0) {
                return -1;
            }
            sub.p = d; sub.end = d + n;
            rc = f == F_NOTIF_WF  ? decode_workflow(&sub, out)
               : f == F_NOTIF_CLI ? decode_client(&sub, out)
                                  : decode_metadata(&sub, out);
            if (rc != 0) {
                return -1;
            }
        } else if (pb_skip_field(r, wt) != 0) {
            return -1;
        }
    }
    return 0;
}

int
cta_pb_decode_request(const unsigned char *buf, size_t len, cta_request_t *out)
{
    pb_reader r;
    uint32_t  f;
    int       wt;

    memset(out, 0, sizeof(*out));
    out->op = CTA_OP_UNKNOWN;
    r.p = buf; r.end = buf + len;

    while (r.p < r.end) {
        if (pb_read_tag(&r, &f, &wt) != 0) {
            return -1;
        }
        if (f == F_REQ_NOTIFICATION && wt == PB_WT_LEN) {
            const unsigned char *d; size_t n; pb_reader sub;
            if (pb_read_len_delim(&r, &d, &n) != 0) {
                return -1;
            }
            sub.p = d; sub.end = d + n;
            if (decode_notification(&sub, out) != 0) {
                return -1;
            }
        } else if (f == F_REQ_ADMINCMD && wt == PB_WT_LEN) {
            /* Admin command (query/listing). The full AdminCmd parse is deferred;
             * for routing it is enough to mark the op. */
            const unsigned char *d; size_t n;
            if (pb_read_len_delim(&r, &d, &n) != 0) {
                return -1;
            }
            out->op = CTA_OP_QUERY;
        } else if (pb_skip_field(&r, wt) != 0) {
            return -1;
        }
    }
    return 0;
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
