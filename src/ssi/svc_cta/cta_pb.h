#ifndef XROOTD_SSI_CTA_PB_H
#define XROOTD_SSI_CTA_PB_H

/*
 * cta_pb.h — CTA SSI message codec (decode cta.xrd.Request, encode
 * cta.xrd.Response / StreamResponse).
 *
 * WHAT: message-specific protobuf decode/encode for exactly the fields the CTA
 *       tape service exchanges, built on the generic pb_wire primitives.
 * WHY:  byte-compatible interop with a real CTA/EOS frontend without protobuf-c
 *       or generated code.
 * HOW:  the CTA field numbers are pinned in cta_pb.c (the entire external-contract
 *       surface), sourced from the real .proto in CERN's
 *       eos/xrootd-ssi-protobuf-interface (cta_frontend.proto / cta_eos.proto /
 *       cta_common.proto). See svc_cta/README.md for provenance.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CTA_OP_ARCHIVE,    /* Workflow.event == CLOSEW (4) */
    CTA_OP_RETRIEVE,   /* Workflow.event == PREPARE (6) */
    CTA_OP_CANCEL,     /* Workflow.event == ABORT_PREPARE (8) */
    CTA_OP_QUERY,      /* Request.admincmd present */
    CTA_OP_UNKNOWN
} cta_op_t;

typedef struct {
    cta_op_t op;
    char     instance[64];     /* Workflow.instance.name (cta.common.Service.name) */
    char     path[1024];       /* Notification.file.lpath (cta.eos.Metadata.lpath) */
    char     request_id[256];  /* Notification.file.request_objectstore_id (999) */
    uint64_t archive_id;       /* Notification.file.archive_file_id */
    char     owner_user[64];   /* Notification.cli.user.username */
    char     owner_group[64];  /* Notification.cli.user.groupname */
} cta_request_t;

/* Decode a cta.xrd.Request. Returns 0 on success (out zero-initialised then
 * filled; unknown fields skipped), -1 on malformed input. */
int cta_pb_decode_request(const unsigned char *buf, size_t len,
                          cta_request_t *out);

/* cta.xrd.Response.ResponseType */
typedef enum {
    CTA_RSP_INVALID      = 0,
    CTA_RSP_SUCCESS      = 1,
    CTA_RSP_ERR_PROTOBUF = 2,
    CTA_RSP_ERR_CTA      = 3,
    CTA_RSP_ERR_USER     = 4
} cta_rsp_type_t;

/* Encode a cta.xrd.Response (type + optional message_txt + optional
 * archive_file_id, archive_id==0 omits the field). Writes into out[cap]; sets
 * *out_len. Returns 0 on success, -1 on overflow. */
int cta_pb_encode_response(cta_rsp_type_t type, const char *message_txt,
                           uint64_t archive_id,
                           unsigned char *out, size_t cap, size_t *out_len);

/* Wrap an already-encoded cta.xrd.Response as a cta.xrd.StreamResponse.header
 * (field 1). Used to head a streamed admin listing. Returns 0 / -1. */
int cta_pb_encode_stream_header(const unsigned char *response, size_t response_len,
                                unsigned char *out, size_t cap, size_t *out_len);

#endif /* XROOTD_SSI_CTA_PB_H */
