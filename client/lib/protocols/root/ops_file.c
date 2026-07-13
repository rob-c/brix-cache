/*
 * ops_file.c - (kept) routing + shared helpers
 * Phase-38 split of ops_file.c; behavior-identical.
 */
#include "ops_internal.h"

int
brix_file_open_read(brix_conn *c, const char *path, brix_file *f, brix_status *st)
{
    return brix_file_open_opaque(c, path, NULL, 0, 0, 0, f, st);
}


int
brix_file_open_write(brix_conn *c, const char *path, int force, int posc,
                     brix_file *f, brix_status *st)
{
    return brix_file_open_opaque(c, path, NULL, 1, force, posc, f, st);
}


int
brix_file_open_update(brix_conn *c, const char *path, int posc,
                      brix_file *f, brix_status *st)
{
    /* force==2: open an EXISTING file for read+write IN PLACE (no truncate, no
     * create) — kXR_open_updt only. Enables random writes over existing content. */
    return brix_file_open_opaque(c, path, NULL, 1, 2, posc, f, st);
}


int
brix_file_close(brix_conn *c, brix_file *f, brix_status *st)
{
    ClientCloseRequest req;
    uint16_t           sid, status;
    uint8_t           *body = NULL;
    uint32_t           blen = 0;
    brix_resp_out      out = { &status, &body, &blen };

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_close);
    {
        xrdw_close_req_t b;
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_close_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_send(c, &req, NULL, &sid, st) != 0) {
        return -1;
    }
    if (brix_recv(c, sid, &out, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}


/* TPC helpers (M8): open-with-opaque + sync (arm/trigger) */
int
brix_file_open_opaque(brix_conn *c, const char *path, const char *opaque,
                      int write, int force, int posc, brix_file *f,
                      brix_status *st)
{
    ClientOpenRequest req;
    uint16_t          status, options;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    char             *payload;
    size_t            need;
    int               plen;

    /* kXR_open option bits come from the shared builder (protocol/open_flags.h)
     * so this request and the server's POSIX-flag decode share one definition of
     * the create/truncate/in-place (`force`) semantics. Writes always make parent
     * dirs (mkpath). */
    options = brix_open_options_build(write, force, posc, /*mkpath=*/1);

    /* The server splits "<path>?<opaque>" — open_extract_opaque (src/protocols/root/read).
     * Heap-size to the actual lengths; no opaque ⇒ bare path (open_read/write). */
    need = strlen(path) + 1 + (opaque ? strlen(opaque) : 0) + 1;
    payload = (char *) malloc(need);
    if (payload == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return -1;
    }
    plen = (opaque != NULL && opaque[0] != '\0')
           ? snprintf(payload, need, "%s?%s", path, opaque)
           : snprintf(payload, need, "%s", path);

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_open);
    /* Marshal the fixed body (mode/options/optiont/fhtemplt) through the shared
     * codec so the client and server agree on the offsets + byte order. */
    {
        xrdw_open_req_t o = { .mode = (uint16_t) (write ? 0644 : 0),
                              .options = options, .optiont = 0 };
        xrdw_open_req_pack(&o, ((ClientRequestHdr *) &req)->body);
    }

    {
        brix_payload  pl  = { payload, (uint32_t) plen };
        brix_resp_out out = { &status, &body, &blen };
        if (brix_roundtrip(c, &req, &pl, &out, st) != 0) {
            free(payload);
            return -1;
        }
    }
    free(payload);

    /* TPC coordinator open deferred: brix_recv surfaced the source's kXR_waitresp
     * (rendezvous key registered, real reply pending) instead of blocking. There is
     * no fhandle yet — the orchestrator never does I/O on this handle (the dest pulls
     * the bytes); it only keeps the connection open so the registration stays live,
     * then drains the deferred reply once the pull is triggered. Report success. */
    if (c->tpc_coord_defer && status == kXR_waitresp) {
        memset(f->fhandle, 0, XRD_FHANDLE_LEN);
        f->read_codec = 0;
        f->write_codec = 0;
        free(body);                              /* NULL on the deferred path */
        return 0;
    }

    if (blen < XRD_FHANDLE_LEN) {
        brix_status_set(st, XRDC_EPROTO, 0, "open reply too short (%u bytes)", blen);
        free(body);
        return -1;
    }
    memcpy(f->fhandle, body, XRD_FHANDLE_LEN);

    /*
     * phase-42 W4/W5 — inline read/write compression.  The ServerOpenBody is
     * fhandle[4] cpsize[4] cptype[4]; a server that confirmed compression sets
     * BOTH cpsize = BRIX_INLINE_CMP_MAGIC (big-endian) AND cptype[0] = codec
     * ordinal (the dual-check contract in codec_core.h).  Require the cpsize magic
     * before trusting cptype[0]: cptype is a legacy XRootD field, so a stock or
     * non-cooperating server may place an arbitrary small byte there — adopting it
     * without the magic would make us inflate PLAINTEXT responses and corrupt the
     * transfer.  Both halves must agree, else fall back to plaintext.
     */
    f->read_codec = 0;
    f->write_codec = 0;
    if (blen >= 12) {
        uint32_t cpsize = ((uint32_t) body[4] << 24) | ((uint32_t) body[5] << 16)
                        | ((uint32_t) body[6] << 8)  |  (uint32_t) body[7];
        uint8_t  cid    = body[8];   /* cptype[0] */
        if (cpsize == BRIX_INLINE_CMP_MAGIC && cid >= 1 && cid < BRIX_CODEC_MAX) {
            /* The server CONFIRMED inline compression with codec `cid` and WILL
             * send compressed frames (read) or expect them (write).  If this
             * client build cannot handle that codec we must FAIL the open: silently
             * falling back to the plaintext branch would copy the still-compressed
             * bytes verbatim and corrupt the transfer (asymmetric build). */
            if (!brix_codec_available(cid)) {
                brix_status_set(st, XRDC_EUNSUPPORTED, 0,
                    "server negotiated inline-compression codec %u that this "
                    "client build cannot decode", (unsigned) cid);
                free(body);
                return -1;
            }
            /* W4 read opens compress responses; W5 write opens compress the
             * payloads this client sends.  At most one direction is negotiated. */
            if (write) {
                f->write_codec = cid;
            } else {
                f->read_codec = cid;
            }
        }
    }

    free(body);
    return 0;
}


int
brix_file_sync(brix_conn *c, brix_file *f, brix_status *st)
{
    ClientSyncRequest req;
    uint16_t          sid, status;
    uint8_t          *body = NULL;
    uint32_t          blen = 0;
    brix_resp_out     out = { &status, &body, &blen };

    memset(&req, 0, sizeof(req));
    req.requestid = htons(kXR_sync);
    {
        xrdw_sync_req_t b;
        memcpy(b.fhandle, f->fhandle, XRD_FHANDLE_LEN);
        xrdw_sync_req_pack(&b, ((ClientRequestHdr *) &req)->body);
    }

    if (brix_send(c, &req, NULL, &sid, st) != 0) {
        return -1;
    }
    if (brix_recv(c, sid, &out, st) != 0) {
        return -1;
    }
    free(body);
    return 0;
}
