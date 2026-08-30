/*
 * sd_http_nearline.c — the nearline (tape/MSS) pair of the http origin driver:
 * residency (is this path online?) and recall (bring it online), spoken over the
 * WLCG Tape REST API.
 *
 * WHY THIS FILE EXISTS
 *   A WebDAV origin in front of an HSM is the storage shape most of WLCG
 *   actually runs, and until this file existed the http driver had neither
 *   nearline slot: brix_vfs_residency reported ONLINE for every path (its answer
 *   for a driver with no residency model), and the first read of a migrated file
 *   blocked a worker for the length of a tape mount instead of parking the open
 *   and answering "staging, retry later". The protocol planes above already know
 *   how to say that — HTTP 202 + Retry-After, S3 InvalidObjectState, root://
 *   kXR_offline — they just had nothing underneath to say it from.
 *
 * THE WIRE
 *   The WLCG Tape REST API is the one interoperable spelling of both halves, and
 *   it splits them exactly as this driver's slots do:
 *     POST {base}/archiveinfo  {"paths":["/k"]}      → [{"path":…,"locality":…}]
 *     POST {base}/stage        {"files":[{"path":"/k"}]} → 201 {"requestId":…}
 *   `archiveinfo` IS the residency slot: it reports locality without touching
 *   the tape system, which is the property the residency contract requires.
 *
 * OPT-IN, AND WHY IT MUST BE
 *   Neither slot is reachable unless the instance advertises
 *   BRIX_SD_CAP_NEARLINE, which brix_sd_http_create sets only when the operator
 *   configured a tape-API base. CAP_NEARLINE is a CONTRACT, not a hint:
 *   tier_build refuses to compose a nearline backend without a cache tier in
 *   front (the recall target, §9.4), so inferring it — from a 202, from a header,
 *   from anything — would turn working plain-http configs into startup failures.
 *
 * SHAPE
 *   Both slots issue ONE request through the shared no-failover namespace sender
 *   (sd_http_ns_send): a stage submission replayed against a second endpoint
 *   would queue the same tape work twice. Neither slot takes a credential — the
 *   vtable has no _cred twin for either — so both run as the instance identity,
 *   which is correct: a recall is the gateway's own housekeeping, driven by the
 *   cache tier on a miss, not an operation the end user names.
 */

#include "sd_http_internal.h"

#include "core/compat/json_min.h"    /* brix_json_get_str  */
#include "core/compat/json_iter.h"   /* brix_json_arr_next */

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* One request/reply pair here is a handful of short JSON objects. The reply is
 * only ever read through the bounded helpers below, so these caps bound the
 * COMPOSED buffers, not the origin's answer. */
#define SD_HTTP_TAPE_BODY_MAX   (SD_HTTP_PATH_MAX * 6 + 64)
#define SD_HTTP_TAPE_LOC_MAX    32


/*
 * WHAT: Write `in` as a complete JSON string literal (quotes included) into
 *       out[cap]. 0, or -1 on overflow.
 * WHY:  The key is the only caller-controlled text in either request body. A
 *       key containing a quote or a backslash would otherwise close the string
 *       early and let the rest of the path be read as JSON structure — a request
 *       for one path becoming a request for several, or a stage submission
 *       carrying fields the driver never wrote. This is an injection defence
 *       before it is an encoding.
 * HOW:  Escape the two characters JSON reserves and emit every control byte as
 *       \u00XX; everything else passes through as-is (a UTF-8 path stays UTF-8).
 *       Overflow is refused, never truncated — a truncated path names a
 *       DIFFERENT object.
 */
static int
sd_http_json_quote(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    size_t i;

    if (in == NULL || out == NULL || cap < 3) {
        return -1;
    }
    out[o++] = '"';
    for (i = 0; in[i] != '\0'; i++) {
        unsigned char c = (unsigned char) in[i];

        if (c == '"' || c == '\\') {
            if (o + 2 >= cap) {
                return -1;
            }
            out[o++] = '\\';
            out[o++] = (char) c;
        } else if (c < 0x20) {
            if (o + 6 >= cap) {
                return -1;
            }
            o += (size_t) snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            if (o + 1 >= cap) {
                return -1;
            }
            out[o++] = (char) c;
        }
    }
    if (o + 2 > cap) {
        return -1;
    }
    out[o++] = '"';
    out[o]   = '\0';
    return 0;
}


/*
 * WHAT: POST one JSON document to {tape_api}{suffix}; 0 with `resp` holding a
 *       reply the caller must resp_free, or -1 with errno set.
 * WHY:  residency and recall differ only in the suffix and the body; the header
 *       block, the identity and the no-failover rule belong to both.
 * HOW:  Through sd_http_ns_send, so this shares the mutation sender's endpoint-0
 *       pinning rather than opening a second wire path. The instance's static
 *       Authorization line rides along when one is configured.
 */
static int
sd_http_tape_post(sd_http_inst_state *is, const char *suffix, const char *body,
    brix_s3_resp_t *resp)
{
    sd_http_ns_req_t rq;
    char             path[SD_HTTP_PATH_MAX];
    char             hdrs[SD_HTTP_AUTH_MAX + 64];
    char             err[256];

    if (snprintf(path, sizeof(path), "%s%s", is->tape_api, suffix)
        >= (int) sizeof(path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    (void) snprintf(hdrs, sizeof(hdrs),
                    "Content-Type: application/json\r\n%s", is->auth_hdr);

    memset(&rq, 0, sizeof(rq));
    rq.method   = "POST";
    rq.path     = path;
    rq.hdrs     = hdrs;
    rq.body     = body;
    rq.body_len = strlen(body);

    err[0] = '\0';
    if (sd_http_ns_send(is, &rq, resp, err, sizeof(err)) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}


/*
 * WHAT: Map one Tape REST API locality token onto a residency class. 0 with
 *       *out set, or -1 with errno set.
 * WHY:  The mapping is the whole semantic content of the residency slot, and
 *       two of its cases are decisions rather than translations: DISK_AND_TAPE
 *       is ONLINE (the disk copy serves the read; the tape copy is irrelevant to
 *       a reader), and NONE is not a residency class at all but the API's way of
 *       saying the path is not in the namespace — reporting it as LOST would
 *       tell every plane above that a file had been DESTROYED because the origin
 *       merely does not have it.
 * HOW:  Exact token match; an unknown token is EIO, never a guess. A new
 *       locality this build has not seen must not be silently read as ONLINE —
 *       that would hand the caller a file the tape system never produced.
 */
static int
sd_http_locality(const char *loc, brix_sd_residency_t *out)
{
    if (strcmp(loc, "DISK") == 0 || strcmp(loc, "DISK_AND_TAPE") == 0) {
        *out = BRIX_SD_RES_ONLINE;
        return 0;
    }
    if (strcmp(loc, "TAPE") == 0) {
        *out = BRIX_SD_RES_NEARLINE;
        return 0;
    }
    if (strcmp(loc, "UNAVAILABLE") == 0) {
        *out = BRIX_SD_RES_OFFLINE;
        return 0;
    }
    if (strcmp(loc, "LOST") == 0) {
        *out = BRIX_SD_RES_LOST;
        return 0;
    }
    if (strcmp(loc, "NONE") == 0) {
        errno = ENOENT;
        return -1;
    }
    errno = EIO;
    return -1;
}


/*
 * WHAT: Pull the first element's `locality` out of an archiveinfo reply body.
 *       0 with *out set, or -1 with errno set.
 * WHY:  Kept separate from the request so the reply grammar — a top-level ARRAY
 *       whose first element describes the one path we asked about — is stated
 *       once, next to the mapping it feeds.
 * HOW:  brix_json_arr_next over the raw body (the span it wants is the array
 *       including its brackets, which is the whole document here), then one
 *       string lookup (brix_json_get_str answers 1 for "found and copied", not
 *       0 — the codec's convention, not errno's). An empty array is ENOENT: the
 *       API answered, and its answer contains nothing about our path.
 */
static int
sd_http_archiveinfo_parse(const char *body, size_t len,
    brix_sd_residency_t *out)
{
    const char *elem;
    size_t      elemlen;
    size_t      cursor = 0;
    char        loc[SD_HTTP_TAPE_LOC_MAX];

    if (body == NULL || len == 0) {
        errno = EIO;
        return -1;
    }
    if (brix_json_arr_next(body, len, &cursor, &elem, &elemlen) != 1) {
        errno = ENOENT;
        return -1;
    }
    if (brix_json_get_str(elem, elemlen, "locality", loc, sizeof(loc)) != 1) {
        errno = EIO;
        return -1;
    }
    return sd_http_locality(loc, out);
}


/* sd_http_residency — vtable residency slot: classify `key` WITHOUT staging it.
 *
 * WHAT: NGX_OK with *out set, or NGX_ERROR with errno (ENOENT for a path the
 *       origin does not hold, EIO for an answer this build cannot read).
 * WHY:  Every protocol plane advertises tape state from this seam, and all of
 *       them must be able to say "on tape" without triggering a recall — which
 *       is exactly what `archiveinfo` is for.
 * HOW:  One POST, one JSON array read. Any non-200 is mapped by the shared
 *       WebDAV status verdict so a 401 here reads as EACCES exactly as it does
 *       on every other slot of this driver.
 */
ngx_int_t
sd_http_residency(brix_sd_instance_t *inst, const char *key,
    brix_sd_residency_t *out)
{
    sd_http_inst_state *is;
    brix_s3_resp_t      resp;
    char                quoted[SD_HTTP_PATH_MAX + 8];
    char                body[SD_HTTP_TAPE_BODY_MAX];
    const void         *rb;
    size_t              rblen = 0;
    int                 rc;

    if (inst == NULL || inst->state == NULL || key == NULL || out == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    is = inst->state;
    if (is->tape_api[0] == '\0') {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (sd_http_json_quote(key, quoted, sizeof(quoted)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    (void) snprintf(body, sizeof(body), "{\"paths\":[%s]}", quoted);

    memset(&resp, 0, sizeof(resp));
    if (sd_http_tape_post(is, "/archiveinfo", body, &resp) != 0) {
        return NGX_ERROR;
    }
    if (resp.status != 200) {
        errno = sd_http_status_to_errno(resp.status);
        is->transport->resp_free(&resp);
        return NGX_ERROR;
    }
    rb = is->transport->resp_body(&resp, &rblen);
    rc = sd_http_archiveinfo_parse(rb, rblen, out);
    if (rc != 0) {
        int e = errno;

        is->transport->resp_free(&resp);
        errno = e;
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}


/*
 * WHAT: Submit the stage request for `key` and copy the origin's request id (or
 *       leave "" when it returned none).
 * WHY:  Split from the slot so recall's DECISION table — which residency classes
 *       stage, which do not — reads as one uninterrupted piece.
 * HOW:  201 is the specified success; 200 and 202 are accepted too, because an
 *       implementation that queues and answers 202 has done precisely what was
 *       asked. The id is advisory: a stage that was accepted without one is
 *       still queued, so a missing `requestId` is not an error.
 */
static void
sd_http_tape_stage(sd_http_inst_state *is, const char *quoted,
    char reqid_out[40])
{
    brix_s3_resp_t resp;
    char           body[SD_HTTP_TAPE_BODY_MAX];
    const void    *rb;
    size_t         rblen = 0;

    (void) snprintf(body, sizeof(body), "{\"files\":[{\"path\":%s}]}", quoted);

    memset(&resp, 0, sizeof(resp));
    if (sd_http_tape_post(is, "/stage", body, &resp) != 0) {
        return;
    }
    if (resp.status == 200 || resp.status == 201 || resp.status == 202) {
        rb = is->transport->resp_body(&resp, &rblen);
        if (rb != NULL && rblen > 0) {
            (void) brix_json_get_str(rb, rblen, "requestId", reqid_out, 40);
        }
    }
    is->transport->resp_free(&resp);
}


/* sd_http_recall — vtable recall slot: bring `key` online, without blocking.
 *
 * WHAT: NGX_OK (already online — a normal cache fill follows), NGX_AGAIN
 *       (staging in flight; reqid_out carries the origin's request id, "" if it
 *       gave none), or NGX_ERROR with errno set.
 * WHY:  This is the verb sd_cache drives on every nearline miss. Returning
 *       NGX_AGAIN instead of stalling is the whole point: the open fails soft
 *       with EAGAIN and the plane above answers "staging, retry later" rather
 *       than holding a worker for the length of a tape mount.
 * HOW:  Residency first — asking the tape system to stage a file that is already
 *       on disk queues pointless MSS work on every cache miss of a resident file.
 *       Then, by class: ONLINE is done; NEARLINE stages, and a stage is ALWAYS
 *       NGX_AGAIN because the API is asynchronous by definition — a successful
 *       submit means "queued", never "done", and a failed submit is still
 *       "retry later" for an object that is genuinely not on disk either way;
 *       UNAVAILABLE is NGX_AGAIN with no id, which is what "temporarily
 *       unavailable" means to a client; LOST is a hard ENOENT, because no amount
 *       of retrying will produce a file the tape system has declared destroyed,
 *       and telling the client to keep waiting for it would be a lie.
 */
ngx_int_t
sd_http_recall(brix_sd_instance_t *inst, const char *key, char reqid_out[40])
{
    sd_http_inst_state *is;
    brix_sd_residency_t res;
    char                quoted[SD_HTTP_PATH_MAX + 8];

    if (reqid_out != NULL) {
        reqid_out[0] = '\0';
    }
    if (sd_http_residency(inst, key, &res) != NGX_OK) {
        return NGX_ERROR;              /* errno already set (ENOENT/EACCES/…) */
    }
    if (res == BRIX_SD_RES_ONLINE) {
        return NGX_OK;                 /* resident — a normal fill follows */
    }
    if (res == BRIX_SD_RES_LOST) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    if (res == BRIX_SD_RES_OFFLINE) {
        return NGX_AGAIN;              /* no request to park on; retry later */
    }

    is = inst->state;
    if (sd_http_json_quote(key, quoted, sizeof(quoted)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    if (reqid_out != NULL) {
        sd_http_tape_stage(is, quoted, reqid_out);
    }
    return NGX_AGAIN;                  /* queued — park the open on reqid */
}


/*
 * WHAT: 1 iff `c` may appear in the operator's Tape REST API base path.
 * WHY:  The base is concatenated into a request line, so it must BE a path and
 *       nothing else: a stray CR/LF would split the request, and a '?' or '#'
 *       would make "/archiveinfo" part of a query or fragment rather than the
 *       endpoint we meant to address. Refusing the whole base on one bad byte
 *       (the caller leaves the instance un-armed, and the export keeps working
 *       as plain http) is the only safe answer — sanitising it would silently
 *       produce a base the operator never wrote and cannot see in the config.
 * HOW:  RFC 3986's unreserved set plus '/', which is every byte a path segment
 *       needs and nothing that can change what the request line means.
 */
static int
sd_http_path_byte_ok(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || strchr("/._~-", c) != NULL;
}


/*
 * WHAT: Record the operator's Tape REST API base on the instance; 1 when the
 *       instance is armed for nearline, 0 when it is not.
 * WHY:  The caps bit is a contract the composing registry enforces, so the ONE
 *       condition that sets it belongs beside the code that uses the base — not
 *       spelled out again in the driver's create path where it could drift from
 *       what the path composer actually accepts.
 * HOW:  A base must be absolute (the composer concatenates it with "/stage")
 *       and every byte must pass sd_http_path_byte_ok; a relative or empty
 *       base leaves the instance un-armed rather than building request paths
 *       that would resolve against the export root. A trailing slash is dropped
 *       so the composed path never doubles it.
 */
int
sd_http_tape_init(sd_http_inst_state *is, const char *base)
{
    size_t n;
    size_t i;

    if (base == NULL || base[0] != '/') {
        return 0;
    }
    n = strlen(base);
    for (i = 0; i < n; i++) {
        if (!sd_http_path_byte_ok((unsigned char) base[i])) {
            return 0;
        }
    }
    while (n > 1 && base[n - 1] == '/') {
        n--;
    }
    if (n < 2 || n >= sizeof(is->tape_api)) {
        return 0;
    }
    memcpy(is->tape_api, base, n);
    is->tape_api[n] = '\0';
    return 1;
}
