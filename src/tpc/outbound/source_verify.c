/* File: source_verify.c — TPC remote source metadata and integrity, split from
 * source_stream.c when that file crossed the 600-line cap (coding-standards §1).
 * WHAT: tpc_stat_source() kXR_stats the origin by path to capture the pull's
 * authoritative size target, and tpc_verify_source_checksum() runs the opt-in
 * post-copy integrity check — kXR_query(kXR_Qcksum) against the origin, hashed
 * locally with the SAME algorithm the origin named, then compared.
 * WHY: "how many bytes, and are they the right ones" is a different concern
 * from "move the bytes" (source_stream.c), and it is the concern a reviewer
 * auditing integrity wants to read on its own.  HOW: every parsing helper is
 * file-static; only tpc_stat_source() and tpc_verify_source_checksum() cross
 * the file boundary, exactly as source_internal.h already declares them. */

#include "tpc/engine/tpc_internal.h"
#include "core/compat/checksum.h"                /* hex_name_fd / hex_obj — dst-side verify */
#include "source_internal.h"


#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp — case-insensitive hex compare */
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>


/*
 * tpc_stat_parse_size — WHAT: read the size (2nd whitespace token) out of an
 * XRootD kXR_stat reply body "id size flags mtime". WHY: the size is the pull's
 * authoritative completion target; the surrounding tokens are irrelevant here.
 * HOW: skip token 0 (id), then strtoull the leading digits of token 1. Returns 0
 * with *size set, or -1 if there is no numeric second token.
 */
static int
tpc_stat_parse_size(const char *body, uint64_t *size)
{
    const char         *p = body;
    char               *end;
    unsigned long long  v;

    while (*p == ' ') {
        p++;
    }
    while (*p != '\0' && *p != ' ') {           /* skip token 0 (id) */
        p++;
    }
    while (*p == ' ') {
        p++;
    }
    if (*p < '0' || *p > '9') {
        return -1;
    }
    errno = 0;
    v = strtoull(p, &end, 10);
    if (end == p || errno != 0) {
        return -1;
    }
    *size = (uint64_t) v;
    return 0;
}

/*
 * tpc_stat_source — kXR_stat the remote source by path to capture its
 * authoritative size (the pull's real completion signal). See source_internal.h.
 * A distinct streamid tag (4) separates the reply from open(2)/read(3)/close(2).
 * A source that errors the stat, or returns an unparseable body, leaves
 * src_size_known=0 — only a socket/framing failure aborts the pull here.
 */
int
tpc_stat_source(brix_tpc_pull_t *t, int fd)
{
    u_char             req[sizeof(ClientStatRequest) + PATH_MAX];
    ClientStatRequest  streq;
    size_t             pathlen = strlen(t->src_path);
    size_t             total   = sizeof(ClientStatRequest) + pathlen;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body = NULL;

    t->src_size       = 0;
    t->src_size_known = 0;

    if (total > sizeof(req)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC src path too long for stat");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    ngx_memzero(&streq, sizeof(streq));
    streq.streamid[1] = 4;                       /* distinct tag: stat replies */
    streq.requestid   = htons(kXR_stat);
    streq.dlen        = htonl((kXR_int32) pathlen);
    ngx_memcpy(req, &streq, sizeof(streq));
    ngx_memcpy(req + sizeof(streq), t->src_path, pathlen);

    if (tpc_send_all(t, fd, req, total) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_stat send failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_stat recv failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }

    if (status == kXR_ok && body != NULL
        && tpc_stat_parse_size((const char *) body, &t->src_size) == 0)
    {
        t->src_size_known = 1;
    }
    free(body);
    return 0;
}

/*
 * WHAT: Record a checksum-verification failure on a TPC pull.
 * WHY: Keep every fail-closed parse/compute path on the same protocol error.
 * HOW: Format the supplied diagnostic and set kXR_ChkSumErr before returning -1.
 */
static int
tpc_checksum_error(brix_tpc_pull_t *t, const char *message)
{
    snprintf(t->err_msg, sizeof(t->err_msg), "%s", message);
    t->xrd_error = kXR_ChkSumErr;
    return -1;
}


/*
 * WHAT: Query the remote source for its whole-file checksum response.
 * WHY: Separate XRootD request framing from digest parsing and comparison.
 * HOW: Send kXR_query(kXR_Qcksum) on stream tag 5, receive one response, and
 *      return its allocated successful body to the caller.
 */
static int
tpc_query_source_checksum(brix_tpc_pull_t *t, int fd, u_char **body_out)
{
    u_char              req[sizeof(ClientQueryRequest) + PATH_MAX];
    ClientQueryRequest  qreq;
    size_t              pathlen = strlen(t->src_path);
    size_t              total = sizeof(ClientQueryRequest) + pathlen;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *body = NULL;

    if (total > sizeof(req)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC src path too long for checksum query");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }
    ngx_memzero(&qreq, sizeof(qreq));
    qreq.streamid[1] = 5;
    qreq.requestid = htons(kXR_query);
    qreq.infotype = htons(kXR_Qcksum);
    qreq.dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(req, &qreq, sizeof(qreq));
    ngx_memcpy(req + sizeof(qreq), t->src_path, pathlen);

    if (tpc_send_all(t, fd, req, total) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum query send failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum query recv failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }
    if (status != kXR_ok || body == NULL) {
        free(body);
        return tpc_checksum_error(t,
                   "TPC checksum verify: source supplied no checksum");
    }
    *body_out = body;
    return 0;
}


/*
 * WHAT: Parse the source's "algorithm digest" checksum response.
 * WHY: Bound both untrusted tokens before passing them to crypto/logging code.
 * HOW: Split at the first space, trim leading separator space, terminate at
 *      whitespace, and copy only tokens fitting the caller's buffers.
 */
static int
tpc_parse_source_checksum(brix_tpc_pull_t *t, const u_char *body,
    char *alg, size_t alg_cap, char *hex, size_t hex_cap)
{
    const char *text = (const char *) body;
    const char *value;
    size_t      alglen;
    size_t      vlen;

    value = strchr(text, ' ');
    if (value == NULL) {
        return tpc_checksum_error(t,
                   "TPC checksum verify: malformed source checksum reply");
    }
    alglen = (size_t) (value - text);
    if (alglen == 0 || alglen >= alg_cap) {
        return tpc_checksum_error(t,
                   "TPC checksum verify: bad source checksum type");
    }
    ngx_memcpy(alg, text, alglen);
    alg[alglen] = '\0';
    do {
        value++;
    } while (*value == ' ');
    vlen = strcspn(value, " \n\r");
    if (vlen == 0 || vlen >= hex_cap) {
        return tpc_checksum_error(t,
                   "TPC checksum verify: bad source checksum value");
    }
    ngx_memcpy(hex, value, vlen);
    hex[vlen] = '\0';
    return 0;
}


/*
 * tpc_verify_dst_hex_writer — sum the destination through the writer session
 * that still owns its bytes.
 *
 * WHY: when the export hands the pull a brix_vfs_writer_t the data lives in the
 * session's staged temp (or in-place handle) and is NOT yet at dst_path, so
 * re-opening the final path would sum the wrong object — or nothing at all.
 * HOW: prefer the session's kernel fd (staged temps are opened read-write); a
 * driver-backed object exposes none, so fall back to reading the object block by
 * block through its driver.
 */
static ngx_int_t
tpc_verify_dst_hex_writer(brix_tpc_pull_t *t, const char *alg, ngx_log_t *log,
    char *hex, size_t hexsz)
{
    brix_checksum_alg_t  parsed;
    char                 normalized[32];
    ngx_fd_t             fd = brix_vfs_writer_fd(t->dst_writer);
    ngx_int_t            rc;

    if (fd != NGX_INVALID_FILE) {
        return brix_checksum_hex_name_fd(alg, (int) fd, t->dst_path, log, hex,
                                         hexsz, normalized, sizeof(normalized));
    }

    rc = brix_checksum_parse(alg, strlen(alg), &parsed, normalized,
                             sizeof(normalized));
    if (rc != NGX_OK) {
        return rc;
    }
    return brix_checksum_hex_obj(parsed, &t->dst_obj, t->dst_path, log, hex,
                                 hexsz);
}


/*
 * tpc_verify_dst_hex — hex-encode `alg` over the bytes this pull just wrote.
 *
 * WHY: the handle the pull WROTE through is not a handle it can READ. A kXR_open
 * that asks only to write maps to O_WRONLY (open_flags.h), so summing t->dst_fd
 * makes read(2) fail EBADF and every checksum-verified pull failed closed on a
 * clean copy — the defect carried unfixed out of the 2026-08-19 session
 * (history-testing-and-incidents §13 coda; the writer theory recorded there is
 * the OTHER arm, below).
 * HOW: with no writer session the bytes are already fsynced at dst_path, so take
 * a fresh confined O_RDONLY fd on it — beneath the same root_canon done.c
 * unlinks through, so the read is confined exactly as the write was — sum it and
 * close. With a writer session the bytes are still in the session; delegate.
 */
static ngx_int_t
tpc_verify_dst_hex(brix_tpc_pull_t *t, const char *alg, ngx_log_t *log,
    char *hex, size_t hexsz)
{
    char       normalized[32];
    ngx_int_t  rc;
    int        fd;

    if (t->dst_writer != NULL) {
        return tpc_verify_dst_hex_writer(t, alg, log, hex, hexsz);
    }

    fd = brix_vfs_open_fd(log, t->conf->common.root_canon, t->dst_path,
                          O_RDONLY | O_NOFOLLOW, 0);
    if (fd < 0) {
        return NGX_ERROR;
    }

    rc = brix_checksum_hex_name_fd(alg, fd, t->dst_path, log, hex, hexsz,
                                   normalized, sizeof(normalized));
    close(fd);
    return rc;
}


/*
 * tpc_verify_source_checksum — opt-in post-copy integrity for the TPC pull.
 * kXR_query(kXR_Qcksum) the source (distinct streamid tag 5), parse the
 * "<alg> <hex>" reply, recompute the same algorithm over the written destination
 * with brix_checksum_hex_name_fd, and fail closed (kXR_ChkSumErr) on any of:
 * source cannot supply a checksum, malformed reply, an algorithm brix cannot
 * compute, a destination read failure, or a digest mismatch. See
 * source_internal.h.
 */
int
tpc_verify_source_checksum(brix_tpc_pull_t *t, int fd)
{
    u_char             *body = NULL;
    char                alg[32];
    char                src_hex[2 * EVP_MAX_MD_SIZE + 1];
    char                local_hex[2 * EVP_MAX_MD_SIZE + 1];
    ngx_log_t          *log = (t->c != NULL) ? t->c->log : ngx_cycle->log;

    if (tpc_query_source_checksum(t, fd, &body) != 0) {
        return -1;
    }
    if (tpc_parse_source_checksum(t, body, alg, sizeof(alg), src_hex,
                                  sizeof(src_hex)) != 0)
    {
        free(body);
        return -1;
    }
    free(body);

    /* Recompute the SAME algorithm over the destination and compare. */
    if (tpc_verify_dst_hex(t, alg, log, local_hex, sizeof(local_hex)) != NGX_OK)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: cannot compute %s on destination", alg);
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }

    if (strcasecmp(local_hex, src_hex) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum mismatch: source %s=%s destination=%s",
                 alg, src_hex, local_hex);
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }

    return 0;
}
