/*
 * capture.c — session capture to a portable .xrdcap bundle + offline replay.
 *
 * WHAT: Record every wire frame (both directions) plus negotiated session
 *       metadata into a self-describing file; decode it later offline (no
 *       server), or re-issue the recorded requests against a live server.
 * WHY:  "Paste the bytes into the bug." A capture is a deterministic artifact a
 *       server bug can be reproduced from — decode it anywhere, or replay it to
 *       reproduce the exchange — without a packet sniffer or a live cluster.
 * HOW:  Writer hooks sit beside the wire-trace hooks in frame.c (inert when the
 *       sink is NULL). The format is an 8-byte magic then a stream of records:
 *         'M' meta : klen:1  key[klen]              vlen:2BE  val[vlen]
 *         'F' frame: dir:1 isreq:1 sid:2BE code:2BE wirelen:4BE wire[wirelen]
 *       where `wire` is the exact on-the-wire bytes (header+body), so replay can
 *       both decode (code→name via trace.c) and re-issue requests verbatim.
 *
 * Clean-room: our own framing; reuses trace.c name decoders. No XrdCl.
 */
#include "xrdc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDCAP_MAGIC "XRDCAP1\n"
#define XRDCAP_MAGIC_LEN 8
#define XRDCAP_WIRE_MAX  (XRDC_DLEN_MAX + 64u)

struct xrdc_capture {
    FILE *fp;
};

/* big-endian writers */static void
put_u16(FILE *fp, uint16_t v)
{
    fputc((v >> 8) & 0xff, fp);
    fputc(v & 0xff, fp);
}

static void
put_u32(FILE *fp, uint32_t v)
{
    fputc((v >> 24) & 0xff, fp);
    fputc((v >> 16) & 0xff, fp);
    fputc((v >> 8) & 0xff, fp);
    fputc(v & 0xff, fp);
}

/* writer */
struct xrdc_capture *
xrdc_capture_open(const char *path)
{
    struct xrdc_capture *cap = (struct xrdc_capture *) calloc(1, sizeof(*cap));
    if (cap == NULL) {
        return NULL;
    }
    cap->fp = fopen(path, "wb");
    if (cap->fp == NULL) {
        free(cap);
        return NULL;
    }
    fwrite(XRDCAP_MAGIC, 1, XRDCAP_MAGIC_LEN, cap->fp);
    return cap;
}

void
xrdc_capture_meta(struct xrdc_capture *cap, const char *key, const char *val)
{
    size_t kl, vl;
    if (cap == NULL || cap->fp == NULL || key == NULL) {
        return;
    }
    if (val == NULL) { val = ""; }
    kl = strlen(key);
    vl = strlen(val);
    if (kl > 255) { kl = 255; }
    if (vl > 0xffff) { vl = 0xffff; }
    fputc('M', cap->fp);
    fputc((int) kl, cap->fp);
    fwrite(key, 1, kl, cap->fp);
    put_u16(cap->fp, (uint16_t) vl);
    fwrite(val, 1, vl, cap->fp);
}

void
xrdc_capture_frame(struct xrdc_capture *cap, int dir, uint16_t sid, int code,
                   int is_request, const void *hdr, uint32_t hdrlen,
                   const void *body, uint32_t blen)
{
    if (cap == NULL || cap->fp == NULL) {
        return;
    }
    fputc('F', cap->fp);
    fputc(dir, cap->fp);
    fputc(is_request ? 1 : 0, cap->fp);
    put_u16(cap->fp, sid);
    put_u16(cap->fp, (uint16_t) code);
    put_u32(cap->fp, hdrlen + blen);
    if (hdrlen > 0 && hdr != NULL) {
        fwrite(hdr, 1, hdrlen, cap->fp);
    }
    if (blen > 0 && body != NULL) {
        fwrite(body, 1, blen, cap->fp);
    }
}

void
xrdc_capture_close(struct xrdc_capture *cap)
{
    if (cap == NULL) {
        return;
    }
    if (cap->fp != NULL) {
        fclose(cap->fp);
    }
    free(cap);
}

/* readers (offline decode + live playback) */
static int
read_magic(FILE *fp, xrdc_status *st)
{
    char m[XRDCAP_MAGIC_LEN];
    if (fread(m, 1, XRDCAP_MAGIC_LEN, fp) != XRDCAP_MAGIC_LEN
        || memcmp(m, XRDCAP_MAGIC, XRDCAP_MAGIC_LEN) != 0) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "not an .xrdcap bundle (bad magic)");
        return -1;
    }
    return 0;
}

static uint16_t rd_u16(FILE *fp) { int a = fgetc(fp), b = fgetc(fp); return (uint16_t) ((a << 8) | (b & 0xff)); }
static uint32_t rd_u32(FILE *fp) {
    uint32_t a = (uint32_t) fgetc(fp), b = (uint32_t) fgetc(fp);
    uint32_t c = (uint32_t) fgetc(fp), d = (uint32_t) fgetc(fp);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

int
xrdc_capture_replay(const char *path, int verbose, FILE *out, xrdc_status *st)
{
    FILE *fp = fopen(path, "rb");
    int   type, frames = 0, metas = 0;

    if (fp == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot open %s", path);
        return -1;
    }
    if (read_magic(fp, st) != 0) {
        fclose(fp);
        return -1;
    }
    fprintf(out, "capture: %s\n", path);
    while ((type = fgetc(fp)) != EOF) {
        if (type == 'M') {
            int      kl = fgetc(fp);
            char     key[256];
            uint16_t vl;
            char    *val;
            if (kl < 0 || fread(key, 1, (size_t) kl, fp) != (size_t) kl) { break; }
            key[kl] = '\0';
            vl = rd_u16(fp);
            val = (char *) malloc((size_t) vl + 1);
            if (val == NULL || fread(val, 1, vl, fp) != vl) { free(val); break; }
            val[vl] = '\0';
            fprintf(out, "  %-10s %s\n", key, val);
            free(val);
            metas++;
        } else if (type == 'F') {
            int      dir = fgetc(fp), isreq = fgetc(fp);
            uint16_t sid = rd_u16(fp);
            uint16_t code = rd_u16(fp);
            uint32_t wlen = rd_u32(fp);
            uint8_t *w;
            if (dir == EOF || isreq == EOF || wlen > XRDCAP_WIRE_MAX) { break; }
            w = (uint8_t *) malloc(wlen ? wlen : 1);
            if (w == NULL || fread(w, 1, wlen, fp) != wlen) { free(w); break; }
            fprintf(out, "%c sid=%u %-14s wire=%u\n", dir, sid,
                    isreq ? xrdc_reqid_name(code) : xrdc_status_name(code), wlen);
            if (verbose >= 1) {
                uint32_t i;
                for (i = 0; i < wlen && i < 64; i++) {
                    fprintf(out, "%02x%s", w[i], (i % 16 == 15) ? "\n" : " ");
                }
                if (wlen > 0 && (i % 16) != 0) { fprintf(out, "\n"); }
            }
            free(w);
            frames++;
        } else {
            break;
        }
    }
    fclose(fp);
    fprintf(out, "(%d frame(s), %d metadata record(s))\n", frames, metas);
    return 0;
}

/* Opcodes that are part of session bring-up/teardown — NOT replayed (the live
 * connection runs its own handshake/login/auth). */
static int
is_session_op(int reqid)
{
    return reqid == kXR_protocol || reqid == kXR_login || reqid == kXR_auth
        || reqid == kXR_bind || reqid == kXR_endsess || reqid == kXR_sigver;
}

int
xrdc_capture_playback(const char *path, const char *url, const xrdc_opts *co,
                      FILE *out, xrdc_status *st)
{
    FILE     *fp;
    xrdc_url  u;
    xrdc_conn c;
    int       type, issued = 0, ok = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot open %s", path);
        return -1;
    }
    if (read_magic(fp, st) != 0) {
        fclose(fp);
        return -1;
    }
    if (xrdc_endpoint_parse(url, &u, st) != 0 || xrdc_connect(&c, &u, co, st) != 0) {
        fclose(fp);
        return -1;
    }
    fprintf(out, "playback: %s -> %s:%d\n", path, u.host, u.port);

    while ((type = fgetc(fp)) != EOF) {
        if (type == 'M') {                       /* skip metadata */
            int kl = fgetc(fp);
            uint16_t vl;
            if (kl < 0) { break; }
            if (fseek(fp, kl, SEEK_CUR) != 0) { break; }
            vl = rd_u16(fp);
            if (fseek(fp, vl, SEEK_CUR) != 0) { break; }
            continue;
        }
        if (type != 'F') {
            break;
        }
        {
            int      dir = fgetc(fp), isreq = fgetc(fp);
            uint16_t sid = rd_u16(fp);
            uint16_t code = rd_u16(fp);
            uint32_t wlen = rd_u32(fp);
            uint8_t *w;
            (void) sid;
            if (dir == EOF || wlen > XRDCAP_WIRE_MAX) { break; }
            w = (uint8_t *) malloc(wlen ? wlen : 1);
            if (w == NULL || fread(w, 1, wlen, fp) != wlen) { free(w); break; }
            /* Replay only client REQUEST frames that are real operations. */
            if (isreq == 1 && dir == '>' && wlen >= 24 && !is_session_op(code)) {
                xrdc_status rst;
                uint16_t    rstat = 0;
                uint8_t    *rb = NULL;
                uint32_t    rl = 0;
                int         rc;
                xrdc_status_clear(&rst);
                if (xrdc_write_full(&c.io, w, wlen, &rst) == 0) {
                    rc = xrdc_recv(&c, 0xffff, &rstat, &rb, &rl, &rst);
                    free(rb);
                    issued++;
                    if (rc == 0) { ok++; }
                    fprintf(out, "  re-issue %-14s -> %s\n", xrdc_reqid_name(code),
                            rc == 0 ? xrdc_status_name(rstat) : rst.msg);
                }
            }
            free(w);
        }
    }
    fclose(fp);
    xrdc_close(&c);
    fprintf(out, "(%d request(s) re-issued, %d ok)\n", issued, ok);
    return 0;
}
