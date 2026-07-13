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
#include "brix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDCAP_MAGIC "XRDCAP1\n"
#define XRDCAP_MAGIC_LEN 8
#define XRDCAP_WIRE_MAX  (XRDC_DLEN_MAX + 64u)

struct brix_capture {
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
struct brix_capture *
brix_capture_open(const char *path)
{
    struct brix_capture *cap = (struct brix_capture *) calloc(1, sizeof(*cap));
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
brix_capture_meta(struct brix_capture *cap, const char *key, const char *val)
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
brix_capture_frame(struct brix_capture *cap, int dir, uint16_t sid, int code,
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
brix_capture_close(struct brix_capture *cap)
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
read_magic(FILE *fp, brix_status *st)
{
    char m[XRDCAP_MAGIC_LEN];
    if (fread(m, 1, XRDCAP_MAGIC_LEN, fp) != XRDCAP_MAGIC_LEN
        || memcmp(m, XRDCAP_MAGIC, XRDCAP_MAGIC_LEN) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "not an .xrdcap bundle (bad magic)");
        return -1;
    }
    return 0;
}

/*
 * skip_bytes — consume and discard `n` bytes from fp, detecting truncation.
 *
 * WHAT: reads n bytes into a scratch buffer, returning 0 when all n bytes were
 *       present or -1 when fewer remain (a truncated/corrupt record).
 * WHY:  fseek(SEEK_CUR) past EOF SUCCEEDS on a regular file, so seeking over a
 *       record body cannot distinguish a complete record from one truncated
 *       mid-body — the skip silently accepts a short file.  An fread-based skip
 *       surfaces the short read exactly as the replay path's body reads do, so a
 *       mid-record truncation fails cleanly instead of passing as valid.
 * HOW:  loop reading up to a fixed scratch buffer until n bytes are consumed or
 *       fread returns short. */
static int
skip_bytes(FILE *fp, size_t n)
{
    char buf[512];
    while (n > 0) {
        size_t want = (n < sizeof(buf)) ? n : sizeof(buf);
        if (fread(buf, 1, want, fp) != want) {
            return -1;
        }
        n -= want;
    }
    return 0;
}

static uint16_t rd_u16(FILE *fp) { int a = fgetc(fp), b = fgetc(fp); return ((uint16_t)(uint8_t)a << 8) | (uint16_t)(uint8_t)b; }
static uint32_t rd_u32(FILE *fp) {
    uint32_t a = (uint32_t) fgetc(fp), b = (uint32_t) fgetc(fp);
    uint32_t c = (uint32_t) fgetc(fp), d = (uint32_t) fgetc(fp);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/*
 * Per-record outcome shared by the replay/playback loops.
 *
 * WHAT: the three ways a single M/F record read can end.
 * WHY:  lets each per-record helper return a typed verdict so the driving loop
 *       stays a flat early-return sequence (no truncated flag threaded by hand,
 *       no goto) while preserving the exact "truncated or corrupt → exit
 *       nonzero" contract the security test depends on.
 * HOW:  OK continues the loop, END stops it cleanly, TRUNC stops it as an error.
 */
typedef enum {
    XRDCAP_REC_OK = 0,     /* record consumed; keep looping */
    XRDCAP_REC_END,        /* clean end of stream */
    XRDCAP_REC_TRUNC       /* short/corrupt record — caller reports the error */
} xrdcap_rec_t;

/*
 * replay_meta_record — decode one 'M' metadata record and print key/value.
 *
 * WHAT: reads klen:1 key[klen] vlen:2BE val[vlen], prints "  key  val", counts it.
 * WHY:  isolates the metadata branch of the replay loop so the driver stays flat.
 * HOW:  every read is bounds-checked; any short read returns TRUNC and frees the
 *       value buffer, matching the original inline break-on-truncation behaviour.
 */
static xrdcap_rec_t
replay_meta_record(FILE *fp, FILE *out, int *metas)
{
    int      kl = fgetc(fp);
    char     key[256];
    uint16_t vl;
    char    *val;

    if (kl < 0 || fread(key, 1, (size_t) kl, fp) != (size_t) kl) {
        return XRDCAP_REC_TRUNC;
    }
    key[kl] = '\0';
    vl = rd_u16(fp);
    val = (char *) malloc((size_t) vl + 1);
    if (val == NULL || fread(val, 1, vl, fp) != vl) {
        free(val);
        return XRDCAP_REC_TRUNC;
    }
    val[vl] = '\0';
    fprintf(out, "  %-10s %s\n", key, val);
    free(val);
    (*metas)++;
    return XRDCAP_REC_OK;
}

/*
 * replay_hexdump_wire — print up to the first 64 wire bytes, 16 per line.
 *
 * WHAT: verbose-mode hex dump of a frame's captured on-the-wire bytes.
 * WHY:  separates the pure formatting from the frame record's read/verify logic.
 * HOW:  side-effect at the edge (fprintf only); wire bytes/length are inputs.
 */
static void
replay_hexdump_wire(FILE *out, const uint8_t *w, uint32_t wlen)
{
    uint32_t i;

    for (i = 0; i < wlen && i < 64; i++) {
        fprintf(out, "%02x%s", w[i], (i % 16 == 15) ? "\n" : " ");
    }
    if (wlen > 0 && (i % 16) != 0) { fprintf(out, "\n"); }
}

/*
 * replay_frame_record — decode one 'F' frame record and print (+optional hexdump).
 *
 * WHAT: reads dir:1 isreq:1 sid:2BE code:2BE wirelen:4BE wire[], prints a summary
 *       line and (verbose) a hex dump, counting the frame.
 * WHY:  isolates the frame branch so the driver stays a flat dispatch.
 * HOW:  rejects EOF fields or an over-long wire as truncated; the wire buffer is
 *       malloc'd (min 1 byte) and freed on every exit — same as the original.
 */
static xrdcap_rec_t
replay_frame_record(FILE *fp, int verbose, FILE *out, int *frames)
{
    int      dir = fgetc(fp), isreq = fgetc(fp);
    uint16_t sid = rd_u16(fp);
    uint16_t code = rd_u16(fp);
    uint32_t wlen = rd_u32(fp);
    uint8_t *w;

    if (dir == EOF || isreq == EOF || wlen > XRDCAP_WIRE_MAX) {
        return XRDCAP_REC_TRUNC;
    }
    w = (uint8_t *) malloc(wlen ? wlen : 1);
    if (w == NULL || fread(w, 1, wlen, fp) != wlen) {
        free(w);
        return XRDCAP_REC_TRUNC;
    }
    fprintf(out, "%c sid=%u %-14s wire=%u\n", dir, sid,
            isreq ? brix_reqid_name(code) : brix_status_name(code), wlen);
    if (verbose >= 1) {
        replay_hexdump_wire(out, w, wlen);
    }
    free(w);
    (*frames)++;
    return XRDCAP_REC_OK;
}

/*
 * brix_capture_replay — decode a .xrdcap file offline and print a human-readable log.
 *
 * WHAT: reads the magic header then a stream of M/F records, printing each to out.
 * WHY:  offline decode lets engineers inspect captured sessions without a live server.
 * HOW:  dispatches each record to a per-type helper; a premature EOF or corrupt
 *       record yields XRDCAP_REC_TRUNC so the caller gets a clean error rather
 *       than silent partial output. This matters for the security test case: a
 *       truncated file must exit nonzero.
 */
int
brix_capture_replay(const char *path, int verbose, FILE *out, brix_status *st)
{
    FILE        *fp = fopen(path, "rb");
    int          type, frames = 0, metas = 0, truncated = 0;
    xrdcap_rec_t rc = XRDCAP_REC_OK;

    if (fp == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cannot open %s", path);
        return -1;
    }
    if (read_magic(fp, st) != 0) {
        fclose(fp);
        return -1;
    }
    fprintf(out, "capture: %s\n", path);
    while ((type = fgetc(fp)) != EOF) {
        if (type == 'M') {
            rc = replay_meta_record(fp, out, &metas);
        } else if (type == 'F') {
            rc = replay_frame_record(fp, verbose, out, &frames);
        } else {
            rc = XRDCAP_REC_TRUNC;   /* unknown record type = corrupt/truncated at boundary */
        }
        if (rc != XRDCAP_REC_OK) {
            truncated = (rc == XRDCAP_REC_TRUNC);
            break;
        }
    }
    fclose(fp);
    fprintf(out, "(%d frame(s), %d metadata record(s))\n", frames, metas);
    if (truncated) {
        brix_status_set(st, XRDC_EPROTO, 0, "%s: truncated or corrupted capture", path);
        return -1;
    }
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

/*
 * playback_skip_meta — consume one 'M' record without decoding it.
 *
 * WHAT: reads klen:1 then discards key[klen] vlen:2BE val[vlen].
 * WHY:  playback ignores metadata but must still walk past it exactly, and detect
 *       a truncation inside it (a short capture must fail, not silently stop).
 * HOW:  fread-based skip (not fseek): fseek past EOF succeeds on a regular file,
 *       so it cannot tell a complete record from one truncated mid-body.
 */
static xrdcap_rec_t
playback_skip_meta(FILE *fp)
{
    int      kl = fgetc(fp);
    uint16_t vl;

    if (kl < 0) { return XRDCAP_REC_TRUNC; }
    if (skip_bytes(fp, (size_t) kl) != 0) { return XRDCAP_REC_TRUNC; }
    vl = rd_u16(fp);
    if (skip_bytes(fp, vl) != 0) { return XRDCAP_REC_TRUNC; }
    return XRDCAP_REC_OK;
}

/*
 * playback_ctx — live-playback loop state passed to the per-record helpers.
 *
 * WHAT: the connection to re-issue against, the human-readable output stream, and
 *       the issued/ok tallies accumulated across frames.
 * WHY:  bundles the four pieces of driver state so the re-issue helper takes one
 *       context rather than a long parameter list (keeps every helper <= 5 params).
 * HOW:  the driver owns one on the stack; helpers mutate issued/ok through it.
 */
typedef struct {
    brix_conn *conn;
    FILE      *out;
    int        issued;
    int        ok;
} playback_ctx;

/*
 * playback_reissue_wire — send one recorded request frame and read its reply.
 *
 * WHAT: writes the exact captured wire bytes, receives the response, prints the
 *       re-issue line, and bumps the issued/ok counters.
 * WHY:  isolates the live-connection side effect (the only I/O against the server)
 *       from the frame's parse/verify, keeping the driver flat.
 * HOW:  pure write+recv over conn->io; the response body is discarded (free rb). A
 *       failed write is silent (matches the original: no line, no counter bump).
 */
static void
playback_reissue_wire(playback_ctx *pc, uint16_t code, const uint8_t *w, uint32_t wlen)
{
    brix_status   rst;
    uint16_t      rstat = 0;
    uint8_t      *rb = NULL;
    uint32_t      rl = 0;
    int           rc;
    brix_resp_out rout = { &rstat, &rb, &rl };

    brix_status_clear(&rst);
    if (brix_write_full(&pc->conn->io, w, wlen, &rst) != 0) {
        return;
    }
    rc = brix_recv(pc->conn, 0xffff, &rout, &rst);
    free(rb);
    pc->issued++;
    if (rc == 0) { pc->ok++; }
    fprintf(pc->out, "  re-issue %-14s -> %s\n", brix_reqid_name(code),
            rc == 0 ? brix_status_name(rstat) : rst.msg);
}

/*
 * playback_frame_record — decode one 'F' record and re-issue it if it is a real op.
 *
 * WHAT: reads the frame header + wire bytes; if it is a client REQUEST for a real
 *       operation (>= 24 bytes, not a session op), re-issues it against the live
 *       connection.
 * WHY:  isolates the frame branch (parse + selective re-issue) from the driver.
 * HOW:  rejects EOF dir or an over-long wire as truncated; the wire buffer is
 *       malloc'd (min 1 byte) and freed on every exit — same as the original.
 */
static xrdcap_rec_t
playback_frame_record(FILE *fp, playback_ctx *pc)
{
    int      dir = fgetc(fp), isreq = fgetc(fp);
    uint16_t sid = rd_u16(fp);
    uint16_t code = rd_u16(fp);
    uint32_t wlen = rd_u32(fp);
    uint8_t *w;

    (void) sid;
    if (dir == EOF || wlen > XRDCAP_WIRE_MAX) { return XRDCAP_REC_TRUNC; }
    w = (uint8_t *) malloc(wlen ? wlen : 1);
    if (w == NULL || fread(w, 1, wlen, fp) != wlen) {
        free(w);
        return XRDCAP_REC_TRUNC;
    }
    /* Replay only client REQUEST frames that are real operations. */
    if (isreq == 1 && dir == '>' && wlen >= 24 && !is_session_op(code)) {
        playback_reissue_wire(pc, code, w, wlen);
    }
    free(w);
    return XRDCAP_REC_OK;
}

int
brix_capture_playback(const char *path, const char *url, const brix_opts *co,
                      FILE *out, brix_status *st)
{
    FILE        *fp;
    brix_url     u;
    brix_conn    c;
    playback_ctx pc = {0};
    int          type, truncated = 0;
    xrdcap_rec_t rc = XRDCAP_REC_OK;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        brix_status_set(st, XRDC_EUSAGE, 0, "cannot open %s", path);
        return -1;
    }
    if (read_magic(fp, st) != 0) {
        fclose(fp);
        return -1;
    }
    if (brix_endpoint_parse(url, &u, st) != 0 || brix_connect(&c, &u, co, st) != 0) {
        fclose(fp);
        return -1;
    }
    fprintf(out, "playback: %s -> %s:%d\n", path, u.host, u.port);

    pc.conn = &c;
    pc.out = out;
    while ((type = fgetc(fp)) != EOF) {
        if (type == 'M') {
            rc = playback_skip_meta(fp);
        } else if (type == 'F') {
            rc = playback_frame_record(fp, &pc);
        } else {
            rc = XRDCAP_REC_TRUNC;
        }
        if (rc != XRDCAP_REC_OK) {
            truncated = (rc == XRDCAP_REC_TRUNC);
            break;
        }
    }
    fclose(fp);
    brix_close(&c);
    fprintf(out, "(%d request(s) re-issued, %d ok)\n", pc.issued, pc.ok);
    if (truncated) {
        brix_status_set(st, XRDC_EPROTO, 0, "truncated or corrupted capture");
        return -1;
    }
    return 0;
}
