/*
 * test_sd_xroot_query.c — the four root:// vtable slots that ask the ORIGIN a
 * question instead of moving bytes: space, query_checksum, residency, recall.
 *
 * WHY THIS UNIT EXISTS: every one of them is a decision that is invisible from
 * the outside, and every one of them was NULL on the driver table until the
 * storage-driver gap wave. A NULL slot is not a crash, it is a wrong answer:
 *   space           — kXR_statvfs reported the statvfs(2) of the GATEWAY's local
 *                     export directory for a root:// export whose bytes live on
 *                     a remote origin, so a client sized a write against a disk
 *                     the data was never going to land on.
 *   query_checksum  — a checksum request pulled the WHOLE object back through
 *                     kXR_read to hash bytes the origin had already hashed.
 *   residency       — brix_vfs_residency answers ONLINE for a driver with no
 *                     residency model, so a tape-backed origin claimed every
 *                     migrated file was on disk.
 *   recall          — with no recall slot the first read of a migrated file
 *                     blocked a worker for the length of a tape mount instead of
 *                     parking the open and answering "staging, retry later".
 *
 * The whole stack is real except the socket. The driver comes from
 * brix_sd_xroot_create, so the slots are reached through the REAL vtable
 * (query_checksum has no other entry point — it is file-static in sd_xroot.c);
 * below it sd_xroot_ns.o / sd_xroot_nearline.o call the real origin clients in
 * origin_protocol.o (kXR_query) and origin_ns.o (kXR_stat, kXR_prepare), which
 * pack their bodies with the real wire codec. Only the connect/bootstrap
 * handshake and the two io primitives stand in for the socket, so every
 * assertion below is about bytes this code would really send, or about an answer
 * really decoded from bytes an origin could really reply with.
 *
 * Arms, per slot: success (the answer is right and the frame that fetched it is
 * the right frame), error (each origin refusal and transport fault maps to its
 * errno / documented soft outcome), and security-negative (no fabricated
 * capacity, no mislabelled digest, no invented LOST verdict, no stale request id
 * and no staging of a path the origin denied).
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/xroot/sd_xroot.h"
#include "fs/backend/xroot/sd_xroot_internal.h"
#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/protocol/flags.h"

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* ---- captured wire state --------------------------------------------------- */

#define MAX_FRAMES   4
#define MAX_FRAME    1024

static int     g_frames;                            /* brix_cache_io_send calls */
static u_char  g_frame[MAX_FRAMES][MAX_FRAME];      /* each one, verbatim       */
static size_t  g_frame_len[MAX_FRAMES];
static int     g_send_rc;                           /* transport fault injection */

/* One scripted reply per request, consumed in order; the last entry repeats so a
 * slot that sends more frames than the script anticipates still terminates. */
typedef struct {
    uint16_t     status;
    int          errnum;     /* kXR_error body errnum (status == kXR_error)     */
    const char  *text;       /* kXR_ok body, NUL-terminated ("" ⇒ empty body)   */
} reply_t;

static reply_t g_reply[MAX_FRAMES];
static int     g_scripted;
static int     g_reads;
static int     g_resp_rc;                           /* read fault injection     */

static int     g_sessions;                          /* origin connects          */
static int     g_closes;                            /* origin_close calls       */
static int     g_connect_rc;                        /* session-open fault       */

static void
reset(void)
{
    memset(g_frame, 0, sizeof g_frame);
    memset(g_frame_len, 0, sizeof g_frame_len);
    memset(g_reply, 0, sizeof g_reply);
    g_frames = 0;
    g_send_rc = 0;
    g_scripted = 0;
    g_reads = 0;
    g_resp_rc = 0;
    g_sessions = g_closes = 0;
    g_connect_rc = 0;
    errno = 0;
}

/* Script the reply to the next unscripted request. */
static void
script_ok(const char *text)
{
    if (g_scripted < MAX_FRAMES) {
        g_reply[g_scripted].status = kXR_ok;
        g_reply[g_scripted].text = text;
        g_scripted++;
    }
}

static void
script_error(int errnum)
{
    if (g_scripted < MAX_FRAMES) {
        g_reply[g_scripted].status = kXR_error;
        g_reply[g_scripted].errnum = errnum;
        g_scripted++;
    }
}

/* ---- stubs: the socket, and nothing above it ------------------------------- */

int
brix_cache_origin_connect(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    g_sessions++;
    if (g_connect_rc != 0) {
        t->xrd_error = 3007;
        return -1;
    }
    oc->fd = 4242;                          /* never a real socket here */
    return 0;
}

int
brix_cache_origin_bootstrap(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    (void) t; (void) oc;
    return 0;
}

void
brix_cache_origin_close(brix_cache_origin_conn_t *oc)
{
    oc->fd = -1;
    g_closes++;
}

int
brix_cache_io_send(brix_cache_origin_conn_t *oc, const void *buf, size_t len)
{
    (void) oc;
    if (g_frames < MAX_FRAMES) {
        g_frame_len[g_frames] = len < MAX_FRAME ? len : MAX_FRAME;
        memcpy(g_frame[g_frames], buf, g_frame_len[g_frames]);
    }
    g_frames++;
    return g_send_rc;
}

int
brix_cache_read_response(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t *status, u_char **body, uint32_t *dlen, uint32_t max_body)
{
    const reply_t *r;
    int            idx;

    (void) t; (void) oc; (void) max_body;

    if (g_resp_rc != 0) {
        return -1;
    }
    idx = g_reads < g_scripted ? g_reads : (g_scripted > 0 ? g_scripted - 1 : 0);
    g_reads++;
    r = &g_reply[idx];
    *status = g_scripted > 0 ? r->status : kXR_ok;

    if (*status == kXR_error) {
        /* kXR_error body: errnum(4, big-endian) + NUL-terminated message. */
        static const char msg[] = "origin refused";
        u_char           *b = calloc(1, 4 + sizeof msg);

        if (b == NULL) { return -1; }
        b[0] = (u_char) ((r->errnum >> 24) & 0xff);
        b[1] = (u_char) ((r->errnum >> 16) & 0xff);
        b[2] = (u_char) ((r->errnum >> 8) & 0xff);
        b[3] = (u_char) (r->errnum & 0xff);
        memcpy(b + 4, msg, sizeof msg);
        *body = b;
        *dlen = (uint32_t) (4 + sizeof msg);
        return 0;
    }

    /* The real reader allocates dlen+1 and NUL-terminates; the decoders below
     * (sscanf on the ASCII stat line, strdup of a query answer) rely on it. */
    {
        size_t  n = (r->text != NULL) ? strlen(r->text) : 0;
        u_char *b = calloc(1, n + 1);

        if (b == NULL) { return -1; }
        if (n > 0) { memcpy(b, r->text, n); }
        *body = b;
        *dlen = (uint32_t) n;
    }
    return 0;
}

/* ---- stubs: the linked closure the driver table names but this unit never
 * calls. The write data path (origin_write.o), the GSI store builder, and the
 * fattr reply parser are the only symbols the whole xroot driver + origin
 * namespace/protocol pair leave undefined once the socket is stubbed. --------- */

void brix_cache_origin_close_file(brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{ (void) oc; (void) fhandle; }
int brix_cache_origin_open_write(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{ (void) t; (void) oc; (void) path; (void) mode_bits; (void) fhandle; return -1; }
int brix_cache_origin_write_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len)
{ (void) t; (void) oc; (void) fhandle; (void) offset; (void) data; (void) len;
  return -1; }
int brix_cache_origin_sync(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{ (void) t; (void) oc; (void) fhandle; return -1; }
int brix_cache_origin_truncate(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t length)
{ (void) t; (void) oc; (void) fhandle; (void) length; return -1; }
int brix_cache_origin_truncate_path(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, uint64_t length)
{ (void) t; (void) oc; (void) path; (void) length; return -1; }
void brix_cache_set_error(brix_cache_fill_t *t, int xrd_error, int sys_errno,
    const char *msg)
{ (void) msg; if (t != NULL) { t->result = -1; t->xrd_error = xrd_error;
  t->sys_errno = sys_errno; } }
void brix_cache_set_origin_error(brix_cache_fill_t *t, u_char *body,
    uint32_t dlen, const char *msg)
{ (void) body; (void) dlen; (void) msg; if (t != NULL) { t->result = -1; } }
void brix_cache_set_syserror(brix_cache_fill_t *t, int sys_errno,
    const char *msg)
{ (void) msg; if (t != NULL) { t->result = -1; t->sys_errno = sys_errno; } }
int brix_cache_sink_pwrite(brix_cache_sink_t *sink, const void *buf,
    size_t len, off_t off)
{ (void) sink; (void) buf; (void) len; (void) off; return -1; }
int xrdp_fattr_nvec_parse(const uint8_t *buf, size_t len, size_t off,
    uint16_t *rc, const uint8_t **name, size_t *nlen, size_t *next_off)
{ (void) buf; (void) len; (void) off; (void) rc; (void) name; (void) nlen;
  (void) next_off; return -1; }
X509_STORE *brix_build_ca_store(const char *path, int is_dir, int allow_proxy,
    int signing_policy, int *crl_count)
{ (void) path; (void) is_dir; (void) allow_proxy; (void) signing_policy;
  (void) crl_count; return NULL; }
/* phase-107 C8: sd_xroot_nearline consults the registry's capability accessor
 * before recall/residency dispatch. Faithful copy of sd_registry.c's one-line
 * body — linking sd_registry.o would drag every builtin driver vtable. */
uint32_t brix_sd_caps(const brix_sd_instance_t *inst)
{ return (inst != NULL && inst->driver != NULL) ? inst->caps : 0; }

/* ---- wire accessors over a captured frame ---------------------------------- */

/* ClientRequestHdr: streamid(2) requestid(2,BE) body(16) dlen(4,BE), payload.
 * Read with memcpy so an odd frame offset is never a misaligned load. */
static uint16_t
frame_opcode(int i)
{
    uint16_t v;

    memcpy(&v, g_frame[i] + 2, sizeof v);
    return ntohs(v);
}

static uint32_t
frame_dlen(int i)
{
    uint32_t v;

    memcpy(&v, g_frame[i] + 20, sizeof v);
    return ntohl(v);
}

/* kXR_query body: infotype(2, BE) reserved(2) fhandle(4) reserved(8). */
static uint16_t
frame_infotype(int i)
{
    return (uint16_t) ((g_frame[i][4] << 8) | g_frame[i][5]);
}

static int
frame_fhandle_is_zero(int i)
{
    int j;

    for (j = 8; j < 12; j++) {          /* body[4..7] = header bytes 8..11 */
        if (g_frame[i][j] != 0) { return 0; }
    }
    return 1;
}

static int
frame_body_is_zero(int i)
{
    int j;

    for (j = 4; j < 20; j++) {          /* the whole 16-byte body */
        if (g_frame[i][j] != 0) { return 0; }
    }
    return 1;
}

static int
frame_payload_is(int i, const char *path)
{
    size_t pl = strlen(path);

    return frame_dlen(i) == (uint32_t) pl
           && g_frame_len[i] == 24 + pl
           && memcmp(g_frame[i] + 24, path, pl) == 0;
}

/* ---- fixtures -------------------------------------------------------------- */

static ngx_stream_brix_srv_conf_t  g_conf;
static brix_sd_instance_t         *g_inst;
static const brix_sd_driver_t     *g_drv;

static void
build_inst(void)
{
    memset(&g_conf, 0, sizeof g_conf);
    g_inst = brix_sd_xroot_create(&g_conf, NULL);
    assert(g_inst != NULL && g_inst->driver != NULL);
    g_drv = g_inst->driver;
}

/* An object standing on a live origin session, for the object-keyed slot
 * (query_checksum). The fill task carries the path the query is issued against;
 * the connection is the stubbed socket. */
static brix_sd_obj_t *
build_obj(const char *path)
{
    brix_sd_obj_t      *obj = calloc(1, sizeof(*obj));
    sd_xroot_obj_state *st = calloc(1, sizeof(*st));

    assert(obj != NULL && st != NULL);
    st->t = calloc(1, sizeof(*st->t));
    assert(st->t != NULL);
    st->t->conf = &g_conf;
    ngx_cpystrn((u_char *) st->t->clean_path, (u_char *) path,
                sizeof(st->t->clean_path));
    st->oc.fd = 4242;
    obj->driver = g_drv;
    obj->inst = g_inst;
    obj->state = st;
    return obj;
}

static void
free_obj(brix_sd_obj_t *obj)
{
    sd_xroot_obj_state *st = obj->state;

    free(st->t);
    free(st);
    free(obj);
}

/* ---- space ----------------------------------------------------------------- */

/* The origin's own oss.* capacity report — the answer a root:// gateway must
 * relay instead of its local statvfs. */
#define QSPACE_REPLY \
    "oss.cgroup=default&oss.space=1000000000&oss.free=250000000" \
    "&oss.maxf=250000000&oss.used=750000000&oss.quota=-1"

static void
check_space(void)
{
    brix_sd_space_t sp;

    CHECK(g_drv->space != NULL, "the driver table carries a space slot");

    /* success: the origin's figures arrive intact, used derived from the pair. */
    reset();
    script_ok(QSPACE_REPLY);
    memset(&sp, 0xee, sizeof sp);
    CHECK(g_drv->space(g_inst, &sp) == NGX_OK, "space ok");
    CHECK(sp.total_bytes == 1000000000ULL, "total is the origin's oss.space");
    CHECK(sp.free_bytes == 250000000ULL, "free is the origin's oss.free");
    CHECK(sp.used_bytes == 750000000ULL, "used is total - free");
    CHECK(g_frames == 1, "exactly one frame sent");
    CHECK(g_sessions == 1 && g_closes == 1, "one session, opened and closed");
    CHECK(frame_opcode(0) == kXR_query, "opcode is kXR_query (3001)");
    CHECK(frame_infotype(0) == kXR_Qspace, "infotype is kXR_Qspace (5)");
    CHECK(frame_payload_is(0, "/"), "the export root is the queried path");
    /* A non-zero fhandle turns a path query into a query about whatever file
     * that handle names — the capacity of one open file, not the export. */
    CHECK(frame_fhandle_is_zero(0), "fhandle is zero: this is a PATH query");

    /* error: a refusing origin, a wire fault, and a session that will not open
     * each fail rather than reporting the gateway's own disk. */
    reset();
    script_error(kXR_NotAuthorized);
    CHECK(g_drv->space(g_inst, &sp) == NGX_ERROR, "kXR_error -> failure");
    CHECK(errno == ENOTSUP, "a refused query has no usable answer -> ENOTSUP");

    reset();
    script_ok(QSPACE_REPLY);
    g_resp_rc = -1;
    CHECK(g_drv->space(g_inst, &sp) == NGX_ERROR, "read fault -> failure");
    CHECK(errno == EIO, "transport fault -> EIO");

    reset();
    g_connect_rc = -1;
    CHECK(g_drv->space(g_inst, &sp) == NGX_ERROR, "unopenable session fails");
    CHECK(g_frames == 0, "no frame without a session");

    /* security-negative: a report the origin did not actually make must never
     * become a capacity figure. A reply carrying oss.free but no oss.space would
     * decode as total=0 — "the export is full" or, to a caller that divides,
     * worse — so it is refused outright and the caller falls back to statvfs. */
    reset();
    script_ok("oss.cgroup=default&oss.free=250000000&oss.quota=-1");
    memset(&sp, 0xee, sizeof sp);
    CHECK(g_drv->space(g_inst, &sp) == NGX_ERROR, "oss.space absent -> failure");
    CHECK(errno == ENOTSUP, "a partial report -> ENOTSUP, not a zero total");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "a failed space query leaves the caller's struct untouched");

    reset();
    script_ok("");
    CHECK(g_drv->space(g_inst, &sp) == NGX_ERROR, "empty reply -> failure");
    CHECK(errno == ENOTSUP, "an empty body is not a capacity of zero");
}

/* ---- query_checksum -------------------------------------------------------- */

static void
check_query_checksum(void)
{
    brix_sd_obj_t *obj = build_obj("/store/data/run42.root");
    char           hex[161];

    CHECK(g_drv->query_checksum != NULL,
          "the driver table carries a query_checksum slot");

    /* success: the origin's digest, in the algorithm that was asked for. */
    reset();
    script_ok("adler32 0badf00d");
    memset(hex, 0, sizeof hex);
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_OK,
          "matching algorithm -> NGX_OK");
    CHECK(strcmp(hex, "0badf00d") == 0, "the origin's hex is returned verbatim");
    CHECK(g_frames == 1, "one frame — no object bytes were read");
    CHECK(frame_opcode(0) == kXR_query, "opcode is kXR_query (3001)");
    CHECK(frame_infotype(0) == kXR_Qcksum, "infotype is kXR_Qcksum (3)");
    CHECK(frame_payload_is(0, "/store/data/run42.root"),
          "the query names the open object's path");

    /* The canonical name is matched case-insensitively: an origin spelling its
     * algorithm ADLER32 holds the same digest, and declining there would cost a
     * whole-object read for nothing. */
    reset();
    script_ok("ADLER32 0badf00d");
    memset(hex, 0, sizeof hex);
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_OK,
          "algorithm match is case-insensitive");
    CHECK(strcmp(hex, "0badf00d") == 0, "and the digest still arrives");

    /* error: no digest, a refusing origin, and a wire fault all DECLINE — the
     * caller then computes, so a network hiccup can never fail a checksum
     * request the compute path could still satisfy. */
    reset();
    script_ok("");
    memset(hex, 0xee, sizeof hex);
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_DECLINED,
          "an origin with no digest declines");

    reset();
    script_error(kXR_NotFound);
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_DECLINED,
          "a refusing origin declines");

    reset();
    script_ok("adler32 0badf00d");
    g_resp_rc = -1;
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_DECLINED,
          "a wire fault declines rather than failing the request");

    reset();
    script_ok("adler32");                   /* no space: not "<alg> <hex>" */
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_DECLINED,
          "a malformed answer declines");

    /* security-negative: a digest in ANOTHER algorithm must never be handed back
     * labelled as the requested one — that is a silent integrity failure, not a
     * performance question — and the caller's buffer must be left empty so a
     * caller that ignores the return code cannot publish a stale digest. */
    reset();
    script_ok("md5 d41d8cd98f00b204e9800998ecf8427e");
    memset(hex, 0, sizeof hex);
    CHECK(g_drv->query_checksum(obj, "adler32", hex, sizeof hex) == NGX_DECLINED,
          "an md5 answer to an adler32 question declines");
    CHECK(hex[0] == '\0', "and never leaves the wrong digest in the buffer");

    reset();
    script_ok("crc32c 11223344");
    memset(hex, 0, sizeof hex);
    CHECK(g_drv->query_checksum(obj, "crc32", hex, sizeof hex) == NGX_DECLINED,
          "crc32c is not crc32 — a prefix match is not a match");
    CHECK(hex[0] == '\0', "and the buffer stays empty");

    /* A caller buffer smaller than the origin's digest must be truncated, never
     * overrun: the guard byte past the declared capacity stays intact. */
    {
        char small[9];

        memset(small, 0, sizeof small);
        reset();
        script_ok("adler32 0123456789abcdef");
        CHECK(g_drv->query_checksum(obj, "adler32", small, 8) == NGX_OK,
              "a short buffer still succeeds");
        CHECK(strlen(small) == 7, "written within the declared capacity");
        CHECK(small[8] == '\0', "the byte past the capacity is untouched");
    }

    free_obj(obj);
}

/* ---- residency ------------------------------------------------------------- */

/* The classic 4-field ASCII stat line: "id size flags mtime". */
#define STAT_ONLINE   "12345 4096 0 1700000000"
#define STAT_OFFLINE  "12345 4096 8 1700000000"        /* 8 = kXR_offline */

static void
check_residency(void)
{
    const char          *path = "/store/mc/archived.root";
    brix_sd_residency_t  res;

    CHECK(g_drv->residency != NULL, "the driver table carries a residency slot");

    /* success: the kXR_offline bit is the whole classification. */
    reset();
    script_ok(STAT_ONLINE);
    res = BRIX_SD_RES_LOST;
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_OK, "residency ok");
    CHECK(res == BRIX_SD_RES_ONLINE, "no kXR_offline -> ONLINE");
    CHECK(g_frames == 1, "one frame");
    CHECK(frame_opcode(0) == kXR_stat, "opcode is kXR_stat (3017)");
    CHECK(frame_payload_is(0, path), "the path is the payload");
    /* options=0, wants=0, fhandle=0: the origin must describe the path by NAME,
     * so a directory is reported with its flag rather than failing an open. */
    CHECK(frame_body_is_zero(0), "the stat body is zeroed: describe by name");

    reset();
    script_ok(STAT_OFFLINE);
    res = BRIX_SD_RES_ONLINE;
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_OK, "offline stat ok");
    CHECK(res == BRIX_SD_RES_NEARLINE, "kXR_offline -> NEARLINE");

    /* Other flag bits are not a residency model: a directory, or a file the
     * origin marks with any flag the base protocol defines, is still ONLINE. */
    reset();
    script_ok("12345 4096 5 1700000000");   /* kXR_isDir|kXR_xset, no offline */
    res = BRIX_SD_RES_LOST;
    CHECK(g_drv->residency(g_inst, "/store/mc", &res) == NGX_OK,
          "a directory stats fine");
    CHECK(res == BRIX_SD_RES_ONLINE, "unrelated flag bits do not mean nearline");

    /* error: a refusal maps to its errno, a malformed line is EIO, a missing
     * out-pointer is refused before any session is opened. */
    reset();
    script_error(kXR_NotFound);
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR, "kXR_NotFound fails");
    CHECK(errno == ENOENT, "kXR_NotFound -> ENOENT");

    reset();
    script_error(kXR_NotAuthorized);
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR, "denial fails");
    CHECK(errno == EACCES, "kXR_NotAuthorized -> EACCES");

    reset();
    script_ok("not a stat line");
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR, "garbage fails");
    CHECK(errno == EIO, "a malformed stat line -> EIO");

    reset();
    CHECK(g_drv->residency(g_inst, path, NULL) == NGX_ERROR, "NULL out fails");
    CHECK(errno == EINVAL && g_frames == 0 && g_sessions == 0,
          "NULL out -> EINVAL before a session is opened");

    reset();
    g_connect_rc = -1;
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR,
          "unopenable session fails");
    CHECK(g_frames == 0, "no frame without a session");

    /* security-negative: a path the origin cannot describe is an ERROR, never a
     * residency class. Reporting LOST would tell the tape REST API a file was
     * destroyed because the origin merely 404'd or refused the credential, and a
     * caller acting on LOST deletes catalogue entries. */
    reset();
    script_error(kXR_NotFound);
    res = BRIX_SD_RES_ONLINE;
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR, "missing path fails");
    CHECK(res == BRIX_SD_RES_ONLINE,
          "a failed residency query never writes LOST into the caller's out");

    reset();
    script_error(kXR_NotAuthorized);
    res = BRIX_SD_RES_NEARLINE;
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_ERROR, "denied path fails");
    CHECK(res == BRIX_SD_RES_NEARLINE,
          "an authorization failure is not a residency verdict either");

    /* And residency is a pure READ: classifying a migrated file must never queue
     * MSS work, or a directory listing would stage the whole tape archive. */
    reset();
    script_ok(STAT_OFFLINE);
    CHECK(g_drv->residency(g_inst, path, &res) == NGX_OK, "offline classify ok");
    CHECK(g_frames == 1 && frame_opcode(0) != kXR_prepare,
          "classifying a NEARLINE path sends no kXR_prepare");
}

/* ---- recall ---------------------------------------------------------------- */

static void
check_recall(void)
{
    const char *path = "/store/mc/archived.root";
    char        reqid[40];

    CHECK(g_drv->recall != NULL, "the driver table carries a recall slot");

    /* success, already resident: no prepare at all. Asking anyway would queue
     * pointless MSS work on every cache miss of a file that is already on disk. */
    reset();
    script_ok(STAT_ONLINE);
    memcpy(reqid, "STALE-FROM-THE-LAST-FILE", 25);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_OK, "resident -> NGX_OK");
    CHECK(g_frames == 1, "one frame: the residency probe only");
    CHECK(reqid[0] == '\0',
          "a stale request id from a previous recall is cleared, never parked on");

    /* success, migrated: stat then kXR_prepare(kXR_stage), and always AGAIN —
     * prepare is asynchronous by definition, so a successful send means queued. */
    reset();
    script_ok(STAT_OFFLINE);
    script_ok("42");
    memset(reqid, 0, sizeof reqid);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_AGAIN, "migrated -> NGX_AGAIN");
    CHECK(strcmp(reqid, "42") == 0, "the origin's request id is the parking handle");
    CHECK(g_frames == 2, "two frames: the probe and the stage");
    CHECK(frame_opcode(1) == kXR_prepare, "the second frame is kXR_prepare (3021)");
    CHECK(frame_payload_is(1, path), "the staged path is the payload");
    /* options live at body[0]; kXR_noerrs rides along so a path the origin
     * cannot stage fails the READ with its own error rather than the prepare. */
    CHECK(g_frame[1][4] == (kXR_stage | kXR_noerrs),
          "options are kXR_stage|kXR_noerrs");
    CHECK(g_sessions == 2 && g_closes == 2,
          "each step uses its own short-lived session, both closed");

    /* error: the residency probe failing is a hard error and stages nothing. */
    reset();
    script_error(kXR_NotFound);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_ERROR, "unknown path fails");
    CHECK(errno == ENOENT, "errno survives from the residency probe");

    reset();
    g_connect_rc = -1;
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_ERROR,
          "unopenable session fails");
    CHECK(g_frames == 0, "no frame without a session");

    /* A prepare that FAILS is still NGX_AGAIN with an empty reqid: the object is
     * genuinely offline, the read cannot be served now either way, and "retry
     * later" describes that better to a client than a hard error on a hint. */
    reset();
    script_ok(STAT_OFFLINE);
    script_error(kXR_NotAuthorized);
    memset(reqid, 0, sizeof reqid);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_AGAIN,
          "a refused prepare is still NGX_AGAIN");
    CHECK(reqid[0] == '\0', "with no parking handle");

    /* An origin that returns no request id at all is the same soft outcome. */
    reset();
    script_ok(STAT_OFFLINE);
    script_ok("");
    memset(reqid, 0, sizeof reqid);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_AGAIN, "empty reqid -> AGAIN");
    CHECK(reqid[0] == '\0', "and reqid stays empty");

    /* security-negative: a resident path must never be staged (billable MSS work
     * an operator did not ask for), a failed probe must never be staged, and an
     * over-long request id from a remote origin must be truncated into the
     * 40-byte contract rather than overrunning the caller's buffer. */
    reset();
    script_ok(STAT_ONLINE);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_OK, "resident recall ok");
    CHECK(g_frames == 1, "a resident path is never staged");

    reset();
    script_error(kXR_NotAuthorized);
    CHECK(g_drv->recall(g_inst, path, reqid) == NGX_ERROR, "denied probe fails");
    CHECK(g_frames == 1, "a path the origin denied is never staged");

    {
        struct { char id[40]; char guard[8]; } buf;
        static const char huge[] =
            "0123456789012345678901234567890123456789"
            "0123456789012345678901234567890123456789";

        memset(&buf, 0, sizeof buf);
        reset();
        script_ok(STAT_OFFLINE);
        script_ok(huge);
        CHECK(g_drv->recall(g_inst, path, buf.id) == NGX_AGAIN,
              "an over-long request id still queues");
        CHECK(strlen(buf.id) == 39, "truncated to the 40-byte contract");
        CHECK(memcmp(buf.guard, "\0\0\0\0\0\0\0\0", sizeof buf.guard) == 0,
              "and never past it");
    }
}

int
main(void)
{
    build_inst();
    check_space();
    check_query_checksum();
    check_residency();
    check_recall();

    if (failures != 0) {
        fprintf(stderr, "sd_xroot query/nearline slots: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("sd_xroot space/query_checksum/residency/recall contract: PASS\n");
    return 0;
}
