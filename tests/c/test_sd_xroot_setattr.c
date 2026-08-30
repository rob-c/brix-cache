/*
 * test_sd_xroot_setattr.c — the root:// driver's metadata-mutation slot, from
 * the vtable entry point down to the bytes on the wire.
 *
 * WHY THIS UNIT EXISTS: before the slot was wired, brix_vfs_chmod saw a NULL
 * driver->setattr, concluded the backend had no mutable metadata, and returned
 * NGX_OK — so `chmod` over a root:// export reported success while the origin
 * was never told anything. The slot now emits kXR_chmod, and the two halves of
 * that claim both need pinning: that a mode change really leaves the gateway,
 * and that everything the xroot namespace CANNOT represent stays off the wire.
 *
 * The whole stack is real except the socket: sd_xroot_ns.o (the plain slot) →
 * sd_xroot_ns_cred.o (the single implementation) → origin_ns.o
 * (brix_cache_origin_chmod) → wire_codec_ns.o (the kXR_chmod body packer). Only
 * the session bootstrap and the two io primitives are stubbed, so every
 * assertion below is about bytes this code would really send.
 *
 * Arms: success (mode applied, one frame, correct opcode/body/payload, cred
 * threaded), error (each origin refusal mapped to its errno; transport faults;
 * a session that will not open), and security-negative (a times/owner-only
 * setattr must NEVER become a chmod 000 on the wire; file-type and setuid bits
 * must never reach the 16-bit mode field; a bad path must not produce a frame).
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/xroot/sd_xroot.h"
#include "fs/backend/xroot/sd_xroot_internal.h"
#include "protocols/root/protocol/opcodes.h"

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* ---- captured wire state --------------------------------------------------- */

#define MAX_FRAME  4096

static int       g_frames;                 /* brix_cache_io_send calls          */
static u_char    g_frame[MAX_FRAME];       /* the last one, verbatim            */
static size_t    g_frame_len;
static int       g_send_rc;                /* transport fault injection         */

static uint16_t  g_status = kXR_ok;        /* scripted reply status             */
static int       g_errnum;                 /* kXR_error body errnum             */
static int       g_resp_rc;                /* read_response fault injection     */

static int                 g_sessions;      /* origin connects (= sessions)     */
static int                 g_closes;        /* origin_close calls               */
static int                 g_connect_rc;    /* session-open fault injection     */
static char                g_bearer[256];   /* the cred the session carried     */

static void
reset(void)
{
    g_frames = 0;
    g_frame_len = 0;
    memset(g_frame, 0, sizeof g_frame);
    g_send_rc = 0;
    g_status = kXR_ok;
    g_errnum = 0;
    g_resp_rc = 0;
    g_sessions = g_closes = 0;
    g_connect_rc = 0;
    memset(g_bearer, 0, sizeof g_bearer);
    errno = 0;
}

/* ---- stubs: the socket, and nothing above it ------------------------------- */
/* sd_xroot_session itself is REAL (sd_xroot_ns.o) — it is where the credential
 * reaches the fill task and where an unusable one is refused, both of which this
 * unit asserts. Only the connect/bootstrap handshake and the two io primitives
 * stand in for the socket. */

int
brix_cache_origin_connect(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    g_sessions++;
    if (g_connect_rc != 0) {
        t->xrd_error = 3007;                /* kXR_NoMemory-ish; maps to EIO */
        return -1;
    }
    oc->fd = 4242;                          /* never a real socket here */
    /* Snapshot what the session decided to authenticate as. */
    memcpy(g_bearer, t->cred_bearer,
           sizeof t->cred_bearer < sizeof g_bearer
               ? sizeof t->cred_bearer : sizeof g_bearer);
    g_bearer[sizeof g_bearer - 1] = '\0';
    return 0;
}

int
brix_cache_origin_bootstrap(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    (void) t; (void) oc;
    return 0;
}

int
brix_cache_io_send(brix_cache_origin_conn_t *oc, const void *buf, size_t len)
{
    (void) oc;
    g_frames++;
    g_frame_len = len < sizeof g_frame ? len : sizeof g_frame;
    memcpy(g_frame, buf, g_frame_len);
    return g_send_rc;
}

int
brix_cache_read_response(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    uint16_t *status, u_char **body, uint32_t *dlen, uint32_t max_body)
{
    (void) t; (void) oc; (void) max_body;

    if (g_resp_rc != 0) {
        return -1;
    }
    *status = g_status;
    if (g_status == kXR_error) {
        /* kXR_error body: errnum(4, big-endian) + NUL-terminated message. */
        static const char msg[] = "origin refused";
        u_char           *b = calloc(1, 4 + sizeof msg);

        if (b == NULL) { return -1; }
        b[0] = (u_char) ((g_errnum >> 24) & 0xff);
        b[1] = (u_char) ((g_errnum >> 16) & 0xff);
        b[2] = (u_char) ((g_errnum >> 8) & 0xff);
        b[3] = (u_char) (g_errnum & 0xff);
        memcpy(b + 4, msg, sizeof msg);
        *body = b;
        *dlen = (uint32_t) (4 + sizeof msg);
        return 0;
    }
    *body = calloc(1, 1);
    *dlen = 0;
    return *body != NULL ? 0 : -1;
}

/* ---- stubs: the rest of the two linked objects' closure (never called) ------ */

void brix_cache_origin_close(brix_cache_origin_conn_t *oc)
{
    oc->fd = -1;
    g_closes++;
}
void brix_cache_origin_close_file(brix_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{ (void) oc; (void) fhandle; }
int brix_cache_origin_open(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc,
    u_char fhandle[XRD_FHANDLE_LEN])
{ (void) t; (void) oc; (void) fhandle; return -1; }
int brix_cache_origin_open_write(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{ (void) t; (void) oc; (void) path; (void) mode_bits; (void) fhandle; return -1; }
int brix_cache_origin_query_space(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, uint64_t *total_out, uint64_t *free_out)
{ (void) t; (void) oc; (void) total_out; (void) free_out; return -1; }
int brix_cache_origin_read_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    brix_cache_sink_t *sink, brix_cache_read_range_t *rng)
{ (void) t; (void) oc; (void) fhandle; (void) sink; (void) rng; return -1; }
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
int sd_xroot_errno(const brix_cache_fill_t *t) { (void) t; return EIO; }
int xrdp_fattr_nvec_parse(const uint8_t *buf, size_t len, size_t off,
    uint16_t *rc, const uint8_t **name, size_t *nlen, size_t *next_off)
{ (void) buf; (void) len; (void) off; (void) rc; (void) name; (void) nlen;
  (void) next_off; return -1; }

/* ---- wire accessors over the captured frame -------------------------------- */

/* ClientRequestHdr: streamid(2) requestid(2,BE) body(16) dlen(4,BE), then the
 * payload. Read with memcpy so an odd frame offset is never a misaligned load. */
static uint16_t
frame_opcode(void)
{
    uint16_t v;

    memcpy(&v, g_frame + 2, sizeof v);
    return ntohs(v);
}

static uint32_t
frame_dlen(void)
{
    uint32_t v;

    memcpy(&v, g_frame + 20, sizeof v);
    return ntohl(v);
}

/* The kXR_chmod body is reserved(14) mode(2, big-endian) — read the mode field
 * back out of the request body exactly where the protocol puts it. */
static uint16_t
frame_mode(void)
{
    return (uint16_t) ((g_frame[18] << 8) | g_frame[19]);
}

static int
frame_reserved_is_zero(void)
{
    int i;

    for (i = 4; i < 18; i++) {          /* body[0..13] = header bytes 4..17 */
        if (g_frame[i] != 0) { return 0; }
    }
    return 1;
}

static int
frame_payload_is(const char *path)
{
    size_t pl = strlen(path);

    return frame_dlen() == (uint32_t) pl
           && g_frame_len == 24 + pl
           && memcmp(g_frame + 24, path, pl) == 0;
}

/* ---- fixtures -------------------------------------------------------------- */

static ngx_stream_brix_srv_conf_t  g_conf;
static sd_xroot_inst_state         g_state;
static brix_sd_instance_t          g_inst;

static void
build_inst(void)
{
    memset(&g_conf, 0, sizeof g_conf);
    memset(&g_state, 0, sizeof g_state);
    memset(&g_inst, 0, sizeof g_inst);
    g_state.conf = &g_conf;
    g_inst.state = &g_state;
}

static brix_sd_setattr_t
mode_attr(mode_t mode)
{
    brix_sd_setattr_t attr;

    memset(&attr, 0, sizeof attr);
    attr.set_mode = 1;
    attr.mode = mode;
    return attr;
}

/* ---- arm 1: success — the mode really leaves the gateway ------------------- */

static void
check_success(void)
{
    const char        *path = "/store/data/run42.root";
    brix_sd_setattr_t  attr = mode_attr(0640);
    brix_sd_cred_t     cred;

    reset();
    CHECK(sd_xroot_setattr(&g_inst, path, &attr) == NGX_OK, "chmod 0640 ok");
    CHECK(g_frames == 1, "exactly one frame sent");
    CHECK(g_sessions == 1 && g_closes == 1, "one session, opened and closed");
    CHECK(g_bearer[0] == '\0', "plain slot opens the service session");
    CHECK(frame_opcode() == kXR_chmod, "opcode is kXR_chmod (3002)");
    CHECK(frame_mode() == 0640, "mode field carries 0640");
    CHECK(frame_reserved_is_zero(), "the 14 reserved body bytes are zero");
    CHECK(frame_payload_is(path), "payload is the path, dlen its length");

    /* The cred slot is the same body with the caller's credential presented to
     * the session — the whole point of the per-user namespace wrappers. A chmod
     * that authenticated as the service credential would apply a mode change the
     * user may have no right to make. */
    memset(&cred, 0, sizeof cred);
    cred.bearer = "USER.JWT.ALICE";
    reset();
    CHECK(sd_xroot_setattr_cred(&g_inst, path, &attr, &cred) == NGX_OK,
          "cred slot ok");
    CHECK(strcmp(g_bearer, "USER.JWT.ALICE") == 0,
          "the user's bearer, not the service credential, opened the session");
    CHECK(g_frames == 1 && frame_mode() == 0640, "cred slot sends the same body");

    /* Groups the xroot namespace cannot represent are accepted and ignored (the
     * documented sd.h contract), not refused — but they add no second frame. */
    reset();
    attr = mode_attr(0755);
    attr.set_times = 1;
    attr.set_owner = 1;
    attr.uid = 1000;
    attr.gid = 1000;
    CHECK(sd_xroot_setattr(&g_inst, path, &attr) == NGX_OK,
          "mode+times+owner ok");
    CHECK(g_frames == 1, "times/owner add no frame");
    CHECK(frame_mode() == 0755, "the mode group still applied");
}

/* ---- arm 2: error — every refusal reaches the caller ----------------------- */

static void
expect_origin_error(int errnum, int want_errno, const char *msg)
{
    brix_sd_setattr_t attr = mode_attr(0644);

    reset();
    g_status = kXR_error;
    g_errnum = errnum;
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_ERROR, msg);
    CHECK(errno == want_errno, msg);
    CHECK(g_closes == 1, "the session is torn down on the error path");
}

static void
check_errors(void)
{
    brix_sd_setattr_t attr = mode_attr(0644);

    expect_origin_error(kXR_NotFound, ENOENT, "missing path -> ENOENT");
    expect_origin_error(kXR_NotAuthorized, EACCES, "refused chmod -> EACCES");
    expect_origin_error(kXR_isDirectory, EISDIR, "kXR_isDirectory -> EISDIR");
    expect_origin_error(kXR_ArgInvalid, EIO, "unmapped origin error -> EIO");

    /* A transport fault on either leg is EIO, not a silent success. */
    reset();
    g_send_rc = -1;
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_ERROR,
          "send fault -> error");
    CHECK(errno == EIO, "send fault -> EIO");

    reset();
    g_resp_rc = -1;
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_ERROR,
          "read fault -> error");
    CHECK(errno == EIO, "read fault -> EIO");

    /* A session that will not open surfaces ITS errno and sends nothing. */
    reset();
    g_connect_rc = -1;
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_ERROR,
          "session refused -> error");
    CHECK(errno == EIO, "session errno preserved");
    CHECK(g_frames == 0, "no frame without a session");

    /* A NULL request is a caller bug, not a chmod. */
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", NULL) == NGX_ERROR,
          "NULL attr -> error");
    CHECK(errno == EINVAL, "NULL attr -> EINVAL");
    CHECK(g_sessions == 0 && g_frames == 0, "NULL attr opens no session");
}

/* ---- arm 3: security-negative — what must NEVER reach the wire ------------- */

static void
check_security(void)
{
    brix_sd_setattr_t attr;
    char              huge[0x8010];

    /* THE one that matters: a times-only or owner-only setattr must not become
     * a chmod of the zeroed mode field. Sending it would strip every permission
     * bit off the object — a `touch -d` turning into `chmod 000`. The slot must
     * not merely mask that out: it must open no session and send no frame. */
    memset(&attr, 0, sizeof attr);
    attr.set_times = 1;
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_OK,
          "times-only setattr succeeds");
    CHECK(g_frames == 0, "times-only setattr sends NO chmod");
    CHECK(g_sessions == 0, "times-only setattr opens no session");

    memset(&attr, 0, sizeof attr);
    attr.set_owner = 1;
    attr.uid = 0;                       /* and certainly not a chown to root */
    attr.gid = 0;
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_OK,
          "owner-only setattr succeeds");
    CHECK(g_frames == 0, "owner-only setattr sends NO chmod");

    memset(&attr, 0, sizeof attr);      /* nothing set at all */
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/x.dat", &attr) == NGX_OK,
          "empty setattr succeeds");
    CHECK(g_frames == 0 && g_sessions == 0, "empty setattr is a pure no-op");

    /* File-type bits must never reach the 16-bit mode field: S_IFDIR is 0040000,
     * which truncates to 0x4000 on the wire and would read as a bit pattern the
     * origin never meant to receive. Only the low nine bits travel. */
    attr = mode_attr((mode_t) (S_IFDIR | 0777));
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/d", &attr) == NGX_OK, "S_IFDIR|0777 ok");
    CHECK(frame_mode() == 0777, "file-type bits stripped from the wire mode");

    attr = mode_attr((mode_t) (S_IFREG | 0644));
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/f", &attr) == NGX_OK, "S_IFREG|0644 ok");
    CHECK(frame_mode() == 0644, "regular-file type bit stripped");

    /* setuid/setgid/sticky have no XRootD encoding: 04755 must go out as 0755,
     * never as 04755 truncated into a field the origin reads as something else. */
    attr = mode_attr(04755);
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/s", &attr) == NGX_OK, "04755 ok");
    CHECK(frame_mode() == 0755, "setuid bit never reaches the wire");

    attr = mode_attr(01777);
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/t", &attr) == NGX_OK, "01777 ok");
    CHECK(frame_mode() == 0777, "sticky bit never reaches the wire");

    /* An explicit chmod 000 is the caller's decision and does travel — the point
     * of the arm above is that an UNASKED-FOR one does not. */
    attr = mode_attr(0);
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "/z", &attr) == NGX_OK, "explicit 000 ok");
    CHECK(g_frames == 1 && frame_mode() == 0, "explicit 000 is sent verbatim");

    /* A deny-mode request whose credential resolved to nothing must NOT quietly
     * fall back to the static service credential and chmod as the gateway. */
    {
        brix_sd_cred_t empty;

        memset(&empty, 0, sizeof empty);
        empty.fallback_deny = 1;
        attr = mode_attr(0777);
        reset();
        CHECK(sd_xroot_setattr_cred(&g_inst, "/x.dat", &attr, &empty)
              == NGX_ERROR, "unusable cred under fallback_deny fails");
        CHECK(errno == EACCES, "unusable cred -> EACCES");
        CHECK(g_frames == 0 && g_sessions == 0,
              "no service-credential chmod behind the user's back");
    }

    /* A path the wire cannot carry is refused before any frame is built. */
    attr = mode_attr(0644);
    reset();
    CHECK(sd_xroot_setattr(&g_inst, "", &attr) == NGX_ERROR, "empty path fails");
    CHECK(errno == EINVAL && g_frames == 0, "empty path -> EINVAL, no frame");

    reset();
    CHECK(sd_xroot_setattr(&g_inst, NULL, &attr) == NGX_ERROR, "NULL path fails");
    CHECK(errno == EINVAL && g_frames == 0, "NULL path -> EINVAL, no frame");

    memset(huge, 'a', sizeof huge - 1);
    huge[sizeof huge - 1] = '\0';
    reset();
    CHECK(sd_xroot_setattr(&g_inst, huge, &attr) == NGX_ERROR,
          "oversized path fails");
    CHECK(errno == EINVAL && g_frames == 0,
          "a path past the 0x7fff dlen limit never becomes a frame");
}

int
main(void)
{
    build_inst();
    check_success();
    check_errors();
    check_security();

    if (failures != 0) {
        fprintf(stderr, "sd_xroot setattr/kXR_chmod: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("sd_xroot setattr -> kXR_chmod contract: PASS\n");
    return 0;
}
