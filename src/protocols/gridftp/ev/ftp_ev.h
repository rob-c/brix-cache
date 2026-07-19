#ifndef BRIX_GRIDFTP_EV_H
#define BRIX_GRIDFTP_EV_H

/*
 * gridftp/ev/ftp_ev.h — event-driven GridFTP gateway: shared per-connection
 * context, state enum, and cross-file declarations.
 *
 * WHAT: declares ftp_ev_t (the per-connection state machine), the control-plane
 * state enum, the buffer geometry constants, and every function exported between
 * the ev/ translation units (I/O engine, reply framing, path resolution,
 * dispatcher, command handlers).
 *
 * WHY: this tree drives the whole RFC 959 / GFD.020 dialogue as a non-blocking
 * nginx STREAM module: the connection's read/write events drive a command→reply
 * state machine, so a single worker multiplexes many sessions rather than pinning
 * one client per worker on a blocking socket.
 *
 * HOW: brix_ftp_ev_handler() is installed as the stream content handler.  It
 * allocates an ftp_ev_t on the connection pool, wires the read/write event
 * handlers, and returns to the event loop.  All subsequent I/O is buffered:
 * inbound bytes accumulate in ->buf (framed into command lines), replies
 * accumulate in ->ob (flushed with short-write handling).  Commands are processed
 * lock-step — the next command is only dispatched once the current reply has
 * fully drained — which bounds outbound buffering to one reply at a time and
 * mirrors the half-duplex control-channel semantics FTP clients rely on.
 */

#include "protocols/gridftp/ftp_gateway.h" /* ngx_stream_brix_ftp_srv_conf_t   */
#include "protocols/gridftp/ftp_eblock.h" /* MODE E framing + ftp_eb_range_t   */

#include "core/types/identity.h"         /* brix_identity_t                    */
#include "auth/gssapi/gsi_mech.h"        /* brix_gssapi_srv_t (RFC 2228 GSI)   */

#include <netinet/in.h>                  /* struct sockaddr_in (active target) */

/* Buffer geometry — kept identical to the sync engine for behavioural parity.
 * The inbound ceiling must hold a single GSI ADAT line: the client-cert flight
 * (proxy + issuer chain, base64) is many KB on one line, and an unterminated
 * line that fills the buffer is rejected as "line too long" (drops the session).
 */
#define BRIX_FTP_EV_CMD_MAX   (128 * 1024) /* inbound command / ADAT line cap  */
#define BRIX_FTP_EV_OB_CAP    (64 * 1024)  /* outbound reply buffer (per conn) */
#define BRIX_FTP_EV_LINE_MAX  2048         /* fixed-buffer reply formatting    */
#define BRIX_FTP_EV_IO_TIMEO  30000        /* ms: idle control-channel deadline */
#define BRIX_FTP_EV_XFER_BUF  (64 * 1024)  /* data-channel transfer chunk      */
#define BRIX_FTP_EV_DATA_BACKLOG 64        /* passive listen backlog (MODE E)  */
#define BRIX_FTP_EV_EB_MAX_CONNS  64       /* MODE E: concurrent passive streams */
#define BRIX_FTP_EV_EB_MAX_RANGES 8192     /* MODE E: committed-range table cap  */


/* Directory-listing formats for the LIST/NLST/MLSD data verbs (matches the sync
 * engine's ftp_list_dir modes). */
enum { FTP_EV_LS_NLST = 0, FTP_EV_LS_LONG, FTP_EV_LS_MLSD };


/* Opaque VFS handles — the data pump only ever holds them by pointer, so the
 * header need not pull in the full VFS surface. */
typedef struct brix_vfs_file_s   brix_vfs_file_t;
typedef struct brix_vfs_dir_s    brix_vfs_dir_t;
typedef struct brix_vfs_writer_s brix_vfs_writer_t;

typedef struct ftp_ev_dc_s ftp_ev_dc_t;


/* Control-plane state.  P82.1 uses CMD/CLOSING; XFER (a data transfer holding
 * the command channel half-open) arrives with the event data channels (P82.2). */
typedef enum {
    FTP_EV_ST_CMD = 0,        /* idle / awaiting or framing the next command   */
    FTP_EV_ST_XFER,           /* a data transfer is in progress (P82.2)        */
    FTP_EV_ST_CLOSING         /* final reply queued; close once ->ob drains    */
} ftp_ev_state_e;


/* Per-connection dialogue state for the event-driven engine. */
typedef struct {
    ngx_stream_session_t            *s;      /* owning stream session          */
    ngx_connection_t                *c;      /* == s->connection (control)     */
    ngx_stream_brix_ftp_srv_conf_t  *conf;   /* per-server gateway config      */

    ftp_ev_state_e  state;

    /* Inbound command reader: bytes accumulate in buf[bpos..blen); a complete
     * CRLF-framed line is handed to the dispatcher.  Sized for GSI ADAT lines. */
    u_char  buf[BRIX_FTP_EV_CMD_MAX];
    size_t  blen;                            /* bytes present                  */
    size_t  bpos;                            /* bytes already consumed         */

    /* Outbound reply buffer: replies append at [ob_len], the flusher drains
     * from [ob_pos]; both reset to 0 once fully sent.  Lock-step processing
     * keeps at most one command's replies resident here at a time. */
    u_char *ob;
    size_t  ob_len;
    size_t  ob_pos;

    /* ---- session / transfer parameters ---- */
    char    cwd[PATH_MAX];                   /* logical CWD, always '/'-rooted */
    int     type_binary;                     /* TYPE I vs A (informational)    */
    int     authed;                          /* USER+PASS or GSI accepted      */
    int     mode_e;                          /* 1 = MODE E extended-block      */
    int     parallelism;                     /* OPTS RETR Parallelism hint     */
    off_t   rest_off;                        /* REST restart offset (one-shot) */
    off_t   allo_size;                       /* ALLO declared file size, -1 =  */
                                             /*   unset (one-shot, per STOR)   */
    char    rnfr[PATH_MAX];                  /* RNFR source awaiting RNTO      */
    int     rnfr_set;

    /* ---- data channel target (the event pump hangs off these) ---- */
    int                 pasv_fd;             /* passive listen fd (-1 = none)  */
    char                prot;                /* 'C' clear or 'P' TLS data ch   */
    int                 dcau_a;              /* client negotiated DCAU A       */
    int                 active;              /* 1 = connect out (PORT/EPRT)    */
    int                 active_offpeer;      /* target != control peer (TPC)   */
    struct sockaddr_in  active_sa;           /* client-nominated data endpoint */
    ftp_ev_dc_t        *dc;                  /* in-flight transfer (NULL idle) */

    /* ---- RFC 2228 GSI security layer (gsiftp://) ---- */
    brix_gssapi_srv_t *gss;                  /* mem-BIO engine (NULL pre-AUTH) */
    int               sec_active;            /* control channel GSS-wrapped    */
    const char       *wrap_code;             /* reply safety code (631/632/633)*/
    brix_identity_t  *identity;              /* verified proxy principal       */
    ngx_str_t         deleg_proxy;           /* delegated credential PEM       */
    ngx_str_t         ctrl_dn;               /* control-channel verified DN    */
    ngx_str_t         ctrl_leaf_pem;         /* client control leaf PEM        */

    unsigned  greeted:1;                     /* 220 greeting queued            */
    unsigned  destroyed:1;                   /* finalize is idempotent         */
} ftp_ev_t;


/* Data-transfer verb selector, shared by the dispatcher and the data pump. */
enum {
    FTP_EV_OP_RETR = 0, FTP_EV_OP_STOR, FTP_EV_OP_LIST,
    FTP_EV_OP_NLST, FTP_EV_OP_MLSD, FTP_EV_OP_APPE
};


/* Per-transfer data-channel context (ftp_ev_data.c).  Allocated on the control
 * connection pool when a transfer verb starts, torn down when it finishes.  Only
 * one transfer is ever in flight per control session (half-duplex FTP), so the
 * control session holds a single ->dc.  The VFS side (fh/writer/dh) is opened
 * once the data connection is established, then the pump moves bytes between it
 * and dconn under the event loop, never blocking on the socket. */
struct ftp_ev_dc_s {
    ftp_ev_t          *fc;          /* owning control session               */
    ngx_connection_t  *lc;          /* passive listener conn (NULL = active) */
    ngx_connection_t  *dconn;       /* data connection (NULL until up)       */
    int                op;          /* FTP_EV_OP_*                          */
    int                connecting;  /* active mode: connect() in flight      */
    int                writing;     /* STOR/APPE (client → server)          */
    int                tls_client;  /* PROT P: connect role (TLS client)     */

    brix_vfs_file_t   *fh;          /* RETR source handle                    */
    brix_vfs_writer_t *writer;      /* STOR/APPE sink                        */
    brix_vfs_dir_t    *dh;          /* LIST/NLST/MLSD directory              */
    int                ls_mode;     /* FTP_EV_LS_* for a listing            */
    ngx_pool_t        *dpool;       /* per-transfer pool for the TLS conn    */
    off_t              off;         /* current file offset                   */
    off_t              size;        /* RETR total size                       */
    off_t              allo_size;   /* STOR: ALLO-declared file size, -1 off */
    unsigned           flags;       /* writer open flags (TRUNC)            */
    int                verify;      /* writer read-back verify (whole STOR)  */

    /* Transfer buffer: RETR/LIST fill it from the source and drain to the
     * socket; STOR fills it from the socket and drains to the writer. */
    u_char            *buf;
    size_t             buf_len;     /* valid bytes                           */
    size_t             buf_pos;     /* bytes already handed to the sink      */
    int                src_eof;     /* source exhausted (VFS/readdir/peer)   */

    /* ---- MODE E extended-block transfer (ftp_ev_mode_e.c) ---- */
    int                mode_e;      /* 1 = extended-block framing this xfer  */
    int                eb_phase;    /* RETR framing: 0 data, 1 trailer, 2 done */
    ftp_eb_range_t    *eb_ranges;   /* STOR: committed ranges (overlap guard) */
    ftp_eb_range_t    *eb_scratch;  /* STOR: 111-marker coalescing workspace  */
    size_t             eb_nranges;
    long               eb_eof_total;/* STOR: -1 until an EOF block declares it */
    long               eb_eod_seen; /* STOR: one EOD per finished child stream */
    off_t              eb_received; /* STOR: bytes committed so far           */
    off_t              eb_marked;   /* STOR: bytes at the last marker emission */
    void              *eb_conns;    /* STOR: ftp_ev_eb_conn_t[] child streams  */
    int                eb_nconns;   /* STOR: children currently live           */

    char               abs[PATH_MAX];
};


/* ---- ftp_ev_io.c : the non-blocking engine ---- */
void      brix_ftp_ev_handler(ngx_stream_session_t *s);
void      brix_ftp_ev_finalize(ftp_ev_t *fc, ngx_int_t rc);
void      brix_ftp_ev_resume(ftp_ev_t *fc);      /* re-enter the control loop */
ngx_int_t brix_ftp_ev_flush(ftp_ev_t *fc);       /* NGX_OK drained / NGX_AGAIN / NGX_ERROR */

/* ---- ftp_ev_reply.c : reply framing (cleartext or GSS-wrapped) ---- */
ngx_int_t brix_ftp_ev_reply(ftp_ev_t *fc, const char *fmt, ...);
ngx_int_t brix_ftp_ev_send_adat(ftp_ev_t *fc, int code, ngx_str_t *tok);
ngx_int_t brix_ftp_ev_b64_decode(ngx_pool_t *pool, const char *b64, ngx_str_t *out);

/* ---- ftp_ev_path.c : path + VFS helpers ---- */
char     *brix_ftp_ev_split(char *line, char **verb_out);
int       brix_ftp_ev_resolve(ftp_ev_t *fc, const char *arg, char *abs, size_t abssz);
void      brix_ftp_ev_vfs_ctx(ftp_ev_t *fc, const char *abs, void *vctx /* brix_vfs_ctx_t* */);

/* ---- ftp_ev_dispatch.c : the command dispatcher ---- */
ngx_int_t brix_ftp_ev_dispatch(ftp_ev_t *fc, char *line);

/* ---- ftp_ev_cmd.c : per-verb handlers (return NGX_OK / NGX_DONE / NGX_ERROR) ---- */
ngx_int_t brix_ftp_ev_cmd_cwd(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_size(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_mkd(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_dele(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_rmd(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_mdtm(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_mlst(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_stat(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_cksm(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_rnfr(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_rnto(ftp_ev_t *fc, const char *arg);

/* ---- ftp_ev_sec.c : RFC 2228 GSI control-channel handshake ---- */
ngx_int_t brix_ftp_ev_cmd_auth(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_adat(ftp_ev_t *fc, const char *arg);
ngx_int_t brix_ftp_ev_cmd_protected(ftp_ev_t *fc, const char *code, const char *arg);

/* ---- ftp_ev_xfer.c : data-transfer verbs + the RETR/STOR/LIST pump ---- */
ngx_int_t brix_ftp_ev_do_transfer(ftp_ev_t *fc, int kind, const char *arg);

/* ---- ftp_ev_data.c : non-blocking data-channel lifecycle ---- */
ngx_int_t brix_ftp_ev_data_setup(ftp_ev_t *fc, int kind, const char *arg);
ngx_int_t brix_ftp_ev_data_open(ftp_ev_dc_t *dc);
void      brix_ftp_ev_data_finish(ftp_ev_dc_t *dc, ngx_int_t rc);
/* Wrap an open data fd in an nginx connection (shared with the MODE E receiver). */
ngx_connection_t *brix_ftp_ev_wrap_conn(ftp_ev_t *fc, int fd);
/* Implemented in ftp_ev_xfer.c, called by ftp_ev_data.c once the socket is up. */
void      brix_ftp_ev_data_ready(ftp_ev_dc_t *dc);

/* ---- ftp_ev_tls.c : PROT P data-channel TLS (GSI DCAU A) ---- */
/* Drive the data-channel TLS handshake off the data connection's events, then
 * hand off to brix_ftp_ev_data_ready().  Called (in place of data_ready) once the
 * socket is up when fc->prot == 'P'; reports failure via brix_ftp_ev_data_finish. */
void      brix_ftp_ev_dc_start_tls(ftp_ev_dc_t *dc);

/* Reusable handshake primitives (shared by the single data connection and each
 * MODE E child stream).  _begin drives the non-blocking handshake — creates the
 * per-connection pool (*poolp), the SSL from the gateway ctx, installs the
 * delegated credential + TLS policy, sets `done` as the ssl->handler, and starts
 * the handshake: returns NGX_AGAIN (armed; `done` fires later), NGX_OK (completed
 * inline; `done` already invoked), or NGX_ERROR (nothing armed — caller cleans
 * up).  _verify is the post-handshake identity gate (handshaked + GSI DN pin). */
ngx_int_t brix_ftp_ev_tls_begin(ftp_ev_t *fc, ngx_connection_t *c,
              ngx_pool_t **poolp, int tls_client, void (*done)(ngx_connection_t *));
ngx_int_t brix_ftp_ev_tls_verify(ftp_ev_t *fc, ngx_connection_t *c);

/* ---- ftp_ev_mode_e.c : MODE E (GFD.020 §3.4) extended-block transfers ---- */
/* RETR: frame the source over the single data connection as extended blocks. */
void      brix_ftp_ev_retr_mode_e_start(ftp_ev_dc_t *dc);
/* STOR: passive listener read handler — accepts up to `Parallelism` streams and
 * reassembles the out-of-order extended blocks they carry into the VFS writer. */
void      brix_ftp_ev_eb_accept(ngx_event_t *rev);
/* Close every live MODE E child stream (called from brix_ftp_ev_data_finish). */
void      brix_ftp_ev_eb_teardown(ftp_ev_dc_t *dc);

#endif /* BRIX_GRIDFTP_EV_H */
