#ifndef BRIX_GFTP_CLIENT_H
#define BRIX_GFTP_CLIENT_H

/* Blocking GridFTP client kernel used only from VFS worker threads. */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define GFTP_CONTROL_CAP 65536
#define GFTP_TEXT_CAP    65536
#define GFTP_COMMAND_CAP 4096
#define GFTP_ADAT_LINE_CAP (128 * 1024)

/* Continuation lines kept from the last multiline reply.  Small on purpose:
 * the only caller is the FEAT capability probe, and a capability list is a
 * short enumeration of verbs, not a payload — an origin that sends more than
 * this is truncated rather than believed (see gftp_session_t::cont). */
#define GFTP_CONT_CAP 2048

typedef struct gftp_gsi_s gftp_gsi_t;

/* Data-channel transfer mode and protection (phase-115 W5.1).  Both are chosen
 * on the store line, negotiated once per control session, and never inferred:
 * an origin that cannot honour the request fails the transfer rather than
 * silently transferring under weaker terms. */
typedef enum {
    GFTP_DMODE_S = 0,   /* RFC 959 stream mode — the phase-91 default        */
    GFTP_DMODE_E = 1    /* GFD.020 3.4 extended block mode (offset-addressed) */
} gftp_dmode_t;

typedef enum {
    GFTP_DPROT_C = 0,   /* clear data channel — the phase-91 default         */
    GFTP_DPROT_P = 1    /* private: TLS on the data socket, DCAU A            */
} gftp_dprot_t;

/* Upper bound on data connections a single MODE E transfer may reassemble, and
 * therefore the ceiling on the `streams=<n>` store param (W5.3).  Every one of
 * them is a socket held by ONE blocking VFS worker thread for the length of a
 * transfer, so the cap is a resource bound, not a protocol one. */
#define GFTP_STREAMS_MAX 16

typedef struct {
    int         fd;
    int         timeout_ms;
    int         code;
    int         secure;
    size_t      buffered;
    char        input[GFTP_CONTROL_CAP];
    char        text[GFTP_TEXT_CAP];
    char        peer_ip[64];
    char        error[256];
    gftp_gsi_t *gsi;

    /* ---- data-channel policy (phase-115 W5.1) ------------------------------
     * `want_*` is what the store line asked for; `mode` is what the wire is
     * actually set to right now, so a listing can drop back to MODE S between
     * transfers without re-sending MODE on every command.  proxy_path/ca_dir are
     * BORROWED from the caller's configuration (they outlive the session, which
     * is opened and closed inside one storage-driver call) and are re-presented
     * on a PROT P data channel. */
    gftp_dmode_t  mode;
    gftp_dmode_t  want_mode;
    gftp_dprot_t  prot;
    gftp_dprot_t  want_prot;
    const char   *proxy_path;
    const char   *ca_dir;
    char          peer_dn[256];   /* control-channel peer DN; "" when clear   */

    /* ---- advertised extensions (phase-115 W5.2) ----------------------------
     * `feat` is meaningful only once `feat_probed` is set: zero means either
     * "not asked yet" or "asked, advertises nothing", and only the flag tells
     * the two apart.  See gftp_feat.h for why the probe is lazy.
     *
     * `cont` holds the CONTINUATION lines of the last multiline reply, which is
     * where a FEAT reply keeps every feature it advertises — `text` gets only
     * the terminator line, a bare "End".  `cont_truncated` says the origin sent
     * more than GFTP_CONT_CAP.
     *
     * What truncation MEANS is per-reader, and the two readers differ.  For
     * FEAT it fails safe on its own: a cut line cannot begin a new one, so
     * truncation can only LOSE a feature, never invent one.  For a SPAS reply
     * (phase-115 W5.3) it would silently DROP STRIPES, and the receiver would
     * then wait for EOD blocks on connections nobody opened — so gftp_spas.c
     * refuses a truncated reply outright rather than reading what survived. */
    unsigned      feat;
    int           feat_probed;
    int           cont_truncated;
    char          cont[GFTP_CONT_CAP];

    /* ---- striped data channel (phase-115 W5.3) -----------------------------
     * How many data connections ONE retrieve may open, from the store line's
     * `streams=<n>`; 1 (the default) means the driver never asks for a striped
     * channel.  Unlike want_mode/want_prot this is a CEILING rather than a
     * requirement: striping changes how fast the same verified bytes arrive,
     * not what they are, so an origin that cannot offer it is served by the
     * single pinned connection instead of failing.  See gftp_spas.h. */
    unsigned      want_streams;
} gftp_session_t;

struct brix_dns_policy_s;   /* net/dns/dns.h: the export's resolver policy */

typedef struct {
    const char *host;
    int         port;
    int         timeout_ms;
    int         require_gsi;
    const char *proxy_path;
    const char *ca_dir;
    const struct brix_dns_policy_s *dns;   /* phase-116: host resolves under it */
    gftp_dmode_t mode;                     /* phase-115 W5.1: MODE S | MODE E  */
    gftp_dprot_t prot;                     /* phase-115 W5.1: PROT C | PROT P  */
    unsigned     streams;                  /* phase-115 W5.3: 0/1 = unstriped  */
} gftp_session_cfg_t;

/* A retrieve sink is POSITIONED: `offset` is relative to the transfer's start
 * offset, never a running cursor.  MODE E delivers offset-addressed blocks that
 * may arrive out of order across parallel data connections, so a sequential sink
 * cannot express the contract; MODE S simply passes its own running count. */
typedef int (*gftp_sink_fn)(void *ctx, off_t offset, const uint8_t *data,
    size_t len);
typedef ssize_t (*gftp_source_fn)(void *ctx, uint8_t *data, size_t cap);

int gftp_session_open(gftp_session_t *session,
    const gftp_session_cfg_t *cfg);
int gftp_authenticate(gftp_session_t *session,
    const gftp_session_cfg_t *cfg);
void gftp_session_close(gftp_session_t *session);
int gftp_read_reply(gftp_session_t *session);
int gftp_command(gftp_session_t *session, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
int gftp_expect(gftp_session_t *session, int low, int high,
    const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void gftp_set_error(gftp_session_t *session, int err, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
ssize_t gftp_socket_read(gftp_session_t *session, int fd, void *buf,
    size_t cap);
int gftp_socket_write_all(gftp_session_t *session, int fd, const void *buf,
    size_t len);

int gftp_retrieve(gftp_session_t *session, const char *path, off_t offset,
    size_t limit, gftp_sink_fn sink, void *ctx, size_t *received);
int gftp_store(gftp_session_t *session, const char *path,
    gftp_source_fn source, void *ctx);
int gftp_slurp(gftp_session_t *session, const char *command,
    char **out, size_t *out_len);

#endif /* BRIX_GFTP_CLIENT_H */
