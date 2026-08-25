#include "query_internal.h"
#include "core/compat/codec_core.h"
#include "core/ident.h"

#include <stdarg.h>
#include <stdio.h>

/*
 * WHAT: kXR_Qconfig — best-effort server capability query returning known feature flags as key=value lines.
 *       Parses whitespace-separated query keys from payload, responds with supported algorithms (chksum), readv support,
 *       TPC availability (tpc=1/0 based on allow_write+thread_pool), and HTTP-TPC delegation status (tpcdlg). Unknown keys return =0.
 *
 * WHY:  XRootD clients (xrdcp, xrdfs) query server capabilities before attempting operations like TPC transfer or readv parallel reads.
 *       This response matches reference XRootD format so client libraries can parse and decide accordingly — e.g., XrdCl parses tpc line
 *       with isdigit()+atoi() expecting just "1" or "0". Empty query returns OK with no payload for compatibility.
 *
 * HOW:  brix_query_config() initializes resp buffer (512 bytes), parses whitespace-separated keys via qconfig_next_token
 *       loop, and dispatches each key through a static descriptor table {key, emit_fn} — one emitter per supported
 *       capability, each appending its key=value line(s) via qconfig_append (vsnprintf with capacity tracking).
 *       Unknown keys echo the key name. Empty query returns kXR_ArgMissing; populated response sends resp at pos bytes.
 */

/* WHAT: Advances the pointer *pp past any whitespace characters (space, tab, newline, carriage return). Used as a preamble before extracting tokens from kXR_Qconfig query payload.
 * WHY: kXR_Qconfig accepts whitespace-separated keys in its payload; this helper ensures token extraction starts at valid non-whitespace boundaries without accidentally capturing separator characters. Standard ASCII whitespace set covers all common delimiters used in client queries.
 * HOW: Single while loop checking **pp against ' ', '\t', '\n', '\r' — increments pointer past each whitespace character until reaching a non-whitespace byte or null terminator. */

static void
brix_qconfig_skip_ws(const char **pp)
{
    while (**pp == ' ' || **pp == '\t' || **pp == '\n' || **pp == '\r') {
        (*pp)++;
    }
}

/* WHAT: Extracts a single token from the payload pointer *pp, skipping leading whitespace first then reading characters until next whitespace or null terminator. Stores extracted token in tok buffer with null termination, returns 1 on success (token found), 0 on failure (end of payload). Enforces tok_sz boundary to prevent overflow.
 * WHY: kXR_Qconfig query payloads contain whitespace-separated capability keys (e.g., "tpc tpcdlg chksum"). This helper enables sequential token extraction without allocating temporary buffers or using strchr-based splitting — efficient for single-threaded nginx event loop processing.
 * HOW: Two-phase → first calls brix_qconfig_skip_ws() to advance past leading whitespace, then reads characters while **pp != '\0' and not whitespace, storing each char in tok[len++] with null termination at len = tok_sz - 1 or end-of-token boundary. Returns 1 if token extracted, 0 if *pp points to '\0' (end of payload). */

static ngx_flag_t
brix_qconfig_next_token(const char **pp, char *tok, size_t tok_sz)
{
    size_t len;

    brix_qconfig_skip_ws(pp);
    if (**pp == '\0') {
        return 0;
    }

    len = 0;
    while (**pp != '\0' && **pp != ' ' && **pp != '\t'
           && **pp != '\n' && **pp != '\r')
    {
        if (len + 1 < tok_sz) {
            tok[len++] = **pp;
        }
        (*pp)++;
    }

    tok[len] = '\0';
    return 1;
}

/* WHAT: Appends formatted text to a response buffer using vsnprintf, tracking the current position via *pos parameter. Returns 1 on success (formatted output fit within remaining buffer), 0 on failure (overflow or NULL pointers). Enforces resp_sz + pos bounds to prevent response buffer overflow during query capability reporting.
 * WHY: kXR_Qconfig builds a multi-line capability report by appending individual key=value pairs; this helper ensures each append respects the 512-byte resp buffer limit without truncating mid-response or corrupting prior output. vsnprintf with remaining capacity calculation prevents format string attacks from exceeding bounds.
 * HOW: Calculate remaining = resp_sz - *pos, call vsnprintf(resp + *pos, remaining, fmt, ap), check n < 0 || (size_t)n >= remaining for overflow → return 0 on failure or update *pos += n and return 1 on success. NULL pointer checks prevent crashes on malformed input. */

static ngx_flag_t
brix_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
    const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static ngx_flag_t
brix_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
    const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  remaining;

    if (resp == NULL || pos == NULL || *pos >= resp_sz) {
        return 0;
    }

    remaining = resp_sz - *pos;

    va_start(ap, fmt);
    n = vsnprintf(resp + *pos, remaining, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= remaining) {
        resp[*pos] = '\0';
        return 0;
    }

    *pos += (size_t) n;
    return 1;
}

/* WHAT: Per-key emitter signature for the kXR_Qconfig descriptor table — appends one capability's value line(s)
 *       to the response buffer, returning 1 on success or 0 on buffer overflow (which aborts the token loop).
 * WHY: kXR_Qconfig is a pure name→value lookup; a static {key, emit_fn} table plus one dispatch loop replaces
 *      the former strcmp if/else ladder, keeping each emitter single-purpose and the dispatcher trivially flat.
 * HOW: Each emitter receives the server conf (for capability flags/limits) plus the shared resp/resp_sz/pos
 *      accounting used by brix_qconfig_append. */
typedef ngx_flag_t (*brix_qconfig_emit_fn)(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos);

/* WHAT: Builds a comma-separated list of the inline-compression codecs actually built into this binary
 *       (zstd/lz4/... per brix_codec_by_id availability) into list[list_sz].
 * WHY: cmpread and cmpwrite both advertise the identical built-in codec set — sharing the walk keeps the
 *      two emitters symmetric and byte-identical, and avoids duplicating the overflow-guarded snprintf loop.
 * HOW: Iterates codec ids 1..BRIX_CODEC_MAX, skipping unavailable descriptors, appending "name" with a ","
 *      separator after the first entry; stops early on snprintf overflow. list is always null-terminated. */
static void
brix_qconfig_codec_list(char *list, size_t list_sz)
{
    size_t          lp = 0;
    brix_codec_id_t cid;

    list[0] = '\0';
    for (cid = (brix_codec_id_t) 1; cid < BRIX_CODEC_MAX; cid++) {
        const brix_codec_desc_t *d = brix_codec_by_id(cid);
        int n;

        if (d == NULL || !d->available) {
            continue;
        }
        n = snprintf(list + lp, list_sz - lp, "%s%s",
                     lp ? "," : "", d->name);
        if (n < 0 || (size_t) n >= list_sz - lp) {
            break;
        }
        lp += (size_t) n;
    }
}

/* WHAT: Emits the max bytes per readv element for "readv_ior_max".
 * WHY: The official "maxReadv_ior". Reported as a bare integer (no key= prefix), matching reference
 *      XRootD, so XrdCl sizes each VectorRead element to our configured brix_readv_segment_size and
 *      never overshoots the per-element cap.
 * HOW: Appends conf->readv_segment_size as %lu + newline. */
static ngx_flag_t
brix_qconfig_emit_readv_ior_max(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    return brix_qconfig_append(resp, resp_sz, pos, "%lu\n",
                               (unsigned long) conf->readv_segment_size);
}

/* WHAT: Emits the inline compression codec list for "cmpread"/"cmpwrite" —
 *       `key=<built-in codec CSV>` when the direction is enabled, else `key=0`.
 * WHY: phase-42 W4/W5: advertise the codecs this build can compress kXR_read
 *      responses with / decompress kXR_write payloads with, so a willing client
 *      knows whether to send "?xrootd.compress=". Read and write share one
 *      emitter so the two directions cannot drift; invisible to stock clients,
 *      which never query these keys.
 * HOW: enabled → brix_qconfig_codec_list CSV, else the literal "0". */
static ngx_flag_t
brix_qconfig_emit_cmp(ngx_flag_t enabled, const char *key,
    char *resp, size_t resp_sz, size_t *pos)
{
    char list[160];

    if (!enabled) {
        return brix_qconfig_append(resp, resp_sz, pos, "%s=0\n", key);
    }

    brix_qconfig_codec_list(list, sizeof(list));
    return brix_qconfig_append(resp, resp_sz, pos, "%s=%s\n", key, list);
}

static ngx_flag_t
brix_qconfig_emit_cmpread(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    return brix_qconfig_emit_cmp(conf->read_compress, "cmpread",
                                 resp, resp_sz, pos);
}

static ngx_flag_t
brix_qconfig_emit_cmpwrite(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    return brix_qconfig_emit_cmp(conf->write_compress, "cmpwrite",
                                 resp, resp_sz, pos);
}

/* WHAT: Emits the server role for the "role" query key.
 * WHY: Reference do_Qconf returns the bare $XRDROLE (XrdOfsConfig exports it from the configured role).
 *      A standalone data server reports "server"; in manager/redirector mode it reports "manager".
 * HOW: Appends "manager" or "server" per conf->manager_mode + newline. */
static ngx_flag_t
brix_qconfig_emit_role(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    return brix_qconfig_append(resp, resp_sz, pos, "%s\n",
                               conf->manager_mode ? "manager" : "server");
}

/* WHAT: Static descriptor table mapping each supported kXR_Qconfig key to its
 *       response — either a fixed line (`fixed`) or a conf-dependent emitter.
 * WHY: Keys are whitespace-separated (see libXrdCl FileSystem::Query config, e.g. "tpc tpcdlg"). Lines in
 *      the response must match reference XRootD: tpc → a line whose first character is '0' or '1' (atoi
 *      for XrdCl); tpcdlg → literal "tpcdlg" when HTTP-TPC delegation is unavailable. Table-driven
 *      dispatch keeps the handler flat and makes adding a key a one-row change; keys whose answer is a
 *      constant of the build state their line in the table and need no emitter.
 * HOW: NULL-key sentinel terminates the linear scan in brix_qconfig_emit_key; exactly one of
 *      `fixed` / `emit` is set per row. */
typedef struct {
    const char           *key;
    const char           *fixed;   /* the literal response line, or NULL */
    brix_qconfig_emit_fn  emit;    /* conf-dependent emitter when fixed == NULL */
    ngx_flag_t            public_safe;
} brix_qconfig_entry_t;

#define BRIX_QCONF_STR_(x)  #x
#define BRIX_QCONF_STR(x)   BRIX_QCONF_STR_(x)

/* WHAT: `public_safe` — may this key still be answered under
 *       `brix_read_only_public`?
 * WHY:  The public posture withholds SERVER configuration, not PROTOCOL
 *       capability.  Every key below whose value is a constant of the wire
 *       implementation (what this build can do, and the limits a client must
 *       respect to talk to it correctly) is safe: withholding it does not hide
 *       anything an anonymous client cannot infer by trying, and DOES break
 *       transfer tuning — a client that cannot read readv_ior_max/readv_iov_max
 *       falls back to conservative defaults and issues far more, far smaller
 *       vector reads.  Keys that describe the DEPLOYMENT — which build is
 *       running (`version`), what role this node plays in a cluster (`role`) —
 *       are the fingerprinting surface the posture exists to close, so they are
 *       withheld and answered exactly like an unknown key.
 * HOW:  0 (the implicit initialiser) means WITHHELD.  A new row added without
 *       thinking about disclosure therefore fails closed: it is invisible to a
 *       public client until someone deliberately marks it 1. */
static const brix_qconfig_entry_t  brix_qconfig_table[] = {
    /* key / fixed response line / emitter / public_safe.  Fixed-line notes:
     * chksum — the bare cslist (no "chksum=" prefix), adler32 first (xrdcp's
     *   default); crc32 = zlib CRC-32 (stock XRootD's standard name), zcrc32
     *   its alias; crc64 = CRC-64/XZ ≠ crc64nvme = CRC-64/NVME (INVARIANT 9).
     * readv_iov_max / bind_max / pio_max — bare integers, reference format
     *   (maxRvecsz; maxStreams-1 = 15; maxPio+1 = 5): XrdCl atoi()s the line.
     * tpc — bare "1": ANY data server can act as a TPC *source* (it only
     *   serves reads to the pulling destination), so even a read-only source
     *   answers 1 or the client aborts with "Source does not support
     *   third-party-copy"; destination-side requirements (allow_write + pool)
     *   are enforced where the pull launches (src/tpc). XrdCl parses the line
     *   with isdigit()+atoi(), so a "tpc=" prefix would reject TPC support.
     * tpcdlg — the literal key echo signals HTTP-TPC delegation unavailable.
     * xrdfs.ext — vendor POSIX-completeness ops (src/write/ext_ops.c); the
     *   native FUSE client probes this before emitting setattr/symlink/....
     * brix.substreams — "=rw" marks bound-secondary REQUEST dispatch; the
     *   native client tears its secondaries down without it (a stock server
     *   merely echoes the unknown key, which lacks the marker).
     * fattr — usxParms "<maxNameLen> <maxValueLen>": Linux user.* caps,
     *   248 = 255 - len("user."), 65536 = 64 KiB value cap (ext4/xfs stock).
     * version — the bare product string (core/ident.h), digits + no prefix. */
    { "chksum",        "adler32,crc32,crc32c,crc64,crc64nvme,zcrc32,"
                       "md5,sha1,sha256\n",                        NULL, 1 },
    { "readv",         "readv=1\n",                                NULL, 1 },
    { "readv_ior_max", NULL,       brix_qconfig_emit_readv_ior_max,      1 },
    { "readv_iov_max", BRIX_QCONF_STR(BRIX_READV_MAXSEGS) "\n",    NULL, 1 },
    { "tpc",           "1\n",                                      NULL, 1 },
    { "tpcdlg",        "tpcdlg\n",                                 NULL, 1 },
    { "cmpread",       NULL,       brix_qconfig_emit_cmpread,            1 },
    { "cmpwrite",      NULL,       brix_qconfig_emit_cmpwrite,           1 },
    { "xrdfs.ext",     "xrdfs.ext=setattr,symlink,readlink,link\n", NULL, 1 },
    { "brix.substreams", "brix.substreams=rw\n",                   NULL, 1 },
    { "bind_max",      "15\n",                                     NULL, 1 },
    { "pio_max",       "5\n",                                      NULL, 1 },
    { "fattr",         "248 65536\n",                              NULL, 1 },
    /* Deployment identity — withheld from a public read-only gateway. */
    { "version",       BRIX_SERVER_VERSION "\n",                   NULL, 0 },
    { "role",          NULL,       brix_qconfig_emit_role,               0 },
    { NULL,            NULL,       NULL,                                 0 },
};

/* WHAT: Dispatches one query key: scans brix_qconfig_table for a matching emitter and invokes it, or —
 *       for an unknown key — echoes the key name + newline. Returns the emitter's success flag.
 * WHY: Unknown config key: the reference echoes the key name + newline (do_Qconf default branch), NOT
 *      "key=value". A bare value-line is what every standard config consumer parses. Centralizing the
 *      lookup keeps brix_query_config a flat token loop.
 * HOW: Linear scan to the NULL sentinel (table is small, request-parse path); strcmp match → emit;
 *      fall-through → append "%s\n" with the key. */
static ngx_flag_t
brix_qconfig_emit_key(const char *key, ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    const brix_qconfig_entry_t *e;

    for (e = brix_qconfig_table; e->key != NULL; e++) {
        if (strcmp(key, e->key) != 0) {
            continue;
        }
        /* Withheld under brix_read_only_public: fall through to the echo below
         * rather than inventing a new answer, so a restricted key is
         * indistinguishable on the wire from one this build never supported —
         * no disclosure, and the client takes a code path it already has. */
        if (conf->common.read_only_public && !e->public_safe) {
            break;
        }
        if (e->fixed != NULL) {
            return brix_qconfig_append(resp, resp_sz, pos, "%s", e->fixed);
        }
        return e->emit(conf, resp, resp_sz, pos);
    }

    return brix_qconfig_append(resp, resp_sz, pos, "%s\n", key);
}

/* public API: brix_query_config() — kXR_Qconfig capability query handler * WHAT: Main handler for Qconfig requests. Initializes 512-byte response buffer, parses whitespace-separated query keys via qconfig_next_token loop, and dispatches each key through the static descriptor table (brix_qconfig_emit_key). Unknown keys echo the key name. Empty query returns kXR_ArgMissing; populated response sends resp at pos bytes. Under brix_read_only_public the table's public_safe column withholds the deployment-identity keys (they echo like unknown keys) while capability/limit keys still answer — see the table comment: refusing the whole query instead would leave clients with no readv limits and no checksum list, i.e. it would break transfer tuning to hide nothing worth hiding. */

ngx_int_t
brix_query_config(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char        resp[512];
    size_t      pos = 0;
    const char *p;
    char        key[128];
    int         ntokens = 0;

    p = (ctx->recv.payload && ctx->recv.cur_dlen > 0) ? (const char *) ctx->recv.payload : "";

    while (brix_qconfig_next_token(&p, key, sizeof(key))) {
        ntokens++;

        if (!brix_qconfig_emit_key(key, conf, resp, sizeof(resp), &pos)) {
            break;
        }
    }

    /* No argument at all (empty/whitespace-only payload) is an error: the
     * reference do_Qconf returns kXR_ArgMissing "query config argument not
     * specified."  A token that simply produced no output still succeeds. */
    if (ntokens == 0) {
        return brix_send_error(ctx, c, kXR_ArgMissing,
                                 "query config argument not specified.");
    }

    if (pos == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }

    return brix_send_ok(ctx, c, resp, (uint32_t) pos);
}
