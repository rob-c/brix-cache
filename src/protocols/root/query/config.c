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

/* WHAT: Emits the checksum-algorithm list for the "chksum" query key.
 * WHY: adler32 first — xrdcp default; list ALL algorithms the Qcksum path answers. crc32 = zlib CRC-32
 *      (stock XRootD's standard name; must be advertised so peers intersecting preference lists can
 *      negotiate it), zcrc32 = its alias; crc64 = CRC-64/XZ, crc64nvme = CRC-64/NVME (this gateway's
 *      de-facto convention; stock XRootD ships no crc64 calculator). Value only (no "chksum=" prefix) —
 *      the reference do_Qconf returns the bare cslist, and xrdcp/XrdCl parse the value line directly.
 * HOW: Single append of the fixed algorithm list line. */
static ngx_flag_t
brix_qconfig_emit_chksum(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos,
        "adler32,crc32,crc32c,crc64,crc64nvme,zcrc32,md5,sha1,sha256\n");
}

/* WHAT: Emits "readv=1" for the "readv" query key.
 * WHY: Advertises vector-read support so XrdCl uses kXR_readv instead of serial reads.
 * HOW: Single fixed-string append. */
static ngx_flag_t
brix_qconfig_emit_readv(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "readv=1\n");
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

/* WHAT: Emits the max number of elements per readv request for "readv_iov_max".
 * WHY: The official "maxRvecsz" — bare integer, reference format.
 * HOW: Appends the compile-time BRIX_READV_MAXSEGS cap + newline. */
static ngx_flag_t
brix_qconfig_emit_readv_iov_max(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "%d\n", BRIX_READV_MAXSEGS);
}

/* WHAT: Emits the TPC capability value for the "tpc" query key.
 * WHY: Advertise TPC support (the client's XrdCl::Utils::CheckTPCLite queries BOTH endpoints before a
 *      transfer). Any xrootd data server can act as a TPC *source* — it only serves reads to the pulling
 *      destination — so a read-only source must still answer tpc>=1 or the client aborts with "Source does
 *      not support third-party-copy". The *destination* pull additionally needs allow_write + a thread
 *      pool; that capability is enforced where the pull is actually launched (src/tpc), not gated here.
 *      Return just the numeric value (1 or 0) to match the reference XRootD server when XRDTPC is set —
 *      XrdCl parses the first response line with isdigit() + atoi(), so a leading "tpc=" prefix would
 *      cause it to reject TPC support.
 * HOW: Appends the constant capability value 1 as %d + newline. */
static ngx_flag_t
brix_qconfig_emit_tpc(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    int tpc_capable = 1;

    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "%d\n", tpc_capable);
}

/* WHAT: Emits the HTTP-TPC delegation status for the "tpcdlg" query key.
 * WHY: The literal "tpcdlg" echo signals HTTP-TPC delegation is unavailable, matching reference behavior.
 * HOW: Single fixed-string append. */
static ngx_flag_t
brix_qconfig_emit_tpcdlg(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "tpcdlg\n");
}

/* WHAT: Emits the inline read-compression codec list for the "cmpread" query key.
 * WHY: phase-42 W4: inline read compression. Advertise the codecs this server can compress kXR_read
 *      responses with (only those actually built in) when brix_read_compress is on, else "cmpread=0" so a
 *      willing client knows not to send "?xrootd.compress=". Invisible to stock clients, which never
 *      query this key.
 * HOW: When read_compress is on, builds the built-in codec CSV via brix_qconfig_codec_list and appends
 *      "cmpread=<list>"; otherwise appends "cmpread=0". */
static ngx_flag_t
brix_qconfig_emit_cmpread(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    char list[160];

    if (!conf->read_compress) {
        return brix_qconfig_append(resp, resp_sz, pos, "cmpread=0\n");
    }

    brix_qconfig_codec_list(list, sizeof(list));
    return brix_qconfig_append(resp, resp_sz, pos, "cmpread=%s\n", list);
}

/* WHAT: Emits the inline write-decompression codec list for the "cmpwrite" query key.
 * WHY: phase-42 W5: inline write decompression — symmetric to cmpread. Advertise the codecs the server
 *      will decompress kXR_write payloads with when brix_write_compress is on, else "cmpwrite=0".
 * HOW: When write_compress is on, builds the built-in codec CSV via brix_qconfig_codec_list and appends
 *      "cmpwrite=<list>"; otherwise appends "cmpwrite=0". */
static ngx_flag_t
brix_qconfig_emit_cmpwrite(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    char list[160];

    if (!conf->write_compress) {
        return brix_qconfig_append(resp, resp_sz, pos, "cmpwrite=0\n");
    }

    brix_qconfig_codec_list(list, sizeof(list));
    return brix_qconfig_append(resp, resp_sz, pos, "cmpwrite=%s\n", list);
}

/* WHAT: Emits the vendor POSIX-completeness extension list for the "xrdfs.ext" query key.
 * WHY: nginx-xrootd vendor POSIX-completeness extensions this server implements (src/write/ext_ops.c).
 *      The native FUSE client queries this to decide whether to emit kXR_setattr/symlink/readlink/link
 *      rather than falling back to no-op utimens / ENOTSUP.
 * HOW: Single fixed-string append. */
static ngx_flag_t
brix_qconfig_emit_xrdfs_ext(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos,
                               "xrdfs.ext=setattr,symlink,readlink,link\n");
}

/* WHAT: Emits the server software version for the "version" query key.
 * WHY: The reference do_Qconf returns the bare version string (e.g. "v5.9.5"); clients parse it for
 *      feature/quirk detection, so it must contain digits and carry NO "version=" prefix. Report the
 *      product version from core/ident.h — the same string every other identity surface advertises.
 * HOW: Appends BRIX_SERVER_VERSION + newline. */
static ngx_flag_t
brix_qconfig_emit_version(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "%s\n",
                               BRIX_SERVER_VERSION);
}

/* WHAT: Emits the max parallel data streams a client may bind for the "bind_max" query key.
 * WHY: Reference format: a bare integer + newline; stock default is maxStreams-1 = 15.
 * HOW: Appends the constant 15 as %d + newline. */
static ngx_flag_t
brix_qconfig_emit_bind_max(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "%d\n", 15);
}

/* WHAT: Emits the max parallel-I/O streams per request for the "pio_max" query key.
 * WHY: The reference do_Qconf returns a bare integer (maxPio+1; stock default 5); XrdCl parses it with
 *      atoi(), so a "pio_max=" prefix would break it.
 * HOW: Appends the constant 5 as %d + newline. */
static ngx_flag_t
brix_qconfig_emit_pio_max(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "%d\n", 5);
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

/* WHAT: Emits the extended-attribute limits for the "fattr" query key.
 * WHY: Reference do_Qconf returns usxParms — the OSS extended-attribute limits
 *      "<maxNameLen> <maxValueLen>". On Linux user.* xattrs the name cap is 248 (255 − len("user.")) and
 *      the value cap 65536 (64 KiB), which is what stock reports on ext4/xfs; we support fattr
 *      (src/fattr/), so advertise the same.
 * HOW: Single fixed-string append. */
static ngx_flag_t
brix_qconfig_emit_fattr(ngx_stream_brix_srv_conf_t *conf,
    char *resp, size_t resp_sz, size_t *pos)
{
    (void) conf;
    return brix_qconfig_append(resp, resp_sz, pos, "248 65536\n");
}

/* WHAT: Static descriptor table mapping each supported kXR_Qconfig key to its emitter.
 * WHY: Keys are whitespace-separated (see libXrdCl FileSystem::Query config, e.g. "tpc tpcdlg"). Lines in
 *      the response must match reference XRootD: tpc → a line whose first character is '0' or '1' (atoi
 *      for XrdCl); tpcdlg → literal "tpcdlg" when HTTP-TPC delegation is unavailable. Table-driven
 *      dispatch keeps the handler flat and makes adding a key a one-row change.
 * HOW: NULL-key sentinel terminates the linear scan in brix_qconfig_emit_key. */
typedef struct {
    const char           *key;
    brix_qconfig_emit_fn  emit;
} brix_qconfig_entry_t;

static const brix_qconfig_entry_t  brix_qconfig_table[] = {
    { "chksum",        brix_qconfig_emit_chksum        },
    { "readv",         brix_qconfig_emit_readv         },
    { "readv_ior_max", brix_qconfig_emit_readv_ior_max },
    { "readv_iov_max", brix_qconfig_emit_readv_iov_max },
    { "tpc",           brix_qconfig_emit_tpc           },
    { "tpcdlg",        brix_qconfig_emit_tpcdlg        },
    { "cmpread",       brix_qconfig_emit_cmpread       },
    { "cmpwrite",      brix_qconfig_emit_cmpwrite      },
    { "xrdfs.ext",     brix_qconfig_emit_xrdfs_ext     },
    { "version",       brix_qconfig_emit_version       },
    { "bind_max",      brix_qconfig_emit_bind_max      },
    { "pio_max",       brix_qconfig_emit_pio_max       },
    { "role",          brix_qconfig_emit_role          },
    { "fattr",         brix_qconfig_emit_fattr         },
    { NULL,            NULL                            },
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
        if (strcmp(key, e->key) == 0) {
            return e->emit(conf, resp, resp_sz, pos);
        }
    }

    return brix_qconfig_append(resp, resp_sz, pos, "%s\n", key);
}

/* public API: brix_query_config() — kXR_Qconfig capability query handler * WHAT: Main handler for Qconfig requests. Initializes 512-byte response buffer, parses whitespace-separated query keys via qconfig_next_token loop, and dispatches each key through the static descriptor table (brix_qconfig_emit_key). Unknown keys echo the key name. Empty query returns kXR_ArgMissing; populated response sends resp at pos bytes. */

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
