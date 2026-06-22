#include "query_internal.h"
#include "../compat/codec_core.h"

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
 * HOW:  xrootd_query_config() initializes resp buffer (512 bytes), determines TPC capability from allow_write+thread_pool, parses whitespace-separated keys via qconfig_next_token loop, appends key=value lines per supported feature using qconfig_append (vsnprintf with capacity tracking). Unknown keys default to =0. Empty query returns send_ok(NULL, 0); populated response sends resp at pos bytes.
 */

/* ---- Function: xrootd_qconfig_skip_ws() — whitespace skip helper ---- */
/* WHAT: Advances the pointer *pp past any whitespace characters (space, tab, newline, carriage return). Used as a preamble before extracting tokens from kXR_Qconfig query payload.
 * WHY: kXR_Qconfig accepts whitespace-separated keys in its payload; this helper ensures token extraction starts at valid non-whitespace boundaries without accidentally capturing separator characters. Standard ASCII whitespace set covers all common delimiters used in client queries.
 * HOW: Single while loop checking **pp against ' ', '\t', '\n', '\r' — increments pointer past each whitespace character until reaching a non-whitespace byte or null terminator. */

static void
xrootd_qconfig_skip_ws(const char **pp)
{
    while (**pp == ' ' || **pp == '\t' || **pp == '\n' || **pp == '\r') {
        (*pp)++;
    }
}

/* ---- Function: xrootd_qconfig_next_token() — whitespace-separated token extraction ---- */
/* WHAT: Extracts a single token from the payload pointer *pp, skipping leading whitespace first then reading characters until next whitespace or null terminator. Stores extracted token in tok buffer with null termination, returns 1 on success (token found), 0 on failure (end of payload). Enforces tok_sz boundary to prevent overflow.
 * WHY: kXR_Qconfig query payloads contain whitespace-separated capability keys (e.g., "tpc tpcdlg chksum"). This helper enables sequential token extraction without allocating temporary buffers or using strchr-based splitting — efficient for single-threaded nginx event loop processing.
 * HOW: Two-phase → first calls xrootd_qconfig_skip_ws() to advance past leading whitespace, then reads characters while **pp != '\0' and not whitespace, storing each char in tok[len++] with null termination at len = tok_sz - 1 or end-of-token boundary. Returns 1 if token extracted, 0 if *pp points to '\0' (end of payload). */

static ngx_flag_t
xrootd_qconfig_next_token(const char **pp, char *tok, size_t tok_sz)
{
    size_t len;

    xrootd_qconfig_skip_ws(pp);
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

/* ---- Function: xrootd_qconfig_append() — vsnprintf with buffer capacity tracking ---- */
/* WHAT: Appends formatted text to a response buffer using vsnprintf, tracking the current position via *pos parameter. Returns 1 on success (formatted output fit within remaining buffer), 0 on failure (overflow or NULL pointers). Enforces resp_sz + pos bounds to prevent response buffer overflow during query capability reporting.
 * WHY: kXR_Qconfig builds a multi-line capability report by appending individual key=value pairs; this helper ensures each append respects the 512-byte resp buffer limit without truncating mid-response or corrupting prior output. vsnprintf with remaining capacity calculation prevents format string attacks from exceeding bounds.
 * HOW: Calculate remaining = resp_sz - *pos, call vsnprintf(resp + *pos, remaining, fmt, ap), check n < 0 || (size_t)n >= remaining for overflow → return 0 on failure or update *pos += n and return 1 on success. NULL pointer checks prevent crashes on malformed input. */

static ngx_flag_t
xrootd_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
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

/* ---- public API: xrootd_query_config() — kXR_Qconfig capability query handler ----
 * WHAT: Main handler for Qconfig requests. Initializes 512-byte response buffer, determines TPC capability from allow_write+thread_pool config, parses whitespace-separated query keys via qconfig_next_token loop, appends key=value lines per supported feature using qconfig_append (vsnprintf with capacity tracking). Unknown keys default to =0. Empty query returns send_ok(NULL, 0); populated response sends resp at pos bytes. */

ngx_int_t
xrootd_query_config(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char        resp[512];
    size_t      pos = 0;
    const char *p;
    char        key[128];
    int         tpc_capable;

    /* TPC pull is available on writable data servers with a thread pool. */
    tpc_capable = (conf->common.allow_write && conf->common.thread_pool != NULL) ? 1 : 0;

    p = (ctx->payload && ctx->cur_dlen > 0) ? (const char *) ctx->payload : "";

    /*
     * Keys are whitespace-separated (see libXrdCl FileSystem::Query config,
     * e.g. "tpc tpcdlg"). Lines in the response must match reference XRootD:
     *   tpc   → a line whose first character is '0' or '1' (atoi for XrdCl)
     *   tpcdlg → literal "tpcdlg" when HTTP-TPC delegation is unavailable
     */
    while (xrootd_qconfig_next_token(&p, key, sizeof(key))) {

        if (strcmp(key, "chksum") == 0) {
            /* adler32 first — xrdcp default; list ALL algorithms the Qcksum path
             * answers.  crc32 = zlib CRC-32 (stock XRootD's standard name; must be
             * advertised so peers intersecting preference lists can negotiate it),
             * zcrc32 = its alias; crc64 = CRC-64/XZ, crc64nvme = CRC-64/NVME (this
             * gateway's de-facto convention; stock XRootD ships no crc64 calculator). */
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "chksum=adler32,crc32,crc32c,crc64,crc64nvme,zcrc32,md5,sha1,sha256\n")) {
                break;
            }

        } else if (strcmp(key, "readv") == 0) {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "readv=1\n")) {
                break;
            }

        } else if (strcmp(key, "tpc") == 0) {
            /*
             * Return just the numeric value (1 or 0) to match the reference
             * XRootD server when XRDTPC is set.  XrdCl::Utils::CheckTPCLite
             * parses the first response line with isdigit() + atoi(), so a
             * leading "tpc=" prefix would cause it to reject TPC support.
             */
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "%d\n", tpc_capable)) {
                break;
            }

        } else if (strcmp(key, "tpcdlg") == 0) {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "tpcdlg\n")) {
                break;
            }

        } else if (strcmp(key, "cmpread") == 0) {
            /* phase-42 W4: inline read compression.  Advertise the codecs this
             * server can compress kXR_read responses with (only those actually
             * built in) when xrootd_read_compress is on, else "cmpread=0" so a
             * willing client knows not to send "?xrootd.compress=".  Invisible
             * to stock clients, which never query this key. */
            if (conf->read_compress) {
                char              list[160];
                size_t            lp = 0;
                xrootd_codec_id_t cid;

                list[0] = '\0';
                for (cid = (xrootd_codec_id_t) 1; cid < XROOTD_CODEC_MAX; cid++) {
                    const xrootd_codec_desc_t *d = xrootd_codec_by_id(cid);
                    int n;

                    if (d == NULL || !d->available) {
                        continue;
                    }
                    n = snprintf(list + lp, sizeof(list) - lp, "%s%s",
                                 lp ? "," : "", d->name);
                    if (n < 0 || (size_t) n >= sizeof(list) - lp) {
                        break;
                    }
                    lp += (size_t) n;
                }
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpread=%s\n", list)) {
                    break;
                }
            } else {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpread=0\n")) {
                    break;
                }
            }

        } else if (strcmp(key, "cmpwrite") == 0) {
            /* phase-42 W5: inline write decompression — symmetric to cmpread.
             * Advertise the codecs the server will decompress kXR_write payloads
             * with when xrootd_write_compress is on, else "cmpwrite=0". */
            if (conf->write_compress) {
                char              list[160];
                size_t            lp = 0;
                xrootd_codec_id_t cid;

                list[0] = '\0';
                for (cid = (xrootd_codec_id_t) 1; cid < XROOTD_CODEC_MAX; cid++) {
                    const xrootd_codec_desc_t *d = xrootd_codec_by_id(cid);
                    int n;

                    if (d == NULL || !d->available) {
                        continue;
                    }
                    n = snprintf(list + lp, sizeof(list) - lp, "%s%s",
                                 lp ? "," : "", d->name);
                    if (n < 0 || (size_t) n >= sizeof(list) - lp) {
                        break;
                    }
                    lp += (size_t) n;
                }
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpwrite=%s\n", list)) {
                    break;
                }
            } else {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpwrite=0\n")) {
                    break;
                }
            }

        } else if (strcmp(key, "xrdfs.ext") == 0) {
            /* nginx-xrootd vendor POSIX-completeness extensions this server
             * implements (src/write/ext_ops.c). The native FUSE client queries
             * this to decide whether to emit kXR_setattr/symlink/readlink/link
             * rather than falling back to no-op utimens / ENOTSUP. */
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "xrdfs.ext=setattr,symlink,readlink,link\n")) {
                break;
            }

        } else {
            if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                       "%s=0\n", key)) {
                break;
            }
        }
    }

    if (pos == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    return xrootd_send_ok(ctx, c, resp, (uint32_t) pos);
}
