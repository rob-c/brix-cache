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
 * HOW:  brix_query_config() initializes resp buffer (512 bytes), determines TPC capability from allow_write+thread_pool, parses whitespace-separated keys via qconfig_next_token loop, appends key=value lines per supported feature using qconfig_append (vsnprintf with capacity tracking). Unknown keys default to =0. Empty query returns send_ok(NULL, 0); populated response sends resp at pos bytes.
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

/* public API: brix_query_config() — kXR_Qconfig capability query handler * WHAT: Main handler for Qconfig requests. Initializes 512-byte response buffer, determines TPC capability from allow_write+thread_pool config, parses whitespace-separated query keys via qconfig_next_token loop, appends key=value lines per supported feature using qconfig_append (vsnprintf with capacity tracking). Unknown keys default to =0. Empty query returns send_ok(NULL, 0); populated response sends resp at pos bytes. */

ngx_int_t
brix_query_config(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    char        resp[512];
    size_t      pos = 0;
    const char *p;
    char        key[128];
    int         tpc_capable;
    int         ntokens = 0;

    /*
     * Advertise TPC support (the client's XrdCl::Utils::CheckTPCLite queries
     * BOTH endpoints before a transfer).  Any xrootd data server can act as a
     * TPC *source* — it only serves reads to the pulling destination — so a
     * read-only source must still answer tpc>=1 or the client aborts with
     * "Source does not support third-party-copy".  The *destination* pull
     * additionally needs allow_write + a thread pool; that capability is
     * enforced where the pull is actually launched (src/tpc), not gated here.
     */
    tpc_capable = 1;

    p = (ctx->recv.payload && ctx->recv.cur_dlen > 0) ? (const char *) ctx->recv.payload : "";

    /*
     * Keys are whitespace-separated (see libXrdCl FileSystem::Query config,
     * e.g. "tpc tpcdlg"). Lines in the response must match reference XRootD:
     *   tpc   → a line whose first character is '0' or '1' (atoi for XrdCl)
     *   tpcdlg → literal "tpcdlg" when HTTP-TPC delegation is unavailable
     */
    while (brix_qconfig_next_token(&p, key, sizeof(key))) {
        ntokens++;

        if (strcmp(key, "chksum") == 0) {
            /* adler32 first — xrdcp default; list ALL algorithms the Qcksum path
             * answers.  crc32 = zlib CRC-32 (stock XRootD's standard name; must be
             * advertised so peers intersecting preference lists can negotiate it),
             * zcrc32 = its alias; crc64 = CRC-64/XZ, crc64nvme = CRC-64/NVME (this
             * gateway's de-facto convention; stock XRootD ships no crc64 calculator). */
            /* Value only (no "chksum=" prefix) — the reference do_Qconf returns
             * the bare cslist, and xrdcp/XrdCl parse the value line directly. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "adler32,crc32,crc32c,crc64,crc64nvme,zcrc32,md5,sha1,sha256\n")) {
                break;
            }

        } else if (strcmp(key, "readv") == 0) {
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "readv=1\n")) {
                break;
            }

        } else if (strcmp(key, "readv_ior_max") == 0) {
            /* Max bytes per readv element (the official "maxReadv_ior"). Reported
             * as a bare integer (no key= prefix), matching reference XRootD, so
             * XrdCl sizes each VectorRead element to our configured
             * brix_readv_segment_size and never overshoots the per-element cap. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "%lu\n",
                                       (unsigned long) conf->readv_segment_size)) {
                break;
            }

        } else if (strcmp(key, "readv_iov_max") == 0) {
            /* Max number of elements per readv request (the official "maxRvecsz"). */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "%d\n", BRIX_READV_MAXSEGS)) {
                break;
            }

        } else if (strcmp(key, "tpc") == 0) {
            /*
             * Return just the numeric value (1 or 0) to match the reference
             * XRootD server when XRDTPC is set.  XrdCl::Utils::CheckTPCLite
             * parses the first response line with isdigit() + atoi(), so a
             * leading "tpc=" prefix would cause it to reject TPC support.
             */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "%d\n", tpc_capable)) {
                break;
            }

        } else if (strcmp(key, "tpcdlg") == 0) {
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "tpcdlg\n")) {
                break;
            }

        } else if (strcmp(key, "cmpread") == 0) {
            /* phase-42 W4: inline read compression.  Advertise the codecs this
             * server can compress kXR_read responses with (only those actually
             * built in) when brix_read_compress is on, else "cmpread=0" so a
             * willing client knows not to send "?xrootd.compress=".  Invisible
             * to stock clients, which never query this key. */
            if (conf->read_compress) {
                char              list[160];
                size_t            lp = 0;
                brix_codec_id_t cid;

                list[0] = '\0';
                for (cid = (brix_codec_id_t) 1; cid < BRIX_CODEC_MAX; cid++) {
                    const brix_codec_desc_t *d = brix_codec_by_id(cid);
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
                if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpread=%s\n", list)) {
                    break;
                }
            } else {
                if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpread=0\n")) {
                    break;
                }
            }

        } else if (strcmp(key, "cmpwrite") == 0) {
            /* phase-42 W5: inline write decompression — symmetric to cmpread.
             * Advertise the codecs the server will decompress kXR_write payloads
             * with when brix_write_compress is on, else "cmpwrite=0". */
            if (conf->write_compress) {
                char              list[160];
                size_t            lp = 0;
                brix_codec_id_t cid;

                list[0] = '\0';
                for (cid = (brix_codec_id_t) 1; cid < BRIX_CODEC_MAX; cid++) {
                    const brix_codec_desc_t *d = brix_codec_by_id(cid);
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
                if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpwrite=%s\n", list)) {
                    break;
                }
            } else {
                if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                           "cmpwrite=0\n")) {
                    break;
                }
            }

        } else if (strcmp(key, "xrdfs.ext") == 0) {
            /* nginx-xrootd vendor POSIX-completeness extensions this server
             * implements (src/write/ext_ops.c). The native FUSE client queries
             * this to decide whether to emit kXR_setattr/symlink/readlink/link
             * rather than falling back to no-op utimens / ENOTSUP. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "xrdfs.ext=setattr,symlink,readlink,link\n")) {
                break;
            }

        } else if (strcmp(key, "version") == 0) {
            /* Server software version.  The reference do_Qconf returns the bare
             * version string (e.g. "v5.9.5"); clients parse it for feature/quirk
             * detection, so it must contain digits and carry NO "version="
             * prefix.  Report the product version from core/ident.h — the same
             * string every other identity surface advertises. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos, "%s\n",
                                       BRIX_SERVER_VERSION)) {
                break;
            }

        } else if (strcmp(key, "bind_max") == 0) {
            /* Max parallel data streams a client may bind (reference: a bare
             * integer + newline; stock default is maxStreams-1 = 15). */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos, "%d\n", 15)) {
                break;
            }

        } else if (strcmp(key, "pio_max") == 0) {
            /* Max parallel-I/O streams per request. The reference do_Qconf
             * returns a bare integer (maxPio+1; stock default 5); XrdCl parses it
             * with atoi(), so a "pio_max=" prefix would break it. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos, "%d\n", 5)) {
                break;
            }

        } else if (strcmp(key, "role") == 0) {
            /* Reference do_Qconf returns the bare $XRDROLE (XrdOfsConfig exports
             * it from the configured role).  A standalone data server reports
             * "server"; in manager/redirector mode it reports "manager". */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos, "%s\n",
                                       conf->manager_mode ? "manager"
                                                          : "server")) {
                break;
            }

        } else if (strcmp(key, "fattr") == 0) {
            /* Reference do_Qconf returns usxParms — the OSS extended-attribute
             * limits "<maxNameLen> <maxValueLen>".  On Linux user.* xattrs the
             * name cap is 248 (255 − len("user.")) and the value cap 65536
             * (64 KiB), which is what stock reports on ext4/xfs; we support
             * fattr (src/fattr/), so advertise the same. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos, "248 65536\n")) {
                break;
            }

        } else {
            /* Unknown config key: the reference echoes the key name + newline
             * (do_Qconf default branch), NOT "key=value". A bare value-line is
             * what every standard config consumer parses. */
            if (!brix_qconfig_append(resp, sizeof(resp), &pos,
                                       "%s\n", key)) {
                break;
            }
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
