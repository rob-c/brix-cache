/*
 * sd_s3_sign.c — S3 SigV4 signing + HTTP error mapping primitives.
 *
 * Split verbatim out of sd_s3.c: the shared signing kernel (sd_s3_sign),
 * its date/hash helpers (sd_s3_utc_now / sd_s3_sha256_hex), the best-effort
 * error formatter (sd_s3_set_err), and the non-2xx status→errno mapper
 * (sd_s3_status_err). These are declared in sd_s3_internal.h and used by every
 * S3 path (read, write, metadata). SigV4 signing uses the same shared kernels
 * (sigv4 / crypto / hex / uri) the server's verify path uses, so client-signs
 * == server-verifies byte-for-byte.
 */
#include "sd_s3.h"
#include "sd_s3_internal.h"     /* sd_s3_file layout + SigV4/error primitives (split out) */

#include "core/compat/crypto.h"        /* brix_sha256 / brix_hmac_sha256 */
#include "core/compat/hex.h"           /* brix_hex_encode */
#include "core/compat/sigv4.h"         /* brix_sigv4_signing_key */
#include "core/compat/uri.h"           /* brix_http_urlencode */
#include "core/compat/host_format.h"   /* brix_format_host_port */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>   /* gettimeofday — NOT <time.h>, which `-I src/compat`
                         * shadows with compat/time.h (a known conflict; that
                         * helper is module-only, absent from libxrdproto). */

void
sd_s3_set_err(char *errbuf, size_t errcap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

void
sd_s3_set_err(char *errbuf, size_t errcap, const char *fmt, ...)
{
    va_list ap;
    if (errbuf == NULL || errcap == 0) {
        return;
    }
    va_start(ap, fmt);
    /* Truncation is acceptable for a best-effort error message; vsnprintf
     * always NUL-terminates within errcap. */
    (void) vsnprintf(errbuf, errcap, fmt, ap);
    va_end(ap);
}

/* sd_s3_utc_now — current UTC as SigV4 amzdate (YYYYMMDDTHHMMSSZ) + datestamp
 * (YYYYMMDD), computed self-contained from the epoch (civil-from-days) so it
 * needs neither <time.h> (shadowed here) nor the module-only compat/time.c. */
void
sd_s3_utc_now(char amzdate[20], char datestamp[12])
{
    struct timeval tv;
    long long      secs, days, rem, z, era, y;
    unsigned       doe, yoe, doy, mp, d, m;
    int            hh, mm, ss;

    gettimeofday(&tv, NULL);
    secs = (long long) tv.tv_sec;
    days = secs / 86400;
    rem  = secs % 86400;
    if (rem < 0) { rem += 86400; days -= 1; }
    hh = (int) (rem / 3600);
    mm = (int) ((rem % 3600) / 60);
    ss = (int) (rem % 60);

    /* Howard Hinnant's civil_from_days (days since 1970-01-01, UTC). */
    z   = days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = (unsigned) (z - era * 146097);
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y   = (long long) yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp  = (5 * doy + 2) / 153;
    d   = doy - (153 * mp + 2) / 5 + 1;
    m   = mp < 10 ? mp + 3 : mp - 9;
    y  += (m <= 2);

    /* Bound the year to 4 digits (real epochs are well within 0000-9999) so the
     * fixed amzdate[20]/datestamp[12] buffers are provably large enough. */
    {
        int yr = (int) (((y % 10000) + 10000) % 10000);
        unsigned mo = m % 100, da = d % 100;
        snprintf(datestamp, 12, "%04d%02u%02u", yr, mo, da);
        snprintf(amzdate, 20, "%04d%02u%02uT%02u%02u%02uZ",
                 yr, mo, da, hh % 100, mm % 100, ss % 100);
    }
}

void
sd_s3_sha256_hex(const void *data, size_t len, char *out /* >=65 */)
{
    uint8_t d[32];
    brix_sha256((const uint8_t *) data, len, d);
    brix_hex_encode(d, 32, out);
}

/* sd_s3_sign — build the SigV4 x-amz-date / content-sha256 / Authorization header
 * block for `method` on this object (payload = UNSIGNED-PAYLOAD). Ported from
 * xrdc_s3_sign_v4_q; all kernels are shared. 0 / -1. */
int
sd_s3_sign(const sd_s3_file *f, const char *method, const char *canon_qs,
           char *hdrs, size_t hdrsz)
{
    const char *payload_hex = "UNSIGNED-PAYLOAD";
    char        host[300];
    char        amzdate[20], datestamp[12];
    char        canon_hex[65], sighex[65];
    char        canon[8192], scope[160], sts[640], enc_uri[2048];
    uint8_t     k4[32], sig[32];
    int         cn;

    if (canon_qs == NULL) { canon_qs = ""; }
    brix_format_host_port(f->host, (uint16_t) f->port, host, sizeof(host));
    sd_s3_utc_now(amzdate, datestamp);

    if (brix_http_urlencode((const unsigned char *) f->key, strlen(f->key),
                              enc_uri, sizeof(enc_uri), "/") < 0) {
        return -1;
    }
    cn = snprintf(canon, sizeof(canon),
             "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\n"
             "host;x-amz-content-sha256;x-amz-date\n%s",
             method, enc_uri, canon_qs, host, payload_hex, amzdate, payload_hex);
    if (cn < 0 || (size_t) cn >= sizeof(canon)) {
        return -1;
    }
    sd_s3_sha256_hex(canon, strlen(canon), canon_hex);

    cn = snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request",
                  datestamp, f->region);
    if (cn < 0 || (size_t) cn >= sizeof(scope)) {
        return -1;
    }
    cn = snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                  amzdate, scope, canon_hex);
    if (cn < 0 || (size_t) cn >= sizeof(sts)) {
        return -1;
    }

    if (!brix_sigv4_signing_key((const uint8_t *) f->sk, strlen(f->sk),
                                  datestamp, f->region, "s3", k4)
        || !brix_hmac_sha256(k4, 32, (const uint8_t *) sts, strlen(sts), sig)) {
        return -1;
    }
    brix_hex_encode(sig, 32, sighex);

    cn = snprintf(hdrs, hdrsz,
             "x-amz-date: %s\r\nx-amz-content-sha256: %s\r\n"
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s\r\n",
             amzdate, payload_hex, f->ak, scope, sighex);
    if (cn < 0 || (size_t) cn >= hdrsz) {
        return -1;
    }
    return 0;
}

/* Map a non-2xx HTTP status to -1 with a diagnostic; returns -1 always. Sets
 * errno to the matching POSIX class (EACCES for 401/403, ENOENT for 404, else
 * EIO) so callers can recover the error category — the message channel alone
 * loses it. The client S3 VFS maps this errno to XRDC_EAUTH/ENOENT; the server
 * S3 backend maps it to kXR via the canonical errno↔kXR table. */
int
sd_s3_status_err(int status, const char *op, const char *key,
                 char *errbuf, size_t errcap)
{
    if (status == 401 || status == 403) {
        sd_s3_set_err(errbuf, errcap,
            "s3 %s: auth failed (HTTP %d) on %s — check AK/SK/region",
            op, status, key);
        errno = EACCES;
    } else if (status == 404) {
        sd_s3_set_err(errbuf, errcap, "s3 %s: not found (HTTP 404) on %s",
                      op, key);
        errno = ENOENT;
    } else {
        sd_s3_set_err(errbuf, errcap, "s3 %s: HTTP %d on %s", op, status, key);
        errno = EIO;
    }
    return -1;
}
