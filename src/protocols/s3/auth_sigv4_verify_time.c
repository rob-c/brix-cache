/*
 * auth_sigv4_verify_time.c — SigV4 request-timestamp parsing and clock-skew /
 * presigned-expiry enforcement.
 *
 * WHAT: Owns the SigV4 timestamp concern carved out of auth_sigv4_verify.c:
 *       the fixed-width YYYYMMDDTHHMMSSZ datetime parser, the header/presigned
 *       clock-skew and expiry rules, and the resolver that turns either source
 *       into the full amz timestamp view (s3_amz_date_out_t) the string-to-sign
 *       consumes. Every rejection edge records the SigV4 auth result and emits
 *       the frozen XML error.
 * WHY:  auth_sigv4_verify.c exceeded the ~500-line file-size guard (phase-79).
 *       Timestamp parsing + skew arithmetic is one cohesive, side-effect-light
 *       concern with two mirrored source paths (presigned query param vs the
 *       x-amz-date header), so it splits cleanly from the verifier orchestrator
 *       and the byte-frozen crypto. INVARIANT §6: SigV4-only — no bearer logic.
 * HOW:  Pure digit/datetime parsers feed timegm(); the two skew checks bound the
 *       parsed time against ngx_time(); s3_sigv4_resolve_request_time forks on
 *       comp->presigned and returns out->date/out->len set to a buffer that
 *       outlives the call (comp's own storage for presigned, out->buf for the
 *       header path). Byte layout and error messages preserved 1:1 with the
 *       pre-split single-file implementation.
 */

#include "s3.h"
#include "s3_auth_internal.h"
#include "auth_sigv4_verify_internal.h"
#include "core/compat/cstr.h"

#include <string.h>
#include <time.h>

#define S3_SIGV4_MAX_HEADER_SKEW_SEC  900
#define S3_SIGV4_MAX_FUTURE_SKEW_SEC  900

/*
 * s3_digit — map an ASCII byte to its decimal value.
 *
 * WHAT:  Return 0-9 for an ASCII digit byte, or -1 for any non-digit.
 * WHY:   The amz timestamp is a fixed-width all-ASCII-digit field; a branch-free
 *        per-byte validator keeps the datetime parser strict and linear.
 * HOW:   Range-check against '0'..'9' and subtract '0'.
 */
static int
s3_digit(u_char c)
{
    return (c >= '0' && c <= '9') ? (int) (c - '0') : -1;
}

/*
 * s3_parse_2digits — parse a 2-character decimal field.
 *
 * WHAT:  Return the value of s[0..1] as a 0-99 integer, or -1 if either byte is
 *        not a digit.
 * WHY:   Month/day/hour/minute/second fields of the amz timestamp are all
 *        2-digit; one validated helper avoids repeating the digit math.
 * HOW:   Validate both digits, combine hi*10 + lo.
 */
static int
s3_parse_2digits(const char *s)
{
    int hi, lo;

    hi = s3_digit((u_char) s[0]);
    lo = s3_digit((u_char) s[1]);
    if (hi < 0 || lo < 0) {
        return -1;
    }
    return hi * 10 + lo;
}

/*
 * s3_parse_4digits — parse a 4-character decimal field.
 *
 * WHAT:  Return the value of s[0..3] as a 0-9999 integer, or -1 if any byte is
 *        not a digit.
 * WHY:   The amz timestamp year is a 4-digit field; a dedicated validator keeps
 *        the parser uniform.
 * HOW:   Validate all four digits, combine into a base-10 value.
 */
static int
s3_parse_4digits(const char *s)
{
    int a, b, c, d;

    a = s3_digit((u_char) s[0]);
    b = s3_digit((u_char) s[1]);
    c = s3_digit((u_char) s[2]);
    d = s3_digit((u_char) s[3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
        return -1;
    }
    return a * 1000 + b * 100 + c * 10 + d;
}

/*
 * s3_parse_amz_datetime — parse a SigV4 YYYYMMDDTHHMMSSZ timestamp to time_t.
 *
 * WHAT:  Parse the fixed 16-byte amz timestamp into *out (UTC epoch seconds),
 *        returning NGX_OK, or NGX_ERROR when the layout or any field is invalid.
 * WHY:   SigV4 timestamps are always the fixed ISO-8601 basic UTC form; strict
 *        field validation prevents timegm from normalising a malformed value.
 * HOW:   Require length 16 with 'T' at [8] and 'Z' at [15]; parse each field;
 *        range-check; populate a zeroed struct tm and convert via timegm.
 */
static ngx_int_t
s3_parse_amz_datetime(const char *s, time_t *out)
{
    struct tm  tm;
    int        year, mon, day, hour, min, sec;

    if (strlen(s) != 16 || s[8] != 'T' || s[15] != 'Z') {
        return NGX_ERROR;
    }

    year = s3_parse_4digits(s);
    mon  = s3_parse_2digits(s + 4);
    day  = s3_parse_2digits(s + 6);
    hour = s3_parse_2digits(s + 9);
    min  = s3_parse_2digits(s + 11);
    sec  = s3_parse_2digits(s + 13);

    if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31
        || hour < 0 || hour > 23 || min < 0 || min > 59
        || sec < 0 || sec > 60)
    {
        return NGX_ERROR;
    }

    ngx_memzero(&tm, sizeof(tm));
    tm.tm_year = year - 1900;
    tm.tm_mon  = mon  - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min  = min;
    tm.tm_sec  = sec;
    *out = timegm(&tm);
    return NGX_OK;
}

/*
 * s3_reject_bad_amz_date — emit the frozen bad-date 403 and record the result.
 *
 * WHAT:  Record BRIX_S3_AUTH_BAD_DATE and return the InvalidRequest 403 with the
 *        supplied message.
 * WHY:   Several timestamp-parse failure sites share one message-carrying error
 *        edge; centralising it keeps the parser linear and the metric consistent.
 * HOW:   Record the result, then send the XML error.
 */
static ngx_int_t
s3_reject_bad_amz_date(ngx_http_request_t *r, const char *message)
{
    s3_record_auth_result(BRIX_S3_AUTH_BAD_DATE);
    return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                             "InvalidRequest", message);
}

/*
 * s3_reject_clock_skew — emit the frozen RequestTimeTooSkewed 403.
 *
 * WHAT:  Record BRIX_S3_AUTH_BAD_DATE and return the RequestTimeTooSkewed 403.
 * WHY:   Both the header and presigned skew checks reject with the identical
 *        status and message; one helper keeps that guarantee obvious.
 * HOW:   Record the result, then send the fixed XML error.
 */
static ngx_int_t
s3_reject_clock_skew(ngx_http_request_t *r)
{
    s3_record_auth_result(BRIX_S3_AUTH_BAD_DATE);
    return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                             "RequestTimeTooSkewed",
                             "The difference between the request time and "
                             "the server time is too large.");
}

/*
 * s3_check_header_clock_skew — bound a header-signed request's timestamp.
 *
 * WHAT:  Return NGX_OK when request_time is within +/-900s of now, otherwise the
 *        terminal skew rejection.
 * WHY:   Header-signed requests may legitimately be slightly ahead of or behind
 *        server time; a symmetric window blocks replay/forgery outside it.
 * HOW:   Compare the signed magnitude of (request_time - now) against the window.
 */
static ngx_int_t
s3_check_header_clock_skew(ngx_http_request_t *r, time_t request_time)
{
    time_t now;

    now = ngx_time();
    if (request_time > now) {
        if (request_time - now > S3_SIGV4_MAX_HEADER_SKEW_SEC) {
            return s3_reject_clock_skew(r);
        }
    } else if (now - request_time > S3_SIGV4_MAX_HEADER_SKEW_SEC) {
        return s3_reject_clock_skew(r);
    }

    return NGX_OK;
}

/*
 * s3_check_presigned_future_skew — reject a presigned request dated too far ahead.
 *
 * WHAT:  Return NGX_OK unless request_time is more than 900s in the future, in
 *        which case return the terminal skew rejection.
 * WHY:   Presigned URLs carry their own expiry window, so only the future edge
 *        needs bounding here; the past edge is the separate expiry check.
 * HOW:   Reject only when request_time - now exceeds the future window.
 */
static ngx_int_t
s3_check_presigned_future_skew(ngx_http_request_t *r, time_t request_time)
{
    time_t now;

    now = ngx_time();
    if (request_time > now
        && request_time - now > S3_SIGV4_MAX_FUTURE_SKEW_SEC)
    {
        return s3_reject_clock_skew(r);
    }

    return NGX_OK;
}

/*
 * s3_sigv4_resolve_request_time — resolve and skew/expiry-check the request time.
 *
 * WHAT:  Parse the SigV4 timestamp (presigned X-Amz-Date query param or the
 *        x-amz-date header), enforce clock-skew / presigned-expiry limits, and
 *        return the full amz timestamp string used in the string-to-sign.
 * WHY:   The presigned and header paths compute the same downstream inputs
 *        (amz_date + amz_date_len) via different sources and different skew
 *        rules; folding both into one helper keeps the verifier body linear.
 * HOW:   Presigned path: parse query-supplied timestamp, future-skew + expiry
 *        check.  Header path: parse the header timestamp, symmetric skew check.
 *        out->date is set to a buffer that outlives this call — either comp's
 *        own storage (presigned) or out->buf (the header path).  Frozen error
 *        messages and result codes preserved 1:1.
 *
 * Returns: NGX_OK with out->date/out->len set, otherwise the terminal ngx_int_t
 *   result (response already emitted).
 */
ngx_int_t
s3_sigv4_resolve_request_time(ngx_http_request_t *r,
    const sigv4_components_t *comp, s3_amz_date_out_t *out)
{
    time_t    request_time = 0;
    ngx_str_t date_hdr;
    ngx_int_t skew_rc;

    if (comp->presigned) {
        if (s3_parse_amz_datetime(comp->amz_date, &request_time) != NGX_OK) {
            return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
        }

        skew_rc = s3_check_presigned_future_skew(r, request_time);
        if (skew_rc != NGX_OK) {
            return skew_rc;
        }

        if (ngx_time() >= request_time
            && ngx_time() - request_time > (time_t) comp->amz_expires)
        {
            s3_record_auth_result(BRIX_S3_AUTH_BAD_DATE);
            return s3_send_xml_error(r, NGX_HTTP_FORBIDDEN,
                                     "AccessDenied",
                                     "Request has expired");
        }

        out->date = comp->amz_date;
        out->len = strlen(comp->amz_date);
        return NGX_OK;
    }

    date_hdr = get_header(r, "x-amz-date");
    if (date_hdr.len == 0) {
        return s3_reject_bad_amz_date(r, "Missing X-Amz-Date header");
    }

    if (brix_str_cbuf(out->buf, sizeof(out->buf), &date_hdr) == NULL) {
        return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
    }

    if (s3_parse_amz_datetime(out->buf, &request_time) != NGX_OK) {
        return s3_reject_bad_amz_date(r, "Invalid X-Amz-Date");
    }

    skew_rc = s3_check_header_clock_skew(r, request_time);
    if (skew_rc != NGX_OK) {
        return skew_rc;
    }

    out->date = out->buf;
    out->len = strlen(out->buf);
    return NGX_OK;
}
