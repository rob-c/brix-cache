/*
 * trace.c — §15 client diagnostics: wire-trace + per-opcode timing.
 *
 * WHAT: Decode requestid/status codes to names, emit one human-readable line per
 *       wire frame (optionally with a bounded hexdump), and accumulate/print
 *       per-opcode round-trip times.
 * WHY:  The native client owns both ends of the protocol and `libxrdproto` can
 *       name every kXR_* struct it frames — so `--wire-trace`/`--timing` give a
 *       paste-into-a-bug view the stock terse tools cannot. Off by default; every
 *       hook in frame.c/conn.c is a single `if (c->diag.*)` when disabled.
 * HOW:  Switch tables over our own opcodes.h constants (clean-room: names from the
 *       wire spec, never from XrdCl). All output goes to stderr so stdout stays
 *       clean for the conformance harness.
 *
 * names: src/protocols/root/protocol/opcodes.h request opcodes (3000–3032) + response statuses.
 */
#include "brix.h"

#include "core/compat/kxr_names.h"   /* shared kXR opcode/status name tables (libxrdproto) */
#include "protocols/root/protocol/frame_hdr.h" /* unaligned-safe BE field accessors (libxrdproto) */

#include <arpa/inet.h>
#include <string.h>
#include <time.h>

/* Both forward to the shared kXR name tables (libxrdproto's kxr_names.c) so the
 * module and client share one source of truth keyed on protocol/opcodes.h. */
const char *
brix_reqid_name(int reqid)
{
    return brix_kxr_request_name(reqid);
}

const char *
brix_status_name(int status)
{
    return brix_kxr_response_status_name(status);
}

uint64_t
brix_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

/*
 * Phase 40 (a): bounded backoff jitter for the SYNCHRONOUS retry / kXR_wait
 * paths. Returns a pseudo-random value in [0, span_ms). Lazily seeded from the
 * monotonic clock so concurrent clients/processes spread their wake-ups instead
 * of retrying in lockstep (thundering-herd). Same xorshift the async core uses
 * (aio.c rc_worker_main); kept here as the single leaf helper both frame.c and
 * xrdcp.c reuse, with NO dependency on the aio/thread machinery.
 */
unsigned
brix_jitter_ms(unsigned span_ms)
{
    static uint64_t state;   /* lazily seeded; 0 until first use */
    if (span_ms == 0) {
        return 0;
    }
    if (state == 0) {
        state = brix_mono_ns() | 1ull;
    }
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return (unsigned) (state % span_ms);
}

/* Bounded hexdump (cap 256 bytes) of buf[0..n) to stderr, 16 bytes per row. */
static void
hexdump(const uint8_t *buf, uint32_t n)
{
    uint32_t cap = (n < 256) ? n : 256;
    uint32_t i;
    for (i = 0; i < cap; i += 16) {
        uint32_t j;
        fprintf(stderr, "      %04x: ", i);
        for (j = i; j < i + 16 && j < cap; j++) {
            fprintf(stderr, "%02x ", buf[j]);
        }
        fprintf(stderr, "\n");
    }
    if (n > cap) {
        fprintf(stderr, "      … (%u more bytes)\n", n - cap);
    }
}

/* ---- Trace one kXR_error response frame ----
 *
 * WHAT: Emits a single stderr line decoding an error frame: the 4-byte
 *       big-endian errnum, its symbolic name, and the trailing message text
 *       (bytes past the errnum, printed with an explicit length so the buffer
 *       need not be null-terminated).
 *
 * WHY:  The errnum-plus-message layout is specific to kXR_error; isolating it
 *       keeps brix_trace_response a flat dispatch and each per-status decoder
 *       independently reviewable. Caller guarantees b != NULL and blen >= 4.
 *
 * HOW:  1. Read the leading 32-bit BE errnum via the unaligned-safe accessor.
 *       2. Print errnum, its brix_kxr_name(), and the message slice
 *          (blen - 4 bytes when present, else an empty string).
 */
static void
brix_trace_error(int dir, uint16_t sid, const uint8_t *b, uint32_t blen)
{
    int errnum = (int) xrd_get_u32_be(b);
    fprintf(stderr, "%c sid=%u error errnum=%d (%s) \"%.*s\"\n",
            dir, sid, errnum, brix_kxr_name(errnum),
            (int) (blen > 4 ? blen - 4 : 0),
            blen > 4 ? (const char *) (b + 4) : "");
}

/* ---- Trace one kXR_redirect response frame ----
 *
 * WHAT: Emits a single stderr line decoding a redirect frame: the 4-byte
 *       big-endian port followed by the target host slice (bytes past the
 *       port), rendered as host:port.
 *
 * WHY:  The port-then-host layout is unique to kXR_redirect; a dedicated
 *       decoder mirrors brix_trace_error and keeps the dispatcher branch-free
 *       of field math. Caller guarantees b != NULL and blen >= 4.
 *
 * HOW:  1. Read the leading 32-bit BE port via the unaligned-safe accessor.
 *       2. Print the host slice (blen - 4 bytes when present, else empty)
 *          joined to the port with a colon.
 */
static void
brix_trace_redirect(int dir, uint16_t sid, const uint8_t *b, uint32_t blen)
{
    int port = (int) xrd_get_u32_be(b);
    fprintf(stderr, "%c sid=%u redirect → %.*s:%d\n",
            dir, sid, (int) (blen > 4 ? blen - 4 : 0),
            blen > 4 ? (const char *) (b + 4) : "", port);
}

/* ---- Trace one kXR_wait response frame ----
 *
 * WHAT: Emits a single stderr line decoding a wait frame's 4-byte big-endian
 *       wait interval, in seconds.
 *
 * WHY:  kXR_wait carries only the retry delay; a leaf decoder keeps it uniform
 *       with the other per-status helpers. Caller guarantees b != NULL and
 *       blen >= 4.
 *
 * HOW:  1. Read the 32-bit BE interval via the unaligned-safe accessor.
 *       2. Print it with a trailing 's' for seconds.
 */
static void
brix_trace_wait(int dir, uint16_t sid, const uint8_t *b)
{
    fprintf(stderr, "%c sid=%u wait %us\n",
            dir, sid, xrd_get_u32_be(b));
}

/* ---- Trace a response (non-request) frame ----
 *
 * WHAT: Emits one stderr line for a response frame, decoding the few
 *       high-value bodies (error, redirect, wait) when the body is present and
 *       long enough, or falling back to a generic status-name + dlen line.
 *
 * WHY:  Splitting the response side out of brix_trace_frame collapses the
 *       status branch ladder into a flat early-dispatch and lets each body
 *       decoder be a small single-purpose helper — the same wire fields are
 *       decoded from our own structs, never from XrdCl.
 *
 * HOW:  1. If code is kXR_error with a >= 4-byte body, delegate to
 *          brix_trace_error.
 *       2. Else if kXR_redirect with a >= 4-byte body, delegate to
 *          brix_trace_redirect.
 *       3. Else if kXR_wait with a >= 4-byte body, delegate to
 *          brix_trace_wait.
 *       4. Otherwise print the generic status-name + dlen line.
 */
static void
brix_trace_response(int dir, uint16_t sid, int code, uint32_t dlen,
                    const uint8_t *b, uint32_t blen)
{
    if (code == kXR_error && b != NULL && blen >= 4) {
        brix_trace_error(dir, sid, b, blen);
    } else if (code == kXR_redirect && b != NULL && blen >= 4) {
        brix_trace_redirect(dir, sid, b, blen);
    } else if (code == kXR_wait && b != NULL && blen >= 4) {
        brix_trace_wait(dir, sid, b);
    } else {
        fprintf(stderr, "%c sid=%u %s dlen=%u\n",
                dir, sid, brix_status_name(code), dlen);
    }
}

void
brix_trace_frame(brix_conn *c, int dir, uint16_t sid, int code,
                 int is_request, uint32_t dlen, const void *body, uint32_t blen)
{
    const uint8_t *b = (const uint8_t *) body;

    if (is_request) {
        fprintf(stderr, "%c sid=%u %s dlen=%u\n",
                dir, sid, brix_reqid_name(code), dlen);
    } else {
        brix_trace_response(dir, sid, code, dlen, b, blen);
    }

    if (c->diag.wire_trace >= 2 && b != NULL && blen > 0) {
        hexdump(b, blen);
    }
}

void
brix_timing_report(const brix_conn *c)
{
    int i, any = 0;
    for (i = 0; i < XRDC_NOP; i++) {
        uint64_t n = c->diag.rtt[i].n;
        double   tot, avg;
        if (n == 0) {
            continue;
        }
        if (!any) {
            fprintf(stderr, "--- per-opcode RTT (n / total / min / avg / max ms) ---\n");
            any = 1;
        }
        tot = (double) c->diag.rtt[i].tot_ns / 1e6;
        avg = tot / (double) n;
        fprintf(stderr, "  %-12s n=%-4llu tot=%.3f min=%.3f avg=%.3f max=%.3f\n",
                brix_reqid_name(i + kXR_1stRequest),
                (unsigned long long) n, tot,
                (double) c->diag.rtt[i].min_ns / 1e6, avg,
                (double) c->diag.rtt[i].max_ns / 1e6);
    }
}
