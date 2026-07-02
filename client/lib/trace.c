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
#include "xrdc.h"

#include "core/compat/kxr_names.h"   /* shared kXR opcode/status name tables (libxrdproto) */
#include "protocols/root/protocol/frame_hdr.h" /* unaligned-safe BE field accessors (libxrdproto) */

#include <arpa/inet.h>
#include <string.h>
#include <time.h>

/* Both forward to the shared kXR name tables (libxrdproto's kxr_names.c) so the
 * module and client share one source of truth keyed on protocol/opcodes.h. */
const char *
xrdc_reqid_name(int reqid)
{
    return xrootd_kxr_request_name(reqid);
}

const char *
xrdc_status_name(int status)
{
    return xrootd_kxr_response_status_name(status);
}

uint64_t
xrdc_mono_ns(void)
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
xrdc_jitter_ms(unsigned span_ms)
{
    static uint64_t state;   /* lazily seeded; 0 until first use */
    if (span_ms == 0) {
        return 0;
    }
    if (state == 0) {
        state = xrdc_mono_ns() | 1ull;
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

void
xrdc_trace_frame(xrdc_conn *c, int dir, uint16_t sid, int code,
                 int is_request, uint32_t dlen, const void *body, uint32_t blen)
{
    const uint8_t *b = (const uint8_t *) body;

    if (is_request) {
        fprintf(stderr, "%c sid=%u %s dlen=%u\n",
                dir, sid, xrdc_reqid_name(code), dlen);
    } else {
        /* Decode the few high-value fields per status, from our own structs. */
        if (code == kXR_error && b != NULL && blen >= 4) {
            int errnum = (int) xrd_get_u32_be(b);
            fprintf(stderr, "%c sid=%u error errnum=%d (%s) \"%.*s\"\n",
                    dir, sid, errnum, xrdc_kxr_name(errnum),
                    (int) (blen > 4 ? blen - 4 : 0),
                    blen > 4 ? (const char *) (b + 4) : "");
        } else if (code == kXR_redirect && b != NULL && blen >= 4) {
            int port = (int) xrd_get_u32_be(b);
            fprintf(stderr, "%c sid=%u redirect → %.*s:%d\n",
                    dir, sid, (int) (blen > 4 ? blen - 4 : 0),
                    blen > 4 ? (const char *) (b + 4) : "", port);
        } else if (code == kXR_wait && b != NULL && blen >= 4) {
            fprintf(stderr, "%c sid=%u wait %us\n",
                    dir, sid, xrd_get_u32_be(b));
        } else {
            fprintf(stderr, "%c sid=%u %s dlen=%u\n",
                    dir, sid, xrdc_status_name(code), dlen);
        }
    }

    if (c->diag.wire_trace >= 2 && b != NULL && blen > 0) {
        hexdump(b, blen);
    }
}

void
xrdc_timing_report(const xrdc_conn *c)
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
                xrdc_reqid_name(i + kXR_1stRequest),
                (unsigned long long) n, tot,
                (double) c->diag.rtt[i].min_ns / 1e6, avg,
                (double) c->diag.rtt[i].max_ns / 1e6);
    }
}
