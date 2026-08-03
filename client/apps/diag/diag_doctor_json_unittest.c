/*
 * diag_doctor_json_unittest.c — standalone unit test for the `xrddiag doctor
 * --json` document assembler (diag_doctor_json.c).
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Ilib -I../src -I../shared \
 *      -DXRDPROTO_NO_NGX apps/diag/diag_doctor_json_unittest.c -o /tmp/ut \
 *   && /tmp/ut          (run from client/)
 *
 * Exit 0 = all checks pass. Pure C — no server, no connection, no libbrix: the
 * TU under test is #included and every extern it calls is satisfied by a stub
 * here. The sub-object emitters (config/latency/recon/eos) are each owned by
 * their own TU and each writes its OWN leading comma, so the property this
 * suite pins is the assembler's: every sub-object must be written INSIDE the
 * endpoint object, i.e. before the `}` that closes it. A regression that emits
 * one after the brace yields a document that is still plausible-looking text
 * but is not parseable JSON — exactly the `eos` defect this suite was written
 * for. The C side asserts byte ordering; the Python driver
 * (tests/test_doctor_json_unit.py) feeds the printed document to a real JSON
 * parser, which is the assertion that actually matters.
 */
#define _GNU_SOURCE   /* open_memstream */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_internal.h"

/* ---- extern stubs ---------------------------------------------------------
 * The four sub-object emitters are stubbed rather than linked: each real one
 * lives in a TU that drags in libbrix. What matters to the assembler is their
 * CONTRACT — "emit `,\"name\":{...}` or nothing" — so the stubs reproduce that
 * shape byte-for-byte (leading comma, one object, no trailing comma) and are
 * gated on the same struct fields the real emitters test.
 */
const char *
doc_color(int s)
{
    return s == DOC_RED ? "red" : s == DOC_YELLOW ? "yellow" : "green";
}

const char *
dx_proto_name(dx_proto p)
{
    return p == DXP_ROOT ? "root" : p == DXP_CMS ? "cms" : "http";
}

const char *
dx_verdict_name(int v)
{
    return v == DX_FAIL ? "fail" : v == DX_WARN ? "warn" : "ok";
}

/* Minimal but correct JSON string emitter (the real one is fjson.c). */
void
fjson_str(FILE *out, const char *s)
{
    fputc('"', out);
    for (; s != NULL && *s != '\0'; s++) {
        if (*s == '"' || *s == '\\') {
            fprintf(out, "\\%c", *s);
        } else if ((unsigned char) *s < 0x20) {
            fprintf(out, "\\u%04x", (unsigned char) *s);
        } else {
            fputc(*s, out);
        }
    }
    fputc('"', out);
}

void
doctor_emit_config_json(const doctor_ep *e, FILE *out)
{
    (void) e;
    fprintf(out, ",\"config\":null");
}

void
doctor_emit_latency_json(const doctor_ep *e, FILE *out)
{
    if (!e->lat.probed) {
        return;
    }
    fprintf(out, ",\"latency\":{\"samples\":%d}", e->lat.samples);
}

void
doctor_emit_recon_json(const doctor_ep *e, FILE *out)
{
    (void) e;
    (void) out;                 /* never probed here => the emitter is silent */
}

void
doctor_eos_emit_json(const doctor_ep *e, FILE *out)
{
    if (e->eos.kind == DOC_EOS_MGM) {
        fprintf(out, ",\"eos\":{\"kind\":\"mgm\",\"instance\":");
        fjson_str(out, e->eos.instance);
        fprintf(out, ",\"fst_count\":%d}", e->eos.fst_count);
    } else if (e->eos.kind == DOC_EOS_FST) {
        fprintf(out, ",\"eos\":{\"kind\":\"fst\",\"geotag\":");
        fjson_str(out, e->eos.geotag);
        fprintf(out, ",\"capacity\":%lld}", (long long) e->eos.cap_bytes);
    }
}

#include "diag_doctor_json.c"

/* ---- harness ---- */
static int g_fail;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
                   g_fail++; } \
} while (0)

/* Byte offset of `needle` in `hay`, or -1. */
static long
at(const char *hay, const char *needle)
{
    const char *p = strstr(hay, needle);

    return p == NULL ? -1 : (long) (p - hay);
}

/* Structural nesting depth at the first occurrence of `needle`, counting only
 * brackets outside string literals; -1 when the needle is absent. This is what
 * makes the placement assertion decisive: an object member sits one level below
 * the object that owns it, so a sub-object flushed out past the endpoint's
 * closing brace lands at the DEPTH OF THE ARRAY, not of its sibling keys —
 * a difference no substring search can see. */
static int
key_depth(const char *doc, const char *needle)
{
    const char *hit = strstr(doc, needle);
    const char *p;
    int         depth = 0, instr = 0;

    if (hit == NULL) {
        return -1;
    }
    for (p = doc; p < hit; p++) {
        if (instr) {
            instr = (*p == '\\') ? (p++, 1) : (*p != '"');
            continue;
        }
        if (*p == '"') {
            instr = 1;
        } else if (*p == '{' || *p == '[') {
            depth++;
        } else if (*p == '}' || *p == ']') {
            depth--;
        }
    }
    return depth;
}

/* Two endpoints: [0] an EOS MGM with a latency probe, [1] a plain FST. */
static void
build_eps(doctor_ep *eps)
{
    memset(eps, 0, sizeof(doctor_ep) * 2);

    eps[0].proto     = DXP_ROOT;
    snprintf(eps[0].host, sizeof(eps[0].host), "mgm.example.org");
    eps[0].port      = 1094;
    eps[0].connected = 1;
    eps[0].status    = DOC_GREEN;
    snprintf(eps[0].auth, sizeof(eps[0].auth), "gsi");
    eps[0].cms.reported = 1;
    eps[0].cms.role     = DOC_CMS_MANAGER;
    eps[0].lat.probed   = 1;
    eps[0].lat.samples  = 5;
    eps[0].eos.kind     = DOC_EOS_MGM;
    snprintf(eps[0].eos.instance, sizeof(eps[0].eos.instance), "eosdev");
    eps[0].eos.fst_count = 3;
    eps[0].nissues = 1;
    snprintf(eps[0].issues[0], sizeof(eps[0].issues[0]),
             "quoted \"issue\" with a backslash \\");

    eps[1].proto     = DXP_ROOT;
    snprintf(eps[1].host, sizeof(eps[1].host), "fst01.example.org");
    eps[1].port      = 1095;
    eps[1].connected = 1;
    eps[1].status    = DOC_YELLOW;
    eps[1].cms.reported = 1;
    eps[1].cms.role     = DOC_CMS_SERVER;
    eps[1].cms.write    = 1;
    eps[1].eos.kind     = DOC_EOS_FST;
    snprintf(eps[1].eos.geotag, sizeof(eps[1].eos.geotag), "uk::ed::r1");
    eps[1].eos.cap_bytes = 42000000000LL;
    eps[1].ndx = 1;
    snprintf(eps[1].dx[0].probe,  sizeof(eps[1].dx[0].probe),  "read");
    eps[1].dx[0].verdict = DX_WARN;
    eps[1].dx[0].kxr     = 3014;
    snprintf(eps[1].dx[0].cause,  sizeof(eps[1].dx[0].cause),  "no holder");
    snprintf(eps[1].dx[0].remedy, sizeof(eps[1].dx[0].remedy), "check cmsd");
}

/* Render the two-endpoint document into a heap buffer the caller frees. */
static char *
render(void)
{
    doctor_ep eps[2];
    char     *buf = NULL;
    size_t    len = 0;
    FILE     *ms  = open_memstream(&buf, &len);

    if (ms == NULL) {
        return NULL;
    }
    build_eps(eps);
    doctor_emit_json(eps, 2, ms);
    fclose(ms);
    return buf;
}

int
main(void)
{
    char *doc = render();
    long  eos0, eos1, brace0, cms0;
    int   depth;

    if (doc == NULL) {
        printf("FAIL: open_memstream\n");
        return 1;
    }

    /* Every sub-object is present and nothing is emitted for the absent ones. */
    CHECK(at(doc, "\"eos\":{\"kind\":\"mgm\"") >= 0);
    CHECK(at(doc, "\"eos\":{\"kind\":\"fst\"") >= 0);
    CHECK(at(doc, "\"latency\":{\"samples\":5}") >= 0);
    CHECK(at(doc, "\"recon\"") < 0);          /* unprobed => nothing at all */
    CHECK(at(doc, "\"cross_endpoint_analysis\":{\"hops\":1}") >= 0);

    /* The defect this suite exists for: `eos` must land INSIDE the endpoint
     * object — i.e. at the same nesting depth as the endpoint's own keys, and
     * before the `},{` that starts the next endpoint. */
    eos0   = at(doc, "\"eos\":{\"kind\":\"mgm\"");
    brace0 = at(doc, "},{\"protocol\"");
    cms0   = at(doc, "\"cms\":{\"reported\":true,\"role\":\"manager\"");
    CHECK(brace0 > 0);
    CHECK(eos0 > 0 && eos0 < brace0);
    CHECK(cms0 > 0 && cms0 < eos0);           /* documented emit order */
    depth = key_depth(doc, "\"protocol\"");   /* an endpoint's own key */
    CHECK(depth > 0);
    CHECK(key_depth(doc, "\"eos\":{\"kind\":\"mgm\"") == depth);
    CHECK(key_depth(doc, "\"eos\":{\"kind\":\"fst\"") == depth);
    CHECK(key_depth(doc, "\"latency\":") == depth);
    CHECK(key_depth(doc, "\"cms\":") == depth);
    CHECK(key_depth(doc, "\"config\":") == depth);

    /* The last endpoint's eos must precede the array terminator. */
    eos1 = at(doc, "\"eos\":{\"kind\":\"fst\"");
    CHECK(eos1 > 0 && eos1 < at(doc, "],\"cross_endpoint_analysis\""));

    /* Strings carrying JSON metacharacters are escaped, not passed through. */
    CHECK(at(doc, "quoted \\\"issue\\\" with a backslash \\\\") >= 0);

    /* Hand the whole document to the Python driver's real JSON parser. */
    printf("JSON %s", doc);
    if (doc[strlen(doc) - 1] != '\n') {
        printf("\n");
    }
    free(doc);

    if (g_fail == 0) {
        printf("all doctor-json assembler checks passed\n");
    }
    return g_fail == 0 ? 0 : 1;
}
