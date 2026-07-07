/*
 * pblock_meta_bench.c — Layer (a) of the pblock metadata reliability suite.
 *
 * Thin main over client/lib/metabench: the thinnest client surface, so it
 * isolates the pblock backend. GSI is taken from X509_USER_PROXY / X509_CERT_DIR
 * (exported by the umbrella tests/run_pblock_meta_gsi.sh).
 *
 * usage: pblock_meta_bench [--workers N] [--ops-per-worker N] [--p99-ceil-ms N]
 *                          [--phase create|remove] [--json] [--print-expected]
 *                          <root-url>
 * exit: 0 = all ops ok and p99 within ceiling; non-zero otherwise.
 *
 * build (done by the umbrella): cc -Ilib -I../src -DXRDPROTO_NO_NGX
 *        tests/tools/pblock_meta_bench.c client/libbrix.a \
 *        shared/xrdproto/libxrdproto.a <ssl/crypto/z/...> -lpthread -o pmb
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "observability/metabench/metabench.h"
#include "observability/metabench/metabench_run.h"

static int arg_int(const char *v, int dflt)
{
    return v ? atoi(v) : dflt;
}

int main(int argc, char **argv)
{
    int workers = 8, ops = 125, ceil_ms = 50, json = 0, print_expected = 0;
    metabench_phase phase = MB_CREATE;
    const char *url_s = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--workers") && i + 1 < argc) {
            workers = arg_int(argv[++i], workers);
        } else if (!strcmp(argv[i], "--ops-per-worker") && i + 1 < argc) {
            ops = arg_int(argv[++i], ops);
        } else if (!strcmp(argv[i], "--p99-ceil-ms") && i + 1 < argc) {
            ceil_ms = arg_int(argv[++i], ceil_ms);
        } else if (!strcmp(argv[i], "--phase") && i + 1 < argc) {
            phase = strcmp(argv[++i], "remove") ? MB_CREATE : MB_REMOVE;
        } else if (!strcmp(argv[i], "--json")) {
            json = 1;
        } else if (!strcmp(argv[i], "--print-expected")) {
            print_expected = 1;
        } else {
            url_s = argv[i];
        }
    }
    if (url_s == NULL) {
        fprintf(stderr, "usage: pblock_meta_bench [opts] <root-url>\n");
        return 2;
    }

    metabench_plan plan;
    metabench_plan_init(&plan, workers, ops, ceil_ms);

    if (print_expected) {   /* "MODE is_dir PATH" sorted — the umbrella diffs this */
        static metabench_entry buf[8192];
        size_t n = metabench_expected(&plan, buf, 8192);
        for (size_t i = 0; i < n && i < 8192; i++) {
            printf("%04o %d %s\n", buf[i].mode & 0777, buf[i].is_dir, buf[i].path);
        }
        return 0;
    }

    brix_url u;
    brix_opts o;
    brix_status st;
    memset(&o, 0, sizeof(o));
    brix_status_clear(&st);
    if (brix_url_parse(url_s, &u, &st) != 0) {
        fprintf(stderr, "bad url: %s\n", url_s);
        return 2;
    }
    /* GSI: libbrix reads X509_USER_PROXY / X509_CERT_DIR from env and the default
     * opts auto-negotiate the server-advertised auth (gsi here). */

    metabench_result r;
    int rc = metabench_run(&u, &o, &plan, phase, &r, &st);
    if (json) {
        metabench_result_json(&r, stdout);
    } else {
        metabench_result_print(&r, stdout);
    }
    return rc == 0 ? 0 : 1;
}
