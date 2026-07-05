/*
 * metabench_unittest.c — standalone checks for the PURE manifest/percentile
 * helpers. Build (no libbrix needed):
 *   cc -Wall -Wextra -Ilib lib/metabench_unittest.c lib/metabench.c -o /tmp/mbu
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "metabench.h"

static int checks;
#define CHECK(c) do { checks++; if (!(c)) { \
    printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

int main(void)
{
    metabench_plan p;
    metabench_plan_init(&p, 8, 125, 50);
    CHECK(p.workers == 8);
    CHECK(p.dirs_per_worker >= 1 && p.files_per_dir >= 1);

    /* per-worker op budget lands near 125 → total near 1000 */
    long total = metabench_storm_ops(&p);
    CHECK(total >= 800 && total <= 1200);

    /* expected namespace: 1 (/w) + D dirs + D*F files per worker */
    static metabench_entry buf[4096];
    size_t n = metabench_expected(&p, buf, 4096);
    size_t per_worker = 1 + (size_t) p.dirs_per_worker
                          + (size_t) p.dirs_per_worker * (size_t) p.files_per_dir;
    CHECK(n == per_worker * (size_t) p.workers);

    /* sorted + modes/types assigned */
    for (size_t i = 1; i < n; i++) {
        CHECK(strcmp(buf[i - 1].path, buf[i].path) <= 0);
    }
    CHECK(buf[0].is_dir == 1);

    /* every dir is 0755 or 0700, every file 0640 */
    for (size_t i = 0; i < n; i++) {
        if (buf[i].is_dir) {
            CHECK(buf[i].mode == 0755 || buf[i].mode == 0700);
        } else {
            CHECK(buf[i].mode == 0640);
        }
    }

    /* percentile: p50 of 1..100 ≈ 50.5, p99 high, empty → 0 */
    double s[100];
    for (int i = 0; i < 100; i++) {
        s[i] = i + 1;
    }
    CHECK(metabench_percentile(s, 100, 50.0) > 49.0
       && metabench_percentile(s, 100, 50.0) < 52.0);
    CHECK(metabench_percentile(s, 100, 99.0) > 98.0);
    CHECK(metabench_percentile(s, 0, 99.0) == 0.0);

    printf("ok — %d checks\n", checks);
    return 0;
}
