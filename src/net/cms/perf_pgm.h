#ifndef BRIX_CMS_PERF_PGM_H
#define BRIX_CMS_PERF_PGM_H

/*
 * cms/perf_pgm.h — §2.11 external machine-load feed (stock cms.perf pgm).
 *
 * Contract: brix_cms_perf_start() is called once per worker that runs the
 * CMS client (cms_start.c, worker 0); it is a no-op unless brix_cms_perf_pgm
 * is configured.  brix_cms_perf_get() returns 1 with the last fed
 * {cpu, net, xeq, mem, pag} vector while it is fresh (within 2x
 * brix_cms_perf_interval), else 0 — the caller then falls back to the /proc
 * meter, so a dead or wedged feed degrades instead of lying.
 *
 * Requires: cms_internal.h types (include after it).
 */

#include <stdint.h>

void brix_cms_perf_start(ngx_cycle_t *cycle,
    ngx_stream_brix_srv_conf_t *conf);
int  brix_cms_perf_get(uint8_t out5[5]);

#endif /* BRIX_CMS_PERF_PGM_H */
