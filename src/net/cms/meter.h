#ifndef BRIX_CMS_METER_H
#define BRIX_CMS_METER_H

/*
 * cms/meter.h — native machine-load meter for the CMS heartbeat (Phase-89 W4).
 *
 * WHAT: Fills the first five kYR_load "theLoad" bytes (cpu, net, xeq, mem,
 * pag — each a 0-100 percentage) from /proc, replacing the zero placeholders,
 * analogous to XrdCmsMeter without the C++ ABI.  The sixth byte (dsk) stays
 * the caller's statvfs-derived utilisation.
 *
 * WHY: A manager balancing on load needs real figures; zeros advertise every
 * node as idle.  The parsers are pure (buffer in, number out, no I/O) so the
 * standalone meter_unittest.c can exercise them without a running nginx.
 *
 * HOW: brix_cms_meter_sample() reads /proc/loadavg, /proc/meminfo,
 * /proc/net/dev and /proc/vmstat, converts the instantaneous readings (cpu,
 * mem) directly and the counter readings (net, pag) as deltas against the
 * previous sample held in brix_cms_meter_t.  Any read/parse failure yields 0
 * for that byte — a meter fault must never take the heartbeat down.  The
 * state struct is valid all-zeroes, so a pcalloc'd owner needs no init call;
 * the first sample reports 0 for the delta-based bytes (unprimed).
 *
 * Pure C: no nginx dependency (unit-tested standalone like rrdata/router).
 */

#include <stdint.h>
#include <stddef.h>

/* Delta state between samples.  All-zeroes = valid initial state. */
typedef struct {
    uint64_t  prev_net_bytes;   /* sum of rx+tx bytes across physical NICs  */
    uint64_t  prev_pgmajfault;  /* cumulative major page faults             */
    uint64_t  prev_ms;          /* caller clock (ms) of the previous sample */
    unsigned  primed;           /* 1 once deltas are meaningful             */
} brix_cms_meter_t;

/* Reference rates that map a delta to a 0-100 percentage.  Fixed nominal
 * figures (1 Gbit/s NIC; 100 major faults/s = fully paging) — the meter is a
 * balancing hint, not an SLA measurement. */
#define BRIX_CMS_METER_NET_REF_BYTES_PER_SEC  (125u * 1000u * 1000u)
#define BRIX_CMS_METER_PAG_REF_FAULTS_PER_SEC 100u

/*
 * Sample the machine and fill out5 = {cpu, net, xeq, mem, pag}, each 0-100.
 * now_ms is the caller's monotonic millisecond clock (ngx_current_msec in
 * nginx; any monotone source in tests).  xeq (run-queue depth) is always 0 —
 * nginx has no per-request queue to report.  Never fails: unparseable or
 * unavailable inputs report 0 for the affected byte.
 */
void brix_cms_meter_sample(brix_cms_meter_t *m, uint64_t now_ms,
    uint8_t out5[5]);

/* Pure parsers (exposed for meter_unittest.c).  Each returns 0 on success
 * with the out param set, -1 on a malformed buffer (out untouched). */

/* "/proc/loadavg" ("0.42 0.31 ..."): *pct = 1-min load / ncpu as 0-100. */
int brix_cms_meter_parse_loadavg(const char *buf, long ncpu, uint8_t *pct);

/* "/proc/meminfo": *pct = (MemTotal - MemAvailable) / MemTotal as 0-100. */
int brix_cms_meter_parse_meminfo(const char *buf, uint8_t *pct);

/* "/proc/net/dev": *total_bytes = sum of rx+tx byte counters over every
 * interface except "lo" (loopback traffic is not network load). */
int brix_cms_meter_parse_netdev(const char *buf, uint64_t *total_bytes);

/* "/proc/vmstat": *pgmajfault = the cumulative "pgmajfault" counter. */
int brix_cms_meter_parse_vmstat(const char *buf, uint64_t *pgmajfault);

/* Map a counter delta over elapsed_ms to a 0-100 percentage of ref_per_sec.
 * elapsed_ms == 0 → 0 (no division; also covers clock stalls). */
uint8_t brix_cms_meter_rate_pct(uint64_t delta, uint64_t elapsed_ms,
    uint64_t ref_per_sec);

#endif /* BRIX_CMS_METER_H */
