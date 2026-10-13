/*
 * cms/meter.c — native machine-load meter for the CMS heartbeat (Phase-89 W4).
 *
 * WHAT: PAL-backed load figures for the kYR_load theLoad bytes — pure
 * parsers (unit-tested standalone) plus the sampling driver that owns the
 * file I/O and delta bookkeeping.
 *
 * WHY: See meter.h.  The parser/driver split keeps everything with a
 * behavioural decision (percentage mapping, delta priming, malformed input)
 * out of the I/O path so meter_unittest.c covers it byte-for-byte.
 *
 * HOW: Each legacy parser walks one text buffer with strtoul/strtod-style
 * scanning and rejects buffers missing the expected fields. sample() uses the
 * host PAL exclusively. Deltas (net, pag)
 * need two samples: the first call only primes the counters.
 */

#include "core/types/tunables.h"
#include "meter.h"
#include "platform/platform_api.h"

#include <stdlib.h>
#include <string.h>

/* Clamp a computed percentage into the wire byte's 0-100 range. */
static uint8_t
meter_clamp_pct(unsigned long v)
{
    return (uint8_t) (v > 100 ? 100 : v);
}


int
brix_cms_meter_parse_loadavg(const char *buf, long ncpu, uint8_t *pct)
{
    char    *end;
    double   load1;

    if (buf == NULL || ncpu <= 0) {
        return -1;
    }

    load1 = strtod(buf, &end);
    if (end == buf || load1 < 0.0) {
        return -1;
    }

    *pct = meter_clamp_pct((unsigned long) (load1 * 100.0 / (double) ncpu));
    return 0;
}


/* Find "<key> <number>" in a /proc key-value listing; the key must start a
 * line.  Returns 0 with *out set, -1 if the key is absent/malformed. */
static int
meter_find_counter(const char *buf, const char *key, uint64_t *out)
{
    const char  *p = buf;
    size_t       klen = strlen(key);
    char        *end;

    while (p != NULL && *p != '\0') {
        if (strncmp(p, key, klen) == 0
            && (p[klen] == ' ' || p[klen] == ':'))
        {
            const char    *v = p + klen + 1;
            unsigned long long  n = strtoull(v, &end, 10);
            if (end == v) {
                return -1;
            }
            *out = (uint64_t) n;
            return 0;
        }
        p = strchr(p, '\n');
        if (p != NULL) {
            p++;
        }
    }
    return -1;
}


int
brix_cms_meter_parse_meminfo(const char *buf, uint8_t *pct)
{
    uint64_t  total = 0, avail = 0;

    if (buf == NULL
        || meter_find_counter(buf, "MemTotal:", &total) != 0
        || meter_find_counter(buf, "MemAvailable:", &avail) != 0
        || total == 0)
    {
        return -1;
    }
    if (avail > total) {
        avail = total;
    }

    *pct = meter_clamp_pct((unsigned long) ((total - avail) * 100 / total));
    return 0;
}


int
brix_cms_meter_memory_pct(uint64_t total, uint64_t available, uint8_t *pct)
{
    uint64_t  used;

    if (total == 0 || pct == NULL) {
        return -1;
    }
    used = available < total ? total - available : 0;
    *pct = meter_clamp_pct((unsigned long) ((used * 100) / total));
    return 0;
}


/* Parse one /proc/net/dev interface line's counters starting just past the
 * ':' — rx_bytes first, tx_bytes as field 9 (skip fields 2-8).  Returns 0
 * with *bytes = rx + tx, -1 on a malformed field. */
static int
meter_netdev_line_bytes(const char *colon, uint64_t *bytes)
{
    char                *end;
    unsigned long long   rx, tx;
    int                  f;

    rx = strtoull(colon + 1, &end, 10);
    if (end == colon + 1) {
        return -1;
    }
    /* tx_bytes is field 9 after the colon; skip fields 2-8. */
    for (f = 0; f < 7; f++) {
        const char *v = end;
        (void) strtoull(v, &end, 10);
        if (end == v) {
            return -1;
        }
    }
    {
        const char *v = end;
        tx = strtoull(v, &end, 10);
        if (end == v) {
            return -1;
        }
    }

    *bytes = (uint64_t) rx + (uint64_t) tx;
    return 0;
}


int
brix_cms_meter_parse_netdev(const char *buf, uint64_t *total_bytes)
{
    const char  *p;
    uint64_t     sum = 0;
    int          seen = 0;

    if (buf == NULL) {
        return -1;
    }

    /*
     * Per-interface lines: "  eth0: rx_bytes ... (8 fields) tx_bytes ...".
     * The two header lines carry no ':' followed by digits, so keying on the
     * colon is sufficient.  Loopback is skipped — lo traffic is not network
     * load and would double-count proxy-to-local-backend transfers.
     */
    for (p = buf; p != NULL && *p != '\0'; p = p ? strchr(p, '\n') : NULL,
         p = p ? p + 1 : NULL)
    {
        const char  *colon, *name;
        uint64_t     line_bytes;

        colon = strchr(p, ':');
        if (colon == NULL) {
            break;                      /* no interface lines left */
        }
        {
            const char *nl = strchr(p, '\n');
            if (nl != NULL && colon > nl) {
                continue;               /* header line — colon is further down */
            }
        }

        name = p;
        while (*name == ' ') {
            name++;
        }
        if (strncmp(name, "lo:", 3) == 0) {
            continue;
        }

        if (meter_netdev_line_bytes(colon, &line_bytes) != 0) {
            return -1;
        }

        sum += line_bytes;
        seen = 1;
    }

    if (!seen) {
        return -1;
    }
    *total_bytes = sum;
    return 0;
}


int
brix_cms_meter_parse_vmstat(const char *buf, uint64_t *pgmajfault)
{
    if (buf == NULL) {
        return -1;
    }
    return meter_find_counter(buf, "pgmajfault", pgmajfault);
}


uint8_t
brix_cms_meter_rate_pct(uint64_t delta, uint64_t elapsed_ms,
    uint64_t ref_per_sec)
{
    uint64_t  per_sec;

    if (elapsed_ms == 0 || ref_per_sec == 0) {
        return 0;
    }
    per_sec = delta * BRIX_CMS_SEC_TO_MS_MULTIPLIER / elapsed_ms;
    return meter_clamp_pct((unsigned long) (per_sec * BRIX_PCT_SCALE / ref_per_sec));
}


/* Sample the point-in-time gauges straight into out5. */
static void
meter_sample_gauges(const brix_plat_sysload_t *sample, uint8_t out5[5])
{
    uint8_t  pct;
    int      cpus = brix_plat_cpu_count();

    if ((sample->have & BRIX_SYSLOAD_HAVE_LOAD) != 0 && cpus > 0) {
        double scaled = sample->load1 * 100.0 / (double) cpus;

        out5[0] = meter_clamp_pct((unsigned long) scaled);
    }
    if ((sample->have & BRIX_SYSLOAD_HAVE_MEMORY) != 0
        && brix_cms_meter_memory_pct(sample->total_memory,
            sample->available_memory, &pct) == 0)
    {
        out5[3] = pct;
    }
}


/* Fold the delta-based figures (net, pag) into out5 and roll the previous
 * counters forward.  The first successful sample only primes the counters. */
static void
meter_fold_deltas(brix_cms_meter_t *m, uint64_t now_ms,
    int have_net, uint64_t net_bytes, int have_pag, uint64_t pgmaj,
    uint8_t out5[5])
{
    uint64_t  elapsed;

    elapsed = now_ms > m->prev_ms ? now_ms - m->prev_ms : 0;

    if (m->primed && elapsed > 0) {
        if (have_net && net_bytes >= m->prev_net_bytes) {
            out5[1] = brix_cms_meter_rate_pct(          /* net */
                net_bytes - m->prev_net_bytes, elapsed,
                BRIX_CMS_METER_NET_REF_BYTES_PER_SEC);
        }
        if (have_pag && pgmaj >= m->prev_pgmajfault) {
            out5[4] = brix_cms_meter_rate_pct(          /* pag */
                pgmaj - m->prev_pgmajfault, elapsed,
                BRIX_CMS_METER_PAG_REF_FAULTS_PER_SEC);
        }
    }

    if (have_net) {
        m->prev_net_bytes = net_bytes;
    }
    if (have_pag) {
        m->prev_pgmajfault = pgmaj;
    }
    m->prev_ms = now_ms;
    m->primed  = (have_net || have_pag) ? 1 : m->primed;
}


void
brix_cms_meter_sample(brix_cms_meter_t *m, uint64_t now_ms, uint8_t out5[5])
{
    brix_plat_sysload_t sample;
    int                 have_net;
    int                 have_pag;

    memset(out5, 0, 5);
    if (brix_plat_sysload_sample(&sample) != 0) return;
    meter_sample_gauges(&sample, out5);
    have_net = (sample.have & BRIX_SYSLOAD_HAVE_NET) != 0;
    have_pag = (sample.have & BRIX_SYSLOAD_HAVE_PAGING) != 0;
    meter_fold_deltas(m, now_ms, have_net, sample.net_bytes, have_pag,
        sample.paging_events, out5);
}
