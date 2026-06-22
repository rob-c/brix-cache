/*
 * units.c — byte-count formatting/parsing + transfer rate pacing shared by the
 * front-end tools (xrdfs dd/upload/download, and any future throttled transfer).
 *
 * xrdc_fmt_size  : render a byte count (raw, or human "1.5G").
 * xrdc_parse_bytes: parse "4096" / "1.5G" (K/M/G/T) → bytes, or -1 if malformed.
 * xrdc_rate_pace : token-bucket sleep so an average stays at/below a byte/s rate.
 */
#include "xrdc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void
xrdc_fmt_size(int64_t n, char *out, size_t sz, int human)
{
    if (!human) {
        snprintf(out, sz, "%lld", (long long) n);
        return;
    }
    {
        static const char u[] = "BKMGTPE";
        double  d = (double) n;
        int     i = 0;
        while (d >= 1024.0 && i < 6) { d /= 1024.0; i++; }
        if (i == 0) { snprintf(out, sz, "%lld", (long long) n); }
        else        { snprintf(out, sz, "%.1f%c", d, u[i]); }
    }
}

int64_t
xrdc_parse_bytes(const char *s)
{
    char   *end;
    double  v;
    int64_t mult = 1;

    if (s == NULL || *s == '\0') { return -1; }
    errno = 0;
    v = strtod(s, &end);
    if (end == s || v < 0 || errno != 0) { return -1; }
    if (*end != '\0') {
        switch (*end) {
            case 'k': case 'K': mult = 1024LL; break;
            case 'm': case 'M': mult = 1024LL * 1024; break;
            case 'g': case 'G': mult = 1024LL * 1024 * 1024; break;
            case 't': case 'T': mult = 1024LL * 1024 * 1024 * 1024; break;
            default: return -1;
        }
        if (end[1] != '\0') { return -1; }
    }
    return (int64_t) (v * (double) mult);
}

void
xrdc_rate_pace(const struct timespec *start, int64_t sent, double rate)
{
    struct timespec now, ts;
    double          elapsed, target, deficit;

    if (rate <= 0.0) { return; }
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (double) (now.tv_sec - start->tv_sec)
            + (double) (now.tv_nsec - start->tv_nsec) / 1e9;
    target  = (double) sent / rate;   /* when we *should* have reached `sent` */
    deficit = target - elapsed;
    if (deficit <= 0.0) { return; }
    ts.tv_sec  = (time_t) deficit;
    ts.tv_nsec = (long) ((deficit - (double) ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}
