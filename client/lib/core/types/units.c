/*
 * units.c — byte-count formatting/parsing + transfer rate pacing shared by the
 * front-end tools (xrdfs dd/upload/download, and any future throttled transfer).
 *
 * brix_fmt_size  : render a byte count (raw, or human "1.5G").
 * brix_parse_bytes: parse "4096" / "1.5G" (K/M/G/T) → bytes, or -1 if malformed.
 * brix_rate_pace : token-bucket sleep so an average stays at/below a byte/s rate.
 */
#include "brix.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void
brix_fmt_size(int64_t n, char *out, size_t sz, int human)
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

/* ---- Map a single-character size suffix to its byte multiplier ----
 *
 * WHAT: Translates one binary-unit suffix character (case-insensitive
 * K/M/G/T) into its power-of-1024 byte multiplier and returns it. Returns
 * 0 for any character that is not a recognised suffix, letting the caller
 * treat 0 as "invalid" (a real multiplier is always at least 1024).
 *
 * WHY: Isolating the suffix table keeps brix_parse_bytes below the project
 * complexity cap and puts the exact set of accepted suffixes (and their
 * binary — not decimal — scaling) in one auditable place.
 *
 * HOW:
 *   1. Switch on the suffix character.
 *   2. Return 1024^n for K/M/G/T (either case).
 *   3. Return 0 for anything else.
 */
static int64_t
brix_bytes_suffix_multiplier(char c)
{
    switch (c) {
        case 'k': case 'K': return 1024LL;
        case 'm': case 'M': return 1024LL * 1024;
        case 'g': case 'G': return 1024LL * 1024 * 1024;
        case 't': case 'T': return 1024LL * 1024 * 1024 * 1024;
        default:            return 0;
    }
}

int64_t
brix_parse_bytes(const char *s)
{
    char   *end;
    double  v;
    int64_t mult = 1;

    if (s == NULL || *s == '\0') { return -1; }
    errno = 0;
    v = strtod(s, &end);
    if (end == s || v < 0 || errno != 0) { return -1; }
    if (*end != '\0') {
        mult = brix_bytes_suffix_multiplier(*end);
        if (mult == 0) { return -1; }         /* unrecognised suffix */
        if (end[1] != '\0') { return -1; }    /* trailing junk after suffix */
    }
    return (int64_t) (v * (double) mult);
}

void
brix_rate_pace(const struct timespec *start, int64_t sent, double rate)
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
