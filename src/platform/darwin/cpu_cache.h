/* Existing Apple CPU-model cache policy for topology estimates.
 * Requires: no prior includes; this is a model estimate, not a hardware probe.
 */
#pragma once

#include <string.h>

static inline int
brix_apple_l2_cache_mb(int generation, const char *model)
{
    const int cache_mb[3][3] = {
        {12, 24, 48},
        {16, 36, 96},
        {16, 36, 144}
    };
    int family = generation >= 3 ? 2 : (generation == 2 ? 1 : 0);
    int edition = 0;

    if (strstr(model, "Max") || (generation < 2 && strstr(model, "Ultra"))) {
        edition = 2;
    } else if (strstr(model, "Pro")) {
        edition = 1;
    }
    return cache_mb[family][edition];
}
