/* Phase-118 page, vector and HTTP-range case generators. */
#include "conform/conform.h"

#include <stddef.h>

static int
pairwise_selected(const size_t *at, const size_t *sizes, size_t axes)
{
    size_t left;
    size_t right;

    if (axes < 2) return 1;
    for (left = 0; left < axes; left++) {
        for (right = left + 1; right < axes; right++) {
            size_t axis;
            int    matches = 1;

            for (axis = 0; axis < axes; axis++) {
                size_t expected;

                if (axis == left || axis == right) continue;
                expected = (at[left] + at[right] + axis) % sizes[axis];
                if (at[axis] != expected) {
                    matches = 0;
                    break;
                }
            }
            if (matches) return 1;
        }
    }
    return 0;
}

int
brix_conform_product_selected(brix_conform_budget budget, const size_t *at,
    const size_t *sizes, size_t axes)
{
    size_t axis;

    if (budget == BRIX_CONFORM_EXHAUSTIVE) return 1;
    if (budget == BRIX_CONFORM_PAIRWISE) {
        return pairwise_selected(at, sizes, axes);
    }
    for (axis = 0; axis < axes; axis++) {
        if (at[axis] == 0 || at[axis] + 1 == sizes[axis]) return 1;
    }
    return 0;
}

size_t
brix_conform_page_cases(brix_conform_budget budget,
    brix_conform_page_case *out, size_t cap)
{
    static const uint32_t first[] = { 0, 1, 2048, 4095 };
    static const uint32_t last[] = { 0, 1, 2048, 4095 };
    static const uint32_t full[] = { 0, 1, 2, 255, 4095 };
    const size_t sizes[] = { 4, 4, 5 };
    size_t       at[3];
    size_t       count = 0;

    for (at[0] = 0; at[0] < sizes[0]; at[0]++) {
        for (at[1] = 0; at[1] < sizes[1]; at[1]++) {
            for (at[2] = 0; at[2] < sizes[2]; at[2]++) {
                brix_conform_page_case item;

                if (!brix_conform_product_selected(budget, at, sizes, 3)) continue;
                item.first_page_off = first[at[0]];
                item.last_page_bytes = last[at[1]];
                item.full_pages = full[at[2]];
                item.offset = item.first_page_off;
                item.length = (item.first_page_off == 0
                    ? BRIX_CONFORM_PAGE_SIZE
                    : BRIX_CONFORM_PAGE_SIZE - item.first_page_off)
                    + (uint64_t) item.full_pages * BRIX_CONFORM_PAGE_SIZE
                    + item.last_page_bytes;
                if (count < cap) out[count] = item;
                count++;
            }
        }
    }
    return count;
}

const char *
brix_conform_vector_geometry_name(brix_conform_vector_geometry geometry)
{
    static const char *const names[] = {
        "ascending", "descending", "interleaved", "duplicated",
        "overlapping", "adjacent", "gapped", "eof-straddling", "past-eof"
    };

    if ((size_t) geometry >= sizeof(names) / sizeof(names[0])) return "unknown";
    return names[geometry];
}

size_t
brix_conform_vector_cases(brix_conform_budget budget,
    brix_conform_vector_case *out, size_t cap)
{
    static const uint32_t counts[] = { 0, 1, 2, 1023, 1024, 1025 };
    static const uint32_t lengths[] = { 0, 1, 4096, 2048, 2097136 };
    static const uint32_t totals[] = { 2097135, 2097136, 2097137 };
    static const uint32_t handles[] = { 1, 3, 2 };
    const size_t sizes[] = { 6, 5, 3, 9, 3 };
    size_t       at[5];
    size_t       count = 0;

    for (at[0] = 0; at[0] < sizes[0]; at[0]++) {
        for (at[1] = 0; at[1] < sizes[1]; at[1]++) {
            for (at[2] = 0; at[2] < sizes[2]; at[2]++) {
                for (at[3] = 0; at[3] < sizes[3]; at[3]++) {
                    for (at[4] = 0; at[4] < sizes[4]; at[4]++) {
                        brix_conform_vector_case item;

                        if (!brix_conform_product_selected(budget, at, sizes, 5)) continue;
                        item.element_count = counts[at[0]];
                        item.element_size = lengths[at[1]];
                        item.total_bytes = totals[at[2]];
                        item.geometry = (brix_conform_vector_geometry) at[3];
                        item.handle_count = handles[at[4]];
                        if (count < cap) out[count] = item;
                        count++;
                    }
                }
            }
        }
    }
    return count;
}

const brix_conform_http_range_case *
brix_conform_http_range_cases(brix_conform_budget budget, size_t *count)
{
    static const brix_conform_http_range_case all[] = {
        { "bytes=0-0", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=-1", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=-0", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=-S", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=-(S+1)", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=(S-1)-", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=S-", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=(S+1)-", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=0-(S-1)", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-S", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-(S+1)", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=1-0", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=0-0,-1", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-99,100-199", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=100-199,0-99", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-99,50-149", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=0-0,0-0", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes = 0 - 0", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "items=0-0", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "bytes=abc-def", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "bytes=<101-ranges>", BRIX_CONFORM_HTTP_RANGE_OVER_LIMIT }
    };
    static const brix_conform_http_range_case boundary[] = {
        { "bytes=0-0", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=-0", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=S-", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes=0-S", BRIX_CONFORM_HTTP_RANGE_VALID },
        { "bytes=1-0", BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE },
        { "bytes = 0 - 0", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "items=0-0", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "bytes=abc-def", BRIX_CONFORM_HTTP_RANGE_INVALID },
        { "bytes=<101-ranges>", BRIX_CONFORM_HTTP_RANGE_OVER_LIMIT }
    };

    if (budget == BRIX_CONFORM_BOUNDARY) {
        *count = sizeof(boundary) / sizeof(boundary[0]);
        return boundary;
    }
    *count = sizeof(all) / sizeof(all[0]);
    return all;
}
