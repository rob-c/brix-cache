/* Boundary axes and declared combinatorial reductions for Phase 118. */
#include "conform/conform.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int
cmp_i64(const void *left, const void *right)
{
    int64_t a = *(const int64_t *) left;
    int64_t b = *(const int64_t *) right;

    return (a > b) - (a < b);
}

static size_t
sort_unique(int64_t *values, size_t count)
{
    size_t in;
    size_t out = 0;

    qsort(values, count, sizeof(values[0]), cmp_i64);
    for (in = 0; in < count; in++) {
        if (out == 0 || values[in] != values[out - 1]) {
            values[out++] = values[in];
        }
    }
    return out;
}

static void
add_value(int64_t value, int64_t *out, size_t cap, size_t *count)
{
    if (*count < cap) {
        out[(*count)++] = value;
    }
}

static int64_t
u64_to_i64_saturated(uint64_t value)
{
    return value > INT64_MAX ? INT64_MAX : (int64_t) value;
}

/* Generate the §6.1 offset axis, sorted and deduplicated. */
size_t
brix_conform_offsets(uint64_t object_size, int64_t *out, size_t cap)
{
    uint64_t half = object_size / 2U;
    uint64_t aligned = half - (half % BRIX_CONFORM_PAGE_SIZE);
    size_t   count = 0;
    int64_t  size = u64_to_i64_saturated(object_size);

#define ADD_OFFSET(v) add_value((int64_t) (v), out, cap, &count)
    ADD_OFFSET(0); ADD_OFFSET(1); ADD_OFFSET(2); ADD_OFFSET(4095);
    ADD_OFFSET(4096); ADD_OFFSET(4097); ADD_OFFSET(8191); ADD_OFFSET(8192);
    ADD_OFFSET(8193); ADD_OFFSET(u64_to_i64_saturated(half) - 1);
    ADD_OFFSET(u64_to_i64_saturated(half));
    ADD_OFFSET(u64_to_i64_saturated(half) + 1);
    ADD_OFFSET(u64_to_i64_saturated(aligned));
    ADD_OFFSET(u64_to_i64_saturated(aligned) + 1);
    ADD_OFFSET(size - 4097); ADD_OFFSET(size - 4096); ADD_OFFSET(size - 4095);
    ADD_OFFSET(size - 2); ADD_OFFSET(size - 1); ADD_OFFSET(size);
    ADD_OFFSET(size == INT64_MAX ? INT64_MAX : size + 1);
    ADD_OFFSET(size > INT64_MAX - 4096 ? INT64_MAX : size + 4096);
    ADD_OFFSET(INT32_MAX); ADD_OFFSET(UINT64_C(2147483648));
    ADD_OFFSET(UINT32_MAX); ADD_OFFSET(UINT64_C(4294967296));
    ADD_OFFSET(INT64_MAX); ADD_OFFSET(-1); ADD_OFFSET(-4096);
    ADD_OFFSET(INT32_MIN); ADD_OFFSET(INT64_MIN);
#undef ADD_OFFSET
    return sort_unique(out, count);
}

/* Generate the §6.2 length axis for one object/offset pair. */
size_t
brix_conform_lengths(uint64_t object_size, int64_t offset, int64_t *out,
    size_t cap)
{
    int64_t remaining;
    size_t  count = 0;

    if (offset < 0 || (uint64_t) offset > object_size) {
        remaining = 0;
    } else {
        remaining = u64_to_i64_saturated(object_size - (uint64_t) offset);
    }
#define ADD_LENGTH(v) add_value((int64_t) (v), out, cap, &count)
    ADD_LENGTH(0); ADD_LENGTH(1); ADD_LENGTH(2); ADD_LENGTH(4095);
    ADD_LENGTH(4096); ADD_LENGTH(4097); ADD_LENGTH(8192); ADD_LENGTH(16384);
    ADD_LENGTH(remaining - 1); ADD_LENGTH(remaining); ADD_LENGTH(remaining + 1);
    ADD_LENGTH(65536); ADD_LENGTH(1048576); ADD_LENGTH(2097136);
    ADD_LENGTH(2097137); ADD_LENGTH(16777215); ADD_LENGTH(16777216);
    ADD_LENGTH(16777217); ADD_LENGTH(INT32_MAX);
    ADD_LENGTH(UINT64_C(2147483648)); ADD_LENGTH(-1);
#undef ADD_LENGTH
    return sort_unique(out, count);
}

/* Walk clear, every individual documented bit, their legal union, and one
 * deliberately unknown bit.  Per-op clause tables supply the documented mask. */
size_t
brix_conform_option_masks(uint64_t known_mask, uint64_t *out, size_t cap)
{
    uint64_t bit;
    uint64_t unknown = 1;
    size_t   count = 0;

#define ADD_MASK(v) do { if (count < cap) out[count] = (v); count++; } while (0)
    ADD_MASK(0);
    for (bit = 1; bit != 0; bit <<= 1) {
        if ((known_mask & bit) != 0) ADD_MASK(bit);
    }
    if (known_mask != 0 && (known_mask & (known_mask - 1)) != 0) {
        ADD_MASK(known_mask);
    }
    while (unknown != 0 && (known_mask & unknown) != 0) unknown <<= 1;
    if (unknown != 0) ADD_MASK(known_mask | unknown);
#undef ADD_MASK
    return count;
}

/* Emit the named numeric limit's exact lower edge, value, and upper edge. */
size_t
brix_conform_limit_values(uint64_t limit, uint64_t *out, size_t cap)
{
    uint64_t values[3];
    size_t   count = 0;
    size_t   i;

    values[0] = limit == 0 ? 0 : limit - 1;
    values[1] = limit;
    values[2] = limit == UINT64_MAX ? UINT64_MAX : limit + 1;
    for (i = 0; i < 3; i++) {
        if (count != 0 && values[i] == values[i - 1]) continue;
        if (count < cap) out[count] = values[i];
        count++;
    }
    return count;
}

/* Parse one stable CLI budget spelling. */
int
brix_conform_budget_parse(const char *name, brix_conform_budget *out)
{
    if (strcmp(name, "exhaustive") == 0) {
        *out = BRIX_CONFORM_EXHAUSTIVE;
    } else if (strcmp(name, "pairwise") == 0) {
        *out = BRIX_CONFORM_PAIRWISE;
    } else if (strcmp(name, "boundary") == 0) {
        *out = BRIX_CONFORM_BOUNDARY;
    } else {
        return -1;
    }
    return 0;
}

/* Return the stable report spelling for a budget. */
const char *
brix_conform_budget_name(brix_conform_budget budget)
{
    if (budget == BRIX_CONFORM_EXHAUSTIVE) return "exhaustive";
    if (budget == BRIX_CONFORM_PAIRWISE) return "pairwise";
    return "boundary";
}

static int
near_named_boundary(int64_t value, uint64_t object_size)
{
    const int64_t fixed[] = { 0, 4096, INT32_MAX, INT32_MIN,
        2097136, 2097137, 16777215, 16777216, 16777217 };
    int64_t size = u64_to_i64_saturated(object_size);
    size_t  i;

    if (value >= size - 1 && value <= size + (size != INT64_MAX)) return 1;
    for (i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        if (value >= fixed[i] - 1 && value <= fixed[i] + 1) return 1;
    }
    return 0;
}

/* Decide whether a generated product row belongs to the declared budget. */
int
brix_conform_case_selected(brix_conform_budget budget, size_t object_index,
    size_t object_count, size_t offset_index, size_t offset_count,
    size_t length_index, size_t length_count, int64_t offset, int64_t length,
    uint64_t object_size)
{
    const size_t indices[] = { object_index, offset_index, length_index };
    const size_t sizes[] = { object_count, offset_count, length_count };

    if (budget == BRIX_CONFORM_EXHAUSTIVE) return 1;
    if (budget == BRIX_CONFORM_BOUNDARY) {
        return near_named_boundary(offset, object_size)
            || near_named_boundary(length, object_size);
    }
    return brix_conform_product_selected(budget, indices, sizes, 3);
}
