/* Standard objects and expected-answer arithmetic for Phase 118. */
#include "conform/conform.h"

#include <limits.h>

static const brix_conform_object OBJECTS[] = {
    { "Z", 0, 0 },
    { "B1", 1, 0 },
    { "P0", 4095, 0 },
    { "P1", 4096, 0 },
    { "P2", 4097, 0 },
    { "Q", 65536, 0 },
    { "M", 1048576, 0 },
    { "V", 2097136, 0 },
    { "V+", 2097137, 0 },
    { "C", 16777215, 0 },
    { "C+", 16777217, 0 },
    { "L", UINT64_C(5368709121), 1 }
};

/* Return the immutable standard-object catalogue. */
const brix_conform_object *
brix_conform_objects(size_t *count)
{
    if (count != NULL) {
        *count = sizeof(OBJECTS) / sizeof(OBJECTS[0]);
    }
    return OBJECTS;
}

/* Compute the exact successful read length, or mark signed wire input invalid. */
brix_conform_read_answer
brix_conform_read_expected(uint64_t object_size, int64_t offset, int64_t length)
{
    brix_conform_read_answer answer = { 0, 0 };
    uint64_t                 available;

    if (offset < 0 || length < 0) {
        answer.invalid = 1;
        return answer;
    }
    if ((uint64_t) offset >= object_size) {
        return answer;
    }
    available = object_size - (uint64_t) offset;
    answer.expected_len = available < (uint64_t) length
        ? available : (uint64_t) length;
    return answer;
}

/* Derive fractional-page units and CRC count for one pgread/pgwrite range. */
brix_conform_page_answer
brix_conform_page_expected(uint64_t offset, uint64_t length)
{
    brix_conform_page_answer answer = { 0, 0, 0, 0 };
    uint64_t                 first_capacity;
    uint64_t                 remaining;

    if (length == 0) {
        return answer;
    }
    first_capacity = BRIX_CONFORM_PAGE_SIZE
        - (offset % BRIX_CONFORM_PAGE_SIZE);
    answer.first_bytes = (uint32_t) (length < first_capacity
        ? length : first_capacity);
    remaining = length - answer.first_bytes;
    answer.full_pages = (uint32_t) (remaining / BRIX_CONFORM_PAGE_SIZE);
    answer.last_bytes = (uint32_t) (remaining % BRIX_CONFORM_PAGE_SIZE);
    answer.units = 1U + answer.full_pages + (answer.last_bytes != 0U);
    return answer;
}
