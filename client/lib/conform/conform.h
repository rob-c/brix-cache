/* BriX protocol-conformance oracle and deterministic boundary generators. */
#ifndef BRIX_CONFORM_H
#define BRIX_CONFORM_H

#include <stddef.h>
#include <stdint.h>

#define BRIX_CONFORM_PAGE_SIZE 4096U
#define BRIX_CONFORM_KEY_SIZE 16U
#define BRIX_CONFORM_AXIS_MAX 40U
#define BRIX_CONFORM_SHAPE_MAX 4096U

typedef struct {
    uint8_t bytes[BRIX_CONFORM_KEY_SIZE];
} brix_conform_key;

typedef struct {
    const char *name;
    uint64_t size;
    int large;
} brix_conform_object;

typedef struct {
    uint64_t expected_len;
    int invalid;
} brix_conform_read_answer;

typedef struct {
    uint32_t first_bytes;
    uint32_t full_pages;
    uint32_t last_bytes;
    uint32_t units;
} brix_conform_page_answer;

typedef enum {
    BRIX_CONFORM_EXHAUSTIVE = 0,
    BRIX_CONFORM_PAIRWISE,
    BRIX_CONFORM_BOUNDARY
} brix_conform_budget;

typedef struct {
    uint32_t first_page_off;
    uint32_t last_page_bytes;
    uint32_t full_pages;
    uint64_t offset;
    uint64_t length;
} brix_conform_page_case;

typedef enum {
    BRIX_CONFORM_VECTOR_ASCENDING = 0,
    BRIX_CONFORM_VECTOR_DESCENDING,
    BRIX_CONFORM_VECTOR_INTERLEAVED,
    BRIX_CONFORM_VECTOR_DUPLICATED,
    BRIX_CONFORM_VECTOR_OVERLAPPING,
    BRIX_CONFORM_VECTOR_ADJACENT,
    BRIX_CONFORM_VECTOR_GAPPED,
    BRIX_CONFORM_VECTOR_EOF_STRADDLING,
    BRIX_CONFORM_VECTOR_PAST_EOF
} brix_conform_vector_geometry;

typedef struct {
    uint32_t element_count;
    uint32_t element_size;
    uint32_t total_bytes;
    brix_conform_vector_geometry geometry;
    uint32_t handle_count;
} brix_conform_vector_case;

typedef enum {
    BRIX_CONFORM_HTTP_RANGE_VALID = 0,
    BRIX_CONFORM_HTTP_RANGE_UNSATISFIABLE,
    BRIX_CONFORM_HTTP_RANGE_INVALID,
    BRIX_CONFORM_HTTP_RANGE_OVER_LIMIT
} brix_conform_http_range_kind;

typedef struct {
    const char *expression;
    brix_conform_http_range_kind kind;
} brix_conform_http_range_case;

const brix_conform_object *brix_conform_objects(size_t *count);
uint64_t brix_conform_prf64(const brix_conform_key *key, uint64_t counter);
uint8_t brix_conform_byte(const brix_conform_key *key, uint64_t offset);
void brix_conform_fill(const brix_conform_key *key, uint64_t offset,
    uint8_t *out, size_t len);
int brix_conform_verify(const brix_conform_key *key, uint64_t offset,
    const uint8_t *actual, size_t len, uint64_t *bad_offset);
int brix_conform_key_parse(const char *hex, brix_conform_key *key);
void brix_conform_key_format(const brix_conform_key *key,
    char hex[BRIX_CONFORM_KEY_SIZE * 2U + 1U]);
brix_conform_read_answer brix_conform_read_expected(uint64_t object_size,
    int64_t offset, int64_t length);
size_t brix_conform_offsets(uint64_t object_size, int64_t *out, size_t cap);
size_t brix_conform_lengths(uint64_t object_size, int64_t offset,
    int64_t *out, size_t cap);
size_t brix_conform_option_masks(uint64_t known_mask, uint64_t *out,
    size_t cap);
size_t brix_conform_limit_values(uint64_t limit, uint64_t *out, size_t cap);
brix_conform_page_answer brix_conform_page_expected(uint64_t offset,
    uint64_t length);
int brix_conform_budget_parse(const char *name, brix_conform_budget *out);
const char *brix_conform_budget_name(brix_conform_budget budget);
int brix_conform_case_selected(brix_conform_budget budget, size_t object_index,
    size_t object_count, size_t offset_index, size_t offset_count,
    size_t length_index, size_t length_count, int64_t offset, int64_t length,
    uint64_t object_size);
int brix_conform_product_selected(brix_conform_budget budget,
    const size_t *indices, const size_t *axis_sizes, size_t axis_count);
size_t brix_conform_page_cases(brix_conform_budget budget,
    brix_conform_page_case *out, size_t cap);
size_t brix_conform_vector_cases(brix_conform_budget budget,
    brix_conform_vector_case *out, size_t cap);
const brix_conform_http_range_case *brix_conform_http_range_cases(
    brix_conform_budget budget, size_t *count);
const char *brix_conform_vector_geometry_name(
    brix_conform_vector_geometry geometry);

#endif
