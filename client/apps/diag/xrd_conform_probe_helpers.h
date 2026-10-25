/*
 * Common conformance probe bookkeeping; requires no prior includes.
 * Keeps scope filtering, budget refusal and verdict evidence identical across
 * independently selectable HTTP and ROOT probe families.
 */
#pragma once
#include "xrd_conform_internal.h"

int xrd_conform_row_active(xrd_conform_execution *execution, const char *id);
int xrd_conform_any_row_active(xrd_conform_execution *execution,
    const char *const *ids, size_t count);
int xrd_conform_reserve_status(xrd_conform_execution *execution, size_t bytes,
    brix_status *status);
int xrd_conform_reserve_probe(xrd_conform_execution *execution, size_t bytes);
int xrd_conform_reserve_request(xrd_conform_execution *execution);
int xrd_conform_reserve_zero_status(xrd_conform_execution *execution,
    brix_status *status);
void xrd_conform_grade_received(xrd_conform_execution *execution,
    const char *id, int pass, const char *success, const char *failure,
    const char *received);
void xrd_conform_grade_comparison(xrd_conform_execution *execution,
    const char *id, int pass, const char *success, const char *failure,
    const char *expected, const char *received);
void xrd_conform_grade(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure);
void xrd_conform_grade_active(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure);
void xrd_conform_grade_status(xrd_conform_execution *execution, const char *id,
    int pass, const char *success, const char *failure,
    const brix_status *status);
void xrd_conform_grade_wire_status(xrd_conform_execution *execution,
    const char *id, int pass, const char *success, const char *failure,
    const brix_status *status);
int xrd_conform_bytes_match(ssize_t got, size_t length, const uint8_t *actual,
    const uint8_t *expected);
int xrd_conform_next_locate_token(const char **cursor, const char **start,
    size_t *length);
int xrd_conform_read_bounded_frame(brix_conn *connection, uint16_t *sid,
    uint16_t *wire_status, uint32_t *length, void *body, size_t capacity,
    brix_status *status);
int xrd_conform_scratch_object_path(xrd_conform_execution *execution,
    const char *leaf, xrd_conform_scratch_object *object);
