/*
 * Ordered human-readable metadata fields and their escaping callback.
 * Requires no prior includes; text remains borrowed for the duration of emit.
 */
#pragma once
#include <stddef.h>
#include <stdio.h>

typedef struct {
    const char *prefix;
    const char *value;
} brix_conform_report_field;

void brix_conform_report_fields(FILE *out,
    const brix_conform_report_field *fields, size_t count,
    void (*emit_text)(FILE *, const char *));
