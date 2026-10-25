/*
 * Immutable errno-fixture vocabulary shared by CLI validation and probes.
 * Requires no prior includes; wire error constants come from internal.h.
 */
#pragma once
#include "xrd_conform_internal.h"

typedef struct {
    const char *name;
    const char *clause;
    uint16_t    expected;
} error_fixture_spec;

const error_fixture_spec *xrd_conform_error_specs(size_t *count);
const error_fixture_spec *xrd_conform_error_spec_find(const char *name,
    size_t length);
