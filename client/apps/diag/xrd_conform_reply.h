/*
 * Owned bounded body returned by a raw conformance roundtrip.
 * The probe releases body with free() after interpreting length.
 * Requires no prior includes.
 */
#pragma once
#include <stdint.h>

typedef struct {
    uint8_t *body;
    uint32_t length;
} xrd_conform_wire_reply;
