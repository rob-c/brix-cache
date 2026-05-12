#pragma once

/*
 * Primitive type aliases matching XProtocol.hh.
 * Request and response structs in wire.h use these names so they stay
 * visually close to the published XRootD protocol specification.
 */

#include <stdint.h>

typedef uint8_t   kXR_char;
typedef uint16_t  kXR_unt16;
typedef uint32_t  kXR_unt32;
typedef uint64_t  kXR_unt64;
typedef int16_t   kXR_int16;
typedef int32_t   kXR_int32;
typedef int64_t   kXR_int64;
