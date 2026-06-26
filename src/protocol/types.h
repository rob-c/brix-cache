#ifndef XROOTD_PROTOCOL_TYPES_H
#define XROOTD_PROTOCOL_TYPES_H

/*
 * Primitive type aliases matching XProtocol.hh.
 * Request and response structs in wire.h use these names so they stay
 * visually close to the published XRootD protocol specification.
 */

#include <stdint.h>

/* 8-bit unsigned — used for status codes, flags, byte fields */
typedef uint8_t   kXR_char;

/* 16-bit unsigned — streamid, requestid in wire headers */
typedef uint16_t  kXR_unt16;

/* 32-bit unsigned — dlen (data length), error codes, query infotypes */
typedef uint32_t  kXR_unt32;

/* 64-bit unsigned — timestamps, sizes, offsets (not used heavily in current protocol) */
typedef uint64_t  kXR_unt64;

/* 16-bit signed — not used in XRootD wire (reserved by spec) */
typedef int16_t   kXR_int16;

/* 32-bit signed — errno mapping, negative status values (not used) */
typedef int32_t   kXR_int32;

/* 64-bit signed — not used in current protocol wire format */
typedef int64_t   kXR_int64;

#endif /* XROOTD_PROTOCOL_TYPES_H */
