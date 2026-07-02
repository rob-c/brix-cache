#ifndef XROOTD_PROTOCOL_PROTOCOL_H
#define XROOTD_PROTOCOL_PROTOCOL_H

/*
 * protocol/protocol.h — XRootD root:// wire-format constants and structs.
 *
 * Sources:
 *   xrootd/xrootd  src/XProtocol/XProtocol.hh  (canonical C++ header)
 *   dcache/xrootd4j                              (Java reference impl)
 *   go-hep/hep     xrdproto/                    (Go reference impl)
 *   XRootD Protocol Specification v5.2.0
 *
 * Sub-headers (include individually when only part of the protocol is needed):
 *   types.h    — kXR_char / kXR_int32 / kXR_unt64 primitive aliases
 *   opcodes.h  — request IDs, status codes, error codes, query infotypes,
 *                fattr subcodes, version constants, wire sizes
 *   flags.h    — bitmask / option constants for every request type
 *   wire.h     — packed on-wire structs (client requests + server responses)
 *   gsi.h      — GSI / XrdSutBuffer step numbers and bucket type codes
 */

#include "types.h"
#include "opcodes.h"
#include "flags.h"
#include "wire.h"
#include "protocol/codec/wire_codec.h"   /* shared per-opcode wire-body pack/unpack codec */
#include "gsi.h"

#endif /* XROOTD_PROTOCOL_PROTOCOL_H */
