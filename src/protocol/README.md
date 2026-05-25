# protocol — XRootD root:// wire-format constants and structs

Reference headers for the XRootD binary protocol.  No C code lives here —
all files are pure `#define` constants and `typedef` / packed struct
declarations.

## File map

| File | Contents |
|------|----------|
| `protocol.h` | Umbrella — includes all five sub-headers below |
| `types.h` | Primitive type aliases (`kXR_char`, `kXR_int32`, `kXR_unt64`, …) matching `XProtocol.hh` |
| `opcodes.h` | Request IDs (`kXR_auth` … `kXR_writev`), response status codes, error codes, query `infotype` codes, fattr subcodes, version constants, fixed wire sizes |
| `flags.h` | Bitmask / option constants for every request type: open flags, stat flags, protocol capability bits, login capver, dirlist / stat / prepare / pgread / pgwrite / readv / writev / sigver / fattr options |
| `wire.h` | All `#pragma pack(1)` structs: client request headers, server response bodies, composite types (`ServerStatusResponse_pgWrite`, etc.) |
| `gsi.h` | GSI / XrdSutBuffer step numbers (`kXGS_*`, `kXGC_*`) and bucket type codes (`kXRS_*`) |
| `wire_core_requests.h` | Core request structs: client request headers and standard response bodies |
| `wire_write_extended_requests.h` | Extended write request structs: pgwrite, writev, sync variants |

## Navigating the protocol

- Adding a **new opcode**: add the numeric ID to `opcodes.h`, any bitmask flags
  to `flags.h`, and the request/response struct to `wire.h`.
- Changing **authentication**: GSI step/bucket constants are in `gsi.h`; the
  GSI auth logic itself lives in `src/gsi/`.
- Understanding **capability negotiation**: see `flags.h` — protocol request
  flags (`kXR_ableTLS`, `kXR_secreqs`) and response flags (`kXR_haveTLS`,
  `kXR_gotoTLS`) are there.
- Understanding **stat / dirlist wire format**: the dStat format note and field
  ordering warning live in `wire.h` next to `ClientDirlistRequest`.

## Sources

- `xrootd/xrootd` — `src/XProtocol/XProtocol.hh` (canonical C++ header)
- `dcache/xrootd4j` (Java reference implementation)
- `go-hep/hep` — `xrdproto/` (Go reference implementation)
- XRootD Protocol Specification v5.2.0
