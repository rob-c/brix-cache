# SSI Phase 4 — Minimal CTA protobuf codec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A small, dependency-free C codec for exactly the CTA SSI messages we exchange — decode `cta.xrd.Request` (with the embedded `cta.eos.Notification` / `cta.admin.AdminCmd`), encode `cta.xrd.Response` and streamed `cta.xrd.Data` — verified byte-for-byte against captured golden vectors.

**Architecture:** Two layers. (1) `pb_wire.{c,h}` — generic protobuf wire primitives (varint, length-delimited, fixed32/64, tag = (field<<3)|wiretype) with bounds-checked readers and appenders. (2) `cta_pb.{c,h}` — message-specific decode/encode that names CTA field numbers in one pinned table (the entire external-contract surface). No `protobuf-c`, no codegen.

**Tech Stack:** Pure C (no nginx, no external libs), standalone-gcc unit tests with golden hex vectors. Reference: CTA `cta_frontend.proto` / `eos_cta.proto` / `cta_common.proto` (field numbers pinned in `cta_pb.c`).

## Global Constraints

- NO `goto`; functional + modular; pure functions; explicit lengths, no globals.
- **Bounds-checked always** — every reader takes `(buf, end)` and returns failure on overrun; never read past `end`. Untrusted input.
- No dynamic schema; only the fields listed in the pinned table are parsed/emitted.
- 3 tests per change: round-trip golden + truncated/malformed input rejected + unknown-field skipped.
- Pure C — compiles with `gcc -Wall -Wextra -Werror -std=c11`; no nginx headers (reused later by the nginx-side service in Phase 5).
- Register `.c` in `./config` (used by the module link in Phase 5); the codec itself is unit-tested standalone.

---

### Task 1: Protobuf wire primitives

**Files:**
- Create: `src/protocols/ssi/svc_cta/pb_wire.{c,h}`
- Create: `src/protocols/ssi/svc_cta/pb_wire_unittest.c`

**Interfaces:**
- `typedef struct { const unsigned char *p, *end; } pb_reader;`
- `int pb_read_varint(pb_reader *r, uint64_t *out);` → 0 ok, -1 overrun.
- `int pb_read_tag(pb_reader *r, uint32_t *field, int *wiretype);`
- `int pb_read_len_delim(pb_reader *r, const unsigned char **data, size_t *len);`
- `int pb_skip_field(pb_reader *r, int wiretype);` (unknown-field skip)
- `typedef struct { unsigned char *p; size_t len, cap; } pb_writer;`
- `int pb_write_varint(pb_writer *w, uint64_t v);`
- `int pb_write_tag(pb_writer *w, uint32_t field, int wiretype);`
- `int pb_write_len_delim(pb_writer *w, uint32_t field, const unsigned char *data, size_t len);`
- `int pb_write_string(pb_writer *w, uint32_t field, const char *s);`

- [ ] **Step 1: Failing test** — `pb_wire_unittest.c`:
  - varint round-trip for 0, 1, 127, 128, 300, 0xFFFFFFFF, 2^63.
  - `pb_read_varint` on a truncated buffer (high-bit-set last byte) returns -1.
  - tag encode/decode: field=11 wiretype=2 → byte 0x5A; round-trips.
  - `pb_skip_field` advances correctly for each wiretype; rejects overrun.
  Golden hex asserted with a `bytes_eq` helper (copy from `ssi_rrinfo_unittest.c`).
- [ ] **Step 2: Run → FAIL.** `gcc -Wall -Wextra -Werror -I src -o /tmp/pb_wire_ut src/protocols/ssi/svc_cta/pb_wire_unittest.c src/protocols/ssi/svc_cta/pb_wire.c && /tmp/pb_wire_ut`
- [ ] **Step 3: Implement `pb_wire.{c,h}`** — standard LEB128 varint (≤10 bytes, reject longer), tag = field<<3|wiretype, length-delimited reads validate `len <= end-p`. Writers append into a caller-sized `cap` buffer, return -1 on overflow.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 2: Decode `cta.xrd.Request`

**Files:**
- Create: `src/protocols/ssi/svc_cta/cta_pb.{c,h}`
- Create: `src/protocols/ssi/svc_cta/cta_pb_unittest.c`
- Modify: `config`

**Interfaces (`cta_pb.h`):**
- `typedef enum { CTA_OP_ARCHIVE, CTA_OP_RETRIEVE, CTA_OP_CANCEL, CTA_OP_QUERY, CTA_OP_UNKNOWN } cta_op_t;`
- `typedef struct { cta_op_t op; char instance[64]; char path[1024]; char request_id[64]; uint64_t archive_id; char owner_user[64]; char owner_group[64]; } cta_request_t;`
- `int cta_pb_decode_request(const unsigned char *buf, size_t len, cta_request_t *out);` → 0 ok, -1 malformed.
- **Pinned field table** in `cta_pb.c`, each entry commented `/* CTA proto: <file> <message> field <n> */`. Fill the actual numbers from CTA's `.proto` (e.g. `cta.xrd.Request.notification` / `.admincmd`; `cta.eos.Notification.wf` workflow event → archive/retrieve/cancel; `.file.lpath`, `.cli.user.username/groupname`, `.wf.instance.name`). The mapping table IS the external contract and the maintenance point.

- [ ] **Step 1: Failing test** — `cta_pb_unittest.c`: a golden `cta.xrd.Request` byte vector (captured/hand-built per the pinned numbers) for an archive (`CLOSEW`) request decodes to `op==CTA_OP_ARCHIVE`, expected `path`, `owner_user`. A retrieve (`PREPARE`) vector → `CTA_OP_RETRIEVE`. A truncated vector → -1. A vector with an unknown field number → still decodes (field skipped).
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement `cta_pb_decode_request`** — top-level loop over `pb_read_tag`; for the `notification`/`admincmd` length-delimited sub-message, recurse with a sub-`pb_reader`; map the workflow-event enum to `cta_op_t`; copy string fields with bounded `memcpy` (truncate to field capacity, NUL-terminate). Unknown fields → `pb_skip_field`. Register `cta_pb.c` in `./config`.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 3: Encode `cta.xrd.Response` and `cta.xrd.Data`

**Interfaces (`cta_pb.h`):**
- `typedef enum { CTA_RSP_SUCCESS, CTA_RSP_ERR_USER, CTA_RSP_ERR_PROTOBUF, CTA_RSP_ERR_CTA } cta_rsp_type_t;`
- `int cta_pb_encode_response(cta_rsp_type_t type, const char *message_txt, unsigned char *out, size_t cap, size_t *out_len);`
- `int cta_pb_encode_data_record(const char *const *cols, int ncols, unsigned char *out, size_t cap, size_t *out_len);` (one streamed `cta.xrd.Data` row for `query` listings)

- [ ] **Step 1: Failing test** — encode a `CTA_RSP_SUCCESS` response with `message_txt="ok"` → golden bytes; decode-back with `pb_wire` readers to confirm field numbers + values. Encode an error response → correct `type` field. Encode a data record of N columns → golden.
- [ ] **Step 2: Run → FAIL.**
- [ ] **Step 3: Implement** the encoders via `pb_write_*`, field numbers from the same pinned table.
- [ ] **Step 4: Run → PASS.** Commit.

---

### Task 4: Docs + golden-vector provenance

- [ ] Create `src/protocols/ssi/svc_cta/README.md`: documents the pinned field table as the external contract, how golden vectors were produced (capture from a real CTA frontend, or `protoc --encode` from the `.proto` — record the exact command), and the re-capture procedure when CTA's schema bumps. Commit.

---

## Self-Review

- Wire primitives (Task 1) → request decode (Task 2) → response/data encode (Task 3). ✓
- Untrusted-input safety: every reader bounds-checked; truncated/malformed rejected; unknown fields skipped (tests in Tasks 1–2). ✓
- External-contract isolation: all CTA field numbers in one pinned table in `cta_pb.c` (Task 2/3), documented (Task 4). ✓
- No nginx dependency → reusable by the Phase-5 service and unit-tested standalone. ✓
- No TBDs in mechanics; the only external unknowns are CTA's concrete field numbers, explicitly called out as the pinned-table fill + golden-vector provenance (Task 4).

## Execution Handoff

Phase 4 of 6. Independent of Phase 3; depends only on the C toolchain. Phase 5 (CTA service) consumes `cta_pb` + the Phase-2 async push + Phase-3 streaming.
