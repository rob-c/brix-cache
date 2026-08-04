# Bound-write data-path (write substreams) — implementation scoping

**Status:** scoping only (no code). **Date:** 2026-08-04. **Requested:** build a
cross-connection *write* data-path so `kXR_write` payloads can arrive on bound
secondary connections (parallel upload), at both server and client level.

Today BriX serves **reads** on bound secondaries but refuses a non-zero-pathid
**write** cleanly (`recv_process.c:255` → `kXR_Unsupported`, no desync; the client
falls back to inline pathid-0 serviced by the streaming-write engine). This doc
scopes what it takes to lift that limitation. See
[data-substreams-conformance](data-substreams-conformance.md) for the current
feature matrix.

---

## 1. Wire reality that shapes the design

| request | pathid field? | consequence |
|---|---|---|
| `kXR_read` (`ClientReadRequest`) | **no** | server routes a read purely by *which connection it arrived on* |
| `kXR_write` (`fhandle[4] offset[8] pathid[1]`) | **yes** (`cur_body[12]`) | server *can* tell a substream write from an inline one, and **the write already carries its own absolute offset** — it is self-addressing |

The write header carrying an explicit `offset` is the single most important fact:
a bound write is **not** an append at "wherever the stream is" — it names its own
byte range. That makes disjoint parallel writes well-defined at the protocol level.
The hard part is entirely on the *server storage* side.

---

## 2. Why reads were easy and writes are not

Bound **reads** sidestep nginx's post-fork fd isolation (workers don't share
descriptors — `handles.c:6`) with a **reopen-independently** trick:

1. the primary publishes handle *metadata* (path, dev/inode, size, r/w flags) to an
   SHM table keyed by `(sessid, handle_index)` — `handles.c:197`
   `brix_session_handle_publish`;
2. a bound secondary — possibly on **another worker** (gateway runs
   `worker_processes 2`) — **reopens the path read-only**, validates dev/inode, and
   reads any offset independently (`open_resolved_file.c:130`).

Reads are *stateless and idempotent*: reopening O_RDONLY and pread-ing a range on a
second fd is always safe. **Write-only handles are deliberately NOT published**
(`handles.c:167` — "an attractive misuse path"), precisely because the reopen trick
does not generalise to writes for one of the two backends:

| write backend | detected by | apply path | reopen-independently safe? |
|---|---|---|---|
| **plain fd / driver** | `file->fd >= 0` \|\| `sd_obj.driver` | `brix_write_stream_apply_direct` → **pwrite @offset** (VFS job) | **yes** — disjoint-range pwrites from independent fds to one file are POSIX-safe |
| **staged whole-object** (gateway → remote origin) | `file->writer != NULL` | `brix_staged_append_raw` → **append-only, sequential, per-connection** staging file, hydrated at close | **no** — append has no concept of a foreign offset; the staging + hydrate + commit pipeline is single-owner |

This split is the whole ballgame. It yields two phases of very different cost.

---

## 3. What already exists to build on

- **The refusal hook** (`recv_process.c:255`) is documented as "the exact hook a
  future data-path implementation uses." A substream write is caught here *before*
  any payload is drained — the replacement path takes over at exactly this point.
- **The streaming-write engine** (`write_stream.c`) already applies a large write in
  bounded chunks at a base offset, to *either* backend
  (`apply_direct` / staged), with a single final ack. A substream write is the same
  apply operation at an arbitrary offset — the per-chunk apply primitives are reusable.
- **The SHM handle table** (`handles.c`) already carries per-(sessid, handle) metadata
  cross-worker. It needs a writable-handle variant, not a new mechanism.
- **The bind machinery** (`bind.c`, pathid assignment, session lookup, capability
  restriction in `policy.c:117`) already stands up secondaries; only the "may only
  read" policy needs widening for the write case.
- **Client**: `brix_streams_open` (`streams.c`) already opens + binds N-1 secondaries
  on the upload path (`copy_upload.c:194`); the write pump `pump_sink_remote`
  (`copy_pump.c:113`) currently issues every `brix_file_write` on the primary only.

---

## 4. Design options

### Option A — cross-worker independent reopen + pwrite (plain-fd export only)
Mirror the read design for the fd backend:

- **Publish writable handles**: extend `brix_session_handle_publish` to also publish
  fd/driver *writable* handles (new `writable` flag + `expected_size` if known),
  guarded so it is only reachable for fd-backed exports, never staged writers.
- **Bound write apply**: on a secondary, a `kXR_write{fhandle, offset, pathid}` looks
  up the published entry, **reopens the path O_WRONLY** (dev/inode-validated, same as
  the read path), and pwrites the payload at `offset` via the existing VFS write job.
  Reuse `write_stream.c` chunking for large substream writes.
- **Close barrier (the new hard part)**: today `close` is primary-only and acks
  immediately. With N independent writers the primary's close must **block until every
  byte range written on a secondary is durable**. Needs a per-handle SHM counter of
  bytes-acked (or a high-water/range set) that close waits on, plus a timeout →
  error. Without this, close can commit/hydrate a partially-written file.
- **Checksum**: any on-ingest streaming checksum is invalidated by out-of-order
  disjoint writes → compute at close by re-reading, or refuse substream writes when a
  streaming digest was negotiated.

**Feasible, bounded. Delivers real parallel upload to local-export BriX.** Does
**not** help the gateway/staged path (which is the common production shape).

### Option B — same-worker rendezvous (works for BOTH backends, incl. staged)
This is the approach task #23 ("kXR_bind write data-path (same-worker rendezvous)
feeding stream engine") was pointed at.

- Secondary write frames (offset + payload) are **forwarded to the primary
  connection's worker** via a rendezvous (SHM ring, or fd handoff), where the
  primary's single write context applies them — feeding `write_stream.c` /
  `brix_staged_append_raw` in **offset order**.
- Because a single owner applies all bytes, it works for the staged backend too:
  either buffer-and-reorder into the sequential append, or switch staging to a
  **random-access staging file** (pwrite@offset) that hydrates at close.
- **Cost**: forwarding *bulk* data cross-worker is exactly what the read side avoided.
  Copying MiB/s of payload through SHM (or passing fds + coordinating) is a
  significant new datapath with its own backpressure, lifetime, and failure model.
  A random-access staging rewrite touches the hydrate/commit/upload-resume pipeline.

**Most general, most expensive.** This is the only path that gives the *gateway*
parallel writes.

### Option C — phased (recommended)
1. **Phase 1 = Option A**, gated strictly to fd-backed exports; staged/gateway writes
   keep returning `kXR_Unsupported` → inline fallback (today's safe behaviour). Ship
   real parallel upload for local-export BriX with a bounded, well-understood change.
2. **Phase 2 = Option B** for the staged/gateway backend, if/when parallel upload to a
   remote origin is worth the rendezvous + random-access-staging cost.

---

## 5. Server work breakdown (Phase 1 / Option A)

| # | change | files (anchors) | risk |
|---|---|---|---|
| S1 | Publish writable fd/driver handles (new `writable`+`expected_size` fields; keep staged writers unpublished) | `handles.c:167,197`; handle struct | med — must not expose staged handles |
| S2 | Widen bound-conn policy: permit `kXR_write` on a bound conn against a writable published handle (still no open/close/stat) | `policy.c:117`; `bind.c` capability note | med |
| S3 | Replace the refusal at `recv_process.c:255` with a bound-write apply path: reopen-O_WRONLY-validate + pwrite@offset, reusing `write_stream.c` chunking for large frames | `recv_process.c:255`; `write_stream.c` apply primitives; `open_resolved_file.c` reopen/validate | **high** — core datapath |
| S4 | Per-handle durable-bytes accounting in SHM + close barrier (primary close waits for all secondary ranges, with timeout→error) | `handles.c` (new counter/rangeset); close path | **high** — correctness gate |
| S5 | Checksum at close by re-read (or refuse substream write when a streaming digest was negotiated) | cksum path; open negotiation | med |
| S6 | Metrics/access-log for substream writes; keep `brix_data_substreams off` refusing as today | `bind.c:48`, metrics | low |

## 6. Client work breakdown

| # | change | files (anchors) | risk |
|---|---|---|---|
| C1 | Multi-stream upload pump: split the byte range into per-stream strides, issue `brix_file_write` on each bound secondary tagged with its **pathid**, track per-stream offsets | `copy_upload.c:194`; `copy_pump.c:113` `pump_sink_remote`; `transfer_pump` | **high** |
| C2 | Set the pathid byte on `kXR_write` from the secondary's assigned pathid (primary stays pathid 0) | write framing in `client/lib/net` | med |
| C3 | Per-stream resilient reopen (the current resilient reopen assumes one connection) | `copy_pump.c` `pump_sink_reopen` | med |
| C4 | Gate: substream **upload** only when the server advertised support AND backend is fd-export; else fall back to inline (never fail the copy) | open reply capability bit (**new** — server must advertise) | med |
| C5 | Default stream count for uploads (and keep write-compression disabling streams — `copy_upload.c:190`) | `xrdcp.c` default; parse | low |

Note C4 implies a **capability handshake**: the client must not blind-fire substream
writes at a server that will refuse them mid-transfer. Either a new open-reply flag or
a protocol/login capability bit is needed so the client knows before it starts.

## 7. Correctness hazards to design against

- **Partial-file commit**: close must not hydrate/commit before every secondary range
  is durable (S4). This is the highest-consequence bug class.
- **Sparse holes**: a lost secondary leaves a gap; the close barrier must detect
  missing ranges, not just a byte count.
- **POSC / upload-resume**: `posc` (persist-on-successful-close) and
  `brix_upload_resume` (`copy_upload.c` notes) both assume a single sequential writer;
  their interaction with disjoint parallel writes must be defined (likely: disable
  resume for substream uploads).
- **Ordering vs offset**: safe for pwrite (self-addressing); unsafe for any
  append/streaming-digest assumption — hence S5.
- **Security**: a writable published handle is the "attractive misuse path"
  `handles.c` warns about — dev/inode validation + sessid scoping must be as strict as
  the read path, and the writable flag must never leak a staged handle.

## 8. Test plan (mirrors the read-substream suite)

- Server, plain-fd export: parallel disjoint-range bound writes reassemble byte-exact
  on disk (extend `tests/test_data_substreams_parallel.py` with a write variant).
- Close barrier: kill a secondary mid-write → close errors, file not committed.
- Staged/gateway handle: substream write still refused cleanly (no desync) until
  Phase 2.
- `brix_data_substreams off`: bind refused (existing `tests/test_bind_substreams.py`).
- Cross-worker: force secondaries onto a different worker (`worker_processes 2`) and
  confirm correctness.
- Client: `brix-xrdcp --streams N` upload to a fd-export BriX round-trips byte-exact;
  to a gateway falls back to inline without failing.
- Cross-client: go-hep (`WithSubStreams`) upload now genuinely fans out to a fd-export
  BriX; still falls back on the gateway.

## 9. Recommendation & rough effort

- **Do Phase 1 (Option A)** first: real parallel upload for fd-backed BriX exports,
  bounded blast radius, reuses the read-substream mechanics and the streaming-write
  engine. Server S1–S6 + client C1–C5. The two genuinely hard pieces are the
  **bound-write apply datapath (S3)** and the **close barrier (S4)**; everything else
  is plumbing.
- **Defer Phase 2 (Option B)** — the staged/gateway rendezvous + random-access staging
  — until parallel upload *to a remote origin* is a proven need, because it adds a
  bulk cross-worker datapath and a staging rewrite that Phase 1 avoids entirely.

Net: Phase 1 is a well-defined, testable slice with two high-risk hunks; Phase 2 is a
substantially larger datapath project. Recommend implementing Phase 1 behind the
existing `brix_data_substreams` gate with a server capability advertisement so mixed
client/server versions degrade safely.
