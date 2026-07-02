# CMS Manager-Breadth — Design Spec

**Date:** 2026-06-26
**Status:** approved design → implementation (see §9 status)
**Scope:** `src/net/cms/` (both halves), config plumbing, tests, docs
**Hard requirement:** **byte-exact wire interop** with stock XRootD `cmsd` — no wire changes; new opcodes match `XProtocol/YProtocol.hh` + `XrdCms/XrdCmsRRData.hh` layouts exactly.

Related: SSI completeness is a **separate** spec/cycle. Non-goals here: meta-manager
multi-tier trees (`subman`/`metaman`/supervisor), the local `XrdCmsAdmin` control
socket, `XrdCmsBlackList`, the C++ plugin ABI, and UDP monitoring.

---

## 1. Motivation

The CMS manager today handles `login/locate/select/state/have/try/load/space/
status/gone/xauth/avail/pong`. A real `cmsd` routes ~25 opcodes. Two breadth
planes remain:

- **Plane A — manager receive / liveness / query:** incoming `kYR_ping`→`pong`,
  `kYR_disc` (graceful), `kYR_update`, `kYR_usage`/`kYR_stats`/`kYR_statfs`, and
  `kYR_have`/`kYR_state` reconciliation.
- **Plane B — forwarded namespace/write plane:** the `Forward`-flagged redirector
  ops `kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc/prepadd/prepdel`. The manager
  fans them out to selected nodes and aggregates `Repliable`/`Delayable` replies;
  the data-node half receives and executes them against local storage.

## 2. Opcode map (byte-exact, from `YProtocol.hh`)

```
kYR_login=0  kYR_chmod=1  kYR_locate=2  kYR_mkdir=3  kYR_mkpath=4  kYR_mv=5
kYR_prepadd=6 kYR_prepdel=7 kYR_rm=8 kYR_rmdir=9 kYR_select=10 kYR_stats=11
kYR_avail=12 kYR_disc=13 kYR_gone=14 kYR_have=15 kYR_load=16 kYR_ping=17
kYR_pong=18 kYR_space=19 kYR_state=20 kYR_statfs=21 kYR_status=22 kYR_trunc=23
kYR_try=24 kYR_update=25 kYR_usage=26 kYR_xauth=27
```

Routing flags (mirror `XrdCmsRouting.cc`): `isSync`, `Forward`, `Repliable`,
`Delayable`, `noArgs`, async-queue class (`AsyncQ0`/`AsyncQ1`).

## 3. Architecture

A table-driven router in `src/net/cms/` mirrors `XrdCmsRouting.cc`. Both halves
dispatch through it:

- **Manager-from-node** (`server_recv.c`) — manager accepting frames *up* from data nodes.
- **Node-from-manager** (`recv.c`) — node accepting forwarded frames *down* from parent.

Each opcode is a descriptor row `{code, name, flags, handler}`, auditable
line-for-line vs `initRouter` / `initRDRrouting` / `initMANrouting`. Pup payloads
decode once into a typed struct; handlers consume typed fields. Plane B fan-out /
aggregation lives in its own module.

## 4. Components

| File | Responsibility |
|---|---|
| `src/net/cms/router.{c,h}` | Descriptor table `xrootd_cms_route_t {uint8 code; const char *name; uint16 flags; handler}` + `xrootd_cms_route_lookup(code, role)`. Role-scoped tables (manager, node). |
| `src/net/cms/rrdata.{c,h}` | `xrootd_cms_rrdata_t` mirroring `XrdCmsRRData` (Path, Opaque, Path2, Opaque2, Avoid, Reqid, Notify, Prty, Mode, Ident, Opts, PathLen, dskFree, dskUtil); `xrootd_cms_rrdata_parse(code, payload, len, *out)` — bounds-checked Pup decode reusing `tlv_read_next` / `cms_srv_read_string`. |
| `src/net/cms/server_ops.c` | **Plane A** manager handlers: `ping→pong`, `disc` (echo+close), `update` (trigger state re-probe), `usage`/`stats`/`statfs` (answer from registry), `have`/`state` reconciliation. |
| `src/net/cms/forward.c` | **Plane B** manager-side: select eligible nodes (`manager/registry`) → fan-out → pending-reply aggregation keyed by streamid, `waitresp`/`Delayable` aware. |
| `src/net/cms/node_ops.c` | **Plane B** node-side: execute forwarded `chmod/mkdir/mkpath/mv/rm/rmdir/trunc` via the **VFS backend** (confined); `prepadd`/`prepdel` → FRM queue; build success/`kYR_error` reply. |

New `CMS_RR_*` constants added to `cms_internal.h`: CHMOD=1, MKDIR=3, MKPATH=4,
MV=5, PREPADD=6, PREPDEL=7, RM=8, RMDIR=9, STATS=11, DISC=13, STATFS=21,
TRUNC=23, UPDATE=25, USAGE=26.

## 5. Data flow

- **Plane A (sync):** node frame → router → handler → immediate reply
  (`pong` / disc-echo / usage payload). `update` schedules a `kYR_state` probe.
- **Plane B manager:** client write/namespace op (redirector path) → router sees
  `Forward` → `forward.c` selects nodes → emits downstream `kYR_<op>` frames →
  registers pending aggregation entry → on each node reply, aggregates → when
  complete (or `Delayable` timeout → `kYR_wait`) replies to the originating client.
- **Plane B node:** manager frame → router → `node_ops.c` resolves path + executes
  via VFS backend → success/error reply upstream.

## 6. Error handling & invariants

- **Path confinement (CRITICAL):** every forwarded namespace mutation resolves
  through `openat2 RESOLVE_BENEATH` helpers (`xrootd_*_beneath`) with a `..`
  pre-check — same guarantee already applied to `kYR_state`. A hostile/compromised
  manager cannot make a node mutate outside its export root. Headline security
  property; gets dedicated negative tests.
- Frame caps unchanged (4096; `dlen` validated before use; fixed stack `inbuf`,
  no attacker-sized heap alloc).
- Unroutable/unknown opcode → log + drop (matches `cmsd` tolerance), never crash.
- Node op failure → `fsFail`-style error string → `kYR_error` reply, errno mapped.
- Aggregation: partial failure reports first/worst error; node timeout → drop that
  node, continue; `prepadd`/`prepdel` honor FRM-disabled state.

## 7. Testing (3-per-change: success + error + security-neg)

- **Wire conformance:** extend `test_cms_wire_pup_conformance.py` — golden
  encode/decode for every new opcode frame (byte-exact vs `YProtocol.hh`).
- **Standalone unit:** `cms_router_unittest` + `cms_rrdata_unittest` (gcc, no nginx;
  matches `csi_unittest`/`ini_unittest` pattern) — route lookup + Pup roundtrip +
  malformed/truncated payload rejection.
- **Plane A:** `ping→pong`, `disc` closes cleanly, `update` triggers state probe,
  `usage`/`stats`/`statfs` reply shape; negatives: oversize/malformed/pre-auth.
- **Plane B:** forwarded `mkdir`/`rm`/`mv` execute on node within export root;
  **`../` traversal rejected** (security-neg); N-node aggregation; node-failure →
  error to client; `Delayable` → `kYR_wait`.
- **Interop:** vs real `cmsd` in the fleet harness where available; golden-frame
  fixtures otherwise.

## 8. Build governance

New `.c` files register in the top-level `./config` `NGX_ADDON_SRCS` list (per
`build_source_list_location` memory), then `./configure`. No nginx-core edits.
Standalone unit tests compile directly with `gcc` against the pure-C sources.

---

## 9. Implementation status (live)

**Build:** clean `./configure` + `make -j` under `-Werror` (binary
`/tmp/nginx-1.28.3/objs/nginx`). New sources registered in top-level `./config`:
`router.{c,h}`, `rrdata.{c,h}`, `node_ops.{c,h}`, `forward.{c,h}`.

**Tests:** 41 standalone unit checks (`rrdata_unittest` 17, `router_unittest` 13,
`node_ops_unittest` 11) + 24 pytest wire-conformance tests in
`tests/test_cms_wire_pup_conformance.py` (run:
`TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_wire_pup_conformance.py`).

| Item | State |
|---|---|
| Foundation: `router` (role tables, flags) | ✅ done + unit-tested |
| Foundation: `rrdata` decode + encode + statfs encode | ✅ done + unit-tested |
| Plane A: `ping→pong`, `disc` (echo+close), `update→status` | ✅ done + conformance-tested (live wire) |
| Plane A: `statfs→data` (registry-sourced) | ✅ done + conformance-tested |
| Plane A: `usage→load`, `stats→data` | ⏳ deferred — load-frame / cluster-blob payloads need a real meta-manager peer to diff byte-exact |
| Plane B node executor: chmod/mkdir/mkpath/mv/rm/rmdir/trunc, confined | ✅ done; planner unit-tested; **confinement breach refusal conformance-tested** (forwarded `/../pwned` → `kYR_error`, nothing created outside root) |
| Plane B node: prepadd/prepdel → FRM | ⏳ deferred (staging integration) |
| Plane B manager: `forward_to_node` send primitive | ✅ done (encoder round-trip unit-tested) |
| Plane B manager **orchestration (redirect)** | ✅ done + fleet-tested — `manager_redirect_mutation` in `handshake/dispatch_write.c` redirects path-based mutations (mkdir/rm/rmdir/mv/chmod/truncate) to the data node; `tests/test_manager_mode.py::TestClusterMutationRedirect` (mkdir→redirect, rm→redirect) pass against the live cluster. This is the nginx-correct mechanism: per-worker node CMS connections make cross-worker CMS fan-out impractical, and redirect needs no shared connection state. |
| Plane B manager: CMS-forward fan-out for **multi-replica** mutation (remove-from-all-holders without client round-trips) | ⏳ remaining — needs cross-worker coordination; the `forward_to_node` primitive + node executor are the building blocks. Single-replica is fully covered by redirect above. |
