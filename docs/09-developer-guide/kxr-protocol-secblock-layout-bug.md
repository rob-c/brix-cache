# kXR_protocol Security-Block Layout Bug (and Phase-1 no-auth benchmark findings)

Phase-1 no-auth benchmark (5 clients × BriX-vs-official, brix-cache v1.4.0) found a real BriX
wire-conformance bug in `src/protocols/root/session/protocol.c::protocol_write_sec_trailer`, plus two
related findings surfaced by the same rig.

## Finding #1 — kXR_protocol sec-block layout (RESOLVED 2026-08-04; fix applied in protocol.c)

**Symptom:** under `brix_auth none`, go-hep and XrdRust reject BriX for every op.

- XrdRust: "kXR_protocol security block has tag 0x00, expected 'S'".
- go-hep: "requires request 3010 to be signed, but the session established no signing key".
- PyXRootDClient passes only because it was patched (c8e5efd) to tolerate the block; official + brix
  C++ clients tolerate it too.

**Root cause (single, layout):** wire spec `ServerResponseBody_Protocol` =
`pval(4) + flags(4) + secreq(ServerResponseReqs_Protocol)`. The `secreq` 'S' block must sit
**immediately after flags** (byte 8). BriX instead prepends a spurious 4-byte "SecurityInfo header" +
N×8-byte binary auth-protocol entries, shifting the 'S' block 4+N*8 bytes downfield. Under no-auth
(N=0) the 'S' char (0x53=83) lands where clients read `seclvl` → XrdRust sees tag 0x00 at byte 8;
go-hep reads seclvl=83 → "sign everything" but no signing key.

`conf->security_level` already defaults to 0, so the seclvl *value* is fine — the layout is the whole
bug. Auth protocols are advertised the standard way via the `&P=gsi,...&P=ztn,...` string in the
**kXR_login** response (`login.c:155-213`), NOT via these binary entries — so the entries are
dead/non-standard and removing them is safe for phase-2 GSI.

**Fix:** emit only the 6-byte `ServerResponseReqs_Protocol` (`'S',0,secver,secopt,seclvl,0`) right
after the body when kXR_secreqs set; drop the SecurityInfo header + binary entries +
`protocol_sec_count` / `protocol_sec_entry_write`. Fixes go-hep + XrdRust for both no-auth and
(structurally) GSI phases. PyXRootDClient stayed 18/18 after. Related:
pyxrootdclient-mnist-brix-2026-08-03.

## Finding #2 (minor) — mkdir -p idempotency over the xroot/cache gateway (RESOLVED 2026-08-04)

BriX `mkdir -p` on an existing dir returned `[3018] Directory not empty`; official xrootd `mkdir -p`
is idempotent. Affected the official-cli mkdir op against the gateway only.

**Root cause:** `src/fs/cache/origin_ns.c::brix_cache_origin_status_errno` maps the origin's
`kXR_ItExists` (3018) → **ENOTEMPTY** — correct for rmdir/mv (a non-empty dir) but WRONG for mkdir,
where 3018 means "target already exists" (EEXIST). The prefix-walk `brix_vfs_backend_mkpath`
(vfs_walk.c) and the `-p` flag only tolerate `errno==EEXIST`, so an existing-dir mkdir aborted with
ENOTEMPTY instead of idempotent success. Stock xrootd returns 3018 with msg "…; file exists"; go-hep
`MkdirAll` walks parents by issuing a plain (non-recursive) mkdir on each ancestor and tolerates the
EEXIST-flavored 3018 but NOT the ENOTEMPTY-flavored one → go/cli mkdir failed only against the gateway
(`:21094`), never local-fs BriX (`:21096`, which returns EEXIST correctly).

**Fix:** in `brix_cache_origin_mkdir`, decode the kXR error CODE from the reply BODY (the header status
is the generic kXR_error(4003); the 3018 rides in the body — decode via `xrd_error_body_decode`, same
as status_errno) and map `kXR_ItExists → EEXIST` for the mkdir path only. rmdir/mv keep ENOTEMPTY
(verified: rmdir on a non-empty dir still fails 3018 correctly).

**Gotcha:** first cut checked `status == kXR_ItExists`, but `status` is always kXR_error(4003) on the
wire — the code is body-encoded. Result: go-hep 17/17, cli mkdir idempotent on stale re-runs. Guards
(vfs_seam, config_coverage) pass. Diagnosis path: tee proxy on the origin conn + strace showed the
mkdir DOES forward to origin (stage decorator `sd_stage_mkdir` is pass-through → sd_xroot_mkdir →
origin_mkdir).

## Finding #3 — go-hep large writes fail on BriX (2 stacked gaps) (RESOLVED 2026-08-04)

Surfaced once #1 was fixed. go-hep (default `WithSubStreams=8`) opens parallel data connections: sends
`kXR_bind` (3024, sessid body) on each, then streams the RAW write payload there while the `kXR_write`
header goes on the primary with a non-zero pathID (`write.go`: "non-zero path ID → data goes to the
other connection"). Diagnosed via raw TCP tee (scratchpad `xrd_tee.py` + `parse_frames.py`): the bound
connection's bytes are det-pattern data (00 01 02 03…) that BriX misreads as a request header →
dlen 0x14149997=336926231 → "payload too large, closing".

- **Gap A — kXR_bind data-path:** `src/protocols/root/session/bind.c` ACCEPTS the bind and returns a
  pathid, but BriX has no cross-connection routing to consume bound-connection raw data as the pending
  pathid-tagged write (comment even assumes secondaries only carry framed kXR_read). go-hep falls back
  to inline pathID=0 if bind is REFUSED (session.go:733-742 "a data path is an optimisation, not a
  requirement").
- **Gap B — 16 MiB write cap:** `BRIX_MAX_WRITE_PAYLOAD`=16 MiB (tunables.h:215), checked in
  `recv_frame_bounds.c` / `recv_process.c` before allocation (BriX buffers the whole payload, doesn't
  stream). go-hep's WriteAtContext sends the full 64 MiB as ONE kXR_write; stock xrootd accepts it. So
  even with bind refused, go's inline 64 MiB write trips the cap.

py / official-cli / brix-cli avoid both because XrdCl/PyXRootD default to pathID=0 AND chunk writes
≤ their buffer.

### Fix — streaming write engine + `brix_data_substreams` knob (both wire-tested)

Fixed WITHOUT building a cross-connection data-path:

- **Streaming write engine** `src/protocols/root/write/write_stream.c` (new; in `./config` + write.h).
  A plain kXR_write with dlen > `BRIX_WRITE_STREAM_CHUNK` (8 MiB) is delivered to the fd/staged writer
  in bounded chunks with ONE final ack instead of buffering the whole payload. recv drives it:
  `brix_write_stream_begin` (recv_process.c after_header, repurposes cur_dlen as the per-chunk length),
  per-chunk `brix_write_stream_apply_chunk`, `brix_write_stream_finish`. Chunks applied
  SYNCHRONOUSLY in offset order (no AIO ack surgery): staged → `brix_staged_append_raw` (new reply-free
  core in write_staged.c), direct → VFS job like the sync fallback. All-or-nothing: first error
  latched, rest drained, one kXR_IOError. kXR_write cap raised to `BRIX_MAX_WRITE_STREAM` (1 GiB) in
  recv_frame_bounds.c; pgwrite/writev/chkpoint keep 16 MiB. Writes ≤ 8 MiB keep the UNCHANGED
  buffered+AIO path. Tests: `tests/test_write_streaming.py` (3, PASS on both direct-fd `:21096` and
  staged→origin `:21094`).
- **`brix_data_substreams on|off`** (shared_conf, root:// stream table, default ON). OFF →
  `brix_handle_bind` refuses bind (kXR_Unsupported) so clients (go-hep WithSubStreams, xrdcp) fall back
  to inline pathid-0 → streaming path. Default ON keeps kXR_bind + bound reads (test_session_bind) —
  verified still ACCEPTED (pathid=1) on a default server. Tests: `tests/test_bind_substreams.py`
  (3, PASS).
- **Safe pathid guard** (recv_process.c after_header): a kXR_write with cur_body[12] (pathid) != 0 is
  refused at the header phase WITHOUT reading dlen bytes (data is header-only on the primary; the
  payload rode a substream) → no desync. This is also the exact hook a future real cross-connection
  write data-path would use.
- Result: **go-hep 17/17 vs BriX** (was 1/17) at repeat=1. The cross-connection parallel-WRITE
  data-path (task #23) was NOT built — it is throughput-only (streaming already gives correctness) and
  a large/multi-worker-fragile subsystem, left as a tracked follow-on.

## Bench rig

`/root/dev/brixbench` (`run_matrix.sh` + `compare.py`, 5 drivers py/go/rust/cli/brixcli). Origin
`:21095`, BriX `:21094`, data under `/tmp/brixbench`. Phase-1 verdict pre-fix: PASS 34 · FAIL 33 ·
N/A 2 (all 33 FAILs are go+rust hitting Finding #1, plus 1 benign cli mkdir).

Guards pass: check_config_coverage, check_vfs_seam. Build via `bash build/build-nginx-modules.sh`
(dynamic module; no objs/nginx — validate with system `nginx -t`). **Do NOT touch** the system
xrootd-brix cluster pids 75668-75671 holding `:11094` (NGINX_ANON_PORT); use dedicated BriX on
`:21096`/`:21097` instead.

**Commit status:** Finding #1 (secblock) fix applied in protocol.c; streaming write engine +
`brix_data_substreams` knob + mkdir idempotency fix all wire-tested but NOT yet committed (awaiting OP
approval to edit core wire code).
