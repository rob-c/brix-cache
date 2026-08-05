# Phase-94 Phase-2: gateway bound-write fan-out already works via the resume/POSC `.part`

Durable decision record for the Phase-94 "Phase 2" work — bound-write substream
fan-out to a **gateway → remote `root://` origin**. The headline finding:
**it is already implemented by Phase 1** and needed no new server code, only a
proving test. Companion to
[remote-fhandle-collision-fix.md](remote-fhandle-collision-fix.md) and
[data-substreams-conformance.md](data-substreams-conformance.md).

## The "gated" premise was wrong

The refactor doc had GATED Phase 2 on a wrong premise: that gateway writes take
the driver-backed whole-object staged writer (`file->writer != NULL`,
unpublishable to the SHM handle table). Empirically (verified 2026-08-04) that is
not the path a writable `root://` gateway takes.

## The real mechanism

A writable `root://` gateway with `brix_upload_resume on` (default) — and POSC,
always implemented — stages the upload to a **local, export-rooted `.part` file**
(`open_resolved_file_staging.c`): a real `fd >= 0` with a real local path. That
is the exact fd-backed shape Phase-1 already publishes to the SHM handle table
and fans bound writes across.

- The resume/POSC commit — and the `brix_stage` write-back tier's
  `stage_move_copy_loop` — reads the completed `.part` **to EOF**, not any
  primary-only in-memory cursor / high-water mark. So bytes a bound secondary
  `pwrote` on another worker are flushed to the origin.
- The client closes only after all write acks arrive → the `.part` is complete at
  commit → no close barrier needed.

## The one residual sequential case

`file->writer != NULL` (sequential, unpublishable) is entered ONLY by
`brix_open_write_needs_staged` = a whole-object PUT backend (S3/WebDAV: no
random-write capability AND no `.pwrite`). That residual case still falls back to
the resilient primary (byte-exact), covered by
`test_bound_write_unpublished_handle_refused`. Parallel throughput straight into
such a sequential store (cases B-i / B-ii) is the only deferred item — a
throughput-only optimisation, not a correctness gap.

## Proof test

`tests/test_data_substreams_gateway.py::TestGatewayBoundWriteFanout` stands up a
`root://` origin + a BriX `brix_storage_backend root://origin` gateway (with a
`brix_stage` tier, `worker_processes 2`) via `/usr/sbin/nginx` +
`load_module` of the built `build/modules/ngx_stream_brix_module.so`. It runs
`brix-xrdcp -f --streams 4` (8 MiB) and asserts `chunks-on-secondaries > 0`
(real cross-worker fan-out) AND byte-exact **on the origin's own storage**.

**Rig gotcha:** nginx workers drop to a **service uid (982)**, so the data tree
must be world-traversable + writable — put it under `/tmp/...` (1777) with
`chmod 0777`, **NOT** under the scratchpad (its ancestors are `drwx------`, so a
uid-982 worker can't traverse in).
