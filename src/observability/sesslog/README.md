# Session Lifecycle Logging

`sesslog` emits compact lifecycle audit records into the existing brix access
log stream. Each live session gets a 16-character ID and a small set of
structured `SESS` lines:

```text
[07/Jul/2026:14:03:22 +0000] SESS 9f3ac1e2b4d87a10 CONNECT proto=root dir=in peer="10.0.0.5:41234" authmethod=gsi
[..] SESS 9f3ac1e2b4d87a10 AUTH ok method=gsi user="/DC=ch/CN=alice" vo="cms"
[..] SESS 9f3ac1e2b4d87a10 ATTEMPT path="/data/f.root" mode=read
[..] SESS 9f3ac1e2b4d87a10 RESULT ok path="/data/f.root" mode=read
[..] SESS 9f3ac1e2b4d87a10 XFER complete path="/data/f.root" mode=read bytes=1048576/1048576 dur=12 avg=87381333
[..] SESS 9f3ac1e2b4d87a10 END reason=client-disconnect dur=20
```

The core formatter in `sesslog.c` is nginx-free: it owns enum labels, field
order, quoting, truncation, and errno/kXR/HTTP error-token mapping. The nginx
glue in `sesslog_ngx.c` owns the per-worker fixed registry, ID minting,
timestamp prefixing, access-log emission through `brix_alog_emit()`, and the
shutdown backstop.

Protocol hooks should call only the glue API. Do not format `SESS` lines in a
protocol handler; add enum values or fields in the formatter first so tests and
all planes keep one grammar.
