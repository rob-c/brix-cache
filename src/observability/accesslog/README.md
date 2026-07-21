# Access Logging

Formats and writes one structured access-log line per XRootD request — client
IP, auth method (gsi/sss/anon), identity (DN), Apache-style timestamp,
verb/path/detail, OK/ERR status, byte count, and request duration in
milliseconds. Every field passes through `brix_sanitize_log_string()` before it
reaches the line, because wire-protocol paths, error messages, and client
addresses may contain arbitrary bytes that would corrupt downstream parsers;
the 4096-byte line buffer accommodates worst-case `\xNN` escape expansion.

The writer is batched (phase 33 C1): instead of one write(2) per request, lines
accumulate in a per-worker 64 KiB static buffer and are flushed on buffer-full,
a target-fd switch, a 1-second timer, and connection close. The stream worker
is a single-threaded event loop, so the static buffer needs no locking, and the
log fd is opened O_APPEND so a batched multi-line write stays atomic per call
and interleaves cleanly with other workers.

File split:

- `access_log.h` — the shared writer entry points: `brix_alog_emit()` (append
  one complete line, flushing across fd switches), `brix_access_log_flush()`,
  and `brix_access_log_time_prefix()` for the standard `[dd/Mon/yyyy:...] `
  prefix.
- `access_log.c` — the batch buffer + timer, the six-phase per-request
  formatting pipeline (`brix_log_access`), and the bridge that derives session
  lifecycle events (auth method, open mode, namespace ops) for the sesslog
  component.

The session-lifecycle logger (`../sesslog/`) writes into this same stream via
`brix_alog_emit()`, which is why timestamping, buffering, fd switching, and
explicit flushes live here and are shared rather than duplicated. Lines never
cross fds: a line targeting a different log than what is buffered forces a
flush first. Durations are floored at zero as clock-skew protection.
