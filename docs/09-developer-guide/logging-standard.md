# BriX diagnostic logging standard

All server, native client and standalone tool diagnostics use a single-line,
bounded record. CLI results, help, progress displays and explicitly requested
reports are presentation output, not diagnostic events. HTTP access and security
audit logs retain their existing dedicated schemas and sinks.

## Record template

`timestamp=… level=INFO service=brix role=client source="client/…/file.c" event="function" message="operation completed" truncated=0`

Required diagnostic fields are `level`, `service`, `role`, `source`, `event`,
`message` and `truncated`. `source` identifies the owning component; `event` is
the emitting function, not a user-supplied identifier. Source paths are relative
to the repository, not the developer's home directory. No dynamic global logger
configuration is needed. Native standalone timestamps are Unix seconds (UTC);
Python timestamps are UTC RFC3339. nginx supplies its timestamp, PID, severity,
connection, errno and configuration file/line context through its existing sink.
Normalize timestamps in the collector; do not interpret Unix seconds as local
time. nginx NOTICE maps to `INFO`, ALERT/EMERG to `FATAL`; original nginx
severity and filtering remain intact.

| Level | Meaning |
| --- | --- |
| DEBUG | Explicitly enabled troubleshooting: protocol trace, retry detail, internal state. |
| INFO | Normal significant lifecycle transitions or completed operations; not every packet. |
| WARN | Recoverable degradation, fallback or insecure/mis-tuned configuration requiring attention. |
| ERROR | An operation failed; include operation, safe context and reason. |
| CRIT | Running service is substantially degraded. |
| FATAL | Startup/configuration cannot proceed. |

Do not promote routine client rejections to service-critical severity. Do not
emit success messages at ERROR. Avoid duplicate records for the same failure at
every stack frame. Keep dynamic paths/identities in messages, not metric labels.
Use `BRIX_DIAG*` to include a concise summary, cause and actionable fix on the
same line. Explain genuine operator action; do not invent a fix.

## APIs and safety

- Server: `BRIX_LOG`, `BRIX_LOG_DEBUG`, `BRIX_CONF_LOG` from
  `src/core/compat/log_event.h`. Keep nginx format specifiers and explicit errno.
  Disabled diagnostics do not evaluate message arguments. Debug categories and
  compile-time debug disabling remain supported.
- Native clients/tools: `BRIX_CLIENT_LOG` / `BRIX_TOOL_LOG` from
  `shared/observability/log_stdio.h`, with an explicit severity. Diagnostics go
  to stderr; stdout remains usable by pipelines. Existing trace/debug flags
  control whether DEBUG call sites execute.
- Python tools: `tools.logging_support.diagnostic` with explicit level, source
  and event. Do not configure the application's root logger when importing a tool.

Escape quotes, backslashes, CR/LF, terminal controls and non-ASCII bytes before
emitting native records. Python uses JSON string escaping for field bodies.
Collectors must handle both documented escaping dialects; this is not JSONL.
Messages are bounded: server raw text 768 bytes, standalone native 1023 bytes,
Python 1024 characters. `truncated=1` makes loss visible. Whole escapes and closing
field quotes must survive truncation. One stdio/nginx call per diagnostic avoids
application-level fragments. Cross-process transport atomicity still depends on
the sink and record size. Adapters preserve native caller errno.

Never log passwords, bearer tokens, private keys, authorization headers or raw
credential payloads, even at DEBUG. Escaping is **not redaction**: keep existing
request-query redaction and credential-sanitization helpers at their trust
boundaries. Access logs must not regain credential-bearing query strings.
Wire dumps omit login/authentication/signing and pre-authentication bodies.
Other payloads can still contain user data: explicit dumps require special
care and are not safe to publish as-is.
Do not add unlimited dumps or high-volume per-byte INFO logging. Rotation,
retention, restrictive file permissions and collector access remain deployment
responsibilities; nginx error/access-log directives remain authoritative.

## Enforcement and verification

Run `python3 tools/ci/check_logging_template.py` and
`PYTHONPATH=tests pytest tests/test_logging_template.py -v`.
Migration scripts under `tools/refactor/normalize_*_logging.py` are lexical/AST
tools, not a substitute for reviewing severity and presentation contracts.

This template follows the severity/context principles in the
[OpenTelemetry log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
and the safety guidance in the
[OWASP logging cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

## Recorded verification (2026-10-04)

- macOS ARM64: server and native client builds; 64 passing focused tests covering
  the template, shared query/redaction helpers, configuration diagnostics, native
  client traces, credential preflight, CLI environment compatibility, cross-plane
  access logs and batched access-log injection boundaries.
- Alma9 ARM64 (Lima): dynamic server-module build and 25 passing template,
  shared query-helper and real nginx configuration-logging checks.
- Logging-template, platform, DNS, VFS seam, VFS mutation and source-coverage
  guards passed. `git diff --check` passed.
- The separate Git-tracking checks require the new logging files to be committed;
  no Git writes were performed. The complexity guard still reports the existing
  `brix_configure_tls` CCN 17 violation (limit 15), not a new logging function.

These are focused checks, not a claim that the entire repository suite or every
packaging target has been retested after the logging migration.
