# Diagnostic record adapters

`log_fields.h` owns bounded byte escaping and repository-relative source names.
`log_stdio.h` uses those helpers for standalone C clients and tools.
The nginx adapter is `src/core/compat/log_event.h`.

These header-only adapters have no mutable state or additional link dependencies.
Severity and filtering remain explicit at each call site. See
[the logging standard](../../docs/09-developer-guide/logging-standard.md).
