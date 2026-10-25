# Native diagnostic and conformance tools

The `xrd conform` probe families share execution state through
`xrd_conform_internal.h`. Each family retains its protocol operations and safety
gates; the following modules own reusable bookkeeping and pure observations.

| Files | Responsibility |
|---|---|
| `xrd_conform_probe_helpers.c` / `.h` | Selected-row filtering, request-budget refusal, verdict evidence and scratch-object path delegation. |
| `xrd_conform_reply.h` | One owned raw-response body/length type shared by open, refresh and checkpoint probes. |
| `xrd_conform_error_fixtures.c` / `.h` | Closed errno-fixture vocabulary used by both CLI validation and runtime probes. |
| `xrd_conform_tpc_helpers.c` / `.h` | Bounded native-TPC URL construction, numeric capability parsing and exact destination verification shared with scoped-copy probes. |

New diagnostic translation units must be registered in `client/Makefile`.
