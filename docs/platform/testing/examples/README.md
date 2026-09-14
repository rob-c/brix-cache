# Manual platform diagnostics

The files described here remain in [`tests/platform/examples/`](../../../../tests/platform/examples/).
Directory listings below refer to that source location; command working
directories are unchanged by this guide’s relocation.

These standalone examples are retained from the macOS development branch.
They are outside the production source lists and the automated pytest suite.
Use the maintained native tests in `tests/platform/` for supported API checks.

| File | Purpose |
|---|---|
| `test_platform.c` | Historical platform detection and API demonstration. |
| `test_checksum_accelerate.c` | Manual Apple Accelerate checksum experiment; requires macOS. |
