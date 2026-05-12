# voms — Optional VOMS virtual-organisation extraction

Extracts VO (Virtual Organisation) membership from VOMS extensions embedded
in x509 proxy certificates.  Compiled only when `XROOTD_HAVE_VOMS` is
defined.

| File | Responsibility |
|------|----------------|
| `loader.c` | Dynamically loads `libvomsapi.so` at nginx startup via `dlopen`; populates the `xrootd_voms_api` function-pointer table so the module has no link-time VOMS dependency |
| `extract.c` | `xrootd_extract_voms_info` — public entry point called by the GSI auth path after the proxy chain is verified; fills `ctx->primary_vo` and `ctx->vo_list` |
| `collect.c` | Converts VOMS API result structs into the comma-separated VO list string used internally |
| `voms_internal.h` | ABI-compatible struct definitions matching `voms-2.1.3`/EL9; the function-pointer table type `xrootd_voms_api_t` |

The extracted `primary_vo` and `vo_list` are used by `path/` to enforce
`xrootd_require_vo` ACLs.

When `libvomsapi.so` is not found at startup, `xrootd_voms_loaded` remains
false and all VO ACL checks are skipped with a warning.
