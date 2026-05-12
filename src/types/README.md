# src/types — Core type definitions

Focused sub-headers extracted from `ngx_xrootd_module.h`. Each file defines exactly one concept so contributors can read just the relevant type without wading through the full umbrella header.

These files are included in order by `ngx_xrootd_module.h` after the nginx, OpenSSL, protocol, metrics, and token headers. Do not include them before those prerequisites.

| File | Contents |
|---|---|
| `tunables.h` | `XROOTD_*` size/count limits, auth-mode constants, SSS constants, `XROOTD_OP_OK/ERR` metric macros, `XROOTD_RETURN_OK/ERR` convenience macros |
| `state.h` | `xrootd_state_t` enum (per-connection state machine), opaque forward declarations for upstream and CMS contexts |
| `file.h` | `xrootd_file_t` — per-open-file bookkeeping; array index = XRootD file handle |
| `context.h` | `xrootd_ctx_t` — per-connection context with all session, auth, I/O, and signing state |
| `config.h` | `ngx_stream_xrootd_srv_conf_t` — per-server configuration struct and its helper types (`xrootd_sss_key_t`, `xrootd_vo_rule_t`, `xrootd_group_rule_t`, `xrootd_manager_map_t`) |
