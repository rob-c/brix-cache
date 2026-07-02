# krb5 — Kerberos 5 authentication for the `root://` stream protocol

## Overview

This subsystem implements the XRootD **`krb5`** security protocol (the wire
equivalent of upstream `XrdSeckrb5`) for `root://`/`roots://` clients. It lets a
client authenticate by presenting a Kerberos service ticket for the gateway's
host principal; on success the gateway maps the client's Kerberos principal to a
local identity and records it as the connection's authenticated DN. It is one of
several pluggable stream credential types (`gsi`, `token`, `sss`, `unix`,
`krb5`), all of which are dispatched from a single `kXR_auth` handler.

Kerberos support is **optional at build time**. The top-level `config` script
probes for `krb5` via `pkg-config`; when present it compiles both files with
`-DXROOTD_HAVE_KRB5=1` and links libkrb5. When absent, the files still compile
(every body is guarded by `#if (XROOTD_HAVE_KRB5)`) but `xrootd_auth krb5`
becomes a configuration-time error and any runtime `krb5` credential is rejected
with `kXR_NotAuthorized` ("krb5 support is not compiled in"). This keeps the
build green on hosts without a Kerberos toolchain.

In the request lifecycle this subsystem sits at the **stream login/auth stage**.
After the handshake and `kXR_login`, the XRootD client sends a `kXR_auth`
request carrying a `krb5`-prefixed credential blob. The opcode handler in
`../gsi/auth.c` inspects the credential type and, for `krb5`, calls
`xrootd_handle_krb5_auth()` here. Configuration is validated once at
`postconfiguration` time by `xrootd_configure_krb5_auth()`. Only the
`root://` stream path uses Kerberos; the WebDAV/HTTPS and S3 HTTP paths use
GSI certs, bearer tokens, and SigV4 respectively and never enter this code.

## Files

| File | Responsibility |
|---|---|
| `config.c` | `xrootd_configure_krb5_auth(cf, xcf)` — config-time setup. When `auth == krb5`: requires `xrootd_krb5_principal`, calls `krb5_init_context`, parses the service principal (`krb5_parse_name`), resolves the keytab (`krb5_kt_resolve`, or `krb5_kt_default` if none given), and validates the keytab is readable (`krb5_kt_start_seq_get`). Logs the resolved principal/keytab/ip_check at NOTICE. Stores the long-lived `krb5_context`/`krb5_principal_obj`/`krb5_keytab_obj` objects on the server conf. When built without Kerberos, fails the config if `auth == krb5`. |
| `auth.c` | `xrootd_handle_krb5_auth(ctx, c, conf)` — per-connection runtime auth. Verifies the client's AP-REQ ticket against the host keytab (`krb5_rd_req`), maps the client principal to a local name, sets the connection identity/session, emits metrics + access log, and returns success or `kXR_NotAuthorized`. Contains static helpers: `xrootd_krb5_error`/`xrootd_krb5_free_error` (error-message lifetime), `xrootd_krb5_peer_addr` (optional source-IP binding), `xrootd_krb5_client_name` (principal → localname mapping), `xrootd_krb5_track_identity` (unique-user metric). |

There are no headers in this directory. The two public entry points are declared
in `../ngx_xrootd_module.h` (`xrootd_handle_krb5_auth`) and
`../config/config.h` (`xrootd_configure_krb5_auth`); the persistent Kerberos
objects and tunable fields live on `ngx_stream_xrootd_srv_conf_t` in
`../types/config.h`.

## Key types & data structures

- **`ngx_stream_xrootd_srv_conf_t`** (`../types/config.h`) — per-server-block
  config. Kerberos fields:
  - `krb5_principal` (`ngx_str_t`) — host service principal, e.g.
    `xrootd/host@REALM`. Required when `auth == krb5`.
  - `krb5_keytab` (`ngx_str_t`) — keytab spec, e.g.
    `FILE:/etc/xrootd.keytab`. Empty = the Kerberos default keytab.
  - `krb5_ip_check` (`ngx_flag_t`) — bind the AP-REQ to the peer source
    address. **Default off**, matching upstream `XrdSeckrb5`.
  - `krb5_context`, `krb5_keytab_obj`, `krb5_principal_obj` — the parsed,
    long-lived libkrb5 handles built once at config time and reused for every
    connection (only present under `XROOTD_HAVE_KRB5`).
- **`xrootd_ctx_t`** (`../types/context.h`) — per-connection state. On success
  this code sets `auth_done = 1`, `token_auth = 0`, copies the mapped principal
  into `ctx->dn`, and updates `ctx->identity` via `xrootd_identity_set_dn(...,
  XROOTD_AUTHN_KRB5)`.
- **`XROOTD_AUTH_KRB5`** (`../types/tunables.h`, value `6`) — the configured
  auth mode the credential is gated against.
- **libkrb5 types** — `krb5_auth_context`, `krb5_ticket`, `krb5_data`,
  `krb5_address`, `krb5_error_code` are used transiently inside
  `xrootd_handle_krb5_auth`.

## Control & data flow

Entry into this subsystem:

1. **Config time** — `../config/postconfiguration.c` calls
   `xrootd_configure_krb5_auth(cf, xcf)` in its per-server auth-setup pass
   (alongside GSI/TLS/token/SSS setup). The `xrootd_krb5_principal`,
   `xrootd_krb5_keytab`, and `xrootd_krb5_ip_check` directives are declared in
   the live `ngx_stream_xrootd_commands[]` table in `../stream/module.c`
   and bound directly to the conf fields
   by nginx's standard `ngx_conf_set_str_slot`/`ngx_conf_set_flag_slot`.

2. **Runtime** — a `root://` connection reaches the `kXR_auth` handler in
   `../gsi/auth.c`, which reads the credential type from the wire. For a `krb5`
   credential it first checks `conf->auth == XROOTD_AUTH_KRB5` (else
   `kXR_NotAuthorized` "krb5 auth not enabled") and then calls
   `xrootd_handle_krb5_auth(ctx, c, conf)`.

Inside `xrootd_handle_krb5_auth` the flow is:

- Guard that Kerberos objects exist; require the payload to begin with the
  4-byte `"krb5"` tag (the ticket bytes follow at `ctx->payload + 4`,
  `ctx->cur_dlen - 4`).
- `krb5_auth_con_init`; if `krb5_ip_check`, derive the peer `krb5_address` from
  `c->sockaddr` and `krb5_auth_con_setaddrs` it.
- `krb5_rd_req` verifies the AP-REQ against `krb5_principal_obj` /
  `krb5_keytab_obj`, yielding the `krb5_ticket`.
- `xrootd_krb5_client_name` maps the ticket's client principal to a local name
  via `krb5_aname_to_localname`, falling back to `krb5_unparse_name` (full
  `user@REALM`) if no `auth_to_local` rule matches.
- On success: set `ctx->dn`/identity, register the session, emit metrics +
  access log, return OK. Every libkrb5 object (`auth_ctx`, `ticket`) is freed
  on all paths.

Calls out to sibling subsystems:

- `../path/README.md` — `xrootd_sanitize_log_string()` escapes the principal
  before it is logged (the principal is attacker-influenced wire data).
- `../metrics/README.md` — `xrootd_metric_auth(XROOTD_PROTO_STREAM,
  XROOTD_AUTHN_KRB5, ok)` records auth success/failure; `xrootd_track_unique_user`
  feeds the unique-identity cardinality estimator. The
  `XROOTD_RETURN_OK`/`XROOTD_RETURN_ERR`/`XROOTD_OP_ERR` macros wrap access log
  + op-counter + send.
- `../session/registry.h` — `xrootd_session_register(ctx->sessid, ctx->dn,
  ctx->vo_list, 0)` records the authenticated session for later `kXR_bind`
  resumption.
- `../types/identity.h` — `xrootd_identity_set_dn()` stores the DN with the
  `XROOTD_AUTHN_KRB5` method on the unified identity object.
- `../gsi/README.md` — the upstream dispatcher that routes the `krb5`
  credential type here.

## Invariants, security & gotchas

- **Fail-closed gating (two layers).** The dispatcher in `../gsi/auth.c`
  rejects `krb5` credentials unless `conf->auth == XROOTD_AUTH_KRB5`; this
  handler independently re-checks that the Kerberos objects are non-NULL before
  touching the wire payload. A misconfigured or non-Kerberos build can never
  fall through to a permissive path.
- **Credential framing.** The payload must be at least 5 bytes and start with
  the literal `"krb5"` tag (`auth.c:186-192`); the actual AP-REQ is the
  remainder. A short or mistagged blob is `kXR_NotAuthorized` "malformed krb5
  credential" — never passed to libkrb5.
- **Ticket verification is the trust boundary.** Authentication succeeds only if
  `krb5_rd_req` (`auth.c:238-240`) validates the AP-REQ against the host keytab.
  There is no bypass; every other branch returns `kXR_NotAuthorized`.
- **Principal mapping & logging.** `krb5_aname_to_localname` is tried first so
  `/etc/krb5.conf` `auth_to_local` rules apply; the raw `user@REALM` is the
  fallback. The mapped name is **sanitized via `xrootd_sanitize_log_string`
  before logging** (`auth.c:287-289`) because it derives from the ticket — do not
  log `cname` raw.
- **IP check is off by default and best-effort.** `krb5_ip_check` only binds
  IPv4/IPv6 peers; other address families return `NGX_DECLINED` from
  `xrootd_krb5_peer_addr` and, when the check is enabled, are rejected. Leaving
  it off matches `XrdSeckrb5` and is correct behind NAT/proxies.
- **No blocking outside config time.** All libkrb5 calls here are local keytab /
  in-memory crypto operations (no KDC round-trip on the server side), so they
  run safely on the event loop. Heavy one-time work (`krb5_init_context`,
  keytab open/scan) happens in `config.c` at startup, not per connection.
- **Object lifetime.** The `krb5_context`, principal, and keytab handles are
  created once and live for the worker's lifetime on the conf; per-request
  `auth_ctx`/`ticket` are always freed on every return path. Error messages
  from `krb5_get_error_message` must be released with
  `krb5_free_error_message` — the `xrootd_krb5_error`/`xrootd_krb5_free_error`
  pair enforces this.
- **Identity precedence.** On success `token_auth` is explicitly cleared so a
  later code path does not mistake a Kerberos session for a token session.
- **Build guard discipline.** Both files compile unconditionally but every
  Kerberos-touching body is inside `#if (XROOTD_HAVE_KRB5)`. New code here must
  preserve the `#else` arms so the no-Kerberos build keeps producing clean
  config-time and runtime errors.

## Entry points / extending

- **Add a krb5 tunable directive** (e.g. a new mapping option): add the field to
  the Kerberos block of `ngx_stream_xrootd_srv_conf_t` in `../types/config.h`,
  register the `ngx_command_t` in the live `ngx_stream_xrootd_commands[]` table
  in `../stream/module.c` (`NGX_STREAM_SRV_CONF`). Set its default
  in the srv-conf merge, and consume it
  in `xrootd_configure_krb5_auth` (validation) and/or `xrootd_handle_krb5_auth`
  (runtime). No new top-level config block, so no `./configure` re-run is needed
  unless you add a new source file.
- **Add a new stream credential type** (not krb5): follow this subsystem as the
  template — implement an `xrootd_configure_<type>_auth` (call it from
  `../config/postconfiguration.c`) and an `xrootd_handle_<type>_auth`, declare
  both in `../config/config.h` / `../ngx_xrootd_module.h`, add the credtype
  branch in `../gsi/auth.c`, register the auth-mode constant in
  `../types/tunables.h` and the auth-method slot in `../metrics/unified.h`, and
  list the new `.c` files in the top-level `config` build script.
- **The two public symbols** are `xrootd_configure_krb5_auth` (config) and
  `xrootd_handle_krb5_auth` (runtime); everything else in this directory is
  file-static.

## See also

- `../gsi/README.md` — `kXR_auth` dispatcher that routes credential types
  (gsi/token/sss/unix/krb5).
- `../token/README.md`, `../sss/README.md`, `../unix/README.md` — sibling
  stream credential types.
- `../session/README.md` — session registry used to record the authenticated DN.
- `../metrics/README.md` — auth counters and unique-user tracking.
- `../path/README.md` — log-string sanitization helper.
- `../config/README.md` — `postconfiguration` auth-setup pass.
- `../README.md` — master subsystem index.
