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
`-DBRIX_HAVE_KRB5=1` and links libkrb5. When absent, the files still compile
(every body is guarded by `#if (BRIX_HAVE_KRB5)`) but `brix_auth krb5`
becomes a configuration-time error and any runtime `krb5` credential is rejected
with `kXR_NotAuthorized` ("krb5 support is not compiled in"). This keeps the
build green on hosts without a Kerberos toolchain.

In the request lifecycle this subsystem sits at the **stream login/auth stage**.
After the handshake and `kXR_login`, the XRootD client sends a `kXR_auth`
request carrying a `krb5`-prefixed credential blob. The opcode handler in
`../gsi/auth.c` inspects the credential type and, for `krb5`, calls
`brix_handle_krb5_auth()` here. Configuration is validated once at
`postconfiguration` time by `brix_configure_krb5_auth()`. Only the
`root://` stream path uses Kerberos; the WebDAV/HTTPS and S3 HTTP paths use
GSI certs, bearer tokens, and SigV4 respectively and never enter this code.

## Files

| File | Responsibility |
|---|---|
| `config.c` | `brix_configure_krb5_auth(cf, xcf)` — config-time setup. When `auth == krb5`: requires `brix_krb5_principal`, calls `krb5_init_context`, parses the service principal (`krb5_parse_name`), resolves the keytab (`krb5_kt_resolve`, or `krb5_kt_default` if none given), and validates the keytab is readable (`krb5_kt_start_seq_get`). Logs the resolved principal/keytab/ip_check at NOTICE. Stores the long-lived `krb5_context`/`krb5_principal_obj`/`krb5_keytab_obj` objects on the server conf. When built without Kerberos, fails the config if `auth == krb5`. |
| `auth.c` | `brix_handle_krb5_auth(ctx, c, conf)` — per-connection runtime auth. Verifies the client's AP-REQ ticket against the host keytab (`krb5_rd_req`), maps the client principal to a local name, sets the connection identity/session, emits metrics + access log, and returns success or `kXR_NotAuthorized`. Contains static helpers: `brix_krb5_error`/`brix_krb5_free_error` (error-message lifetime), `brix_krb5_peer_addr` (optional source-IP binding), `brix_krb5_client_name` (principal → localname mapping), `brix_krb5_track_identity` (unique-user metric), `brix_krb5_session_grant` (shared success bookkeeping, reused by both the single-round path and the delegation round-2 finalize). When `brix_krb5_delegate on`, round-1 branches into `brix_krb5_begin_delegation` and a round-2 `kXR_auth` re-enters via `brix_krb5_finish_delegation` (both defer to `deleg_capture.c`). |

### Forwarded-TGT delegation (EXCHANGE path — phase-70 §5.7)

These files implement per-user backend auth by **forwarding the caller's TGT** to
the origin, so the outbound leg authenticates as the inbound user with no admin
pre-provisioning. They are only exercised when `brix_krb5_delegate on` (inbound
capture) and `brix_backend_krb5_forwardable on` (outbound drive).

| File | Responsibility |
|---|---|
| `deleg_capture.c` / `.h` | Inbound two-round `kXR_authmore`/`"fwdtgt"` delegation-CAPTURE state machine. Always-compiled seams: `brix_krb5_deleg_wanted` (config gate), `brix_krb5_deleg_credbytes` (strip the `"krb5"` prefix + optional NUL from a round-2 payload → raw `KRB_CRED`), `brix_krb5_send_fwdtgt` (round-1 `kXR_authmore` carrying `"krb5"`+`"fwdtgt"`), `brix_krb5_deleg_origin_spn` (request-time gate + origin-SPN derivation). Under `BRIX_HAVE_KRB5`: `brix_krb5_deleg_park` (copy the verified client + park the round-1 `krb5_auth_context` on `ctx->krb5` with a pool-cleanup that frees the handles + `unlink`s the 0600 ccache at connection close), `brix_krb5_deleg_capture` (round-2: decode → `brix_krb5_capture_fwd_cred` → serialise the TGT to a fresh 0600 FILE ccache, stashing the PATH on `ctx->krb5.ccache`), `brix_krb5_deleg_release`. |
| `capture.c` / `.h` | `brix_krb5_capture_fwd_cred()` — the crypto core: `KRB_CRED` → `krb5_rd_cred` (under the round-1 auth context) → MEMORY ccache → `gss_krb5_import_cred`. Live-proven vs a real KDC (`test_krb5_forward_live.py` mode `capture`). |
| `carry.c` / `.h` | Async-safe cred carry: `brix_krb5_cred_to_ccache` (export the captured initiator cred to a 0600 FILE ccache via RFC 5588 `gss_store_cred_into`), `brix_krb5_cred_from_ccache` (re-import on a fresh handle for the async fill task), `brix_krb5_cred_carry_release`. A live `gss_cred_id_t` is request-scoped and unsafe to embed in the async `brix_cache_fill_t`; the PATH is not. |
| `forward.c` / `.h` | Outbound origin leg: `brix_krb5_origin_princ_from_host` (derive `host/<fqdn>@REALM`), `brix_krb5_deleg_to_origin` (one GSSAPI step), `brix_krb5_deleg_negotiate` (the full `gss_init_sec_context` ↔ origin loop to `GSS_S_COMPLETE`, mutual-auth-required, fail-closed). |
| `kxr_wire.c` / `.h` | `brix_krb5_kxr_wire()` — the `brix_krb5_wire_fn` transceiver over a real origin connection, framing each negotiation leg as `kXR_auth` credtype `"krb5"` ↔ `kXR_authmore`/`kXR_ok`. |

The public runtime/config entry points (`brix_handle_krb5_auth`,
`brix_configure_krb5_auth`) are declared in `src/core/ngx_brix_module.h` and
`src/core/config/config.h`; the delegation modules expose their own local headers
(above). The persistent Kerberos objects, the `krb5_*` tunable fields, and the
`delegate` flag live on `ngx_stream_brix_srv_conf_t` in `src/core/types/config.h`; the
per-connection delegation round state lives in `brix_ctx_krb5_t`
(`src/core/types/context.h`).

### Other files

| File | Responsibility |
|---|---|
| `apreq.c` / `.h` | raw-krb5 AP-REQ builder for the outbound origin leg (§5.7). |

## Key types & data structures

- **`ngx_stream_brix_srv_conf_t`** (`src/core/types/config.h`) — per-server-block
  config. Kerberos fields:
  - `krb5_principal` (`ngx_str_t`) — host service principal, e.g.
    `xrootd/host@REALM`. Required when `auth == krb5`.
  - `krb5_keytab` (`ngx_str_t`) — keytab spec, e.g.
    `FILE:/etc/xrootd.keytab`. Empty = the Kerberos default keytab.
  - `krb5_ip_check` (`ngx_flag_t`) — bind the AP-REQ to the peer source
    address. **Default off**, matching upstream `XrdSeckrb5`.
  - `krb5_context`, `krb5_keytab_obj`, `krb5_principal_obj` — the parsed,
    long-lived libkrb5 handles built once at config time and reused for every
    connection (only present under `BRIX_HAVE_KRB5`).
- **`brix_ctx_t`** (`src/core/types/context.h`) — per-connection state. On success
  this code sets `auth_done = 1`, `token_auth = 0`, copies the mapped principal
  into `ctx->dn`, and updates `ctx->identity` via `brix_identity_set_dn(...,
  BRIX_AUTHN_KRB5)`.
- **`BRIX_AUTH_KRB5`** (`src/core/types/tunables.h`, value `6`) — the configured
  auth mode the credential is gated against.
- **libkrb5 types** — `krb5_auth_context`, `krb5_ticket`, `krb5_data`,
  `krb5_address`, `krb5_error_code` are used transiently inside
  `brix_handle_krb5_auth`.

## Control & data flow

Entry into this subsystem:

1. **Config time** — `src/core/config/postconfiguration.c` calls
   `brix_configure_krb5_auth(cf, xcf)` in its per-server auth-setup pass
   (alongside GSI/TLS/token/SSS setup). The `brix_krb5_principal`,
   `brix_krb5_keytab`, and `brix_krb5_ip_check` directives are declared in
   the live `ngx_stream_brix_commands[]` table in `src/protocols/root/stream/module.c`
   and bound directly to the conf fields
   by nginx's standard `ngx_conf_set_str_slot`/`ngx_conf_set_flag_slot`.

2. **Runtime** — a `root://` connection reaches the `kXR_auth` handler in
   `../gsi/auth.c`, which reads the credential type from the wire. For a `krb5`
   credential it first checks `conf->auth == BRIX_AUTH_KRB5` (else
   `kXR_NotAuthorized` "krb5 auth not enabled") and then calls
   `brix_handle_krb5_auth(ctx, c, conf)`.

Inside `brix_handle_krb5_auth` the flow is:

- Guard that Kerberos objects exist; require the payload to begin with the
  4-byte `"krb5"` tag (the ticket bytes follow at `ctx->payload + 4`,
  `ctx->cur_dlen - 4`).
- `krb5_auth_con_init`; if `krb5_ip_check`, derive the peer `krb5_address` from
  `c->sockaddr` and `krb5_auth_con_setaddrs` it.
- `krb5_rd_req` verifies the AP-REQ against `krb5_principal_obj` /
  `krb5_keytab_obj`, yielding the `krb5_ticket`.
- `brix_krb5_client_name` maps the ticket's client principal to a local name
  via `krb5_aname_to_localname`, falling back to `krb5_unparse_name` (full
  `user@REALM`) if no `auth_to_local` rule matches.
- On success: set `ctx->dn`/identity, register the session, emit metrics +
  access log, return OK. Every libkrb5 object (`auth_ctx`, `ticket`) is freed
  on all paths.

Calls out to sibling subsystems:

- `../../fs/path/README.md` — `brix_sanitize_log_string()` escapes the principal
  before it is logged (the principal is attacker-influenced wire data).
- `../../observability/metrics/README.md` — `brix_metric_auth(BRIX_PROTO_ROOT,
  BRIX_AUTHN_KRB5, ok)` records auth success/failure; `brix_track_unique_user`
  feeds the unique-identity cardinality estimator. The
  `BRIX_RETURN_OK`/`BRIX_RETURN_ERR`/`BRIX_OP_ERR` macros wrap access log
  + op-counter + send.
- `src/protocols/root/session/registry.h` — `brix_session_register(ctx->sessid, ctx->dn,
  ctx->vo_list, 0)` records the authenticated session for later `kXR_bind`
  resumption.
- `src/core/types/identity.h` — `brix_identity_set_dn()` stores the DN with the
  `BRIX_AUTHN_KRB5` method on the unified identity object.
- `../gsi/README.md` — the upstream dispatcher that routes the `krb5`
  credential type here.

## Invariants, security & gotchas

- **Fail-closed gating (two layers).** The dispatcher in `../gsi/auth.c`
  rejects `krb5` credentials unless `conf->auth == BRIX_AUTH_KRB5`; this
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
  fallback. The mapped name is **sanitized via `brix_sanitize_log_string`
  before logging** (`auth.c:287-289`) because it derives from the ticket — do not
  log `cname` raw.
- **IP check is off by default and best-effort.** `krb5_ip_check` only binds
  IPv4/IPv6 peers; other address families return `NGX_DECLINED` from
  `brix_krb5_peer_addr` and, when the check is enabled, are rejected. Leaving
  it off matches `XrdSeckrb5` and is correct behind NAT/proxies.
- **No blocking outside config time.** All libkrb5 calls here are local keytab /
  in-memory crypto operations (no KDC round-trip on the server side), so they
  run safely on the event loop. Heavy one-time work (`krb5_init_context`,
  keytab open/scan) happens in `config.c` at startup, not per connection.
- **Object lifetime.** The `krb5_context`, principal, and keytab handles are
  created once and live for the worker's lifetime on the conf; per-request
  `auth_ctx`/`ticket` are always freed on every return path. Error messages
  from `krb5_get_error_message` must be released with
  `krb5_free_error_message` — the `brix_krb5_error`/`brix_krb5_free_error`
  pair enforces this.
- **Identity precedence.** On success `token_auth` is explicitly cleared so a
  later code path does not mistake a Kerberos session for a token session.
- **Build guard discipline.** Both files compile unconditionally but every
  Kerberos-touching body is inside `#if (BRIX_HAVE_KRB5)`. New code here must
  preserve the `#else` arms so the no-Kerberos build keeps producing clean
  config-time and runtime errors.

## Entry points / extending

- **Add a krb5 tunable directive** (e.g. a new mapping option): add the field to
  the Kerberos block of `ngx_stream_brix_srv_conf_t` in `src/core/types/config.h`,
  register the `ngx_command_t` in the live `ngx_stream_brix_commands[]` table
  in `src/protocols/root/stream/module.c` (`NGX_STREAM_SRV_CONF`). Set its default
  in the srv-conf merge, and consume it
  in `brix_configure_krb5_auth` (validation) and/or `brix_handle_krb5_auth`
  (runtime). No new top-level config block, so no `./configure` re-run is needed
  unless you add a new source file.
- **Add a new stream credential type** (not krb5): follow this subsystem as the
  template — implement an `brix_configure_<type>_auth` (call it from
  `src/core/config/postconfiguration.c`) and an `brix_handle_<type>_auth`, declare
  both in `src/core/config/config.h` / `src/core/ngx_brix_module.h`, add the credtype
  branch in `../gsi/auth.c`, register the auth-mode constant in
  `src/core/types/tunables.h` and the auth-method slot in `src/observability/metrics/unified.h`, and
  list the new `.c` files in the top-level `config` build script.
- **The two public symbols** are `brix_configure_krb5_auth` (config) and
  `brix_handle_krb5_auth` (runtime); everything else in this directory is
  file-static.

## See also

- `../gsi/README.md` — `kXR_auth` dispatcher that routes credential types
  (gsi/token/sss/unix/krb5).
- `../token/README.md`, `../sss/README.md`, `../unix/README.md` — sibling
  stream credential types.
- `../../protocols/root/session/README.md` — session registry used to record the authenticated DN.
- `../../observability/metrics/README.md` — auth counters and unique-user tracking.
- `../../fs/path/README.md` — log-string sanitization helper.
- `../../core/config/README.md` — `postconfiguration` auth-setup pass.
- `../README.md` — master subsystem index.
