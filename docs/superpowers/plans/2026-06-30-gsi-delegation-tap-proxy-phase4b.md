# GSI X.509 Delegation — Terminating Tap Proxy (Phase 4b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`). **HIGH RISK** — exercises the known-fragile GSI/delegation foundation. Stop and report at the first checkpoint that cannot pass; do not push broken code forward.

**Goal:** When a client authenticates to the terminating tap proxy via GSI (X.509 proxy) and delegates a proxy credential, the proxy uses **that delegated proxy** to perform a GSI login to the upstream XRootD server **as the user**, then forwards opcodes — verified by an end-to-end test where a delegating GSI client reads a file byte-exact through the proxy from a GSI-only upstream, with the tap logging the opcodes.

**Architecture (threaded-blocking reuse):** Reuse the proven blocking in-process GSI client (`xrootd_cache_origin_connect` + `xrootd_cache_origin_bootstrap`, which the cache uses to authenticate GSI `root://` origins). For a `gsi` proxy auth mode, the proxy: (1) as a GSI *server*, captures the client's delegated proxy into `ctx->gsi_deleg_proxy_pem` (existing `delegation.c`, gated on `xrootd_tpc_delegate`); (2) on first opcode, writes that PEM to a `0600` temp file and **offloads** a blocking "connect + GSI-login to the upstream with this proxy" to an `ngx_thread_task` (the proxy has no threads today — this is the new integration), producing an authenticated fd; (3) on task completion, wraps the fd in an `ngx_connection_t`, splices it into the proxy as the IDLE upstream, and dispatches the saved request; (4) the existing async forward/relay + Phase-4a tap take over.

**Tech Stack:** C nginx stream module, OpenSSL/GSI (`gsi_core`), `ngx_thread_task`, the cache origin client, bash+xrdfs GSI integration test, `pki_helpers`.

## Global Constraints

- **NO `goto`**; functional/modular; no new globals; explicit ctx.
- **HELPERS — reuse:** `xrootd_cache_origin_connect`/`_bootstrap` (blocking GSI login), `delegation.c` capture, `ngx_thread_task` (cache `thread.c` pattern), `xrootd_open_credfile`/temp-cred helpers (`0600`, `O_EXCL`), the Phase-4a tap. Do NOT write a new GSI handshake — reuse `gsi_core`.
- **Credential hygiene:** the delegated proxy temp file is `0600`, `O_EXCL`, owner-only, unlinked immediately after the GSI login (or on connection teardown). Never log proxy private bytes.
- **Thread safety:** the blocking login runs in a thread-pool worker; it touches ONLY its own synth conf + `oc` + the temp file — no shared session state. The fd is handed back to the event loop via the task completion handler (main thread).
- **Build governance:** likely a new `.c` (`src/net/proxy/gsi_upstream.c`) → register in `./config`, then `./configure`. A `thread_pool` must be configured for the proxy server (the task is a no-op fallback / clean error if absent).
- **Stop-on-risk:** if the upstream GSI login cannot be made to work (foundation bug), STOP at Task 4, document the exact failure, and do not fake the e2e result.

---

### Task 1: `gsi` auth mode + delegation enablement (config, verifiable)

**Files:** `src/core/types/config.h` (auth-mode enum value if needed), `src/net/proxy/directives.c` (`xrootd_conf_set_proxy_auth` accepts `gsi`), `src/protocols/root/stream/module.c` (already has `xrootd_tap_proxy_auth`).

**Interfaces:** Produces a parsed `proxy_auth == XROOTD_PROXY_AUTH_GSI`; when set, the proxy server must run with delegation capture on.

- [ ] **Step 1: Test (config accept)** — extend a config test: `xrootd_tap_proxy_auth gsi;` is accepted by `nginx -t`. Before: FAIL (unknown value).
- [ ] **Step 2:** Add `XROOTD_PROXY_AUTH_GSI` to the proxy auth enum (near the existing `XROOTD_PROXY_AUTH_ANONYMOUS/FORWARD/SSS`); accept `"gsi"` in `xrootd_conf_set_proxy_auth`.
- [ ] **Step 3:** When `proxy_auth == GSI`, require/auto-enable delegation: at server prepare, if `proxy_enable && proxy_auth==GSI` and `tpc_delegate` is unset, set it on (so the GSI server captures the delegated proxy) and log a NOTICE. Verify the client-login GSI path populates `ctx->gsi_deleg_proxy_pem` (it already does under `tpc_delegate`).
- [ ] **Step 4:** Build + `nginx -t` accepts `gsi`. **Commit SKIP.**

### Task 2: Persist the delegated proxy to a secure temp (verifiable)

**Files:** new `src/net/proxy/gsi_upstream.c` + `.h`.

**Interfaces:** Produces `int xrootd_proxy_gsi_write_deleg(xrootd_ctx_t *ctx, char *path_out, size_t cap)` — writes `ctx->gsi_deleg_proxy_pem` to a freshly-created `0600 O_EXCL` temp file under the configured cred dir, returns 0/-1.

- [ ] **Step 1: Unit-ish test** — a standalone test (or a guarded runtime assert) that, given a PEM blob, the writer creates a `0600` owner-only file whose contents round-trip and that a second call uses a distinct path. Before: undefined.
- [ ] **Step 2:** Implement using the existing secure-temp helper (`open_download_temp`/`xrdc_open_credfile` analog on the server side; if none server-side, `mkstemp` + `fchmod 0600` + write-all). Reject empty PEM.
- [ ] **Step 3:** Verify perms + content. **Commit SKIP.**

### Task 3: Threaded blocking GSI login → authenticated fd

**Files:** `src/net/proxy/gsi_upstream.c`, `src/net/proxy/proxy_internal.h` (task ctx fields).

**Interfaces:** Produces `xrootd_proxy_gsi_connect_async(proxy)` that posts an `ngx_thread_task`; the task body builds a synth `ngx_stream_xrootd_srv_conf_t` (upstream host/port from the selected upstream, `cache_origin_x509_proxy` = temp path, `gsi_store` from the proxy's CA dir) + a minimal `xrootd_cache_fill_t`, calls `xrootd_cache_origin_connect` then `xrootd_cache_origin_bootstrap`, and on success stashes the authenticated `oc.fd` (dup'd out of `oc`, so close doesn't take it) + result code on the task ctx.

- [ ] **Step 1:** Define the task ctx (synth conf, oc, result fd, errno/err string) on the proxy or a heap struct owned by the task.
- [ ] **Step 2:** Implement the blocking body reusing the cache connect+bootstrap. Mirror `sd_xroot`'s synth-conf construction (host/port/tls/x509_proxy/gsi_store). On success, `result_fd = oc.fd; oc.fd = -1;` (transfer ownership) so `xrootd_cache_origin_close` won't close it.
- [ ] **Step 3:** Verify in isolation against the GSI origin from `run_credential_xroot_gsi.sh` (call the body directly from a tiny harness, or log the authenticated fd). **This is the highest-risk checkpoint — if the blocking GSI login to the upstream fails here, STOP and report.**
- [ ] **Step 4: Commit SKIP.**

### Task 4: Fd handoff into the proxy + dispatch

**Files:** `src/net/proxy/gsi_upstream.c`, `src/net/proxy/connect_upstream.c` (gsi branch), `src/net/proxy/forward_relay_dispatch.c`.

**Interfaces:** The task completion handler (main thread) wraps `result_fd` in an `ngx_connection_t` (`ngx_get_connection` + set read/write handlers to the proxy relay handlers), sets `proxy->conn`, transitions to `XRD_PX_IDLE`/forwarding, unlinks the temp, and calls `xrootd_proxy_dispatch_pending(proxy)`.

- [ ] **Step 1:** In `xrootd_proxy_connect`, when `eff_auth == GSI`, branch to `xrootd_proxy_gsi_connect_async` instead of the async TCP connect + bootstrap.
- [ ] **Step 2:** Implement the completion handler: build the upstream `ngx_connection_t` around the authed fd, install `xrootd_proxy_read_handler`/`write_handler`, mark `from_pool`-like (bootstrap already done → straight to IDLE), dispatch pending.
- [ ] **Step 3:** Handle failure: task result != 0 → `xrootd_proxy_abort` with a clean client error; always unlink the temp.
- [ ] **Step 4: Build.** **Commit SKIP.**

### Task 5: End-to-end GSI delegation test (the done bar)

**Files:** `tests/run_tap_proxy_gsi.sh`.

- [ ] **Step 1:** Provision PKI via `pki_helpers.blitz_test_pki()` (CA + server cert + user proxy), as `run_credential_xroot_gsi.sh` does.
- [ ] **Step 2:** Stand up: an **origin** requiring GSI (`xrootd_auth gsi`, server cert, CA dir); a **tap proxy** (`xrootd_auth gsi` to the client, `xrootd_tap_proxy on`, `_upstream <origin>`, `_auth gsi`, server cert, CA dir, a `thread_pool`); both with `xrootd_tpc_delegate on`.
- [ ] **Step 3:** A delegating GSI client (`xrdfs`/`xrdcp` with `X509_USER_PROXY` = the user proxy and delegation requested) cats a file through the proxy.
- [ ] **Step 4: Assert:** byte-exact read; the tap log shows `open`; the proxy's access/log shows it logged into the upstream as the user (DN match). A control: a client with NO proxy is rejected.
- [ ] **Step 5:** Run `run_tap_proxy.sh` (anon) + `run_transparent_relay.sh` + `run_cache_xroot_origin.sh` for parity. **Commit SKIP.**

---

## Notes / Risk

- **Foundation risk:** the delegated-proxy → upstream-GSI path has never run end-to-end in this codebase (TPC's use of it is broken). Task 3 is the go/no-go. If the blocking login authenticates a GSI upstream with the delegated proxy, the rest is integration; if not, this needs foundation work (the GSI client / delegation assembly) that is its own project.
- **Thread pool:** the proxy server must declare `thread_pool`; absent it, `gsi` auth mode should fail config validation with a clear message.
- **No async-GSI fallback** in this phase (deferred): we reuse the blocking client per the chosen approach.

## Self-Review

- **Spec coverage:** spec §6 (GSI X.509 delegation upstream, terminating mode) → Tasks 1–5; isolated from Phases 1–4a as the spec required. The "as the user" requirement is met by presenting the user's *delegated* proxy (not a service cert) to the upstream GSI auth.
- **Placeholder scan:** the design names exact reuse functions; Task 3/4 specify the fd-ownership transfer and handoff concretely. The one open variable (server-side secure-temp helper name) is a check-then-pick in Task 2 Step 2.
- **Type consistency:** the synth-conf + `oc` reuse mirrors `sd_xroot`'s existing, compiling construction; `result_fd` ownership transfer (`oc.fd = -1`) matches `xrootd_cache_origin_close`'s contract.
