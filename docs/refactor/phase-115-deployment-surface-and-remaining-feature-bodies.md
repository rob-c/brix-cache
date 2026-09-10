# Phase 115 — Deployment surface and the remaining feature bodies

**Status:** IMPLEMENTED (register created 2026-09-05; every `[ ]` row below is
now `[x]`, W1 through W9, landed 2026-09-05/07 and uncommitted). Four rows
closed with a stated limit rather than a green local run — W5.5's live lab
needs real grid endpoints, W6 is a research spike that deliberately writes no
production code, and W5.2's ESTO / W5.3's SPOR are deferred by design with the
refusal pinned; each says so in its own row.
**Source:** the 2026-09-05 whole-repository scope review — "what large features are
missing and what should be developed next" — folded into one work-todo register
**Depends on:** Phase 91 (gsiftp backend v1, CLOSED 2026-09-03), Phase 104
(OCI/RPM distribution), Phase 105/107/108 (VFS mutation gate + surface), Phase
110 (uniform monitoring vocabulary), Phase 111 (repository-work register)
**Trigger:** any item below moves from `[ ]` to in-progress; each item becomes its
own phase doc (Phase 116+) when its design exceeds a page, and this register then
delegates to it the way Phase 111 §7 delegates to owning phases

## Goal

Hold the nine ranked gaps left after the Phase 111 burndown as one ordered
work-todo list with an anchor into the code or doc that owns each gap, a
verification contract per item, and a close protocol. Nothing here is a
regression of landed work; every item is either a missing body, a residual the
XRootD feature-parity audit still lists as open, or a documentation surface that
no longer matches the source.

## Problem

The server is feature-broad (all 32 active XRootD 5.2 opcodes, nine auth
mechanisms, eleven storage drivers) but has **no runnable deployment surface**:
no published server OCI image, no `docker-compose.yml` anywhere in the tree, no
CI-validated `examples/` tree, and several user-facing docs that describe
directives or modes that no longer exist. Behind that, the parity audit
(`xrootd-feature-parity-audit-2026-08-04.md`) still carries a ranked open list
whose top entries are the CMS select-then-proxy gateway, tape/space parity, and
cache residuals. The remaining items are smaller but each has a named owner
doc and none has a phase.

Ranking below is the recommended execution order: item 1 unblocks demos and
evaluation, item 2 is the largest single missing body, item 6 is a research
spike, everything else is parallelisable polish.

## Work items

### W1 — Deployment surface (recommended first)

Tests: `tests/test_phase115_example_configs.py` (44); guard
`tools/ci/check_example_configs.py` + `tools/ci/example_config_lib.py`, wired
into `guards.yml` after the build step.

- [x] **W1.1 Published server image.** `.github/workflows/image.yml` builds
  `deploy/docker/Dockerfile` (RPM-based, entrypoint derives the worker user from
  the config and keeps the credential store `0700`) and publishes to GHCR on
  push/tag. Tests: `test_entrypoint_derives_the_worker_user_from_the_config`
  (success), `test_entrypoint_keeps_the_credential_store_private`
  (security-negative), image build itself is CI-only — docker cannot run on the
  development host (SIGBUS), so the local proof is W1.2's stack boot.
- [x] **W1.2 docker-compose stacks per deployment mode.** Nine stacks under
  `deploy/compose/` (standalone, xrootd-proxy, webdav-edge, gridftp-gateway,
  httpg-proxy, cms-cluster, s3-frontend, xcache, cvmfs), each with a `pki`
  init service, a `client` smoke profile and a POSIX `smoke.sh`; `README.md`
  there is the index. Tests: `test_stack_has_the_agreed_shape`,
  `test_every_compose_conf_parses`, `test_smoke_scripts_are_posix_sh`
  (success); `test_stack_boots_and_passes_its_smoke[<stack>]` boots every
  locally runnable stack on remapped ports with `HOSTALIASES` and runs the
  same `smoke.sh` the compose client runs — each smoke carries its own error
  and security-negative legs (anonymous PUT refused, bad S3 secret refused,
  no-cert httpg refused, cache read-only).
- [x] **W1.3 CI-validated examples tree.** `check_example_configs.py` renders
  every compose conf, `*.conf.example` and the ```nginx fences of README and
  the configuration references into a scratch tree and runs `nginx -t`; every
  `brix_*` name used in any doc must be a registered directive. Tests:
  `test_guard_passes_a_valid_tree` (success),
  `test_guard_fails_an_unknown_directive` /
  `test_guard_fails_the_headline_regression_retired_cache_origin` (error),
  `test_render_never_materialises_outside_the_prefix` (security-negative: an
  example can never make the checker touch `/etc`), plus the classify /
  render / nginx_t / fences groups.
- [x] **W1.4 Stale deployment docs.** README Mode 3 directives, deployment-mode
  count, comparison guide step 4, the 2026-06 snapshots in
  `feature-gap-analysis.md` / `opportunities.md`, and
  `production-deployment.md` (helm path marked legacy, compose stacks pointed
  at) are reconciled. Test: `test_path_rewrite_is_documented_under_its_live_name`;
  the fence guard is the regression net for every documented example.
- Discoveries pinned by tests (each would otherwise silently regress):
  - `check_directive_registry._ENTRY` was blind to any `ngx_command_t` entry
    with a C comment between its fields — `brix_root`, `brix_auth`,
    `brix_scvmfs_x509_dn` were invisible to guard R3
    (`test_registry_regex_tolerates_c_comments_between_fields`,
    `test_registry_sees_the_previously_invisible_directives`).
  - `brix_tap_proxy_path_rewrite` had lost its registration in the 32698a676
    rename while setter, runtime and docs survived; re-registered
    (`test_path_rewrite_directive_parses_with_two_arguments`,
    `..._refuses_one_argument`).
  - Loading a Grid CA directory left `PEM_R_NO_START_LINE` on OpenSSL's error
    queue at three sites (`<hash>.signing_policy` next to `<hash>.0`), and every
    later handshake logged `ignoring stale global SSL error`; fixed in
    `src/auth/crypto/pki_load.c` / `src/auth/gsi/parse_x509.c`
    (`test_stack_boots_and_passes_its_smoke` asserts the log is clean).
  - Demo PKI defects: trust dir must hold no private key, signing policy names
    the CA in slash form, end-entity certs must be able to sign RFC 3820 proxies
    (`test_demo_pki_*`).
  - The credential store must be `0700` both when rendered and in the image
    (`test_render_makes_the_credential_store_private`,
    `test_entrypoint_keeps_the_credential_store_private`).
  - glibc honours `HOSTALIASES` for `nginx -t` and master-time probes but not
    for per-request worker lookups; the stack test rewrites only server-side
    `host:port` positions to loopback (`test_localise_*`, three tests).
  - The renderer must leave `error_log`/`access_log` paths to nginx, not
    pre-create them (`test_render_leaves_log_files_to_nginx`).
  - Smoke-level compat found while making the stacks pass: the GridFTP door
    refuses `CWD` into a directory that does not exist (the smoke `MKD`s after
    the 550, as `globus-url-copy -cd` does); curl's `--aws-sigv4` before 7.80
    signs a canonical request brix rejects as `SignatureDoesNotMatch` (awscli,
    boto3, rclone and xrdcp interoperate, so the smoke uses xrdcp's `s3://`);
    under TLS 1.3 a no-cert httpg client completes the handshake and gets an
    HTTP 400 rather than a TLS abort, and the smoke accepts either as "refused".
  - `check_doc_links.py` resolves targets via `git ls-files`: a link to a new
    file reads as dead until the file is staged.
  - `free_port()` leases deterministic slots from the lane's mock range and
    never probes the kernel; a lane based above the ephemeral floor collides
    with live outgoing connections (`bind() ... failed (98)`); the stack boot
    now takes `_lease_bindable()` slots.
- Verification: success — every compose conf parses and every locally
  runnable stack boots and passes its smoke; error — a misspelled directive
  turns the guard red; security negative — anonymous writes are refused by
  the stacks' auth blocks (smoke legs) and the renderer cannot escape its
  prefix. Docker image build and `docker compose up` are verified by CI only.

### W2 — Select-then-proxy CMS gateway and upstream auth

Tests: `tests/test_phase115_cms_select_proxy.py` (10); configs
`tests/configs/nginx_p115_cms_gateway.conf`,
`tests/configs/nginx_p115_cms_dataserver.conf`; lifecycle slots
`lc-p115-gw-{proxy,redirect,unix}` + `lc-p115-ds` in
`tests/fleet_ports_shared_phase5_rest_b.py`. Narrative:
`docs/05-operations/hierarchical-cluster.md` "Proxy/gateway integration".

- [x] **W2.1 `brix_cms_response redirect|proxy`** — reopened 2026-09-07 on a real defect, **FIXED and closed the same day**; the defect entry at the end of this row is kept in full because it also records a security finding. Every selection site
  (open/locate/stat/dirlist/checksum/write managers and the kYR_have wake in
  `src/net/cms/recv_frame.c`) goes through `brix_cms_answer_selected()`
  (`src/net/proxy/cms_select.c`); `proxy` dispatches through the data-plane
  proxy via `brix_proxy_dispatch_to()` with a per-session pinned target.
  Tests: `test_proxy_mode_serves_data_server_bytes_without_redirect`
  (success), `test_dead_selected_node_is_an_error_not_a_hang` /
  `test_data_server_dying_mid_transfer_is_a_clean_error` (error),
  `test_bogus_response_mode_is_rejected_at_parse` (config-negative),
  `test_redirect_mode_still_redirects_to_the_selected_node` (compat).
  - **REOPENED 2026-09-07 — DEFECT FOUND BY THE SUITE, NOT BY REVIEW.**
    `test_idle_session_repins_to_the_newly_selected_node` fails
    deterministically (3/3 in isolation on a quiet lane; peer session's rhB30
    hunt). The re-pin body `proxy_repin_idle()`
    (`src/net/proxy/forward_relay_dispatch.c:261`) is correct and is compiled
    into the shipped binary — but it is **unreachable from a client's own
    second open**, so the feature this row claims does not work for the case it
    exists to serve.
    Chain: `src/protocols/root/handshake/dispatch.c:98` short-circuits EVERY
    opcode to `brix_proxy_dispatch()` once `ctx->proxy != NULL`; that helper
    calls `brix_proxy_dispatch_to(ctx, c, conf, NULL, 0)` with **host == NULL**
    (`forward_relay_dispatch.c:435`); and `brix_proxy_dispatch_to` gates the
    re-pin on `host != NULL` (:382). So after the first selection pins the
    session, no later open ever reaches `brix_open_manager_dynamic`, no
    registry selection happens, and `proxy_repin_idle` is reachable only from
    the CMS **wake** path (`src/net/cms/recv_frame.c:163`). The client's open
    for a path held by another node is forwarded verbatim to the already-pinned
    upstream, which answers 4003.
    The comment above that gate ("keeps riding that upstream for every later
    opcode") states the opposite of this row's design — two halves of W2.1
    contradicting each other. **The test is right; the implementation is
    incomplete.** Not a flake, not test-ahead-of-binary: the string
    `brix: cms select: re-pinning idle session to %s:%ud` is present in the
    02:38:36 binary, and both source files predate that build.
    **FIXED 2026-09-07** (binary md5 585cc582, 04:44:41). Three files, no new
    sources:
      - `handshake/dispatch.c` — new static `dispatch_defer_to_manager()`; the
        forwarding gate is now
        `(conf->proxy.enable || ctx->proxy != NULL) && ctx->login.auth_done &&
        !dispatch_defer_to_manager(conf, ctx)`. A **selection**-pinned session
        (`ctx->proxy` set while `conf->proxy.enable` is off) whose upstream is
        movable falls through to the normal dispatchers, so the manager runs
        again and `brix_cms_answer_selected()` re-pins through
        `brix_proxy_dispatch_to(host, port)`. A statically configured proxy has
        no manager to fall through to and is explicitly excluded — its
        behaviour is byte-for-byte unchanged.
      - `net/proxy/forward_relay_dispatch.c` — new exported
        `brix_proxy_session_may_reselect()` = `state == XRD_PX_IDLE &&
        !proxy_has_open_handles()`. With a handle open (or a request in flight)
        the predicate is false and the session keeps its node: one upstream per
        session survives the change. Same file: the comment and `if` that a
        linter had collapsed onto one line at :390 put back on two, by Edit.
      - `net/proxy/proxy.h` — the declaration.
    No opcode allowlist was needed. Any opcode reaching this gate with no open
    handle is either path-carrying (the manager can select on it) or a handle
    operation that is already invalid, so "the pin is movable" is by itself the
    correct and complete predicate.
    **DESIGN DELTA, deliberate.** On a registry MISS the manager now declines
    and the request falls to the gateway's own resolve — it is no longer
    forwarded blind to whatever node the session happens to be riding. The
    registry, not a stale pin, is the authority on what a session may reach.
    **SECURITY FINDING (this is why the delta matters).** The old blind forward
    was an information disclosure, not merely a wrong answer. Proven by running
    the new negative against the preserved pre-fix binary
    (`/tmp/brix-binaries/nginx-35233d03-20260907-0238`): a session pinned to a
    data server by a legitimate selection on `/live` opened
    `/unlisted/secret.bin` — a real file on that server's export under a prefix
    **no CMS node advertises** — and was answered `kXR_ok` with a live handle.
    On the fixed binary the same open is `kXR_error`/4003 and the session
    remains usable. Three tests, all three failing before the fix and passing
    after: `test_idle_session_repins_to_the_newly_selected_node` (success),
    `test_session_with_an_open_file_keeps_its_node` (design — the busy session
    must NOT move), and the new
    `test_unregistered_path_is_not_served_through_a_stale_pin`
    (security-negative). Suite: 11 passed.
  - **RETRACTED (this row's own first draft was wrong).** An earlier revision of
    this bullet claimed the `upstream_fh != 255` clause in
    `proxy_has_open_handles()` (`forward_relay_dispatch.c:231-243`) "has no
    counterpart anywhere in the tree". It does: 255 is the documented
    **open-pending sentinel**, written at `forward_request.c:54`,
    `forward_session_helpers.c:203` and `forward_relay_dispatch.c:416`, and
    specified in `src/net/proxy/README.md:89` and :193. `proxy_has_open_handles()`
    is correct as written and needs no change.
  - **SECOND, REAL DEFECT in the same area — the fh map is one byte wide.**
    `brix_proxy_relay_open_status()` (`forward_relay_response.c:234`) keeps only
    `body[0]` of the upstream's 4-byte `fhandle`, and every translation writes a
    single byte back (`forward_rewrite_helpers.c:298`,
    `forward_relay_response_lazy.c:105`/`:124`). Two consequences, both invisible
    against a brix upstream because `BRIX_MAX_FILES` is 16
    (`src/core/types/tunables.h:225`) so a brix data server never issues a handle
    outside 0..15:
      1. **Sentinel collision.** A non-brix upstream that answers `kXR_open` with
         `fhandle[0] == 0xFF` is stored as 255 — indistinguishable from
         "open pending". `proxy_has_open_handles()` then reports *no* open handle,
         so the idle-only reconnect recovery (`connect_lifecycle.c:111`, `:188`)
         and any re-pin will run **out from under an open file**, breaking the
         one-upstream-per-session invariant this row rests on.
      2. **Truncation.** An upstream handle with any non-zero byte in 1..3 is
         forwarded back as `{byte0,0,0,0}` — a different handle than the server
         issued.
    Scope note: this is a *proxy-to-foreign-xrootd* limitation, not a bug in the
    brix↔brix path W2.1 exercises, and widening `upstream_fh` to the full 4 bytes
    is a change to the wire-translation core rather than to the dispatch gate. It
    is therefore **recorded here and carried as W2.6** rather than folded into the
    dispatch-gate fix, whose test matrix cannot reach it.
- [x] **W2.2 Auth bridging (G3).** By reuse: the dispatch gate requires an
  authenticated session and the upstream identity follows
  `brix_tap_proxy_auth` / `brix_proxy_login_user`. Tests:
  `test_unauthenticated_open_never_reaches_the_data_node` and
  `test_write_open_is_refused_by_the_read_only_data_server` (both
  security-negative: zero connections before auth; the data server, not a
  gateway super-credential, is the write authority).
- [x] **W2.3 CMS-driven upstream pool (G4).** The registry is the pool: nodes
  enter on kYR_login, leave on disconnect, `brix_srv_select*` applies
  health/blacklist, and the session pin follows the selection. Tests:
  `test_idle_session_repins_to_the_newly_selected_node`,
  `test_session_with_an_open_file_keeps_its_node`.
- Design choices and discoveries (pinned above):
  - The relay lives in `src/net/proxy/` (data-plane tap proxy: bootstrap,
    `fh_map`, saved-request replay, `kXR_oksofar` streaming), not in
    `src/net/upstream/` as the G2 sketch assumed — that subsystem is the
    one-shot redirector relay.
  - One upstream per session: the pin is a fixed `pinned_buf[256]`
    (no allocation on re-pin); pinned sessions never use the shared pool.
  - An idle session (no request in flight, no open handle) re-pins to a newly
    selected node; a busy one keeps its upstream and the request rides to the
    pinned node, which answers for itself.
  - In proxy mode `kXR_locate` is answered as the gateway itself
    (`brix_locate_answer_self()`); forwarding it would leak the node address
    and the client would bypass the gateway.
  - The proxy conf defaults merge even with `brix_tap_proxy off`, so a
    proxy-mode manager needs no `brix_tap_proxy` block; a dispatch-gate
    change (`conf->proxy.enable || ctx->proxy != NULL`) routes a pinned
    session's later requests. No new metric family.
  - The upstream-reset block was factored into `brix_proxy_reset_upstream()`
    (idle reconnect + re-pin) to stay under the absolute duplication gate.
- [x] **W2.4 Transparent-upstream GSI and credentialed cache-origin auth.**
  Landed 2026-09-05. Transparent upstream: `src/net/upstream/auth_gsi.c` (new)
  and `bootstrap.c` choosing gsi/ztn from the login advert; directives
  `brix_upstream_x509_proxy` / `brix_upstream_x509_key`
  (`src/protocols/root/stream/directives_net.h`). Three shared kernels so the
  three outbound GSI clients (upstream, cache origin, native TPC) stop cloning
  each other: `src/auth/gsi/cred_load.c` (PEM/key loaders),
  `brix_gsi_verify_peer_leaf` in `src/auth/crypto/gsi_verify.c` (tri-state
  1 verified / 0 failed / -1 could-not-evaluate, so the credentialed peers fail
  closed while TPC keeps its fall-through), and
  `brix_gsi_build_certreq_from_parms` in `src/auth/gsi/gsi_core.c`. The
  cache-origin half already existed (`src/fs/cache/origin_auth_gsi.c`, fed by
  `brix_storage_credential` → `brix_credential { x509_proxy ...; }`); the
  guide that listed it as open was stale, and it now runs on the same kernels.
  Discoveries, each pinned by a named test:
  - *Login-advert blindness* (bug). A real brix or stock server answers
    kXR_login with kXR_ok + 16-byte sessid + `&P=...`, never kXR_authmore; the
    old connector took every kXR_ok as "logged in" and the relayed request
    was refused. `test_kxr_ok_login_advert_starts_the_ztn_exchange`.
  - *Auth-phase body cap* (design). A kXR_auth reply carrying a kXGS_cert is
    far larger than the BRIX_MAX_PATH+256 cap every other reply is held to;
    `src/net/upstream/events.c` widens it to XRD_UP_AUTH_BODY_MAX (64 KiB)
    only while `bs_phase == XRD_UP_BS_AUTH`.
    `test_kxgs_cert_larger_than_the_old_cap_is_read_then_judged` /
    `test_kxgs_cert_above_the_auth_cap_is_refused`.
  - *NULL issuer hash* (latent worker crash). `brix_gsi_build_certreq` took
    `strlen()` of a NULL hash when an advert carried no `ca:` (native TPC
    passed NULL); now an empty hash.
    `test_gsi_is_preferred_and_a_missing_ca_hint_does_not_crash`.
  - *Credential selection* (design). gsi is preferred when advertised and a
    proxy is set; ztn when advertised, or when the advert names nothing
    recognised (bare-authmore origins); an advert naming only
    unix/host/krb5/sss relays unauthenticated for the upstream to judge;
    gsi/ztn advertised with no matching credential aborts naming both
    directives. `test_no_credential_fails_closed_naming_both_directives`,
    `test_advert_without_a_supported_protocol_relays_unauthenticated`,
    `test_bare_authmore_still_gets_the_ztn_token`.
  - *Verification opt-out* (design). Without `brix_trusted_ca` the upstream
    leaf is not verified and one WARN per handshake says so, mirroring the
    cache origin. `test_without_trusted_ca_the_leaf_is_unverified_but_warned`.
  - *The server-level anchor never reaches the xroot origin leg* (discovery,
    2026-09-07). `brix_trusted_ca` is stream-level and IS read on other
    outbound legs (TPC outbound TLS `src/tpc/outbound/tls.c:56`, the Pelican
    origin `src/fs/cache/origin/pelican_register.c:286`), but the cache→origin
    leg runs on a SYNTHETIC srv_conf whose trust store is built only from the
    credential block's own `ca_dir`: `vfs_backend_config.c:298-301` →
    `vfs_backend_registry_source.c:163` → `sd_xroot.c:411-443`, which returns
    early on an empty one. Writing the anchor at server level next to
    `brix_storage_credential` therefore arms nothing and warns nobody — and
    this suite fell for exactly that: its own rogue-anchor negative ran with
    verification switched off, asserting only that the cache accepts
    connections. Now `test_brix_trusted_ca_does_not_anchor_the_outbound_origin_leg`
    holds the foot-gun still while the two real rows carry `ca_dir` inside the
    credential. Corollary, not exercised here (this suite has no TLS origin;
    found by the phase-116 session): the same early return also skips
    `sd_xroot.c:426-431`, so `synth->common.trusted_ca` stays empty and the
    root:// TLS upgrade falls back to the system CA bundle — one
    misconfiguration, two verification surfaces.
  - *A cold cache answers `kXR_open` before contacting the origin* (discovery,
    2026-09-07). The miss is filled LAZILY, so an open-only negative passes on
    a cache with a rogue anchor, on a cache with a broken origin, and on a
    cache with no verification at all. Every negative in the suite now drives a
    read; the trap is written into `_open_then_read`'s docstring so it cannot
    be reintroduced.
  - *Four peer-verify behaviours across three outbound GSI clients* (open
    question, NOT decided here; found with the phase-116 session, which owns it
    with its OP). `src/auth/crypto/gsi_verify.h:87-90` states one contract for
    all three — "each must refuse to agree a session secret with an unverified
    peer" — and the sites disagree with it and with each other:
    `src/net/upstream/auth_gsi.c:70` WARNs and skips on a NULL store;
    `src/fs/cache/origin_auth_gsi.c:127` skips silently but then fails closed
    (`!= 1`, and a missing kXRS_x509 bucket is refused);
    `src/tpc/gsi/gsi_outbound_exchange.c:89-104` skips silently and then falls
    through twice — a missing bucket returns 0 (accepted, :92-96) and only a
    parsed-and-rejected leaf refuses (`== 0`), so an unparseable leaf passes,
    documented at :97-98 as "the historical fall-through"; and
    `sd_xroot.c:438` logs only when a store BUILD fails, never when none was
    attempted. So an operator cannot tell an unverified leg from a verified one
    in the logs, and a TPC destination that simply omits its certificate is
    accepted by a store the operator believes is armed. Not an undiscovered bug
    — an undecided one, since tightening any of it changes who is refused in
    production. This suite only pins today's cache-origin behaviour so a change
    to it is visible.
  Tests: `tests/test_phase115_upstream_gsi.py` (16: a real GSI upstream behind
  six credential-variant fronts, a scripted mock upstream for the advert
  parser / abort paths / cap, three config-parse checks) and
  `tests/test_phase115_cache_origin_gsi.py` (5: fill byte-exact through a GSI
  origin verified against the credential's `ca_dir`, object persisted in the
  store, no-credential fail-closed with the operator hint, a rogue `ca_dir`
  refused before the proxy is presented, and the same rogue anchor written as
  `brix_trusted_ca` ignored on this leg).
  Directive rows: `docs/03-configuration/directives.md` (added by the
  2.0-readiness session on request).
- [x] **W2.5 TLS-upgraded native TPC sources.** Already landed before this
  register opened; the roadmap row was stale. `src/tpc/outbound/tls.c` and
  `src/tpc/outbound/bootstrap.c` drive kXR_gotoTLS on the source leg
  (phase-57 §F5), pinned by `tests/test_audit15h_tpc_gsi_tls.py` (12: TLS+GSI
  cross pull, cleartext destination refused by the TLS face, untrusted source
  chain refused at the TLS layer and at the GSI layer, source hostname bound to
  its certificate, unarmed key refused). `docs/10-reference/xrdhttp-parity-roadmap.md`
  corrected 2026-09-05; no code change.
- Verification: success — a client opens through the gateway in proxy mode
  and bytes flow with no redirect on the wire; error — a selected server that
  dies mid-transfer surfaces as a clean upstream error, not a hang;
  security negative — a gateway identity without write authority on the
  selected server's export is refused there, proving bridging carries
  identity and not a gateway super-credential. All three are the W2.1–W2.3
  tests above; W2.4/W2.5 add their own triples.

- [x] **W2.6 The proxy file-handle map is one byte wide.** Split out of the
  W2.1 defect entry rather than folded into its fix, because W2.1's test matrix
  cannot reach it. **FIXED 2026-09-07.** `brix_proxy_relay_open_status()`
  (`net/proxy/forward_relay_response.c:234`) kept only `body[0]` of the
  upstream's 4-byte `fhandle`, and every translation wrote a single byte back
  (`forward_rewrite_helpers.c:298`, `forward_relay_response_lazy.c:105`/`:124`).
  Against a **non-brix** upstream that cost three things:

  1. an open answered with `fhandle[0] == 0xFF` was stored as the 255
     open-pending sentinel, so `proxy_has_open_handles()` reported no open
     handle and both the idle-only reconnect recovery
     (`connect_lifecycle.c:111`, `:188`) and the W2.1 re-pin would move the
     session out from under an open file;
  2. any handle with a non-zero byte in 1..3 was forwarded back truncated,
     naming a different file than the server issued — two handles sharing
     byte 0 alias, so a read on the second file is relayed with the first
     file's exact handle and an exact-match upstream answers it with the
     first file's bytes;
  3. **found while fixing, not before** — the client-facing rewrite
     unconditionally wrote `body[0..3]` into a buffer of
     `ngx_alloc(dlen + 1)` (`events_read.c:98`), so a `kXR_ok` open answering
     with 1..3 body bytes overran the allocation by up to three bytes. The
     length is chosen by the **upstream**, which on a proxying gateway is a
     remote data server, not the operator.

  Invisible brix↔brix because `BRIX_MAX_FILES` is 16
  (`core/types/tunables.h:225`), which is also why no existing test caught any
  of the three.

  **Fix.** State and value are now separate fields: `fh_map[i].upstream_fh`
  is a `u_char[4]` holding the raw handle and `fh_map[i].fh_state` is one of
  `BRIX_PROXY_FH_FREE`/`_PENDING`/`_BOUND` (`proxy_internal.h`), so "pending"
  no longer lives inside the handle's own value space. Two `ngx_inline`
  helpers own every access — `brix_proxy_fh_bind()` (zero-pads a short body
  instead of reading past it) and `brix_proxy_fh_put()` (writes all four
  bytes) — and the new `proxy_relay_open_local_fh()` clamps the client-facing
  rewrite to `dlen` and releases the slot when `dlen < 4`, so a handle-less
  open is refused by `proxy_translate_fh()` rather than guessed. The rename
  from `int upstream_fh` was deliberate: it made the compiler enumerate all 21
  call sites across nine files (`forward_request.c`,
  `forward_session_helpers.c`, `forward_relay_dispatch.c`,
  `forward_relay_response.c`, `forward_relay_response_lazy.c`,
  `forward_fh_translate.c`, `forward_rewrite_helpers.c`,
  `connect_lifecycle.c`, `proxy_internal.h`) rather than leaving one to be
  found at run time; `src/net/proxy/README.md` loses its six references to the
  255 sentinel.

  **Tests** — `tests/test_phase115_proxy_fhandle_width.py`, six cases over a
  new `_FhServer` (an upstream that issues **scripted** handles a brix server
  never would and matches reads on all four bytes, which is what the wire
  protocol requires of a client): `test_upstream_fhandle_round_trips_all_four_bytes`
  (success), `test_handles_differing_outside_byte_zero_do_not_alias` and
  `test_handle_starting_ff_still_holds_the_session_on_its_node`
  (security-negatives for findings 2 and 1), and
  `test_short_open_response_is_refused_not_guessed[1|2|3]` (finding 3).
  All six are a REGRESSION WITNESS, not just coverage: 6/6 fail on the
  pre-fix binary (md5 585cc582…, 2026-09-07 04:44) and 6/6 pass on the fixed
  one (5d2f7a1d…, 05:19). Finding 2 reproduced exactly as predicted there —
  `assert b'the file the client opened first\n' != b'the file the client
  opened first\n'`, i.e. the read on the SECOND handle was answered with the
  FIRST file's bytes.

  Unrelated but landed in the same edit, because `check_duplication` went red
  on it: `tier_parse_one_arg` in `src/fs/tier/tier_config_args.c` was five
  cloned dispatch `if`s plus a cloned `mode=`/`prot=` one-letter validator.
  Both are now one `static const tier_arg_kw_t tier_arg_kws[]` table and one
  `tier_ftp_param_letter()` helper. This moved `nearline` off a hand-written
  exact-length compare onto the shared `tier_arg_is()` matcher, whose
  non-`key=` branch was deliberately loose for its only previous caller
  (`verify_pages`, which validates its own tail) — so the matcher's flag
  became a three-value `tier_arg_shape_e` rather than a bool, and three new
  `nginx -t` negatives (`nearline-suffix-typo`, `nearline-valued`,
  `nearline-truncated` in `tests/test_phase115_pgread_verify_parse.py`) pin
  the shape the table must keep. **No pre-existing defect here**: an earlier
  draft of this paragraph claimed `nearlineX` was silently accepted before
  the dedup; the preserved 02:38 binary refuses it with the same message the
  new one does, so that claim is retracted.

### W3 — Tape and space parity

- [x] **W3.1 OssArc dataset→zip aggregation** (parity audit §3.5). Landed
  2026-09-06. The synchronous seal became the 2.0 F3 backup queue on
  2026-09-08 (`sd_frm_arc_seal.c`, `archive` stage-engine kind; see
  `docs/10-reference/release-2.0-readiness.md`). `tape://<adapter>/<base>?arc=<depth>` (1..8; the same query on a
  tier store URL) wraps whichever MSS adapter the URL selects in the dataset
  archiver decorator `src/fs/backend/frm/sd_frm_arc.c` (+ `sd_frm_arc_store.c`
  sidecar index and compose/extract, `sd_frm_arc.h`, `sd_frm_arc_internal.h`),
  selected by `frm_select_arc_decorator` in `sd_frm_adapter.c` after the
  lib→exec→stub ladder; `brix_sd_frm_create_opts` / `brix_sd_frm_parse_query`
  in `sd_frm.h` carry the option from both parsers (`vfs_tape_query` in
  `src/fs/vfs/vfs_backend_config_ceph.c`, `tier_split_tape_query` in
  `src/fs/tier/tier_config.c`; `tape_arc_depth` on the registry entry). Design
  choices, each pinned by a test: a dataset is the first `depth` path
  components; members' per-key migrate is deferred (they stay in the online
  buffer, the purge engine's `on_tape` sees them as un-migrated) until the
  completion marker `.brix-dataset-complete` is written, which packs every
  regular file below the dataset into ONE **stored** ZIP `<ds>.brixarc.zip`
  (`src/fs/backend/frm/frm_zip.c`, a ZIP32 writer/reader over the existing
  `brix_crc32_ieee` — stored-only so `unzip`/`zipfile` and any tape tool open
  it; symlinks/specials skipped), migrates it through the inner adapter, writes
  a sidecar index `<base>/.arcidx/<ds>.idx` (name/size/lfh_off/crc, sorted) and
  then migrates the marker; stat/dirlist of a sealed dataset answer from the
  sidecar with no recall; a member read recalls the archive and extracts that
  member only, rebuilding a missing sidecar; a member absent from its archive is
  `ENOENT` → kXR_NotFound (the `frm_ensure_online` recall-begin failure now
  preserves ENOENT instead of flattening to EIO); a sealed dataset refuses new
  members (EPERM), a marker republish (EEXIST) and the reserved `*.brixarc.zip`
  key (EINVAL); member names are validated on index and extract (no `..`, no
  absolute, no control bytes) — unsafe names are skipped and counted in a WARN,
  never created. Tests: `tests/test_phase115_tape_arc.py` (15: seal → one
  archive + sidecar + marker migrate + plain-key per-file migrate + dirlist +
  byte-exact recall; zipfile-written archive interop; missing member NotFound;
  6 refused + 1 accepted `nginx -t` queries on `brix_storage_backend` and the
  tier-grammar refusal on `brix_stage_store`; crafted escaping names; sealed
  immutability with byte-identical tape objects; purge engine spares unsealed
  members then releases them once sealed; the `frm_zip_unittest.c` C checks
  (59) compiled and run). Lifecycle slots `lc-p115-arc`, `lc-p115-arc-purge`
  (ladder +2). Peer-owned docs (`directives.md`, `quick-reference.md`, parity
  audit §3.5 row) requested from the release-readiness session on 2026-09-06.
- **W3.1 write-path burndown** (2026-09-06). Building the archiver's own tests
  walked the whole tape write path and turned up defects that had nothing to do
  with archives; each is fixed and pinned in
  `tests/test_phase115_tape_recall_gate.py` (11) or `test_phase115_tape_arc.py`.
  (a) **Residency inversion** — the adapter's OFFLINE verdict was passed
  through as the storage driver's OFFLINE, inverting the enum, so a nearline
  file read as online and vice versa. (b) **A dead stage kick** — the recall
  path built a stage request the engine never consumed, and (c) an **async
  waiter that was never delivered** on the cross-worker arm; (d) `kXR_wait`
  retries **duplicated the durable stage record** instead of joining it.
  (e) The driver advertised `CAP_RANDOM_WRITE` it does not have, so a seek-write
  reached a driver that can only append. (f) `brix_stage_store` was inert
  without `brix_stage on`, silently. (g) The tier and backend parsers spelled
  the tape URL query differently. (h) The ABSENT publish precondition was
  evaluated against the writer's own buffer, so a key that reached tape mid-
  upload was overwritten — now `frm_commit_precond` consults the adapter's
  `on_tape`. (i) `close`/`sync` mapped every driver failure to a blanket
  `kXR_IOError`, and open mapped `EPERM`/`EINVAL` the same way — both now go
  through `brix_kxr_from_errno`. (j) **Security:** `brix_vfs_staged_abort` never
  reached the driver's `staged_abort` slot, so a refused or disconnected
  writer's bytes stayed on tape and a truncated upload became a live object;
  the abort now propagates and `test_disconnected_upload_leaves_no_object`
  pins it. The archiver itself keeps two documented limitations: a deferred
  member's `MATCH_*` publish precondition is shadowed by the dataset barrier,
  and `arc_sync_publish` lives in `sd_frm_arc_store.c` only for the 600-line
  file cap.
- [x] **W3.2 Tape-buffer purge engine** (§3.4). Landed 2026-09-05. The online
  buffer behind a `tape://` tier (`<base>/.online`) now has an eviction policy
  of its own: `src/fs/backend/frm/sd_frm_purge.c` (new) runs one LRU pass per
  `brix_frm_purge_interval` on worker 0, paced by
  `src/core/config/process_frm_purge.c` (new, armed from the per-server init
  ladder), with two arms — the filesystem watermark pair
  `brix_frm_purge_watermark` (accepted-only since phase 64, now live) and the
  new owned-bytes cap `brix_frm_purge_max_bytes <size>`
  (`src/protocols/root/stream/directives_net.h`, `off_t purge_max_bytes` in
  `brix_frm_conf_t`). Design choices, each pinned by a test: a copy is released
  only when the adapter's new `on_tape` vtable slot (`brix_mss_adapter_t`; stub
  = tape-path stat, exec/lib = the `exists` verb) confirms a durable copy, so an
  un-migrated online copy is never dropped; a live stage-request record for the
  path (`brix_stage_request_find_by_path`) pins it; copies touched within 30 s
  are skipped; the walk is `nftw(FTW_PHYS|FTW_MOUNT)` — symlinks counted, never
  followed; a non-blocking `flock` on `<online>/.brix-purge.lock` serialises
  passes; purge directives on an export with no `tape://` tier WARN and never
  arm. Books `brix_frm_purge_total` (its HELP no longer says scaffolding) and
  `brix_vfs_evict_bytes_total{driver="frm"}`. The exec/lib adapters' shared
  vtable ops moved verbatim from `sd_frm_stub.c` (at the 600-line cap) to
  `sd_frm_mss_ops.c`. Tests: `tests/test_phase115_tape_purge.py` (9: cap arm
  LRU + pin + young + un-migrated + byte-exact recall of a released copy; idle
  watermark; held lock defers then LRU-releases; no-tier WARN; symlink/tape
  security negative; four `nginx -t` grammar pins) and the `brix_frm_*` grammar
  pin `tests/test_frm_directive_pin.py` extended to the 22nd directive.
  Lifecycle slots `lc-p115-purge-{cap,idle,notier,lock}` (ladder +4).
  Peer-owned docs (`directives.md`, `quick-reference.md`, the 2.0 readiness
  register §(c.1), parity audit §3.4) requested from the release-readiness
  session on 2026-09-05.
- [x] **W3.3 Space groups, cgroup accounting and quota** (§3.1–3.3), including
  the `oss.quota=-1` unlimited sentinel. Landed 2026-09-06.
  `brix_oss_space <group> <prefix> [quota=<size>|quota=-1]` (SRV_CONF,
  repeatable — `src/core/config/space_group_conf.{h,c}` new, declared in
  `src/protocols/root/stream/directives_security.h`, `ngx_array_t *oss_spaces`
  in `src/core/types/srv_conf_fields_auth.h`, inherited by
  `server_conf_merge_security.c`) names a group over an export-relative prefix.
  Design choices, each pinned by a test: **longest prefix wins and only at a
  component boundary**, so `/atlasdata` is not owned by the `/atlas` group and a
  nested `/atlas/deep` group takes its own subtree out of its parent's; the
  export root itself stays the **default group** (`brix_oss_cgroup` /
  `brix_oss_quota`) and is never declarable as a prefix; a group's `quota=-1` is
  the unlimited sentinel — accounting only, and it also **exempts the subtree
  from the export-wide `brix_oss_quota`**, which from here on governs only
  ungrouped paths; group quota is enforced on writes only when
  `brix_oss_quota_enforce on` (the export-wide gate's own rule, kept), refusing
  with `kXR_overQuota`. Usage is a confined `brix_vfs_walk` of the prefix
  (`src/protocols/root/write/write_space_group.{h,c}` new, hooked into
  `brix_write_within_maxsize` in `write.c` **before** the export-wide §3.3 gate)
  summing `st->size`, cached per worker for 5 s
  (`BRIX_SPACE_GROUP_TTL_MS`) with **every admitted write charged to the cached
  figure**, so a burst inside one TTL window cannot overshoot; a failed walk
  fails **open** with one INFO line (a broken accounting walk must not deny
  service), and `NGX_DECLINED` — the prefix directory does not exist yet — is an
  empty group, not an error. `kXR_Qspace` (`src/protocols/root/query/space.c`)
  reports the group that owns the queried path, or the one named by an
  `?oss.cgroup=<name>` selector which wins over the path (the default group is
  selectable by its `brix_oss_cgroup` name); an unknown name is
  `kXR_ArgInvalid`, never a silent fall-back to the export figures.
  `kXR_open` with a create/write intent must name the owning group if it names
  one at all (`brix_open_cgroup_check` in
  `src/protocols/root/read/open_request.c`) — a write open carrying another
  group's name is `kXR_ArgInvalid` *before* the file is created, which is what
  stops a client from charging its bytes to a group it does not write into;
  read opens ignore the selector. The opaque parser gained the general
  `brix_opaque_value()` (`src/protocols/root/path/opaque_validate.{c,h}`) and
  `brix_opaque_asize()` was refactored onto it (same semantics); the group-name
  byte rule is now the shared `brix_oss_space_name_ok()` that
  `brix_conf_set_oss_cgroup` (`module.c`) also uses, so both directives refuse
  exactly the bytes that would break the `oss.*` CGI report grammar.
  Tests: `tests/test_phase115_space_groups.py` (12: longest-prefix ownership and
  the nested-group report; selector by name; unknown selector `kXR_ArgInvalid`;
  group quota governs its prefix while the export quota governs the rest;
  over-quota refusal **inside** the cache TTL and the release once usage is
  re-walked; one group over quota never refuses another; the create-open
  cgroup-name check with four refusals that create no file and four accepted
  forms plus a read open with a bogus name; 10 `nginx -t` grammar refusals and
  the accepted forms). Lifecycle slot `lc-p115-space` (ladder 31008).
  Peer-owned docs (`directives.md`, `quick-reference.md`, the 2.0 readiness
  register, parity audit) landed by the release-readiness session on 2026-09-06.
- Verification: success — a dataset of N small files stages as one archive and
  reads back byte-exact per member; error — an archive member missing on tape
  returns the per-file error, not a whole-dataset failure; security negative —
  a quota-exceeded write on one space group cannot spill into another group's
  allocation.

### W4 — Cache residuals

- [x] **W4.1 Serve-while-filling for whole-file mode** (§4.5); block mode
  already serves partial content. Landed 2026-09-06.
  `brix_cache_serve_while_filling <time>` (default `0` = off, the value is the
  no-progress deadline) makes a cache MISS whose whole-file fill is already in
  flight FOLLOW that fill instead of serialising behind it: the arriving reader
  streams the staged bytes below the fill frontier and is told to retry past it,
  so it starts at the origin's pace rather than paying the full object's
  transfer time before its first byte. New driver
  `src/fs/backend/cache/sd_cache_follow.{c,h}` (registered in the repo-root
  `./config`, so this workstream needs a `./configure` re-run); armed from the
  fill spine (`sd_cache_follow_arm` in `sd_cache_fill.c`) and consumed on the
  miss path (`sd_cache_follow_open` in `cache_open_miss_serve`,
  `sd_cache.c`).

  Design choices, each pinned by a test:

  * **The coordination channel is the filesystem, not SHM.** The filler
    publishes `<local_root><key>.brixfill` holding
    `"<pid> <declared size> <staged path>"`, so followers work across workers
    and across processes with no SHM and no IPC — the same doctrine as the fill
    lock in `fs/cache/lock.c`. It is also what makes the behaviour testable
    without racing anything: the suite plants a marker and reads through it.
  * **Termination is decided from the follower's OWN fd**, the only race-free
    signal: `st_nlink == 0` → the staged file was unlinked → the fill ABORTED →
    `EIO`; the marker is gone → the staged file was renamed → COMMITTED → real
    EOF; otherwise still pumping → `EAGAIN`. That ordering is a hard constraint
    on the spine: commit (rename) BEFORE withdrawing the marker, and unlink the
    staged file BEFORE withdrawing it on an abort (`sd_cache_follow_withdraw`).
  * **DISCOVERY — a staged file's `st_size` is the frontier, not its length.**
    The phase-107 C5 admission reserve (`sd_posix_reserve`) claims blocks with
    `fallocate(FALLOC_FL_KEEP_SIZE)`, which never moves `st_size`. A follower
    that reported `st_size` from `fstat` would tell the client the object is
    short and the client would stop reading at the frontier — so the source's
    declared size is carried in the marker and reported instead, and a frontier
    that reaches it is EOF without waiting for the commit.
  * **A filler that dies without withdrawing is bounded, not waited on.** The
    marker outlives the process that wrote it, so "marker present" can never
    mean "fill alive"; the follower fails `ETIMEDOUT` once its own frontier has
    not moved for the configured deadline.
  * **`caps == 0` on the follower driver**, so `brix_sd_fd()` declines and no
    sendfile span is ever built over a file that is still growing.
  * **Compat layer — one shared read-side errno funnel.** `EAGAIN` is not a
    failure on a read path, so `brix_read_io_error()` (`read.h`/`read.c`) turns
    it into `kXR_wait(BRIX_FILL_WAIT_SECS)` and everything else into today's
    `kXR_IOError` + `strerror()`. Every serve strategy that can see the
    follower's errno now routes through it — buffered, offloaded, AIO
    (`reads.c`, `pgreads.c`, `aio/readv.c`, which gained an `io_errno` field so
    the completion can tell the two apart), compressed, and the three windowed
    trains — and `BRIX_OP_ERR` is no longer counted for a retry. A bare
    `strerror(0)` on an AIO site whose errno was unset would have printed
    "Success" on a `kXR_IOError`; the funnel reports `EIO` there instead.
  * **DISCOVERY — a windowed read cannot be waited on once it has sent a
    frame.** After a `kXR_oksofar`/`kXR_PartialResult` frame the response has
    already promised bytes, so a `kXR_wait` would be consumed as file data. A
    new `win_sent:1` bit in `brix_ctx_rd_t` splits the two cases: before the
    first frame → `kXR_wait`; after it → terminate the train as a legal SHORT
    read (`kXR_read` may return fewer bytes than asked and the client
    re-reads). The readv window keeps its existing abort instead, because a
    readv body advertises its full length in the outer header and cannot be
    shortened.
  * **SECURITY — only an unverified fill is followable.** Under any
    `brix_cache_verify` mode the staged bytes are PROVISIONAL: `cache_fill_verify`
    may still reject them as a digest mismatch or a broken signature chain, by
    which time a follower would already have served them. `arm()` refuses to
    publish, and — defence in depth, since a marker seen under a verify policy
    is stale or planted — `open()` independently refuses to follow one.
  * **SECURITY — the staged path is confined to the cache store.** The marker
    names a file this process opens and streams to a client, so honouring an
    arbitrary path would turn a writable marker into an arbitrary-file read.
    The path must lie under the store's `local_root` at a path-component
    boundary (a prefix SIBLING such as `<store>-evil/x` is refused), which is
    exactly where `brix_staged_open` puts the temp. A marker that does not
    parse is treated as absent rather than guessed at.

  Tests: `tests/test_phase115_serve_while_filling.py` (14 — the store-layout
  pin the plants depend on; the follower serving staged bytes where source and
  staged differ byte-for-byte at equal length; the declared size reported
  through `kXR_open(kXR_retstat)`; bytes below the frontier and `kXR_wait` at
  it; the aborted fill failing closed with `kXR_IOError` instead of a short
  EOF; the no-progress deadline giving up rather than hanging; and four
  security negatives — a verifying export refusing to follow, five malformed
  markers treated as absent, an out-of-store staged path refused, and the
  prefix-sibling refused) plus grammar accept/reject/duplicate in
  `tests/test_cache_directive_parse.py`. Lifecycle slots `lc-cache-swf`,
  `lc-cache-swf-verify` (exclusive ladder +2). User prose added to
  `docs/03-configuration/directives.md`.
- [x] **W4.2 RAM tier** (§3.6, §4.12) — **IMPLEMENTED** as a storage driver,
  `brix_cache_store ram:<size>`. The store is a per-worker heap object table
  (`src/fs/backend/ram/`: `sd_ram.c`, `sd_ram_table.c`, `sd_ram_staged.c`)
  reached only through the cache decorator, so every existing cache behaviour —
  admission, passthrough, only-if-cached, cinfo, staged fills — composes over it
  unchanged.

  * **DESIGN — per worker, not shared memory.** Both stock caches this mirrors
    are per-process, and an SHM variant would need a config-time
    `ngx_shared_memory_add` per export, a variable-size allocator, and a lock on
    the READ path. The directive's size is therefore per worker, which is a
    number an operator will misread (`ram:8g` on 16 workers is 128 GB resident),
    so `sd_ram_init` logs it at NOTICE with `PER WORKER` spelled out.
  * **DESIGN — the store is deliberately OUTSIDE the phase-31 transfer
    budget.** `xfer_heap_in_use` (`src/protocols/root/connection/budget.h`)
    bounds transfer scratch: `brix_budget_admit` defers a read with `kXR_wait`
    once the sum crosses the cap. Folding cache-resident bytes in would make a
    FULL CACHE defer reads — the server would wedge itself exactly when the
    cache was working best. The RAM store carries its own hard cap instead and
    reports occupancy through the driver's `space` slot. The phase-115 register
    line originally said "budgeted by the Phase 31 memory-budget accounting";
    that is the one thing it must not be, and this box is the correction.
  * **DESIGN — a HARD cap, reserved at open.** `brix_sd_ram_staged_open`
    reserves the declared size under the store mutex, so two concurrent fills
    cannot both be told there is room for the same bytes. A fill whose origin
    declared no length outgrows its reservation by design, so
    `brix_sd_ram_ent_grow` re-enters `brix_sd_ram_make_room` per extension.
  * **DISCOVERY — the shared eviction reaper cannot serve a pathless store.**
    `brix_cache_state_root` (`src/fs/cache/paths.c`) returns
    `brix_cstore_local_root()`, which is NULL for a non-local store, so
    `brix_cache_try_evict_lock` fails `EINVAL` and the watermark pass declines —
    correctly: its lock is a lock FILE in a physical cache root, and a
    per-worker store has neither a root nor any business taking a cross-worker
    lock. A hard cap with no eviction is a store that fills once and then
    refuses every fill forever, so the cap and the LRU are ONE mechanism:
    `brix_sd_ram_make_room` walks the MRU-ordered list from the tail, skipping
    open entries (`refs > 1`) so a pass never reports room it has not got.
  * **COMPAT — `brix_cstore_freespace` now falls through to the driver.** Its
    non-LOCAL arm asks the driver's `space` slot and still returns
    `NGX_DECLINED` for a driver without one, so cache occupancy is a real number
    for a RAM store instead of a `statvfs` of a logical root that does not
    exist. It does NOT arm the reaper (see above), and the comment in
    `cstore.c` says so rather than over-claiming.
  * **BUG (mine, caught before it shipped) — the charge was on the wrong
    side.** `brix_sd_ram_unref` originally took a `charged` flag from its caller:
    `detach` passed 1 while an open handle still held a reference (so nothing
    was discounted), and `sd_ram_close` passed `!ent->unlinked`, which is 0 in
    exactly the unlink-while-open case — `st->used` was then over-counted
    forever and the store shrank to nothing over a long run. The charge now
    lives on the entry (`unsigned charged:1`, set by `brix_sd_ram_insert`) and
    only the free that discounts it clears it, so every path discounts exactly
    once.
  * **SECURITY / DURABILITY — a `ram:` store is legal only as the HOT cache.**
    As the write stage it would acknowledge a client PUT into memory that no
    worker restart survives: silent data loss with a success status on the wire.
    As the backend it would be the only copy of every byte. `tier_parse_capacity`
    refuses both by role. Zero is rejected with the malformed sizes — an
    unbounded RAM store is an OOM, not a configuration.
  * **SECURITY — the COLD tier is refused too, one layer up.** Both cache
    stores parse as `BRIX_TIER_CACHE`, so the tier parse cannot tell them apart
    and `brix_cache_cold_store ram:64m` was accepted at first. The cold tier is
    the DEMOTION target: backing it with per-worker memory makes it costlier and
    more volatile than the disk tier demoting into it, and a reload drops the
    demoted copy while the hot store survives. The refusal lives in
    `runtime_server_backend_cache.c`, the only layer that knows hot from cold,
    keyed on `capacity != 0` (the ram driver's signature).
  * **DEGRADE, never fail.** A fill the store cannot fit returns `ENOSPC` from
    `staged_open`; `cache_open_miss_serve` (`sd_cache.c` §16) turns that into a
    plain source read. A full RAM cache is a slow server, never a broken one.
  * **KNOWN LIMIT — the `brix_cache_*` Prometheus families stay silent for a
    RAM store.** `stream_cache_emit_fs_family` renders from a `statvfs` of the
    per-server `cache_root` string; a pathless store has none, so its rows are
    skipped rather than faked. Publishing per-worker occupancy into the shared
    SHM record is new machinery and is not in this wave.

  Tests: `tests/test_phase115_ram_tier.py` (config-parse accept for four size
  spellings; four bad-size rejects incl. `ram:0`; the bare-`ram` no-scheme
  diagnostic; three role refusals — stage, backend, cold; a source assertion
  that no file under `src/fs/backend/ram/` names `xfer_heap_in_use` or
  `brix_budget_*`; and live HTTP against the `ram-cache` instance for fill-then-
  hit, over-cap degrade-to-source, LRU eviction under the cap, `..` refused, and
  a genuine absence answering 404 rather than leaking an `ENOSPC`). Live reads
  are observed by rewriting the ORIGIN bytes in place with size and mtime
  preserved: stale bytes back means the store served them. Fixture: dedicated
  role `ram-cache` on fixed port 18459 (`tests/configs/nginx_ram_cache.conf`),
  NOT a lifecycle-ladder slot — the exclusive lane is a running sum and every
  widening shifts the tail behind it. `SETTINGS_WIDTH` 178 -> 179 and
  `PORT_COUNT` 2325 -> 2326 with it.
  * **Amendment (2026-09-07, release-2.0 readiness audit) — the over-cap
    degrade was red on the HTTP fill path, and the cause was not in this
    driver.** `test_object_larger_than_the_cap_degrades_to_the_source` answered
    504: the offloaded whole-file fill received the store's `ENOSPC`,
    `brix_fill_classify` called it transient, the ladder ran out to
    `ETIMEDOUT`, and the waiter resolver mapped that to 504 (a definitive
    verdict would still have been 502 — only `NGX_OK` re-entered). Fixed in
    the fill spine, not here: `ENOSPC` is the store's definitive refusal
    (`brix_fill_store_refused`, `src/fs/cache/fill_retry.h`), the worker marks
    the request (`fill_refused`) and re-enters every coalesced waiter, the
    re-entered handler declines a second offload and opens with the new
    `BRIX_SD_O_NOFILL` (`brix_vfs_ctx_t.cache_no_fill`), and the decorator
    serves the source after the `only_if_cached`/admission checks, caching
    nothing. `test_phase115_ram_tier.py` 22/22 on the 16:45 binary; the fix's
    own suite is `tests/test_release20_store_refusal_degrade.py` (8). The
    register `docs/10-reference/release-2.0-readiness.md` (a) RAM-caches row
    owns the narrative.
- [x] **W4.3 Per-page origin verification and `uvkeep`** (§4.3) —
  **IMPLEMENTED.** `uvkeep` was already landed (2026-08-10, parity-audit line
  756), so the remaining half was the per-page one: a `verify_pages` store-line
  param on a `root://` backend makes every origin read a `kXR_pgread` whose
  4 KiB pages each carry a CRC32c, checked before the byte reaches the caller
  (`src/fs/cache/origin_pgread.c`, new).

  * **DESIGN — this closes the half `brix_cache_verify` cannot reach.** That
    engine checks a COMPLETED fill against the origin's advertised whole-file
    digest. Two holes follow from its shape: a partial/slice read has no whole
    file to hash, and a digest-less origin offers nothing to compare against.
    Over cleartext `root://`, a plain `kXR_read` then carries NO integrity at
    all — TCP's 16-bit checksum is not a guarantee, and
    `tests/test_fault_proxy_corruption.py` already documents that such a copy
    "WILL silently return corrupt bytes". `verify_pages` is the second axis:
    per-PAGE, per-READ, and therefore live on ranges and on digest-less origins.
  * **DESIGN — a store-line param, not a directive.** `verify_pages` describes
    the LINK to one origin, so it belongs on the line that names the origin,
    beside the existing `nearline` / `credential=` / `block_size=` params
    (`tier_parse_args`). A server-level directive would also have had to answer
    "which of my three backends?" — and the srv_conf cache-field header, the
    stream directive table and the storage merge file are owned by another
    session's wave, so a directive could not have been added honestly on both
    planes in this one.
  * **DESIGN — the bare token means REQUIRE.** An operator who writes
    `verify_pages` is asking for verified bytes; an origin that cannot deliver
    them must say so rather than silently degrade. `verify_pages=best-effort`
    is the explicit opt-in for a federation of mixed-vintage origins, and
    `=require` is the same thing spelled out.
  * **DESIGN — capability, not trial-and-error.** `kXR_suppgrw` (0x00200000) is
    already in the `kXR_protocol` reply every origin sends;
    `origin_bs_protocol` parsed those flags and threw them away. It now records
    them on the connection (`brix_cache_origin_conn_t.srv_flags`), so the read
    path answers "this origin cannot page-read" from the advert instead of
    burning a round trip on a request a pre-5.x origin would answer
    `kXR_InvalidRequest`. Our own server always advertises it
    (`src/protocols/root/session/protocol.c:118`).
  * **COMPAT (the discovered case) — advertise-then-refuse.** An origin may
    advertise `kXR_suppgrw` and still answer `kXR_pgread` with
    `kXR_Unsupported`: an export with paged reads disabled, or a proxy in
    front of one. `BRIX_CACHE_PGREAD_UNSUPPORTED` (-2) is returned for that
    case ONLY while nothing has been written (`rng->got == 0`), sets no task
    error, and is a property of the ORIGIN rather than of the bytes. Under
    `require` it becomes a hard `kXR_Unsupported` refusal; under best-effort
    the verdict is remembered on the OBJECT (`sd_xroot_obj_state.pgread_off`)
    and the range is re-issued as a plain `kXR_read` — so a 4 GiB file costs
    ONE refused request, not one per 1 MiB stride. Per object, not per
    instance: the verdict belongs to the connection it was learned on, and one
    instance serves many concurrent objects with no lock.
  * **SECURITY — a late refusal mid-train is a protocol error, not a
    fallback.** Once pages have been committed, the caller cannot re-read the
    range without double-writing, so an origin that abandons a pgread train
    after delivering bytes is refused ("cache origin abandoned pgread
    mid-train") instead of quietly restarting under a weaker mode.
  * **SECURITY — pages for an unrequested offset are refused.** A frame whose
    `pgr.offset` is not the next byte the client asked for is rejected: honouring
    it would hand the origin a write-anywhere primitive into the caller's
    buffer, since the page train's file offset is what selects the destination.
  * **SECURITY — an empty PARTIAL frame is refused.** A train of
    `kXR_PartialResult` frames carrying no pages makes no progress; a reader
    that simply looped until `kXR_FinalResult` would hold a thread-pool worker
    forever. One empty partial frame ends the read.
  * **DESIGN — the parse refuses where the param could only lie.** It is
    accepted on `brix_storage_backend` with the `xroot` driver and nowhere
    else: on a posix/s3/http store there is no per-page checksum to ask for,
    and a cache/stage tier is where verified bytes LAND, not the link they
    arrive over. Both refusals are `[emerg]` at config time, because the
    failure mode being prevented is an operator who believes bytes are
    verified when nothing verifies them.
  * **BUG (mine, W4.2, found by a peer's fail-fast lane) — `ram:1g` was
    rejected by its own error text.** `tier_parse_capacity` used
    `ngx_parse_size`, which understands only `k`/`m`; the diagnostic it emitted
    suggested "512m, 2g". It now uses `ngx_parse_offset` (adds `g`/`G`, returns
    `off_t`), which is also the right type for a byte capacity.
  * **HOUSEKEEPING — the store-line param parser is its own file now.**
    `verify_pages` pushed `tier_config.c` past the 600-line cap, so the params
    split into `src/fs/tier/tier_config_args.c` (with `tier_internal.h` for the
    two shared operator-error helpers). The split axis is real: `tier_config.c`
    answers "what STORE is this line naming?", the new file answers "what does
    the operator want done with it?".

  Tests: `tests/test_phase115_pgread_verify_parse.py` (`nginx -t` only — eight
  accepts incl. `roots://` and composition with the other params; fifteen
  refusals covering role, driver, every bad value spelling incl. the
  dangerous-looking `verify_pages=off`, near-miss tokens, and a regression row
  for each pre-existing param so the file split cannot have changed one) and
  `tests/test_phase115_pgread_verify.py` (live, against a scriptable origin in
  `tests/_test_phase115_pgread_verify_helpers.py`: byte-exact under both modes
  with the pgread actually issued, a page-verified RANGE read, a control
  proving the default still uses `kXR_read`, a corrupted page refused under
  both modes, `require` failing closed against a non-advertising origin with
  ZERO wasted requests, best-effort serving that same origin, the
  advertise-then-refuse fallback with its ask-once assertion, and the two
  hostile frames above — the empty-partial leg's assertion is the timeout
  itself). The stub speaks the wire directly, so neither suite needs an
  external `xrootd`.
- Verification for W4 as a whole — met: success — a second reader of a filling
  file gets bytes at the origin's pace without waiting for completion (W4.1);
  error — an origin that changes mid-fill invalidates the cached object rather
  than serving a torn file (W4.1); security negative — per-page verification
  fails closed: a page whose CRC32c does not match is never served, and under
  `verify_pages=require` an origin that cannot page-read is refused rather than
  read unverified (W4.3). The original wording of this line ("a client cannot
  read pages the origin has not yet authorised") described an authorisation
  property that per-page verification does not have and was never going to
  have — pgread checks INTEGRITY, not authority; authority is the endpoint
  write check and the typed VFS policy (invariants 3 and 12).

### W5 — gsiftp outbound backend, optional expansions

Production v1 is **landed** (Phase 91, CLOSED 2026-09-03:
`src/fs/backend/gsiftp/`). Remaining scope is exactly the "Optional expansion —
Not scheduled" row of `phase-91-gsiftp-storage-backend.md`:

- [x] **W5.1 MODE E and PROT P** on the data channel — **IMPLEMENTED.** Both
  are store-line params (`mode=e`, `prot=p`) on a `ftp://` / `gsiftp://`
  backend, negotiated once per control session
  (`src/fs/backend/gsiftp/gftp_mode_e.c`, `gftp_dc_tls.c`, new).

  * **DESIGN — a requirement, never a preference.** An origin that refuses
    `MODE E` (504) or `PROT P` (534) fails the transfer. The operator asked for
    a restartable, offset-addressed channel — or for a protected one — and a
    silent fall back to stream mode or to cleartext would leave them with
    neither the property nor any way to tell.
  * **DISCOVERY — `prot=p` cannot be honoured over an anonymous origin, and is
    refused at config time.** `gftp_dc_tls_pin` pins the data peer's leaf DN to
    the CONTROL channel's identity, and an `ftp://` origin never authenticates
    one (`session->peer_dn[0] == '\0'`). The pin is the whole value of PROT P —
    without it the data channel is encrypted to whoever answered — so the
    combination is rejected rather than served unpinned.
  * **BUG FOUND AND FIXED — an EOF block that overpromises hung a worker
    thread.** `gftp_eb_poll` returned 0 when no connection was still live, and
    `gftp_mode_e_receive` loops on `!gftp_eb_complete()`; an origin whose EOF
    block promised more EOD blocks than ever arrived therefore spun a VFS
    worker at 100% CPU with no timeout to end it. One lie about a count, one
    thread, indefinitely. A truncated transfer now ends, as `EPROTO`.
  * **Tests.** `tests/test_phase115_gridftp_mode_e.py` (three WebDAV fronts
    differing only in the store line, so byte-exactness is asserted as a
    DIFFERENTIAL between MODE E and MODE S rather than against the fixture) and
    `tests/test_phase115_gridftp_prot_p.py` (PROT P vs PROT C, plus a fourth
    `ftp://` front proving the refused origin serves that same file happily —
    so the refusal is provably about protection and not a broken lab). The four
    non-conforming block streams — overlap, out-of-window, truncated header,
    short EOD — are driven from a real origin, name-addressed as
    `eb-<fault>-*.bin`, not stubbed.
- [x] **W5.2 ERET** partial-retrieve extension — **IMPLEMENTED.**
  **ESTO: DEFERRED BY DESIGN** (see below). `ERET P <offset> <length> <path>`
  (GFD.020 §5.3) replaces `REST`+`RETR` on the read path
  (`src/fs/backend/gsiftp/gftp_feat.c`, new).

  * **DESIGN — the win is not a round trip, it is the tail.** RFC 959 can only
    say "start here"; the transfer then runs to EOF. `sd_gsiftp_pread` issues a
    BOUNDED read on every read operation, so each ranged read left the origin
    pushing a tail nobody drained while the driver dropped the connection. ERET
    carries the window and the origin stops at its end. On a 256-byte range of
    a 10 GB file that is not a micro-optimisation.
  * **DESIGN — MODE E only, and that is a security rule.** A door that ignores
    the ERET window and answers with the whole file from offset 0 sends bytes
    that are entirely genuine and simply not the part that was asked for. In
    stream mode there is nothing to check them against: the driver would take
    the first 256 bytes off the socket and hand the HEAD of the file to a caller
    that believes it holds bytes 100000..100255, under a `Content-Range` that
    lies. MODE E blocks carry their absolute offset, so `gftp_eb_claim` refuses
    them. ERET is therefore sent only where its answer can be verified.
  * **DISCOVERY — the reply parser was dropping every FEAT reply's payload.**
    A FEAT reply's final line is a bare `211 End`; the features live in the
    CONTINUATION lines, which `gftp_reply_scan` stepped over and discarded. Any
    capability probe built on `session->text` would have found nothing, every
    time, and silently concluded the origin supports no extensions.
    `gftp_reply_t` now reports the continuation span and the session keeps it
    (2 KiB, truncation recorded — truncation can only LOSE a feature, never
    invent one, so the probe still fails safe).
  * **DESIGN — the probe is lazy.** A session lives for exactly ONE
    storage-driver call, so an unconditional FEAT would put a round trip on
    every stat and every listing. It is issued from the retrieve decision and
    nowhere else, pinned by a test that enumerates the callers.
  * **COMPAT — advertised then refused is a real door, and it downgrades.**
    Origins list ERET in FEAT and implement only retrieve-modes this driver
    never sends. A 5xx arrives with the control channel clean and no bytes
    transferred, so the driver falls back — to the POSITIONED `REST`+`RETR`
    path, never to a bare `RETR` that would restart at zero — and clears the
    bit so the session does not ask twice. `550` is excluded: that says the
    PATH is unavailable, not the extension.
  * **DEFERRED BY DESIGN — ESTO has no caller and would ship unreachable.**
    This driver has no partial-write path at all: writes go to a local scratch
    file and are published by one whole-file `STOR` plus a rename
    (`sd_gsiftp_staged.c`), and `gftp_store` takes no offset. Implementing
    `ESTO A` would add a command nothing could emit — the exact defect
    `test_phase115_store_param_reachability.py` was built to catch — so it
    follows the Phase 114 precedent: deferred, with the BOUNDARY pinned.
    `test_phase115_gridftp_eret_static.py` fails if `gftp_store` gains an
    offset or a second caller, so the deferral cannot quietly outlive its
    reason.
  * **Tests.** `tests/test_phase115_gridftp_eret.py` (two fronts with an
    IDENTICAL store line over two origins that differ only in what they
    advertise — ERET is discovered, not configured, so holding the config fixed
    is the only honest way to attribute a difference to it; the origin's own
    command log proves an ERET was actually sent, without which the suite would
    pass unchanged if the feature were disabled) and
    `tests/test_phase115_gridftp_eret_static.py` (12 structural rows: the MODE E
    guard, the lazy probe's caller set, the positioned fallback, the whole-token
    feature match, and the ESTO boundary).
- [x] **W5.3 SPAS** striped data channels — **IMPLEMENTED.**
  **SPOR: DEFERRED BY DESIGN** (see below). `SPAS` (GFD.020 §5.1) opens up to
  `streams=<n>` parallel data connections for one read
  (`src/fs/backend/gsiftp/gftp_spas.c`, new).

  * **DESIGN — `streams=` is a CEILING, and that makes it a different KIND of
    parameter from its two neighbours.** `mode=` and `prot=` say what the bytes
    ARE — how they are framed, whether they are protected — so they may never
    degrade: an origin that refuses them fails the transfer, because serving
    the request another way would be serving something the operator did not ask
    for. `streams=` says how FAST the same, identically framed, identically
    verified bytes arrive. Every way of not striping therefore falls back to
    the single pinned connection and still serves the file: an origin that does
    not advertise SPAS, one that refuses it, one that answers with more stripes
    than the budget, one whose reply will not parse, and one that names an
    address the driver will not dial. This is the ERET precedent (W5.2) applied
    to a resource decision rather than a capability one.
  * **SECURITY — a SPAS reply is a LIST OF ADDRESSES, and it is the only place
    in this protocol where the origin gets to hand the driver more than one.**
    Everywhere else `gftp_dc_open` throws the advertised PASV address away and
    dials the control channel's own pinned numeric peer, so a redirected data
    channel is not expressible. A stripe list re-opens exactly that door: an
    origin that lists `10.0.0.7,…` turns the storage driver into an
    origin-directed port scanner inside the operator's network — the classic
    FTP bounce, with the operator's own egress rules as the only remaining
    control. So every stripe must equal the control peer, and ONE that is not
    abandons the WHOLE reply: no partial dial, nothing opened, fall back to the
    single connection. The cost is that a genuinely MULTI-HOST striped server
    is read over one connection. That is a performance limit and never a
    correctness one, and it is the right side to be wrong on.
  * **DESIGN — the cross-parameter check runs on the whole line, not per
    parameter.** `streams=<n>` above 1 requires `mode=e`, because a striped
    transfer is reassembled from blocks that carry their own offsets and stream
    mode has none. Checking that inside the `streams=` parser would accept
    `streams=4 mode=e` and refuse `mode=e streams=4` — the same configuration,
    accepted or rejected by word order. That is an operator trap, not a rule,
    so `tier_check_ftp_args` runs once the line is parsed.
  * **DISCOVERY — `tier_fail` does not format like nginx.** The first draft of
    that message used `%ud`, which is right everywhere else in this tree and
    wrong here: `tier_fail` reaches C `vsnprintf`, not `ngx_vslprintf`, so
    nginx's width suffix is a literal and the operator was told their config
    said `streams=4d`. A diagnostic that misquotes the operator's own line back
    at them is worse than no diagnostic — they go looking for a typo they did
    not make. Fixed to `%u`, with the reason in a comment at the call site and
    a test that renders the message and reads the number.
  * **COMPAT — truncation means something different to the SPAS reader than to
    the FEAT reader.** Both read the same 2 KiB continuation capture (W5.2).
    For FEAT, a cut line cannot begin a new one, so truncation can only LOSE a
    feature and the probe fails safe on its own. For SPAS it would silently
    DROP STRIPES — and the receiver would then sit waiting for EOD blocks on
    connections nobody ever opened, which is a hang, not a partial success. So
    `gftp_spas.c` refuses a truncated reply outright instead of reading what
    survived. Same buffer, opposite conclusion, recorded at the field.
  * **COMPAT — an over-budget list is refused, not trimmed.** A front saying
    `streams=2` against an origin listing four dials neither four (the peer
    would be overriding a config line's resource decision — every stream is a
    socket pinned by one blocking VFS worker thread for the length of the
    transfer) nor the first two (the origin's other two stripes would hold
    blocks nobody will ever read, and the transfer hangs). The whole attempt is
    abandoned and the refusal is remembered for the session, as ERET's is, so
    the round trip is not spent again on every read.
  * **DEFERRED BY DESIGN — SPOR would make this driver a listener.** `SPOR` is
    the mirror image of `SPAS`: the CLIENT hands the server a list of addresses
    to dial, which requires the driver to bind and accept. It never does — every
    data channel in `src/fs/backend/gsiftp/` is dialled outward from a worker,
    and a listening socket inside an nginx worker is a new inbound surface,
    a new firewall conversation, and a new NAT story for a transfer that
    already works. It follows the ESTO (W5.2) and Phase 114 precedent:
    deferred, with the BOUNDARY pinned —
    `test_phase115_gridftp_spas_static.py::test_the_driver_never_listens` fails
    if any file under that directory grows a `bind(` or `listen(`.
  * **INCIDENT — a new source that is not in `./config` deletes the shared
    binary.** `gftp_spas.c` was written, and its callers wired, before the file
    was added to the repo-root `./config` source list. The link failed on
    `undefined reference to gftp_dc_group_close`, and a failed link REMOVES
    `objs/nginx` — so the fault surfaced as a missing binary in a peer session's
    tree, not as a compile error in this one. Register the source first.
    `test_the_stripe_module_is_registered_in_the_build` now asserts both files
    appear in `./config`, so the failure cannot recur silently.
  * **Tests.** `tests/test_phase115_gridftp_spas_parse.py` (32 rows over the
    `streams=` parser: the accept/reject grid, the driver check ordering ahead
    of the value check, the `GFTP_STREAMS_MAX` bound, and the two rendered
    messages), `tests/test_phase115_gridftp_spas_static.py` (16 structural rows:
    the address check exists and is reachable from the parser, a foreign stripe
    abandons the whole reply, truncation refuses it, over-budget refuses it, the
    refusal is remembered, MODE E confinement, FEAT gating, the single failure
    return in `gftp_dc_group_open` so a future refusal cannot fail a transfer
    over a performance decision, partial-dial cleanup, the never-listens and
    no-SPOR boundaries, and the build registration above), and
    `tests/test_phase115_gridftp_spas.py` (11 live rows over five fronts —
    striped, unstriped control, non-advertising origin, over-budget, and a
    BOUNCE origin advertising `127.0.0.2`; the security negative asserts both
    that the bounce read still returns the right bytes over one connection AND
    that `127.0.0.2` never appears in the error log, since a dial that was
    refused before any socket leaves no connect failure behind).
- [x] **W5.4 Same-origin server copy — IMPLEMENTED.**
  **SSH transport: DEFERRED BY DESIGN** (see below). WebDAV `COPY` between two
  paths of one gsiftp-backed export is now served by the driver
  (`src/fs/backend/gsiftp/sd_gsiftp_copy.c`, new) instead of the client.

  * **DISCOVERY — this was not a slow path, it was an ABSENT one.** The
    driver's `server_copy` slot was NULL, and `brix_vfs_copy_driver` turns a
    NULL slot into `ENOTSUP`, so every `COPY` on a gsiftp export was refused
    outright. A client that wanted `/a` copied to `/b` had to `GET` the whole
    object and `PUT` it back: the bytes crossed its link twice, and the copy
    was only as durable as that one client's connection. The register entry
    said "server copy" as if it were an optimisation of something that worked.
  * **DESIGN — a GATEWAY RELAY, not origin-side zero-copy.** FTP has no
    server-side copy verb at all, so the bytes still move; they just never
    leave the gateway<->origin link. This is the `sd_xroot_copy_body`
    precedent (`src/fs/backend/sd_xroot_ns.c:290`) applied to a second driver,
    and the honest claim is "the client is out of the loop", not "no data
    moved".
  * **DESIGN — one control session does both legs, spilling to a scratch
    file.** FTP is sequential on the control channel, so after the source's
    `226` the same session is idle and ready to store — a second session would
    be a second authentication and a second chance to land the two legs on
    different origin instances behind one name. The legs cannot drive each
    other directly because `gftp_retrieve` PUSHES to a sink while `gftp_store`
    PULLS from a source; joining them would take a thread per copy, which is a
    worse trade than the `tmpfile()` spill the staged-write path already takes
    for every `PUT`.
  * **DISCOVERY — a whole-file copy must stat FIRST, because a zero limit
    reads nothing.** `gftp_retrieve` loops `while (total < g->limit)`, so
    passing 0 for "the whole file" transfers zero bytes and reports success.
    The stat is therefore not a precaution but the mechanism — and it doubles
    as the acceptance test: a bounded read that returns fewer bytes than the
    origin's own stat just reported is a truncation the origin will not report,
    so the size is re-checked after the transfer and the copy fails with `EIO`
    rather than publishing a short file.
  * **DESIGN — publication is STOR-to-temp plus `RNFR`/`RNTO`, reusing the
    staged-write path's own name generator.** A `COPY` that stores straight
    onto an existing destination replaces a whole object with a partial one for
    the length of the transfer and leaves it that way if the transfer fails.
    `sd_gsiftp_temp_path` was made non-static rather than reimplemented: two
    generators publishing into one namespace would be two chances to collide.
    A failed publish deletes its own temp instead of leaving litter only we can
    recognise.
  * **DESIGN — a copy onto its own path is refused with `EINVAL`.** It would
    WORK — scratch, temp, rename over the original — and that is the problem:
    it rewrites a healthy object for no gain, and any failure in the middle
    damages the only copy of a file the caller never asked to modify.
  * **SECURITY — a `COPY` is a mutation of the DESTINATION, so the typed VFS
    mutation policy must refuse it before any FTP command is written.** A
    refusal issued after the source had been pulled would return the same 403
    and leave the same absent destination, while having spent the origin's
    bytes and this gateway's disk on a request policy had already denied. Only
    the origin's command log can tell the two apart, so that is what the
    negative asserts — an empty log slice, not a status code.
  * **DEFERRED — GridFTP-over-SSH (`sshftp://`), and it could not be otherwise
    in this tree.** It needs a per-session child process, and
    `src/fs/xfer/xfer.h` records why no worker may fork: nginx's master
    `SIGCHLD` handler walks every SHM zone as an `ngx_slab_pool_t` and several
    module zones overwrite that header, so reaping ANY worker child SIGSEGVs
    the master. The one sanctioned seam — a double-forked, reparented agent
    shuttling fixed-size request/reply frames, with `on_reply` on the event
    loop and no fd passing — is architecturally mismatched to a blocking
    threadpool driver that needs a session-lifetime bidirectional fd. A
    `socat`/`ssh -L` sidecar cannot substitute either, and for a reason W5.3
    put there on purpose: the data channel dials the control channel's PINNED
    peer, which would be `127.0.0.1` while the origin advertises the storage
    host. The control transport must terminate ON the storage host, which is
    what SSH transport means and what this driver cannot start. Same shape as
    W5.2's ESTO, W5.3's SPOR and phase 114's credential reaper: deferred, with
    the boundary pinned by tests rather than by memory.
  * Tests: `tests/test_phase115_gsiftp_server_copy_static.py` (14 structural
    rows: both halves of the vtable wiring — a capability bit without a pointer
    dereferences NULL and a pointer without the bit is never reached — the
    build registration, credential forwarding, atomic publication and its
    single shared name generator, temp cleanup, the post-transfer size check,
    stat-before-`tmpfile`, the same-path refusal, that the copy opens no
    connection or name lookup of its own, that both legs share one session, and
    the SSH boundary: no `fork`/`exec`/`posix_spawn`/`system` and no `sshftp`
    scheme anywhere in the driver, plus a row that FAILS if `xfer.h` ever stops
    documenting the SIGCHLD hazard the deferral cites) and
    `tests/test_phase115_gsiftp_server_copy.py` (12 live rows over three fronts
    on ONE origin — read/write, the same export under `brix_read_only on`, and
    a second export rooted a directory deeper so "same origin" is tested as the
    driver sees it rather than as "same hostname"; byte-exactness is asserted
    together with the source surviving, because a copy implemented as a rename
    would satisfy the first alone and this driver already has a rename).
- [x] **W5.5 Live-lab lane — DELIVERED, AND IT CANNOT RUN HERE.** The
  `gridftp-outbound` scenario (`k8s-tests/labtools/lab_suite.py`, chart
  `k8s-tests/charts/gridftp-interop` + role config
  `k8s-tests/charts/topology-role/configs/gridftp_outbound.conf`, suite
  `k8s-tests/remote-suite/tests/test_gridftp_outbound_interop.py`) points brix
  at a REAL Globus or dCache door. It is off by default and stays off in every
  lane in this repository, because no such door is redistributable.

  * **DESIGN — this lane is the INVERSE of the `gridftp` one, and that is its
    whole point.** Everything W5.1–W5.4 proved was proved against
    `brix_suite/servers/ftp_origin_server.py`, which was written from the same
    reading of GFD.020 as the driver it tests: a shared misreading passes both
    sides. Here the reference implementation is the thing under test and brix
    is the client, so MODE E, PROT P, SPAS striping and same-origin COPY meet a
    server nobody in this repository wrote.
  * **DESIGN — four WebDAV fronts over ONE door, differing only in the store
    line** (`plain` · `mode=e` · `mode=e prot=p` · `mode=e streams=n`), one
    export, one credential, one thread pool. Any difference between the fronts
    is then attributable to the data-channel parameters and not to the door,
    the path or the proxy. `plain` is the control: a door that fails there is
    unreachable or broken, and the other three fronts' failures mean nothing
    until it passes.
  * **DISCOVERY — the `prot=p` front cannot be rendered for a cleartext door.**
    `prot=p` on `ftp://` is refused at `nginx -t`, and rightly: the value of
    PROT P is the DN pin, and an anonymous control channel authenticates no
    identity to pin against. Rendered unconditionally it would not fail one
    cell — it would fail the config parse and take all four fronts down with
    it, so the front (and the `brix_credential` block) sits behind
    `{{- if eq $door.scheme "gsiftp" }}` and an `ftp://` door gets a
    three-front lane.
  * **DESIGN — no door is ever defaulted; the scenario REFUSES.**
    `_outbound_door()` raises `SystemExit` naming `BRIX_OUTBOUND_DOOR` rather
    than falling back to a placeholder host, and the values ship `host: ""`.
    A lane pointed at a placeholder deploys, fails to connect, skips every cell
    and exits 0 — indistinguishable from a lane that ran and passed. Same
    reason the suite's own skips are per-test and named rather than a
    module-level collect-time skip.
  * **SECURITY — the credential is the OPERATOR's, never the lab's own PKI.**
    The `gridftp` lane's `pki-bootstrap` Job mints a CA, a host credential and
    two proxies; reusing any of it here would authenticate brix to a CA the
    real door has never heard of, so the lane would go green against our own
    trust anchors while proving nothing about the door's. The outbound role
    takes `auth.extraSecret: outbound-proxy` + `auth.caBundle: outbound-ca`,
    both created by the operator from their own grid credential.
  * **COMPAT — the proxy is read from `/etc/brix/extra`, not from the Secret
    mount.** That path is the role chart's existing init-container `cp -rL`
    into a plain emptyDir, and it is required rather than tidy: the credential
    loader opens proxies `O_NOFOLLOW` and refuses a Secret's `..data/` symlink
    farm, which fails at load time with a permission-shaped error and no hint
    why. Reusing that plumbing is why this lane adds no new mounts.
  * **HONEST STATUS — unrun, and not runnable from this tree.** No cell of
    `test_gridftp_outbound_interop.py` has ever executed: it needs a door, a
    proxy and trust anchors that only a site can supply. What IS verified here
    is the wiring, which is the part that rots silently — see below.
  * Tests: `k8s-tests/pytests/test_gridftp_outbound_wiring.py` (12 static rows
    pinning the three files that describe the same four fronts against each
    other: the runner's `_OUTBOUND_PORTS` against the chart's port list — a
    necessary duplicate, since the test runner is a separate release and can
    only reach a front by number — the positional `index .Values.role.ports N`
    order the config depends on, one `server` block per front, store lines that
    differ ONLY in the data-channel parameters, and the env the suite reads
    against the env the runner exports, because a port exported and never read
    is a silent skip; then the refusal rows — off by default, `condition:
    outbound.enabled`, empty host, `SystemExit` on a missing door, the
    `gsiftp`-only guard around `prot=p` — and the security negatives: no
    `gridftp-pki`/`gridftp-ca-bundle`/`gridftp-jwks` anywhere in the outbound
    subtree, the proxy path under the dereferenced mount, and every front
    naming `brix_storage_credential door` so none of them can fall back to
    whatever the worker's environment happens to hold) plus
    `k8s-tests/pytests/test_remote_suite.py` (the scenario wires all four
    fronts; a missing door raises rather than skips).
- Verification: as Phase 91 — success/error/security-negative per expansion,
  the security negative being that a `PROT P` origin never falls back to
  `PROT C` silently.

### W6 — Erasure coding (research spike)

- [x] **W6.1 XrdEc design spike — CLOSED, verdict NO-GO.** The design is
  `docs/refactor/phase-117-erasure-coding-design-spike.md`; no erasure-coding
  code is proposed. The three questions the register asked, answered:

  * **Placement** — if built, a decorator driver in `src/fs/backend/ec/` holding
    `k+m` children. That shape is not new: `sd_cache` (origin + cache tier) and
    `sd_stage` (origin + staging) are already drivers that dispatch to child
    drivers, so `k+m` children is the same pattern made wider. It is NOT built,
    because the durability is already available one layer down — a Ceph EC pool
    under `sd_ceph`, or an array under the POSIX driver — and building it here
    would move the risk of a silent bad reconstruction out of a decade-old
    implementation and into ours in exchange for no new capability.
  * **Wire signalling** — `kXR_ecRedir` stays unset, and NOT merely for want of
    a backend. The bit tells a client to expect shard redirects and reassemble
    them itself, so it is a client contract: a server whose erasure coding were
    internal must still leave it clear, exactly as a RAID under a POSIX export
    is invisible to the protocol. That makes internal EC a zero-opcode design.
  * **Repair** — the part that decided it. EC without repair is worse than no
    EC, and repair here hits three specific walls: a rebuild is a background
    mutation and phase-105 requires it to carry the export policy BY VALUE (a
    repair on a `brix_read_only` export would be a policy bypass with a
    durability excuse); nothing in this tree owns the cross-node shard
    catalogue such a repair would walk (the FRM queue and the CSI scrubber are
    both per-node); and the Galois-field math cannot run on the event loop, so
    `sd_ec` would be a blocking-threadpool driver with a new `isa-l`
    dependency.
  * **DISCOVERY — the gap tables described the wrong modules, in both
    directions.** `docs/10-reference/protocol-gaps-vs-xrootd.md` had `XrdEc` as
    "Event data catalog / nice-to-have" and `XrdOssCsi` as "Erasure coding / no
    storage layer". `XrdEc` IS the erasure-coding library the same document
    flags ❌ two tables earlier, and `XrdOssCsi` is the checksummed-storage
    integrity layer — which is IMPLEMENTED here (`src/fs/backend/csi_*.c`,
    phase-59, five `brix_csi*` directives). A design started from that table
    would have been designed against the wrong module. Both rows corrected.
  * **DISCOVERY — the existing multi-origin syntax means the inverse of a
    stripe set.** `brix_storage_backend` already takes a pipe-separated list
    (phase-68 T11), with FAILOVER semantics: every endpoint holds the whole
    object. Stripes are "no endpoint holds the whole object and any `k` of
    `k+m` are required", so reusing `|` would give one syntax two incompatible
    meanings — and would let a deployed failover list be read as a stripe set,
    turning a redundant export into an unreadable one. Any EC configuration
    needs its own directive, never a mode flag on that one.
  * Tests: `tests/test_phase117_ec_spike.py` (12 rows — the verdict and its
    reversal trigger are recorded; both corrected gap rows say what the spike
    says and the integrity layer one of them now claims really exists; every
    in-tree artifact the document cites resolves, with a narrow, separately
    tested exemption for the paths it PROPOSES rather than cites; the failover
    pipe it warns about is still failover; and the security negative — no
    `src/` code sets `kXR_ecRedir`, while the client's diagnostic decoder may
    still read it off a foreign server, because advertising a shard layout you
    do not implement and decoding somebody else's are opposite acts).
- Verification: the spike is closed by a reviewed design, with the go/no-go
  recorded here.

### W7 — Client ecosystem

- [x] **W7.1 Preload write, readdir and stdio interposition** (§7.8) — the
  preload library is read-only today. **DONE, and the row was one third
  stale when it was written.**
  - **DISCOVERY — the write half had already landed.** `open(O_WRONLY)` has
    diverted to `remote_open_write` since the §7.8 write wave, with `write`
    and `pwrite` streaming and `close` committing, all covered by
    `tests/test_preload_write.py`. "The preload library is read-only today"
    was true of the version the parity audit read, not of `main`. Only
    readdir and stdio were actually missing; that is what this row delivered.
  - **readdir** — `client/preload/brixposix_dir.c`: `opendir` takes ONE
    `brix_dirlist` snapshot the handle owns, and `readdir`/`readdir64`/
    `readdir_r`/`rewinddir`/`telldir`/`seekdir`/`closedir` walk it. A
    directory that cannot be enumerated is barely accessible: every tool that
    DISCOVERS its inputs, rather than being handed them, was falling through
    to a local path that does not exist.
  - **Design choice — pointer identity, never a magic field.** Every wrapper
    asks a registry "is this `DIR*` one of mine?" by pointer comparison and
    hands anything else to real libc untouched. A magic field would mean
    dereferencing glibc's `DIR`, whose layout is opaque and whose memory the
    shim does not own.
  - **Design choice — `dirfd()` refuses (`-1`/`ENOTSUP`).** There is no kernel
    fd behind a remote listing, and inventing one would send a caller's
    `openat()` into the wrong directory — or, with a shadow fd number, into a
    file.
  - **Compat layer — synthesized `.`/`..` and a guaranteed non-zero `d_ino`.**
    The wire listing carries neither, and a directory without them is not a
    POSIX directory. `d_ino == 0` reads as "deleted" to readdir consumers, so
    an entry the server gave no file id gets a name-derived FNV-1a instead.
  - **Bug found while writing it — a 256-byte name cannot fit a
    `struct dirent`.** `strncpy` into `d_name` would leave no room for the
    NUL. Such an entry is now SKIPPED rather than cropped: a cropped name is a
    *different* name, and the caller would go on to open it.
  - **stdio** — `client/preload/brixposix_stdio.c`: `fopen`/`fopen64` over
    glibc's `fopencookie`, so the shim interposes only the calls that CREATE a
    stream and glibc keeps doing `fread`/`fgets`/`ungetc`/`feof`/`fclose`. No
    fake `FILE*` exists anywhere. The cookie's read/write/seek/close are the
    shim's OWN interposed `read`/`write`/`lseek`/`close`, which is what keeps
    the file short and keeps it correct as the fd layer grows.
  - **Security choice — an unsupported mode REFUSES, it does not fall
    through.** `"a"` (a remote write handle starts at offset 0 and cannot seek
    to end) and any `+` mode (one handle is read OR write) return `ENOTSUP`.
    Falling back to the real `fopen` would open — or create — a LOCAL file
    wearing the remote path's name, and the caller would read bytes that are
    not the ones it asked for. `freopen` refuses a remote target for the
    matching reason: it cannot rebind the caller's existing `FILE*`, and
    returning a different one silently breaks `freopen(p, "r", stdin)`.
  - **Build** — the shim's object list was written out three times; it is now
    one `PRELOAD_OBJS` in `client/Makefile`, because a TU named in only one of
    the two sites either links without dep tracking or is dep-tracked and
    never linked.
  - Tests: `tests/test_preload_dir_stdio.py` (19). Success — enumeration
    through both the C driver and CPython's `listdir`, no zero inode,
    `rewinddir`, `fopen`+`fgets`, `fopen("w")`. Error — `opendir` of a missing
    directory FAILS rather than reporting an empty one (which would turn "you
    cannot see this" into "there is nothing here"), `fopen` of a missing file
    returns NULL with the server's errno. Security negative — a foreign `DIR*`
    and a foreign `FILE*` reach real libc untouched, `dirfd` refuses, and all
    four unsupported fopen modes refuse with no local shadow left behind.
    A C driver is required: CPython's `open()` is its own io stack over
    `os.open` and never calls `fopen`. HONEST STATUS — the three
    `TestPreloadBuildWiring` rows pass now; the sixteen live rows are
    `requires_local_server` and were run only in the final suite pass.
- [x] **W7.2 xrootdfs fan-out and sss identity** (§7.9) — **both halves of the
  audit row implemented.** The audit's words are the whole scope: "xrootdfs has
  no multi-server fan-out / per-user sss identity"
  (`docs/refactor/xrootd-feature-parity-audit-2026-08-04.md:70`). Deliberately
  NOT widened to an `xrdfs ls --cluster` flag <!-- client-flags-allow: named
  only to record the flag this work deliberately does NOT build --> — that is a
  different surface with a different audience, and nothing in the audit asks
  for it; see W7.2b for what is built instead.
  - **W7.2b — cluster-wide readdir.** `client/lib/fs/dirfanout.c` (new,
    `brix_dirlist_all`), reached from the mount with `--cluster-readdir`.
    A CMS manager answers `kXR_dirlist` by REDIRECTING to a single registered
    data server (`src/protocols/root/dirlist/handler.c:92-130`), so a mount
    over a manager enumerates one node's share and every file whose only
    replica lives elsewhere is simply absent — a silent wrong answer, not an
    error. Stock solves this client-side in `XrdFfsPosix_readdirall`. The
    implementation locates the path, keeps only the data-server entries, asks
    each one, and unions the results.
    - **Design choice — the failure policy is deliberately ASYMMETRIC.** A node
      reporting not-found contributes nothing; ANY other per-node failure fails
      the whole call. A caller cannot tell a short listing from a complete one,
      and "the file is missing" is the exact bug this feature exists to remove,
      so a partial union is returned as an error instead. Pinned by
      `TestFanoutFailurePolicy` (three rows: the skip predicate names only the
      two not-found forms, the loop has no `continue`, and the single
      `brix_close` covers every path).
    - **Design choice — managers are never dialed.** `M`/`m` locate entries are
      managers; dialing one re-enters the single-node redirect being worked
      around, and on a multi-manager mesh it can bounce the client. The token
      filter is the only thing preventing it, so the guard also pins that there
      is exactly ONE place nodes enter the table.
    - **Discovery — the CMS locate token has NO space after its two prefix
      bytes** (`Srhost:1094`, not `Sr host:1094`; documented at
      `client/lib/xfer/copy_xcp_sources.c:93-106`). My first unit fixture wrote
      the spaced form, which made `token + 2` empty and silently skipped every
      token — six checks failed and the CODE was right. The corrected shape is
      now the fixture.
    - **Design choice — no second `host:port` splitter.** A naive rsplit on `:`
      turns `Sr[2001:db8::5]:1095` into a connection to the wrong host, so the
      parser composes `root://<token+2>//` and reuses `brix_url_parse`, which
      already knows bracket syntax. Pinned live by the unit's IPv6 section and
      statically by a guard that no `strrchr`/`sscanf`/`atoi` appears beside it.
    - **Bug found and fixed during the build — `-Wformat-truncation` at
      `dirfanout.c:230`.** After inlining, GCC could not prove the node table's
      host terminated within `brix_url.host`. Silencing it would have hidden a
      real truncation-to-the-wrong-host risk; instead a `_Static_assert` pins
      the two widths equal (the `client/lib/auth/sss/sss_keytab.c:94-98`
      precedent) and the copy became a fixed-size `memcpy`. A later widening of
      either side is now a build error.
  - **W7.2a — per-caller sss identity.** `client/apps/fs/xrootdfs_identity.c`
    (new) behind `--sss-identity`: a table keyed on the FUSE caller's uid, each
    slot holding its own pool/mgr logged in under that caller's own login name.
    - **Design choice — refuse, never fall back.** `xfs_ident_get` returns
      `-EMFILE` (table full — an operator capacity limit) or `-EACCES` (this
      identity could not connect), and NEITHER ever yields the mount-wide
      `g_pool`/`g_mgr`. Serving a request under the mount owner's identity is
      the pre-W7.2a behaviour, and it would now be silent: the caller asked to
      be someone else and was not told they weren't.
    - **Design choice — slots are never recycled.** A slot reused for a second
      uid leaves an in-flight request holding a pool that now belongs to
      somebody else. Refcounting is the alternative; not recycling is the
      cheaper correctness. The one destroy on a slot a caller could still be
      told about is the builder's own rollback, which NULLs the pointer and
      marks the slot failed.
    - **Design choice — the connect runs OUTSIDE the table lock**, behind a
      `creating` flag plus a condvar. Building a pool is a TCP connect and an
      auth round trip; holding the mutex across it would let one user's
      blackholed server stall every other user's metadata op on the mount.
    - **Design choice — the DATA plane carries the identity too.**
      `afh_open` (`client/apps/fs/xrootdfs_io.c:101`) resolves it before
      `brix_mgr_pick`. Mapping only metadata would be theatre — the bytes are
      what the caller is being kept away from, and `kXR_open` is where the
      server decides.
    - **The security ceiling, verified on the wire.** `--sss-identity` cannot
      escalate: `sss_map_identity` (`src/auth/sss/auth_request.c:213-230`) sets
      `*user = key->user` and honours the client's NAME TLV only when the key
      carries ANYUSR/ALLUSR (`user=anybody`/`allusers`). A client proposing
      `root` against a `u:svc` keytab is authenticated as `svc`. The client
      half asks; the operator's keytab decides.
    - **Discovery — `BRIX_SSS_OPT_NOIPCK` is parsed and then read nowhere.**
      `src/auth/sss/config.c:75-78` derives it from a keytab name ending in
      `+`, and a repo-wide grep finds no other consumer than the constant's own
      definition and the README. In stock XrdSecsss the `+` suppresses a
      client-IP check; brix performs no such check at all, so the suffix is
      inert. Recorded as a compat note, not a defect, and pinned LIVE (a `+`
      keytab authenticates and resolves the same identity) so the day someone
      wires an IP check up, the row says what used to be true.
    - **Bug found and fixed during the build — two `-Wcomment` warnings.**
      `xrootdfs_internal.h:77` and `xrootdfs_identity.c:250` both wrote
      `*pool/*mgr` inside a block comment, which the compiler read as a nested
      `/*`. Both reworded.
  - **Compat layer — the lifecycle ledger grew by three.** The identity lab
    needs one instance per keytab shape (anybody / fixed user / `+` suffix),
    because a keytab is read at config-parse time and cannot be varied on a
    live server. `LIFECYCLE_SHARED_WIDTH` 1057 -> 1060 and every lane below it
    repacked as the running sum (`PORT_COUNT` 2354 -> 2357); verified by
    `tests/test_port_ladder.py` + `tests/test_fleet_ports.py` (24).
  - Tests: `tests/c/dirfanout_test.c` (20 checks, built by
    `make -C client dirfanout`), `tests/test_phase115_cluster_readdir_fanout.py`
    (10) and `tests/test_phase115_fuse_caller_identity.py` (17).
    Success — a locate reply becomes exactly the set of data servers, bracketed
    IPv6 literals survive, the union is sorted and deduplicated; a proposed name
    becomes the identity and two names on one server are two identities.
    Error — a hostile 4000-char host token is DROPPED rather than truncated, the
    node table clamps at 64 instead of overflowing, a non-not-found node fails
    the whole call; an empty proposed name maps to `nobody` rather than to the
    connecting account, and the two identity failures stay distinguishable.
    Security negative — manager entries are never dialed, no second bracket-blind
    `host:port` splitter appears; a fixed-user keytab IGNORES a proposed `root`,
    no failure path reaches `g_pool`/`g_mgr`, and no function outside the
    builder's rollback and shutdown destroys a live identity's connections.
    HONEST STATUS — the wire behaviour of the fan-out needs a real multi-node
    CMS cluster plus a FUSE mount, which this environment cannot stand up; the
    kernels are therefore exercised directly by the C unit and the wiring around
    them by static guards (the shape W7.3 established). The sss half IS driven
    end-to-end over sockets, because the credential is minted in Python.
  - **Unrelated finding while building — 276 stale `.gcno` files** from a
    09-03 coverage build make `client/Makefile:379-383` add `--coverage` to
    every subsequent link, which is why `.gcda` files appear during test runs
    and why unit binaries print `libgcov profiling error`. Not caused by this
    wave; clearing it costs a full rebuild of a tree shared with other sessions,
    so it was left alone and recorded here instead.
- [x] **W7.3 Fork safety** across the client library (§7.7) — **the engine was
  already landed; this wave found and fixed TWO silent defects in it, and
  pinned both.** `brix_forksafe_register/unregister` + the `pthread_atfork`
  child handler exist; what did not work:
  - **Bug 1 — the registry leaked a slot per re-registration.**
    `brix_forksafe_register` scanned for the first NULL slot only, so a
    connection registered twice (`brix_connect_setup` at `conn.c:271` does
    `memset(c, 0, sizeof(*c))`, which clears `forked` and makes a re-dial on
    the same object legal — and therefore common) consumed a second slot while
    the first still pointed at it. A long-lived process that re-dials fills
    `BRIX_FORKSAFE_MAX` and every connection past it is silently NOT neutered
    in a child. Fixed with `forksafe_slot_for()`, which returns an existing
    match before a free slot; `brix_forksafe_unregister` lost its `break;` so
    it clears *every* slot naming the connection; `forksafe_child` now NULLs
    each slot it neuters and resets `g_fs_overflow`.
  - **Bug 2 — bound substreams were never registered at all.** `brix_bind`
    (`client/lib/net/conn.c`) opens a SECOND live socket to the same server,
    and the high-throughput read path is made of them, but only the primary
    connection was in the registry. A forked child inherited each substream
    un-neutered and its first `brix_send` would interleave frames into the
    parent's data stream — exactly the corruption the primary is protected
    from. `brix_bind` now registers on the far side of `kXR_bind` (the two
    earlier failure paths close the fd themselves) and `brix_streams_close`
    unregisters before the fd goes.
  - **Design choice:** registration belongs to the callers that CREATE a
    connection (`brix_connect`, `brix_connect_no_login`, `brix_bind`), never to
    `brix_bringup`/`brix_bringup_ex`, which are shared bring-up helpers reached
    from both. A guard pins that rule rather than trusting it.
  - **New public helper:** `brix_forksafe_stats(int *live, int *overflow)`
    (`client/lib/_brix_net_ext.h`) — occupancy is otherwise unobservable, and a
    leak that only manifests after a fork is untestable without it.
  - Tests: `tests/c/forksafe_test.c` (4 sections, 12 checks, built by the new
    `make forksafe` target; forks for real, the child `_exit`s a code naming
    the invariant it broke) and `tests/test_client_forksafe_registry.py` (10
    static guards: every `brix_bringup` caller registers, every `brix_bind`
    success path registers, every close path unregisters, no forbidden emitter
    in the child handler). **Both fixes were negative-tested** — reverting
    `forksafe_slot_for` reddens the C re-registration check, removing
    `brix_forksafe_register(sec)` reddens exactly 2 static rows. The Python
    guard blanks C comments before scanning (`_code()`), because forksafe.c's
    own explanatory comments name the very emitters the guard forbids.
- [x] **W7.4 Byte-offset `--continue`** for the xrdcp-style client under
  `client/` — **ALREADY IMPLEMENTED; this register row was stale when written,**
  the same way W7.1's write third was. Verified by reading the code, not by
  grep: `client/lib/xfer/copy_continue.c` (197 lines) implements
  `copy_download_continue()` on the handled? contract, gated from
  `copy_local.c:420`; the destination is written DIRECTLY (no temp+rename) and
  resumes at its current size; the resume loop uses a 1 MiB chunk rather than
  the normal 8 MiB, deliberately, so a mid-flight sever costs less refetch.
  `--continue` is parsed at `apps/copy/xrdcp_parse_transport.c:54` into
  `brix_copy_opts.cont`, aliased as the `continue` policy value
  (`xrdcp_parse.c:152`), documented at `xrdcp.c:105`, and refused in
  combination with `--force`, `--pgrw`/`--compress`, `--zip` and
  `--journal`/`--resume` (`xrdcp_parse_validate.c:52,57,63,216` — four distinct
  diagnostics, not one catch-all). Tests already on disk and carrying the full
  triple: `tests/test_xrdcp_continue.py` — `TestContinueSuccess` (partial
  resumes byte-exact, fresh destination, equal-size no-op),
  `TestContinueErrors` (oversized local refused and left untouched;
  parametrized conflicting-flag matrix), `TestContinueHostile` (a poisoned
  partial cannot plant a full-size file).
  - **HONEST RESIDUAL, and it is not covered by those tests.** The row's error
    verification — "a resumed copy whose remote changed size fails with a clear
    mismatch" — holds only in the SHRINK direction: `start > job->si->size`
    raises `XRDC_EUSAGE` ("larger than the source — refusing to guess",
    `copy_continue.c:160-166`). A remote REPLACED between attempts by a file of
    the same size or larger resumes silently and yields a full-size file that
    is a splice of two generations: old head, new tail. The only thing that
    catches it is the optional `--cksum`. Stock xrdcp has the same weakness, so
    this is a hardening choice rather than a parity gap, and it is recorded
    here instead of being quietly closed. Cheapest honest fix: WARN loudly when
    `--continue` resumes a non-empty partial without `--cksum`. Real fix:
    stamp source size+mtime into an xattr on the partial and refuse on change.
- Verification: success — a forked child continues a parent's open stream
  correctly; error — a resumed copy whose remote changed size fails with a
  clear mismatch; security negative — sss identity under xrootdfs cannot be
  spoofed by an unprivileged local user.

### W8 — Operability polish

- [x] **W8.1 Dashboard first milestone** — **IMPLEMENTED; row stale.** All four
  named sub-items exist in `src/observability/dashboard/`: per-session `state`
  via `dashboard_state_name(conf, slot->state, snap->idle_ms, snap->avg_bps>0)`
  (`api_transfers.c:150`, plus a separate TPC state at :322), `idle_ms` and
  `avg_bps` carried through `api.c`/`api_transfers.c`/`api_snapshot.c`/`page.c`;
  filters are real and client-side over the snapshot — protocol, direction,
  state, free-text search and a five-key sort, all in `filteredRows()`
  (`page.c:96-103`) against the `<select>` toolbar at `page.c:48-51`;
  multi-admin `brix_dashboard_users` is a registered directive
  (`module.c:383`) with a conflict diagnostic against the single-user form
  (`module.c:258`); the JSON payload carries a versioned `"schema"` key
  (`dashboard_json.c:77`). Tests already on disk, eight suites, including the
  row's own shared security negative: `test_audit15c_dashboard_users.py`,
  `test_dashboard_config_anon.py`, `test_audit15q_dashboard_thresholds.py`,
  `test_audit15h_dashboard_session_ttl.py`, `test_dashboard.py`,
  `test_dashboard_files.py`, and the two `test_cmd_dashboard_*` live suites.
- [x] **W8.2 Mid-transfer delegated-token renewal**
  (`docs/10-reference/xrdhttp-parity-roadmap.md`) — **WAS GENUINELY MISSING;
  BUILT.** The audit stands as written: `refresh_token` / `token_refresh` /
  `cred_refresh` had zero occurrences in `src/`, and the only "renew" in the
  tree was an operator-facing error string in `src/auth/crypto/gsi_verify.c:266`
  telling a user to renew an expired proxy. A long pull outlived its own
  credential and there was nothing in the code that could notice.
  - **Split, per the `vfs_policy.c` precedent: a pure kernel and a wire leg.**
    `src/tpc/common/cred_renew.c` is nginx-free and links standalone —
    `brix_tpc_renew_verdict(expires_at, now, lead)` answers
    `NOT_NEEDED` / `DUE` / `EXPIRED`, and `brix_tpc_renew_mode_can_mint()` is
    an exact-match allow-list. Everything unknown — a zero expiry, a
    backwards clock, an unrecognised token mode — answers NOT_NEEDED, so the
    kernel fails toward *doing nothing*, which is the safe direction for a
    transfer already in flight.
  - **The sample point is the one quiet moment on the socket.**
    `tpc_stream_to_dst()` is strictly synchronous — send one `kXR_read`, drain
    it fully, loop — so the top of that loop is the only place an unrelated
    request/response pair can be carried without interleaving into a read
    reply. Renewal is therefore sampled once per `TPC_CHUNK_SIZE` (1 MiB,
    `src/tpc/engine/tpc_internal.h:26`), at `source_stream.c:286`, before the
    chunk's read is sent. In-connection renewal is possible at all because a
    repeat `kXR_auth` is accepted on a live session
    (`brix_handle_auth_inner()`, `src/auth/gsi/auth.c:304`, which gates only on
    `ctx->login.logged_in`).
  - **Four gates stand before any issuer round trip**, in order: a credential
    was actually presented; the pure verdict is DUE or EXPIRED; the token mode
    is one the server may mint for; and the retry window
    (`TPC_RENEW_RETRY_SECS` 60) plus the `cred_renew_off` latch have not
    already given up. A renewal that comes back still inside the lead disables
    itself with a WARN rather than re-minting every chunk — an issuer that
    cannot help must not be asked 3,600 times an hour.
  - Operator surface follows the house `0 = off` rule:
    `brix_tpc_outbound_renew_lead` (seconds, default 0 = never resample) and
    `brix_tpc_outbound_renew_strict` (flag, default 0). Strict refuses the pull
    outright rather than carrying a credential that will die mid-copy.
  - **DISCOVERY — "duplicate" on a directive's FIRST use.** Both new directives
    were declared correctly at every site a reviewer checks (table entry,
    `common.*` field, merge default) and `nginx -t` refused both:
    `"brix_tpc_outbound_renew_lead" directive is duplicate`, on a config
    containing one occurrence. The stock `ngx_conf_set_*_slot` setters use the
    field's own value as the "already set" marker, and `ngx_pcalloc`'s 0 is a
    legitimate value for a `time_t` or `ngx_flag_t` — so a field not parked at
    `NGX_CONF_UNSET` in `brix_shared_conf_init()` looks to its first directive
    exactly like a second one, and defeats the merge default at the same
    time. `shared_conf.h` already carried a comment saying so from phase-105
    W2; nothing enforced it, which is why it was hit again. Now enforced, over
    the whole tree, by the static arm below.
  - Tests: `tests/c/test_tpc_cred_renew.c` (kernel, 15 verdict cases + a
    5,000-tick monotonicity sweep + 15 mint-authority cases, run as the
    `tpc_cred_renew` unit via `tests/cmdscripts/c_simple_units.py`);
    `tests/test_phase115_tpc_cred_renew.py` REN-01..REN-08 (live, two-sided
    `brix_token_clock_skew` splits the source's and destination's view of one
    token, so "the credential died mid-copy" reproduces in under a second) —
    **success** REN-01 renews and the copy is byte-exact, **error** REN-06 a
    failed renewal of an expired credential fails the pull with
    `kXR_AuthFailed` and is not retried every chunk, **security negative**
    REN-07/REN-08 the default mode never re-mints a forwarded credential and
    `renew_strict` refuses rather than minting (both assert zero IdP hits);
    and `tests/test_phase115_conf_unset_sentinel.py` for the discovery —
    **success** the two directives are accepted on first use, **error** a bad
    value is still refused, **security negative** a real duplicate is still
    rejected (the sentinel must not be bought by weakening the duplicate
    check), plus the tree-wide static arm and the http-adopt census.
- [x] **W8.3 CMS admin socket** — **BUILT.** `brix_cms_admin_socket <path>`
  now exposes the cluster plane — `nodes`, `drain <host> <port> [secs]`,
  `undrain`, `forget`, `reset` — over the same unix-socket transport and the
  same 0600 security model as §1.16's session socket.
  - **The reuse was mandatory, so the transport moved rather than being
    copied.** `src/protocols/root/session/admin_socket.c` had accept, the I/O
    vtable a bare `ngx_get_connection()` leaves NULL, newline framing,
    oversized-line refusal, the `NGX_AGAIN`-safe reply flush and the per-worker
    path (`worker 0 -> <path>`, `worker n -> <path>.<n>`) interleaved with the
    root verbs. All of it is now `src/net/admin/admin_unix.{c,h}` (581 -> 358
    lines in the root file), and each plane contributes nothing but a
    `brix_admin_verb_t[]`. New README: `src/net/admin/README.md`.
  - **Verb-match semantics preserved exactly, and now pinned.** A bare verb
    matches the whole line; an operand verb needs name + space + at least one
    operand byte. So `drain` alone is an unknown command and `cont` can never
    be reached by a prefix of `continue`. Prefix matching would let a truncated
    operand mutate the wrong target.
  - **DESIGN CHOICE — the reply arena keeps `buf`/`cap` separate from
    `out`/`len`,** so a long-body verb (root `list`, cms `nodes`) reserves 32
    bytes of header room, fills the body forwards, then repoints `out`
    *backwards* over the finished header instead of memmoving up to 64 KiB.
  - **DESIGN CHOICE — the two planes have different scope, deliberately.**
    Sessions are per-worker, so the session socket answers only for its own
    worker's connections; the node registry is SHM, so the cluster plane is
    node-wide and an operator needs only one worker's socket.
  - **DESIGN CHOICE — `forget` of an absent node answers `ok`, not
    `err not-found`,** because absent IS the state it asks for; `undrain`
    answers `err not-found` because not-drained means the operator's premise
    was wrong. The two wordings are asserted together so neither can be
    "unified" away.
  - **DIVERGENCE, deliberate — the socket's audit lines are NOT hash-chained**
    while the HTTP admin API's are (`api_admin.c::admin_audit()`, P90-28.2).
    The chain makes a *network-reachable* API tamper-evident; a principal who
    can open a 0600 path can rewrite the log itself, so a chain here would
    assert an integrity property the threat model does not support. The fields
    are identical so the two streams read together. (`admin_audit()` is in any
    case not reusable: it needs an `ngx_http_request_t` and the dashboard loc
    conf holding the chain state.)
  - **Tests** — `tests/test_phase115_cms_admin_socket.py`, 44 green over a live
    two-node registry populated by real CMS logins (two `FakeNode`s on the
    ladder-owned `NODE_A_PORT`/`NODE_B_PORT` of `lc-p115-cmsadm-mgr`; seeding
    the SHM table from outside would test the socket against a fiction):
    - success — `test_nodes_lists_the_live_registry_with_the_snapshot_field_names`
      (the wire field names ARE `brix_srv_snapshot_entry_t`'s, so the two cannot
      drift), `test_drain_moves_one_node_and_undrain_puts_it_back` (draining A
      leaves B alone), `test_drain_survives_the_heartbeat_that_follows_it`
      (`brix_srv_update_load()` refreshes but never re-creates or un-drains — a
      drain a 1 s heartbeat silently lifted would be worse than none),
      `test_forget_removes_the_registration`,
      `test_forget_of_an_absent_node_is_ok_not_not_found`.
    - error — `test_every_refusal_has_its_own_wording` (12 cases: `err
      not-found`, `err bad-target` for a missing/non-numeric/out-of-range/empty
      target, the distinct `err bad-seconds` so the operator learns *which*
      half was wrong, `err unknown-command`) and
      `test_a_refusal_does_not_close_the_connection`.
    - security-negative — `test_both_admin_sockets_are_owner_only` (0600 is the
      entire authorization model),
      `test_no_verb_is_reachable_by_a_prefix_or_a_short_spelling` (12 cases,
      each also asserting the registry is unchanged),
      `test_an_oversized_command_line_is_refused_without_answering`
      (`BRIX_ADMIN_CMD_MAX` 512; refused by closing, so a long line cannot be
      split into a second attacker-chosen command),
      `test_root_verbs_are_unknown_on_the_cms_socket` and
      `test_cms_verbs_are_unknown_on_the_root_socket` — the two tables are
      DISJOINT, which the shared transport cannot check for itself because it
      only ever sees the table it was handed.
    - regression — `test_the_root_verb_table_still_answers_after_the_extraction`
      proves the six root verbs are unchanged now that accept/framing/flush
      moved out from under them.
  - Wiring: `./config` (2 sources + 2 headers), `src/core/config/process.c`
    (`brix_cms_admin_socket_init`), `src/protocols/root/stream/module.c`,
    `src/protocols/root/stream/directives_cms.h`, ladder lane
    `lc-p115-cmsadm-mgr` (4 ports, `PORT_COUNT` 2385 -> 2389).
- [x] **W8.4 ManTree negotiation** (§2.9) and the small CMS residuals —
  **CLOSED: §2.9 was implemented-but-under-tested, §2.4 / §2.15 / §2.18 were
  genuinely missing and are now built; §2.10 is deferred by design.**
  - ManTree-style supervisor offload is real: the conf field and its `0 = off`
    default (`src/net/cms/server.h:125`, `server_module.c:97`), the
    login-admission offload decision and the `kYR_try` redirect of a NEW data
    server past the direct cap (`server_module.c:324`,
    `server_recv_frame.c:97,151`, `recv_frame.c:231`), and the least-utilised
    supervisor finder (`src/net/manager/registry.h:204`,
    `registry_policy.c:7`).
  - **RETRACTION.** This row previously read "No test file matches 'mantree'"
    and concluded the half was untested. That was a filename grep reported as a
    coverage fact: `tests/test_cms_parity_wave.py` already carried
    `test_max_direct_offloads_to_supervisor` (success) and
    `test_max_direct_without_supervisor_admits` (the error path). Only the
    security-negative was genuinely absent. It now exists —
    `tests/test_phase115_cms_space_floor.py::test_an_offloaded_login_never_enters_the_registry`
    proves an offloaded node leaves no registry footprint, so the cap cannot be
    walked past by simply logging in again.
  - **§2.4 `cms.space` — the manager parsed the field and threw it away.** The
    node advertises its free-space policy floor in the LOGIN **mSpace** field
    (`brix_cms_min_free`); the manager's parser read it as
    `/* mSpace */ (void) tlv_read_next(p, end);`. It is now kept, and
    `brix_cms_space_enforce on` latches a **sticky** write-block when the live
    fSpace from the kYR_load heartbeat falls under that floor, clearing it only
    at a high-water mark (`brix_cms_space_hwm`) clamped **up** to the node's own
    floor. A blocked node degrades to the §2.3 `over` last-resort tier rather
    than being refused, and the latch is write-only: reads and the §2.5 stage
    selector ignore it. The floor is self-scoped — a node can only remove
    itself, which is what the absurd-floor negative pins.
  - **§2.15 request coalescing** — a locate for a path with a `kYR_state` wave
    already in flight now parks on that wave instead of opening a second one
    (`locate_manager.c` `locate_coalesced()`, keyed off the pending table's
    `probe_path` that §2.6 already maintained; the wake fan-out is
    `src/net/cms/coalesce_wake.c`). Per **worker**, because waking a parked
    session resolves `conn_fd` in the caller's own process, and **never** on
    `kXR_refresh` — refresh means "observe the cluster now", and an answer that
    predates the request would not. Counted by
    `brix_cms_locate_coalesced_total`.
  - **§2.18 M/m locate entry types — a mislabel with a live victim.**
    `brix_srv_locate_all` emitted a hardcoded `'S'` for every entry, so managers
    and supervisors were published to clients as data servers. brix's own `xcp`
    source selector (`client/lib/xfer/copy_xcp_sources.c`) skips `M`/`m`
    entries, so the first thing the mislabel broke was brix dialling its own
    managers as copy sources. Entries now carry the registry role (`M` for
    manager/supervisor, `S` for a data server), lowercased when stale.
  - **Defect found in this row's own work:** `brix_cms_space_enforce` was first
    registered `NGX_CONF_TAKE1` with `ngx_conf_set_flag_slot`. It parsed, but
    it rendered as `<value>` in the generated directive reference and would not
    reject a non-boolean the way every other brix flag does. Corrected to
    `NGX_CONF_FLAG` (`src/protocols/root/stream/directives_cms.h`).
  - **Tests** (success + error + security-negative per change):
    `tests/test_phase115_cms_space_floor.py` (5: the floor moves a write off the
    roomier node, the directive-off control, hysteresis clears at the hwm not
    the floor, an absurd floor removes only its advertiser and only for writes,
    plus the §2.9 offload negative),
    `tests/test_phase115_cms_locate_coalesce.py` (4: one wave serves two
    waiters, the coalescing-off control, `kXR_refresh` never rides someone
    else's wave, a forged `kYR_have` from a non-exporting node wakes neither
    waiter), `tests/test_phase115_cms_locate_entry_types.py` (3: managers and
    supervisors publish as `M`, a stale entry lowercases and is still listed, a
    drained supervisor is never named). `tests/_test_cms_parity_wave_helpers.py`
    gained a payload-identical `min_free` kwarg defaulting to the shipped 100,
    so every pre-existing caller still builds the same LOGIN bytes.
  - **DEFERRED BY DESIGN: meta-manager ClustID/gshr (§2.10)**, still zero
    occurrences in `src/`. It is an architectural tier above the manager, not a
    residual, and it is already carried as a documented divergence in the
    parity audit; folding it into this row would misreport a design decision as
    a gap.
- [x] **W8.5 Signing-table conformance** (§5.2) — **IMPLEMENTED; row stale.**
  The signing policy is a real (opcode × security_level) table, not a flag:
  `brix_sigver_opcode_requires()` (`handshake/sigver.c:149-153`) delegates to
  `brix_gsi_sigver_required(opcode, level)` over levels 0-4 (0=none,
  2=standard: mutations + kXR_open, 3=intense: everything post-login,
  4=pedantic: everything), with session/auth state-machine opcodes excluded by
  construction; `brix_signing_enforce_level()` (:199-208) is the enforcement
  point and consults `ctx->sigver.verified` set by the verify half (:28-35).
  Tests: `test_wlcg_conformance_signing_policy.py` — a conformance suite, which
  is precisely what this row asks for — plus `test_c_signing_policy.py` and
  `test_audit15v_signing_policy.py`.
- [x] **W8.6 SSI client library and ShMap** (§8) — **HALF STALE: the SSI
  SERVER plane is implemented and heavily tested; what is missing is a NATIVE
  client and ShMap.** `src/protocols/ssi/` is a full plane (provider, registry,
  session, service, dispatch, reply, rrinfo, respbuf, deliver, plus the
  `svc_cta` service), gated by `brix_ssi on|off`
  (`src/core/types/srv_conf_fields_net.h:53`), counted by four §7 families
  (`metrics.h:223-226`, `stream_family.c:384-404`) and carried on the file
  handle as an SSI request/response channel (`src/core/types/file.h:271`).
  Nine suites already exercise it (`test_ssi.py`, `_alerts`, `_async`,
  `_config`, `_cta`, `_metrics`, `_multiplex`, `_stream`, `_wire`, plus
  `test_ssi_mutation_policy_guard.py`), and `tests/ssi_client.cc` drives it
  with a **real `libXrdSsi` client**, so the wire is already interop-proven
  against stock. The genuine gap is therefore narrower than the row implied:
  `client/` has ZERO SSI code, so the pure-C suite cannot speak to its own
  server's SSI plane without the C++ stack the suite exists to avoid; and
  **ShMap** (`XrdSsiShMap`) has zero occurrences anywhere in the tree.

  **DELIVERED (2026-09-07), in two halves.**

  *Half 1 — the native SSI client.* `client/lib/protocols/ssi/ssi_client.{c,h}`
  gives the pure-C client an SSI request/response channel, so the suite speaks
  to its own server's SSI plane without the C++ stack it exists to avoid.
  Registered in `client/Makefile`; covered by
  `tests/test_phase115_ssi_client.py` (13 tests).

  *Half 2 — the shared queue, in place of `XrdSsiShMap`.* `XrdSsiShMap` itself
  is **explicitly out of scope** per the 2026-06-30 design spec, and naming it
  was what made this row look larger than it was. The in-tree gap the row
  actually named is the ADR at `svc_cta/README.md:69` — "cross-worker SHM queue
  is deferred" — and that deferral was **not an optimisation left on the table.
  It was a client-visible correctness defect.**

  `cta_service.c:20` held `static brix_cta_queue_t *g_cta_queue`, which is
  per-process. Every worker replayed the same journal, every worker therefore
  set `next_id` to the same `max+1`, and every worker then allocated from its
  own private copy — so **two workers handed out the same request id**. A
  `query` or `cancel` naming id 7 landed on whichever worker the connection
  happened to reach and could act on a different request than the client was
  told about. The shape of that bug lives in what each worker independently
  believed, which stops existing the moment the zone lands, so it is recorded
  here rather than left to be reconstructed from a diff.

  The queue now lives in ONE SHM zone (`svc_cta/cta_shm.{c,h}`), allocated with
  `brix_shm_table_alloc()` per INVARIANT 10 — from the slab pool, never laid
  over `shm.addr`, with the mutex bound to the pool's own lock word so a worker
  dying mid-operation is recovered. It is registered once from a new
  `postconf_cta_queue()` (`src/core/config/postconfiguration.c`) when any
  enabled server block carries `brix_ssi_service cta`. When the zone is absent
  the service answers `CTA_RSP_ERR_CTA` "CTA queue unavailable"; it never falls
  back to a private queue, because that fallback *is* the defect.

  Three consequences, each carrying its own tests:

  - **`brix_cta_queue_t` had to lose every process-local pointer.** It held a
    `void *journal` (a `FILE*`) and each entry a `void *queue` back-pointer,
    both meaningless to a second process. The journal became an `int
    journal_fd` and `cta_queue_transition()` gained the queue as its first
    parameter.
  - **The journal is opened once, in the master, before fork.** Every worker
    inherits one open file description with one shared `O_APPEND` offset, so
    one journal serves the whole set — and each record is emitted with a
    single `write(2)`, since one atomic append per record is what makes that
    sharing safe (stdio promises nothing about buffer boundaries). One zone
    means one journal: where two enabled blocks name different
    `brix_ssi_cta_journal` paths the first non-empty wins and the ignored one
    is named in a config-time WARN — not silent, because an operator would
    otherwise believe the second block was being journalled; not fatal,
    because refusing the config would take down deployments that have run this
    way until now.
  - **The zone lock stays off the executor run.** The executor transitions
    through a new `cta_progress_t::transition` hook bound to
    `brix_cta_shm_transition`, which takes the lock for one transition and
    drops it. A lock held across an archive or retrieve would serialise every
    worker behind one tape operation. `NULL` means "call the queue directly",
    which is what the standalone unit suites want, so `cta_queue.c` stays pure
    C and `cta_queue_unittest.c` still builds with `gcc -Isrc` and no nginx.

  **A security defect found on the way (D1), fixed here.** `journal_append()`
  wrote `owner` and `req.path` RAW into a tab-delimited, newline-terminated
  record grammar. `req.path` is `Notification.file.lpath` — up to 1023
  wire-chosen bytes. A submitted path containing a newline **forged a second
  journal record**, including its `owner` field, which is the principal
  `cta_queue_cancel()` gates on; a tab is the same attack one field narrower.
  The forgery is inert until the next replay, so the request that plants it
  looks unremarkable at the time. Both text fields are now escaped
  (`\\`, `\t`, `\n`, `\r`) and unescaped symmetrically; a record whose
  escaped form will not fit is not written at all; an over-long line is
  discarded WHOLE on replay rather than re-split into a forged one.

  A second discovery on the way: **nothing executed `cta_queue_unittest.c`**,
  and the build command in its own header comment had rotted to the pre-move
  `src/ssi/svc_cta/` paths. Both facts are now tests.

  Tests: `tests/test_phase115_cta_journal.py` (10) — including three that
  neuter `journal_escape`, `journal_unescape` and `journal_line_whole` in a
  copy and assert the C suite reddens, so the negatives are proven capable of
  failing; `tests/test_phase115_cta_shm_queue.py`; and the two standalone C
  suites, `cta_queue_unittest.c` (12 cases) and `cta_exec_unittest.c` (8),
  which now run under the pytest lane rather than being unreachable.

  **Not done, and deliberately:** `XrdSsiShMap` as a general-purpose shared map
  is out of scope per the design spec, and DEFECT CANDIDATE #63 (the CTA
  *executor* selection aliasing across server blocks through
  `g_cta_use_prod`) is a separate documented defect with its own pinning suite
  at `tests/test_audit15aa_default_tokens.py`; W8.6 moved the queue off its
  process global, not the executor.
- [x] **W8.7 BWM / throttle pacing** — **IMPLEMENTED; row stale.** Both
  upstream surfaces exist under `src/net/ratelimit/`, each wired at a real
  admission point rather than left as an engine with no call site (the
  phase-95 lesson this row's neighbours record):
  - **XrdBwm-style reservation** — `reservation.c/.h` (phase-59 W3b): a named
    zone with an aggregate bytes/sec budget, `brix_resv_schedule()` returning a
    handle on grant and `0` when queued, byte-precise `brix_resv_done()` so
    concurrent grants release their own budget. Charged at
    `read/open_resolved_file_finalize.c:178`. Documented limitation, not a
    defect: the budget is per-worker, and the cross-worker SHM upgrade is a
    stated follow-on.
  - **XrdThrottle-style pacing** — `throttle_compat.c/.h` (phase-59 W3a) maps
    the one upstream `throttle.*` semantic BriX enforces (the per-user
    open-files cap) onto the existing leaky-bucket SHM engine, charged on
    `kXR_open` at `read/open_resolved_file_finalize.c:137` and released on
    close/disconnect. Its never-wired siblings were deliberately removed in
    phase-95 and must return WITH their call sites.
  - The general pacing story is broader than either: `ratelimit.h` carries
    request-rate, **bandwidth** (`bw_rate` bytes/s, `bw_excess`) and
    concurrency dimensions over one identity-aware key space, across both the
    stream and HTTP surfaces.
  - Tests: `test_phase92_bwm_reservation.py` (reservation),
    `test_audit15_throttle_open_files.py` (the open-files cap),
    `test_phase25_ratelimit.py` + `_b` + helpers and
    `test_ipv6_admin_ratelimit_metrics.py` + `_b` (the rate/bandwidth engine),
    `test_admin_rate_limit.py` (the admin surface).
- Verification: per sub-item, with the shared security negative that a
  dashboard viewer listed in `brix_dashboard_users` without the admin role
  cannot reach any mutating admin endpoint.

### W9 — Hardening proposals

All from `docs/07-security/advanced-hardening-proposals.md`; each already has a
threat statement there and needs only a phase and a body.

**Four of these five rows were stale when the register was written.** An
evidence audit (2026-09-07, read-only) found W9.1-W9.4 already implemented AND
already covered by tests; W9.5 was the only real remaining work, and it is now
built (exhaustive model checking, not a proof assistant). Each verdict below
was confirmed by reading the implementation, not by a name grep — the first
pass of that audit wrongly called W9.4 dead code because it grepped the wrong
symbol, and wrongly called W9.2 a syntax-only check because it stopped at tier 1.

- [x] **W9.1 seccomp-BPF worker profile** — **IMPLEMENTED.** `src/core/seccomp/`
  (`seccomp_core.c` 423 lines + `seccomp.c` 169, same ngx-free-core split as
  wverify/opaque/negcache). Two modes: AUDIT (`SCMP_ACT_LOG` default, allowlist
  as `SCMP_ACT_ALLOW`, so the steady-state set is observable before it is
  enforced) and ENFORCE (`SCMP_ACT_ERRNO(EPERM)` default — fail-safe — with a
  named-dangerous set at `SCMP_ACT_KILL_PROCESS`). A syscall name this
  build/arch does not know resolves to `__NR_SCMP_ERROR` and is skipped, so one
  table serves every arch. Installed per worker LAST, after every one-shot
  setup, at `src/core/config/process.c:326-333` (`brix_seccomp_install_once`);
  the allowlist is already load-bearing elsewhere (`sd_posix_io.c:130`).
  Tests: `test_seccomp_enforce.py`, `test_seccomp_exec_frm.py`,
  `test_seccomp_tape_stub.py`, `tests/c/test_seccomp.c`. The
  `seccomp-exec-broker-plan.md` Option B broker remains separate and unbuilt —
  that is a different artifact from the worker profile this row names.
- [x] **W9.2 Opaque-CGI schema validation** — **IMPLEMENTED, in two tiers,**
  both in `src/protocols/root/path/opaque_validate.{c,h}` (368 lines), wired
  from `read/open_request.c`. Tier 1 is byte hygiene (§D-2, CWE-88/93/117): a
  256-entry permit table built once from an explicit allow string; the first
  byte outside URL-unreserved + path/authority + percent-encoding + CGI
  structure rejects the request with `kXR_ArgInvalid` *before* any handler
  parses, logs, or splices it into an outbound TPC request. Tier 2 is the
  schema proper — `brix_opaque_schema_check()`, opt-in via `brix_opaque_strict`
  (`opaque_validate.h:45`, `src/fs/path/path.h:318`), which splits on `&` ONLY,
  mirroring stock's rule that `;` is ordinary value content rather than a
  separator. Tests: `test_opaque_strict.py`, `tests/c/test_opaque_schema.c`.
- [x] **W9.3 Protocol downgrade protection** — **IMPLEMENTED; Phase 88 was more
  than a seed.** One pure enforcement expression,
  `brix_tls_gate_refused(mask, caps, is_tls)` (`src/fs/vfs/vfs_secgate.c:105`),
  over the BRIX_TLSREQ_LOGIN/SESSION/DATA/TPC capability mask parsed from the
  `brix_tls_require` grammar. Five real call sites, i.e. every negotiation path
  into an export: the root stream pre-dispatch
  (`handshake/dispatch.c:58` → `policy.c:119-129`), the native-TPC choke point
  (`read/open_tpc.c:227`), the WebDAV dispatcher twice
  (`webdav/dispatch.c:59,76` — the generic gate plus a dedicated TPC gate), and
  the S3 handler (`s3/handler.c:388`); the mask is also advertised as kXR_tls*
  bits at kXR_protocol (`session/protocol.c`), so a conforming client never
  attempts the downgrade in the first place. Tests: `test_tls_require.py`,
  `test_audit15d_tls_require_tpc.py`. **What this row still owes is not code
  but an exhaustive negative matrix** — one refusal case per (entry protocol ×
  capability) cell, so that a future protocol added without a gate reddens.
- [x] **W9.4 Negative-stat backoff** against enumeration — **IMPLEMENTED** as
  `src/core/negcache/` (E-4): a per-principal sliding-window counter of
  missing-path lookups; when a principal's miss rate crosses the threshold
  inside the window the slot arms, and every further miss inside the backoff
  interval is answered `kXR_wait` instead of `kXR_NotFound`. Because the stock
  client answers `kXR_wait` by sleeping and re-sending, every legitimate lookup
  still completes one interval later while a stat-harvest loop is paced to
  roughly one path per interval; clients that rarely miss never arm. Directive
  `brix_negcache_backoff off | <threshold> <window_s>`, 8192-slot cross-worker
  SHM zone, pure core linked directly by `tests/c/test_negcache.c`. **Wired at
  both sites the row implies**, verified by call-site grep on the real symbol
  `brix_negcache_note_miss`: `read/stat.c:346` and `read/locate.c:229`.
  Tests: `test_negcache_backoff.py`, `tests/c/test_negcache.c`.
- [x] **W9.5 Formal ACL verification** of the typed VFS policy kernel
  (`src/fs/vfs/vfs_policy.c`) — **DONE, by exhaustive model checking rather
  than by a proof assistant.** The kernel's inputs are narrow enough that
  "formal" can mean *checked on every input* instead of *argued about*: the
  five properties below each sweep the full 2^32 word of their axis, so the
  result is a decision procedure's answer, not a sample.
  - S1 policy axis: exactly 1 of 4,294,967,296 policy words opens the gate.
  - S2 operation axis: exactly 16 of 4,294,967,296 words are in the operation
    vocabulary — the same 16 labels T4 proves distinct.
  - S3 open-flag axis: 134,217,728 of 4,294,967,296 flag words are provably
    read-only, and no other word is treated as one.
  - S4 form agreement: all five call forms open on the same single word — no
    form is a softer door into the same kernel.
  - S5 derivation: exactly 1 `allow_write` value opens, and 0 values widen the
    verdict beyond what the policy already permitted.
  - Structural arms T1–T4 pin the parts a sweep cannot see: NULL and
    unconfined inputs fail closed *and in that order*, one denial is counted
    per refusal and none per success or malformed input (an audit trail that
    over- or under-counts is its own defect), and the kernel is pure — the
    forward and reverse sweeps agree exactly, so no call leaves state behind
    that changes the next verdict.
  - Tests: `tests/c/vfs_policy_model_test.c` driven by
    `tests/test_phase115_vfs_policy_model.py` — 6 fast structural tests
    (2.1 s) and 13 exhaustive ones marked `slow` (4 m 05 s in-suite, 3 m 02 s
    standalone). **Security negative:** S1/S4/S5 are themselves the negative —
    they assert that every one of the ~4.29 billion words *other than* the
    single opening value is refused, which is the strongest form the CLAUDE.md
    triple can take here.
- Verification: each item ships the CLAUDE.md triple — success, error,
  security negative — and the security negative is the item's reason to exist.

## Rules while this register is open

- Every item keeps the Phase 105 invariant: any new mutation path passes
  `src/fs/vfs/vfs_policy.c` first and answers `EROFS` before any leaf check.
- New `src/` files go in the repo-root `./config`; new `client/` files go in
  `client/Makefile` (the coverage guards `tools/ci/check_config_coverage.py`
  and `tools/ci/check_client_build_coverage.py` enforce this).
- Storage syscalls stay in `src/fs/backend/` (`tools/ci/check_vfs_seam.py`).
- No item is marked `[x]` without its three tests named beside it.

## Harness defects found while verifying this register (2026-09-07)

Ten defects surfaced while verifying this register, every one of them a case of
a run reporting something other than what it tested. They are recorded here
because the register's verification numbers are worthless without them.

The family has one shape: **silence was read as green**. A freeze that had been
released, a key that had been zeroed, a cited file that had never run, a guard
satisfied by a comment, a pin detector that counted the wrong things — none of
them complained, and not complaining was taken for passing. Evidence that a
check EXECUTED is a different claim from evidence that it did not object, and
only the first is worth anything. Two cheap proofs recur below and are the
standard for anything added to this register: a **census** (assert the set that
was actually scanned) and a **deliberate revert** (assert the check reddens when
the defect it exists for is put back).

### §H1 — the run-wide nginx freeze was released by the first lane

`operator_runtime._capture_suite_nginx()` freezes the binary ONCE for the whole
run and publishes it as `TEST_NGINX_BIN`/`NGINX_BIN`, inherited by every lane.
Lane 1's `pytest_sessionfinish` (`conftest_part5._remove_test_root`) then
removed it, so lanes 2..N inherited a dead path; `freeze_nginx()` took its
`not src.exists()` branch, found nothing to validate, and handed the dead path
back, and every server exec failed ENOENT. **Any four-lane `suite` run before
this fix reported only its first lane.** Any pre-2026-09-07 multi-lane number
quoted as authoritative is lane-1-only.

The first fix reproduced the same ENOENT from the other side: it released the
freeze *directory*, and a lane may call `run_suite()` in-process — 
`tests/test_cmd_operator_runtime.py` does, eight times, with a throwaway nginx —
so the nested run deleted the live run's binary. Lane 1 collapsed at 48% with
6508 `FileNotFoundError`s. The rule is therefore: publish the ownership marker
with `setdefault` so a nested run defers to an outer owner, release only the ONE
binary this run's own capture froze, remove the directory only if empty, and
clear the marker only when it names the path just released.

- Fix: `tests/cmdscripts/operator_runtime_part2.py`,
  `tests/conftest_part5.py`, marker single-sourced as
  `live_common.SUITE_OWNS_FROZEN_NGINX`.
- Tests: `tests/test_phase115_suite_freeze_ownership.py` (12), plus a source
  wiring pin so a revert fails loudly rather than silently halving the run.

### §H2 — a crash-truncated signing key was reused as a generated one

The VM takes fatal machine-check panics under full-tier load (three on
2026-09-07: 13:10, 14:35, 14:49; hardware, the operator's). `/tmp` survives the
reboot, so a session inherits its predecessor's `TEST_ROOT`. The 13:10 panic
left `tokens/signing_key.pem`, `signing_key_2.pem` and `signing_key_ec.pem` all
at **zero bytes, mode 0400** — ext4 persisted the rename from `init_keys`'
temp+chmod+`os.replace` sequence but not the data behind it.

`SigningKeyStep` asks `.exists()`, saw three names, skipped regeneration, and
every `make_token.py gen` for the rest of the run died with
`ValueError: Unable to load PEM file ... MalformedFraming`. The fleet came up
with no issuable tokens and the whole WLCG/scitoken surface failed for reasons
unrelated to the code under test — visible only as two `[fleet_prep] ... rc=1`
lines scrolled off the top of the log.

`_missing_sentinels`, whose entire purpose is to stop a bad tree being
snapshotted or accepted as a restore, asked `.exists()` too. A crash-damaged
tree was therefore eligible for the artifact cache, which would have propagated
the damage into every later session and survived deleting `TEST_ROOT`.

- Fix (reuse gate): `_is_usable()` — regular file, non-empty — replaces every
  existence check on a generated artifact; `_is_loadable_pem()` adds the END
  armour and gates the signing key alone. Scoped deliberately: the sentinel
  predicate stays a length test so the short-string fakes other suites write
  (`"cert"`, `"proxy"`) keep meaning what they mean.
- Fix (durability): `utils/make_token.py init_keys()` fsyncs the key body
  before `os.replace` and the directory after, so the file that survives a
  panic is the one that was written. The fsync precedes the chmod, so the key
  still lands at 0400.
- Tests: `tests/test_phase115_crash_truncated_artifacts.py` (20) — success
  (a good key is still reused, no keygen tax), error (zero-length, truncated,
  absent), security negatives (a damaged tree can never be snapshotted; a
  directory is not an artifact; an unreadable key fails closed; the mode stays
  0400; no temp key material is left behind), and a wiring pin.

Reverting both fixes fails exactly 9 of the 20 and passes the rest.

### §H3 — a register row cited a file that had never run

`tests/test_phase115_tpc_cred_renew.py` (W8.2, mid-transfer credential renewal)
builds its lab with `brix_token_clock_skew 3600`. `src/core/config/shared_conf_merge.h`
has rejected anything outside `[0, 300]` with EMERG since phase-105 W8, when the
clamp moved out of webdav's merge so every HTTP protocol enforces it and s3
stopped accepting arbitrary values. So `nginx -t` failed, `lifecycle.start()`
raised, and all **nine** tests ERRORed in the shared fixture on every binary
this tree has ever produced.

The lesson is not the wrong constant. It is that **a file whose every test
errors in setup reports zero failures**: nine ERRORs are not nine reds in a
summary line that counts passed/failed, and the register cited the file as this
row's evidence while it had never once executed. Phase 111's NO-PHANTOM-EVIDENCE
check resolves that a cited test *exists*; it cannot see that the test never
ran. Found 2026-09-07 by a peer session's `-x` fast lane halting on it, not by
this register's own verification.

- Fix: `brix_token_clock_skew 300` — the widest LEGAL grace. `STALE_TTL = -60`
  still sits inside it, so the source-ACCEPTS / destination-EXPIRES
  disagreement the whole lab is built on is unchanged.
- Tests: three static guards in the same file.
  `test_the_lab_skew_is_inside_the_security_clamp` reads the ceiling out of the
  C with a regex rather than hardcoding 300, so a retuned clamp retunes the
  guard instead of pinning a number that used to be true;
  `test_the_clamp_still_refuses_the_value_this_lab_used_to_use` is the security
  negative — relaxing the clamp to accommodate a lab like this one would restore
  the hour-long grace on expired tokens that the unit-confusion clamp exists to
  catch; `test_the_stale_credential_stays_inside_the_corrected_skew` pins the
  premise so a later edit cannot deepen the staleness past the clamp and turn
  every renewal test into a plain auth failure that still looks green-ish.

Reverting the constant to 3600 fails the first guard with `3600 = max([3600])`.

**The general rule, since this is the second instance in a day.** Phase 116's
amendment 15 found `tools/ci/check_dns_seam.py` filtering on `.c`/`.h`, so six
shipped C++ sources under `client/apps/ceph/` were never scanned and the guard
still printed OK. Different mechanism, same shape as §H3: **silence read as
green.** A count of failures proves nothing on its own — it is equally consistent
with "nothing is wrong" and with "nothing was asked". Evidence has to establish
that a check EXECUTED, not merely that it did not complain, and the two cheapest
ways to establish it are a census (assert the set of things scanned, not just the
verdict) and a deliberate revert (assert the check fails when the defect is put
back). Every guard added for §H1–§H3 carries one or both.

### §H4 — a structural guard was satisfied by a comment

`test_phase115_store_param_reachability.py` scraped the store-line param
keywords out of the BODY of `tier_parse_one_arg`, and carried an explicit
anti-vacuity row (`test_every_param_is_routed`) whose whole job was to fail if
that scrape ever came back empty. Both went quiet at once.

The dispatch was later folded from a chain of cloned
`if (tier_arg_is(arg, "verify_pages", ...))` ifs into a one-row-per-param const
table, `tier_arg_kws[]`. Every string literal moved out of the function, so the
scrape returned the empty set — and the guard that exists to catch exactly that
did not fire, because its regex
`tier_parse_one_arg\(.*?\n\{(.*?)\n\}` matched `tier_arg_is`'s doc COMMENT,
which names `tier_parse_one_arg` a hundred lines above the definition, then ran
on to the next `\n{`. The `assert m, "the dispatcher moved"` was satisfied by
prose.

Fixed by anchoring on the table declaration at column 0 (`KW_TABLE_RE`), making
the emptiness check an unconditional assertion rather than a side effect of the
match, and turning the roster into a census — the set of keywords must EQUAL the
seven the file reasons about, so a param added without a row here fails loudly.
Three rows pin the anchor itself: it finds the real table, it refuses a
differently-named one, and a comment mentioning the table cannot satisfy it.
Renaming `tier_arg_kws[]` fails `test_every_param_is_routed`.

Nothing was wrong in `src/`: `streams=`, the seventh param and the one the old
roster never mentioned, is carried end to end (`tier.ftp_streams` →
`e->origin_ftp_streams` → `vfs_backend_registry_gsiftp.c`).

### §H5 — the ESTO deferral was pinned by caller IDENTITY, not by the property

`test_the_write_path_still_has_no_partial_caller` asserted
`callers == {"sd_gsiftp_staged.c"}`. `sd_gsiftp_copy.c` appeared and it went
red — correctly alarmed, but for the wrong reason and with no way to clear
itself: the new caller is `sd_gsiftp_copy_publish`, which STOREs a whole scratch
file to a temp name and RNFR/RNTOs it into place, its source callback preading
sequentially from `written = 0`. Entirely benign.

The deferral rests on a PROPERTY — nothing writes at an offset — and the guard
was checking a proxy for it. `gftp_source_fn` carries no offset argument, so the
only way a caller can write a window is to start its ctx cursor somewhere other
than zero. `test_no_store_caller_streams_from_a_nonzero_offset` now reads that
cursor in every caller; the caller set is kept as a separate REVIEWED census, so
a new caller still stops the build with "review it, then add it here". Setting
`source.written = 4096` in `sd_gsiftp_copy.c` fails the property row.

### §H6 — a mid-body integrity refusal has no status code to send

Six `test_phase115_pgread_verify.py` rows failed on
`ConnectionError: RemoteDisconnected` raised out of `requests.get`, before the
assertion they were written to make. The server is right and the test was wrong.

A per-page CRC32c mismatch is discovered inside `sd_xroot_pread`, which returns
`-1`/`EIO`. By then the response headers — and a Content-Length taken from the
origin stat — are long since committed, so nginx aborts the connection. That is
not a degraded refusal, it is the strongest one available: a client gets a
transport error rather than a short body it could mistake for a legitimate EOF.

`_attempt()` now returns the abort as a first-class outcome (`_served()` answers
False for it), so the refusal rows assert the contract instead of the transport;
the SUCCESS rows deliberately keep `_get`, where an abort must still be a hard
error. Two rows pin the SHAPE rather than the verdict, because `not _served(...)`
alone would also pass if the node handed back the corrupt page and then aborted:
whatever prefix arrives must be a clean prefix of the object and must stop before
the bad page, and the refusal must not be downgraded to a silently short 200.

### §H7 — one red became fifteen: a fixed name released only on the happy path

A lane-1 run lost 15 rows across three files to
`ValueError: server already registered: lc-wlcg`. Not one of the 15 was the
defect. `WlcgInstance.__init__` claims the fixed name and only `stop()` releases
it, so any construction that never starts — several suites build an instance
purely to call `configtest()` — and any body that fails between the two leaves
the name held. Every later construction in the file then dies in `register()`,
and the cascade buries whichever failure started it: the first traceback scrolls
away behind fourteen identical ones that say nothing about it.

Same class as commit `81064d8eb`. A test harness must not convert one red into
fifteen, and a fixed-name acquisition has to be idempotent whatever the previous
owner did. `_release_stale()` (brix_suite/mesh/wlcg_fleet.py) stops first and
unregisters second — the reverse order would orphan the process holding the
ledger port, which is the failure being prevented, one layer down.

Pinned by `test_wlcg_fleet_name_idempotency.py`: a stale claim does not block the
next instance (both resolve the same `davs_port`); the release stops before it
unregisters and survives a dead instance whose `stop()` raises; and it touches
only the exact name, so an unheld name costs no `stop()` call and a decoy
registration survives. Proven non-vacuous by deleting the `_release_stale` call
and observing the exact cascade error return.

### §H8 — the pin detector counted test FUNCTIONS where xdist schedules ITEMS

`test_suite_parallel_hygiene.py` rule 2 flags a fixed-port lifecycle subject
started by more than one test without an `xdist_group`. It counted starters by
walking test FUNCTIONS. xdist schedules ITEMS, and a `@pytest.mark.parametrize`
turns one function into several: a single 2-way parametrized starter is two
items, which two workers can take, which is one instance launched twice on one
port.

`test_wlcg_conformance_proxy.py` was exactly that — a 2-way parametrize driving
the fixed exclusive-band `lc-wlcg` (port 31020) with no group — and rule 2 had
called the file clean since it was written. `_item_count()` now multiplies the
parametrize cases; computed argvalues count as 0 (unknown, deliberately not 1)
so an unreadable decorator cannot be silently treated as a single item.

### §H9 — the pin detector could not see a subject claimed inside a helper class

The same rule read ledger names only as string literals in the test module.
`lc-wlcg` is spelled in `WlcgInstance.__init__`, so the detector had never once
seen it: the four hand-written `xdist_group("lc-wlcg")` pins were correct by
authorship alone, and the fifth file that forgot one (§H8) was never flagged.
Silence from a guard that cannot see the subject is not evidence of a pin.

`_helper_subjects()` maps an exported helper name to the ledger subjects its own
body claims, and a test gets credit for a helper only when the module actually
IMPORTS it — a mention or a local shadow does not count. Only literals inside a
top-level class or function body are read, so the port-ledger modules, which
spell every name at module level in a dict, contribute nothing rather than
mapping some name to the whole ledger. Extended, the detector flagged exactly one
module across the whole suite: one true positive, zero false positives.

Three rows pin it: the helper map contains `WlcgInstance -> {"lc-wlcg"}` and no
top-level name of `fleet_ports_exclusive`; items are counted, not functions
(2-way -> 2, 1-way -> clean, computed -> 0, stacked 2x3 -> 6); and helper credit
requires a real import.

### §H10 — a launcher guard named its subject, so a different name read as clean

`test_server_registry_lint`'s argv0 pattern matched a closed list of three exact
identifiers: `NGINX_BIN`, `NGINX`, `nginx_bin`. A module that spells the binary
any other way is not judged clean by that guard — it is never read at all.

Both directions were live in the tree. Harmless direction:
`test_phase115_conf_unset_sentinel.py` runs `nginx -t` and nothing else, through
`_nginx_bin()`; `_validation_only` saw zero nginx calls and withheld the
inline-config exemption that exists for precisely that shape, so a correct file
was flagged. Dangerous direction: `test_data_substreams_gateway.py` starts two
real gateway servers from a module-level `_NGINX` and had never been examined by
`test_no_new_direct_nginx_launches` — neither offender nor backlog, simply
unseen. It is on `LAUNCH_BACKLOG` now, documented as a migration target, so it is
at least SEEN.

The pattern now accepts an optional leading underscore and an optional empty
call; `_argv_is_non_server_action` learned `-s`, because signal mode stops a
master that is already running and starts nothing (which is what the registry's
own stop path does). Three rows pin it — every argv0 spelling is seen; the census
that the widening caught a launcher that had never been seen, plus `-s quit` not
counting as a launch; and argv0 anchoring is not lost, so a binary merely NAMED
inside an `xrdcp`/`curl` argv, or a look-alike such as `MY_NGINX_WRAPPER`, is
still not a launch. Each proven non-vacuous by substituting the old pattern back
(the first two redden) and a deliberately argv-wide one (the third reddens).

### §H11 — five test listeners asked the kernel for a port

`test_fleet_port_uniqueness.py::test_test_sources_never_request_kernel_assigned_ports`
was red on the tree, on five `bind((host, 0))` sites in four modules — three of
them this register's own: `_test_phase115_pgread_verify_helpers.py`,
`test_phase115_cms_select_proxy.py` (twice), `test_phase115_proxy_fhandle_width.py`
and `test_cms_node_readiness.py`.

Port zero is not merely untidy. A kernel-assigned listener is invisible to the
test-port ledger, so nothing can detect that it has taken a managed service's
port — and it *can* take one, because a lane's fixed range and the host's
ephemeral range overlap. The failure that follows lands on the service whose
port was stolen, in a different module, at a different time, and reads as a
flake. This is the same shape as §H1–§H10: nothing complains, and the run that
did not complain is read as green.

Four of the sites are listeners and now lease before they bind —
`self.port = free_port(H)` then `bind((H, self.port))` — with the
`getsockname()` read-back deleted, because a leased port is known before the
socket exists. The fifth was different in kind and is the discovery worth
recording: `_closed_port()` bound port zero, read the number back and closed the
socket, purely to obtain *a port nothing listens on*. A mock-range lease is
already exclusive to the session, so the whole bind/close dance was ceremony
that happened to be exactly what the guard forbids; the helper is now a single
`return free_port(H)`. A remedy applied only to the sites that look like
listeners would have left this one red.

No new test was written. The guard already existed, already stated the property
in the form that matters (a census over every `tests/**/*.py`, so a new offender
is seen the day it lands), and was simply failing; the fix is proven by it
turning green, and the four modules — 34 tests — pass unchanged, which is what
shows the leases are usable and not merely legal.

#### Coda to §H11 — two lane bases 8000 apart are not disjoint

Fixing the five sites moved them onto the mock lease range, which made a second
fact matter: **a lane does not occupy the ports it binds, it reserves a ladder**.
At `TEST_PORT_START=B` the ladder runs `B+1 .. B+18807` and the mock lease range
is its tail, `B+2424 .. B+18807`. Concretely, for the three bases in use while
this register was being verified:

| base | full ladder | mock lease range |
| ---- | ----------- | ---------------- |
| 12000 | 12001-30807 | 14424-30807 |
| 15000 | 15001-33807 | 17424-33807 |
| 20000 | 20001-38807 | 22424-38807 |

Every pair overlaps. Bases chosen 3000 or 8000 apart *look* disjoint and are not,
because each reserves ~18.8k ports; only one full lane fits per host - and per
WSL2 VM, since all distros share one network namespace, so a `pgrep` in this
distro cannot see the listener that will collide.

This is not theoretical. `test_fleet_port_uniqueness.py::test_duplicate_listen_port_reports_address_already_in_use`
squats a leased port with a WILDCARD bind and no `SO_REUSEPORT`, deliberately, so
that the second bind is guaranteed to collide rather than load-balance. That same
deliberate choice means any foreign listener on that port - another lane, another
distro - reddens the test on the SQUATTER's bind, before the behaviour under test
is ever reached. The two signatures must not be confused: `OSError: EADDRINUSE`
raised at the squat is a lane collision, while the defect the test exists to catch
surfaces later as a `RegistryCommandFailure` carrying nginx's own bind error. One
is an environment report, the other is a real finding.

#### Coda — the one guard that did NOT go quiet

The W4.3 §5 refusal-SHAPE rows needed two lifecycle-shared slots. The width bump
landed without re-summing the tail of the packed ladder, so `lifecycle-shared`
overlapped `lifecycle-exclusive` by 2 and port 21274 was assigned twice. This is
the failure the 2026-08-16 and 2026-08-17 notes in `port_ladder_offsets_tail.py`
describe, and `test_fleet_ports.py`'s band check named it within the hour —
offset, both owners, and the exact overlapping port. It is recorded here as the
control case for §H1–§H10: a guard that states what it examined fails LOUDLY and
specifically, and costs one repack rather than a hunt.

## Production defects found while verifying this register (2026-09-07)

### §P1 — MODE E policed a window the origin was never told about

`mode=e` over a GridFTP door without ERET could not serve a single object larger
than one read window. The failure was a 200 with zero bytes and an aborted
connection, and it reached the client with no line in `error.log` at all.

`gftp_eb_claim()` refuses any block outside `req->limit`, whatever command
opened the transfer. That is right after ERET P, which carries offset AND
length: the origin was told where to stop, so a block past the end is the peer
writing outside the address range it was given. It is wrong after REST+RETR.
RFC 959 RETR carries no length; the origin sends the whole tail by
specification, so the second block of any object bigger than the window is
surplus the caller never asked for and the origin was never warned off. MODE S
never noticed because `gftp_retrieve_stream()` reads `limit` bytes and abandons
the rest. MODE E, which polices offsets, read the same bytes as an attack.

With the W5.1 lab's own numbers: a 384000-byte object, a 65536-byte first
window, an origin chunk of 65536 and no ERET. Block 1 (offset 0, count 65536)
fills the window exactly; block 2 (offset 65536, count 65536) fails
`count > limit - (off - base)` and the transfer dies — with the 65536 bytes
already committed discarded and the 200 headers already on the wire.

The fix gives MODE E the rule MODE S has always had, and no more than that.
`gftp_mode_e_req_t` gains `bounded` (IN: did the command DECLARE this window?)
and `stopped_early` (OUT: the caller must not wait for a completion reply — the
same contract MODE S signals by returning 0). Two narrow relaxations, both
unbounded-only: a block that BEGINS at or past an already-fully-committed window
ends the transfer cleanly, and a block that STRADDLES the end is committed to
the edge and then ends it, because the connection is thereafter mid-payload and
the next 17 bytes would be a header invented out of the file's contents.

The narrowness is the design, and it was arrived at by trying the wide version
first. "The window is full, stop reading" is simpler and would have been wrong:
on any object smaller than one window the window fills exactly at EOF, which is
precisely where the `overlap` fault sends its replayed block. Requiring the
surplus block to BEGIN at or past the end keeps all four faults exactly as
refusable as they were.

How much the wide rule cost was measured rather than argued. The two rules were
transcribed into Python and driven by `ftp_origin_mode_e.send_transfer()`
itself — the real sender, so every fault is the exact stream the suite puts on
the wire — over eleven cases: the four faults, an unbounded over-run, a
straddling Range, a complete small object, and a declared ERET window both
honoured and over-run. The narrow rule answers all eleven as designed. The wide
rule defeats TWO pinned security refusals, not the one that was expected:
`overlap` AND `short-eod` both become a silent `stopped` with 224 bytes served,
because both faults do their lying AFTER the window has filled. It also reports
every complete sub-window transfer as a stop rather than a completion.

That model is design evidence and is deliberately NOT a test. A Python
transcription of a C rule is a thing that can agree with itself while the C
drifts away from both — a test that passes while the code is broken is the §H
failure with extra steps. The three tests below go through nginx and the real
driver; the model's only job was to make the choice between two candidate rules
a measurement instead of an opinion.

Three tests, and each one exists because a cheaper version would not have held:

- **Success** — a whole-file GET over the ERET-less origin is byte-exact, and
  the origin's own audit shows `RETR` more than once and `ERET` never. The audit
  assertion carries it: byte-exactness alone would pass just as well if someone
  later gave that origin ERET, at which point no surplus would ever arrive and
  the path would be pinned by nothing.
- **Error** — a 300-byte Range answered with a whole 65536-byte block returns
  206 with exactly those 300 bytes AND adds no `outside the requested window`
  line. A truncation at the edge is a complete window, not a refusal; an
  implementation logging both alike would pass every byte assertion and leave an
  operator chasing a security event on every ordinary ranged read.
- **Security negative** — a new ERET origin fault, `overrun`, honours the offset
  and ignores the length. It is the only shape that discriminates: the existing
  `liar` answers from offset 0 and is refused on its offsets whatever the window
  rule says, so a driver that had dropped window policing altogether would still
  pass it.

Found the same way as everything in §H: not from a failing assertion naming it,
but from asking why a green-looking silence had no diagnosis behind it.
`gftp_set_error()` writes a specific, actionable sentence into `session->error`
and every caller discarded it, keeping only `errno`. Three call sites in
`sd_gsiftp_io.c` now log it through `inst->log`. That change is worth more than
the fix: the next MODE E defect will announce itself.

### §P2 — a pre-header origin failure was finalised by closing the connection

An origin that refused before a single byte of the object existed produced no
status line at all. `curl` printed "Empty reply from server" and scored it
`%{http_code} 000`; an `error_log` line existed, but nothing on the wire told
the client whether the object was missing, forbidden, or the origin was down.

The cause is ordering, not error handling. The serve path emitted headers and
then began reading, so by the time the driver discovered it could not get the
first block the 200 and its `Content-Length` were already committed and the only
remaining way to signal failure was to stop writing — which, on a response that
has not yet sent a byte, nginx finalises as a bare close.

The fix primes the FIRST read before the headers go out, and only that read. A
failure discovered there is still a status the server is free to choose, so it
becomes one: the shared errno table decides it, with its unclassified 500
default promoted to 502 because this path is only ever reached for an
origin-backed object and "we could not reach the thing that holds it" is what
502 means.

Two boundaries make the change safe, and each is a test rather than a comment:

- The promotion is for UNCLASSIFIED failures only. A missing object stays 404
  and a refused one stays 403. Promoting either would blur an existence or an
  authorization answer into an availability one: the client retries, the
  operator hunts a network fault, and the real answer is never seen.
- A request with no body does not prime. HEAD and a zero-length range have
  nothing to fetch, and priming anyway would turn every metadata request into an
  origin data transfer — a real cost on a tape or WAN backend, and one that
  would make HEAD fail wherever GET fails. The proof is an origin that cannot
  serve a single byte answering HEAD with a 200 and the right `Content-Length`.

The counterpart is deliberately left alone. `late-overlap` serves the opening
window cleanly and lies on the next one, so the 200 is already on the wire when
the refusal fires. There is no status left to send and inventing one would be
worse than sending none — the client would be handed a 502 for a response it had
already begun reading as a 200. That transfer stops, and the client must be able
to SEE that it stopped: a short read against a declared length, never a tidy 200
whose body is quietly incomplete.

The tests carry a distinction that a status assertion alone would lose:
`NO_REPLY = 0` is asserted against separately, because a regression here does
not produce a WRONG status, it produces NO status, and a bare
`assert status == 502` would report the defect as an unhandled
`RemoteDisconnected` raised inside a transport helper.

### §P3 — FEAT never detected a feature on any conforming origin

`gftp_feat_line_is()` treated a feature name as terminated by `' '`, `'\t'` or
NUL. RFC 2389 §3.2 advertises each feature as a continuation line of a 211
reply, and RFC 959 §4.2 terminates every reply line with CRLF, so on every
conforming door the byte after the name was `\r`. The mask came back 0 — every
time, on every origin.

Nothing said so. ERET and SPAS were simply never negotiated: the driver fell
back to REST+RETR and to single-stream transfers, served the right bytes, and
was slower and unbounded. Two whole extensions were dead in production and the
suites that test them were green, because those suites drive an origin the lab
starts with `--eret` and assert byte-exactness, which the fallback path also
satisfies.

The pin that owned this is the reason it is written up rather than merely fixed.
`test_feature_names_match_whole_tokens` asserted the SPELLING of one comparison
in the C (`line[len] == '\0'`). It was green for the entire life of the defect
and it went RED on the repair — a check that cannot see the bug it is named
after, and that objects to the fix, argues for the bug. That is the §H failure
with the sign flipped: not a check that never ran, but one that ran and was
measuring the wrong thing.

What replaces it is a pair, because neither half is sufficient:

- **A set census, not a spelling.** The needle now extracts the terminator
  comparisons out of `gftp_feat_line_is()` and asserts the SET is
  `{NUL, ' ', '\t', '\r', '\n'}`. It reddens when a boundary is dropped and
  stays quiet when the same set is re-spelled.
- **The matcher, run.** `tests/c/gftp_feat_test.c` includes the translation
  unit (the matcher is static) and stubs `gftp_command()` so `gftp_feat()`
  itself can be driven, not just its parser — the probe's other two failure
  modes, a non-211 code and a body read from `session->text` instead of
  `session->cont`, are invisible to a test of the parser alone. Fourteen checks:
  six terminators, five look-alikes, three refusals.

`tests/test_phase115_gridftp_feat_tokens.py` then does to that driver what §H
asks of every check. It censuses the PASS lines against a named set, so a check
that stops running is a red rather than a silence. It censuses
`gftp_feat_names[]`, so a third feature added to the table cannot inherit the
green — that census earned itself immediately: SPAS was only ever driven inside
a multi-line blob and had no terminator check of its own. And it mutation-tests
in both directions, because a boundary set is a two-sided property: narrowed
back to the shipped defect it must be caught by exactly `{T1,T2,T3,T6}`, and
widened to a bare prefix match by exactly `{S1,S3}`. Both killer sets were
measured before they were written down.

On the wire, the fix is visible as `ERET P` appearing in the origin's audit for
the first time, and a decoy origin advertising ` ERETSTAT`, ` SITE ERET`,
` SPASV` and ` X-ERET` lighting no bit.

### §P4 — a ranged read of a remote object fetched the whole object

Found while proving §P3, and larger than it.

A storage backend with no kernel file descriptor carries
`BRIX_SD_CAP_MEMFILE` — gsiftp, http, xroot, s3, ceph, cephfs_ro, remote, ram,
pblock. The serve path asked the VFS for a sendfile fd with
`brix_vfs_file_sendfile_fd(fh)`, a WHOLE-OBJECT question, and with no fd to hand
back the VFS answered it by MATERIALISING: preading the entire object through
the driver into a memfd, 64 KiB at a time. On a remote origin that is a network
transfer of the whole file, and it was paid on every ranged read.

Measured on the W5.2 lab before the fix: a `Range: bytes=100000-100255` GET of a
384000-byte object produced SIX `ERET` commands over six control connections,
covering 0..384000. After it: exactly one, `ERET P 100000 256 /base/plain.bin`.

Nothing was observably wrong — right bytes, right `Content-Range`, right status
— so the cost was invisible from the client, which is precisely why it survived
every byte-exactness test in the ERET suite. It also silently cancelled the
extension that suite exists to test: `ERET` was issued, correctly formed, for
the wrong window. A bounded-retrieve negotiation whose bound is the whole file
is not a bounded retrieve.

The fix is `brix_vfs_file_sendfile_fd_window(fh, off, len)`, and its shape is
the design:

- The backend PROBE is unchanged and asks whole-object, so `sd_block` /
  `sd_pblock` acceptance does not widen. Only the materialisation FALLBACK is
  gated on the window being the whole object.
- A strict sub-window declines the fd and the caller takes its memory-backed
  path. Declining costs nothing: the memfd was already a full copy of an object
  the backend cannot sendfile in the first place, so the "zero-copy" it bought
  was zero-copy over a copy.
- A caller that will read nothing passes `len < 0`. A HEAD must never reach the
  fallback.
- INVARIANT 2 is unaffected: the backend's sendfile-fd availability still picks
  exactly one of file-backed+sendfile and `b->memory = 1`, and this only changes
  which of the two a fd-less backend gets for a sub-window.

The multi-range WebDAV path deliberately still asks whole-object: it serves
several windows from one handle, so the object IS its window.

Three tests, in `tests/test_phase115_vfs_sendfile_window.py`, all counted in
BYTES the origin was asked for rather than in commands issued — an
implementation that split the same whole-object fetch across more, smaller
ERETs would satisfy a command count and still move the entire file:

- **Success** — a ranged GET asks the origin for exactly the window.
- **Error side** — a whole-object GET still moves exactly one object's worth.
  This is the other half of the boundary: a gate that declined the memfd for a
  whole-object read would push every ordinary GET onto the memory-backed path.
- **Security negative** — a HEAD moves zero bytes of payload. If it did not,
  any client able to issue HEAD could make the gateway pull whole objects off
  the origin on demand, at no cost to itself and with no body to show for it —
  a bandwidth amplifier that no access log would explain.

### §P5 — the materialisation that fixed §P4 still paid five logins for one object

Found immediately after §P4 and hidden by it. Once a whole-object read is the
only thing that materialises, what materialisation COSTS becomes the question,
and `brix_vfs_memfile_fill()` was reading the object in fixed 64 KiB steps
through a stack buffer.

A driver whose `pread` slot is stateless pays that once per step. gsiftp's is
stateless by protocol: each `pread` opens a control connection and runs
`USER`/`PASS`/`TYPE`/`REST`/`RETR`. Materialising a 307200-byte object
therefore cost one login per 64 KiB step where one would do for the whole
object — and because those steps together move exactly one object's worth of
bytes, the §P4 byte census is green throughout. Only a count of SESSIONS can see it.

The fix is to ask for the remainder rather than for a chunk: the loop requests
`size - off` every time, and the memfd is filled through one `mmap` of itself
rather than through a stack buffer, because it already holds the whole object
and the mapping costs no memory the materialisation was not paying anyway. A
conforming driver answers in one call; a short-reading one still finishes,
because the loop is unchanged in shape and only the span asked for grew.

Tests in `tests/test_phase115_vfs_memfile_sessions.py`, counted in LOGINS
rather than in bytes for the reason above:

- **Success** — one whole-object GET on a gsiftp export opens exactly one
  origin session.
- **Error side** — the loop must not have become a single-`pread` assumption,
  which is the tempting way to write "ask for everything" and which breaks
  every driver that legitimately answers short. No origin in this harness
  answers short — a `REST`+`RETR` always yields the whole remainder — so this
  one is pinned on the loop's SHAPE rather than behaviourally: it re-asks from
  a cursor it advances by what it actually received.
- **Security negative** — a HEAD opens no data session at all. A HEAD that
  materialised would let any client make the gateway pull whole objects off the
  origin on demand, with no body to show for it and nothing in an access log to
  explain the traffic.

### §P6 — a driver's blocking wire was decided by its NAME

`brix_http_serve_offload_remote()` moves a serve off the event loop when the
driver owns a socket it will block on, and it decided who needed that with
`ngx_strcmp(driver->name, "xroot")`. That was correct exactly once, on the day
xroot was the only such driver.

The gsiftp driver arrived later speaking a whole FTP conversation per read —
connect, `USER`/`PASS`, `PASV`, `RETR`, drain — was never added to the list, and
so served every byte on the event loop. Nothing failed loudly: a worker simply
stopped answering for the length of each transfer, and where the origin was
reachable only through that same worker the request could not complete at all.

The repair is to stop asking the name. `BRIX_SD_CAP_BLOCKING_WIRE` (bit 19) is
declared by the driver itself, and `serve_is_remote_socket()` reads the bit. A
driver that dials a socket now arrives with the offload already correct.

Tests in `tests/test_phase115_blocking_wire_offload_static.py`, five of them,
built as a CENSUS rather than as a spelling check — both sides are derived from
the tree, so a new socket driver reddens on the day it is added:

- **Success** — the predicate reads the capability, and no `->name` comparison
  survives anywhere in it.
- **Error side** — every backend directory that calls a blocking dial helper
  declares the bit, and none that does not declare it. The second direction
  matters: the bit costs a full extra copy of every object served, so a local
  driver claiming it is a real regression rather than an untidy one.
- **Security negative** — `posix` and `ram` are named explicitly as NOT
  carrying it. Without one concrete expectation the census above would be
  satisfied by two empty sets.

### §P7 — outbound PROT P failed closed, three times over

The protected GridFTP data channel worked on nobody's machine. Each of the
three reasons produced a log line naming something other than its cause, and
each had to be fixed before the next became visible.

**(a) The handshake ran at dial time.** `gftp_dc_open_at()` connected the data
socket and immediately ran `SSL_connect` on it. A passive FTP server has no
reason to touch the data connection until it has a transfer to run — BriX's own
inbound half arms its accept handler from `brix_ftp_ev_data_open()`, which the
transfer verb calls after sending its 150 — so the client waited for a
ServerHello the server would not send until it read a command the client had not
sent. Both ends then sat there: the origin logged `control channel idle timeout
(110)`, and the client an `SSL_connect` failure with an EMPTY error queue.
Neither line names an ordering bug. The fix splits `gftp_dc_open_at()` (dial)
from `gftp_dc_secure()` (handshake) and reorders all three transfer sites to
dial, command, THEN secure.

**(b) OpenSSL was asked whether a delegated proxy is a TLS server
certificate.** It is not, and it does not claim to be. The in-handshake purpose
check rejected the origin's chain with `X509_V_ERR_INVALID_PURPOSE` (26) before
a byte moved, and reported it as `certificate verify failed` — which reads as a
misconfigured origin. The inbound half of the same feature
(`src/protocols/gridftp/ftp_dc_sec.c`) has always accepted at the TLS layer and
applied BriX's proxy policy afterwards; the connect half was the one still
asking. The fix arms a data-channel-only `SSL_set_verify` accept callback. It
is stricter than what it replaces, not weaker: `gftp_dc_tls_pin()` runs
`brix_gsi_verify_chain` over the presented chain against the SAME CA store and
then requires the leaf DN to name the delegating identity — a test OpenSSL's
generic path does not make at all. The control channel keeps OpenSSL's verdict.

**(c) The DN pin compared the wrong two identities.** A GridFTP server runs its
data channel on the credential the CLIENT delegated to it, so the DN that comes
back is ours plus one `/CN=<serial>` per delegation step — never the origin's
host DN. Pinning to the origin's control DN could not match on a correct
transfer, and the refusal accused the origin:

```
data-channel DN ".../CN=Test User/CN=12345/CN=12346/CN=3228637842"
  != control DN "/DC=test/DC=xrootd/CN=localhost"
```

The fix reads our own subject with `SSL_get_certificate()` and pins to that.
The security property is unchanged in strength and clearer to state: the peer
holds the PRIVATE KEY of the credential we handed to the origin we
authenticated. A third party that reaches the passive data port has the public
proxy at most and cannot answer. An unauthenticated control channel still
refuses outright — it delegated nothing, so there is nothing to pin to.

`src/protocols/gridftp/ftp_dc_dn.h` now records that the two roles pin against
DIFFERENT BASES, because passing the wrong one is a silent no-match rather than
an error.

Behavioural proof is `tests/test_phase115_gridftp_prot_p.py` (7) and
`tests/test_phase115_gridftp_spas.py` (11, three of which this repaired). The
SHAPE that made each defect possible is pinned in
`tests/test_phase115_prot_p_handshake_static.py` (9), because all three are
invisible to a test that only asks whether the bytes arrived:

- **Success** — the dial does not handshake; every transfer site secures after
  it commands, asserted against the command WRITE rather than against the dial,
  since a handshake placed between the two deadlocks exactly as the original
  did; and the origin's three-link interlock still holds (it handshakes on the
  accept, the accept handler is armed by opening the data channel, and opening
  the data channel has exactly one caller, in the transfer verb's file).
- **Error side** — a failed handshake reports `SSL_get_verify_result` rather
  than the queue's generic text. This is the diagnostic that would have named
  (b) on the first attempt instead of the third.
- **Security negative** — two ways of "fixing" this are worse than the bug, so
  both are guarded as pairs: the TLS-layer accept may not exist without the
  post-handshake verify that replaces it, and neither role may grow a second
  copy of the DN comparison. A predicate that exists twice gets fixed once.

### §P8 — the WebDAV self-target guard could not see two objects on a remote export

WebDAV refuses a COPY or MOVE whose destination names the source (RFC 4918
§9.8.5 / §9.9.4 → 403), and the refusal is load-bearing: the copy engine
publishes by writing a temp object and renaming it over the destination, so a
copy onto the source destroys the only copy of a file the caller never asked to
modify, and a failure part-way through destroys it permanently.

Both verbs implemented that guard as `(dev,ino)` equality and nothing else. A
REMOTE namespace has no inodes: `gsiftp`, `http`, `s3` and `xroot` never fill
`brix_vfs_stat_t.ino/.dev`, so every path on such an export stats as `(0,0)` and
the guard read "source and destination are the same file" for EVERY destination
that already existed. Every ordinary overwrite on every remote-backed export
answered 403.

The fix is one shared predicate, `brix_webdav_same_object()` in
`src/protocols/webdav/webdav_path.h`, reached by both `copy.c` and `move.c`.
Path equality is the arm that always holds; the `(dev,ino)` arm is consulted
only when the backend supplied an identity to compare. The predicate is shared
rather than duplicated because it WAS duplicated, and only COPY's copy was
found first.

Tests in `tests/test_phase115_same_object_guard.py` (13) and three added rows in
`tests/test_phase115_gsiftp_server_copy.py`:

- **Success** — on a remote export, a second copy onto a now-existing
  destination is accepted, and MOVE onto an existing destination replaces it.
  This is the defect itself, on the namespace where it bit.
- **Error side** — the discrimination rows on a POSIX export: an ordinary
  overwrite succeeds while a self-copy is refused. A guard that refused
  everything would pass every refusal row in the suite, which is precisely what
  the broken one did.
- **Security negative** — the inode arm must SURVIVE the fix. The tempting
  simplification is to drop it, since the path arm alone passes every test
  written against a remote export; on a POSIX export it does not, because a
  hardlink is a second NAME for one object. A copy onto a hardlink of the
  source is refused, and a companion row proves the two names really are one
  inode, so the refusal cannot pass for the wrong reason.

Two rows of the predicate's truth table cannot be produced over the wire at all
— a remote export will not hand out an inode and a local one will not withhold
one, and the row an inode-only predicate gets wrong is one of them. So the
suite lifts `brix_webdav_same_object` out of the header, compiles it with `cc`,
and runs all six rows against the shipped body. Lifted rather than
reimplemented: a model of the predicate would keep passing after the predicate
changed, which is the one thing it must not do.

### §P9 — the offload widened back every window §P4 had narrowed

Found while burning §P6 down, and created by it. §P4 narrowed what a fd-less
backend materialises to the window the request will actually send. §P6 then
made every blocking-wire driver self-declare `BRIX_SD_CAP_BLOCKING_WIRE`, which
correctly routed gsiftp into `brix_http_serve_offload_remote()` — a path that
runs BEFORE `file_serve.c` and copied the WHOLE object into a scratch temp file.
The layer above narrowed the read; the layer below widened it straight back.

Nothing about the response changed — right bytes, right `Content-Range`, right
status — so only the origin's own command log could see it, and on the ERET lab
it said `ERET P 0 384000` to serve a 256-byte window. §P4's own suite went red
the moment §P6 landed, which is how a fix for one finding turning off another
was caught at all.

The repair gives the offload the same window decision the serve already makes.
`brix_serve_offload_fill()` (new, `src/protocols/shared/serve_offload_fill.c`)
parses the request's `Range` against the object size with the same
`brix_http_parse_range()` the serve uses, and writes the fetched window into the
scratch fd AT ITS TRUE OFFSET over a hole of the full object size.
`brix_http_serve_file_ranged()` then re-derives the same window from the same
header against the same size and reads exactly those bytes: one computation run
twice, so the fetch and the send cannot disagree. The hole costs no disk and is
never read. The thread may not touch `r`, so the raw header travels into the
worker as bytes; one too long to copy is simply left absent, which fetches the
whole object — the slow answer, never the wrong one.

Three consequences are worth stating, because each invalidated a test that was
correct before it:

**The drain is ALL-OR-NOTHING for a bounded window.** `xvfs_drain_window()`
returns `EIO` when a bounded window ends early, and only an unbounded drain may
stop at EOF. A sparse `dst` holding a hole inside the range the caller asked
for is indistinguishable from one holding the object's real zero bytes, so an
origin that simply stays silent could otherwise write zeroes into any window of
any file. This is a risk the sparse temp CREATES; it is the price of writing a
narrowed window at its true offset, and this is the line that pays it.

**A whole-object copy reports what it READ; a narrowed one reports the object
size.** An origin whose size is a lie must not make the response promise bytes
that are not in the scratch — so an unbounded drain sets the response size from
what arrived. A narrowed drain cannot do that, because its `Content-Range`
denominator has to be the object size; it is safe not to, because its window is
all-or-nothing and there is nothing left to disagree about.

**A blocking-wire door has no post-header refusal.** Materialise-then-respond
means a failure during materialisation is a clean pre-header status carrying no
object bytes, where the streamed path could only stop early under a 200 whose
`Content-Length` was already on the wire. That is strictly better for the
client — a truncated 200 can only be caught by comparing what arrived against
`Content-Length`, a 502 cannot be missed — but it is a different shape, and two
MODE E rows and one pgread row had pinned the old one. They are re-pinned, with
the reason in each docstring rather than in a commit message.

Tests in `tests/test_phase115_serve_offload_window.py`, four of them. They pin
what §P4's suite structurally cannot reach: that suite counts bytes on a
384000-byte object, which fits inside one 1 MiB drain chunk and is therefore
always one retrieve, so it proves the window is narrowed and would pass
identically against a loop that widened at the tail or accepted a short answer.
Every row here needs the loop to iterate, or needs the origin to withhold what
it promised. The lab gains a 3 MiB seed and a fourth ERET misbehaviour, `hole`,
which accepts the window, opens the data connection and sends nothing.

- **Success** — a 1500000-byte window over the 3 MiB object is fetched as more
  than one bounded retrieve whose lengths sum to exactly the window. Both
  assertions are needed and neither implies the other: the total says the loop
  never widened, the count says a loop ran at all. A second row asserts WHERE
  each iteration asked, because a total is blind to placement — a loop that
  advanced its cursor by the chunk size rather than by what it received moves
  the right number of bytes to the wrong offsets, and against an origin that
  always answers in full the body is still correct, because each misplaced
  write is overwritten by the next iteration.
- **Error side** — a window the origin withholds is a status, not a short body.
  It must also not be a `416`: the range is perfectly satisfiable against the
  object, and reporting an origin failure as an unsatisfiable range tells the
  client its REQUEST was wrong, so it does not retry and an operator reading the
  log goes looking at the client. `416` is what the pre-fix serve answered.
- **Security negative** — the hole never arrives as object bytes. Alone among
  these rows it does not fail against the pre-§P9 serve, and cannot: that
  scratch was only ever as long as what had been read. It is a mutation pin on
  the `EIO` branch above — drop it and the same request returns `206` with a
  correct `Content-Range` and a body of zeroes.

The re-pinned rows carry their own evidence:
`tests/test_phase115_gridftp_mode_e.py` moves the RETR-surplus property onto a
RANGED read, where a length-less `RETR` genuinely over-runs a narrow window —
after §P5 and §P9 a whole-object GET asks for everything, and nothing can be
surplus to a request for everything — and moves the late-window overlap refusal
onto a range spanning three 64 KiB blocks, since a narrower one fills inside the
first block and the driver truncates at the window edge before the replay is
ever sent. `tests/test_phase115_pgread_verify.py` now accepts either refusal
shape explicitly and keeps the one assertion it exists for: no page that failed
its CRC32c reaches the client, in either.


## Harness defects found in the post-register full tier (2026-09-08)

The full four-lane tier on binary `cf481268` finished 88 failed / 43,122 passed.
No phase-115 module appeared in any red list and nothing was attributable to
§P9. Five of the reds were ours to answer for, and each turned out to be a test
that could not say what it had actually observed. They are recorded here because
the fix in every case was to give the test a witness, not to change a server.

### §H3 — a corruption test asserted failure where the invariant is integrity

`resilience/test_tls_token_leg_sweep.py::test_pgrw_catches_corruption_that_a_plain_read_delivers`
failed once in lane 3 with `rc == 0` and passed 6/6 on re-run.

The assertion was `rc != 0`: a `--pgrw` transfer over a proxy flipping bytes at
5 ppm must fail. That over-states what pgread promises. A per-page CRC32c
mismatch is caught at the page, and the page can be re-requested; at this rate
about 2% of 4 KiB pages carry a flip, so a re-read usually comes back clean and
the whole transfer can legitimately finish — clean `rc`, byte-exact file, every
flip caught and repaired. Asserting `rc != 0` made the repair path a failure.

What must never happen is a clean `rc` over bytes that are wrong, and that is
what is asserted now (`rc != 0 or exact`), with the refusal path still pinned
(`rc == 0 or size == 0`). The property did not weaken: a silent corrupt success
still fails, and now names the byte count.

- **Success** — the repaired and the refused outcome are both accepted, and the
  message on either carries how many bytes the proxy actually flipped.
- **Error** — every corruption case in the module now guards on `flips > 0`
  first. A run where the lever drew nothing used to be a green test asserting
  nothing; it now reports itself as vacuous.
- **Security negative** —
  `test_pgrw_cannot_repair_wholesale_corruption` at 500 ppm: page-level re-reads
  are recovery from a sparse fault, never laundering of a hostile stream. Every
  page carries flips, no bounded number of re-reads yields a clean one, and the
  transfer must fail leaving nothing behind.

The witness is the proxy's own counter, read through the new
`FaultProxy.counters()` (`tests/resilience/servers_part3.py`), which parses the
`metrics` control reply. `tests/resilience/test_fault_proxy_counters.py` (4)
pins the counter itself: the parse and a byte-exact `bytes_down` delta on a
clean relay; that `corrupt_total` counts exactly the positions that differ; that
it stays at 0 with the lever disarmed — so the `flips > 0` guard can actually
fail — and that a torn-down proxy raises rather than reporting a stale snapshot
a caller would difference to a plausible 0.

### §H4 — a ztn auth error that was really a broken TLS leg

Four `tests/test_tpc_token_auth.py` copies failed in lane 2 with
`security protocol 'ztn' disallowed for non-TLS connections`; the module passes
9/9 in isolation. XrdCl will not put a ztn credential on a cleartext
connection, so anything that stops the in-protocol TLS leg surfaces as four
separate auth failures that read like a token or TPC defect. The harness PKI is
per-`TEST_ROOT`, so the two live causes are a CA regenerated under a server that
kept its cert, and a host clock that stepped past a validity window
(a known defect of this host).

- **Success** — `_tls_pki_fault()` returns `None` on a healthy fleet PKI, so it
  can never redden a good run.
- **Error** — it names a chain break (with the CA file it checked against) and,
  separately, an out-of-window cert as the clock case. Both are pinned against
  a decoy PKI built in `tmp_path`; the expired leaf is issued with `-days 0`, so
  no host clock is touched.
- **Security negative** —
  `test_the_tls_diagnosis_stays_off_an_unrelated_failure`: the annotation fires
  only on the ztn-cleartext refusal. A copy that fails for any other reason
  carries no PKI verdict, or a real TPC or authorization defect would be dressed
  up as a harness problem and go unfixed.

The check runs once in the `node` fixture, and `_xrdcp_tpc` appends the same
verdict to `stderr` on a ztn refusal, so every existing assertion in the module
prints the cause where it already prints the failure.

### §H5 — a source tripwire keyed to a filename

`test_gohep_interop.py::test_static_map_redirect_tripwire` asserted
`brix_find_manager_map` appears in `src/protocols/root/read/stat.c`. The call
moved to `read/stat_manager.c` in 9ab5c3f5 (2026-08-25). The behaviour is
intact; the tripwire had simply stopped testing it and then failed for the wrong
reason. It now asks the op's directory, which is the stable unit — the
guarantee is that the stat path consults the map, not that a particular file
does. `test_static_map_tripwire_ignores_a_mention_in_a_comment` is the
security negative: comments are stripped before matching, so a README line or a
commented-out call cannot certify a redirect path that no longer exists.

### §H6 — two checked-in artifacts that had drifted

`tools/diag/sd_slot_matrix.py` still coded `gsiftp` as absent for `server_copy`
and `server_copy_cred` after the driver grew both; the generated matrix is
regenerated and `--check` is clean (446 implemented cells, was 444).
`tests/golden/cli_baseline.json` carried the pre-`identity:`/`cluster:` help
text for `xrootdfs`; only the `noarg:xrootdfs` entry was recaptured, so the
diff is one line and no unrelated drift was absorbed.

### §H7 — host literals

The lane-wide census went from 38 literals in 14 files to 16 in 7. Every
phase-115 row is cleared: four swapped to `HOST`, eighteen marked
`# net-literal-allow:` with a reason. The remainder belong to the phase-116 and
release-2.0 streams and are theirs to clear; `test_no_hardcoded_hosts.py` stays
red until they do.

### §H8 — a live TLS-trust module raced the phase-116 DNS seam, and its absences went vacuous

`test_audit16y_upstream_tls_verify_live.py` was written on 2026-08-18 against an
upstream that `ngx_parse_url()` resolved at configuration time. Phase-116 moved
`brix_upstream` onto the runtime DNS seam: `src/net/upstream/directives.c`
registers the redirector with `brix_dns_target_register()`, and
`src/net/upstream/start.c` reads it through `brix_dns_target_next()`, which
declines while `naddrs == 0`. `dns_target_arm()` schedules the first lookup
`ngx_random() % DNS_FIRST_JITTER_MS + 1` ms (jitter 200 ms) after worker init
and hands it to the thread pool, so the answer lands some way after the
listener binds. The fixture's `readiness="tcp"` returns at the bind.

Seven of this module's eight planes spell the upstream as `{UP_HOST}` —
`localhost`, a name. In the window between the two moments each of them refuses
every session at `start.c:289` with `brix: upstream: cannot resolve "localhost"`
**before a socket is dialled**. Nothing here is a defect in either stream: the
seam is behaving as I-DNS-1 requires (a name that does not resolve must never
block startup), and the module's trust decisions are still correct once the
answer lands.

What the window exposed is a test defect. Five of the module's assertions are
absences — `"tls-login" not in kinds`, `details("forwarded-request") == []` —
and a leg that never dialled satisfies every one of them. The module could
therefore report green on a run in which no plane ever reached a peer, which is
precisely the shape §H3 had: an assertion with no witness that the thing it
forbids was ever possible.

  * **Success** — the fixture now gates on the leg itself. `_wait_for_leg()`
    drives the export-missing path through the armed default plane until the
    stub records `tls-established`, which nothing but a resolved name, a
    dialled socket and a verified peer produces, and fails with the tail of
    `error.log` if it never does.
    `test_the_leg_is_dialable_once_the_gate_has_passed` asserts the gate rather
    than only relying on it.
  * **Error** — `test_no_plane_is_judged_while_the_upstream_is_unresolved`
    counts `cannot resolve` in `error.log` against the count taken at the gate.
    Any new one means a plane was judged on a leg that never dialled, and names
    that as the reason rather than reporting the plane's verdict as wrong.
  * **Security-negative** —
    `test_an_absence_alone_cannot_tell_a_refusal_from_an_undialled_leg` drives a
    path served from the export beside the refused peer and shows the two carry
    identical absences; only the positive witness separates them. The four
    refusal tests (`test_no_login_reached_the_untrusted_peer`,
    `test_the_client_request_is_never_forwarded`,
    `test_the_wrong_host_peer_sees_no_login`,
    `test_the_opted_out_plane_still_fails_closed`) now each demand one.
  * `test_the_address_literal_plane_never_waited_on_a_name` corroborates the
    mechanism from the other side: `IP_PIN_PORT` is a literal, final at
    registration, so it is the one plane the race cannot reach — and its
    refusal is still the #104 certificate failure, not a resolve failure.

The gate's own first live run is worth recording, because it failed in exactly
the way the gate exists to prevent. A leg that is not ready yet does not merely
answer late — it refuses or drops the session, and the `ConnectionError` from
that propagated straight out of the retry loop, turning a wait into **36 setup
errors** across the whole module. The loop now treats any `ConnectionError` or
`OSError` as a "not yet" and keeps retrying, and
`test_the_gate_absorbs_a_transport_error_but_still_refuses_to_pass` pins both
halves: pointed at a leased port nothing listens on, the gate must survive the
transport error *and* still refuse to let the module proceed, naming the attempt
count and what a silent pass would have meant. Confirmed live: 37/37 on
cf481268.

The lesson generalises past this module: any suite written before phase-116 that
spells a `brix_upstream`, a proxy backend or a mirror as a **name** now has a
readiness question it did not have before, and `readiness="tcp"` does not answer
it. The witness is cheap — one warm-up dial the fixture already knows how to
make.

## Close protocol

This register closes when every `[ ]` above is either `[x]` with a test
reference or delegated to a numbered phase doc listed in Phase 111 §7.4 and in
`00-overview.md`. Items abandoned by decision are marked
`DEFERRED BY DESIGN` with the reason, following the Phase 114 precedent.
