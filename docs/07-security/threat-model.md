# Threat Model & Security Posture

This document records the adversarial threat model for the BriX-Cache gateway, the
controls already in place, the hardening delivered in **Phase 28**, and the items
explicitly deferred. It is the companion to `docs/refactor/phase-28-adversarial-hardening.md`.

## Threat actors

| Actor | Capability | Primary concern |
|---|---|---|
| Unauthenticated client | Reach any listener (root://, davs://, S3, /metrics, CMS port) | Path traversal, auth bypass, DoS |
| Authenticated user | Valid token / cert / S3 key, scoped | Privilege escalation beyond scope, SSRF via TPC |
| Malicious CMS peer | Can connect to the manager's CMS port | Redirect poisoning (steer clients to a rogue data node) |
| Bot / abusive client | High request volume | Algorithmic & volumetric DoS |
| Compromised admin | Holds the admin API credential | Blast radius — redirect traffic, exfiltrate |
| Curious insider | Host/log/core access | Secret disclosure at rest |

## Attack surface at a glance

Every listener is a front door; each has a primary threat and the control that
closes it:

```text
   EXTERNAL                  LISTENER                  PRIMARY THREAT → CONTROL
  ──────────                ──────────                ─────────────────────────
  anon client ──▶ root:// / roots:// ──▶ path traversal → openat2 RESOLVE_BENEATH
  user+token  ──▶ davs:// (WebDAV)   ──▶ scope escalation → token scope + authdb
  user+key    ──▶ S3 REST            ──▶ key enum / replay → SigV4 constant-time
  TPC source  ──▶ (outbound from us) ──▶ SSRF / DNS-rebind → net_target + RESOLVE pin
  cmsd peer   ──▶ CMS manager port   ──▶ redirect poisoning → sss + CIDR + host-validate
  scraper     ──▶ /metrics, /healthz ──▶ info leak → low-cardinality, PII-free
  admin       ──▶ admin API          ──▶ blast radius → CIDR ACL + allowlist + audit
                                          │
                       ┌──────────────────┴───────────────────┐
                       │  shared cross-cutting controls        │
                       │  rate limit · log sanitize · XXE off  │
                       │  per-principal concurrency cap        │
                       └───────────────────────────────────────┘
```

## Already-strong controls (pre-Phase-28)

These were verified during the Phase 28 audit and require no further work:

- **Kernel path confinement** — `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` via
  `src/fs/path/beneath.c`; the `*at()` parent-confinement fix closes mkdir/rename/unlink escapes.
- **Native root:// TPC SSRF gating** — `src/tpc/outbound/connect.c`, `src/tpc/engine/launch.c` via
  `src/core/compat/net_target.c` (blocks loopback / link-local / 169.254 / RFC-1918 / ULA, gated
  by `tpc_allow_local` / `tpc_allow_private`).
- **S3 SigV4** — constant-time `CRYPTO_memcmp` signature compare; replay window enforced.
- **Admin API** — `CRYPTO_memcmp` secret, CIDR ACL, 64 KB body cap, structured audit log.
- **PROPFIND** — Depth:infinity entry cap + XXE disabled (`XML_PARSE_NONET|XML_PARSE_NO_XXE`).
- **Rate limiting** — per-identity leaky buckets keyed on VO / issuer / DN / IP / volume.
- **Log/error hygiene** — `xrootd_sanitize_log_string` / `xrootd_log_safe_path`; no secrets
  or absolute paths leaked to unauthenticated clients.
- **AuthDB ADMIN ('k') privilege is path-scoped** — `xrootd_check_authdb_identity` matches
  each rule against the resolved path prefix *and* the needed privilege bits, so 'k' grants
  admin only within the rule's path subtree (audited; not global).

## Phase 28 hardening delivered

### W1 — CMS registration redirect poisoning (CRITICAL) — vanilla-compatible

The manager's CMS port previously admitted any peer's self-reported host:port:paths into the
server registry, which then drove client redirects. Three layered controls, each compatible
with stock XRootD cmsd:

```text
   THE ATTACK                              THE THREE-LAYER DEFENSE
   ──────────                              ───────────────────────
  rogue peer ─LOGIN─▶ manager          peer ──▶ ① CIDR allowlist (W1b)
  "I serve /atlas at evil:1094"               │   off-list IP rejected at accept
         │                                    ▼
         ▼ (before)                      ② sss kYR_xauth (W1a)
  registry stores evil:1094                   manager demands valid sss cred vs
         │                                    keytab; no cred ⇒ never admitted
         ▼                                    ▼
  client locate /atlas                   ③ host-char validation (W1c)
         │                                    reject control bytes at the single
         ▼                                    xrootd_srv_register choke point
  REDIRECT ──▶ evil:1094  ✗ poisoned          ▼
                                         only clean, authenticated peers enter
                                         the registry → no redirect poisoning ✓
```

- **W1a — sss cluster authentication.** Implements the real cmsd `kYR_xauth` handshake
  (`XrdCmsLogin::Admit` → `getToken`+`Authenticate`): after the data node's LOGIN frame the
  manager sends its security parms and defers registration until the node returns a valid
  **sss credential**, verified against a shared keytab (`xrootd_cms_server_sss_keytab`). The
  verifier is the shared `xrootd_sss_verify_blob` (same XrdSecProtocolsss credential format as
  the XRootD client protocol). Like vanilla cmsd, sss is required only when a keytab is
  configured — **fail-closed in sss mode, back-compat otherwise**. `src/net/cms/server_auth.c`.
- **W1b — CIDR allowlist.** `xrootd_cms_server_allow <cidr>...` rejects unauthorised peer IPs
  at accept time (`ngx_cidr_match`). Default back-compat (no list ⇒ accept + one-time warning).
- **W1c — host validation.** `xrootd_net_host_chars_valid` rejects any registry host that is
  not a clean hostname/IP literal, enforced at the single store choke point
  (`xrootd_srv_register`), which protects every redirect-emit path from control-byte injection.

### W2 — WebDAV TPC DNS-rebind + TLS verification (HIGH)

`src/protocols/webdav/tpc_curl.c` `tpc_curl_secure()` now (a) sets `CURLOPT_SSL_VERIFYPEER=1` /
`VERIFYHOST=2` explicitly rather than relying on curl defaults, and (b) resolves the target
once under SSRF policy and pins the validated address via `CURLOPT_RESOLVE`
(`xrootd_net_target_check_dns_pin`), so curl cannot re-resolve to a rebind address. Applied to
single, multi-stream, and HEAD paths.

### W3 — Helper-exec argv option-injection (MEDIUM)

`oidc-token`'s client-derived host argument is rejected if it begins with `-`
(`src/protocols/webdav/tpc_cred.c`); the curl token-exchange builders place a `--` end-of-options
terminator before the endpoint URL in `tpc_cred.c` and `src/tpc/outbound/tpc_token.c`.

### W4 — STATX authorization parity (MEDIUM)

`src/protocols/root/read/statx.c` now applies the authdb check (`XROOTD_AUTH_LOOKUP`) that single-path STAT
already enforced, so a batched statx cannot leak metadata for an authdb-denied path. Denials
fall through to the per-entry "inaccessible" sentinel.

### W5 — S3 access-key side channel (MEDIUM)

`src/protocols/s3/auth_sigv4_verify.c` defers the access-key match into a `key_ok` flag and folds it into
the final constant-time signature decision: an unknown key and a bad signature now traverse the
same HMAC work and return the identical `SignatureDoesNotMatch`/403 — no timing or message
oracle for key enumeration.

### W6 — Admin blast radius & secret hygiene (MEDIUM/LOW)

- `xrootd_admin_proxy_allow <host>...` restricts dynamic proxy backends to an allowlist; an
  off-allowlist target is 403 + audited (`host_not_allowed`).
- Admin secrets shorter than 16 bytes are rejected at config load.
- The transient stack copy of the admin secret is `OPENSSL_cleanse`-d.

### W7 — Per-principal concurrency limit (MEDIUM)

`xrootd_concurrency_limit zone=.. key=.. limit=N` caps in-flight requests per principal
(VO/issuer/DN/IP/volume) via a SHM counter. The slot is acquired in the HTTP access phase and
released in the **log phase**, which runs for every finalized request (including errors and
aborts) — so the counter cannot leak and lock out a principal. `src/net/ratelimit/`.

### W8 — Hygiene

- PROPFIND XML parsing carries an explicit guard comment: the safe flag set is intentional and
  `XML_PARSE_HUGE` must never be added without a separate size bound (billion-laughs defense).
- ADMIN ('k') path-scope audited (already scoped — see above).

## Deferred / operational recommendations

These are documented rather than enforced in code, by deliberate choice:

- **Stream-plane concurrency cap & per-identity TPC byte quota.** W7 covers the HTTP plane
  (the primary unbounded-transfer surface). The stream plane has no log phase, so a leak-free
  release point needs the connection-close path; deferred.
- **Core-dump suppression** (`prctl(PR_SET_DUMPABLE,0)`, `RLIMIT_CORE=0`, `MADV_DONTDUMP`).
  Not enabled by default because it interferes with operational debugging and ptrace; operators
  who handle long-lived secrets should set `ulimit -c 0` / `fs.suid_dumpable=0` at the unit level.
- **cmsd sss with gsi/krb5** — only the sss security protocol is implemented for the cluster
  handshake; gsi/krb5 within cmsd are out of scope.
- **JWKS HTTP auto-refresh / rotation** — JWKS is loaded from disk at config time; rotate by
  reloading nginx. OCSP "unknown" honors the configured `soft_fail` posture.

## Verifying the posture

See `tests/test_security_redteam.py` for the config-level negative-path regression suite, and
`tests/test_cms_mesh_interop.py::TestCmsSssAuth` for the live CMS sss fail-closed test — an
`xrootd_cms_server_sss_keytab` manager refuses a real cmsd data node that does not present a
valid sss credential (the node connects but is never admitted to the registry, so a locate
returns no redirect). That topology is built and gated by the standard mesh lifecycle
(`manage_test_servers.sh start-all` → `cms_mesh_servers.py`), so it runs with the rest of the
suite. Build and run per `CLAUDE.md` BUILD & TEST.

> The *positive* direction (a real cmsd presenting a valid sss credential and registering) is
> site-specific: it requires the cmsd's own client-side sss to be configured (`all.seclib` +
> `sec.protocol sss` + a reachable keytab) such that `XrdCmsSecurity::Configure` receives the
> config file. The nginx manager side — keytab load and the `kYR_xauth` challenge — is verified
> independently; only the real-cmsd client configuration is environment-dependent.
