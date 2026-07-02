# Phase 28: Adversarial Hardening — Users, Admins, Bots & Creative Attackers

**Date:** 2026-06-12
**Author:** security threat-model audit
**Status:** PLAN — not yet begun
**Scope:** the module under `src/` only — no nginx-core edits (build governance)
**Companion:** [Phase 27 — Memory-Safety & Anti-Abuse](phase-27-memory-safety-hardening.md)
covers heap/handle leaks + raw resource exhaustion. **This phase covers
*logic-level* abuse**: authn/authz, injection, SSRF, trust, and insider/admin
threats. The two are complementary — neither subsumes the other.

---

## Goal

Treat every input boundary as hostile and every privileged role as potentially
compromised, then close the gaps a **creative** attacker would actually reach
for: argument-injection into helper processes, SSRF to cloud-metadata, trust
poisoning of the cluster redirect path, timing/enumeration side channels, and an
**evil-or-compromised admin** with a too-large blast radius.

The deliverable is a **threat-model-driven hardening roadmap + an adversarial
test suite + abuse telemetry** so the posture is *enforced and observable*, not
just asserted. Each functional fix keeps the repo rule — 3 tests incl. a
**security-negative** — and reuses existing helpers/caps.

---

## Threat Actors & Assets

| Actor | Capability assumed | What they want |
|---|---|---|
| Unauthenticated client | Send arbitrary bytes on any listener | RCE, read/write outside root, crash, redirect to attacker |
| Authenticated user (least-trust) | Valid token/cert/SSS, normal API | Escalate scope, traverse paths, abuse TPC as a proxy, exfiltrate via SSRF |
| Malicious peer (CMS/data node/origin) | Speak the cluster/TPC/proxy protocols | Poison the registry → hijack client redirects; feed evil responses |
| Bot / automated abuser | High request volume, credential stuffing | Resource exhaustion, brute force, enumeration |
| **Compromised / evil admin** | Holds `xrootd_admin_secret`, can call admin API | Repoint proxying to attacker, exfiltrate config/secrets, disable auth, cover tracks |
| Curious insider | Read logs, memory dumps, core files | Harvest secrets (tokens, SSS keys, delegated creds) |

**Assets to protect:** the filesystem behind `root`; client credentials &
delegated tokens the server holds; SSS keytabs & the admin secret; the
integrity of redirect/routing decisions; availability for honest users.

---

## Current Posture (genuinely strong — credit & generalise)

The audit found the security-critical core is **well built**. New work must not
regress these, and should extend their rigor to the edges.

- **Atomic, TOCTOU-free confinement.** `src/path/beneath.c` uses
  `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` (hard-fails build
  on kernels < 5.6). No stat-then-open race, no symlink/magic-link escape. This
  is best-in-class — the gold standard the rest of the plan leans on.
- **JWT done right.** `src/token/validate.c:134` *explicitly rejects `alg:"none"`*
  and any non-RS256/ES256 alg before verification; key selected by `kid` from the
  JWKS (so HMAC/RSA-pubkey **alg-confusion is structurally impossible** — no
  symmetric path exists); `iss`/`aud`/`exp`/`nbf` all enforced (`token_cache.c:38`,
  `validate.c`). ES256 requires exact 64-byte P1363 sig (`signature.c`).
- **S3 SigV4 replay window.** `src/s3/auth_sigv4_verify.c:184–219` rejects clock
  skew (incl. presigned future-skew); signatures must be exactly 64 hex chars
  (`:590`).
- **SSS replay protection.** Timestamp-vs-`sss_lifetime` check, `RAND_bytes`
  nonce, CRC integrity for wrong-key detection (`src/sss/auth_request.c`).
- **Constant-time admin compare + network ACL.** `src/dashboard/api_admin.c:190`
  uses `CRYPTO_memcmp` against the bearer secret and enforces a CIDR allowlist
  (`:198`); body capped at 64 KB.
- **Secret hygiene exists.** `OPENSSL_cleanse`/`ngx_memzero` wipe crypto material
  in `gsi/parse_x509.c`, `sss/auth_request.c`, `token/macaroon.c`.
- **Native-TPC SSRF policy.** `allow_local`/`allow_private` source gates
  (`src/tpc/launch.c`, `src/tpc/noop.c`); WebDAV-TPC curl restricted to
  `CURLPROTO_HTTPS` only (`src/webdav/tpc_curl.c:55,57`).
- **TLS peer verification on** for OCSP (`crypto/ocsp.c:151`) and origin cache
  (`cache/origin_connection.c:197`).
- **Auth brute-force cap** (`gsi/auth.c:357`, `XROOTD_MAX_AUTH_ATTEMPTS`) and the
  pre-allocation per-opcode payload cap table (`connection/recv.c`, from Phase 27).
- **No shell.** Helper processes use `fork`+`execve`/`execlp`/`execvp` — no
  `system()`/`popen()` with a shell, so classic shell-metachar injection is
  already off the table.

So the work below is **edge-hardening and insider-threat reduction**, not a
fix-the-broken-core exercise.

---

## Findings by Attack Class

Severity = exploitability × impact for the named actor. Each cites real code.

### A — Argument / metacharacter injection into helper processes

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| A1 | `src/webdav/tpc_cred.c:176,187` | `execlp("oidc-token","oidc-token","-c",host,…)` — `host` derives from the client-supplied source URL. A value beginning with `-` is parsed as an **option** by oidc-token (argv injection, no shell needed). | High | Insert `"--"` end-of-options before any attacker-derived arg; reject/encode values with a leading `-`; validate host as a strict hostname |
| A2 | `src/webdav/tpc_cred.c:197,200` | `execve(helper, {helper, sockpath, source_url}, NULL)` passes the raw `source_url` to a credential helper. | Med | Same `--`/leading-dash defense; canonicalise+validate URL first |
| A3 | `src/webdav/tpc_cred.c:288–325` | `curl_argv[16]` built for the rfc8693 exchange; if any attacker-derived value (URL, token) lands in argv without `--`, curl flags like `-o`/`-K`/`--config` enable **file write / file read (SSRF-by-config)**. | High | Hard `--` terminator before URLs; never let user data occupy an argv slot that precedes a flag; prefer a fixed-arg helper over building curl argv |
| A4 | `src/tpc/tpc_token.c:125` | `fork`+`execve`/`execlp oidc-token` token helper — same argv-position discipline needed. | Med | `--` terminator; arg validation |

The fork/exec design is correct (no shell); the gap is **option-injection via
attacker-controlled argv values**, which `--` + leading-dash rejection closes.

### B — SSRF & confused-deputy (the server fetching on an attacker's behalf)

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| B1 | `src/tpc/launch.c`, `src/webdav/tpc_curl.c:52` | TPC source host comes from the client. `allow_private` gates RFC1918 but there is **no explicit block of link-local `169.254.0.0/16` / cloud-metadata `169.254.169.254` / `::1` / `0.0.0.0`** (no literal found anywhere in src). An attacker points TPC/copy at the metadata endpoint → credential theft. | High | Default-deny destination IP classes: loopback, link-local, metadata, multicast, unspecified, ULA `fc00::/7`; apply to **both** native-TPC and curl paths |
| B2 | `src/webdav/tpc_curl.c` | Host is validated/policy-checked, then curl **re-resolves DNS** and connects → **DNS-rebinding TOCTOU**: policy sees a public IP, curl connects to an internal one. | High | Resolve once, validate the *resolved* IP set, pin curl to it (`CURLOPT_RESOLVE`/`OPENSOCKETFUNCTION`); re-check post-resolution |
| B3 | `src/webdav/tpc_curl.c:63–72,275–287` | Sets `SSLCERT/SSLKEY/CAINFO/CAPATH` but **does not explicitly set `CURLOPT_SSL_VERIFYPEER=1` / `VERIFYHOST=2`** — relies on curl's compiled default. A build/default change silently disables verification. | Med | Set both explicitly; never expose a "disable verify" knob |
| B4 | `src/webdav/tpc_cred.c`, `src/tpc/*` | **Confused deputy:** the server uses *its own* delegated credential/token to fetch a *client-named* source → client redirects the server's privileged identity at an unintended target. | Med | Bind the delegated credential's usable audience/host to the request's intended source; refuse cross-target reuse |
| B5 | `src/cache/origin_connection.c`, `src/proxy/*`, `src/mirror/*` | Origin/upstream/mirror targets — confirm they are **config-fixed**, never request-derived; if any path lets a header pick the upstream, it is SSRF. | Med | Audit; assert upstream selection is config-bound only |

### C — Trust & redirect poisoning (cluster/PKI integrity)

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| C1 | `src/manager/registry.c`, `src/cms/server_recv.c:306` | A data node self-reports `host:port:paths` at CMS login; the manager later **redirects clients to that host** (`src/read/locate.c:60,78,116`). A rogue/spoofed node registers an attacker host → clients (and their credentials) are redirected to the attacker. | High | Authenticate CMS registration (shared secret / mTLS on the cms port); validate the advertised host against an allowlist / the peer's connecting IP; rate-limit + alert on registration churn |
| C2 | `src/read/locate.c:116` | Redirect host string is emitted from registry data onto the wire — ensure it cannot contain control bytes / be a different scheme. | Low | Validate host syntax before emit (reuse `xrootd_sanitize_log_string`-style validation for wire host) |
| C3 | `src/crypto/ocsp.c`, `src/token/jwks.c` | OCSP/CRL freshness and JWKS refresh: a stale/again-trusted revoked cert or rotated-out JWK key widens the window for a stolen credential. | Med | Define max-staleness; fail-closed on OCSP "unknown" for high-value ops; periodic JWKS refresh with bounded cache age |

### D — AuthN/Z bypass & side channels

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| D1 | `src/s3/auth_sigv4_verify.c:581` | Final SigV4 signature comparison — confirm it uses **`CRYPTO_memcmp`**, not `strcmp`/`memcmp` (the file uses `strcmp` for cache-key/region at `:270`). Non-constant-time compare of an HMAC is a (low-but-real) timing channel. | Low-Med | Constant-time compare for the signature itself |
| D2 | cross-cutting | **Deny-by-default audit:** every handler must reach a default-deny if no auth/ACL rule matches. The global `allow_write` gate is correctly checked before serving writes (`src/read/open_request.c:253`) — extend the same "explicit allow required" audit to *every* op (stat, locate, dirlist, fattr, query). | Med | Matrix test: each op × (no-auth, wrong-scope, wrong-VO) must 403/NotAuthorized |
| D3 | `src/path/authdb.c:50` | The `k` → `XROOTD_AUTH_ADMIN` privilege bit — verify it is never implicitly granted and that ADMIN ⇏ all-paths without an explicit path scope. | Med | Test ADMIN bit is path-scoped, not global |
| D4 | auth paths | **User enumeration / timing:** do auth failures differ (message or timing) between "unknown user" and "bad credential"? GSI rate-limit helps; token/SSS/S3 should return a **uniform** failure + constant-ish work. | Low-Med | Uniform auth-failure response; avoid early-out timing divergence on secret-bearing compares |
| D5 | `src/sss/auth_request.c`, S3 | Replay is window-bounded (timestamp/skew) but there is **no nonce cache** — replay *within* the window is possible for non-idempotent ops. | Low | Optional short-TTL nonce cache for mutating ops where replay matters |

### E — Malicious / compromised admin (blast-radius reduction)

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| E1 | `src/dashboard/api_admin.c`, dynamic upstream/proxy (Phase 23) | A holder of `admin_secret` can **repoint proxying/upstreams** (potentially to an attacker host) and exfiltrate traffic. Single secret = single point of total compromise. | High | (a) Append-only, tamper-evident **admin audit log** of every mutation (who/when/what/from-IP); (b) bound admin-settable upstream targets to an allowlist; (c) require the CIDR ACL *and* the secret (defense-in-depth, already partly present) |
| E2 | `src/dashboard/module.c:103` | `admin_secret` default is `""` → if the directive is omitted the API is correctly disabled (`api_admin.c:175`), but a weak/static secret never rotates. | Med | Support secret rotation + minimum-length enforcement at config time; warn on short secrets |
| E3 | admin API | No **separation of duties** — read-dashboard vs write-admin share posture. | Low-Med | Distinct read vs mutate credentials/scopes |
| E4 | logging | Admin actions and config must **never log the secret/tokens**; confirm. | Med | Secret-redaction lint over log call sites |

### F — Secret handling & information disclosure

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| F1 | cross-cutting | `OPENSSL_cleanse` is used in gsi/sss/macaroon but **not necessarily everywhere** secrets live (delegated tokens, admin secret buffer, JWKS private material, SSS clear blocks on all paths). | Med | Audit every secret buffer → cleanse on all exits; never leave on the stack/pool |
| F2 | error paths | Error messages must not leak absolute filesystem paths, internal hostnames, or which auth step failed, to unauthenticated clients (they may to logs). | Med | Two-tier errors: detailed to log, generic to wire |
| F3 | core dumps / `/proc` | Long-lived secrets in worker memory are exposed via a core dump or memory read. | Low | `madvise(MADV_DONTDUMP)` for secret pages; disable core dumps for workers; `mlock` keytab/admin secret |

### G — Abuse, bots & algorithmic complexity (adversarial DoS)

Mostly Phase 27 territory; the *adversarial* additions:

| # | Area | Issue | Sev | Guard |
|---|------|-------|-----|-------|
| G1 | `src/webdav` PROPFIND `Depth: infinity`, dead-props XML | Deep/recursive WebDAV traversal and nested XML are amplification vectors. | Med | Cap `Depth`, XML nesting depth & entity count; reject `Depth: infinity` on large trees |
| G2 | per-identity flooding | Auth-attempt cap exists, but no **per-identity request-rate / concurrency cap** for authenticated floods. | Med | Reuse the rate-limit infra (Phase 25) keyed by identity; connection caps per source |
| G3 | TPC/readv amplification | A small request triggers large server-side I/O/egress (TPC pull, readv coalescing). | Med | Per-identity concurrent-TPC and aggregate-bytes quotas |

---

## Hardening Workstreams

Sequenced so detection lands before the riskier behavioral changes.

### H1 — Untrusted-input → subprocess argv safety (A1–A4)
New helper `src/shared/argv_guard.h`: `xrootd_argv_is_safe(s)` (rejects leading
`-`, NULs, control bytes) and a convention to **always emit `"--"`** before the
first attacker-derived argv element. Refactor `tpc_cred.c` / `tpc_token.c` to a
fixed-shape argv with a hard option terminator. Prefer a single purpose-built
helper binary over assembling `curl` argv from user data.

### H2 — Egress / SSRF policy engine (B1–B5)
New `src/shared/egress_policy.{c,h}`: given a target host/URL, resolve once,
classify every resolved IP, and **default-deny** loopback / link-local /
metadata / multicast / unspecified / ULA unless explicitly allowed; pin the
connection to the validated IP set (anti-rebind). Route **all** outbound fetches
(native TPC, WebDAV-TPC curl, credential helpers, origin cache, mirror) through
it. Explicitly set `CURLOPT_SSL_VERIFYPEER=1`/`VERIFYHOST=2` and forbid a
disable knob. Bind delegated credentials to the intended target (B4).

### H3 — Cluster trust: authenticated registration & redirect validation (C1–C3)
Require a shared secret or mTLS on the `xrootd_cms_server` port before a node may
register; validate the advertised redirect host against an allowlist and/or the
peer's connecting address; rate-limit registration churn and surface it in
`/metrics`. Validate every host string before it is emitted on a redirect.
Define OCSP/JWKS max-staleness and fail-closed posture for high-value ops.

### H4 — Authz consistency & constant-time compares (D1–D5)
Make the S3 signature compare constant-time (D1). Build a **deny-by-default
authorization matrix test** (op × identity-class) as the enforcement mechanism
(D2/D3). Standardise a uniform auth-failure response + reduce timing divergence
(D4). Optional nonce cache for mutating ops (D5).

### H5 — Admin blast-radius & audit (E1–E4)
Append-only, tamper-evident admin audit log (hash-chained) of every mutation;
allowlist admin-settable upstream targets; config-time minimum-secret-length +
rotation support; secret-redaction lint over all log sites; optional read/write
credential split.

### H6 — Secret lifecycle & disclosure (F1–F3)
Audit every secret buffer for `OPENSSL_cleanse` on all exits; two-tier error
messages (verbose→log, generic→wire); `MADV_DONTDUMP` + core-dump disable +
`mlock` for long-lived secret pages.

### H7 — Adversarial abuse controls (G1–G3)
Cap WebDAV `Depth`/XML nesting/entity count; per-identity rate & concurrency
limits (reuse Phase 25 limiter) and per-identity TPC/byte quotas.

### H8 — Assurance: red-team test suite + fuzz + threat-model doc (the keystone)
- `tests/test_security_redteam.py`: positive **and** security-negative cases for
  every finding — argv-injection (`source=-oXXX`), SSRF to `169.254.169.254` and
  `127.0.0.1`, DNS-rebind, alg-confusion/`alg:none`, expired/forged tokens, S3
  replay, SSS replay, path-traversal (`..`, encoded, symlink, magic-link),
  registry-poisoning redirect, admin without secret / wrong CIDR, oversized
  Depth/XML.
- Fuzz the **auth/credential parsers** (Phase 27 W7 corpus extended): JWT header,
  SigV4 canonical request, SSS packet, GSI buckets, macaroon caveats.
- A living `docs/07-security/threat-model.md` (STRIDE per listener) kept in sync;
  a **secure-defaults checklist** (Appendix B) reviewed each release.

---

## New Files / Helpers

| File | Purpose | Build impact |
|---|---|---|
| `src/shared/argv_guard.h` | leading-dash/control-byte rejection, `--` discipline (H1) | header-only, no `./configure` |
| `src/shared/egress_policy.{c,h}` | resolve-and-classify SSRF gate, anti-rebind (H2) | **new `.c` → register in `src/core/config/config.h`, run `./configure`** |
| `tests/test_security_redteam.py` | adversarial pos/neg suite (H8) | test-only |
| `tests/fuzz/fuzz_auth_*.c` | auth-parser fuzz targets (H8) | standalone |
| `docs/07-security/threat-model.md` | STRIDE threat model + secure-defaults checklist | docs |

Most behavioral fixes are edits to existing files routed through H1/H2 helpers.

---

## Sequencing & Effort

1. **H8 first (partial)** — stand up `test_security_redteam.py` with the
   *expected-secure* assertions; several will already pass (confinement,
   alg:none) and lock in the good behavior, the rest become the worklist.
2. **H2 + H1** — SSRF engine and argv safety (highest external impact: B1–B3, A1–A3).
3. **H3** — cluster trust (C1 redirect poisoning).
4. **H4 + H5** — authz matrix + admin audit/blast-radius.
5. **H6 + H7** — secret lifecycle + adversarial abuse controls.

Effort: H8-bootstrap ~1 day; H1 ~1 day; H2 ~2–3 days (resolve/classify/pin +
wiring every egress path); H3 ~2 days; H4 ~1–2 days; H5 ~2 days; H6 ~1–2 days;
H7 ~1–2 days. Highest ROI: **H2 (SSRF) and H3 (registry poisoning)** — both are
externally reachable, high-impact, and currently un-gated at the edges.

---

## Verification

```bash
# Build (egress_policy adds a .c → configure once)
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)

# Red-team suite — every finding has a security-negative test
PYTHONPATH=tests pytest tests/test_security_redteam.py -v
# e.g. must all be rejected:
#   TPC source = http://169.254.169.254/...        -> blocked (B1)
#   TPC source host = "-oEvil"                       -> blocked (A1)
#   JWT alg=none / alg=HS256-with-pubkey             -> rejected (validate.c:134)
#   path = /../../etc/passwd (raw/encoded/symlink)   -> NotAuthorized (beneath.c)
#   rogue CMS register host=attacker                 -> not redirected (C1)
#   admin API w/o secret or wrong CIDR               -> 401/403 (E1)

# Confinement regression (must stay green — it already passes)
PYTHONPATH=tests pytest tests/ -k "traversal or confine or auth" -v

# Fuzz the auth parsers under ASAN (shares Phase 27 W6 sanitizer build)
for t in tests/fuzz/fuzz_auth_*; do "$t" -runs=500000 -max_total_time=180 corpus/; done

# Secret-redaction + argv lint
tests/lint_secrets.sh && tests/lint_argv.sh   # exit 0
```

Every behavioral change ships with **success + error + security-negative**
tests, per the repo rule.

---

## Risk Assessment

- **H2 egress policy can break legitimate transfers** (e.g. an on-prem TPC source
  on RFC1918). It must be **policy-configurable** (extend the existing
  `allow_private`/`allow_local` knobs) with safe defaults, not a hard block —
  default-deny metadata/loopback always, RFC1918 per-config.
- **H3 CMS auth changes the cluster handshake** — must stay wire-compatible with
  real `cmsd` (see [[cms_real_protocol_wire_spec]]); validate against the
  `tests/test_cms_mesh_interop.py` mesh before/after.
- **H1 `--` insertion** assumes the helpers honor end-of-options (oidc-token,
  curl do); verify per helper.
- Constant-time / timing changes (D1/D4) must be measured, not assumed.
- Most helpers are additive; `egress_policy.c` is the only new build unit.

## Rollback

H1/H4(compare)/H6/H8 are additive (headers, tests, lint, cleanse calls) and
revert cleanly. H2 is gated behind config flags — disable to restore prior
behavior. H3/H5/H7 are per-feature and revertible individually under the 3-test
rule. No nginx-core files are touched.

---

## Appendix A — External-input → action surface (audit map)

| Listener | Untrusted input | Reaches | Primary risk |
|---|---|---|---|
| `root://` stream | opcode + `dlen` + path + auth blob | confinement, registry, TPC | traversal, registry poison, SSRF |
| WebDAV `davs://` | method, headers, XML body, `Source:`/`Credential:` | curl TPC, dead-props, copy | SSRF, argv-inj, XML amplification |
| S3 REST | SigV4 headers, multipart, copy-source | object store, copy | replay, traversal, SSRF |
| CMS port | login + register (`host:port:paths`) | manager registry → redirects | **redirect poisoning** |
| TPC source | source URL/host | `execve`/curl/native connect | **SSRF + argv injection** |
| Admin API | bearer secret + JSON body | dynamic upstreams/proxy | **evil-admin repointing** |

## Appendix B — Secure-defaults checklist (review each release)

- [ ] Egress: metadata/loopback/link-local **denied by default**; RFC1918 opt-in.
- [ ] curl: `SSL_VERIFYPEER=1`, `VERIFYHOST=2`, protocol-restricted; no disable knob.
- [ ] All attacker-derived argv preceded by `--`; no leading-dash values.
- [ ] CMS registration authenticated; advertised host allowlisted.
- [ ] JWT: `alg:none`/symmetric rejected; `iss`/`aud`/`exp`/`nbf` enforced. *(present)*
- [ ] Confinement: `openat2 RESOLVE_BENEATH|NO_MAGICLINKS` on every open. *(present)*
- [ ] Secret compares constant-time (admin ✓, token ✓ via EVP, S3 → fix).
- [ ] Every op default-denies without an explicit allow.
- [ ] Admin mutations audited (append-only) + target-allowlisted; secret ≥ min len.
- [ ] Secrets `OPENSSL_cleanse`d on all exits; never logged; pages `MADV_DONTDUMP`.
- [ ] WebDAV `Depth`/XML nesting/entity counts capped.
- [ ] Per-identity rate + concurrency + TPC byte quotas enforced.
