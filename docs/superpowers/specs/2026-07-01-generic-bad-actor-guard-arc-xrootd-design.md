# Generic bad-actor MITM guard — ARC + XRootD front-end

**Date:** 2026-07-01
**Status:** design approved, plan pending
**Implementation plan:** `docs/refactor/phase-65-generic-bad-actor-guard.md`

---

## 1. Problem

We run an nginx instance in front of grid data services that speak an HTTP-like
protocol (NorduGrid **ARC**) and, separately, in front of a real **XRootD**
instance (`root://` binary stream + XrdHttp/WebDAV HTTP surface). These backends
are exposed to the open internet and take constant hostile noise: bots probing
for `*.php` / `/wp-login` / `/.env`, path enumeration, credential-stuffing. The
noise both wastes backend cycles and destabilises the service under connection
churn.

We want nginx to:

1. **Terminate TLS legitimately** — it holds the service host cert and presents
   it to clients — inspect each request in cleartext, and **forward the client's
   credentials (X.509 proxy cert / bearer token) to the backend** so the backend
   still performs the real user authentication.
2. **Bounce the single offending request** (403/444, or a TCP drop on the stream)
   when it is unambiguous junk.
3. **Emit a structured, greppable log line for every bad-actor signal** so
   **fail2ban** tails it and installs the durable nftables/iptables ban. nginx is
   *not* the firewall; fail2ban is.

The same bad-actor logic must work in front of **both** ARC and a real XRootD
instance, factored generically rather than duplicated.

## 2. Decisions (locked)

| # | Decision |
|---|---|
| D1 | **TLS terminates at nginx** using the service host cert; client cert forwarded to backend as a header, `Authorization` passed through. Backend does the real auth. |
| D2 | **Log-driven enforcement.** nginx classifies → emits one structured line per signal → bounces only the offending request. fail2ban does the durable IP bans. |
| D3 | **All four signals in scope:** junk/scanner signatures (pre-backend), namespace-grammar violations (pre-backend), backend 404/non-existent-path storms (post-response), auth-failure/credential abuse (post-response). |
| D4 | **Proxying uses stock `ngx_http_proxy_module`** (`proxy_pass`). Our module adds only classify (ACCESS phase) + audit (LOG phase) + credential-forwarding config + the ARC/XRootD decode. No bespoke HTTP proxy. |
| D5 | **Protocol-agnostic guard core + thin adapters.** Bad-actor logic, audit format, rule config live once in `src/guard/` (pure C, no nginx). Adapters normalize their wire form into one `guard_request_t`. |
| D6 | **Three surfaces guarded:** ARC-HTTP, XrdHttp/WebDAV-HTTP (same nginx module, different `profile`), and `root://` stream (via existing `src/relay` + `src/tap`, enforcement = drop connection). |

## 3. Architecture

```
                    ┌───────────── src/guard/ (pure C, no nginx, unit-testable) ─────────────┐
                    │  guard_request_t {ip, proto, op, path, cred_present, outcome, status}   │
   ARC-HTTP adapter │  guard_classify_pre()  → ALLOW | BOUNCE:{signature|grammar}             │
   XrdHttp adapter ─┤  guard_classify_post() → {NONE|notfound|authfail}  (log-only signal)    │
   (one nginx http  │  guard_audit_format()  → one JSON line → shared audit log → fail2ban     │
    module, profile)│  guard_ruleset_t: signatures + per-proto grammar + outcome toggles      │
                    └────────────────────────────────────────────────────────────────────────┘
   root:// adapter ─► reuse src/tap decode → guard_request_t → verdict → close/RST connection
   (src/relay tap)
```

### 3.1 Guard core — `src/guard/`

Pure C, no nginx / no allocation / no OpenSSL, matching the `src/tap/` discipline
so it unit-tests standalone.

```c
typedef enum { GUARD_OP_READ, GUARD_OP_WRITE, GUARD_OP_LIST, GUARD_OP_DELETE,
               GUARD_OP_JOBCTL, GUARD_OP_STAGE, GUARD_OP_INFO, GUARD_OP_DELEG,
               GUARD_OP_HANDSHAKE, GUARD_OP_UNKNOWN } guard_op_class_t;

typedef enum { OUTCOME_PENDING, OUTCOME_OK, OUTCOME_NOTFOUND,
               OUTCOME_AUTHFAIL, OUTCOME_ERROR } guard_outcome_t;

typedef enum { GUARD_ALLOW, GUARD_BOUNCE } guard_verdict_t;
typedef enum { GUARD_R_NONE, GUARD_R_SIGNATURE, GUARD_R_GRAMMAR,
               GUARD_R_NOTFOUND, GUARD_R_AUTHFAIL } guard_reason_t;

typedef struct {
    const char       *ip;          /* remote_addr, adapter-supplied */
    const char       *proto;       /* "arc" | "xrdhttp" | "root" */
    guard_op_class_t  op;
    const char       *path;  size_t path_len;   /* sanitized at the adapter edge */
    int               cred_present;
    guard_outcome_t   outcome;     /* PENDING pre-backend; set post-response */
    int               status_code;
} guard_request_t;
```

Functions:

- `guard_verdict_t guard_classify_pre(const guard_ruleset_t*, const guard_request_t*, guard_reason_t *why)`
  — the only judgement possible before the backend: **signatures** (blocklist of
  `*.php`, `/wp-`, `/.env`, `/.git`, `/cgi-bin`, `/phpMyAdmin`, bogus methods) and
  **grammar** (path must start with a valid prefix, op must be allowed). Sets
  `*why` to `SIGNATURE` or `GRAMMAR` on BOUNCE.
- `guard_reason_t guard_classify_post(const guard_ruleset_t*, const guard_request_t*)`
  — maps `outcome` to `NOTFOUND` / `AUTHFAIL`, else `NONE`. Never bounces (the
  response already went out); exists to feed the audit line.
- `guard_signature_match(const guard_ruleset_t*, const char *path, size_t)` —
  suffix/prefix/substring match against the ruleset (defaults + operator adds).
- `guard_grammar_ok(const guard_ruleset_t*, guard_op_class_t, const char*, size_t)`.
- `size_t guard_audit_format(const guard_request_t*, guard_reason_t, char *out, size_t)`
  — single-line record (see §6), mirroring `src/tap/tap_audit.c`. Pure, no I/O.

`guard_ruleset_t` holds: signature patterns, per-protocol grammar (valid prefixes
+ allowed op-classes), and outcome-flag toggles. Adapters build it from nginx
directives; unit tests build it from literals.

### 3.2 HTTP adapter — `ngx_http_xrootd_guard_module` (ARC + XrdHttp)

One module, two profiles selected by `xrootd_guard_profile arc|xrdhttp` (grammar
differs; mechanism identical).

- **ACCESS phase handler** — build `guard_request_t` from `r`:
  `ip=$remote_addr`, `op` = method × profile mapping, `path=r->uri` (run through
  `xrootd_sanitize_log_string()` at this edge — INVARIANT: sanitize wire strings),
  `cred_present` = (`$ssl_client_verify != NONE`) OR non-empty `Authorization`.
  Call `guard_classify_pre`. **BOUNCE** → stash reason in the request ctx, return
  `xrootd_guard_bounce_status` (default 444) — backend never touched. **ALLOW** →
  `NGX_DECLINED`, stock `proxy_pass` runs.
- **LOG phase handler** — set `outcome` from the upstream/response status
  (`404→NOTFOUND`, `401|403→AUTHFAIL`, `2xx/3xx→OK`), call `guard_classify_post`.
  If a pre-bounce reason **or** a post-signal is set, append
  `guard_audit_format(...)` to the audit log.
- **Credential forwarding** — operator config wires
  `ssl_certificate <host-cert>`, `ssl_verify_client optional_no_ca`,
  `proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert`, and lets
  `Authorization` pass through. The module never invents header keys; it only
  reads verify state to set `cred_present`.

### 3.3 Stream adapter — extend `src/relay/`

The relay already feeds a per-direction `xrootd_tap_stream`. Add a guard sink:

- **C2U frame** → `guard_request_t` (`op` from opcode via a small opcode→op-class
  table, `path` from `frame->path` sanitized, `cred_present` from login state) →
  `guard_classify_pre`. **BOUNCE** ⇒ mark the relay to **close/RST the connection**
  after writing the audit line.
- **U2C frame** → `frame->status`: `kXR_NotFound→OUTCOME_NOTFOUND`,
  `kXR_NotAuthorized→OUTCOME_AUTHFAIL` → `guard_classify_post` → audit line.
- **Signatures on the stream** = non-XRootD garbage handshakes / invalid opcodes.
- **Limitation:** `roots://` bulk-TLS is opaque to the tap, so stream guarding
  there is connection-level only — the same limitation the existing relay has.
  Cleartext `root://` gets full frame-level guarding.

All three adapters write to **one shared audit log** in one schema.

## 4. Credential forwarding

- **HTTP:** terminate with the host cert; `ssl_verify_client optional_no_ca`
  accepts a grid proxy-cert chain without a local CA and defers real validation to
  the backend. Client cert PEM → `X-SSL-Client-Cert`; bearer `Authorization`
  passes through. Backend does the real auth.
- **Stream:** true end-to-end passthrough — the relay never terminates the XRootD
  auth handshake; GSI/token/SSS creds flow verbatim. The guard reads login state
  only to set `cred_present`.

## 5. Configuration directives

Registered in the top-level `./config` source/command lists (per repo build rule).

**HTTP guard (http/server/location):**

| Directive | Default | Purpose |
|---|---|---|
| `xrootd_guard on\|off` | off | enable ACCESS+LOG guard |
| `xrootd_guard_profile arc\|xrdhttp` | — | grammar defaults + `proto` label |
| `xrootd_guard_valid_prefix <path>` | (profile) | repeatable; valid namespace roots |
| `xrootd_guard_valid_method <m>…` | (profile) | allowed methods → op-class |
| `xrootd_guard_signature <pat>` | — | repeatable; adds to blocklist |
| `xrootd_guard_default_signatures on\|off` | on | built-in php/wp/.env/… set |
| `xrootd_guard_audit_log <path>` | — | shared fail2ban audit file |
| `xrootd_guard_bounce_status 403\|444` | 444 | pre-backend bounce status |

**Stream guard (on the `xrootd_transparent_proxy` server block):**
`xrootd_guard_stream on|off`, reusing `xrootd_guard_audit_log` /
`xrootd_guard_signature` / grammar from the shared ruleset.

## 6. fail2ban contract & deliverables

One audit log, one line per flagged request, stable field order so a single
filter serves all three protocols:

```
2026-07-01T12:00:00Z ip=203.0.113.9 proto=arc signal=signature op=read path="/wp-login.php" status=403
```

JSON form (audit-log body, from `guard_audit_format`):
```json
{"ts":"2026-07-01T12:00:00Z","ip":"203.0.113.9","proto":"arc","signal":"signature","op":"read","path":"/wp-login.php","status":403}
```
(The plan picks ONE of these two line formats — key=value is simpler for
`failregex`; JSON is richer for SIEM. Default: **key=value** for the fail2ban file,
JSON optional via a second sink. Decided in the plan, Task 3.)

Deliverables under `deploy/fail2ban/`:
- `xrootd-guard.filter` — `failregex` per signal, `<HOST>` bound to `ip=`.
- `jail.d/xrootd-guard.conf` — per-signal policy: `signature` `maxretry=1`
  (insta-ban); `grammar` `maxretry=2`; `notfound` `maxretry=20 findtime=60`;
  `authfail` `maxretry=5 findtime=120`; nftables `banaction`.
- a `fail2ban-regex` fixture asserting correct `<HOST>` extraction per signal.

## 7. Testing (3 per unit: success + error + security-neg)

- **Guard core** — standalone `gcc` unit test (like `src/zip/zip_dir`, tap tests):
  signature match, grammar allow/deny, `guard_classify_post` mapping, audit-line
  exact bytes.
- **HTTP adapter** (pytest): valid ARC req → proxied, no `signal`;
  `/wp-login.php` → 444 pre-backend + `signal=signature`; grammar violation →
  bounce; missing cred + backend 401 → `signal=authfail`; in-grammar 404 →
  `signal=notfound`. Repeat the matrix under `profile=xrdhttp`.
- **Stream adapter**: valid `root://` op relayed + clean audit; garbage handshake
  → connection dropped + `signal=signature`; `kXR_NotFound` response →
  `signal=notfound`.
- **fail2ban**: `fail2ban-regex` over the sample log → correct `<HOST>` per signal.

## 8. Non-goals (YAGNI)

- nginx does **not** keep its own persistent offender/ban table — fail2ban owns
  durable bans (D2).
- No bespoke HTTP proxy — stock `proxy_pass` moves the bytes (D4).
- No metrics carrying paths/IPs (INVARIANT 8: low-cardinality labels only). The
  audit log holds the high-cardinality detail; any metric counts by `signal`
  class only.
- No `roots://` frame-level inspection (bulk-TLS opaque; connection-level only).

## 9. Reuse / invariants honoured

- Reuses `src/tap/` decode + `tap_audit.c` JSON style; extends `src/relay/`.
- Uses stock `ngx_http_proxy_module` — no reimplemented proxy (HELPERS rule).
- `xrootd_sanitize_log_string()` on every wire-derived path (log-sanitize inv.).
- Guard-core allocation-free/pure like `src/tap/`; nginx allocation only in the
  adapter via `ngx_palloc(r->pool,…)`.
- No `goto`; functional/modular; new `.c` files registered in `./config`.
