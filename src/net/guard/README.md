# net/guard — protocol-agnostic bad-actor classifier

Pure-C core of the generic bad-actor MITM guard (phase-65): every fronted
protocol (ARC HTTP, XrdHttp/WebDAV, `root://`) normalizes each request into one
`guard_request_t`, and this directory classifies it — junk-scanner signatures,
namespace-grammar violations, backend not-found / auth-failure outcomes — and
formats the single `key=value` audit line fail2ban bans on.

**The pure-C rule (same discipline as [`src/net/tap/`](../tap/)):** no nginx
headers, no allocation, no OpenSSL. That is what lets the same objects embed in
an nginx HTTP module (`src/net/httpguard/`), in the stream relay
(`src/protocols/root/relay/relay_guard.c`), and in a standalone plain-`gcc`
unit test.

| File | Responsibility |
|---|---|
| `guard.h` | Public API: `guard_request_t`, op/outcome/verdict/reason enums, `guard_ruleset_t`, every prototype. |
| `guard_classify.c` | `guard_signature_match`, `guard_grammar_ok`, `guard_classify_pre` (bounce verdict, signature > grammar), `guard_classify_post` (outcome → signal), `guard_classify_handshake` (first-bytes wire check: is this even a kXR client?). |
| `guard_audit.c` | `guard_audit_format` (the fail2ban line — field order and tokens are load-bearing) + `guard_reason_str`/`guard_op_str`/`guard_wire_str` token maps. |
| `guard_ruleset.c` | Ruleset builders: init, built-in scanner signature set, operator signatures/prefixes, per-profile grammar defaults (`arc`/`xrdhttp`/`root`). |
| `guard_test.c` | Standalone unit test — **never** compiled into nginx. |

## The `guard_request_t` contract

Adapters own everything the core cannot do allocation-free:

- **`path` is pre-sanitized at the adapter edge** (`brix_sanitize_log_string()`
  or equivalent — no control bytes, quotes, or backslashes) and borrowed for the
  call only.
- **`ip` and `proto` are NUL-terminated borrowed strings.**
- **Adapters own the clock**: `guard_audit_format` takes a caller-built
  timestamp string.
- Ruleset pattern/prefix strings must outlive the ruleset (string literals or
  conf-pool memory).

## Audit line (the fail2ban contract)

```
<ts> ip=<ip> proto=<proto> signal=<reason> op=<op> path="<path>" status=<code>
```

Single line, fixed field order; `signal=` tokens are `signature` | `grammar` |
`notfound` | `authfail` | `notroot` | `proxyabuse` | `cvmfs_tamper`. The filters in
`deploy/fail2ban/filter.d/` match these literally — never change one side alone.

## Wire-level "not speaking root" check (`guard_classify_handshake`)

The classifier above operates on already-decoded requests (opcodes, paths). A
client that never speaks the protocol — a TLS ClientHello, an HTTP scanner, an
SSH bannergrab, raw junk — produces no decodable request and would otherwise
never be classified. `guard_classify_handshake()` closes that gap: it inspects
the **first bytes** of a connection for the fixed kXR `ClientInitHandShake`
signature (12 zero bytes, then `fourth == htonl(4)`; `fifth` left unchecked so
odd-but-real clients still pass) and returns a `guard_wire_t` — `ROOT` for a
genuine (or still-arriving zero-prefix) kXR opening, otherwise the wire it
recognizes (`tls-clienthello` / `http-request` / `ssh-banner` / `empty` /
`junk`). A non-root client is dropped and logged as `signal=notroot
op=handshake path="<wire>"`. The root:// stream relay wires this in via
`brix_relay_guard_handshake()` (see `src/protocols/root/relay/relay_guard.c`),
running it once on the opening client→upstream chunk **before** it is
forwarded, so nothing that isn't speaking root ever reaches the backend.

## CVMFS forward-proxy abuse check (`signal=proxyabuse`)

The CVMFS content handler can run as a forward proxy (absolute-form request
lines, `GET http://s1:8000/cvmfs/...`); the `brix_cvmfs_upstream_allow`
Stratum-1 allowlist is the sole thing separating it from an open HTTP proxy
(SSRF surface — see `src/protocols/cvmfs/request.c`). Enforcement was already
airtight; what was missing was the **guard contract**. `src/protocols/cvmfs/
gate.c` (`cvmfs_guard_proxyabuse()`) now emits the unified audit line
(`proto=cvmfs signal=proxyabuse op=read path="<attempted authority>"`) whenever
an absolute-form target is refused for an SSRF-relevant cause — a
non-allowlisted authority, a non-http(s) scheme, or a malformed target port —
so a bad actor probing the cache to reach an arbitrary remote is banned by the
`[xrootd-guard-proxyabuse]` jail (maxretry 3: above accidental, below scanner
rates). The attempted upstream authority (`host[:port]`, wire-supplied →
`brix_sanitize_log_string`) rides the path field. The line is emitted alongside
the pre-existing human-readable `cvmfs-reject:` WARN, not instead of it.

## CVMFS content-tamper check (`signal=cvmfs_tamper`)

Phase-85 F2. When a CVMFS cache fill fails integrity verification — the staged
bytes don't hash to their content-addressed name (`brix_cache_verify
cvmfs-cas`), or the manifest/whitelist signature chain doesn't verify against
the configured master key — the fill spine emits the unified audit line via
`sd_cache_guard_tamper()` (`src/fs/backend/cache/sd_cache_fill.c`) alongside
the quarantine. Fills are detached and request-coalesced, so there is no
client to blame: the **origin authority that answered the fill**
(`sd_http_last_origin`) rides the `ip=` field, and the
`[xrootd-guard-cvmfs_tamper]` jail (maxretry 1 — a verified tamper is never
accidental) bans that origin, cutting it out of the failover set.

## CVMFS token-gate check (`signal=authfail`)

Phase-85 F3. A repo gated by `brix_cvmfs_repo_authz` that is probed without a
valid READ-scope bearer answers 401 and emits the unified audit line
(`proto=cvmfs signal=authfail op=read path="<uri>"`) via the generalized
emitter in `src/protocols/cvmfs/gate.c` (`cvmfs_guard_emit()`);
`cred_present=1` when an Authorization header was offered but rejected.
Unauthenticated probing of a private repo is the same actor shape as a
credential brute-force elsewhere, so it feeds the existing
`[xrootd-guard-authfail]` jail — no new filter or jail needed.

## Testing

```bash
tests/guard/run_guard_core.sh    # builds guard_*.c with plain gcc, runs all checks
```
