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
| `guard_classify.c` | `guard_signature_match`, `guard_grammar_ok`, `guard_classify_pre` (bounce verdict, signature > grammar), `guard_classify_post` (outcome → signal). |
| `guard_audit.c` | `guard_audit_format` (the fail2ban line — field order and tokens are load-bearing) + `guard_reason_str`/`guard_op_str` token maps. |
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
`notfound` | `authfail`. The filters in `deploy/fail2ban/filter.d/` match these
literally — never change one side alone.

## Testing

```bash
tests/guard/run_guard_core.sh    # builds guard_*.c with plain gcc, runs all checks
```
