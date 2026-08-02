# Protocol Fuzz-Conformance Suite — malformed-packet parsing across every front-end

> **Status:** Living · **Authored:** 2026-07-28 · **Owner:** security workstream
>
> **Scope:** a byte-exhaustive, malformed-input conformance corpus replayed against
> *every* protocol surface BriX exposes, asserting the parsers can never be driven to
> crash, wedge the accept path, or emit corrupt framing. This is the **read/parse**
> counterpart to the write-path [`hostile-network-lessons.md`](hostile-network-lessons.md)
> sweep: that document hardens *what signals a complete transfer*; this one hardens
> *what happens when the very first bytes are garbage*.

## What it covers

Two pytest files drive one shared corpus module. **12,800 collectable tests**; each
case is replayed on a fresh connection so a crashed worker refuses the next case and
fails loudly rather than skipping.

| File | Surface | Endpoints exercised |
| --- | --- | --- |
| `tests/test_fuzz_http_conformance.py` | HTTP-family parsers | plain HTTP/WebDAV, HTTPS/WebDAV (`https://` / `webdav://`), `httpg://` (HTTP-over-GSI-TLS), S3 gateway |
| `tests/test_fuzz_binary_conformance.py` | XRootD stream parser + TLS record layer | `root://` anon/token/gsi cleartext streams; `roots://` / WebDAV-TLS / httpg TLS record layer |
| `tests/fuzz_corpus.py` | deterministic corpus (no server needed to build) | — |

The named protocols map onto these surfaces as: `root://`/`roots://` → XRootD +
TLS legs; `https://`/`webdav://`/`httpg://`/`http://`/`s3://` → HTTP-family leg.
`cvmfs://` reuses the HTTP parser (its manifest/catalog parsing has a dedicated
corpus suite, `test_cvmfs_*`), and `gsiftp://` is fronted by the GridFTP gateway
whose control-channel fuzzing lives with its per-module fixture.

### Corpus generators (`fuzz_corpus.py`)

- `http_generic_cases()` — method / version / path / header-name / header-value
  byte sweeps `0..255`, request-line structure, `Content-Length` matrices,
  `Transfer-Encoding` / chunked-body abuse, oversize + truncation, LCG garbage.
- `s3_cases()` — SigV4 `Authorization` / `x-amz-*` / query-string fuzz.
- `webdav_cases()` — verbs, `Destination` / `Depth` / `If` headers, malformed XML bodies.
- `xrootd_cases()` — opcode sweep (incl. out-of-range 2990–3050 + wide `u16` steps),
  `dlen` sweep, handshake variants, truncated frames, `dlen`/payload mismatch,
  streamid sweep, open-options, read-extents.
- `tls_junk_cases()` — TLS record-type byte sweep + curated malformed ClientHellos.

Pseudo-random bytes come from a fixed LCG so test IDs are stable across runs.

## The robust-liveness invariant

The suites deliberately assert **survival and framing sanity**, never a fragile
per-case status code:

- **HTTP leg** — a non-empty reply must be *either* a well-formed `HTTP/1.x` status
  line (`HTTP/\d\.\d [1-5]\d\d …`, so a mangled/truncated status line still fails)
  *or*, when it carries no status line, a coherent **HTTP/0.9** body: decodable text
  with no NUL bytes. Binary garbage or a corrupt status line is the crash/heap-scribble
  fingerprint and is rejected. An empty read (clean close / reset / TLS alert) is fine.
- **XRootD leg** — any framed reply's `dlen` must be `<= 16 MiB`; a header claiming a
  multi-gigabyte body is the signature of a length/sign-extension parser bug.
- **TLS leg** — junk records must draw an alert/close without crashing; survival is
  proven by a per-port teardown probe.
- **Every leg** — a module-teardown probe issues one last *valid* request per endpoint,
  catching a crash on the final fuzz case.

## Notable finding — HTTP/0.9 fallback is spec-correct, not a parser fault

Two generic cases produce a reply that does **not** begin with `HTTP/`:

| Case | Request bytes | Reply |
| --- | --- | --- |
| `version-var-14` | `GET / \r\n` (trailing space, no version token) | `<html>…403 Forbidden…` |
| `path-byte-0a`  | `GET /\na HTTP/1.1` (bare `LF` ends the request line at `GET /`) | `<html>…403 Forbidden…` |

nginx interprets a request line carrying no valid `HTTP/x.y` token as **HTTP/0.9**,
whose response by spec has no status line and no headers — just the body (here the
stock 403 page, since `GET /` on the docroot is forbidden). This reproduces identically
on the cleartext HTTP endpoint, confirming it is protocol-correct behaviour on every
front-end, **not** a TLS artifact and **not** a defect. The suite's liveness check
accounts for it (coherent-text body-only replies pass); the two cases are the only
non-`HTTP/`-prefixed replies in the entire 1,968-case generic corpus.

**Lesson for the next fuzz harness:** a body-only reply is a legitimate HTTP/0.9
answer, not evidence of a broken parser. Assert *framing coherence* (well-formed
status line **or** clean text body), not the literal `HTTP/` prefix.

## Running

```sh
# Full corpus (slow tier — auto-marked `slow` by the "conformance" filename,
# so excluded from the fast tier):
PYTHONPATH=tests pytest tests/test_fuzz_http_conformance.py -q      # ~8k tests
PYTHONPATH=tests pytest tests/test_fuzz_binary_conformance.py -q    # ~4.8k tests

# Offline collect works with no server up; each endpoint column skips cleanly
# if that listener is unreachable.
PYTHONPATH=tests pytest tests/test_fuzz_*_conformance.py --collect-only -q
```

Run against the always-on `main` fleet. Last full green run (2026-07-28):
`8027 passed` (HTTP, 24m37s) + `4773 passed` (binary, 52s) — **12,800 total, 0 failures**.
Run the two files **sequentially**: two concurrent clients hammering the same TLS
listeners introduce contention that muddies the liveness signal.
