# Design: `root://` auth-handshake conformance harness

**Date:** 2026-07-04
**Status:** approved (design), pending implementation plan
**Type:** new test infrastructure + conformance findings + C-client fixes
**Program context:** Sub-project 1 of a multi-phase client-conformance program
(auth handshake first, then `root://` data/metadata, then HTTP/WebDAV + S3). Each
sub-project is its own spec → plan → implementation → findings/fixes cycle.

---

## 1. Problem & goal

The `nginx-xrootd` C clients (`libbrix` + `client/apps/xrdcp`/`xrdfs`) are one of
several independent `root://` implementations that live side-by-side under
`~/HEP-x/`. The existing conformance suite is **server-focused** (e.g.
`test_official_interop.py`, `test_conf_*.py`, `test_gohep_interop.py`) — it proved
the *server* against the reference. Client-side conformance is thin
(`test_native_client_conformance.py` covers 7 ops). Auth-handshake divergences in
particular have historically hidden as "agrees-with-our-own-server" traps — the
`kXR_sigver`-ack bug survived for a long time because our client *and* server both
diverged from the spec in the same way; only the independent go-hep client caught it.

**Goal:** a reusable multi-implementation conformance harness, applied first to the
`root://` auth handshake, that runs our C client alongside four independent oracles,
diffs **both observable behavior and wire bytes**, and surfaces → documents → **fixes**
divergences in the C client. Working assumption (repo convention, from
`conformance-findings.md`): *a divergence is a C-client bug unless there is positive
evidence otherwise.*

### The auth handshake under test
The `root://` login sequence, in order:
`handshake (20-byte preamble) → kXR_protocol (security requirements negotiation) →
kXR_login (username/pid/capver/ability + optional token) → kXR_auth (per-method
credential exchange) → kXR_sigver (request-signing prefix, when required)`.

## 2. The implementations (oracles)

Four independent oracles plus the C client under test. Wire spec:
`/tmp/xrootd-src/src/XProtocol/XProtocol.hh`.

| Impl | Lang | Location | Invocation | Runnable here |
|---|---|---|---|---|
| **nginx-xrootd/client** (under test) | C | `client/bin/xrdfs`, `xrdcp` | native binary | yes (built) |
| **Official XrdCl** (reference) | C++ | `/usr/bin/xrdfs`, `xrdcp` (v5.9.5); src `/tmp/xrootd-src` | native binary | yes |
| **XRootD.jl** | Julia | `~/HEP-x/XRootD.jl/bin/xrdfs.jl` | `julia … xrdfs.jl` (1.11.9) | yes |
| **pyBall/pyxrdcp** | Python | `~/HEP-x/pyBall/pyxrdcp` | `python3 -m pyxrdcp.cli` (3.13.5) | yes |
| **go-hep** | Go | `~/HEP-x/go-hep/xrootd` (`xrdfs`) | Go build | needs Go toolchain install |

**Capability matrix is measured, not assumed.** Each impl supports a different auth
subset (go-hep historically unix/host/krb5; Julia/Python lean unix/host/sss/token/tls;
C has all). The harness **auto-probes** what each impl supports and gates each auth
method's differential to the impls that pass the probe. This avoids brittle hard-coded
matrices and adapts as the sibling clients evolve.

## 3. C-client auth surface (where fixes land)

| Stage | C client file |
|---|---|
| handshake / connect | `client/lib/net/conn.c` |
| frame codec | `client/lib/protocols/root/frame.c` |
| auth driver (method select) | `client/lib/auth/auth.c` |
| unix / host / krb5 / gsi / sss / pwd / token | `client/lib/auth/sec/sec_{unix,host,krb5,gsi,sss,pwd,token}.c` |
| request signing | `client/lib/auth/sigver.c` |
| TLS | `client/lib/net/tls.c` |

## 4. Components (each a focused, independently-testable unit)

All new harness code lives under `tests/conformance/`.

### 4.1 Oracle adapters — `tests/conformance/oracles/*.py`
One small adapter per impl, a uniform interface:
```
probe(server_url, auth_method, env) -> ProbeResult
ProbeResult = { exit_class: ok|autherr|fail, auth_outcome, identity, stderr_norm }
supports(auth_method) -> bool     # empirical capability probe, cached
```
Adapters: `oracle_c`, `oracle_official`, `oracle_julia`, `oracle_python`, `oracle_go`.
Each wraps that client performing a login+auth then a trivial probe op (`stat /` or a
protocol/ping query) and normalizes the observable result. CLI-surface differences
between the five tools are absorbed here (the adapter is the only impl-specific code).

### 4.2 Capture proxy — `tests/conformance/capture_proxy` (C, from `tests/c/fault_proxy.c`)
A transparent TCP relay: forwards client↔server byte-for-byte and writes a
direction-tagged, timestamped dump of the raw stream to a file. Protocol-agnostic at
the socket level → identical capture path for all five clients. One instance per
capture run; the adapter points its client at the proxy's listen port, which forwards
to the real server. **Cleartext only** — see §5.

### 4.3 PDU decoder — `tests/conformance/wire.py`
Parses a capture dump into an ordered PDU list:
`[HandshakePreamble, {streamid, opcode, dlen, fields{…}}, …]`, decoding the
handshake / `kXR_protocol` / `kXR_login` / `kXR_auth` / `kXR_sigver` request+response
layouts using `XProtocol.hh` field offsets. Field extraction is per-opcode (e.g. login
= username[8], zeros[1], pid[4], capver[1], role[1], ability, token). The tap decoder
`src/net/tap/tap_decode.c` is the C-side reference for these layouts and may be
cross-checked, but the harness decoder is pure-Python (no build coupling).

### 4.4 Differential comparator — `tests/conformance/conformance_matrix_lib.py`
Given `ProbeResult`s + decoded PDU-lists across impls for one `(op, auth_method)`:
- **behavioral diff** — do all impls agree on exit_class / auth_outcome / identity?
- **wire majority-vote** — per PDU position and field, compute the majority value;
  any impl differing is flagged a suspect, with `XProtocol.hh` as the spec tiebreaker
  when there is no clear majority (e.g. 2-vs-2).
Emits a structured divergence record `{stage, field, per_impl_values, suspect, spec_ref}`.

### 4.5 Test suite — `tests/test_auth_conformance.py`
- Parametrized `(auth_method × impls-that-support-it)` behavioral tests.
- Dedicated 5-way **wire** tests for the common handshake/protocol/login prefix
  (present in every impl regardless of auth method).
- **Cross-target** parameters: our C client → {our nginx server, stock `xrootd`
  server} to separate client bugs from server bugs.
- Skips cleanly when an oracle/toolchain is absent (Go not installed, no stock server).

### 4.6 Findings doc — `docs/10-reference/comparison/auth-conformance-findings.md`
Divergence table (`impl | stage | was | now/spec | found-by`) + per-fix narrative,
mirroring `conformance-findings.md`. Each C-client fix gets a row and a guarding test
reference. Cross-linked from `conformance-findings.md` and `xrootd-implementations.md`.

### 4.7 Go toolchain setup
A documented harness step (script + README): install the Go toolchain and build
go-hep's `xrdfs`/`xrdcopy`. Recorded as a prerequisite; the suite skips the go oracle
if the build is absent so the harness is not hard-blocked on it.

## 5. Key constraint — TLS opacity

The capture proxy sees **plaintext PDUs only for cleartext auth** over `root://`
(unix / host / sss / krb5 / gsi / sigver). For TLS transports (`roots://`,
ztn-over-TLS) it sees ciphertext, so those cases are **behavioral-only** (no
byte-vote) and are marked as such in results. (Consistent with the project-memory
WSL2 6.18.6 kTLS caveat: TLS engagement is itself unverifiable at the byte level here.)
Wire-level conformance therefore targets the cleartext handshake/login/auth/sigver
surface, which is exactly where the historic divergences lived.

## 6. Auth methods in scope (this sub-project)

The handshake/protocol/login prefix (5-way wire compare), then per method gated to
supporting impls: **unix, host, sigver-signing, sss, krb5, gsi, token(ztn)**. GSI and
token are exercised behaviorally where the oracle supports them; sigver signing is a
prime wire-vote target (it is a request prefix, byte-comparable across impls).

## 7. Servers

- Our nginx fleet: anon `:11094`, GSI `:11095`, token `:11097`, plus an SSS endpoint,
  managed by `tests/manage_test_servers.sh` (attach to a running fleet per the
  conftest lifecycle; do not force a wipe).
- A stock `xrootd` server (v5.9.5) for cross-target isolation — reuse the fleet's
  stock server if present, else spin a minimal anon/sss instance.

## 8. Fix scope & risks

- **Fix as found:** each C-client divergence gets a root-caused fix in
  `client/lib/auth/…`, a guarding test in `test_auth_conformance.py`, and a findings
  row. Coordinated server+client fixes (like the historic sigver fix) are allowed but
  must keep the server conformance suites green.
- **Risks / mitigations:**
  - *Go install needs network* — gated/skippable; harness not hard-blocked on it.
  - *Oracle CLI drift* — absorbed in the per-impl adapter (only impl-specific code).
  - *TLS byte-opacity* — behavioral-only for TLS (§5), documented in results.
  - *Capability variance* — empirical probe gates each method (§2); no hard-coded matrix.
  - *Fleet flakiness* — attach to a running fleet (conftest auto-attach), never wipe;
    honor the serial-run caveats from project memory.
  - *False "C is wrong" votes* — when the majority is a non-C impl but `XProtocol.hh`
    backs C, the spec tiebreaker wins and the finding is recorded against the peer, not C.

## 9. Success criteria

- Harness runs green against a live fleet; produces the findings doc.
- The capability probe correctly reports each oracle's supported auth methods.
- Wire-vote reproduces at least the known-real handshake/login/sigver structure and
  flags any genuine C-client divergence.
- Every C-client fix is pinned by a guarding test; server conformance suites stay green.
- Harness is pytest-integrated and skips cleanly when oracles/toolchains are absent.
