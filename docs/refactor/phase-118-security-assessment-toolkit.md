# Phase 118 — `xrd conform`: the deployment-time protocol-conformance oracle

**Status:** PLAN — no code proposed as landed by this document.
**One-sentence goal:** make `xrd` the tool an operator runs at the end of a
deployment to learn, with evidence, whether their XRootD or BriX-Cache endpoint
is *configured correctly and behaving according to the spec* — by asking it
thousands of detailed, fractional, boundary and deliberately off-spec questions
and checking every answer against an oracle.
**Scope:** `client/` only (apps + libbrix) plus new docs/tests. No `src/` edits:
the target of a conformance run is *someone else's* server — stock XRootD v5/v6,
EOS, dCache, StoRM, or a BriX-Cache — so every capability here must be a
composition of the public client API against a remote endpoint.
**Depends on:** phase-37 (swiss-army `xrd`), phase-38 (the split that produced
`client/apps/diag/`), phase-39 (fault proxy), phase-93 (remote config advisor),
phase-99 (DPI/middlebox levers), phase-116 (the DNS seam).
**Adjacent, NOT superseded:** `phase-27`/`phase-28` harden *this* server;
`docs/07-security/` documents *this* server's posture;
[`docs/07-security/protocol-fuzz-conformance.md`](../07-security/protocol-fuzz-conformance.md)
is the in-CI crash corpus. This phase is the inverse of all three: it makes the
client a portable judge of a *remote* server, ours or not.
**Methodological precedent:** [`docs/10-reference/conformance/`](../10-reference/conformance/README.md)
already does exactly this for the WLCG X.509 stack — 559 spec-first clause rows
in `tests/clauses/`, each carrying a verdict *derived from the standard, not
from what the code does*, driven through three independent surfaces and
differentially recorded against stock XRootD v6.1.0 in
[`differential-findings.md`](../10-reference/conformance/differential-findings.md).
**Phase 118 is the wire-protocol analogue of that work, shipped as a tool
instead of a test suite.** That is the whole idea in one sentence.
**CLI contract:** every item below is additive under
[`docs/09-developer-guide/client/apps/README.md`](../09-developer-guide/client/apps/README.md) §"CLI compatibility
contract" C1–C5. No existing flag, exit code, or non-TTY byte changes meaning.
New `.c` files go in `client/Makefile` (guard
[`check_client_build_coverage.py`](../../tools/ci/check_client_build_coverage.py)).

**Reading order.** Part I is the argument. **Part II is the engine spec and
Part III is the ledger — those two are the deliverable**; everything else
supports them.

| | | |
|---|---|---|
| **Part I** | §1–§4 | what this is, why the fuzz corpus is not it, the oracle problem, the ground truth |
| **Part II** | §5–§8 | the planted-object oracle, the fractional case generators, the clause row, the verdict algebra |
| **Part III** | §9–§30 | **the clause ledger** — 44 families, 527 individually numbered rows |
| **Part IV** | §31–§35 | profiles, run shapes, report, calibration, safety |
| **Part V** | §36–§40 | inventory, spines, register, sequencing, verification |

---

# Part I — What this is

## 1. The question this tool answers

> *"I have just stood up an XRootD server / a BriX-Cache / a redirector. Is it
> right? Not 'is it up' — is it **correct**? Will the client that shows up in
> three weeks with an unusual read pattern get the right bytes, or a plausible
> lie?"*

Nothing in the ecosystem answers that today. `xrdcp` proves the happy path.
Monitoring proves liveness. A site's own tests prove the operations that site
happens to use. What is missing is a **conformance oracle**: a portable program
that interrogates a deployed endpoint across the whole legal input space —
especially its unglamorous corners — and reports, clause by clause, where the
answers diverge from what the protocol requires.

The two failure directions matter equally, and the second is why this is also a
security tool:

- **Advertised but broken.** The server sets `kXR_tlsData` in its `kXR_protocol`
  flags, or `kXR_suppgrw`, or answers `1` to `Qconfig tpc` — and then does not
  deliver, or delivers wrongly.
- **Unadvertised but present.** The server does something it never claimed:
  serves an export it should not, honours `kXR_open` on a bound substream,
  follows a redirect it should refuse, answers anonymously on a path it says is
  token-gated. Every one of these is a misconfiguration finding *and* an attack
  surface, and the same mechanism finds both.

### 1.1 What "hyper complete" means here, concretely

A conformance tool is complete when a competent adversarial reviewer cannot name
a legal request shape it never sends. This document therefore commits to:

1. **Every request code** in `XRequestTypes` (3000–3031) has a family, including
   the ones nobody tests — `kXR_chkpoint` (3012), `kXR_gpfile` (3005),
   `kXR_writev` (3031), `kXR_sigver` (3029), `kXR_endsess` (3023).
2. **Every option bit** of every option enum is exercised set and clear, and the
   documented illegal combinations are exercised too.
3. **Every numeric limit named in the header** is probed at `limit−1`, `limit`,
   `limit+1` — `kXR_faMaxVars`=16, `kXR_faMaxNlen`=248, `kXR_faMaxVlen`=65536,
   `maxRvecsz`=1024, `maxRVdsz`=2097136, `kXR_pgMaxEpr`=128, `kXR_pgMaxEos`=256,
   `kXR_maxReqRetry`=10, and the 16 MiB `kXR_oksofar` chunking threshold.
4. **Every error code** in `XErrorCode` (3000–3035) that a client can provoke
   from outside has a row that provokes it and asserts it.
5. **Every response code** in `XResponseType` — including the ones servers rarely
   emit (`kXR_attn`/`kXR_asynresp`, `kXR_waitresp`, `kXR_oksofar`) — has a row
   that forces the server onto that path and validates the frame.
6. **Every fractional axis** is generated, not hand-picked: the offset × length ×
   alignment × object-size product, with a stated reduction strategy (§6.6).
7. **Every row states its reference and its oracle**, so no finding is arguable.
8. **Every row has a negative fixture** it is known to catch (§40).

## 2. Why the existing 12,800-case corpus does not answer it

[`tests/fuzz_corpus.py`](../../tests/fuzz_corpus.py) (488 lines) generates 12,800
malformed inputs — opcode sweeps, `dlen` sweeps, handshake variants, truncated
frames, `dlen`/payload mismatches, streamid sweeps, open-option sweeps,
read-extent extremes, TLS junk, plus HTTP/S3/WebDAV families. It is good work and
it stays.

But it answers exactly one question, with a one-bit answer:

| | input | oracle | verdict |
|---|---|---|---|
| **Crash fuzzing** (exists) | garbage | *none* — the gate is "the process is still alive" | survived / died |
| **Behavioural conformance** (this phase) | well-formed but unusual, fractional, boundary, degenerate | the specific answer the protocol mandates | conformant / divergent, with the clause |

A server that answers `kXR_ServerError` to every one of the 12,800 cases passes
the corpus perfectly and is completely broken. Conversely the interesting
deployment defects — a `pgread` at a non-page-aligned offset that CRCs a padded
page, a `Range: bytes=0-0` that returns the whole file, a `kXR_set` that errors
on an unknown modifier and silently breaks every XrdCl client, a manager whose
`locate` names a server that does not have the file — are all *well-formed
requests with wrong answers*. No survive gate can see them.

The corpus is a **survivability** battery. This phase adds the **correctness**
battery it has never had, and reuses the corpus generators as one input source
among several (§23, item C9).

## 3. The oracle problem, and its four answers

### 3.1 Three competing references

[`docs/10-reference/quirks.md`](../10-reference/quirks.md) states the tension
outright: *"`xrdcp` behavior often differs from the nominal protocol docs —
implementation follows working client behavior first."* So there are three
references, and they disagree:

1. **The nominal spec** — `XProtocol.hh` and the protocol reference.
2. **Stock XRootD's de facto behaviour** — what the reference implementation
   actually does, which is what the ecosystem has calcified around.
3. **What real clients depend on** — narrower than either, and the only one
   whose violation causes a visible outage.

`XProtocol.hh` contains its own proof that these differ. `mapError()` maps
`ENOTEMPTY` to `kXR_ItExists` with the comment *"In the case one tries to delete
a non-empty directory we have decided that until the next major release the
kXR_ItExists flag will be returned"* — an acknowledged wart that clients now
depend on. A tool that judged `rmdir` on a non-empty directory against the
*nominal* answer would report a false finding against every conformant server in
existence.

**Every clause row therefore carries an explicit `ref` field** — `spec`,
`xrootd`, `client`, or `cons` (self-consistency) — and the report prints it. A
row whose reference is `xrootd` or `client` is documenting a de-facto contract
and says so out loud.

### 3.2 The four oracle classes

Ranked by how deployable they are, best first. Each clause uses whichever is
strongest for it, and the ledger records which.

**O1 — self-consistency.** The server's own answers must agree with each other.
Needs no ground truth, no reference implementation, and no write access beyond
what the operator already has. This is by far the most powerful oracle and it is
almost entirely unexploited today. The full O1 comparator set is §8.2.

**O2 — the planted-object oracle (arithmetic ground truth).** For read-shaped
questions the correct answer is *computable*, which is what makes a huge
fractional grid affordable. Fully specified in §5.

**O3 — spec-literal.** The rule is written down and can be asserted directly:
a constant in `XProtocol.hh`, a numbered note in
[`protocol-notes.md`](../10-reference/protocol-notes.md), an RFC clause.

**O4 — differential.** Run the same battery against a reference endpoint and
diff. This is how §3.1's tension gets *resolved* instead of argued: a row where
the target diverges from both spec and stock XRootD is a target bug; a row where
stock XRootD diverges from spec is an ecosystem fact clients depend on, and it
goes in a differential table exactly like
[`differential-findings.md`](../10-reference/conformance/differential-findings.md).

### 3.3 Claims-versus-behaviour

Before any battery runs, the tool reads what the endpoint *claims*. That claim
set is machine-readable and exhaustively enumerable, because it is a bitmask:

| source | claims |
|---|---|
| `kXR_protocol` response `flags` | `kXR_isServer` 0x1, `kXR_isManager` 0x2, `kXR_attrCache` 0x80, `kXR_attrMeta` 0x100, `kXR_attrProxy` 0x200, `kXR_attrSuper` 0x400, `kXR_attrVirtRdr` 0x800, `kXR_recoverWrts` 0x1000, `kXR_collapseRedir` 0x2000, `kXR_ecRedir` 0x4000, `kXR_supposc` 0x100000, `kXR_suppgrw` 0x200000, `kXR_supgpf` 0x400000, `kXR_anongpf` 0x800000, `kXR_tlsData` 0x01000000, `kXR_tlsGPF` 0x02000000, `kXR_tlsLogin` 0x04000000, `kXR_tlsSess` 0x08000000, `kXR_tlsTPC` 0x10000000, `kXR_tlsGPFA` 0x20000000, `kXR_gotoTLS` 0x40000000, `kXR_haveTLS` 0x80000000 |
| `kXR_protocol` `secreq` (when `kXR_secreqs` asked) | `secver`, `secopt` (`kXR_secOData` 0x01, `kXR_secOFrce` 0x02), `seclvl` (0–4), per-request `secvec` signing requirements (`kXR_signIgnore`/`Likely`/`Needed`) |
| `kXR_login` response | `sessid[16]`, the `sec` continuation string (auth mechanisms offered) |
| `kXR_query kXR_Qconfig` | the site's own advertised key set |
| HTTP | `DAV:` header, `OPTIONS` `Allow`, `Accept-Ranges`, `Server` |
| S3 | service/bucket responses, advertised signature versions |

That claim set does two jobs: it **selects** the applicable clause rows (no point
failing a server for `pgwrite` when `kXR_suppgrw` is clear), and it becomes a
clause family of its own (§17, `CLM`): **everything claimed must work, and
nothing unclaimed may work.** A server advertising `kXR_tlsData` that
nonetheless serves a cleartext read is the single most common serious deployment
defect in this space, and it is one clause row.

## 4. Ground truth this phase is built on

Named explicitly so a later session does not re-derive it, and so every `src`
citation in the ledger resolves.

| tag | source | what it gives |
|---|---|---|
| `XP` | `/usr/include/xrootd/XProtocol/XProtocol.hh` (v5.1.x, 1496 lines) | request codes 3000–3031, response codes 4000–4007, error codes 3000–3035, every option enum, every struct layout, every numeric limit, and `XProtocol::mapError()` — described in the header itself as *"the official mapping from errno to xroot protocol error"* |
| `PN§n` | [`docs/10-reference/protocol-notes.md`](../10-reference/protocol-notes.md) | 30 numbered reverse-engineered wire behaviours, several of which are clause text verbatim and have **no external checker today** |
| `QK` | [`docs/10-reference/quirks.md`](../10-reference/quirks.md) | the spec-versus-real-clients tension, and the per-quirk detail |
| `AG` | `docs/09-developer-guide/agent-guide-extended.md` §"errno → kXR → HTTP" | the cross-plane error table and the EROFS rule |
| `CL` | `CLAUDE.md` invariants | 1 (pgread/pgwrite → `kXR_status` + per-page CRC32c), 3 (endpoint write check before token scope), 5 (collection DEL/MOVE/COPY recursive), 12 (EROFS never EACCES) — all externally probeable |
| `RFC` | RFC 9110/9111/9112 (HTTP), RFC 4918 (WebDAV), RFC 7143 (CRC32C), AWS SigV4 | the web planes |

**The `XP` numbers this document depends on**, extracted once so the ledger can
cite them:

```
request hdr        24 bytes   (ALIGN_CHECK: sizeof(ClientRequest) == 24)
response hdr        8 bytes   (ALIGN_CHECK: sizeof(ServerResponseHeader) == 8)
kXR_1stRequest   3000        kXR_REQFENCE 3032   (last valid code + 1)
kXR_ArgInvalid   3000        kXR_ERRFENCE 3036
kXR_ok              0   kXR_oksofar 4000  kXR_attn 4001  kXR_authmore 4002
kXR_error        4003   kXR_redirect 4004  kXR_wait 4005  kXR_waitresp 4006
kXR_status       4007
kXR_pgPageSZ     4096   kXR_pgUnitSZ 4100  kXR_pgMaxEpr 128  kXR_pgMaxEos 256
kXR_pgRetry      0x01   kXR_AnyPath  0xff
rlItemLen          16   maxRvecln  16384   maxRvecsz 1024
minRVbsz      2097152   maxRVdsz 2097136
wlItemLen          16   maxWvecln  16384   maxWvecsz 1024
kXR_faMaxVars      16   kXR_faMaxNlen 248  kXR_faMaxVlen 65536
kXR_statusBodyLen  16   RespType: Final 0, Partial 1, Progress 2
kXR_maxReqRetry    10
protocol versions: 0x500 TLS+xattr, 0x310 signing, 0x511 pgread/pgwrite
```

---

# Part II — The engine

## 5. The planted-object oracle

The mechanism that makes an enormous fractional grid affordable. Without it,
every fractional read needs a reference copy of the bytes; with it, the expected
answer to *any* read-shaped question is computed in O(1).

### 5.1 Content function

The tool uploads objects whose byte at file offset `i` is a keyed pseudo-random
function of `i` alone:

```
byte[i] = PRF(run_key, i)
```

Implementation: a 64-bit counter-mode stream — `SipHash-2-4(run_key, i >> 3)`
yields eight bytes, `byte[i]` is lane `i & 7`. Properties that matter:

- **Random access.** Verifying bytes `[o, o+n)` costs O(n) and needs no state,
  so a 64 GiB planted object can be spot-checked at offset 63 GiB in microseconds.
- **Position-sensitive.** A server that returns the *right number of bytes from
  the wrong offset* — an off-by-one page, a stale cache block, a mis-stitched
  `kXR_oksofar` chunk — fails immediately. A repeating pattern would not catch it.
- **Incompressible.** Nothing on the path can accidentally satisfy a check by
  serving a compressed or deduplicated stand-in.
- **Per-run keyed.** A second run against a warm cache cannot pass on stale
  bytes from the first, and two operators running concurrently never collide.
- **Cheap CRC.** Because `PRF` is seekable, the expected CRC32C of any page is
  computed directly, which is what the `PGR` family needs.

### 5.2 The standard object set

Every read-shaped family runs against all of these. Sizes are chosen so that each
one puts a *different* boundary in play:

| name | size | why this size |
|---|---|---|
| `Z` | 0 | the degenerate object: every read, range, and checksum has a defined answer on an empty file, and almost nothing tests it |
| `B1` | 1 | single byte; `bytes=-1` == `bytes=0-0` == whole file |
| `P0` | 4095 | one byte short of a page: every pgread's only page is fractional |
| `P1` | 4096 | exactly one page |
| `P2` | 4097 | one page plus one byte: forces a 1-byte second page |
| `Q` | 65536 | 16 pages, and `kXR_faMaxVlen` |
| `M` | 1048576 | 256 pages, a typical block |
| `V` | 2097136 | `maxRVdsz` — the readv single-transfer ceiling, exactly |
| `V+` | 2097137 | one byte over it |
| `C` | 16777215 | one byte under the `kXR_oksofar` chunking threshold |
| `C+` | 16777217 | one byte over it — forces chunking |
| `L` | 5368709121 | 5 GiB + 1: crosses the 32-bit offset boundary and the S3 5 GiB single-PUT ceiling |

`L` is created only when the profile permits and the scratch prefix reports the
space; otherwise it is **skipped with a reason** (§8.3), never silently dropped.

### 5.3 The expected-answer function

For a plain read of `(off, len)` against a planted object of size `S`, with
`off ≥ 0` and `len ≥ 0`:

```
n_expected = clamp(S - off, 0, len)          /* bytes that must come back   */
bytes_expected[k] = PRF(run_key, off + k)    /* for k in [0, n_expected)    */
status_expected = kXR_ok                     /* even when n_expected == 0   */
```

Three consequences the ledger asserts and most servers get at least one of wrong:

1. **`len == 0` is a success, not an error.** `kXR_ok`, `dlen == 0`.
2. **`off == S` is a success with zero bytes**, not `kXR_NotFound`, not
   `kXR_IOError`, not a hang.
3. **A straddling read returns exactly `S - off` bytes**, in one response — not a
   short read the client must retry, and not `kXR_error`.

For negative `off` or negative `len` the expectation flips to
`kXR_error/kXR_ArgInvalid` (§14, `RD-30`..`RD-33`), because `XP` types both as
signed (`kXR_int64 offset`, `kXR_int32 rlen`) and a negative value is
representable on the wire.

### 5.4 Read-only degraded mode

When the operator has no writable scratch prefix, the tool takes one existing
file, fetches it whole once, and uses that buffer as the reference for every
fractional query afterwards. Everything in §14–§16 still runs; what is lost is
the standard object set — the boundaries that then get tested are whatever sizes
the site happens to have. The report says so explicitly, and every clause that
needed a specific size is **skipped with reason `no-planted-object`**. This mode
is the default for `--watch` against production.

## 6. Choosing the axes

The generators below are the literal answer to "as much detailed even off-spec
and fractional queries as possible". They are products of small, deliberately
chosen value sets, not hand-written case lists.

### 6.1 The offset axis

Relative to object size `S` and page size `P` = 4096:

```
0, 1, 2, P-1, P, P+1, 2P-1, 2P, 2P+1,
S/2 - 1, S/2, S/2 + 1,                        /* interior, unaligned       */
(S/2 - S/2 % P), (S/2 - S/2 % P) + 1,         /* interior, aligned & +1    */
S-P-1, S-P, S-P+1, S-2, S-1, S, S+1, S+P,
2^31 - 1, 2^31, 2^32 - 1, 2^32, 2^63 - 1,     /* width boundaries          */
-1, -P, -2^31, -2^63                          /* illegal, must be refused  */
```

### 6.2 The length axis

```
0, 1, 2, P-1, P, P+1, 2P, 4P,
S - off - 1, S - off, S - off + 1,            /* exact-fit and one-over    */
65536, 1048576, 2097136, 2097137,             /* maxRVdsz and one over     */
16777215, 16777216, 16777217,                 /* oksofar threshold ±1      */
2^31 - 1, 2^31, -1                            /* width and illegal         */
```

### 6.3 The alignment axis (`PGR`/`PGW` only)

The page algebra is the richest fractional surface in the protocol and gets its
own derivation. For a pgread of `(off, len)`:

```
first_page_off   = off % P                       /* 0 => aligned            */
first_page_bytes = min(P - first_page_off, len)
full_pages       = (len - first_page_bytes) / P
last_page_bytes  = (len - first_page_bytes) % P
units            = (first_page_bytes > 0) + full_pages + (last_page_bytes > 0)
```

and the mandated response carries exactly `units` CRC32C values, each **over the
bytes actually delivered for that unit**, never over a zero-padded 4096-byte
page. The alignment axis is the cross-product

```
first_page_off  ∈ {0, 1, P/2, P-1}
last_page_bytes ∈ {0, 1, P/2, P-1}
full_pages      ∈ {0, 1, 2, 255, 4095}
```

minus the impossible combinations, which yields the four shapes the ledger names
`aligned/aligned`, `fractional/aligned`, `aligned/fractional`,
`fractional/fractional`, plus the two degenerate ones — `len < P` entirely
inside one page, and `len` spanning a page boundary by exactly one byte.

### 6.4 The vector axes (`RDV`/`WVC`)

```
element count : 0, 1, 2, 1023, 1024, 1025            /* maxRvecsz = 1024    */
element size  : 0, 1, P, maxRVdsz/1024, maxRVdsz
total bytes   : maxRVdsz - 1, maxRVdsz, maxRVdsz + 1
geometry      : ascending | descending | interleaved | duplicated |
                overlapping | adjacent | gapped | EOF-straddling | past-EOF
handles       : one | several in one request | one closed mid-flight
```

### 6.5 The HTTP range axis

```
bytes=0-0                bytes=0-              bytes=-1
bytes=-0                 bytes=-S              bytes=-{S+1}
bytes={S-1}-             bytes={S}-            bytes={S+1}-
bytes=0-{S-1}            bytes=0-{S}           bytes=0-{S+1}
bytes=1-0                                      /* inverted: unsatisfiable  */
bytes=0-0,-1             bytes=0-99,100-199    /* multi, adjacent          */
bytes=100-199,0-99       bytes=0-99,50-149     /* descending, overlapping  */
bytes=0-0,0-0            bytes = 0 - 0         /* duplicate, whitespace    */
items=0-0                bytes=abc-def         /* bad unit, bad numbers    */
{101 ranges}                                   /* range-count ceiling      */
```

### 6.6 Combinatorial budget

The full offset × length product is 30 × 20 = 600 per object per verb, times 12
objects, times the read-shaped verbs (`read`, `pgread`, `readv`, HTTP GET) —
around 29,000 checked requests before the non-read families. That is affordable
for `--full` and not for `--accept`, so the engine supports three reductions,
declared per run and printed in the report:

- **`exhaustive`** — the whole product. The commissioning-window setting.
- **`pairwise`** (default for `--full`) — a covering array over the axes such
  that every *pair* of axis values appears together at least once. Empirically
  ~7% of the product with essentially the same defect yield, because boundary
  bugs are almost always pairwise.
- **`boundary`** (default for `--accept`) — only the values within ±1 of a named
  boundary (`0`, `P`, `S`, `2^31`, `maxRVdsz`, `16 MiB`), which is ~200 requests
  per verb and finishes in seconds.

A run that reduces says so on every clause row it reduced, so no reader mistakes
a `boundary` pass for an `exhaustive` one.

## 7. The clause row

```
brix_clause {
    id;            /* "PGR-014" — stable forever, never renumbered         */
    family;        /* PGR                                                  */
    ref;           /* spec | xrootd | client | cons                        */
    oracle;        /* O1 | O2 | O3 | O4                                    */
    text;          /* the normative sentence being asserted                */
    src;           /* "XP:kXR_pgUnitSZ" | "PN§26" | "RFC9110 §14.4" | ...  */
    profile_mask;  /* data|cache|manager|tape|s3|tls|ec|proxy              */
    claim_mask;    /* required kXR_protocol flag bits, if any              */
    probe_class;   /* read | mutate | adversarial | dos                    */
    negative;      /* the fault-proxy fixture this clause must FAIL (§40)  */
    generate();    /* emit N concrete cases from the §6 axes               */
    expect();      /* the mandated answer for each case                    */
}
```

Rows are **data, not code**. One table, many probes: that is what makes the
ledger enumerable, citable, diffable across versions, and publishable as the
reference document in §32 item D1.

## 8. Verdicts

### 8.1 The verdict set

Four values, and the distinction between the last two is what keeps the tool
honest:

| verdict | meaning |
|---|---|
| `conformant` | the mandated answer was received |
| `divergent` | a different answer was received — the finding carries expected, received, and the wire evidence |
| `skipped` | the clause did not apply (profile, claim mask, missing planted object, probe class not enabled) — **always with a reason string** |
| `inconclusive` | the clause applied and the tool could not determine the answer — a timeout, a redirect out of scope, a truncated session. **Never counted as a pass** |

### 8.2 The O1 comparator set

The self-consistency comparators, written once and reused across families:

| comparator | assertion |
|---|---|
| `partition≡whole` | for any partition of `[0,S)` into fractional reads, the concatenation is byte-identical to one whole-object read |
| `readv≡reads` | `readv` of extents *E* equals the concatenation of individual reads of *E*, in request order |
| `pgread≡read` | `pgread` bytes equal plain `read` bytes for the same extent, and every returned CRC32C matches the bytes delivered |
| `pgwrite≡read` | bytes written by `pgwrite` read back identically by `read` and by `pgread` |
| `cksum≡bytes` | `kXR_Qcksum` equals the checksum recomputed over the bytes the server serves |
| `dstat≡stat` | each `kXR_dirlist` dStat block equals a standalone `kXR_stat` on that path |
| `dcksm≡Qcksum` | each `kXR_dirlist` `kXR_dcksm` digest equals `kXR_Qcksum` for that path |
| `statx≡stat` | `kXR_statx` flags for each path equal the `kXR_stat` flags for that path |
| `HEAD≡GET` | `HEAD` headers equal `GET` headers minus the body |
| `range≡slice` | every HTTP range response equals that slice of the whole-object GET |
| `pages≡listing` | the union of paginated listings equals the unpaginated listing, with no duplicates and no omissions |
| `space≥sum` | `kXR_Qspace` satisfies `used + free ≤ total` and does not move backwards under a pure read workload |
| `locate⊨open` | every server named by `kXR_locate` can actually `kXR_open` the path |
| `xpr≡xpr` | the same object via `root://`, `https://`, `davs://`, `s3://` agrees on size, mtime, checksum, bytes, and error code for the same fault |

### 8.3 Skip discipline

A conformance tool that reports "247 passed" while having silently skipped 400
clauses is worse than no tool. Therefore:

- Every skip carries a machine-readable reason: `profile-excluded`,
  `claim-absent:<flag>`, `probe-class-disabled:<class>`, `no-planted-object`,
  `no-scratch-prefix`, `reduced:<mode>`, `out-of-scope`, `unsupported-by-target`.
- The terminal summary prints skips **on the same line** as passes, never in a
  footnote: `PGR 31 ok · 2 divergent · 9 skipped (claim-absent:kXR_suppgrw)`.
- The exit contract counts `inconclusive` as failure by default under
  `--fail-on`, because an oracle that could not decide has not certified
  anything.
- A golden-report test pins the skip accounting so a future refactor cannot
  quietly convert skips into passes.

---

# Part III — The clause ledger

Every row below is an individually-addressable clause. `ref` is the reference it
judges against (§3.1), `O` the oracle class (§3.2), `src` the citation (§4).
Rows marked **†** are ones no existing tool in this repo or the ecosystem checks
today, as far as this survey found.

## 9. `FRM` — frame structure and stream discipline

The 24-byte request header and the 8-byte response header, asserted by
`ALIGN_CHECK` in `XP`. Every other family assumes these hold.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| FRM-001 | A well-formed 24-byte request header with `dlen` = 0 for a verb needing no payload is accepted | spec | O3 | XP |
| FRM-002 | The response header is exactly 8 bytes: `streamid[2]`, `status`, `dlen` | spec | O3 | XP |
| FRM-003 | The response `streamid` echoes the request `streamid` byte-for-byte | spec | O3 | XP |
| FRM-004 † | With N requests in flight on distinct streamids, each response carries its own request's streamid — responses may interleave, identities may not | spec | O1 | XP |
| FRM-005 † | A streamid of `\0\0` is legal and is echoed as `\0\0` | spec | O3 | XP |
| FRM-006 † | A streamid reused after its response completes is legal | spec | O3 | XP |
| FRM-007 | A streamid reused while its first response is still outstanding is a protocol error, not a silently-dropped response | spec | O3 | XP |
| FRM-008 | Exactly one trailing NUL inside a path `dlen` is accepted; the path is `dlen−1` bytes | client | O3 | PN§19 |
| FRM-009 | A NUL **embedded** before `dlen−1` in a path is rejected | spec | O3 | PN§19 |
| FRM-010 † | Two trailing NULs are rejected — the allowance is exactly one | client | O3 | PN§19 |
| FRM-011 | `dlen` = 0 where a path is required yields `kXR_ArgMissing` | spec | O3 | XP |
| FRM-012 | `dlen` larger than the bytes actually sent does not wedge the connection: the server times out or errors, and the next request on a fresh connection is served | spec | O3 | XP |
| FRM-013 | `dlen` smaller than the bytes sent leaves the surplus interpreted as the next request header, or the connection is dropped — never a silent partial-apply | spec | O3 | XP |
| FRM-014 | `dlen` < 0 is rejected with `kXR_ArgInvalid` | spec | O3 | XP |
| FRM-015 | `dlen` = 0x7FFFFFFF is refused without allocating it | spec | O3 | XP |
| FRM-016 | Reserved/pad bytes in a request header are **ignored**, not validated — a request with 0xFF padding is served identically to one with 0x00 | xrootd | O4 | XP |
| FRM-017 | A request code in the reserved range `[kXR_REQFENCE, 65535]` yields `kXR_InvalidRequest`, not a disconnect | spec | O3 | XP |
| FRM-018 | A request code below `kXR_1stRequest` (3000) yields `kXR_InvalidRequest` | spec | O3 | XP |
| FRM-019 † | Every code in `[3000, 3031]` is either served or answered `kXR_Unsupported` — none is answered `kXR_ServerError` and none disconnects | spec | O3 | XP |
| FRM-020 | A request split across TCP segments at every byte boundary (24 splits) is reassembled identically | spec | O1 | XP |
| FRM-021 † | A request whose payload arrives one byte per second for `dlen` seconds either completes or is refused by a documented timeout — never a permanent slot leak | spec | O3 | — |
| FRM-022 | Pipelined requests sent in a single TCP write are all served | spec | O1 | XP |
| FRM-023 † | The server does not require the client to wait for a response before sending the next request on the same stream | xrootd | O4 | XP |

## 10. `HSK` — handshake and protocol negotiation

| id | assertion | ref | O | src |
|---|---|---|---|---|
| HSK-001 | The 20-byte `ClientInitHandShake` (`0,0,0,4,2012`) is answered with `ServerInitHandShake` | spec | O3 | XP |
| HSK-002 | An XRootD v5 server's handshake response uses the v5 format, not the v4 one | xrootd | O3 | PN§1 |
| HSK-003 | `protover` in the response is ≥ 0x300 and ≤ the tool's supported ceiling | spec | O3 | XP |
| HSK-004 | A short handshake (< 20 bytes, then close) leaks no server state: a subsequent full connection succeeds | spec | O1 | — |
| HSK-005 † | A handshake with the fourth/fifth words altered is rejected, not silently accepted | spec | O3 | XP |
| HSK-006 | A second handshake on an already-handshaken connection is a protocol error | spec | O3 | XP |
| HSK-007 † | Any request sent **before** the handshake yields an error or a disconnect, never service | spec | O3 | XP |

## 11. `PROT` — `kXR_protocol` (3006)

| id | assertion | ref | O | src |
|---|---|---|---|---|
| PROT-001 | `kXR_protocol` before login is answered — it is the one verb that must work unauthenticated | spec | O3 | XP |
| PROT-002 | The response body is at least `kXR_ShortProtRespLen` (`pval` + `flags`) | spec | O3 | XP |
| PROT-003 | `flags` sets exactly one of `kXR_isServer` / `kXR_isManager` | spec | O3 | XP |
| PROT-004 | With `kXR_secreqs` set, the response carries the `'S'`-tagged `ServerResponseReqs_Protocol`; without it, it does not | spec | O3 | PN§2 |
| PROT-005 † | With `kXR_bifreqs` set, a `'B'`-tagged `ServerResponseBifs_Protocol` is returned or omitted — and when present, `bifILen` matches the padded length and the struct is 8-byte aligned | spec | O3 | XP |
| PROT-006 | `seclvl` is in `[kXR_secNone, kXR_secPedantic]` (0–4) | spec | O3 | XP |
| PROT-007 | Each `secvec` entry's requirement is one of `kXR_signIgnore`/`Likely`/`Needed` | spec | O3 | XP |
| PROT-008 | `secvsz` matches the number of `secvec` items actually present | spec | O3 | XP |
| PROT-009 † | Two `kXR_protocol` requests on the same connection return identical bodies | cons | O1 | — |
| PROT-010 † | `kXR_protocol` before and after login return the same capability bits (the answer must not depend on identity) | cons | O1 | — |
| PROT-011 | A `clientpv` below the server's floor is answered, not refused — version negotiation is advisory | xrootd | O4 | XP |
| PROT-012 | `expect` = `kXR_ExpTPC` does not change the flags a non-TPC client sees for the same connection | spec | O1 | XP |
| PROT-013 † | An `expect` value outside `kXR_ExpMask` is ignored, not rejected | spec | O3 | XP |
| PROT-014 | If `kXR_haveTLS` is clear, `kXR_gotoTLS` and every `kXR_tls*` bit are clear too | spec | O3 | XP |

## 12. `LOG` — `kXR_login` (3007), `kXR_auth` (3000), `kXR_endsess` (3023)

| id | assertion | ref | O | src |
|---|---|---|---|---|
| LOG-001 | A successful login returns a 16-byte `sessid` | spec | O3 | XP |
| LOG-002 † | Two logins on two connections return **different** `sessid` values | spec | O1 | XP |
| LOG-003 † | `sessid` is not predictable from a previous one (collect 64, test for monotonicity, low entropy, and shared prefixes) | spec | O1 | — |
| LOG-004 | The `sec` continuation names at least one mechanism when the server requires auth | spec | O3 | XP |
| LOG-005 | Every mechanism named in `sec` actually completes a handshake, or the claim is false | cons | O1 | — |
| LOG-006 † | No mechanism **not** named in `sec` is accepted | cons | O1 | — |
| LOG-007 | `username[8]` shorter than 8 is NUL-padded and accepted; 8 non-NUL bytes are accepted | spec | O3 | XP |
| LOG-008 † | A `username` containing a NUL at position 0 is handled without leaking a default identity | spec | O3 | — |
| LOG-009 | The GSI login challenge is plain text, not a binary buffer | xrootd | O3 | PN§3 |
| LOG-010 | `kXRS_puk` carries a DH blob, not an RSA public key | xrootd | O3 | PN§4 |
| LOG-011 | DH shared-secret derivation requires no padding | xrootd | O3 | PN§5 |
| LOG-012 | The server DH key persists across the two `kXR_auth` round-trips | xrootd | O3 | PN§6 |
| LOG-013 | `kXR_auth` without a preceding `kXR_login` is refused | spec | O3 | XP |
| LOG-014 | A second `kXR_login` on an authenticated connection is refused, not silently re-identified | spec | O3 | XP |
| LOG-015 | `kXR_authmore` continuations terminate: a mechanism cannot loop forever (bound at `kXR_maxReqRetry` = 10) | spec | O3 | XP |
| LOG-016 | An `authmore` continuation carrying garbage yields `kXR_AuthFailed` (3030), not `kXR_ServerError` | spec | O3 | XP |
| LOG-017 † | After a failed auth, the connection either closes or serves only unauthenticated verbs — it never retains partial identity | spec | O1 | CL |
| LOG-018 † | `kXR_endsess` with the current `sessid` ends the session; a subsequent file op fails | spec | O3 | XP |
| LOG-019 † | `kXR_endsess` with **another connection's** `sessid` is refused — this is a session-hijack clause | spec | O3 | XP |
| LOG-020 † | `kXR_endsess` with an all-zero or random `sessid` yields an error, never a wildcard teardown | spec | O3 | XP |
| LOG-021 | Bearer-token auth is offered as the `ztn` credential type | xrootd | O3 | PN§23 |
| LOG-022 | A token whose audience does not match the endpoint is refused | spec | O3 | — |
| LOG-023 | A token past `exp`, and one before `nbf`, are both refused | spec | O3 | — |
| LOG-024 † | A token with a valid signature but an unknown `iss` is refused, not accepted-with-no-scope | spec | O3 | — |
| LOG-025 † | Login ability bits the client does not set are not assumed: a client that omits `kXR_hasipv64` is not sent an IPv6-only redirect | spec | O3 | XP |

## 13. `SIG` — `kXR_sigver` (3029) request signing

Skipped wholesale unless `PROT` reported a `seclvl` above `kXR_secNone` or any
`secvec` entry requires signing — and *that* selection is itself clause CLM-011.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| SIG-001 | When `seclvl` requires signing for a request code, that code **unsigned** is refused with `kXR_SigVerErr` (3022) | spec | O3 | XP |
| SIG-002 | A correctly signed request at the same level is served | spec | O3 | XP |
| SIG-003 † | A signature over the right payload but the wrong `expectrid` is refused | spec | O3 | XP |
| SIG-004 † | A replayed `seqno` is refused — `seqno` is documented as monotonically increasing | spec | O3 | XP |
| SIG-005 † | A `seqno` that skips forward is accepted (monotonic, not consecutive) | spec | O3 | XP |
| SIG-006 | `kXR_nodata` set means the payload was not hashed; a server must not then validate a payload hash | spec | O3 | XP |
| SIG-007 | `crypto` with an unknown hash in `kXR_HashMask` is refused, not defaulted to SHA-256 | spec | O3 | XP |
| SIG-008 | `version` != `kXR_Ver_00` is refused | spec | O3 | XP |
| SIG-009 † | Signing requirements are enforced identically on a bound substream as on the primary | cons | O1 | XP |
| SIG-010 † | `kXR_secOFrce` set means signing is enforced even on a TLS connection | spec | O3 | XP |

## 14. `OPN` — `kXR_open` (3010) and `kXR_close` (3003)

The option word is 16 bits (`XOpenRequestOption`) and the mode word is 9 bits
(`XOpenRequestMode`). The generator walks every single bit set alone, every
documented pair, and the illegal combinations named below.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| OPN-001 | `kXR_open_read` on an existing readable file returns a 4-byte `fhandle` | spec | O3 | XP |
| OPN-002 | Each open returns a **distinct** `fhandle`; two opens of the same path do not alias | spec | O1 | XP |
| OPN-003 † | An `fhandle` is not reused while the first handle is open, and a closed handle's value is refused with `kXR_FileNotOpen` (3004) until reissued | spec | O3 | XP |
| OPN-004 † | An `fhandle` from **another connection** is refused — cross-session handle theft | spec | O3 | XP |
| OPN-005 | `kXR_retstat` set makes the response carry the stat info after the handle; clear makes it not | spec | O3 | XP |
| OPN-006 | The `kXR_retstat` stat info is byte-identical to a `kXR_stat` on the same path | cons | O1 | XP |
| OPN-007 | `kXR_compress` set returns `cpsize`/`cptype`; an uncompressed file returns `cpsize` = 0 | spec | O3 | XP |
| OPN-008 | `kXR_new` **without** `kXR_delete` behaves as `O_EXCL`: creating over an existing file yields `kXR_ItExists` (3018) | spec | O3 | PN§14 |
| OPN-009 | `kXR_new` **with** `kXR_delete` truncates instead of failing | spec | O3 | PN§14 |
| OPN-010 | `kXR_mkpath` creates missing parents; without it, a missing parent yields `kXR_NotFound` | spec | O3 | XP |
| OPN-011 | `kXR_open_updt` on a read-only export yields `kXR_fsReadOnly` (3025), **not** `kXR_NotAuthorized` (3010) | spec | O3 | AG, CL-12 |
| OPN-012 | The read-only refusal is returned **before** any credential is evaluated: an anonymous client and a fully-scoped token get the same code | spec | O1 | CL-3, CL-12 |
| OPN-013 | Opening a directory path yields `kXR_isDirectory` (3016) | spec | O3 | PN§16 |
| OPN-014 | `kXR_open_apnd` positions writes at EOF; a write at an explicit offset under append is either honoured per spec or refused, never silently misplaced | spec | O1 | XP |
| OPN-015 | `kXR_posc` set makes an aborted transfer leave no visible file | spec | O3 | PN§29 |
| OPN-016 | `kXR_posc` set makes a cleanly closed transfer leave the complete file | spec | O3 | PN§29 |
| OPN-017 | `kXR_posc` on a server with `kXR_supposc` clear is refused, not silently ignored | cons | O1 | XP |
| OPN-018 † | `kXR_seqio` is accepted and does not change the bytes returned by a random-access read | spec | O1 | XP |
| OPN-019 † | `kXR_async` set does not change the byte content of any subsequent read | spec | O1 | XP |
| OPN-020 † | `kXR_nowait` on a staged-out (offline) file returns promptly with a defined answer instead of blocking | spec | O3 | XP |
| OPN-021 † | `kXR_refresh` forces a metadata re-read: after an out-of-band change, a refreshed open sees the new size | spec | O1 | XP |
| OPN-022 † | `kXR_replica` and `kXR_open_wrto` are either honoured or refused with `kXR_Unsupported` — never accepted and ignored | spec | O3 | XP |
| OPN-023 | CGI on a write-mode path is stripped before the path reaches storage | xrootd | O3 | PN§9 |
| OPN-024 † | Every one of the 16 option bits set **alone** produces either service or a defined error; none produces `kXR_ServerError` | spec | O3 | XP |
| OPN-025 † | Option bits 0xFFFF (all set, including contradictory ones) yields `kXR_ArgInvalid`, not a crash and not partial honouring | spec | O3 | XP |
| OPN-026 | `mode` bits outside the 9 defined in `XOpenRequestMode` are rejected or masked, and the created file's mode reflects only defined bits | spec | O1 | XP |
| OPN-027 | A path longer than the server's limit yields `kXR_ArgTooLong` (3002) | spec | O3 | XP |
| OPN-028 | An empty path (`dlen` = 0) yields `kXR_ArgMissing` (3001) | spec | O3 | XP |
| OPN-029 | Path traversal (`../`, encoded, doubled, overlong-UTF-8, backslash, NUL-truncated) never escapes the export root, on **open and every other path-taking verb** | spec | O3 | CL-4 |
| OPN-030 | `kXR_close` on a valid handle succeeds; a second close of the same handle yields `kXR_FileNotOpen` | spec | O3 | XP |
| OPN-031 † | `kXR_close` carrying a non-zero size argument that disagrees with the bytes written is refused | spec | O3 | XP |
| OPN-032 † | Handle exhaustion (open until refusal) yields `kXR_NoMemory` or a documented limit error, and the server recovers fully when the handles are closed | spec | O1 | — |
| OPN-033 † | An open handle survives an idle period exceeding the connection's keepalive, or is closed with a defined error — never silently invalidated | spec | O3 | — |

## 15. `RD` — `kXR_read` (3013): the fractional read grid

Generated from §6.1 × §6.2 over the §5.2 object set. The expected answer is
`n_expected = clamp(S − off, 0, len)` with `PRF`-derived content (§5.3).

| id | assertion | ref | O | src |
|---|---|---|---|---|
| RD-001 | A whole-object read returns exactly `S` bytes, byte-exact against `PRF` | spec | O2 | XP |
| RD-002 | **`rlen` = 0 returns `kXR_ok` with `dlen` = 0** — not an error, not EOF | spec | O2 | XP |
| RD-003 | **`offset` = `S` returns `kXR_ok` with zero bytes** — not `kXR_NotFound`, not `kXR_IOError` | spec | O2 | XP |
| RD-004 | `offset` > `S` returns `kXR_ok` with zero bytes | spec | O2 | XP |
| RD-005 | **A straddling read returns exactly `S − offset` bytes in one response** | spec | O2 | XP |
| RD-006 | A read of `[0,1)` returns exactly one byte, equal to `PRF(key,0)` | spec | O2 | XP |
| RD-007 | A read of `[S−1,S)` returns exactly the last byte | spec | O2 | XP |
| RD-008 | Reads at `offset` = 4095, 4096, 4097 return position-correct bytes (page-boundary off-by-one) | spec | O2 | XP |
| RD-009 | A read whose response would exceed 16 MiB is chunked with `kXR_oksofar` and terminated by `kXR_ok`; the reassembly is byte-exact | spec | O3+O1 | PN§26 |
| RD-010 | On object `Z` (size 0), every read returns `kXR_ok` with zero bytes | spec | O2 | XP |
| RD-011 † | Reads at `offset` ≥ 2³¹ on object `L` return position-correct bytes (32-bit truncation bug detector) | spec | O2 | XP |
| RD-012 † | A read at `offset` = 2⁶³−1 returns zero bytes or `kXR_ArgInvalid`, never wrapped-around data | spec | O2 | XP |
| RD-013 | `rlen` = 2³¹−1 on a small object returns `S − offset` bytes, not an allocation failure | spec | O2 | XP |
| RD-014 | **Any partition of `[0,S)` into fractional reads concatenates to the whole object** — run with 2, 3, 7, 4096 and `S` pieces, at aligned and unaligned cut points | cons | O1 | — |
| RD-015 † | The same read issued twice returns identical bytes (idempotence; catches a cache that mutates on read) | cons | O1 | — |
| RD-016 † | Overlapping concurrent reads of the same handle from two substreams return mutually consistent bytes | cons | O1 | — |
| RD-017 | A read on a handle opened write-only is refused | spec | O3 | XP |
| RD-018 | A read on a closed handle yields `kXR_FileNotOpen` (3004) | spec | O3 | XP |
| RD-019 | A read with an `fhandle` never issued yields `kXR_FileNotOpen`, not `kXR_ServerError` | spec | O3 | XP |
| RD-020 † | `read_args.pathid` = 0 means the primary stream; the response arrives on the primary | spec | O3 | XP |
| RD-021 † | `read_args.pathid` naming an unbound path yields an error, not a hang | spec | O3 | XP |
| RD-022 † | The readahead list appended to `read_args` is honoured or ignored, and either way the primary read's bytes are unchanged | spec | O1 | XP |
| RD-023 † | A `dlen` on `kXR_read` that is neither 0 nor `sizeof(read_args)` nor a valid readahead multiple yields `kXR_ArgInvalid` | spec | O3 | XP |
| RD-030 | `offset` < 0 yields `kXR_ArgInvalid` (3000) | spec | O3 | XP |
| RD-031 | `rlen` < 0 yields `kXR_ArgInvalid` | spec | O3 | XP |
| RD-032 | `offset` = −2⁶³ yields `kXR_ArgInvalid`, not an unsigned reinterpretation | spec | O3 | XP |
| RD-033 | `offset` < 0 **and** `rlen` < 0 yields one error, not two responses | spec | O3 | XP |

## 16. `PGR` — `kXR_pgread` (3030): the page algebra

**The marquee fractional family**, and the external check for CLAUDE.md
invariant 1. Every row is skipped with `claim-absent:kXR_suppgrw` if the server
did not advertise it — and that skip is itself asserted by CLM-008.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| PGR-001 | The response is a `kXR_status` (4007), **not** a plain `kXR_ok` | spec | O3 | XP, CL-1 |
| PGR-002 | `ServerResponseHeader::dlen` ≥ `kXR_statusBodyLen` (16) | spec | O3 | XP |
| PGR-003 | `ServerResponseBody_Status::requestid` equals `kXR_pgread − kXR_1stRequest` = 30 | spec | O3 | XP |
| PGR-004 | `ServerResponseBody_Status::streamID` equals the header streamid | spec | O3 | XP |
| PGR-005 | The body `crc32c` validates over the bytes it covers (RFC 7143 CRC32C) | spec | O3 | XP |
| PGR-006 | `resptype` is `kXR_FinalResult` for a single-frame answer and `kXR_PartialResult` for every non-final frame of a multi-frame answer | spec | O3 | XP |
| PGR-007 | `ServerResponseBody_pgRead::offset` equals the file offset of the data that follows | spec | O3 | XP |
| PGR-008 | An **aligned** offset with an exact multiple of 4096 returns `len/4096` units of `kXR_pgUnitSZ` (4100) bytes each | spec | O2 | XP |
| PGR-009 | **A non-page-aligned offset produces a fractional first unit whose CRC32C covers `min(4096 − off%4096, len)` bytes — never a zero-padded 4096** | spec | O2 | XP, CL-1 |
| PGR-010 | An aligned offset with a non-multiple length produces a short final unit, CRC over the actual bytes | spec | O2 | XP |
| PGR-011 | Both ends fractional produces a short first **and** a short last unit | spec | O2 | XP |
| PGR-012 | A request wholly inside one page (`len` < 4096, no boundary crossed) produces exactly one unit | spec | O2 | XP |
| PGR-013 | A request spanning a page boundary by exactly one byte produces exactly two units, the second of length 1 | spec | O2 | XP |
| PGR-014 | The unit count equals `(first_page_bytes>0) + full_pages + (last_page_bytes>0)` from §6.3 for every generated case | spec | O2 | XP |
| PGR-015 | `offset` = `S−1` returns one unit of one byte with a correct CRC | spec | O2 | XP |
| PGR-016 | On object `P0` (4095 bytes) every pgread's only unit is fractional | spec | O2 | XP |
| PGR-017 | On object `Z` (0 bytes) a pgread returns zero units and `kXR_ok`-equivalent status, not an error | spec | O2 | XP |
| PGR-018 | `rlen` = 0 returns zero units and success | spec | O2 | XP |
| PGR-019 | **`pgread` bytes equal plain `read` bytes for the same extent**, for every case in the grid | cons | O1 | — |
| PGR-020 | Every returned CRC32C matches a client-side recompute of the bytes actually delivered | cons | O1 | CL-1 |
| PGR-021 † | A deliberately corrupted page (injected by the fault proxy) is **detected** by the CRC — the negative fixture for this whole family | spec | O3 | §40 |
| PGR-022 † | `reqflags` = `kXR_pgRetry` (0x01) re-requests a page and returns the same bytes | spec | O1 | XP |
| PGR-023 † | `dlen` on the request must be 0 with no args, 1 with `pathid`, 2 with `pathid`+`reqflags`; any other value yields `kXR_ArgInvalid` | spec | O3 | XP |
| PGR-024 † | `pathid` = `kXR_AnyPath` (0xff) is accepted and the response arrives on some valid stream | spec | O3 | XP |
| PGR-025 | A pgread crossing the 16 MiB threshold splits into `kXR_PartialResult` frames whose reassembly is byte- and CRC-exact | spec | O3+O1 | PN§26, XP |
| PGR-026 † | Unit boundaries in a chunked pgread do not straddle frames — each frame contains whole units | spec | O3 | XP |
| PGR-027 † | At most `kXR_pgMaxEpr` (128) checksum errors are reported per request | spec | O3 | XP |
| PGR-028 † | Reads at `offset` ≥ 2³¹ on object `L` produce correct per-page CRCs (the 32-bit page-index truncation detector) | spec | O2 | XP |
| PGR-029 | pgread on a handle opened write-only is refused | spec | O3 | XP |
| PGR-030 | `offset` or `rlen` < 0 yields `kXR_ArgInvalid` | spec | O3 | XP |
| PGR-031 † | `ServerResponseBody_Status::reserved[4]` is zero in every returned frame | spec | O3 | XP |
| PGR-032 † | `resptype` is one of `kXR_FinalResult` (0), `kXR_PartialResult` (1), `kXR_ProgressInfo` (2) — no other value | spec | O3 | XP |

## 17. `PGW` — `kXR_pgwrite` (3026)

`mutate` probe class; skipped entirely under `--accept` on a read-only profile.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| PGW-001 | The response is a 32-byte `kXR_status` | xrootd | O3 | PN§10 |
| PGW-002 | The request payload is CRC-first per page, not data-first | xrootd | O3 | PN§11 |
| PGW-003 | `ServerResponseBody_pgWrite::offset` equals the offset written | spec | O3 | XP |
| PGW-004 | A correct pgwrite is read back byte-identically by `read` and by `pgread` | cons | O1 | — |
| PGW-005 | **A page with a deliberately wrong CRC is rejected** | spec | O3 | XP |
| PGW-006 | **A rejected page is not committed** — the prior bytes are still there on read-back | spec | O1 | — |
| PGW-007 | The rejection carries `ServerResponseBody_pgWrCSE` with `dlFirst`, `dlLast`, and the offset list | spec | O3 | XP |
| PGW-008 | `cseCRC` in that struct validates over the bits that follow it | spec | O3 | XP |
| PGW-009 † | A retry of only the rejected pages succeeds and yields a correct whole object | cons | O1 | XP |
| PGW-010 † | At most `kXR_pgMaxEos` (256) checksum errors are outstanding before the server takes terminal action | spec | O3 | XP |
| PGW-011 | A pgwrite at a non-page-aligned offset is either honoured with a correct fractional first page or refused — never silently realigned | spec | O2 | XP |
| PGW-012 | A pgwrite of zero length is a defined no-op success | spec | O3 | XP |
| PGW-013 | pgwrite on a read-only export yields `kXR_fsReadOnly` (3025) | spec | O3 | AG, CL-12 |
| PGW-014 | pgwrite when `kXR_suppgrw` is clear is refused, not accepted | cons | O1 | XP |

## 18. `WRT` / `WVC` / `SYN` / `TRN` / `CKP` — the write plane

| id | assertion | ref | O | src |
|---|---|---|---|---|
| WRT-001 | A write at EOF extends the object; read-back is byte-exact | spec | O1 | XP |
| WRT-002 | A write **beyond** EOF creates a hole; reading the hole returns zeros, and the object size reflects the far end | spec | O1 | XP |
| WRT-003 | A zero-length write is a defined success and does not change the size | spec | O3 | XP |
| WRT-004 | Overlapping writes leave the last-written bytes; read-back matches | cons | O1 | — |
| WRT-005 | A write on a read-only handle is refused | spec | O3 | XP |
| WRT-006 | A write to a read-only export yields `kXR_fsReadOnly` (3025), never `kXR_NotAuthorized` | spec | O3 | AG, CL-12 |
| WRT-007 | A write past quota yields `kXR_overQuota` (3021); past device capacity yields `kXR_NoSpace` (3009) | spec | O3 | XP |
| WRT-008 | The write payload limit is separate from the path limit; a payload over it yields a defined error | xrootd | O3 | PN§12 |
| WRT-009 | `offset` < 0 yields `kXR_ArgInvalid` | spec | O3 | XP |
| WRT-010 † | A write whose `dlen` disagrees with the bytes sent does not partially apply | spec | O1 | XP |
| WRT-011 † | Concurrent writes to disjoint extents of one handle both land | cons | O1 | — |
| WVC-001 † | `kXR_writev` (3031) with a valid `write_list` lands every element; read-back is byte-exact | spec | O1 | XP |
| WVC-002 † | Element count at `maxWvecsz` (1024) is accepted; 1025 is refused | spec | O3 | XP |
| WVC-003 † | `options` = `doSync` (0x01) makes the data durable before the response | spec | O3 | XP |
| WVC-004 † | A `writev` with a zero-length element is a defined no-op for that element only | spec | O1 | XP |
| WVC-005 † | `kXR_writev` when unsupported yields `kXR_Unsupported` (3013), never a silent partial write | spec | O3 | XP |
| SYN-001 | `kXR_sync` (3016) on a written handle succeeds and the bytes survive a reconnect | spec | O1 | XP |
| SYN-002 | `kXR_sync` on a read-only handle is a defined success or a defined error, not a crash | spec | O3 | XP |
| TRN-001 | `kXR_truncate` (3028) to a smaller size discards the tail; read-back confirms | spec | O1 | XP |
| TRN-002 | Truncate to a **larger** size zero-extends; the hole reads as zeros | spec | O1 | XP |
| TRN-003 | Truncate to 0 leaves a zero-length object that still exists | spec | O1 | XP |
| TRN-004 | Truncate to the current size is a no-op success | spec | O3 | XP |
| TRN-005 | Truncate with `offset` < 0 yields `kXR_ArgInvalid` | spec | O3 | XP |
| TRN-006 | Truncate on a read-only export yields `kXR_fsReadOnly` | spec | O3 | AG, CL-12 |
| TRN-007 † | Truncate by path and truncate by `fhandle` give the same result | cons | O1 | XP |
| CKP-001 † | `kXR_chkpoint` (3012) is either implemented or answered `kXR_Unsupported` — never `kXR_ServerError` | spec | O3 | XP |
| CKP-002 † | `kXR_ckpQMax` returns `maxCkpSize` ≥ `useCkpSize` | spec | O3 | XP |
| CKP-003 † | A checkpoint, a write, and a rollback restore the pre-write bytes exactly | cons | O1 | XP |
| CKP-004 † | A checkpoint that exceeds `maxCkpSize` is refused before any data is lost | spec | O3 | XP |

## 19. `STA` / `DIR` — `kXR_stat` (3017), `kXR_statx` (3022), `kXR_dirlist` (3004)

| id | assertion | ref | O | src |
|---|---|---|---|---|
| STA-001 | The stat response is **size before flags**, in the order stock clients parse | xrootd | O3 | PN§7 |
| STA-002 | The reported size equals `S` for every object in the §5.2 set | spec | O2 | XP |
| STA-003 | Flags for a regular file carry neither `kXR_isDir` nor `kXR_other` | spec | O3 | XP |
| STA-004 | Flags for a directory carry `kXR_isDir` (0x02) | spec | O3 | XP |
| STA-005 | `kXR_readable` / `kXR_writable` reflect the export policy: on a read-only export, `kXR_writable` is **clear** | cons | O1 | CL-12 |
| STA-006 | `kXR_writable` clear and an `open`-for-write refusal agree — the flag does not promise what the verb denies | cons | O1 | — |
| STA-007 | Stat on a nonexistent path yields `kXR_NotFound` (3011) | spec | O3 | XP |
| STA-008 | Stat by open `fhandle` (`dlen` = 0 with a handle) returns the same info as stat by path | cons | O1 | CL-7 |
| STA-009 | The `mtime` is a plausible UNIX time (not 0, not negative, not > now + skew) | spec | O3 | XP |
| STA-010 † | `kXR_offline` (0x01) is set only for objects that a read would have to stage | cons | O1 | XP |
| STA-011 † | `kXR_poscpend` (0x10) is set for a file left open under `kXR_posc` and clear afterwards | cons | O1 | XP |
| STA-012 † | `kXR_bkpexist` (0x20) is reported consistently between `stat` and `query` | cons | O1 | XP |
| STA-013 | `kXR_vfs` (0x01 in `options`) returns the filesystem-space form, not the file form | spec | O3 | XP |
| STA-014 | The `id` field is stable across two stats of the same object and differs between two distinct objects | cons | O1 | XP |
| STA-015 † | `kXR_statx` (3022) returns one flag byte per path, in request order, for a multi-path request | spec | O3 | XP |
| STA-016 † | `kXR_statx` flags agree with per-path `kXR_stat` flags for the same paths | cons | O1 | XP |
| STA-017 | Stat of a path with an embedded newline, tab, or 0x7F is answered or refused — never truncated silently | spec | O3 | PN§27 |
| STA-018 | Stat of a 4096-byte path yields `kXR_ArgTooLong`, not a buffer failure | spec | O3 | XP |
| DIR-001 | A dirlist of a known planted directory returns exactly the planted names, no more and no fewer | spec | O2 | — |
| DIR-002 | `kXR_dstat` set returns the `dStat` form; the entry count matches the plain form | cons | O1 | PN§17 |
| DIR-003 | The `dStat` form is introduced by the **10-byte sentinel** `.\n0 0 0 0\n` | xrootd | O3 | PN§17 |
| DIR-004 | Names containing control characters are skipped or escaped consistently in both forms | xrootd | O1 | PN§27 |
| DIR-005 | Dirlist of an empty directory returns success with zero entries, not `kXR_NotFound` | spec | O3 | XP |
| DIR-006 | Dirlist of a file path yields a defined error, not a one-entry listing | spec | O3 | XP |
| DIR-007 | A listing longer than one response is continued with `kXR_oksofar` and reassembles without duplicate or lost names | spec | O1 | PN§26 |
| DIR-008 † | `kXR_dcksm` set returns checksums that match `kXR_Qcksum` for the same entries | cons | O1 | XP |
| DIR-009 | Dirlist honours the export root: `..` in the listed path never yields entries from outside | spec | O3 | CL-4 |
| DIR-010 † | A directory of 10,000 entries lists completely; the count matches a second listing | cons | O1 | — |

## 20. `MKD` / `MV` / `RM` / `CHM` — the namespace-mutation plane

`mutate` probe class. Every row has a read-only twin asserting `kXR_fsReadOnly`.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| MKD-001 | `kXR_mkdir` (3008) creates the directory; a following `stat` shows `kXR_isDir` | spec | O1 | XP |
| MKD-002 | `kXR_mkdirpath` creates missing parents (`mkdir -p`) | spec | O3 | PN§15 |
| MKD-003 | Without `kXR_mkdirpath`, a missing parent yields `kXR_NotFound` | spec | O3 | PN§15 |
| MKD-004 | mkdir over an existing path yields `kXR_ItExists` (3018) | spec | O3 | XP |
| MKD-005 | mkdir on a read-only export yields `kXR_fsReadOnly` (3025) | spec | O3 | AG, CL-12 |
| MKD-006 | The created mode reflects only the 9 defined `XOpenRequestMode` bits | spec | O1 | XP |
| MV-001 | `kXR_mv` (3009) renames; the old path is gone and the new path holds the same bytes | spec | O1 | XP |
| MV-002 | The two paths are separated as the deployed server expects — **space-separated** for stock, `arg1len`-framed where the struct field is honoured; the tool probes both and reports which | xrootd | O3 | PN§13, XP |
| MV-003 | mv onto an existing target follows the server's documented policy consistently across two attempts | cons | O1 | XP |
| MV-004 | mv of a nonexistent source yields `kXR_NotFound` | spec | O3 | XP |
| MV-005 | mv across exports is refused with a defined error, not a silent copy | spec | O3 | XP |
| MV-006 | mv on a read-only export yields `kXR_fsReadOnly` | spec | O3 | AG, CL-12 |
| MV-007 | mv with one path empty yields `kXR_ArgMissing` (3001) | spec | O3 | XP |
| RM-001 | `kXR_rm` (3014) removes a file; a following `stat` yields `kXR_NotFound` | spec | O1 | XP |
| RM-002 | `kXR_rmdir` (3015) on an empty directory succeeds | spec | O1 | XP |
| RM-003 | **`kXR_rmdir` on a non-empty directory yields `kXR_ItExists` (3018), not `kXR_isDirectory`** — the acknowledged `ENOTEMPTY` wart | xrootd | O3 | XP |
| RM-004 | `kXR_rm` on a directory yields `kXR_isDirectory` (3016) | spec | O3 | XP |
| RM-005 | `kXR_rmdir` on a file yields a defined error, not a successful unlink | spec | O3 | XP |
| RM-006 | rm of a nonexistent path yields `kXR_NotFound` | spec | O3 | XP |
| RM-007 | rm on a read-only export yields `kXR_fsReadOnly` | spec | O3 | AG, CL-12 |
| RM-008 | A collection delete takes recursive child locks: a concurrent open of a child during the delete never observes a half-removed tree | cons | O1 | CL-5 |
| CHM-001 | `kXR_chmod` (3002) changes the mode; a following `stat` reflects it | spec | O1 | XP |
| CHM-002 | Mode bits outside the defined 9 are rejected or masked | spec | O1 | XP |
| CHM-003 | chmod on a read-only export yields `kXR_fsReadOnly` | spec | O3 | AG, CL-12 |
| CHM-004 † | chmod that would make an export-owned path unreadable by the server itself is refused or reversible | spec | O3 | — |

## 21. `LOC` / `FAT` / `PRP` / `QRY` — locate, xattr, prepare, query

| id | assertion | ref | O | src |
|---|---|---|---|---|
| LOC-001 | `kXR_locate` (3027) on an existing path returns at least one endpoint | spec | O3 | XP |
| LOC-002 | Each returned endpoint is prefixed by one of `S`/`s`/`M`/`m` and a `r`/`w`/`x`/`?` access byte | spec | O3 | XP |
| LOC-003 | A returned `S`/`s` endpoint actually serves the path — the tool connects and stats it | cons | O1 | — |
| LOC-004 | A `w` access byte on a read-only export is a divergence: the locate promise contradicts the open refusal | cons | O1 | CL-12 |
| LOC-005 | `kXR_refresh` set forces a fresh lookup rather than a cached answer | spec | O1 | XP |
| LOC-006 | `kXR_nowait` returns promptly even when a subset of the cluster is slow | spec | O3 | XP |
| LOC-007 | `kXR_prefname` returns hostnames; without it, addresses | spec | O3 | XP |
| LOC-008 | Locate of a nonexistent path yields `kXR_NotFound`, not an empty success | spec | O3 | XP |
| LOC-009 † | `kXR_addrboth` / `kXR_addrIPv4` / `kXR_addrIPv6` each return the requested family only | spec | O3 | XP |
| LOC-010 † | `kXR_compress` on locate returns the compact form and the same endpoint set | cons | O1 | XP |
| FAT-001 † | `kXR_fattr` (3020) `kXR_fattrSet` then `kXR_fattrGet` round-trips the exact value bytes | cons | O1 | XP |
| FAT-002 † | `kXR_fattrList` includes every name previously set and no others | cons | O1 | XP |
| FAT-003 † | `kXR_fattrDel` removes the name; a following get yields the defined not-found error | cons | O1 | XP |
| FAT-004 † | A value at `kXR_faMaxVlen` (65536) is accepted; 65537 is refused | spec | O3 | XP |
| FAT-005 † | A name at `kXR_faMaxNlen` (248) is accepted; 249 is refused | spec | O3 | XP |
| FAT-006 † | At most `kXR_faMaxVars` (16) variables per request are accepted; 17 is refused | spec | O3 | XP |
| FAT-007 † | An 8-bit-clean value (all 256 byte values) round-trips unchanged | cons | O1 | XP |
| FAT-008 † | `kXR_fattr` when unimplemented yields `kXR_Unsupported`, never `kXR_ServerError` | spec | O3 | XP |
| FAT-009 † | fattr set on a read-only export yields `kXR_fsReadOnly` | spec | O3 | AG, CL-12 |
| PRP-001 | `kXR_prepare` (3021) with `kXR_stage` returns a request id | spec | O3 | XP |
| PRP-002 | `kXR_cancel` with that id is accepted; a second cancel is a defined error, not a crash | spec | O3 | XP |
| PRP-003 † | `kXR_evict` (0x04) on a cached object makes a following read re-stage rather than serve stale bytes | cons | O1 | XP |
| PRP-004 † | `kXR_fresh` forces a re-stage even when a copy is resident | cons | O1 | XP |
| PRP-005 | `kXR_prepare` of a nonexistent path yields an error at request time or a failed status at query time — never silent success forever | spec | O3 | XP |
| PRP-006 | `kXR_notify` with an unreachable notification target does not wedge the request | spec | O3 | XP |
| PRP-007 | prepare on a read-only export: staging is a read-side operation and is **not** refused with `kXR_fsReadOnly` | spec | O3 | CL-12 |
| QRY-001 | `kXR_query` (3001) `kXR_Qconfig` returns one line per requested keyword, in request order | spec | O3 | XP |
| QRY-002 | `kXR_Qconfig tpc` returns a **raw numeric** value, not a yes/no word | xrootd | O3 | PN§28 |
| QRY-003 | Every `kXR_Qconfig` value the server reports is consistent with observed behaviour — `readv_ior_max` bounds the largest accepted readv element, `chksum` names the algorithms `kXR_Qcksum` actually serves | cons | O1 | — |
| QRY-004 | `kXR_Qcksum` returns `<algo> <hex>`; the hex matches a client-side recompute of the bytes | cons | O1+O2 | XP |
| QRY-005 | **`crc64` and `crc64nvme` are distinct algorithms and are not answered interchangeably** | spec | O3 | CL-9 |
| QRY-006 | Requesting an unsupported algorithm yields a defined error, not a different algorithm's digest | spec | O3 | CL-9 |
| QRY-007 | `kXR_Qckscan` returns the scan state without recomputing | spec | O3 | XP |
| QRY-008 | `kXR_Qspace` returns `oss.space` values whose free ≤ total | cons | O1 | XP |
| QRY-009 | `kXR_Qxattr` returns the extended attributes for the path | spec | O3 | XP |
| QRY-010 † | `kXR_Qvisa`, `kXR_Qopaque`, `kXR_Qopaquf`, `kXR_Qopaqug` are answered or `kXR_Unsupported` — never `kXR_ServerError` | spec | O3 | XP |
| QRY-011 | `kXR_Qprep` on a live request id returns a status whose fields agree with the `kXR_prepare` that created it | cons | O1 | XP |
| QRY-012 | `kXR_Qstats` output parses as the documented summary format | spec | O3 | XP |
| QRY-013 † | An unknown `infotype` yields `kXR_ArgInvalid`, not a default answer | spec | O3 | XP |
| QRY-014 | `kXR_Qconfig` of an unknown keyword returns a defined not-supported marker for that line and still answers the known ones | spec | O1 | XP |

## 22. `RDV` — `kXR_readv` (3025): the vector-read grid

`readv` is where fractional geometry and framing meet: the response is a chain
of `readahead_list` headers whose lengths and offsets must reproduce the request
exactly. Generated from the §6.2 length axis crossed with element counts.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| RDV-001 | A one-element readv returns the same bytes as the equivalent `kXR_read` | cons | O1 | XP |
| RDV-002 | Each returned `readahead_list` element echoes the requested `rlen` and `offset` | spec | O3 | XP |
| RDV-003 | Elements are returned **in request order** | spec | O3 | XP |
| RDV-004 | The concatenation of all elements is byte-exact against `PRF` for every element extent | spec | O2 | — |
| RDV-005 | Duplicate elements (the same extent twice) both return, both correct | spec | O2 | XP |
| RDV-006 | Overlapping elements each return their own full extent | spec | O2 | XP |
| RDV-007 | Elements given out of ascending offset order are **not** silently reordered | spec | O3 | XP |
| RDV-008 | A zero-length element returns a zero-length element, not an omission | spec | O2 | XP |
| RDV-009 | An element wholly past EOF returns zero bytes for that element and does not fail the request | spec | O2 | XP |
| RDV-010 | An element straddling EOF returns exactly `S − offset` bytes for that element | spec | O2 | XP |
| RDV-011 | `maxRvecsz` (1024) elements are accepted; 1025 is refused with a defined error | spec | O3 | XP |
| RDV-012 | Total data at `maxRVdsz` (2097136) is accepted; one byte more is refused | spec | O3 | XP |
| RDV-013 | A single element at `maxTransferSize` is accepted; larger is refused | spec | O3 | XP |
| RDV-014 † | Elements naming **different `fhandle`s** in one readv are served correctly or refused wholesale — never mixed up | spec | O2 | XP |
| RDV-015 † | An element naming a closed handle fails that element or the request with `kXR_FileNotOpen`, never returns another handle's bytes | spec | O3 | XP |
| RDV-016 | An element with negative `offset` or `rlen` yields `kXR_ArgInvalid` for the request | spec | O3 | XP |
| RDV-017 | A `dlen` that is not a whole multiple of the element size yields `kXR_ArgInvalid` | spec | O3 | XP |
| RDV-018 | A readv whose total exceeds one response is chunked with `kXR_oksofar`; reassembly preserves element boundaries | spec | O1 | PN§26 |
| RDV-019 | `readv_ior_max` and `readv_iov_max` reported by `kXR_Qconfig` bound what readv actually accepts | cons | O1 | — |
| RDV-020 † | 1024 one-byte elements at 1024 scattered offsets each return the right byte (the scatter-correctness detector) | spec | O2 | — |

## 23. `RDR` / `WAI` / `ATN` / `CHU` / `BND` / `ENV` — control and flow

| id | assertion | ref | O | src |
|---|---|---|---|---|
| RDR-001 | A `kXR_redirect` (4004) carries a valid `host[:port][?opaque]` | spec | O3 | XP |
| RDR-002 | The redirect target actually serves the path — the tool follows it and stats | cons | O1 | — |
| RDR-003 | A redirect loop terminates: the tool follows at most N hops and reports a divergence if the chain does not converge | spec | O1 | — |
| RDR-004 | A redirect does not silently downgrade the security level — a `roots://` client is not sent to a cleartext endpoint | spec | O3 | CL-2 |
| RDR-005 † | Opaque data attached to a redirect is echoed back on the follow-up request and honoured | spec | O1 | XP |
| RDR-006 | A manager with zero eligible data servers answers with a defined error, not an empty redirect | spec | O3 | — |
| WAI-001 | A `kXR_wait` (4005) carries a plausible seconds value (≥ 0, ≤ a sane ceiling) | spec | O3 | XP |
| WAI-002 | Retrying after the stated wait succeeds or yields a **different** answer — an endless identical wait is a divergence | cons | O1 | — |
| WAI-003 | `kXR_waitresp` (4006) is followed by the real response on the same streamid | spec | O3 | XP |
| WAI-004 † | Under a load spike the server sheds with `kXR_wait` rather than dropping connections | cons | O1 | — |
| ATN-001 † | `kXR_attn` (4001) `kXR_asyncdi` / `kXR_asyncrd` / `kXR_asyncwt` bodies parse per their structs | spec | O3 | XP |
| ATN-002 † | `kXR_asyncms` message text is NUL-terminated and within `dlen` | spec | O3 | XP |
| ATN-003 † | An `attn` arrives only on a stream that requested async notification | spec | O3 | XP |
| CHU-001 | `kXR_oksofar` (4000) frames are followed by exactly one terminal frame | spec | O3 | XP |
| CHU-002 | Every `oksofar` frame carries the same streamid as the request | spec | O3 | XP |
| CHU-003 | The 16 MiB boundary is the split point; a response one byte under it is unsplit | xrootd | O3 | PN§26 |
| CHU-004 | Concurrent chunked responses on two streamids interleave without cross-contamination | cons | O1 | — |
| BND-001 † | `kXR_bind` (3024) returns a `pathid` that a following read can use | spec | O3 | PN§25 |
| BND-002 † | Data requested on a bound substream arrives on that substream | spec | O3 | PN§25 |
| BND-003 † | Bytes read over a substream are byte-identical to the primary-stream read | cons | O1 | — |
| BND-004 † | Binding more substreams than the server supports is refused with a defined error | spec | O3 | XP |
| BND-005 † | A `pathid` from a closed substream is refused, not reused | spec | O3 | XP |
| ENV-001 | `kXR_set` (3018) always answers `kXR_ok` — even for an unknown key | xrootd | O3 | PN§24 |
| ENV-002 † | `kXR_ping` (3011) answers `kXR_ok` and does not disturb an in-flight read on another stream | spec | O1 | XP |
| ENV-003 † | `kXR_endsess` (3023) with a valid session id ends that session; a following request on it is refused | spec | O3 | XP |
| ENV-004 † | `kXR_endsess` with a **foreign** session id is refused — cross-session teardown | spec | O3 | XP |
| ENV-005 † | `kXR_gpfile` (3005) is implemented or answers `kXR_Unsupported` | spec | O3 | XP |

## 24. `ERR` — the error-mapping ledger

Grounded in `XProtocol::mapError()` (§4), and **exhaustive over it**: every
`case` arm in that switch has a row, plus the `default:` arm. Each row provokes
the errno condition and asserts the exact wire code. This family is the external check for
CLAUDE.md invariant 12 and for the errno→kXR→HTTP table in the agent guide.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| ERR-001 | `ENOENT` → `kXR_NotFound` (3011) | spec | O3 | XP |
| ERR-002 | `EINVAL` → `kXR_ArgInvalid` (3000) | spec | O3 | XP |
| ERR-003 | `EPERM` → `kXR_NotAuthorized` (3010) | spec | O3 | XP |
| ERR-004 | `EACCES` → `kXR_NotAuthorized` (3010) | spec | O3 | XP |
| ERR-005 | **`EROFS` → `kXR_fsReadOnly` (3025), never `kXR_NotAuthorized` (3010)** | spec | O3 | XP, AG, CL-12 |
| ERR-006 | `EEXIST` → `kXR_ItExists` (3018) | spec | O3 | XP |
| ERR-007 | **`ENOTEMPTY` → `kXR_ItExists` (3018)** — the acknowledged wart, not `kXR_isDirectory` | xrootd | O3 | XP |
| ERR-008 | `EISDIR` → `kXR_isDirectory` (3016) | spec | O3 | XP |
| ERR-009 | `ENAMETOOLONG` → `kXR_ArgTooLong` (3002) | spec | O3 | XP |
| ERR-010 | `EIO` → `kXR_IOError` (**3007**) | spec | O3 | XP |
| ERR-011 | `ENOMEM` → `kXR_NoMemory` (3008) | spec | O3 | XP |
| ERR-012 | `ENOBUFS` → `kXR_NoMemory` (3008) — the second errno on that code | spec | O3 | XP |
| ERR-013 | `ENOSPC` → `kXR_NoSpace` (3009) | spec | O3 | XP |
| ERR-014 | `EDQUOT` → `kXR_overQuota` (3021) | spec | O3 | XP |
| ERR-015 | `ENOTSUP` → `kXR_Unsupported` (3013) | spec | O3 | XP |
| ERR-016 | `EBADF` → `kXR_FileNotOpen` (3004) | spec | O3 | XP |
| ERR-017 | `ETIMEDOUT` → `kXR_ReqTimedOut` (**3034**) | spec | O3 | XP |
| ERR-018 | `ETIME` → `kXR_TimerExpired` (3035) — distinct from `ETIMEDOUT` | spec | O3 | XP |
| ERR-019 | `ECANCELED` → `kXR_Cancelled` (3017) | spec | O3 | XP |
| ERR-020 | `ETXTBSY` → `kXR_inProgress` (3020) | spec | O3 | XP |
| ERR-021 | `EBADRQC` → `kXR_InvalidRequest` (3006) | spec | O3 | XP |
| ERR-022 | `ENOTBLK` → `kXR_NotFile` (3015) | spec | O3 | XP |
| ERR-023 | `ENODEV` → `kXR_FSError` (**3005**) — **not** `kXR_NotFile` | spec | O3 | XP |
| ERR-024 | `EFAULT` → `kXR_ServerError` (**3012**) — the *only* errno that maps here | spec | O3 | XP |
| ERR-025 | `EDOM` → `kXR_ChkSumErr` (3019) | spec | O3 | XP |
| ERR-026 | `EILSEQ` → `kXR_SigVerErr` (3022) | spec | O3 | XP |
| ERR-027 | `ERANGE` → `kXR_DecryptErr` (3023) | spec | O3 | XP |
| ERR-028 | `EUSERS` → `kXR_Overloaded` (3024) | spec | O3 | XP |
| ERR-029 | `ENOATTR` → `kXR_AttrNotFound` (3027) | spec | O3 | XP |
| ERR-030 | `EPROTOTYPE` → `kXR_TLSRequired` (3028) | spec | O3 | XP |
| ERR-031 | `EADDRNOTAVAIL` → `kXR_noReplicas` (3029) | spec | O3 | XP |
| ERR-032 | `EAUTH` → `kXR_AuthFailed` (3030) | spec | O3 | XP |
| ERR-033 | `EIDRM` → `kXR_Impossible` (3031) | spec | O3 | XP |
| ERR-034 | `ENOTTY` → `kXR_Conflict` (**3032**) — **not** `kXR_Unsupported` | spec | O3 | XP |
| ERR-035 | `ETOOMANYREFS` → `kXR_TooManyErrs` (3033) | spec | O3 | XP |
| ERR-036 | `ENETUNREACH` / `EHOSTUNREACH` / `ECONNREFUSED` → `kXR_noserver` (3014) — three errnos, one code, and the collapse is recorded not flagged | spec | O3 | XP |
| ERR-037 | **`kXR_FSError` (3005) is `mapError()`'s `default:` arm — so it is the true catch-all, and a run in which it appears often is a run against a server that is not classifying its failures.** The tool counts and reports it separately from every other code | spec | O1 | XP |
| ERR-038 | **`kXR_ServerError` (3012) appears only for a genuine internal fault** — every occurrence is reported with its provoking request as a probable server bug | spec | O1 | XP |
| ERR-039 | Every error response carries a non-empty, NUL-terminated, human-readable message within `dlen` | spec | O3 | XP |
| ERR-040 | The message does not leak an absolute server filesystem path, a hostname the client did not supply, or a credential fragment | spec | O3 | — |
| ERR-041 | The same logical failure returns the same code on two attempts (determinism) | cons | O1 | — |
| ERR-042 | The same logical failure returns the same code through `open`, `stat` and `query` (cross-verb agreement) | cons | O1 | — |
| ERR-043 | **The same logical failure maps to the corresponding HTTP status on the HTTP plane** — 3011/404, 3010/403, 3025/403, 3000/400, 3007/500, 3008/507 | cons | O1 | AG |
| ERR-044 | `kXR_fsReadOnly` on the WebDAV plane is `403`; on S3 `AccessDenied` XML; on OCI `DENIED`; on GridFTP `550 Permission denied (read-only)` | spec | O3 | AG |
| ERR-045 | No code outside 3000–3035 is ever returned (`kXR_ERRFENCE` = 3036) | spec | O3 | XP |
| ERR-046 | `toErrno()` is **not** asserted to be an inverse of `mapError()` — `EPERM`/`EACCES` collapse onto 3010, and `ENETUNREACH`/`EHOSTUNREACH`/`ECONNREFUSED` onto 3014. The tool records each collapse rather than reporting it as a divergence | spec | O3 | XP |
| ERR-047 † | An authentication failure is `kXR_AuthFailed` (3030) or `kXR_NotAuthorized` (3010), never `kXR_FSError`, for every enabled security protocol | spec | O1 | — |
| ERR-048 † | A policy refusal is distinguishable on the wire from a missing object, but not so finely that the error code alone lets a probing client enumerate a namespace beyond its scope | spec | O3 | — |

## 25. `TLS` / `CLM` — transport security and claims-versus-behaviour

| id | assertion | ref | O | src |
|---|---|---|---|---|
| TLS-001 | `kXR_gotoTLS` in the protocol response is followed by a working TLS upgrade | spec | O3 | XP |
| TLS-002 | Every request class the server flags as TLS-required (`kXR_tlsData`, `kXR_tlsGPF`, `kXR_tlsLogin`, `kXR_tlsSess`, `kXR_tlsTPC`) is **refused in cleartext** | cons | O1 | XP, CL-2 |
| TLS-003 | Every class **not** flagged is served in cleartext — the server does not over-enforce beyond its advertisement | cons | O1 | XP |
| TLS-004 | Under TLS, response buffers are memory-backed; the tool detects a sendfile-path leak by asserting the cleartext-only fast path is not taken on a TLS connection (observable as a `Content-Length`/`dlen` mismatch or an unencrypted segment) | spec | O3 | CL-2 |
| TLS-005 | A TLS session and a cleartext session return byte-identical data for the same read | cons | O1 | — |
| TLS-006 | TLS 1.2 is the floor; a 1.1 or 1.0 ClientHello is refused | spec | O3 | — |
| TLS-007 | The certificate chain presented validates against the site CA bundle, and the hostname matches | spec | O3 | RFC5280 |
| TLS-008 † | Renegotiation is refused | spec | O3 | — |
| TLS-009 † | A resumed session does not carry the previous session's authorization | spec | O3 | — |
| CLM-001 | Every bit set in the `kXR_protocol` flag word has a family that exercises it | cons | O1 | XP |
| CLM-002 | `kXR_isManager` claimed ⇒ `kXR_locate` and redirects work; `kXR_isServer` claimed ⇒ direct reads work | cons | O1 | XP |
| CLM-003 | `kXR_attrMeta` / `kXR_attrProxy` / `kXR_attrSuper` are consistent with the observed role | cons | O1 | XP |
| CLM-004 | `kXR_supgetf` / `kXR_supputf` claimed ⇒ `kXR_gpfile` works; not claimed ⇒ it is refused with `kXR_Unsupported` | cons | O1 | XP |
| CLM-005 | `kXR_haveTLS` claimed ⇒ the TLS handshake completes | cons | O1 | XP |
| CLM-006 | `kXR_anongpf` claimed ⇒ an unauthenticated gpfile is served; not claimed ⇒ it is refused | cons | O1 | XP |
| CLM-007 | **Unclaimed features do not work** — for every clear bit, the corresponding verb is refused, not quietly served | cons | O1 | XP |
| CLM-008 | Every clause skipped for `claim-absent:<flag>` names a flag that was genuinely clear in the protocol response — the skip ledger is itself audited | cons | O1 | §8.3 |
| CLM-009 | `kXR_Qconfig` values agree with the protocol flag word: `tpc` non-zero ⇔ TPC is served, `chksum` names algorithms `kXR_Qcksum` serves | cons | O1 | — |
| CLM-010 | The advertised protocol version is ≥ every feature the server actually implements — a v4 server serving pgread is a divergence | cons | O1 | XP |

## 26. `HTR` / `HTC` / `HTE` / `DAV` — the HTTP and WebDAV planes

The same endpoint usually serves `root://` and `https://` over the same
namespace. Every row here has a `root://` twin in §14–§25; the value is the
**cross-plane agreement** (`XPR`, §30), not the HTTP behaviour alone.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| HTR-001 | `GET` of a planted object returns exactly `S` bytes, byte-exact against `PRF` | spec | O2 | RFC9110 |
| HTR-002 | `HEAD` returns the same `Content-Length` as the `GET` body length and no body | spec | O1 | RFC9110 |
| HTR-003 | `Range: bytes=0-0` returns `206` with exactly one byte and `Content-Range: bytes 0-0/S` | spec | O2 | RFC9110 §14 |
| HTR-004 | `Range: bytes=S-1-` (last byte) returns `206` with one byte | spec | O2 | RFC9110 |
| HTR-005 | `Range: bytes=-1` (suffix) returns the **last** byte, not the first | spec | O2 | RFC9110 |
| HTR-006 | `Range: bytes=-0` is unsatisfiable → `416` | spec | O3 | RFC9110 |
| HTR-007 | `Range: bytes=S-` returns `416` with `Content-Range: bytes */S` | spec | O3 | RFC9110 |
| HTR-008 | `Range: bytes=0-S` (end past EOF) is clamped to `S−1` and returns `206`, not `416` | spec | O2 | RFC9110 |
| HTR-009 | `Range: bytes=0-` on a zero-length object returns `416`, and a plain `GET` returns `200` with zero bytes | spec | O3 | RFC9110 |
| HTR-010 | A **multi-range** request returns `206` `multipart/byteranges` whose parts reassemble byte-exact, or `200` with the whole object — never a single wrong part | spec | O2 | RFC9110 |
| HTR-011 | Overlapping and descending ranges are handled per the coalescing rules and the returned parts are individually correct | spec | O2 | RFC9110 |
| HTR-012 | A range set with more parts than the server's limit yields `200` or `416`, never a truncated `206` | spec | O3 | RFC9110 |
| HTR-013 | `Range: bytes=abc-def` is ignored (`200`), not `500` | spec | O3 | RFC9110 |
| HTR-014 | `Range: bytes=2-1` (inverted) is ignored or `416`, never a negative-length body | spec | O3 | RFC9110 |
| HTR-015 | The `Content-Length` always equals the bytes actually delivered | cons | O1 | RFC9110 |
| HTR-016 | `Transfer-Encoding: chunked` responses reassemble to exactly `Content-Length`-equivalent bytes and terminate with a zero chunk | spec | O3 | RFC9112 |
| HTR-017 | `ETag` is stable across two `GET`s and changes after a write | cons | O1 | RFC9110 |
| HTR-018 | `If-None-Match` with the current `ETag` returns `304` and no body | spec | O3 | RFC9110 |
| HTR-019 | `If-Range` with a stale validator returns the whole object, not a mixed body | spec | O3 | RFC9110 |
| HTR-020 | `Accept-Encoding: gzip` either returns identity or a body that decompresses byte-exact | cons | O1 | RFC9110 |
| HTR-021 | `Digest`/`Want-Digest` values match a client-side recompute and use the same algorithm names as `kXR_Qcksum` | cons | O1+O2 | CL-9 |
| HTC-001 | A `PUT` of known bytes is read back byte-exact by `GET` **and** by `root://` read | cons | O1 | — |
| HTC-002 | A `PUT` to a read-only export returns `403`, and the `root://` twin returns `kXR_fsReadOnly` | cons | O1 | AG, CL-12 |
| HTC-003 | A zero-length `PUT` creates a zero-length object | spec | O1 | RFC9110 |
| HTC-004 | A `PUT` whose body is shorter than `Content-Length` leaves no partial object | spec | O1 | RFC9112 |
| HTC-005 | Chunked `PUT` with a malformed terminator leaves no partial object | spec | O1 | RFC9112 |
| HTE-001 | `404` for missing, `403` for denied, `403` for read-only, `400` for invalid, `500` for I/O, `507` for no-space — matching the errno table | spec | O3 | AG |
| HTE-002 | No error body leaks a server filesystem path or a credential | spec | O3 | — |
| HTE-003 | An unknown method yields `405` with an `Allow` header, not `500` | spec | O3 | RFC9110 |
| HTE-004 | Header injection via `%0d%0a` in a path is rejected; no split response | spec | O3 | RFC9112 |
| HTE-005 | A request line at and above the server's limit yields `414`, not a crash | spec | O3 | RFC9112 |
| HTE-006 | Duplicate `Content-Length`, or `Content-Length` with `Transfer-Encoding`, is rejected — request-smuggling defence | spec | O3 | RFC9112 §6.3 |
| HTE-007 | Absolute-form and origin-form request targets resolve to the same object | cons | O1 | RFC9112 |
| HTE-008 | `%2e%2e%2f` and every other traversal encoding is rejected identically to the literal form | spec | O3 | CL-4 |
| DAV-001 | `PROPFIND` `Depth: 0` returns exactly one response element | spec | O3 | RFC4918 |
| DAV-002 | `PROPFIND` `Depth: 1` returns the collection plus its direct children, matching a `kXR_dirlist` | cons | O1 | RFC4918 |
| DAV-003 | `PROPFIND` `Depth: infinity` is served or `403` with `propfind-finite-depth` — never a partial tree presented as complete | spec | O3 | RFC4918 |
| DAV-004 | `getcontentlength` equals `S` for every planted object | spec | O2 | RFC4918 |
| DAV-005 | `MKCOL` on an existing collection yields `405` | spec | O3 | RFC4918 |
| DAV-006 | `DELETE` of a collection is recursive and atomic from the client's view | spec | O1 | RFC4918, CL-5 |
| DAV-007 | `MOVE` with `Overwrite: F` onto an existing target yields `412` | spec | O3 | RFC4918 |
| DAV-008 | `COPY`/`MOVE` `Destination` outside the export is refused | spec | O3 | CL-4 |
| DAV-009 | A multi-status body is well-formed XML whose per-href statuses match the single-resource answers | cons | O1 | RFC4918 |
| DAV-010 | `LOCK`/`UNLOCK` round-trip a token, and a write without the token yields `423` | spec | O1 | RFC4918 |
| DAV-011 | XML entity expansion in a `PROPFIND` body is refused — no external entity is fetched | spec | O3 | — |

## 27. `S3` — the S3 plane

| id | assertion | ref | O | src |
|---|---|---|---|---|
| S3-001 | `GetObject` returns exactly `S` bytes, byte-exact against `PRF` | spec | O2 | AWS |
| S3-002 | The same `Range` grid as `HTR-003`–`HTR-014` gives the same byte answers | cons | O1 | — |
| S3-003 | `ListObjectsV2` returns the planted key set exactly; pagination with `max-keys=1` yields the same set | cons | O1 | AWS |
| S3-004 | Continuation tokens are opaque and a replayed token returns the same page | cons | O1 | AWS |
| S3-005 | A **SigV4 signature over a modified request** is rejected — signing covers the canonical request, not just the path | spec | O3 | CL-6 |
| S3-006 | An expired presigned URL is rejected | spec | O3 | AWS |
| S3-007 | A presigned URL for one key does not serve another key | spec | O3 | CL-6 |
| S3-008 | **A WLCG bearer token is not accepted in place of a SigV4 signature, and vice versa** | spec | O3 | CL-6 |
| S3-009 | `AccessDenied` XML is returned for a read-only-export write, matching `kXR_fsReadOnly` on the twin | cons | O1 | AG |
| S3-010 | `NoSuchKey` for missing, `NoSuchBucket` for a missing export — not a generic `InternalError` | spec | O3 | AWS |
| S3-011 | Multipart upload: parts out of order reassemble correctly; a missing part fails the complete | spec | O1 | AWS |
| S3-012 | A part below the minimum size (except the last) is refused at complete time | spec | O3 | AWS |
| S3-013 | The `ETag` of a multipart object has the `-N` form and is not mistaken for an MD5 | spec | O3 | AWS |
| S3-014 | Key names with `+`, `%`, spaces, and UTF-8 round-trip through list and get unchanged | cons | O1 | AWS |

## 28. `CMS` / `CAC` / `TPC` — cluster, cache, and third-party copy

| id | assertion | ref | O | src |
|---|---|---|---|---|
| CMS-001 | A manager's `kXR_locate` set is a subset of the data servers that actually hold the path | cons | O1 | — |
| CMS-002 | A path held by no server yields `kXR_NotFound` from the manager, not an empty redirect | spec | O3 | — |
| CMS-003 | With one data server down, the manager still redirects to a live holder | cons | O1 | — |
| CMS-004 | With **all** holders down, the manager answers a defined error within the stated wait, not a hang | cons | O1 | — |
| CMS-005 | Two managers in a redundant pair return mutually consistent locate answers | cons | O1 | — |
| CMS-006 | A manager does not serve data directly when it claims `kXR_isManager` only | cons | O1 | XP |
| CMS-007 | The cluster map from `xrdmapc` matches the endpoints `kXR_locate` returns | cons | O1 | — |
| CAC-001 | A cache's first read populates and the second read is byte-identical | cons | O1 | — |
| CAC-002 | **A cached read and an origin read return identical bytes** for every extent in the fractional grid — the cache does not change page geometry | cons | O1 | — |
| CAC-003 | A partially filled block serves correct bytes for the filled and unfilled parts alike | spec | O2 | — |
| CAC-004 | Serve-while-filling returns bytes that are correct at every offset, never zeros for the not-yet-filled tail | spec | O2 | — |
| CAC-005 | An over-capacity cache refuses or evicts — it does not answer `504`/transient for a readable object | spec | O3 | — |
| CAC-006 | `kXR_prepare kXR_evict` followed by a read re-fetches; the bytes are still correct | cons | O1 | — |
| CAC-007 | A cache's `kXR_Qcksum` equals the origin's for the same object | cons | O1 | — |
| CAC-008 | A cache's `stat` size equals the origin's | cons | O1 | — |
| CAC-009 | Under a corrupted cache block (fault-injected), the read fails or refetches — it never serves the corruption | spec | O3 | §40 |
| CAC-010 | A cache on a read-only export answers writes with `kXR_fsReadOnly`, not a cache-local success | spec | O3 | CL-12 |
| TPC-001 | A native TPC pull of a planted object lands byte-exact at the destination | cons | O2 | CL-11 |
| TPC-002 | The TPC rendezvous key is single-use: replaying it is refused | spec | O3 | — |
| TPC-003 | A TPC whose source refuses authorization fails **terminally** — no retry loop, no partial destination object | spec | O1 | — |
| TPC-004 | A destination-side abort leaves no partial object when `kXR_posc` is in force | spec | O1 | PN§29 |
| TPC-005 | The delegated credential is not usable for any path outside the transfer's scope | spec | O3 | — |
| TPC-006 | WebDAV TPC (`COPY` with `Source`/`Destination` and a bearer) transfers the same bytes as native TPC | cons | O1 | CL-11 |
| TPC-007 | The TPC CGI parameter set is the documented one; unknown parameters are ignored, not honoured | spec | O3 | PN§30 |
| TPC-008 | `kXR_Qconfig tpc` numeric value agrees with whether TPC actually works | cons | O1 | PN§28, CLM-009 |
| TPC-009 | A TPC to an egress-blocked destination is refused at the source, not attempted | spec | O3 | — |

## 29. `XPR` — cross-plane agreement

The rows that only a multi-protocol tool can check. Each names one object and
asserts that every enabled plane tells the same story about it.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| XPR-001 | Object size agrees across `kXR_stat`, HTTP `Content-Length`, WebDAV `getcontentlength`, and S3 `ContentLength` | cons | O1 | — |
| XPR-002 | Object **bytes** agree across `root://` read, `pgread`, HTTP `GET`, and S3 `GetObject`, over the whole fractional grid | cons | O1+O2 | — |
| XPR-003 | Checksums agree across `kXR_Qcksum`, HTTP `Digest`, and S3 `ChecksumSHA256`/`ETag`, using the same algorithm naming | cons | O1 | CL-9 |
| XPR-004 | The namespace agrees: `kXR_dirlist`, `PROPFIND Depth: 1`, and `ListObjectsV2` return the same name set | cons | O1 | — |
| XPR-005 | Authorization agrees: an object denied on one plane is denied on all, with the corresponding per-plane spelling | cons | O1 | AG |
| XPR-006 | **Read-only policy agrees**: `kXR_fsReadOnly` / `403` / `AccessDenied` / `DENIED` / `550` for the same object and the same identity | cons | O1 | AG, CL-12 |
| XPR-007 | Existence agrees: an object absent on one plane is absent on all — no plane exposes a namespace the others hide | cons | O1 | — |
| XPR-008 | Path normalization agrees: the same traversal payload is refused identically on every plane | cons | O1 | CL-4 |
| XPR-009 | Mutation agrees: a `PUT` is visible to `kXR_stat` and to `ListObjectsV2` with the same size and checksum | cons | O1 | — |
| XPR-010 | Case sensitivity agrees across planes | cons | O1 | — |
| XPR-011 | A UTF-8, a Latin-1, and a raw-byte filename resolve to the same object on every plane, or are refused on every plane | cons | O1 | — |

## 30. `ADV` — the adversarial corpus arm

The classic fuzz surface, kept as a **subordinate** arm (§2): it runs after the
ledger, its oracle is liveness plus the invariants below, and its findings are
reported separately from clause verdicts.

| id | assertion | ref | O | src |
|---|---|---|---|---|
| ADV-001 | For every generated case, the connection is either served or closed with a defined error — never left half-open | spec | O1 | — |
| ADV-002 | The server process is alive and accepting after every case | spec | O1 | — |
| ADV-003 | Steady-state RSS after the corpus returns to within a stated band of the pre-corpus baseline | cons | O1 | — |
| ADV-004 | Open file descriptors after the corpus return to the pre-corpus count | cons | O1 | — |
| ADV-005 | **A clause that passed before the corpus still passes after it** — the corpus does not leave the server in a degraded state | cons | O1 | — |
| ADV-006 | No case produces `kXR_ServerError` (3012) or an unclassified `kXR_FSError` (3005); every case that does is reported with its exact bytes as a reproducer | spec | O1 | ERR-037, ERR-038 |
| ADV-007 | Corpus classes: truncated frames · `dlen` disagreeing with the body (both directions) · reserved bytes non-zero · every request code 0–65535 including the 3032–65535 gap · every option bit combination on the smallest verbs · nested/duplicated CGI · every path-encoding trick · oversized and undersized every length field · streamid reuse and streamid storms · out-of-order and interleaved frames | — | — | — |
| ADV-008 | Every corpus case that produces a finding is minimized to the smallest reproducing byte sequence and emitted as a replayable `.xrdcap` | — | — | — |
| ADV-009 | The corpus is seeded deterministically from `--run-key`; the same key reproduces the same cases exactly | — | — | — |
| ADV-010 | Corpus runs are `mutate`-classed and refused under `--accept` on a production target unless `--allow-mutate` is given | — | — | §35 |

---

# Part IV — Running it

## 31. Profiles: which clauses apply to *this* endpoint

A clause ledger with 40 families is only usable if the tool can decide, per
target, which rows are *in scope*. A row that does not apply must be **skipped
with a reason**, never silently dropped and never counted as a pass (§8.3).

Scope is decided by three inputs, in this order:

1. **Discovery.** The `kXR_protocol` flag word, `kXR_Qconfig` keyword sweep, and
   an `OPTIONS`/`PROPFIND` probe on the HTTP plane. This is the primary source:
   it is the server's own claim, and CLM (§25) audits it in both directions.
2. **The profile**, naming the *role* the operator believes they deployed.
   Discovery says what the server claims; the profile says what the operator
   intended. **A disagreement between the two is itself a finding** — the most
   valuable one the tool produces, because it is exactly the shape of a
   misconfiguration: "you meant to deploy a read-only cache; the endpoint
   advertises write and accepts it."
3. **Explicit flags**, which narrow further but never widen past discovery.

### 31.1 The role profiles

| profile | the endpoint is | families in scope | the characteristic assertion |
|---|---|---|---|
| `data` | a standalone data server | FRM HSK PROT LOG SIG OPN RD PGR RDV WRT PGW WVC SYN TRN CKP STA DIR MKD MV RM CHM LOC FAT PRP QRY ERR TLS CLM CHU ENV | direct reads are byte-exact over the whole fractional grid |
| `manager` | a redirector / cmsd manager | FRM HSK PROT LOG SIG LOC QRY RDR WAI ERR TLS CLM CMS | it redirects and never serves data |
| `cache` | a proxy or caching layer | `data` ∪ CAC ∪ RDR | cached bytes equal origin bytes at every offset |
| `proxy` | a forwarding proxy | `manager` ∪ RD PGR ∪ RDR | it forwards without changing geometry or authorization |
| `tape` | an HSM / tape-backed endpoint | `data` ∪ PRP ∪ WAI | `kXR_offline`, staging, and `kXR_wait` are honest |
| `s3` | an S3-fronted export | HTR HTC HTE S3 XPR ERR TLS | SigV4 is enforced and is not interchangeable with a token |
| `http` | a WebDAV/HTTP endpoint | HTR HTC HTE DAV XPR ERR TLS | the Range grid is RFC-exact |
| `tls` | any of the above, TLS-focused | TLS ∪ HSK ∪ PROT ∪ SIG | claimed TLS classes are enforced and unclaimed ones are not |
| `ec` | an erasure-coded backend | `data` ∪ a stripe-boundary axis added to §6.1 | reads across stripe boundaries are byte-exact |
| `tpc` | a TPC-participating endpoint | TPC ∪ LOC ∪ ERR ∪ TLS | delegated credentials are scope-limited and single-use |
| `full` | everything discovery permits | every family | — |

`ec` deserves a note: erasure coding introduces a **second** alignment quantum
underneath the page quantum, and a stripe-boundary read is the classic place for
a wrong-bytes-right-length defect. When the profile is `ec` (or discovery
reports a stripe size), §6.1's offset axis gains `k·stripe ± {1, 0}` and
`k·stripe ± page` for the first, middle and last stripe of each object.

### 31.2 Reference selection: `strict` versus `ecosystem`

§3 established that "the spec" is three competing references. The tool refuses
to arbitrate silently; the operator picks, and the choice is recorded in the
report header:

| `--reference` | a row whose `ref` is… | rationale |
|---|---|---|
| `strict` | `spec` is graded; `xrootd` and `client` rows are graded **as divergences from the nominal spec** | for a protocol implementer, or a site that wants to know its de-facto debt |
| `ecosystem` *(default)* | `spec`, `xrootd` and `client` are all graded as conformant answers | for an operator: the question is "will real clients work", and the ecosystem's de-facto behaviour is part of the answer |
| `both` | every row graded twice, reported in two columns | for a report that has to survive an argument |

The `ENOTEMPTY → kXR_ItExists` row (RM-003) is the worked example: `conformant`
under `ecosystem`, `divergent (de-facto)` under `strict`, and both under `both`.
Neither answer is wrong; publishing which one you asked for is what makes the
report trustworthy.

## 32. The three run shapes

```
xrd conform accept   <url>   # <!-- client-flags-allow: proposed C7 run shape; xrd conform is not built yet -->
xrd conform full     <url>   # <!-- client-flags-allow: proposed C7 run shape; xrd conform is not built yet -->
xrd conform watch    <url>   # <!-- client-flags-allow: proposed C7 run shape; xrd conform is not built yet -->
```

| shape | budget | probe classes | when |
|---|---|---|---|
| `accept` | ~2 min, `boundary` reduction (§6.6), ~1,200 requests | `read` + `mutate` in a scratch prefix only | at the end of a deployment, before the endpoint takes traffic — the gate |
| `full` | 20–60 min, `exhaustive`, ~29,000 requests, plus the `ADV` corpus | all, including `disrupt` under `--allow-disrupt` | pre-production sign-off, upgrade validation, an investigation |
| `watch` | continuous, `boundary` sampled on a duty cycle | `read` only | a production endpoint, as a conformance heartbeat next to liveness monitoring |

Every shape takes the same flags, and all three write the same artefacts:

| flag | meaning |
|---|---|
| `--profile <role>` | §31.1; repeatable; default = discovery |
| `--reference strict\|ecosystem\|both` | §31.2 |
| `--run-key <hex>` | seeds the PRF and the corpus; the reproducibility handle (§5.1) |
| `--scratch <path>` | where planted objects live; **the only path any `mutate` clause may touch** |
| `--allow-mutate` / `--allow-disrupt` | §35; both default off, and `disrupt` additionally requires a written target confirmation |
| `--families A,B,…` / `--exclude` | narrow the ledger by family or by id glob |
| `--budget exhaustive\|pairwise\|boundary` | §6.6 |
| `--fail-on divergent\|inconclusive\|any` | exit-code policy (§33) |
| `--baseline <file>` | compare to a previous run; report only what changed |
| `--out <dir>` | artefact directory |

### 32.1 The read-only degraded mode

An operator often cannot write to the endpoint they need to certify. `xrd
conform` therefore runs without a scratch prefix, in the mode §5.4 describes: it
**adopts** existing objects, learns each one's size and content digest by a full
read, and then uses that as the O2 ground truth for the whole fractional grid.
Every `mutate` clause is skipped with `no-scratch`, and the report says so on its
first page. This is a smaller run, not a weaker one — the fractional grid, the
page algebra, the cross-plane agreement and the entire O1 comparator set all
still apply, because they never needed to write anything.

## 33. The report

Three renderings of one artefact set, because three audiences read it.

**Terminal** — the operator, live. One line per family, a progress counter, and
every divergence printed in full as it is found, with its reproducer command.
Diagnostics to stderr (C4); the machine-readable summary to stdout only when
`--json` is given; non-TTY output byte-identical to TTY minus the hints (C3).

```
FRM   23/23  ok
HSK    7/7   ok
PROT  13/14  1 divergent
  PROT-009  divergent  kXR_suppgrw claimed but kXR_pgread answered kXR_Unsupported (3013)
            ref: spec (XProtocol.hh kXR_PROTPGRWVERSION 0x511)   oracle: O1 self-consistency
            repro: xrd conform full root://ds1.example:1094 --families PROT --only PROT-009   # <!-- client-flags-allow: proposed C7 run shape; xrd conform is not built yet -->
```

**Markdown / HTML** — the site report, and the thing that gets attached to a
ticket or a WLCG deployment review. Header block: target, discovered claims,
profile, reference mode, run key, tool version, timestamp, budget, and the
skip ledger. Then a table per family in the §7 row format, then the divergences
in full with their captured bytes.

**SARIF + ECS JSON** — the pipeline. SARIF so a divergence lands in a code-scanning
view with a rule id (`brix.conform.PGR-009`) and a fingerprint stable across runs;
ECS so a `watch` run streams into the same log store as everything else.

Exit codes are frozen under C5 from the first release:

| code | meaning |
|---|---|
| 0 | every in-scope clause conformant |
| 1 | at least one `divergent` |
| 2 | at least one `inconclusive` and none divergent (only with `--fail-on inconclusive\|any`) |
| 3 | the run could not be completed (target unreachable, discovery failed) |
| 4 | usage error |

Every run also writes a **`.xrdcap` capture per divergent clause** — the exact
bytes sent and received. That capture is replayable by the existing
`xrddiag replay` path, which means a divergence can be handed to a server
developer as a self-contained artefact with no access to the reporter's site.

## 34. Calibration: the tool must be graded before it grades

A conformance tool that has never been wrong is a tool nobody has checked. Before
any release, the ledger is run against a calibration matrix and the results are
published in-repo as the differential record — exactly as
[`differential-findings.md`](../10-reference/conformance/differential-findings.md)
does for the X.509 clauses.

| target | expected outcome | what a surprise means |
|---|---|---|
| stock XRootD v5.6.x | a known, published divergence set | the ledger has a false positive, or v5 genuinely differs — either way it is recorded, with the row |
| stock XRootD v6.1.x | a known, published divergence set | the primary reference point; every row here is the de-facto answer for `ecosystem` mode |
| BriX-Cache (this repo) | zero divergences on `full`, or a documented row | **a divergence here is a bug in `src/`, filed as such** — the tool grades us first |
| EOS, dCache, StoRM, a commercial gateway | recorded, not judged | the ecosystem baseline; a row that every implementation fails is a row that is wrong |
| the fault proxy (§40) | **every clause fails its own negative fixture** | a clause that passes its negative is not testing anything |

The last row is the one that matters most, and §40 makes it a hard gate.

Two derived rules fall out of calibration:

- **A row that no implementation passes is retracted or downgraded**, with the
  reason recorded. The reference is not whatever the document author believed.
- **A row that every implementation passes on every target is kept but marked
  `low-yield`**, and is dropped from the `accept` budget. `accept` is a gate,
  and a gate's time belongs to the rows that have ever caught something.

## 35. The safety model

The tool points at *production storage that is not the operator's test rig*.
Nothing about its design may make it dangerous to run, and nothing may make its
findings ambiguous about what it touched.

**Probe classes.** Every clause carries one, and the class is in the row:

| class | may | default |
|---|---|---|
| `read` | read, stat, list, query, locate — no state change | always on |
| `mutate` | create, write, rename, delete — **only under `--scratch`** | on for `full`, off for `watch`, on for `accept` only when `--scratch` is given |
| `disrupt` | provoke load, exhaust handles, hold connections, force `kXR_wait` | off; requires `--allow-disrupt` **and** a typed confirmation naming the target |

**The scratch invariant.** A `mutate` clause receives a path prefix and may not
construct a path outside it. This is enforced structurally: the clause is handed
a prefix-bound path builder, not a string, and a static guard
(`tools/ci/check_conform_scratch.py`) fails the build if a `mutate` clause
references any other path source. A conformance tool that deleted an operator's
data once would never be run again, by anyone.

**Ceilings.** Every run has a wall-clock ceiling, a request-rate ceiling, a
concurrent-connection ceiling and a total-bytes ceiling, all defaulted low and
all printed in the report header. `watch` additionally honours a duty cycle so
its steady-state cost is a stated fraction of one connection.

**Credential hygiene.** The tool reads credentials the same way every other brix
client does (`brix_env_resolve()`, C2). It never writes one to an artefact: the
report records *which* credential was used by its identity and fingerprint, never
its bytes, and the `.xrdcap` captures are scrubbed of credential frames before
they are written. A `--redact` self-check asserts this on every capture before
it lands.

**Refusal to guess.** When the tool cannot establish an oracle for a clause, the
verdict is `inconclusive` and the reason is machine-readable. It never reports
`conformant` on the strength of "no error was returned".

---

# Part V — Building it

## 36. Honest inventory: what exists today

Nothing in this plan starts from zero. The client already has the transport, the
discovery, a happy-path battery, and a fault injector. What it does not have is
the **ledger**, the **generator**, and the **oracle** — Parts II and III. Stating
the boundary precisely is what keeps the C/S/A/D register (§38) honest.

| capability | today | file | gap for `conform` |
|---|---|---|---|
| `root://` transport, framing, TLS, auth | complete | `client/lib/net/`, `client/lib/protocols/root/frame.c` | none — this is the substrate |
| raw frame send/recv with an arbitrary 24-byte header | present | `brix_send()`, `brix_recv()`, `brix_roundtrip()` (`brix_net_frame.h`) | **this is the key enabler**: off-spec clauses need a header the typed ops layer would never build, and this API already allows one |
| typed ops: open/read/readv/pgread/pgwrite/write/stat/dirlist/query/locate/prepare | complete | `brix_ops.h` (`brix_file_pgread`, `brix_file_readv`, `brix_query`, `brix_locate_opts`, …) | none for the on-spec half of the ledger |
| substream bind | present | `brix_bind()`, `brix_streams_open()` | BND family can be written against it |
| capability discovery | present | `xrd caps` — server role from `c.server_flags` + the `kXR_Qconfig` matrix via `xrd_probe_caps()` (`xrd_mount.c:169`) | it *prints* claims; §31 needs it to *return* them as a scope decision, and §25 needs it to grade them |
| identity discovery | present | `xrd whoami` — chosen auth, offered `sec_list`, token and proxy explanation | reusable verbatim for the report header |
| a functional battery | present, happy-path | `xrd_battery.c` + `xrd_battery_web.c`, ~24 named checks (`read-verify`, `readv`, `write-suite`, `path-confinement`, `PROPFIND`, `list-objects`, …) across the root/WebDAV/S3 faces | **the seed of the ledger, and the honest measure of the gap**: it answers "does readv work", the ledger asks the 20 questions of §22 |
| fault injection | complete | `brix-fault-proxy` — toxics `corrupt`, `truncate`, `drop`, `dup`, `reorder`, `chunk`, `latency`, `jitter`, `lossy`, `drip_bytes`, `rate`, `down` | **this is the §40 negative-fixture engine, already built** |
| a gated external oracle | present | `brix_fault_oracle.h` — `fp_oracle_run()`, double-gated behind `--enable-exec` | the pattern to copy for "did the clause fail as it should" |
| session capture and replay | present | `xrddiag replay <file.xrdcap>`, `--playback <url>` | the `.xrdcap` divergence artefact of §33 needs no new format |
| latency/throughput probing | present | `xrddiag bench`, `xrdstorascan bench` | out of scope here; `conform` grades correctness, not speed |

Two conclusions follow, and both are load-bearing for the estimate:

1. **No new protocol code is required.** Every clause in Parts III is a
   composition of `brix_send`/`brix_recv` or an existing typed op. The work is
   the ledger, the generator, the oracle and the report — not the wire.
2. **The battery is the precedent, not the competitor.** `xrd doctor --rw`
   already walks three protocol faces and records pass/fail per named check. The
   ledger is that shape, two orders of magnitude wider, with a verdict derived
   from a reference instead of from a boolean.

## 37. The three spines

Everything in Parts II–IV decomposes into three independent pieces of work that
can be built and reviewed separately. Each has a single owner concept, a single
new-file group, and a test surface that does not depend on the other two.

**Spine A — the oracle and the generator** (`client/lib/conform/`). The planted
object (§5): key derivation, `PRF` byte generation, the plant/adopt/verify cycle,
the standard object set. The axis generators (§6): offsets, lengths, page
algebra, option-bit walks, limit triples, and the three budget reductions. The
expected-answer arithmetic (§5.3, §6.3). **This spine has no network dependency
at all** — it is pure computation over sizes and offsets, and it is therefore
unit-testable to exhaustion. Every number in §6.3 is a test case; the generator's
own correctness is checked by asserting that the union of a generated partition
reconstructs `[0,S)` for every object in the standard set.

**Spine B — the ledger and the runner** (`client/lib/conform/` + `client/apps/diag/xrd_conform*.c`).
The `brix_clause` struct (§7), the family tables of §9–§30 as static data, the
scope resolver (§31), the runner that walks clauses against a target, the verdict
algebra and the O1 comparator set (§8), the skip ledger. This is the bulk of the
line count and almost none of the difficulty: each clause is a small function
over an existing op plus an assertion.

**Spine C — the report and the safety envelope** (`client/lib/conform/report_*.c`).
The three renderings (§33), the exit-code policy, the `.xrdcap` divergence
capture and its credential scrub, the probe-class enforcement and the
prefix-bound path builder (§35), the baseline diff. C3/C4 compliance lives here
and is pinned by `tests/test_cli_golden.py` the same way every other tool is.

The dependency order is A → B → C, but B's clause tables can be written in
parallel with A because they consume the generator only through its interface.

## 38. The C/S/A/D register

Each row is **C**omplete, **S**ubstantial, **A**dditive, or **D**eferred, against
the inventory in §36. Nothing here is claimed as landed; this is a plan.

| # | item | spine | state | note |
|---|---|---|---|---|
| 1 | planted-object PRF + plant/adopt/verify | A | **S** | new; ~1 file, no network |
| 2 | standard object set + read-only adoption | A | A | §5.2, §32.1 |
| 3 | offset/length/option/limit axis generators | A | **S** | §6.1–§6.5, the heart of "fractional" |
| 4 | page-algebra expected-answer engine | A | **S** | §6.3; the PGR family is worthless without it |
| 5 | budget reductions (`exhaustive`/`pairwise`/`boundary`) | A | A | §6.6 |
| 6 | `brix_clause` struct + registry | B | A | §7 |
| 7 | verdict algebra + skip ledger | B | A | §8.1, §8.3 |
| 8 | the 14 O1 comparators | B | **S** | §8.2; these are the rows no other tool can produce |
| 9 | scope resolver + profiles | B | A | §31; consumes `xrd_probe_caps()` |
| 10 | FRM/HSK/PROT/LOG/SIG families (§9–§13) | B | A | 79 rows; mostly raw-frame work over `brix_send` |
| 11 | OPN/RD/PGR/PGW/write-plane families (§14–§18) | B | **S** | 130 rows; the marquee fractional surface |
| 12 | STA/DIR/namespace/QRY families (§19–§21) | B | A | 90 rows over existing typed ops |
| 13 | RDV/control-flow families (§22–§23) | B | A | 51 rows |
| 14 | ERR family (§24) | B | **S** | 27 rows; needs a provocation harness per errno |
| 15 | TLS/CLM families (§25) | B | **S** | claims-vs-behaviour in both directions |
| 16 | HTTP/WebDAV/S3 families (§26–§27) | B | A | 60 rows; `xrd_battery_web.c` is the precedent |
| 17 | CMS/CAC/TPC families (§28) | B | A | 30 rows; needs a multi-node fixture |
| 18 | XPR cross-plane agreement (§29) | B | **S** | 11 rows, and the reason the tool is one binary |
| 19 | ADV corpus arm (§30) | B | A | subordinate; reuses the phase-27 corpus shape |
| 20 | terminal / Markdown / SARIF+ECS renderings | C | A | §33 |
| 21 | `.xrdcap` divergence capture + credential scrub | C | A | format exists; the scrub is new |
| 22 | probe classes + prefix-bound path builder + `check_conform_scratch.py` | C | **S** | §35; the safety invariant |
| 23 | baseline diff | C | A | §32 |
| 24 | calibration matrix + published differential record | — | **S** | §34; needs the stock-XRootD fixtures the repo already runs |
| 25 | `ec` stripe axis | A | **D** | §31.1; needs a stripe-size discovery path |
| 26 | `watch` duty-cycle mode | C | **D** | after `accept` and `full` prove out |
| 27 | GridFTP and OCI planes in XPR | B | **D** | the errno table already names their spellings (§24 ERR-044) |
| 28 | fuzz-corpus minimization to a reproducer | B | **D** | §30 ADV-008; valuable, not on the critical path |

## 39. Sequencing

Five milestones. Each ends with something an operator can run, which is the only
honest definition of a milestone for a tool.

| M | delivers | register rows | the demo |
|---|---|---|---|
| **M1** | the engine, no ledger | 1–5 | plant the standard object set against a scratch prefix, generate the full §6 case list, print it; verify every expected answer offline against a local file |
| **M2** | `accept` on the read plane | 6–9, 11 (RD+PGR only), 20 | `xrd conform accept root://…` returns 0 or names a divergent row, in under two minutes |
| **M3** | the ledger complete on `root://` | 10, 12–15, 19 | `xrd conform full` over every root-plane family, with the skip ledger and the `.xrdcap` artefacts |
| **M4** | cross-plane | 16–18, 21–23 | one run grades `root://`, HTTPS/WebDAV and S3 on the same objects and reports XPR disagreements |
| **M5** | calibrated and published | 24 | the differential record against stock v5, stock v6 and BriX-Cache lands in `docs/10-reference/conformance/`, and §40 passes |

M2 is the release-worthy point: `accept` alone — the fractional read grid, the
page algebra, the claims audit and the error map — is already the thing the
one-sentence goal promises, and everything after it widens rather than deepens.

## 40. Verification: the tool must fail on demand

The meta-rule, and the gate on every milestone:

> **Every clause carries a negative fixture it is known to catch, and the suite
> asserts that the clause FAILS against that fixture.** A clause that has never
> gone red is not evidence; it is decoration.

This is affordable only because the negative-fixture engine already exists
(§36): `brix-fault-proxy` sits between the tool and a healthy reference server
and makes it misbehave in exactly the way a clause claims to detect.

| clause class | fixture | toxic |
|---|---|---|
| byte-exactness (RD, RDV, PGR-019, XPR-002) | flip a byte in the payload | `corrupt` |
| length correctness (RD-005, HTR-015) | shorten a response body | `truncate` |
| per-page CRC (PGR-020, PGR-021, CAC-009) | corrupt one page of a pgread train | `corrupt` at a page offset |
| framing (FRM, CHU) | split, duplicate or reorder frames | `chunk`, `dup`, `reorder` |
| chunked reassembly (RD-009, DIR-007, RDV-018) | force an early `oksofar` boundary | `chunk` |
| timing and wait honesty (WAI, LOC-006) | inject latency past the stated wait | `latency`, `jitter` |
| liveness and recovery (ADV-001–005) | drop the connection mid-response | `drop`, `down` |
| error mapping (ERR) | rewrite the error code in the response | frame rewrite via `corrupt` at the code offset |
| claims audit (CLM) | rewrite the `kXR_protocol` flag word | frame rewrite on the protocol response |
| cross-plane (XPR) | corrupt one plane only | `corrupt` scoped to one route |

Four further verification obligations, each a hard gate:

1. **No false positives on a healthy reference.** A `full` run against a known-good
   stock XRootD and against BriX-Cache produces zero divergences other than the
   published, explained calibration set (§34). A new unexplained red on a healthy
   server is a tool bug and blocks the release.
2. **Generator self-consistency.** For every object in the standard set and every
   budget, the generated partition of `[0,S)` reconstructs the object exactly,
   and every expected-answer computation agrees with a naive reference
   implementation over the whole grid. Pure unit tests, no server.
3. **Determinism.** The same `--run-key` against the same server produces a
   byte-identical report modulo timestamps. Two different keys produce different
   planted bytes and the same verdicts.
4. **The safety invariant holds under test.** `check_conform_scratch.py` fails the
   build on a `mutate` clause that names a path outside the scratch builder, and a
   negative test plants a violation to prove the guard catches it. The credential
   scrub is asserted on every `.xrdcap` the suite produces.

### 40.1 What "done" looks like

An operator finishes a deployment, runs one command, and gets one of two answers:

- **`0` — conformant.** With a report naming exactly which clauses were in scope,
  which were skipped and why, which reference was used, and what run key
  reproduces it. That report is attachable to a WLCG deployment review and
  survives being argued with, because every row cites its authority.
- **non-zero — divergent.** With the failing clause, the reference it violates,
  the exact bytes that provoked it, a one-line command that reproduces it, and a
  `.xrdcap` that a server developer can replay without access to the site.

Neither answer is "it seems fine". That is the whole point.
