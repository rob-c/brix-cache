# `xrd conform` protocol calibration record

This is the published differential record for the Phase 118 deployment-time
protocol oracle. It records observed wire behaviour, the exact clause decision
derived from it, and whether BriX-Cache agrees. It does not import or inspect an
external server implementation.

## Release matrix and completion rule

Calibration is capability-scoped. A stock data server cannot honestly satisfy
BriX-only cache-state, multi-export, WebDAV/S3, CMS or delegated-TPC fixture
contracts, and an absent external topology is never treated as a passing
observation. The Phase 118 release cells are therefore the following explicit
matrix, rather than a Cartesian-product claim that every target implements every
profile.

| Release cell | Applicable assessment | Recorded outcome | State |
|---|---|---|---|
| stock XRootD v5 | portable ROOT read/vector semantics used to detect inherited ecosystem behaviour | 5.9.7 calibrated the two readv EOF rows; both fail the whole vector with the published `kXR_FSError` spelling | complete |
| stock XRootD v6 | primary portable ROOT reference slice | 6.1.1 produced 24 conformant rows and the published `QRY-002` divergence in PROT/OPN/STA/DIR/LOC/QRY/ERR; its RDV slice produced eight conformant, zero divergent and twelve unsupported rows | complete |
| BriX-Cache | every implemented family, using a live endpoint where portable and a named controlled fixture where topology/state is part of the assertion | all 523 executable clauses have success/error/security-negative coverage; the family records below preserve the live calibration decisions and no unexplained healthy-target divergence remains | complete |
| hostile fixtures | one registered negative identity per executable clause | 1,272 Darwin ARM64 reports prove 523/523 exact `--verify-negative` declarations, with zero missing rows and zero evidence-integrity errors | complete |
| EOS, dCache, StoRM, commercial gateways | observational ecosystem baseline | not required for the Phase 118 release; future results are recorded, never assumed | optional |

The four withdrawn assertions (`PGR-027`, `STA-012`, `LOC-009`, `LOC-010`)
are explicit retractions and are not part of the 523-clause denominator. The
negative-evidence result was independently recomputed with:

```console
python3 tools/diag/conform_negative_coverage.py REPORT_ROOTS... --require-complete
reports=1272 covered=523/523 missing=0
```

The aggregator accepts only a passing declaration whose reported clause is
divergent and whose negative-fixture identity exactly matches the generated
ledger. Ordinary divergences do not contribute. This closes the M5 matrix and
§40 gates while preserving the difference between unsupported topology and a
conformant result.

## CAL-RDV-EOF — vector reads at and beyond EOF

Calibration date: 2026-10-04. Architecture: Linux AArch64. Run key:
`000102030405060708090a0b0c0d0e0f`. The runner planted the same 65,536-byte PRF
object on each writable endpoint and removed it after the run.

| Target | Version | RDV-009 wholly past EOF | RDV-010 straddles EOF |
|---|---|---|---|
| stock XRootD | 5.9.7 (AlmaLinux 9 EPEL) | whole request returns `kXR_FSError` (`illegal seek`) | whole request returns `kXR_FSError` (`illegal seek`) |
| BriX-Cache | 2.0.0 development tree | whole request returns `kXR_IOError` | whole request returns `kXR_IOError` |
| stock XRootD | 6.1.1 (AlmaLinux 10 EPEL) | whole request fails; `RDV-009` conformant | whole request fails; `RDV-010` conformant |

The original draft ledger incorrectly applied scalar-read EOF semantics to
`kXR_readv`, expecting zero/short elements. Existing in-repository differential
coverage (`tests/test_conf_readv.py::test_readv_eof_parity`) already documented
the stock all-or-error behaviour. A live `xrd conform` run independently exposed
the contradiction by reporting both stock XRootD 5.9.7 and BriX-Cache as
divergent. In accordance with Phase 118 §34, the false-positive rows were
corrected instead of changing the server to violate the ecosystem contract.

The calibrated ecosystem verdict for RDV-009 and RDV-010 is therefore:

- conformant only when the whole request fails with a defined I/O error;
- the calibrated ecosystem spellings are BriX `kXR_IOError` and stock-v5
  `kXR_FSError` (`illegal seek`), which remain visible in report evidence;
- divergent if any partial segment bytes are returned; and
- inconclusive when the exact response status cannot be observed.

The stock 6.1.1 cell was measured with the packaged AlmaLinux 10 EPEL server on
Linux AArch64. The bounded runner used 28 requests and 143,404 bytes for the RDV
slice and reported eight conformant, zero divergent and twelve rows unsupported
by that stock target. This closes the reference-version cell for the selected
RDV slice; families outside that scoped calibration were not selected and make
no claim about the runner's implementation coverage.

## CAL-RDV-FRAMING — large vector response framing

Calibration date: 2026-10-05. Architecture: Linux AArch64. A dedicated BriX
endpoint advertised a 16 MiB per-element limit and served four 8 MiB elements
from a 36 MiB object. The official XrdCl client completed the 32 MiB vector
when BriX emitted one `kXR_ok` header whose `dlen` covered the logical readv
body while streaming that body through bounded internal windows.

The same client timed out when each internal window was exposed as a separate
`kXR_oksofar` response. Small raw-wire readv clients likewise observed an
unexpected first `kXR_oksofar` instead of their complete `kXR_ok` response.
This proves that protocol-notes §26 describes large scalar reads and must not
be generalized to `kXR_readv`. RDV-018 therefore requires one length-delimited
logical response, byte-exact native-client reassembly, and bounded server-side
streaming. The calibration is pinned by `test_readv_segment_size.py` and the
scratch-confined 16 MiB+ Phase 118 corpus probe.

## CAL-ROOT-BASIC — typed read-side metadata and error behaviour

Calibration date: 2026-10-05. Architecture: Linux AArch64. The stock endpoint
was XRootD 6.1.1 from AlmaLinux 10 EPEL and the adopted fixture was the
65,536-byte `brix-conform-Q` object. No mutation probe was enabled.

The implemented PROT/OPN/STA/DIR/LOC/QRY/ERR slice produced 24 conformant rows
and one divergence on stock 6.1.1. Handles were distinct and session-bound;
directory open, missing locate, unknown checksum and Qspace answers carried the
expected defined status or shape; repeated missing-locate errors were stable and
human-readable. `DIR-001` remained inconclusive because the adopted parent was
not an exclusive directory fixture. `QRY-004` remained inconclusive because the
endpoint did not advertise the requested SHA-256 checksum.

The sole stock divergence is `QRY-002`: stock 6.1.1 answers `kXR_Qconfig tpc`
with the echoed token `tpc`, while the row's frozen assertion requires a raw
numeric value. BriX-Cache answers `1` and conforms to that assertion. This is a
published ecosystem difference, not a reason to broaden the numeric oracle:
clients already treat a non-numeric answer as capability unknown, and accepting
arbitrary text would make the row incapable of detecting a malformed value.

## CAL-BRIX-RD-PGR — complete `accept` read plane

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The target was the rebuilt BriX-Cache development server on loopback. Mutation
authority was explicitly enabled with a scratch prefix; every planted object
was removed and the export was checked for residue after the run.

The runner exercised `Z` (0), `P0` (4,095), `Q` (65,536), `C+` (16,777,217),
and a sparse `L` (5 GiB + 1). It observed and validated ordinary
`kXR_oksofar` framing and paged `kXR_PartialResult` framing above 16 MiB,
whole-unit page-frame boundaries, position-correct bytes and CRCs above 2 GiB,
two simultaneous overlapping reads on bound streams, and refusal of both read
forms on a write-only handle.

The RD/PGR result was 57 conformant, zero divergent, and two inconclusive. The
two inconclusive rows are intentionally not healthy-endpoint questions:
`PGR-021` requires injected page corruption and `PGR-027` requires an injected
checksum-error flood. The controlled hostile origin proves `PGR-021` goes green
when corruption is detected while `PGR-020` goes red for the faulty endpoint.
`PGR-027` was subsequently retracted: the authoritative `kXR_pgMaxEpr` limit
belongs to pgwrite CSE reporting, while pgread has no checksum-error-list
response to cap. It is therefore excluded from the executable §40 matrix rather
than carried as an impossible negative fixture.

## CAL-BRIX-HSK-PROT — bootstrap and protocol negotiation

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The target was the rebuilt BriX-Cache development server on loopback. A scoped
run used a deliberately nonexistent object path to prove that selecting only
HSK and PROT performs no object stat, open, or read.

All seven HSK and all fourteen PROT rows were conformant, with zero divergent or
inconclusive rows. The run used ten charged exchanges and 131 request bytes. It
covered short and altered handshakes, a second handshake, a request before the
handshake, exact v5 response shape, repeated pre/post-login protocol bodies,
the optional bind-preference request, TPC and out-of-mask `expect` values, and
the signing-requirements trailer shape.

A controlled Python origin supplied two independent negative calibrations. A
security level outside 0–4 makes `PROT-006` divergent; a trailer claiming one
security-vector entry without carrying it makes `PROT-007` and `PROT-008`
divergent. Both runs exit 1 and emit a valid scrubbed per-clause `.xrdcap`.

## CAL-BRIX-FRM — complete framing and stream identity

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The live BriX endpoint passed all 23 FRM rows with no divergence. The bounded
run used 58 charged requests and 1,371 request bytes. Isolated connections
proved zero and reused stream IDs, two pipelined identities, exact response
identity, path-NUL rules, truncated/surplus payload recovery, refusal of
0xFFFFFFFF and 0x7FFFFFFF lengths before allocation, bytewise TCP header
reassembly, slow payload completion, padding indifference, and defined answers
across every standard opcode from 3000 through 3032.

This calibration also reconciled the Phase 118 ledger with the authoritative
in-repo opcode registry: `kXR_clone` occupies 3032, so `kXR_REQFENCE` is 3033
and the valid standard range is 3000–3032. It also corrected three oracle-model
errors: stream IDs are opaque client tags rather than uniqueness leases;
`dlen` is an unsigned wire field; and `kXR_sigver` is a silent prefix whose
defined behaviour is observed through the covered request. A controlled origin
that flips the post-login response stream ID makes `FRM-003` divergent and exits
1. The healthy run independently exercised argument errors and fail-closed
disconnects for malformed lengths and path frames.

## CAL-BRIX-LOG-ANON — anonymous session lifecycle

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The anonymous BriX endpoint passed nine live LOG rows with no divergence.
Sixty-four independently established sessions produced unique, non-monotonic
16-byte IDs without a shared eight-byte prefix. Both NUL-padded short usernames
and eight-byte non-NUL usernames logged in; auth before login and a second login
were refused.

Session teardown was tested in three directions. Ending the current session
made a following file operation unauthorized. Naming a different live session,
or an unknown session ID, returned the recovery-compatible idempotent answer
without de-authenticating the carrying connection. This reconciles LOG-019 and
LOG-020, and their ENV-003/ENV-004 aliases, with the repository's authoritative recovery semantics in
`session/lifecycle.c`; treating every foreign ID as a mandatory error would
break reconnect cleanup. A controlled origin that returns the same all-zero
session ID for every login makes LOG-002 divergent with
`duplicate-session-id`.

## CAL-BRIX-CHUNKING — bounded plain-read continuations

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The protocol permits `kXR_oksofar` continuation frames without prescribing a
16 MiB split threshold. BriX deliberately uses a smaller bounded-memory read
window. CHU-003 therefore verifies the interoperable property: a small read is
one terminal frame, while a larger read uses validated continuation frames and
reassembles byte-exactly. Treating 16 MiB as mandatory produced a false
divergence against a safer, protocol-valid implementation.

## CAL-BRIX-RM — empty-directory removal

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The deployed filesystem operation behind `kXR_rm` may implement a non-recursive
"remove" that accepts files and empty directories. BriX does so, while still
mapping a non-empty directory to the established `kXR_ItExists` spelling.
RM-004 therefore accepts either successful removal of an empty directory or an
explicit `kXR_isDirectory` refusal; RM-003 independently proves that the
operation never recurses into a non-empty directory.

## CAL-BRIX-PGWRITE-CSE — accept-then-correct page checksums

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The target was the rebuilt BriX-Cache development server on loopback, with
mutation authority confined to the run's generated scratch object.

A 4,096-byte `kXR_pgwrite` carrying a deliberately corrupted page CRC received
a successful fixed `kXR_status` response plus one checksum-error (CSE) trailer
entry. The probe validates the fixed-response CRC and identity fields, the
`dlFirst`/`dlLast` values, the rejected-page offset, and the trailer CRC. A
close attempted before correction was rejected with `kXR_ChkSumErr`; the same
page resent with `kXR_pgRetry` and its correct CRC then closed successfully and
read back byte-exactly. This records BriX's accept-then-correct lifecycle: the
initial request is acknowledged with a CSE list, while finalization remains
fail-closed until every reported page is corrected.

The bounded limit arm then submitted two disjoint 128-page CSE batches on one
handle. Both were reported in complete, CRC-valid trailers; the 257th distinct
uncorrected page was rejected with `kXR_TooManyErrs`. This pins both the
per-request reporting ceiling and the 256-page per-open outstanding ceiling
without relying on an implementation counter or log message.

## CAL-BRIX-FATTR-LIMITS — complete attribute boundary vectors

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The mutation-confined probe set and retrieved all 256 byte values, listed and
deleted named attributes, accepted a 65,536-byte value and a 248-byte name, and
accepted sixteen attributes in one request. The corresponding one-over cases
were refused by the opcode validator with defined argument errors. A native
Darwin ARM64 repeat additionally proved that the 248-byte name can be set,
read, listed and deleted despite Darwin's 127-byte physical xattr-name limit;
the reserved digest-key envelope remained invisible at the wire boundary.

The first run exposed a framing defect: the generic `BRIX_MAX_PATH + 64` gate
closed legal fattr requests before dispatch. The corrected pre-allocation cap is
derived from `kXR_faMaxVars`, `kXR_faMaxNlen`, and `kXR_faMaxVlen`; an isolated
parser KAT proves the exact cap is admitted and one byte above it is rejected
before allocation. The rebuilt Linux AArch64 and Darwin ARM64 endpoints then
completed FAT-001 through FAT-008 with zero divergence. A native Darwin ARM64
run against the dedicated typed read-only export completed FAT-009 by observing
`kXR_fsReadOnly`; the same exact-clause probe went divergent on both a writable
fixture and a missing fixture, and removed the attribute accepted by the
writable control. The FAT family is therefore 9/9 on BriX-Cache.

## CAL-BRIX-WRITEV-LIMITS — vector segment count boundary

Calibration date: 2026-10-05. Architecture: Linux AArch64 (AlmaLinux 9 Lima).
The mutation-confined live probe sent 1,024 one-byte `kXR_writev` segments and
read the resulting 1,024 distinct bytes back exactly. It then authenticated an
isolated connection and sent 1,025 well-framed, zero-length descriptors. The
server returned `kXR_ArgTooLong` and dropped only that isolated link, preserving
the primary assessment session. This establishes both acceptance at
`maxWvecsz` and fail-closed refusal one element above it.
