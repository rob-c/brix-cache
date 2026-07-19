# Hostile-Network Lessons — BriX gateway hardening

> **Status:** Living synthesis · **Authored:** 2026-07-19 · **Owner:** security workstream
>
> **Basis:** the `brix-fault-proxy` hardening sweep — a systematic, top-down pass over
> *every* front-end gateway to a POSIX filesystem (native `root://`, WebDAV, S3,
> gsiftp/GridFTP, plus the outbound commit leg to remote origins), driving each with
> an in-path adversary that can truncate, stall, reorder, and corrupt bytes while
> leaving framing and signatures intact.
>
> The per-finding forensic record (findings #1–#12, with repros and fixes) lives in
> [`../09-developer-guide/history-storage-and-caching.md`](../09-developer-guide/history-storage-and-caching.md)
> §6.1 (table) and §7 (cross-cutting lessons). This document is the *distilled* version:
> the durable engineering principles a reviewer should carry into the **next** gateway,
> independent of which byte flipped in which finding.

## The threat model in one sentence

The network is run by an uncooperative admin: any middlebox between BriX and its peer
(client *or* origin) may cut a connection early, hold it open forever, or flip bytes —
and it will do so in the way that keeps every length field, checksum-of-the-wrong-thing,
and cryptographic signature looking valid. Our job is to ensure that a *stopped* or
*mangled* transfer can never be mistaken for a *complete, faithful* one.

## The two questions every write path must answer

Every finding reduced to a gateway failing to answer one of these two questions. Ask
both, explicitly, of every ingest and every egress path:

1. **What signals COMPLETE (vs merely STOPPED)?** A transfer that ends is not a transfer
   that finished. There must be an explicit, in-band completion signal that a truncating
   middlebox cannot forge by simply closing the socket. If there is none, a stopped
   transfer reads as complete and silent truncation poison is committed.

2. **What proves the bytes are the peer's (vs corrupted in flight)?** Length framing
   answers "how many bytes", never "which bytes". Corruption needs an end-to-end digest
   the *peer* asserts and *we* (or the far origin) verify. A storage read-back that
   re-reads what we just wrote proves nothing — it faithfully returns the corrupted bytes.

"Sound vs truncation" ≠ "sound vs corruption." A path can be provably safe against one
and wide open to the other. Verify both; a verified-*sound* outcome is a real result —
do not fabricate a bug to have something to fix.

### What "signals COMPLETE" looked like, per protocol

The completion signal is protocol-specific, and finding it is the core review work:

| Gateway | COMPLETE signal | If absent → the poison |
| --- | --- | --- |
| Native `root://` | in-band `kXR_close`/`kXR_sync` | (sound — explicit signal exists; #11) |
| WebDAV PUT | client-asserted `Digest`/`Content-MD5` | truncated body committed silently (#6) |
| S3 PutObject | classic `Content-MD5` / `x-amz-checksum-*` | short object stored as complete (#7) |
| GridFTP MODE E | gapless byte-tiling `[0, high-water)` | zero-filled hole served as `226` (#8) |
| GridFTP STREAM | declared size via `ALLO` | bare data-close = truncation-as-complete (#9) |

The general rule: enumerate the completion signals a protocol actually offers (digest,
gapless tiling, declared size). If the protocol offers *none*, the gateway must add an
opt-in one or accept that a stopped transfer is indistinguishable from a finished one.

## Integrity has a direction — audit every hop

A single server has two hops to worry about (client→server, server→disk). A *gateway* has
more: client→BriX, and BriX→origin. "Verify on ingest" plus "verify on read" still leaves
the middle — the **outbound commit leg** (BriX→its own S3/HTTP origin) — completely naked,
and it is the hop most easily forgotten because it feels internal (#12).

Name what proves the bytes at **every** hop, and remember the egress leg cuts the same way
as the ingress leg: S3's `UNSIGNED-PAYLOAD` signing means the signature covers headers only,
so a body bit-flip verifies fine — inbound (#7) *and* outbound (#12).

Prefer a **peer-validated header** (a checksum the far end enforces inline, atomically,
during the same request — `x-amz-checksum-crc32`, `Content-MD5`) over a post-commit
HEAD-and-compare probe: the inline header fails the write closed with `400 BadDigest`
before anything is published; the read-back probe races, costs a round trip, and re-reads
storage that may itself be lying.

## Truncation and corruption demand *opposite* recovery

When a transfer is cut, whether the clean prefix is salvage or poison depends entirely on
whether the client had *declared* completion:

- **Mid-payload cut** (client still sending): the clean prefix is a legitimate resume
  candidate — keep it (e.g. GridFTP STREAM keeps the prefix for REST-resume; native
  keeps the staged temp for the 111-marker). The transfer *stopped*; it did not lie.
- **Declared-complete but incomplete** (all EODs in, but the byte-tiling has a hole; a
  digest that does not match): this is poison, not a resume candidate — the peer told us
  it was done and it was not. Abort and `unlink` (GridFTP MODE E declared-complete-holed
  unlinks; a digest mismatch fails closed).

Getting this backwards either discards resumable work or publishes a hole.

## Repair protocols are only sound where the repair channel exists

"Accept-then-correct" (take a page now, fix it on a later rewrite) is a valid pattern only
where the later rewrite can actually happen — a random-write/POSC handle whose offsets can
be revisited. On a **sequential-append** or staged whole-object handle, a given offset is
seen exactly once; "accept the corrupt page, we'll fix it later" is a lie that both hides
the corruption *and* wedges the handle (#10). On append-only paths, reject at ingest,
fail-closed. Match the repair posture to whether a repair channel physically exists.

## Every publish point must consult the *same* gate

When one commit point is integrity-gated, **every** publish point must call the *same*
shared gate — enumerate them by "what publishes", not by opcode name. A close-time CSE
gate that `kXR_sync` sidesteps because sync commits through a different code path is not a
gate (#10): `close`, `sync`, `staged-commit`, and `TPC-finalize` are all publish points.
Route them through one shared predicate (`brix_pgw_fob_commit_blocked()` was the pattern)
so a new publish path cannot silently bypass the check.

## Timeouts: an idle timer is not a deadline

A per-poll timeout that is re-armed on every iteration measures *idleness between reads*,
never the total wall-clock of the logical operation. A slow-drip adversary (one byte per
`timeout - ε`) keeps a connection hostage forever under a per-poll timer (#5). A logical
operation that must complete needs an **absolute deadline** spanning the whole operation
(`XRDC_STALL_DEADLINE_MS` / `brix_io_stall_arm`), independent of the per-read idle timer.

## New-integrity surfaces are opt-in knobs; clear bugs fail closed

The fix posture that held across the sweep:

- **Outright bugs** — a stopped/corrupt transfer committed as complete — are fixed to
  **fail closed**, unconditionally (truncation gaps, the missing shared gate, the idle-vs-
  deadline timer).
- **New integrity surfaces** that a protocol simply never offered, and that a
  standards-compliant-but-strict peer might reject, ship as **opt-in `require`/`?opt`
  knobs, default OFF**: `brix_webdav_require_digest`, `brix_gridftp_require_allo_size`,
  `brix_require_pgwrite`, `s3://…?put_checksum=1`. Default-off preserves parity with the
  stock protocol (e.g. RFC 959 `ALLO` is advisory; S3 `UNSIGNED-PAYLOAD` is the norm) so
  an unknown-header-rejecting or advisory-only peer keeps working, while a security-
  conscious admin can turn the guarantee on.

## Config and deployment footguns are part of the threat surface

Two operational hazards surfaced by the sweep — worth a checklist entry because they make a
correct fix *look* broken:

- **The storage-backend registry is keyed by canonical export root.** Two servers/exports
  that differ *only* in backend options (e.g. `put_checksum` on vs off, or two different
  origins) but share one `brix_export` root collide on a single registry entry; the last
  registration silently wins for both. Distinct backend behaviour requires distinct export
  roots (#12).
- **Two same-named option structs are a silent no-op knob.** A connection-level `brix_opts`
  and a copy-level `brix_copy_opts` each carrying `max_stall_ms`/`no_retry` means setting
  the knob on one leaves the other at its default; the setting reads as applied but does
  nothing until the two are explicitly bridged (`finalize_resilience_posture`) (#5, #9).

## Never truncate coverage silently

If a fix or a test bounds what it exercises (top-N, no-retry, sampling, a single corruption
site), *say so* in a `log()`/comment. A silent cap reads as "everything was covered" when it
was not — the same failure mode as the gateways themselves, applied to our own verification.

## The review checklist, distilled

For any new or reviewed gateway to POSIX storage, in priority order:

1. For every **ingest** and every **egress** path, answer both questions: what signals
   COMPLETE, and what proves the bytes are the peer's.
2. Enumerate **all hops** (client→BriX, BriX→origin) and name the integrity guarantee at
   each; the outbound commit leg is the one that gets forgotten.
3. Enumerate **all publish points** (close/sync/staged-commit/TPC-finalize) and route them
   through one shared integrity gate.
4. Confirm truncation recovery matches **declared-completion** state (prefix = salvage vs
   poison).
5. Confirm repair/accept-then-correct is used **only** where a repair channel physically
   exists; else reject at ingest.
6. Confirm every logical operation has an **absolute deadline**, not just a per-read idle
   timer.
7. Fix outright poison-commit bugs **fail-closed**; ship never-offered guarantees as
   **opt-in, default-off** knobs.
8. Write the **3-test ritual** per finding: success (clean commit byte-exact), error
   (corruption/truncation rejected, no poison left), security-neg (knob-off proves the gap
   is real).
