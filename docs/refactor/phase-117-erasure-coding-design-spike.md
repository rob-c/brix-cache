# Phase 117 — Erasure coding (XrdEc): design spike and go/no-go

**Status:** SPIKE CLOSED — **NO-GO for in-tree Reed–Solomon; GO for the two
adjacent corrections it uncovered.** This document is the deliverable of
phase-115 W6.1 ("output is a phase doc that decides stripe placement, the wire
signalling, and the repair story — not code"). No erasure-coding code is
proposed for implementation by this phase.
**Source:** phase-115 W6.1; `docs/refactor/xrootd-feature-parity-audit-2026-08-04.md`
§7 ("XrdEc (erasure coding): MISSING, 0%") and §1 item 1 ("greenfield").
**Depends on:** phase-55 (storage-driver seam), phase-59 (CSI page tags),
phase-60/89 (Ceph/RADOS driver), phase-105 (typed VFS mutation policy),
phase-109 (thread-offload conventions).
**Touches (this phase):** this document;
`docs/10-reference/protocol-gaps-vs-xrootd.md` (two mislabelled rows);
`src/protocols/root/protocol/flags.h` (comment only);
`tests/test_phase117_ec_spike.py` (new).
**Verification:** the spike is closed by this design with the verdict recorded
in §7. The two corrections it produced are pinned by tests, because a spike
whose only output is prose rots the moment the tree moves under it.

---

## 1. What was actually asked for

`kXR_ecRedir` is listed ❌ in `docs/10-reference/protocol-gaps-vs-xrootd.md`,
and the parity audit lists erasure coding as the first of the hard backend
gaps. The register asked which of three places the stripes should live in — a
per-export driver under `src/fs/backend/`, a VFS decorator, or somewhere else —
what goes on the wire, and how a lost shard comes back.

Answering those three in order turns out to answer the fourth, unasked
question — *should this be built here at all* — and the answer is no. The
reasoning is below, followed by the trigger that would reverse it.

## 2. Discovery — the gap tables describe the wrong modules

Two rows of `docs/10-reference/protocol-gaps-vs-xrootd.md` are wrong, and they
are wrong in the way that matters most to a spike: a design started from that
table would have been designed against the wrong module.

| Row as written | What the module actually is |
|---|---|
| `XrdOssCsi` — "Erasure coding" — *No storage layer* | The **checksummed-storage integrity** layer: per-granule CRCs alongside the data. Not erasure coding, and **implemented here** — `src/fs/backend/csi_{tagstore,verify,scrub}.c`, five `brix_csi*` directives. |
| `XrdEc` — "Event data catalog" — *Nice-to-have* | The **erasure-coding library**, which is the thing the same document flags ❌ two tables earlier and the parity audit calls a hard blocker. |

So the tree simultaneously said erasure coding was a nice-to-have already
covered by a module with no storage layer, *and* that it was a 0% hard blocker.
Both rows are corrected in this phase (§8), because the next person to plan
this work will start where I started.

The second half of that discovery is load-bearing for the design: **CSI is the
integrity substrate an erasure code needs, and it already exists.** Reed–Solomon
reconstruction is only sound if you can tell *which* shard is wrong; parity
alone detects corruption but cannot locate it beyond the single-error case.
`csi_verify.c` already holds per-granule CRC32C against a block granule, with
"0 means not computed" and a scrubber (`csi_scrub.c`). Any EC design here would
build on that rather than invent shard checksums, and that is worth writing
down even though nothing is being built.

## 3. Placement — the three candidate seams, and which one is real

**(a) Client-side, as stock does it. REJECTED for this tree — but it is what
the wire flag means.** Stock `XrdEc` is a *client* library: the client writes
`k+m` shards to `k+m` data servers and reconstructs on read. `kXR_ecRedir` is a
login-response flag that tells a client the redirect targets it is about to be
handed are EC shards it must reassemble itself. That makes the flag a **client
contract**, not a storage one — see §4.

**(b) A decorator driver over N child instances. The natural seam, and it
already exists twice.** `sd_cache` (origin + cache tier) and `sd_stage` (origin
+ write staging) are drivers that hold and dispatch to child drivers, so an
`sd_ec` holding `k+m` children is not a new architectural idea, only a wider
one: two children become `k+m`, and the fan-out becomes arithmetic instead of
a policy choice. Everything above the seam — confinement, metrics, access log,
page CRC, buffer shaping — keeps working unchanged, which is exactly the
property `src/fs/backend/README.md` claims for the seam.

**(c) Below the driver — the storage does it. AVAILABLE TODAY, and it is the
supported answer.** A Ceph EC pool under `sd_ceph` (`src/fs/backend/rados/`,
phase-60/89) gives `k+m` durability with reconstruction, scrubbing and repair
that a storage team already operates. So does a filesystem or array under the
POSIX driver. The gap between (c) and (b) is not durability — it is *which
software has to be correct*, and (b) moves that from Ceph's EC implementation
to ours.

**Verdict on placement:** if it were built, it would be (b), a decorator driver
in `src/fs/backend/ec/` (proposed — no such directory exists, and this phase
creates none). It is not being built, for the reasons in §5–§7.

## 4. Wire signalling — the flag stays unset, on purpose

**Decision: `kXR_ecRedir` must NOT be set by a server whose erasure coding is
internal.** The flag does not mean "this server is durable"; it means "expect
shard redirects and reassemble them yourself". A server that strips and
reconstructs behind its own export owes the client nothing at all — the object
it serves is the object the client wrote, exactly as with a RAID under a POSIX
export. Setting the flag would promise a shard layout (stock `ObjCfg` naming,
per-chunk CRCs, the `.metadata` member) that this server would then have to
implement to keep, and it would break clients that believed it.

This makes the design pleasantly small on the wire: **internal EC is invisible
to the protocol.** No new opcodes, no new flags, no negotiation. The only
protocol-visible consequences are the ones any slow backend already has —
longer `open`/`read` latencies and a bigger `kXR_wait` surface under repair.

Setting `kXR_ecRedir` would only ever be right for the *other* design, the
client-side one — and that design is the client's problem, not this server's.
The comment in `flags.h` is corrected to say which of the two it is waiting on
(§8), and a test pins that no `src/` code ever sets the bit while permitting
the client's diagnostic decoder (`client/apps/diag/diag_doctor_recon.c:270`) to
keep *reading* it from a foreign server. Reading a peer's advertisement and
making the claim yourself are opposite acts and the guard must not confuse them.

## 5. Configuration — the existing multi-origin syntax means the wrong thing

`brix_storage_backend` already accepts a **pipe-separated ordered list** of
endpoints (phase-68 T11, `src/fs/vfs/vfs_backend_config_http.c:223`) with
**failover** semantics: every endpoint holds the whole object, any one of them
can serve it, and a health score picks the order.

Stripes are the exact inverse: no endpoint holds the whole object, and any `k`
of the `k+m` are required. Expressing stripes with `|` would give one syntax two
incompatible meanings, and — worse — would give an *existing deployed config* a
new meaning if a mode flag ever defaulted wrong: a failover list silently read
as a stripe set turns a redundant export into an unreadable one. Any EC
configuration therefore needs its own directive (`brix_storage_ec k+m …`) and
its own parse, never a mode flag on the current one. Recorded here so the next
attempt does not reach for the pipe.

## 6. Repair — the part that decides it

**Erasure coding without repair is worse than no erasure coding**, because it
converts a survivable `m`-shard loss into a total loss the moment the `m+1`th
arrives, while having convinced the operator the data was safe. So the repair
story is the whole story, and here it runs into three specific walls in this
tree:

1. **Repair is a background mutation, and phase-105 says background mutations
   carry their policy by value.** A rebuild writes a shard nobody requested, on
   behalf of no session, possibly onto an export the request-time policy would
   have refused. The mechanism exists (`_require_carried_mutation` /
   `brix_vfs_export_require_mutation`) and would have to be threaded through
   every repair path; a repair that ran on a `brix_read_only` export would be a
   policy bypass with a durability excuse.
2. **Nothing here schedules long-running background work over a fleet.** The FRM
   queue and the CSI scrubber are the closest things, and both are per-node,
   per-export walks. Shard repair needs to know which nodes hold which shards
   of which objects, which is a *catalogue* — the same catalogue that phase-114
   deferred for credentials and that no component here owns.
3. **The parity math cannot run on the event loop.** Encode-on-write and
   decode-on-degraded-read are CPU-bound Galois-field work; they belong in the
   thread pool (the seam `brix_thread_pool` already gives the gsiftp driver),
   which makes `sd_ec` a blocking-threadpool driver whose worst case is `k`
   concurrent child reads *plus* a matrix multiply per block, with a new
   external dependency (`isa-l`) that the build governance would have to admit.

Each is tractable alone. Together they are a phase of their own with a
correctness surface — silent reconstruction of wrong bytes — that no test in
this repository could honestly claim to cover, because the failure it must
detect is one the storage under it is also trying to hide.

## 7. Verdict

**NO-GO** on implementing erasure coding in this tree, now.

The reasoning in one line: the durability this would add is **already available
to every site that needs it**, one layer down (§3c), while the correctness risk
of a home-grown coder — silent bad reconstruction — is the one class of bug
this project's own integrity machinery exists to prevent. Building (b) would
move that risk from Ceph's decade-old implementation into ours in exchange for
no new capability.

**What was banked instead** (both delivered by this phase, §8): the two
mislabelled gap rows are corrected, and the `kXR_ecRedir`-stays-unset decision
is pinned by a guard rather than by a comment.

**The trigger that reverses this verdict.** Any ONE of:

- a deployment that needs `k+m` durability **across independent sites** (which
  a single Ceph EC pool cannot span, and which is the actual WLCG use case for
  `XrdEc`);
- a requirement to *read* data written by stock `XrdEc` (interop, not
  durability — the shard layout and `.metadata` member become a wire format we
  must parse, exactly as `sd_ceph` parses stock's RADOS striper layout);
- a client-side requirement, i.e. `client/` gaining EC reads, which is where
  stock puts it and where `kXR_ecRedir` would finally be honest.

The second is the likeliest, and it is a **reader**, not a coder: parsing
somebody else's shards is a bounded, testable problem against real data, in the
same shape as the striper-interop work phase-60/89 already did for Ceph. If
this is ever revived, revive it as that.

## 8. What this phase changes in the tree

- [x] **W117.1 Correct the two mislabelled gap rows.** `XrdOssCsi` is the
  checksummed-storage integrity layer and is implemented here; `XrdEc` is the
  erasure-coding library and is the ❌ the same document already records.
- [x] **W117.2 Record the `kXR_ecRedir` decision where the flag is defined.**
  The comment said "out of scope — requires EC storage backend", which is the
  wrong reason: an internal EC backend must still leave the bit clear. It now
  says the bit belongs to the client-side design.
- [x] **W117.3 Pin both, plus the spike's own claims.**
  `tests/test_phase117_ec_spike.py`:
  * *success* — the corrected rows say what §2 says, and this document records
    a verdict;
  * *error* — every in-tree artifact this document cites resolves (the
    NO-PHANTOM-EVIDENCE rule from phase-111: a spike that cites a file which no
    longer exists is worse than no spike, because it reads authoritative);
  * *security negative* — no `src/` code sets `kXR_ecRedir`, while the client's
    diagnostic decoder may still read it from a foreign server. A server that
    advertises a shard layout it does not implement misleads every client that
    believes it.
