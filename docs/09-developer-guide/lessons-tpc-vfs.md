# Lessons learned — native TPC + VFS data-plane work

**Scope:** the phase-55/56 VFS storage-driver refactor and the phase-57 native
third-party-copy (TPC) work — server-outbound GSI, async opens, in-protocol TLS,
bounded multi-round auth, and X.509 proxy delegation. This is a field guide of the
non-obvious things that cost real time, written so the next person spends that time
elsewhere. Companion to [phase-57 plan](../refactor/phase-57-tpc-delegation-zip-locks.md)
and the [shmtx postmortem](postmortem-shmtx-semaphore-stall.md).

---

## 1. The biggest meta-lesson: build the gate before the feature

Every TPC stage that went smoothly had a **red-on-main test gate written first**;
every stage that wasted days did not. The original native-TPC-over-GSI work *looked*
done because the only test used `xrdcp --tpc first`, which silently **falls back to a
client-mediated copy** when server-side TPC fails — so it passed `rc=0` while the
destination did no server-side pull at all. A `--tpc only` test (no fallback) would
have shown red immediately.

```text
  THE TRAP: --tpc first hides a broken server-side pull

  xrdcp --tpc first src dst                xrdcp --tpc only src dst
  ────────────────────────                 ────────────────────────
  try server-side TPC ──┐                  try server-side TPC ──┐
       │                │ fails            │                     │ fails
       ▼                │ silently         ▼                     ▼
  dest pulls? ──no──────┘                  dest pulls? ──no──▶ rc≠0  ✗ RED
       │                ▼                       │
      yes      fall back to client-mediated   yes
       │       copy (data flows THROUGH        │
       ▼       the client)  ──▶ rc=0 ✓ GREEN   ▼
   real TPC                  ↑                real TPC ──▶ rc=0 ✓ GREEN
                    "passes for the wrong reason"
```

A green `--tpc first` proves only that bytes arrived — not that the *server*
pulled them. Only `--tpc only` (no fallback) gates the behaviour you built.

Rules that came out of this:

- **A passing test that can pass for the wrong reason is worse than no test.** Prefer
  the strict mode (`--tpc only`, `strict=True` xfail) that cannot be satisfied by a
  fallback path.
- **Stand up the interop gate before writing the protocol code.** For F6 delegation
  we stood up a real stock `xrootd` source (`tests/test_tpc_delegation.py`) and drove
  the handshake against it; that gate surfaced *five* separate blockers (below) that
  no amount of reading our own code would have revealed.
- **Assert on the peer's observable state, not just `rc`.** The delegation gate
  asserts the *source's* access log shows the **user's** DN — the only thing that
  actually proves delegation worked end to end.

## 2. GSI / XrdSecgsi interop — the expensive surprises

Driving our GSI client *and* server against stock XrdSecgsi v5.9.5 cost the most
time. None of these are documented anywhere obvious; all were found by packet/log
archaeology.

1. **`gsi_ca_hash` only computes when `xrootd_trusted_ca` is a CA *file*, not a
   directory.** `src/gsi/config.c` does `fopen(trusted_ca)` + `PEM_read_X509`; a
   directory leaves the advertised `ca:00000000`, and a stock client then fails
   `unknown CA: cannot verify server certificate`. **Our own native client tolerates
   `ca:0`, which is exactly why this latent bug survived** — interop bugs hide behind
   lenient first-party clients. (Worth fixing: compute the hash from a cert in the
   dir too.)

2. **X.509 proxy delegation requires signed-DH.** A stock client *clears* the
   delegation option bits when the server's DH parameters aren't RSA-signed
   ("no signed DH parameters … will not delegate"). You must run
   `xrootd_gsi_signed_dh require` (or auto with a ≥10400 peer) or delegation silently
   no-ops.

3. **The plan said `-dlgpxy:1`; the stock option is `-dlgpxy:request`.** XrdSecgsi
   parses delegation via `getOptVal` over a *named* table (`{ignore, request}`,
   `XrdSecgsiOpts.hh`); a numeric `-dlgpxy:1` silently resolves to `ignore`. Verify
   option parsing against the source, not the docs.

4. **The client forbids delegation when it "used DNS" to verify the server name.**
   Connecting by an IP (or a hostname whose case/spelling doesn't match the cert CN)
   forces a reverse-DNS fallback → `usedDNS=true` → delegation refused (auth still
   succeeds, so it looks like only delegation is broken). **The cert CN must match the
   connect host exactly, including case** — the client lowercases the hostname, so an
   upper-case CN from `socket.getfqdn()` breaks it.

5. **Every server GSI message needs the rtag proof-chain.** A `kXGS_*` message must
   carry `kXRS_signed_rtag` = the server's RSA signature of the *peer's previous*
   `kXRS_rtag`, plus a fresh `kXRS_rtag`. Omit it and the client rejects the round
   with `ErrBadRndmTag: random tag missing`. We had to persist the client's rtag from
   `kXGC_cert` (`parse_x509.c`) and sign it with the server key in the pxyreq.

6. **`XrdSecGSIDELEGPROXY=1` (dlgReqSign) ≠ `=2` (dlgSendpxy).** Mode 1 makes the
   client *sign our certificate request* (request-based delegation, what we want);
   mode 2 makes it *forward its private key*. They produce different wire buckets;
   pick the one matching your capture model.

**Takeaway:** the GSI delegation handshake is a multi-round negotiation where each
side can silently *disable* a feature based on conditions established several rounds
earlier. When a feature "does nothing," look for where the *peer* turned it off, not
for where you failed to turn it on.

## 3. Structuring protocol code so it's testable

- **Separate the crypto kernel from the wire plumbing.** The F6 RFC-3820 primitives
  (`src/gsi/proxy_req.c`: `build_pxyreq` / `sign_pxyreq` / `assemble_proxy`) are
  ngx-free, OpenSSL-only, and have a standalone C unit suite
  (`src/gsi/proxy_req_unittest.c`, run in CI via `tests/test_gsi_proxy_crypto.py`,
  compiled `-Werror`). That suite — request→issue→assemble round-trip, RFC-3820 chain
  verification, two-level delegation, negatives — retired the *highest-risk* part of
  F6 (new crypto) **without** needing the network, the module, or stock interop. Do
  this for any security-critical crypto: it's the only part you can verify exhaustively
  and cheaply.

- **One implementation, both directions.** F4 collapsed the duplicated GSI round-2
  into a single shared kernel (`xrootd_gsi_build_cert_response`) used by both the
  native client and the TPC destination. Two parallel implementations of the same
  wire handshake *will* drift; a shared kernel plus tripwire tests
  (`test_gsi_interop_guards.py` asserts both callers delegate to it) keeps them honest.

- **Bound every async wait three ways.** The async `kXR_open` resolver
  (`tpc_open_resolve`, F8) is bounded by a per-recv `SO_RCVTIMEO`, a clamped single
  wait, an iteration cap, *and* a wall-clock deadline. The prior attempt hung because
  it relied on a single 60s socket timeout against a source whose `kXR_attn` never
  arrived. A blocking thread-pool worker makes blocking I/O *legal*, but you still
  must bound it so a silent peer fails fast (and the client's `--tpc` fallback runs in
  time — see §5).

## 4. VFS data-plane: the storage-driver seam

```text
  ┌───────────────────────────────────────────────────────────┐
  │  PROTOCOL HANDLERS   root://   WebDAV   S3   native-TPC     │
  │  populate xrootd_vfs_ctx_t, never touch a raw fd            │
  └───────────────────────────────┬───────────────────────────┘
                                  │  xrootd_vfs_io_execute()  ← live entry
                                  │  (xrootd_vfs_read/write = DEAD, no callers)
  ┌───────────────────────────────▼───────────────────────────┐
  │  VFS  (src/fs/)   confinement · metrics · cache · page-CRC  │
  └───────────────────────────────┬───────────────────────────┘
                                  │  xrootd_sd_driver_t  (sd.h)
                                  │  capability-typed seam ↓ swappable
  ┌───────────────────────────────▼───────────────────────────┐
  │  STORAGE DRIVER (src/fs/backend/)   POSIX default           │
  │  the ONLY place raw pread/pwrite/copy_file_range/fstat live │
  │  ← object/S3 backend slots in here without touching above   │
  └────────────────────────────────────────────────────────────┘
     known leak sites still above the line (being migrated):
     zip · frm · S3 upload_part_copy · webdav-io · cache-io
```

- **"Data POSIX lives only in the backend" is the load-bearing invariant.** All file
  byte I/O flows `proto → VFS (src/fs/) → storage driver (src/fs/backend/, POSIX
  default)` via the capability-typed `xrootd_sd_driver_t` seam (`src/fs/backend/sd.h`).
  The point is that an object/S3 backend can become primary *without touching anything
  above it*. Every raw `pread`/`pwrite`/`copy_file_range`/`fstat` on file data that
  leaks above the backend erodes that guarantee — they get audited and migrated
  (remaining known leak sites: zip, frm, S3 `upload_part_copy`, webdav-io, cache-io).

- **Cross-backend operations are VFS↔VFS, not POSIX shortcuts.** File staging became a
  backend↔backend move (`staged_file.c` `stage_move_objects`: `src->driver->pread →
  dst->driver->pwrite`) rather than a local-filesystem `rename`. Resisting the
  "just copy_file_range it" shortcut is what keeps the object-store future open.

- **Know which VFS entry points are live.** `xrootd_vfs_read` / `xrootd_vfs_write`
  currently have **no callers** — the live data path is `xrootd_vfs_io_execute()`.
  Wiring new code to a plausible-looking but dead entry point is an easy way to ship
  something that never runs. Grep for callers before depending on an API.

- **The shared kernel is compiled into the ngx-free client too.** Routing
  `checksum_core.c` through `sd.h` (phase-55) broke the client build, which compiles
  the shared code with `-DXRDPROTO_NO_NGX`; it was reverted to a direct `pread`. Any
  file that both the module and `client/` link must stay ngx-free — verify with a
  client build, not just the module build.

## 5. Build & test process gotchas (each cost a debugging cycle)

- **Editing a struct in `context.h` then `rm -rf objs/addon` breaks `make`.**
  `./configure` creates the `objs/addon/*` directories; removing them and running
  `make` gives `Fatal error: can't create … No such file or directory`. Re-run
  `./configure` after any clean of the addon objects. (And editing a mid-struct field
  + an *incremental* build risks a stale-object mixed-ABI crash — when in doubt, full
  rebuild.)

- **New `.c` files register in the top-level `./config`** (the `$ngx_addon_dir/src/…c`
  lists), then `./configure`. Not `src/config/config.h` (CLAUDE.md is imprecise here).

- **`ngx_log_error` does not understand `%02x`/`%d`.** Use the ngx specifiers
  (`%xd`, `%ui`, `%uz`, `%*s`); a wrong specifier prints literally or empty and sends
  you chasing a phantom. (`%u` is *not* valid — use `%ui` with an `ngx_uint_t` cast.)

- **`/*` inside a block comment is a `-Wcomment` (→ `-Werror`) break.** It bites on
  doc text like `*payload/*plen` and `NGX_*/kXR_`. Reword to avoid the `/` `*` pair.

- **Test isolation is real.** The stock-source `--tpc first` test and the multiround
  test pass alone but flake in a batch: port reuse + F8's bounded ~15s `waitresp` wait
  under load exceeding the 60s subprocess timeout. Give network tests dedicated ports,
  settle time, and headroom over any internal bounded wait.

- **Distinguish your breakage from concurrent breakage.** Repeatedly during this work
  the tree was red from an *unrelated* in-flight edit (`src/frm/residency.c`,
  `client/lib/uring.c` "disk ring chunk too large" on large downloads). Before
  concluding "I broke it," check the failing file is one you touched and that the
  failure mode matches your change (e.g. uploads passing but downloads failing is not
  an auth-code regression).

## 6. When to stop and what "done" means for unverifiable work

F6 delegation cannot be fully verified end-to-end in a WSL2 rig (synthetic hostnames
defeat the client's `usedDNS` delegation policy, §2.4). The discipline that kept this
honest:

- **Ship the verifiable layers; gate the unverifiable one off by default.** The crypto
  (25 standalone checks), the inbound capture (verified to `kXGC_sigpxy` against a real
  stock client), and the outbound use are all in and no-regression; only the final
  end-to-end DN assertion is `xfail`, with the exact environmental preconditions
  documented so it flips green on a real grid host.
- **Never report unverified crypto as "done."** The plan's own discipline — "do not
  add unverifiable code on top" — is why F6 stayed behind `xrootd_tpc_delegate`
  (default off) until each layer had the strongest gate the environment allowed.
- **Record the dead ends.** The five GSI findings above each looked like the end of
  the road. Writing them down (here + in the plan's §F6) is the difference between the
  next person finishing F6 in an afternoon on a grid host vs rediscovering all five.
