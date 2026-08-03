# Pure-Python PyXRootDClient Writing MNIST `.root` Through brix — Walkthrough & Runbook

**Date:** 2026-08-03
**Status:** ✅ Working end-to-end. A real MNIST `.root` file was written by the pure-Python
`xrd` client, through a **brix** gateway, to an **official XRootD v5.9.6** origin, and then
independently validated with `uproot 5.7.5`.
**Scope (brix repo):** `client/Makefile`, and the brix-side protocol trailer that is
test-locked by `tests/test_handshake_protocol_wire.py` and `tests/test_security_level.py`.
**Scope (external):** the pure-Python client lives **outside this repo** at
`/root/dev/PyXRootDClient` (GitHub `rob-c/PyXRootDClient`); its fixes are referenced here but
are committed in that repo, not this one.

> **TL;DR.** The pure-Python `xrd` client can write a genuine MNIST ROOT file across a brix
> proxy to a stock xrootd backend with no auth. Getting there needed one **client-side** fix
> (tolerating brix's non-standard, deliberately-extended `kXR_protocol` security trailer —
> committed as `c8e5efd` to `rob-c/PyXRootDClient`) and one **brix-side** fix (a
> `client/Makefile` build regression). brix's protocol trailer is *not* a bug — it is a
> deliberately test-locked feature; the correct fix was client tolerance, matching XrdCl.

---

## Context

The goal was to drive brix's write path from a completely independent, pure-Python XRootD
client (no `libXrdCl`, no official C++ bindings) and confirm the bytes land correctly on a
stock backend. The client is the `xrd` Python module from GitHub `rob-c/PyXRootDClient`,
cloned locally to `/root/dev/PyXRootDClient` (external to the brix repo).

A real MNIST training set was serialized into a `.root` file and written through the stack.
Independent validation with `uproot 5.7.5` confirmed the result: **20 trees**, with
`train_0 = 5923 × 784 uint8` and labels correct.

**Python compatibility.** The `xrd` client requires **Python 3.10+**; the box default is 3.9.
`python3.11` was installed (dnf, appstream) and a venv created at `/root/dev/xrdvenv`
(`pip install -e .`). The full client test suite is **3085 pass**. The only failures — 25
ERRORS in `test_interop.py` — are environmental, not bugs: xrootd refuses to run as root
("Security reasons prohibit running as superuser") inside its `RealServer` harness (see the
run-as-nobody note below).

---

## The end-to-end path

Local, no-auth topology under `/tmp/xrdmnist/`:

- **Official xrootd origin on port 21095** — `xrootd-origin.cfg` with `oss.localroot`,
  `all.export /`, no `seclib` (so anonymous, default read/write).
- **brix gateway on port 21094** — `nginx-brix.conf` with:
  - `brix_root on;`
  - `brix_auth none;`
  - `brix_allow_write on;`
  - `brix_storage_backend root://127.0.0.1:21095;`
  - `brix_stage on;`
  - `brix_stage_store posix:/tmp/xrdmnist/stage;`
  - `brix_stage_flush sync;`

Standalone-nginx config requirements:

- Load the stream module **before** the brix stream module:
  `load_module .../ngx_stream_module.so;` must precede
  `load_module .../ngx_stream_brix_module.so;`.
- Set `user nginx;` so workers (uid 982 here) can write the stage/gwdata directories.

brix's **write-staging → commit** worked perfectly for both native `xrdcp` and the Python
client. Notably, the old [[xrd1-cache-origin-demo-2026-07-23]] **LIVE BUG 1** (write
staged-commit ENOENT) did **not** reproduce in this topology.

---

## Fixes that made it work

### 1. Client-side: tolerate brix's extended `kXR_protocol` security trailer (committed `c8e5efd`)

`src/xrd/proto/responses.py::parse_protocol` (in the **external** PyXRootDClient repo)
hard-failed with `ProtocolError: security block has tag 0, expected 'S'` on brix's
`kXR_protocol` reply.

Root cause: brix intentionally answers `kXR_secreqs` with a **4-byte security-methods header
+ 8 bytes per method entry + the `'S'` ServerResponseReqs record**, so the `'S'` sits at
**trailer offset 4 (body offset 12)**, not the offset 8 the stock short form uses. Official
xrootd sends the 8-byte short form at auth-none.

Fix (client): added `_find_sec_reqs()` to locate the `'S'` record across all three shapes
(short form / spec-at-8 / vendor-prefixed) and fall back to `secNone` instead of raising —
matching XrdCl's tolerance. `tests/test_responses.py` was updated (mislabelled→tolerated,
plus a vendor-prefixed case). This fix was **committed and pushed** to
`github.com/rob-c/PyXRootDClient` as commit **`c8e5efd`**.

**Why this is a client fix, not a brix bug.** brix's non-standard protocol trailer is
**deliberate and test-locked** — brix advertises its security level + methods in the
`kXR_protocol` trailer. Do **not** "fix" brix to the stock spec; it would break the
security-level advert feature. The tests that lock this behavior:

- `tests/test_handshake_protocol_wire.py::test_protocol_secreqs_trailer`
- `tests/test_security_level.py` — decodes `sec_count = body[10]` and
  `offset = 8 + 4 + sec_count * 8` (confirmed present at those lines in the brix repo).

Auth methods are **also** advertised the standard way, in the login `&P=` block (see
`src/protocols/root/session/login.c`).

### 2. brix-side: `client/Makefile` build regression

Commits `7d8b73215..bd316c023` added 44 new client `.c` translation units + 9 shared
cvmfs/cache TUs but never updated `client/Makefile`, which lists **every** source explicitly
(no wildcards). As a result `xrddiag` / `xrdcksum` (and would-be others) failed to link with
`undefined reference` errors (`js_str`, `download_to_fd`, `copy_web`, `doctor_*`, …).

Fix: registered all new files in the correct `LIB_SRCS` / `<name>_OBJS` / FUSE-split lists.
**Only `client/Makefile` changed** (~45 additions / ~20 deletions). The full RPM build then
completes.

---

## How to reproduce

1. **Client env (external repo).** Install Python 3.10+ (3.11 used here) and create a venv:

   ```
   python3.11 -m venv /root/dev/xrdvenv
   /root/dev/xrdvenv/bin/pip install -e /root/dev/PyXRootDClient
   ```

2. **Origin.** Launch the official xrootd v5.9.6 on 21095 with `xrootd-origin.cfg`
   (`oss.localroot`, `all.export /`, no `seclib`). xrootd **refuses to run as root**, so run
   it as `nobody`:

   ```
   runuser -u nobody -- xrootd -c /tmp/xrdmnist/xrootd-origin.cfg
   ```

   Use `runuser -u nobody` (NOT `-R` or `-b`, which were flaky here) and launch it via the
   Bash tool's `run_in_background`.

3. **brix gateway.** Start nginx with `nginx-brix.conf` (directives listed above) on 21094;
   ensure `user nginx;` and the stream-module load order.

4. **Write + validate.** Write the MNIST `.root` through brix (port 21094) with the `xrd`
   client or native `xrdcp`; validate the result independently with `uproot 5.7.5` (expect
   20 trees; `train_0` = 5923 × 784 uint8; labels correct).

5. **Benchmark harness (client, external repo).** For throughput comparisons:

   ```
   benchmarks/bench.py --url root://HOST:PORT//bench --size <MiB> --repeat N --json out.json
   ```

   It compares `xrd` vs the official bindings vs `xrdcp`; point it at 21094 (brix) and 21095
   (origin).

---

## Related

- [[xrd1-cache-origin-demo-2026-07-23]] — the earlier cache+origin demo whose write
  staged-commit ENOENT (LIVE BUG 1) did not reproduce here.
