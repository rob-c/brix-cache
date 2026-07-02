# go-hep Interop Findings — Three Protocol Bugs a Stock Client Exposed

> **What this is.** A record of what testing the **go-hep** XRootD client
> (`github.com/go-hep/hep`, the `xrootd` package — `xrd-ls`, `xrd-cp`,
> `xrd-client`) against this module revealed. go-hep is an independent,
> clean-room Go implementation of the `root://` protocol (targeting protocol
> v3.1/2012). Because it is *not* derived from XRootD C++ and uses a strict,
> **stat-before-open**, fully-stock request sequence, it acted as an excellent
> conformance probe and surfaced **three real bugs** in this module that our own
> client (and the test fleet) had never tripped.
>
> Companion: [`xrootd-implementations.md`](xrootd-implementations.md) (the
> five-implementation comparison). Regression tests:
> `tests/test_gohep_interop.py`.

---

## 1. What go-hep can and cannot do (compatibility matrix)

go-hep's `xrootd` package implements only the binary `root://` protocol with
**unix / host / krb5** auth — **no GSI, no TLS, no HTTP/xrdhttp** (confirmed in
its source and empirically). So the testable surface is anonymous `root://`,
direct and through a mesh:

| Scenario | Anonymous | GSI |
|---|---|---|
| `root://` direct | ✅ ls / cp / byte-identical (after fix #1) | ❌ go-hep: `could not authorize using gsi: provider was not found` |
| `root://` mesh (static-map redirector → data server) | ✅ ls / cp / byte-identical (after fixes #2 + #3) | ❌ (same — go-hep has no GSI) |
| xrdhttp (`http(s)`/`davs`) | N/A — go-hep ships no HTTP client | N/A |

The GSI and xrdhttp "failures" are **go-hep limitations**, not module defects:
our server correctly offered GSI and go-hep cleanly reported it had no provider.
Everything go-hep *can* do now works.

---

## 2. The three bugs

### Bug #1 — Server sent a response to `kXR_sigver` (a request *prefix*)

**Symptom (go-hep):** every op failed with
`xrootd: statinfo "" doesn't have enough fields, expected format is: "id size flags modtime"`.

**Root cause:** `kXR_sigver` (3029) is a **prefix** to the request it signs — the
server must produce exactly one response, belonging to the *signed* request.
Our `xrootd_handle_sigver()` ended with `xrootd_send_ok(ctx, c, NULL, 0)`, emitting
a separate empty `kXR_ok` on the signed request's streamid. A stock client reads
that empty ack as its real reply (go-hep: stat → empty statinfo). The XRootD C++
reference processes sigver via `XrdXrootdProtocol::ProcSig()` and sends **no
response on success** (only `kXR_SigVerErr` on failure).

**Why our own stack never caught it:** our native client *also* read the ack
(`client/lib/sigver.c`) — a consistent-but-non-standard pair. Both sides diverged
from the spec in a way that only an independent client revealed.

**Fix (coordinated):**
- `src/protocols/root/session/signing.c` — success path returns `NGX_OK` with **no** queued
  response (the recv loop then reads the signed request, whose response is the
  only one); error paths still reply.
- `client/lib/sigver.c` — no longer reads an ack after sending the sigver frame.

**Impact beyond go-hep:** this also makes us correct for the **official XRootD
client** at `security_level ≥ 2` (which would have hit the identical desync).

### Bug #2 — `stat` / `dirlist` ignored the static `xrootd_manager_map`

**Symptom (go-hep through a static-map redirector):**
`xrootd: error 3007: Bad file descriptor` on `ls`/`cp` (the redirector answered
the stat locally — it has no `xrootd_root` — instead of redirecting).

**Root cause:** only `open` (`src/protocols/root/read/open_request.c`) and `locate`
(`src/protocols/root/read/locate.c`) consulted `xrootd_find_manager_map()`. `stat`
(`src/protocols/root/read/stat.c`) and `dirlist` (`src/protocols/root/dirlist/handler.c`) redirected **only via
the CMS registry**, so a static-map-only redirector never redirected them — and a
stat-first client (go-hep, and stock `xrdfs`/`xrdcp`) failed before it ever
opened anything.

**Fix:** `src/protocols/root/read/stat.c` and `src/protocols/root/dirlist/handler.c` now consult
`xrootd_find_manager_map()` and emit a `kXR_redirect`, mirroring `open`.

### Bug #3 — Root prefix `/` matched only `/`, not its children

**Symptom:** with bug #2 fixed, `stat /` redirected but `stat /blob.bin` did not
(it fell through to a local stat → `Bad file descriptor`).

**Root cause:** `xrootd_path_prefix_match("/", 1, "/blob.bin")` —
`strncmp` matched, but the component-boundary check `path[1]` saw `'b'` (not
`'\0'`/`'/'`) and returned no-match. A prefix that **itself ends in `/`** (the
root `/`, which cannot be stripped, or any explicit `/dir/`) is already at a
separator and should match everything beneath it.

**Fix:** `src/auth/authz/find_rule.c` — `xrootd_path_prefix_match()` returns a match
when the prefix ends in `/`.

**Impact beyond go-hep:** this matcher backs **`manager_map`, VO rules, authdb
rules, and group rules**. The fix makes a **root-level rule apply recursively**
(previously a `/` VO/authdb/manager_map rule matched only the literal `/`) — the
correct, expected semantics, but it changes ACL/redirect matching, so the
authdb/VO and redirector/cluster regression suites should run before release.

---

## 3. Verification

All proven live (Go 1.23 build of go-hep, self-provisioned local servers):

- anon `root://` direct: `xrd-ls -l`, `xrd-cp` 64 KiB blob → **byte-identical**.
- anon `root://` mesh (redirector → data): `xrd-ls`, `xrd-cp` → **byte-identical**.
- GSI: clean, expected failure (`provider was not found`).
- Non-regression: GSI guard suite + local TPC GSI handshake test still pass.

---

## 4. Regression tests — `tests/test_gohep_interop.py`

Self-provisioning (no fleet, no network, no Go required for the core tiers):

1. **Raw-wire protocol guards (CI-safe)** — a minimal Python XRootD client against
   self-started local servers:
   - `test_sigver_no_ack` — handshake + anon login + `kXR_sigver` + `kXR_stat`;
     asserts the first response is a **valid 4-field statinfo**, i.e. the server
     did NOT ack the sigver (bug #1).
   - `test_static_map_redirects_stat_child` — a static-map redirector must answer
     `kXR_redirect` for `stat /child` (bugs #2 + #3).
   - `test_static_map_redirects_dirlist_child` — same for `dirlist` (bug #2).
2. **go-hep end-to-end (gated on a Go toolchain)** — builds `xrd-ls`/`xrd-cp` and
   runs anon-direct + mesh with integrity checks; skips cleanly without Go.
3. **Source tripwires (CI-safe)** — fail if any of the three fixes is reverted:
   server sigver path doesn't `send_ok`; client doesn't read a sigver ack;
   `stat`/`dirlist` call `xrootd_find_manager_map`; the prefix matcher handles a
   trailing-`/` prefix.

```bash
PYTHONPATH=tests pytest tests/test_gohep_interop.py -v
# with go-hep e2e:
PATH=/path/to/go/bin:$PATH PYTHONPATH=tests pytest tests/test_gohep_interop.py -v
```
