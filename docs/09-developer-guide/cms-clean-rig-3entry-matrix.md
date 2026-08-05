# CMS Clean-Rig — 3-Entry-Point Data+Metadata Matrix

**2026-08-05.** A fresh **no-auth** (`brix_auth none`) loopback CMS rig running the full
data+metadata matrix (mkdir / stat / statvfs / upload / stat-file / ls / download / cat / cksum /
mv / rm / rmdir), 3× each, through **three entry points**, plus
`xrddiag remote-doctor cms://` (connect / locate / redirect).

## Rig

- Launcher `scratchpad/launch_clean_rig.py`, driver `scratchpad/run_matrix.py` (session 257ace70).
- `CMS_MESH_DIR=/tmp/xrd-test/cms-clean`, `TEST_NGINX_BIN=/tmp/xrdhttp-deleg/nginx-build/objs/nginx`.
- Reuses `tests/cms_mesh_lib.py` primitives (`Mesh` / `cfg_manager`) but on disjoint **255xx** ports:
  - **xrd** (all-REAL): xrootd mgr `:25500` (cms `:25501`) + real ds `:25502` → *XRootD-direct*.
  - **bmgr**: BriX nginx cms manager `:25510` (cms `:25511`) + real ds `:25512` → *BriX cms manager/redirector*.
  - **bfront**: BriX **`brix_tap_proxy on` + `brix_tap_proxy_upstream 127.0.0.1:25500` +
    `brix_tap_proxy_auth anonymous`**, listen `:25520` → *BriX front over the clustered XRootD*.

### Two root-box gotchas (both handled in `real_node()` of the launcher)

- Stock xrootd/cmsd refuse to run as superuser → launch with **`-R nobody`** and
  `chown -R nobody` the data/run/logs dirs.
- Real xrootd `-n <name>` nests its log at `logs/<name>/<name>-xrootd.log` (not the bare `-l` path).

## Results (per-entry PASS, 12 ops × 3 runs = 36)

- XRootD-direct **30/36** · BriX-cms-manager **33/36** · BriX-front(tap) **27/36**.
- `remote-doctor cms://` → **GREEN** connect+locate+redirect on both cms redirectors (`:25500`, `:25510`).
- cms redirect/locate verified per op in logs (BriX manager logs the plane as
  `cmsd-action op=have … location cached, client woken`; stock mgr as `redirects … to :25502`).

## Three deltas — two FIXED, one is a stock-xrootd property

### 1. `cksum` — FIXED (at the origin)

Initially failed on all three (`query chksum not supported`) — the data nodes had no checksum
configured. **CLOSED** by appending `xrootd.chksum max 2 adler32` to **every** real node in the
launcher's `real_node()` (BOTH manager and server): the manager must advertise a chksum type to
answer/redirect `query checksum` (else it replies "not supported" WITHOUT redirecting), and the data
server must have it to compute the digest. Now identical `adler32` across all three entries (proof
the digest flows through the cms redirect). Same class as the delegation-matrix Want-Digest/cksum
gaps, but here closed at the origin.

### 2. `ls` (dirlist) asymmetry — OPEN, but a STOCK property (not a BriX bug)

Works directly on the data server `:25502` and via the **BriX** redirector `:25510`
(BriX-cms-manager scores **36/36**), but FAILS via the **stock xrootd** redirector `:25500`
("Unable to open directory … NotFound") and therefore via bfront (which fronts the stock cluster).
**BriX's redirector serves dirlist; the stock xrootd redirector + bundled client does not** — BriX is
the more-capable side.

### 3. `statvfs` through the tap-proxy front — FIXED (source, verified)

Was `proxy: invalid file handle` (kXR_InvalidRequest). Root cause vs `XProtocol.hh`:
`brix_proxy_forward_stat` shared the kXR_stat + kXR_truncate + kXR_fattr path in
`src/net/proxy/forward_request.c` and read the fhandle at **`req[4]`** — right for
`ClientTruncateRequest` / `ClientFattrRequest` (fhandle@4) but **wrong for `ClientStatRequest`, where
byte 4 is the `options` field** (fhandle@16). Plain `stat` (options=0) fell through to the path branch
and worked by luck; **`statvfs` sets `options=kXR_vfs=1`**, misread as a live fhandle →
`proxy_translate_fh` fails → reject.

**FIX:** split **`brix_proxy_forward_statx`** (kXR_stat only) out of the shared handler — translate the
fhandle at byte 16 only when present (open-handle stat), forward path/vfs stats verbatim; renamed the
residual to `brix_proxy_forward_trunc_fattr` (truncate+fattr, unchanged).

Tests: `tests/test_proxy_stat_vfs.py` (success = statvfs kXR_ok · error = plain/bad path unaffected ·
sec-neg = forged open-fhandle still rejected) — 3 PASS + 22 existing proxy tests green. Rebuilt
`/tmp/xrdhttp-deleg/nginx-build/objs/nginx`; live front `:25520` statvfs now matches direct.
Related: remote-fhandle-collision-fix.

## GSI variant (2026-08-05)

Same 3 entry points on **256xx** (launcher `scratchpad/launch_gsi_rig.py`, driver
`run_matrix.py <runs> gsi`). GSI bound to the client-facing `xrootd` plane only via
`if exec xrootd … fi` so the cmsd cluster plane keeps unix auth and registration is unaffected. Client
presents alice's X509 proxy `/tmp/alice_proxy.pem` (`xrdgsiproxy init`, EEC CN=Test User/CN=12345 →
gridmap → **alice**; host cert → bob).

Results match noauth exactly (XRootD-direct 30/34 · BriX-cms-manager 34/34 · BriX-front(tap) **30/34**),
and the data-node logs show **all ops login-as-alice, zero bob** (xrd-ds 62×, bmgr-ds 38×) — full
per-user identity across the cms redirect on all three entries.

### tap-proxy GSI upstream fix — `brix_tap_proxy_auth gsi` (NOT `forward`)

First GSI front attempt used `brix_tap_proxy_auth forward` and failed "user not authenticated" —
`forward` forwards a WLCG **bearer/ztn token** (`proxy_bs_auth_forward_bearer`), NOT a GSI credential,
so the GSI-requiring upstream cluster got nothing. `BRIX_PROXY_AUTH_GSI` is a distinct mode
(`src/net/proxy/directives.c`). Correct front block (from `brixbench/gsi_deleg_alice_bob.sh`):
client-facing `brix_auth gsi` + `brix_gsi_signed_dh require` + `brix_tpc_delegate on` (capture the
delegated proxy), relay `brix_tap_proxy on` + `brix_tap_proxy_auth gsi`; client env
`XRDC_GSI_DELEGATE=1 XRDC_NO_PROMPT=1` so xrdfs actually delegates alice's proxy.

**Gotcha:** the front's worker (nobody) must own `/dev/shm/brix-creds` or delegation silently no-ops
("credential store owned by uid … workers run as …" warning) — chown it to the worker user. See
gsi-delegation-alice-bob-fullmatrix.

## ls-of-a-file-in-a-subdir determination (2026-08-05)

Changed the `ls` op to target a file inside a subdir (`ls-subdir` + `ls-file-insub`).

- **BriX-cms-manager: works as expected** — `ls sub` lists `sub/g.dat`, and `ls sub/g.dat` correctly
  resolves the path then refuses to dirlist a file ("Unable to open directory … not a directory",
  FSError).
- **XRootD-direct and BriX-front(tap): both FAIL** — `ls` returns "Unable to open directory …
  NotFound", i.e. dirlist never resolves through the **stock xrootd redirector** (bfront fronts that
  same stock cluster), so it can't even reach the file-vs-dir distinction.

Same stock-redirector dirlist gap as delta #2 above; BriX's redirector is the more-capable side. Both
noauth and gsi profiles show identical ls behaviour.

## Uncommitted (no OP approval this conversation)

`src/net/proxy/forward_request.c` + `tests/test_proxy_stat_vfs.py`. See cms-auto-role-submanager for
the manager-role auto-derivation this rig exercises.
