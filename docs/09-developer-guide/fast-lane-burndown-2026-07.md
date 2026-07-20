# Fast-lane test burndown — 2026-07 session writeup

**Scope:** a full sweep of the pure-Python fast-lane pytest suite on the root
build host `xrd1` (`ce4/xrd1.edi.scotgrid.ac.uk`), taking it from **354
failures** immediately after the bash→pytest fleet migration down to **31
failures / 0 errors** (7531 passing) and root-causing every remaining cluster —
then a follow-on pass that fixed the last high-value deep bugs (upload-resume
staging, the GSI store-memo observability gap, and the CVMFS trust-gate `-9`
whitelist-parser bug) and swept the CVMFS conformance suites green.

This document is the durable record of **what broke, why, how it was fixed, and
— most importantly — how to not hit the same class of bug again.** It is written
for the next engineer who sees a wall of red on a root box.

> TL;DR of the whole session: **~90 % of the failures were one bug class —
> "the test harness runs as `root`, but the nginx/xrootd *worker* runs as
> `nobody`."** Everything downstream (EACCES, 403, 503, `NotAuthorized`, silent
> empty transfers, "Service key not available", "did not come up") was a symptom
> of a `nobody`-owned process touching a `root`-owned path, key, or socket. Fix
> the ownership/privilege model (§2) and the symptom evaporates. The
> genuinely-deep remainder was a handful of **protocol / format conformance**
> divergences settled against the real XRootD / CVMFS sources (§3), plus one
> **config-time observability** gap (§2.7).

---

## 1. The environment, and why it matters

- **Host runs as `root`.** pytest, the fleet launcher, and every helper run with
  `euid == 0`. This is *not* how CI or a dev laptop usually runs, so a whole
  class of latent "root-only" assumptions surface here for the first time.
- **nginx drops workers to `nobody`.** The vendored nginx (`/tmp/nginx-1.28.3`,
  `--add-module=$REPO`) has no compiled-in privileged user; with a `root` master
  and **no `user` directive**, workers run as `nobody`. So: **master = root,
  worker = nobody.**
- **Stock XRootD refuses to run as `root` at all** ("Security reasons prohibit
  running as superuser; program is terminating") — it must be launched with
  `-R <user>` to drop privileges.
- **A worker-hardening pass now sheds `CAP_DAC_OVERRIDE`** in every worker
  (`brix_imp_worker_harden`, `src/core/config/process.c`). Before it, a
  `root`→`nobody` worker could *sometimes* still write `root`-owned paths via the
  inherited capability; after it, it genuinely cannot. This un-masked several
  perms bugs that had been silently "working."

**Rule of thumb:** if a test creates a file/dir/socket as `root` and a
`nobody` worker later has to read or write it, it will fail on this host unless
the path is explicitly opened up (chmod/chown) or the worker is run as `root`
(`-g "user root;"`).

---

## 2. Fix catalogue by root-cause class

### 2.1 nobody-worker cannot read a `root`-owned credential / keytab

| Symptom | Test(s) | Root cause | Fix |
|---|---|---|---|
| `krb5 credential verification failed: Service key not available` on every valid AP-REQ | `test_krb5_auth`, `test_native_krb5` | `kdc_helpers.provision()` `chmod 0600 root` on the service keytab; the `nobody` acceptor worker cannot read it, so `krb5_rd_req` has no service key. **The keytab was provably valid** (`kvno -k` OK) — a classic "blame the code, but it's file perms" trap. | `kdc_helpers.py`: `shutil.chown(KRB5_KEYTAB, "nobody")` when `euid==0` (fallback `chmod 0644`). |
| globus-url-copy `535 GSSAPI authentication failed`; server "unable to get local issuer certificate"; leaf DN is the **real host cert** | `test_gridftp_gsiftp*` | globus-url-copy **as root** ignores `X509_USER_PROXY` and falls back to `/etc/grid-security/hostcert.pem` (a real IGTF cert not in the test CA). `voms-proxy-info` honours the proxy as root but globus-url-copy does **not**. | new `tests/gridftp_client_env.py::gsi_client_env()` — pins `X509_USER_CERT`/`X509_USER_KEY` to the proxy when `euid==0`. |

**Avoid it again:** any test-generated secret a worker must read (keytab, host
key, GSI key, S3 secret file) must be **owned by / readable by the worker's
runas account**, not left `0600 root`. For grid client tools run as root,
remember they have their *own* credential-discovery quirks — set
`X509_USER_CERT`+`X509_USER_KEY`, not just `X509_USER_PROXY`.

### 2.2 nobody-worker cannot WRITE a `root`-owned data / cache / control dir

| Symptom | Test(s) | Root cause | Fix |
|---|---|---|---|
| WebDAV/S3 PUT → `403`; log `staged open for write failed … (13: Permission denied)` | `test_put_content_encoding` | export tree created under a `root`-owned `tmp_path`; `nobody` worker can't create objects. | fixture `os.chmod(export, 0o777)` when `euid==0`. |
| chmod/stat differential `ours=54 [3010] permission denied` vs `stock=0` | `test_conf_write_ops`, `test_conf_xrdfs`, `test_conf_pathedge`, `test_conf_errors`, `test_native_xrdcp_xrdfs_b` | the differential harness chowned only the *stock* file to `nobody`; **OUR** worker is now *also* `nobody` and can't chmod a `root`-owned file. | `L.chown_stock()` applied to **both** sides, not just stock. |
| tape-REST `POST /api/v1/stage → 503 "tape staging is not configured"` | `test_frm_owner` | worker-hardening sheds `CAP_DAC_OVERRIDE`; `nobody` worker can't write the `root`-owned FRM control-dir, so the stage-request registry singleton never initialises (`tape_queue() == NULL`). | fixture chmods `control`/`queue`/`data` `0777` when `euid==0`. |
| pblock-fsck `no such table: objects`; catalog.db is `root:root` with only the `ctl` table | `test_pblock_lab_*` | a test helper (`_ctl_set`, `_lock`, `_sql`, `_catalog_size`) does `sqlite3.connect(catalog.db)` **as the root pytest process** *before* the `nobody` worker lazily creates it → catalog born `root`-owned; the worker then can't open it read-write, the `objects` table is never created, pblock silently falls back. | new `pblock_live.pblock_worker_own(catalog)` chowns catalog + `-wal`/`-shm` to `nobody` after every side-channel write; `pblock_worker_readable()` for the crypt keyfile. |
| upload `xrdcp rc=54 permission denied (NotAuthorized)` at `kills=0` (before any chaos); staged partial never appears | `test_shutdown_resume` (the 3 UPLOAD cases; downloads always passed) | the test creates `brix_stage_dir` at `/dev/shm/xrd-stage-<pid>` with default `0755 root`; the `nobody` worker can't write staged `.part` files there, so the staged-open is refused and the client sees `NotAuthorized`. (brix logs nothing for this — a minor logging gap.) | fixture `os.chmod(stage, 0o777)` when `euid==0` at both `/dev/shm` stage-dir sites. |

**Avoid it again:** `server_launcher` only opens up the instance's `data_root`.
**Any auxiliary directory a worker writes** (FRM control-dir, cache store,
sqlite side-channel, spool) that lives *outside* `data_root` must be chmod'd by
the test. When a test process pokes a DB/file that a worker also owns, **hand it
back to the worker** (`chown nobody`) — never leave a `root`-owned artifact in
the worker's write path.

### 2.3 stock/official xrootd refuses to run as superuser

| Symptom | Test(s) | Fix |
|---|---|---|
| stock `xrootd` exits rc=8/immediately; port never opens; `pytest.skip("… did not come up")` or fixture ERROR | `test_gridftp_delegate_xrootd`, `test_tpc_gsi_outbound`, `test_tpc_delegation`, `test_native_gsi_interop`, `test_mirror_upstream`, `test_dropin_byte_for_byte`, `test_official_xrootd_resilience`, `resilience/test_loss_sweep_gsi` | launch `xrootd` with `-R <REF_RUNAS_USER, default nobody>` when `euid==0`, and **pre-open the paths the dropped user needs**: `oss.localroot` (a+rwX), CA certdir (a+rX), hostcert (a+r), **hostkey `chown nobody` + 0400** (XrdSecgsi refuses a group/world-writable key), and `all.adminpath`/`all.pidpath` under the test's writable base (set them explicitly; the default is `root`-owned). If `-n <instance>` is used, pre-create+chmod the `<logdir>/<instance>` dir. |

**The proven pattern** (mirror it for any *new* direct-`xrootd` launcher):
```python
argv = ["xrootd", "-c", cfg, "-l", log, ...]
if os.geteuid() == 0:
    runas = os.environ.get("REF_RUNAS_USER", "nobody")
    # data root a+rwX; CA dir a+rX; hostcert a+r; adminpath/pidpath a+rwX
    # hostkey: chown runas + 0400  (NEVER world-writable — XrdSecgsi rejects it)
    argv += ["-R", runas]
```
There is already a canonical implementation in
`server_launcher._xrootd_runas_user`; tests that launch `xrootd` **directly**
(not via `LifecycleHarness`) bypass it and must replicate the drop.

### 2.4 raw nginx launch bypasses the `user root;` injection

| Symptom | Test(s) | Fix |
|---|---|---|
| GSI-authenticated cache fill returns 0 bytes / times out, **no server-side error** | ~13 `test_cmd_*` scenarios (`credential_xroot_gsi`, cache-fill family, …) | the live scenarios launch their own nginx via `run([nginx, "-c", …])`, which — unlike `LiveRun.start_nginx` — does **not** inject `-g "user root;"`; the `nobody` worker can't read the root-owned credential or write the cache. |

**Central fix** (`tests/cmdscripts/__init__.py::run`): detect a genuine nginx
*server* launch (`argv[0]` is nginx, has `-c`, not `-t`/`-s`/`-v`, no existing
`-g`) and append `-g "user root;"` when `euid==0`. One change fixed the whole
family. `_maybe_force_nginx_root_worker()` is the helper; reuse it for any new
scenario that launches nginx via a bare `subprocess`.

### 2.5 test-isolation races under `pytest -n --dist load`

| Symptom | Test(s) | Root cause | Fix |
|---|---|---|---|
| all krb5 tests **ERROR at setup**: `kdb5_util create … command failed` | `test_krb5_auth` + `test_native_krb5` | both files `provision()` the **shared** KDC realm (rmtree + `kdb5_util create`) and, under `--dist load`, land on different xdist workers that race. `xdist_group` does **not** help — `--dist load` ignores it. | cross-process **`flock`** in `kdc_helpers.up()`/`down()` on a lockfile *outside* the rmtree'd `KRB5_DIR`; serialises each `up()`→`down()` lifecycle. |
| ~7 tests fail in the aggregate but **pass in isolation** | `test_gsi_tls`, `test_dashboard`, `test_phase31_memory`, `test_s3`, `test_tape_rest`, `test_io_edge_cases_b` | genuine parallel-contention flakes (shared PKI regeneration, port pressure). | (left as flakes; the real ones are §2 fixes) — **always re-run a suspected failure in isolation before "fixing" it.** |

**Avoid it again:** any test that mutates a **process-/host-global** resource
(a fixed-port daemon, a shared realm/DB, the shared PKI) is unsafe under
`--dist load`. Guard it with a file lock, or make the resource per-test. Don't
reach for `@pytest.mark.xdist_group` — it is a no-op unless the suite runs
`--dist loadgroup`.

### 2.6 PKI desync (historical, fixed earlier in the session)

A mid-run `blitz_test_pki()` rmtree+regenerates the **entire** CA/hostcert; the
standing fleet loaded its certs once at startup, so a fresh client proxy chained
to the *new* CA while the fleet served the *old* one → every concurrent
TLS/GSI/HTTPS handshake failed (one stray gsi scenario blew up ~130 unrelated
TLS tests). Fixed by `live_common.refresh_shared_pki()` — refresh **only the
proxy** (via `utils/make_proxy.py`) when the CA/hostcert are present; full-blitz
only when they are genuinely absent. **Never regenerate a shared CA while a
fleet that trusts it is running.**

### 2.7 config-time diagnostics are invisible in `nginx -t` (log level)

| Symptom | Test | Root cause | Fix |
|---|---|---|---|
| `gsi-store-memo` scenario greps `nginx -t` output for `"reusing the CA/CRL store"` → 0 matches, test fails | `test_cmd_gsi_trust_live[gsi-store-memo]` | The CA/CRL trust-store memoization **works** (`brix_gsi_build_trust_store` passes `cache_scope = cf->cycle`, so the second GSI block reuses the first's store), but the `"reusing…"` memo was logged at `NGX_LOG_NOTICE`. **nginx pins the config-parse log to WARN** — the `error_log` directive's level (`info`/`notice`/`debug`) does *not* lower it, so a config-time NOTICE never reaches `nginx -t` **or** the startup diagnostics. The test could not observe a thing that was genuinely happening. | `pki_build.c` — the reuse memo `NGX_LOG_NOTICE → NGX_LOG_WARN` (phrased as a `"NOTE:"`), matching brix's existing convention of surfacing operator-relevant GSI config notes at WARN (the CRL note at `postconfiguration.c:88`). |

**Avoid it again:** a `NGX_LOG_NOTICE` (or lower) emitted from **postconfiguration**
is invisible in `nginx -t` and in startup output — nginx fixes that phase's log
at WARN and the `error_log` level does not change it. Worker-init messages
(`init_process`) *do* reach the `error_log` at its configured level, which is why
`"endpoint ready"` shows but `"trust store built"` did not. If a config-time
diagnostic must be operator- **or test-** observable, emit it at **WARN** (as a
`"NOTE:"`), or observe it at worker-init, not config parse. **Never assert on a
config-time NOTICE via `nginx -t`.**

---

## 3. Protocol / format conformance fixes (real C changes)

These are the genuinely-deep bugs — brix diverging from the XRootD wire
protocol. Every one was settled by reading the XRootD 5.8.4 source
(`/tmp/xrootd-src/src`, container-overlay debugsource; wire spec
`/usr/include/xrootd/XProtocol/XProtocol.hh`) rather than guessing. **When in
doubt about wire behaviour, read `XrdOuc`/`XrdCl`/`XrdOfs`/`XrdXrootd` — do not
assume.**

### 3.1 opaque `;` — parameter-smuggling divergence (fixed the RIGHT way)

> **Correction (this section was initially fixed the WRONG way).** The first
> attempt *rejected* any opaque containing `;` and shipped in commit `f36eb208`.
> That was a **backwards-compat regression** and is corrected here. Kept in full
> as a cautionary example of exactly the trap this doc exists to prevent: reading
> half the XRootD source and stopping at a conclusion that "sounds secure."

- **File:** `src/protocols/root/path/opaque_validate.c` — `BRIX_OPAQUE_ALLOWED`
  (the byte-gate) **and** `brix_opaque_schema_check` (the pair splitter).
- **The real bug:** brix's *schema splitter* tokenised the opaque on `&` **or**
  `;`, while **XRootD splits on `&` ONLY** — server-side `XrdOuc/XrdOucEnv.cc`
  (`XrdOucEnv::Env` scans for `&`, a value runs `while (*vdp && *vdp != '&')`)
  and client-side `XrdCl/XrdClURL.cc` `URL::SetParams()` (`splitString(…, "&")`).
  So `k=v;other=z` is the single pair `k = "v;other=z"` to XRootD, but brix split
  it into TWO pairs — a genuine **parameter-smuggling** divergence (a client
  could hide a second `authz`/`tpc.*` key behind a `;` that XRootD keeps inside
  the value but brix honours separately).
- **The WRONG fix (regression):** removing `;` from `BRIX_OPAQUE_ALLOWED` made
  brix *reject* `k=v;other=z` outright — which **stock XRootD accepts**. It broke
  wire parity (`test_conf_pathedge::test_opaque_cat_returns_content[…;…]`) for
  zero real gain: `;` is not a wire-level command separator, the opaque is
  parsed and never handed to a shell.
- **The RIGHT fix (XRootD parity):** `;` is **ordinary value content** — so (a)
  keep `;` in `BRIX_OPAQUE_ALLOWED` (accept it, like stock), and (b) make
  `brix_opaque_schema_check` split on `&` **ONLY**. Now brix and XRootD resolve
  the *identical* set of pairs, which closes the smuggling divergence **and**
  preserves compat. The safety property lives in the *splitter*, not a
  reject-list.
- **Lesson:** when brix's parsing diverges from XRootD, the fix is almost always
  "match XRootD's parsing," not "reject the input." Rejecting a byte stock
  accepts is a compat regression by construction. Read the *whole* tokeniser
  (both the `while` scan loop AND what it treats as a value byte), not just the
  separator set.
- **Regression guard:** conformance block in `test_conf_openflags.py` —
  `test_open_opaque_semicolon_is_value_content_not_a_separator` × 6 (each asserts
  byte-for-byte parity with the stock server via `assert_same_category`, incl. a
  `authz=K;tpc.org=O` smuggling case where the `tpc.org` must stay *inside* the
  value), `test_open_opaque_ampersand_is_the_sole_separator`, and
  `test_open_opaque_semicolon_inert_across_ops` (the `;` form and the `&` form of
  a neutral opaque must land in the same category in read and create modes).

### 3.2 native TPC pull hung — `tpc.org` host string mismatch

- **File:** `src/tpc/engine/launch_prepare.c` (`tpc_build_origin_id`).
- **Symptom:** `[3012] TPC kXR_open recv failed` after a 15 s idle timeout;
  source log `ofs_TPC: … tpc grant … expired` + `open file async resp aborted;
  user gone`.
- **Cause:** the TPC source pairs the destination's `tpc.org` against the
  client-registered grant with a **raw `strcmp`** (`XrdOfs/XrdOfsTPCInfo.cc`
  `Match`). Every XRootD server is IPv6 dual-stack, so it sees an IPv4 client as
  the **IPv4-mapped** `::ffff:127.0.0.1` and reverse-resolves *that* (which fails
  → numeric `[::ffff:127.0.0.1]`). brix's TPC listener is IPv4-only, so
  `getnameinfo(127.0.0.1, NI_NAMEREQD)` **succeeds → `localhost`**. `localhost ≠
  [::ffff:127.0.0.1]` → never paired → grant expires → pull hangs.
- **Fix:** map an `AF_INET` peer into `::ffff:a.b.c.d`, reverse-resolve the
  **mapped** form (fails for loopback exactly like XRootD), fall back to the
  bracketed numeric literal — reproducing `XrdNetAddr::Name()` /
  `XrdOfsTPC::genOrg`. Strictly *more* conformant; unchanged for DNS-named hosts.
- **11/12 `test_root_tpc` now pass.** (The last, `tpc_gsi_nginx_source`, is the
  separate brix-*source* key-rendezvous path — green again as of 2026-07-20.)
- **This fix also closed the long-open "native TPC vs stock `ofs.tpc` source"
  item** (the "push-model limitation" theory was a misdiagnosis of the parked
  unmatched grant): `xrdcp --tpc only` from a stock GSI source now completes as
  a genuine server-side pull. Gate: `tests/test_tpc_gsi_stock_source_only.py`;
  resolution record: `history-security-and-credentials.md` (top).

### 3.3 open-handle stat dropped `kXR_xset` — hand-rolled retstat flags

- **File:** `src/protocols/root/read/open_resolved_file.c`
  (`brix_open_build_retstat`).
- **Symptom:** `f.stat()` on an open handle diverged by the exec bit
  (`ours=48` vs `stock=49`) for a mode-777 file.
- **Cause:** `f.stat()` returns the stat **embedded in the kXR_open response**
  (`kXR_retstat`), not a fresh `kXR_stat`. That builder hand-rolled the `flags`
  field as only `readable|writable|cachersp` — **never `kXR_xset`** (nor the
  dir/other type bits), diverging from stock's `XrdXrootdProtocol::StatGen`.
- **Fix:** compute the flags through the shared `brix_stat_flags_from_stat()`
  helper (the same `StatGen`-mirroring predicate the plain `kXR_stat` path uses).
- **Lesson:** there were **two** stat-flag encoders (retstat + `brix_make_stat_body`);
  one drifted. Single-source such wire encoders — the helper already existed.

### 3.4 s3:// origin cache-fill self-connect deadlock

- **File:** `src/protocols/root/read/open_resolved_file_staging.c`
  (`brix_open_stage_preflight`).
- **Symptom:** cache fill from an s3:// origin hung for 60 s, served 0 bytes,
  worker SIGKILLed. (Mis-labelled a "SigV4 failure" — SigV4 and the fill both
  work; 700 KB filled correctly.)
- **Cause:** the composed-cache post-fill re-open runs the read-side
  directory-reject existence probe on the **export path**, which resolves to the
  **raw remote (`sd_remote`/`sd_s3`) backend** → a **blocking SigV4 HEAD on the
  event loop**. When origin and cache node share one worker, that HEAD deadlocks
  the very worker meant to answer it.
- **Fix:** skip the directory-reject probe on a composed-cache tier
  (`brix_cache_storage_decorator(conf) != NULL`) — a just-filled object is a
  regular file and a tier serves objects, not directory listings. Legacy
  `cache_root`/posix/pblock exports keep the local, non-blocking probe.
- **Lesson (production-relevant, not just the test):** **never issue a
  synchronous remote-origin round-trip on the nginx event loop.** The offload
  spine already guards the *open* path (`brix_sd_cache_fill_needs_offload`); the
  staging preflight had no equivalent guard.

### 3.5 CVMFS whitelist parser dropped `E0`–`E9` fingerprints (the ~5% "flaky" mount)

- **File:** `shared/cvmfs/signature/whitelist.c` (`cvmfs_whitelist_parse`).
  Compiled into **both** the client (`brixMount`) **and** the nginx module
  (`config:1060`) — rebuild both.
- **Symptom:** `test_cvmfs_prefetch` failed ~5 % of the time under load with the
  trust gate returning **`-9`** on a *cryptographically valid* manifest; the
  mount then retried forever. A prior investigation proved the crypto (fingerprint
  ∈ whitelist, signature body-binding) was byte-for-byte correct, which made it
  look impossible.
- **How it was found:** instrumenting the `-9` gate (`client.c:224`) printed
  `fp_listed=0, verify_rc=0` — the signature verified fine, but the computed
  fingerprint (`E8:49:…:9F`, matching the forge oracle) was **not found in the
  whitelist**, even though it is right there on its own line.
- **Root cause:** the parser told a `E<14 digits>` **expiry** line apart from a
  **fingerprint** line by checking only that the *second* character was a digit
  (`L[1] >= '0' && L[1] <= '9'`). But a fingerprint starting `E0`–`E9` — whenever
  the signing cert's SHA-1 first byte is `0xE0`–`0xE9`, **≈ 4 % of certs** — *also*
  has a digit at `L[1]` (e.g. `E8:49:…`). Such fingerprints were **swallowed by
  the expiry branch and never stored**, so `cvmfs_whitelist_lists_fp` could not
  match them. `0xE0`–`0xE9` ≈ 4 % is exactly the observed "~5 % flake."
- **Fix:** a real expiry line is `E` followed by **14 consecutive decimal
  digits**; a fingerprint breaks that run at its `:` (index 2). Require the full
  14-digit run instead of testing `L[1]` alone.
- **Verified:** the saved reproducer `badweb4` (a deterministic `E8:` case) now
  **mounts** (was a deterministic `-9`); `test_cvmfs_prefetch` 3 passed ×3;
  `test_cvmfs_conformance_fuse_whitelist` **59 passed**.
- **Lesson:** a "flaky" failure whose rate is a clean fraction (≈ 1/16, ≈ 1/256,
  ≈ 4 %…) is almost never a race — it is a **data-dependent** bug keyed on a
  **byte-class boundary** (here, first byte `0xE0`–`0xE9`). When a disambiguation
  looks at *one* character of a variable-length token, ask what other tokens share
  that character. Reproduce deterministically by *finding* the cursed input, not
  by hammering under load.

---

## 4. Reusable helpers introduced this session

| Helper | Location | Use it for |
|---|---|---|
| `gsi_client_env(cert_dir, proxy)` | `tests/gridftp_client_env.py` | any globus-url-copy invocation as root (pins `X509_USER_CERT/KEY`). |
| `_maybe_force_nginx_root_worker(argv)` | `tests/cmdscripts/__init__.py` | auto-injects `-g "user root;"` for raw nginx server launches via `run()`. |
| `pblock_worker_own(catalog)` / `pblock_worker_readable(path)` | `tests/cmdscripts/pblock_live.py` | after a test-side `sqlite3`/keyfile write the pblock worker must own. |
| realm `flock` in `up()`/`down()` | `tests/kdc_helpers.py` | serialise a shared fixed-port daemon/DB across xdist workers. |
| `refresh_shared_pki(want_proxy=)` | `tests/cmdscripts/live_common.py` | refresh the proxy without churning the fleet's CA. |
| `_xrootd_runas_user` | `tests/server_launcher.py` | canonical `-R nobody` drop + path pre-open (mirror it for direct launches). |

---

## 5. Prevention checklist (pin this to the wall)

When adding or debugging a fast-lane test **on a root host**:

1. **Who owns the process?** master=`root`, worker=`nobody` (unless the config
   says `user root;` or the launch injects `-g "user root;"`). Stock xrootd must
   be `-R nobody`.
2. **Does a `nobody` worker touch a `root`-owned path?** If yes, chmod/chown it.
   `server_launcher` only handles `data_root` — everything else is on you.
   Remember the worker no longer has `CAP_DAC_OVERRIDE`.
3. **Any secret the worker reads** (keytab, host key, GSI key, S3 secret) must be
   **readable by the worker account**, not `0600 root`.
4. **Grid client tools run as root have credential quirks** — set
   `X509_USER_CERT`+`X509_USER_KEY`, not just `X509_USER_PROXY`.
5. **Never regenerate a shared CA under a running fleet.** Refresh the proxy
   only.
6. **A shared fixed-port daemon / realm / DB is unsafe under `--dist load`.**
   File-lock it; `xdist_group` won't help.
7. **Suspected failure? Re-run it in isolation first.** ~7 of the final 31 were
   pure parallel-contention flakes.
8. **Wire behaviour question? Read the XRootD source** at `/tmp/xrootd-src/src`
   (`XrdOuc`/`XrdCl`/`XrdOfs`/`XrdXrootd`) and the spec at
   `/usr/include/xrootd/XProtocol/XProtocol.hh`. Then add a differential/
   conformance test so the answer is pinned forever.
9. **Never issue a blocking remote/origin round-trip on the event loop** — offload
   it. A "hang + SIGKILL" is almost always this.
10. **A silent empty/0-byte transfer** on a self-hosted origin+node topology is a
    self-connect deadlock until proven otherwise.
11. **A config-time `NOTICE` is invisible in `nginx -t`** (nginx fixes that phase
    to WARN; `error_log` level does not change it). Emit operator/test-visible
    config diagnostics at **WARN** as a `"NOTE:"`, or observe at worker-init.
    Never assert on a config-time NOTICE via `nginx -t`.
12. **A "flake" with a clean fractional rate (≈ 1/16, ≈ 4 %, …) is a
    data-dependent bug, not a race** — usually a parser keyed on a byte-class
    boundary. Find the cursed input and reproduce deterministically; don't hammer
    under load. When a disambiguation reads *one* char of a variable-length token,
    ask which other tokens share it.
13. **When a widely-#included source gains a new dependency, sweep every inline
    build recipe.** `brixcvmfs.c` pulling in `net/cpool.h` (+ `cvmfs_walk_*`)
    broke test harnesses that hand-roll a `gcc` line; they need
    `-Iclient/lib -Isrc -DXRDPROTO_NO_NGX`, `shared/cvmfs/walk/walk.c`, and the
    `client/libbrix.a` + `shared/xrdproto/libxrdproto.a` archives (mirror the
    client Makefile). Prefer a shared build helper over per-file copies.

---

## 5.5 Round 6 (2026-07-20, single-pass — retry ladder removed): the cross-worker shared-state sweep

The operator retry ladder was deleted on request (`operator_runtime._pytest_lane`
is now one `pytest` invocation; a first-run failure is final). The first
single-pass run surfaced **21 failures / 7604 passed** — and after root-causing,
**every diagnosed failure was one bug class: shared mutable state raced across
pytest-xdist workers.** The load-flakes the retry pass used to launder were
never noise; they were real isolation bugs in the test infrastructure. Fix
catalogue:

- **Recursive glob into a live FUSE mount** (3 tests: `test_xfer_ledger` ×2,
  `test_s3_checksums` stage-audit). `glob(TEST_ROOT/**/xfer_audit.log,
  recursive=True)` walked into a concurrent live-test's CDN-backed cvmfs bench
  mount under `TEST_ROOT/tmp` and hung until the 30s timeout. Audit sinks only
  ever live at `TEST_ROOT/logs/` and `TEST_ROOT/registry/*/logs/` — the globs
  are now those two patterns, with a comment banning `TEST_ROOT/**` forever.
- **Conformance port-tile claim race** (8 tests: `test_cvmfs_qos` ×5,
  `test_cvmfs_transcode` ×3). `cvmfs/conformance_common._tile_free` probed
  tile ports with transient binds — a TOCTOU window 12 workers raced, so two
  workers settled on the SAME tile → port collisions → `ConnectionReset`
  storms. Now `_claim_tile()` binds and **holds** a per-tile lock port
  (`_TILE-1` offset, outside every block span) for the process lifetime —
  claims are atomic. Pinned by `tests/test_cvmfs_conformance_tiles.py`.
- **Shared interop data trees** (`test_conf_rename_b` ×2,
  `test_conf_client2` stat CTime parity). `start_pair()` was already
  per-worker for servers/ports but both workers still exported the SAME
  `data-interop-{our,off}` trees: fixed-name working files (`/rn_chain_a.bin`)
  raced, and another worker's `harmonize_perms`/`chown_stock` re-run bumped
  ctime mid-parity-check (chmod/chown bump ctime even when values are
  unchanged). Fixes: data roots are now keyed by `PYTEST_XDIST_WORKER`
  (`data-interop-our-gw3`), and the perm/owner harmonizers skip files already
  at target. Pinned by `tests/test_interop_lib_isolation.py`.

  > **SUPERSEDED (round 7, §5.6):** the per-worker data-root keying was WRONG
  > and was reverted. `data-interop-{our,off}` are a **fleet contract** — the
  > standing interop pair and six conf modules hard-wire those exact paths, so
  > suffixing desynced seeding from serving and produced 184 kXR 3011 failures.
  > The idempotent harmonizers (the actual fix for the ctime race) remain.
- **Enumerating the shared fleet root** (`test_cli_aliases` tree/ls/du alias
  equivalence). Two invocations of the same listing can straddle another
  worker's file creation. The four enumeration tests now run over a private
  server-side `cli_alias_<uuid>` directory seeded by a module fixture.
- **One JWKS file, four mutating tests** (`test_token_jwks_refresh`). The
  class rotates/corrupts/restores the dedicated server's single JWKS assuming
  strict in-order execution; `--dist load` scatters the class across workers
  (seen live: a concurrent worker's restore made the old key valid again mid
  rejection-test). Each test now takes a cross-process `flock`
  (`_jwks_mutation_lock`) and re-baselines the key material itself —
  order- and worker-independent.
- **One per-IP rate bucket, whole-module hammering**
  (`test_xrdhttp_wait_retry_digest_range` ×3). The xrdhttp-digest server's
  2r/s per-IP bucket is a single budget for every worker (all arrive from
  127.0.0.1); concurrent tests drained it continuously → all-429. An autouse
  cross-process flock (`_rate_budget_mutex`) gives each test the bucket to
  itself.
- **C-harness compile under lane load** (`test_c_regression_units
  [delegation_store]`). ~10s compile+run alone; under 12-way CPU contention it
  blew the suite-wide 30s signal timeout. Marked `@pytest.mark.timeout(120)`.
- **Watch item (unreproduced):** `test_xrootd.py::TestGSI::test_gsi_anon_same_data`
  failed once with `kXR_IOError (3007) Illegal seek` (ESPIPE) reading
  `/random.bin` on the anon endpoint. No ESPIPE emit site exists on the
  sendfile path; suspects are an fd-recycle race feeding `pread` a
  non-seekable fd, or a stale `errno` strerror'd in
  `read_finish_buffered()` when `nread<0` arrives with `io_errno==0`.
  200 concurrent 5 MB reads did not reproduce it. If it recurs, instrument
  `read_sync_fill`/AIO done-path to log `job.io_errno` vs `errno`.

**The recurring shape** (pin next to §5's checklist): *any* fixture resource a
test mutates — a data tree, a key file, a rate budget, a port range, a listing
being compared across two calls — must be either (a) keyed per-worker
(`PYTEST_XDIST_WORKER` in path/port math), or (b) serialized with a
cross-process `flock` **plus per-test re-baselining** so order never matters,
or (c) replaced with a test-private namespace (`uuid` dir). Sleeping "long
enough" is never one of the options.

Infra note for whoever runs the suites by hand: never run two pytest sessions
concurrently against the same `/tmp/xrd-test` — one session's teardown wipes
the shared registry/basetemp under the other (symptoms: `INTERNALERROR: failed
to make path absolute`, fleet bind-storms from orphaned masterless nginx
workers). Recovery: `pkill -9 nginx`, then `manage_test_servers start-all`.

---

## 5.6 Round 7 (2026-07-20): 234 failures decomposed to three causes — two self-inflicted-or-external, one instrumented

Round 7 (first full lane after the §5.5 sweep) came back **207 failed / 27
errors** — alarming, but the decomposition was clean:

- **184 conf-suite failures = the §5.5 per-worker interop keying, i.e. our own
  previous fix.** Suffixing `FLEET_OUR_DATA`/`FLEET_OFF_DATA` with the xdist
  worker id made each worker seed `data-interop-our-gw3/…` while the standing
  fleet pair (whose `nginx_interop.conf` hard-codes
  `${TEST_ROOT}/data-interop-our`) and the six raw-wire conf modules
  (openflags, sessions, sessions_b, dirlist, prepfattr, prepfattr_b — fixed
  `FLEET_OUR_PORT`/`FLEET_OFF_PORT`) kept serving the unsuffixed trees →
  every open answered kXR 3011. **Reverted** to the unsuffixed paths, now
  documented in `official_interop_lib.py` as a FLEET CONTRACT with the list of
  hard-wired consumers; cross-worker safety instead rests on the machinery that
  already existed: `_seed_file` create-once (atomic tmp+replace, skip-if-
  present), the age-gated stale-file wipe, per-worker `lroot_<tag>` listing
  dirs, and the §5.5 idempotent harmonizers. Re-pinned by the rewritten
  `tests/test_interop_lib_isolation.py`. Lesson: **a "shared mutable state"
  diagnosis does not automatically license per-worker keying — first check
  whether the path is a contract some fixed server config also encodes.**
- **~50 failures/errors (27 errors + ~23 failures across credential_dir,
  fleet_ports, xrdhttp, https_webdav, cache_write_through, frm, dropin,
  manager_mode, brix_fault_proxy) = the concurrent-build EACCES storm.**
  `exec /tmp/nginx-1.28.3/objs/nginx` → `EACCES` on every mid-lane launch;
  the binary's mtime proved another session's `make` relinked it during the
  run. Cascade anatomy: `ldd` against the half-written binary silently
  dropped the krb5 detection → krb5-kdc/krb5 specs vanished from the fleet
  registry → dependent servers never booted → connection-refused walls. All
  ~50 pass in a quiet window. **Durable shield:** every test-side nginx exec
  now routes through `freeze_nginx()` — `server_launcher._nginx_bin()` (used
  by both `launch_detached_daemon` and `_nginx()`) and
  `fleet_specs._nginx_has_krb5()` take a per-process validated frozen copy
  (`/tmp/brix-live-nginx-<pid>/`, `-v`-checked, retried, atexit-cleaned) so an
  external relink can no longer corrupt a running lane. Pinned by 4 new tests
  in `tests/test_live_common.py` (incl. "never cache a broken binary").
- **1 = the §5.5 GSI watch item, recurred with a NEW errno.**
  `test_gsi_tls` 5 MB copy failed `kXR_IOError (3007) Bad file descriptor`
  (round 6 was ESPIPE) — pattern-matches an fd closed/recycled under an
  in-flight windowed read. Not reproduced on rerun. **Instrumented instead of
  guessed:** new `brix_fd_kind()` (`src/core/aio/fd_kind.c`, C-unit
  `fd_kind` in the regression harness) + `brix_read_io_failure_log()` now fire
  at all three buffered-read error sites (`brix_read_window_emit`,
  `brix_read_aio_done`, `read_finish_buffered`), logging
  `fd/off/len/io_errno/strerror/fd_kind` — the next occurrence self-reports
  whether the fd is `stale`/`socket`/`fifo` (recycle race) or `regular` with
  `io_errno=0` (stale-errno strerror). Watch item stays OPEN until it recurs
  with forensics attached.

---

## 5.7 Round 8 (2026-07-20): the shield itself became the bug — 110 red from one wiped directory

Round 8 came back **36 failed / 74 errors / 7532 passed** — and ~108 of the
110 were ONE cause: **the round-7 frozen-binary shield put its copy inside the
blast radius it was meant to escape.** `freeze_nginx()` used
`tempfile.gettempdir()`, which honours the lane's `TMPDIR=/tmp/xrd-test/tmp` —
the same tree pytest's basetemp garbage-rotation `rm -rf`'s mid-session. The
frozen copy vanished under the running lane and every subsequent
LifecycleHarness nginx exec failed. Two stacked fixes:

- **`_FREEZE_ROOT = Path("/tmp")`** (module constant in
  `cmdscripts/live_common.py`) — the freeze target is literal `/tmp`, never
  derived from `TMPDIR`. Tests patch the constant to a private root; without
  that they ETXTBSY against (and would clobber) the pytest process's own real
  frozen binary.
- **`RegistryCommandFailure` un-frozen.** It was `@dataclass(frozen=True)` on
  a `RuntimeError` — Python assigns `exc.__traceback__` on re-raise
  (contextlib `__exit__`, `raise … from`), a frozen dataclass blocks that,
  and every real launch failure was MASKED by
  `dataclasses.FrozenInstanceError`. Exception dataclasses must never be
  frozen.

Both pinned in `tests/test_live_common.py` (freeze-root default, TMPDIR
independence, re-raise round-trip). Lesson pair: **a durable artifact must
live outside every rotated/It-gets-wiped tree (TMPDIR, basetemp, TEST_ROOT)**,
and **never make an exception class immutable**.

The remaining 2 were the GSI watch item again — `test_gsi_tls` 5 MB reads,
back to ESPIPE (`[3007] Illegal seek`), same worker, back-to-back, this time
on the GSI+TLS server. The instrumented forensic line was live in the binary,
but the lane's session teardown (`TEST_OWN_FLEET=1` → `rmtree(TEST_ROOT)`)
destroyed the server logs before they were read. 120 quiet-fleet reruns did
not reproduce — load-coupled. Round 9 runs with a sidecar watcher that
continuously copies the GSI servers' logs out of `TEST_ROOT` so the next
occurrence's `fd_kind=` line survives teardown.

---

## 5.8 Round 9 (2026-07-20): the ESPIPE/EBADF ghost caught — windowed pump served the PREVIOUS handle's storage object

Round 9: **5 failed / 0 errors / 7632 passed.** Three of the five were one
real C bug — the load-coupled `[3007]` read failure stalked since round 6 —
finally root-caused by running the main nginx as strace's child and
correlating fd lifecycles across the worker and thread-pool traces.

**The bug.** `brix_read_window_pump` (src/core/aio/reads.c) shares ONE
reusable AIO task struct per session with the single-shot buffered path
(`read_post_aio`, read_buffered.c). The buffered path sets `t->csi`/`t->obj`
per post; the pump set neither. The VFS worker routes the pread through
`t->obj`'s driver whenever `obj.driver != NULL` — and the driver object
carries **its own fd**, so `t->fd` (which the pump DID set correctly) is
ignored. Every windowed read after a buffered read on the same connection
therefore executed against the *previous* read handle's storage object:

- previous fd still open on the same file → correct bytes by luck;
- fd number recycled to another file → **silently serves the wrong file**
  (cross-connection data bleed — the integrity/confidentiality failure mode);
- fd number recycled to an O_WRONLY staging temp (`.xrdresume.*.part`) or
  closed → `pread` EBADF → `kXR_IOError` on the wire (the observed 3007).

`t->csi` was likewise stale — a dangling pointer to the closed handle's freed
CSI record (the trace showed a `openat("<heap garbage>.cinfo")` probe from a
thread: a live UAF, not just a wrong fd).

**Why it hid for so long.** Single-connection runs are immune: the fresh open
almost always gets the just-freed lowest fd number back, so the stale obj
points at the right file. It needs ≥2 concurrent connections churning
open/close on one worker so another connection's open (data file or
upload-resume temp) grabs the number in the gap. 475 single-connection cycles
clean; 4-6 concurrent repro processes failed within 1-3 cycles. The
"windowed read failed fd=N" forensic line logged `ctx->rd.win_fd` — the
*fresh* fd — while the syscall used the stale obj's fd, which sent the
investigation down a false "fd closed under the handle" path until the strace
showed the executed fd differing from the logged one.

**Fix** (reads.c, both pump paths): rebind `t->csi`/`t->obj` (and the inline
fallback's `job.csi`/`job` obj) from `ctx->files[ctx->rd.win_idx]` on every
window post. pgread/readv/qcksum already rebound per post — the pump was the
sole offender. Verified: 6 concurrent repro processes × 240 s with per-process
payloads and full content verification = ~1,400 cycles clean (pre-fix: dead in
1-3 cycles); regression trio in
`tests/test_windowed_read_handle_binding.py` (concurrent churn byte-exact ·
clean-error + connection survival · cross-file bleed security-neg).

**Lessons.**
- A shared/reusable task struct is a *union of every poster's fields*: any
  poster that skips a field inherits the previous poster's value. When adding
  a field (here: the phase-55 driver seam's `obj`), grep EVERY site that
  posts the struct, not just the one you're extending.
- When a forensic log field and the syscall trace disagree, the log is
  printing different state than the executor consumed — that disagreement IS
  the clue, not noise.
- strace filters must include `openat2` in this codebase (confined VFS opens
  are invisible to plain `openat` filters), and `preadv2` if warm-probe reads
  matter.
- Identical payloads in a repro mask wrong-file reads; always salt per
  connection and verify content, not just status.

The remaining 2 round-9 failures were test-side and are now FIXED (verified
green): `test_conf_sequences::test_write_sync_advances_mtime` (the stale-file
janitor wiped the backdated-mtime fixture — backdate removed, integer-second
sleep suffices) and
`test_brix_fault_proxy::test_fail_nth_fails_only_that_connection` (`conns`
read before the proxy had accepted+counted `_wait_port`'s probe connection —
added a settle loop).

---

## 5.9 Round 10 (2026-07-20): 18F/10E — the host clock was jumping backwards every 27 s

Round 10 (`operator_runtime suite --fast`, 12 workers, 7822 items, 27 min):
**18 failed, 10 errors, 7624 passed**. Worse than round 9 — but the whole
delta decomposed into TWO environmental pathologies plus THREE real test/config
defects, all now fixed or root-caused:

### Environmental pathology 1 — the wall clock steps BACKWARDS ~2.7 s every ~27 s

Proof chain:
- `test_rate_limit_throttles` asserted `elapsed > 0.8` and measured
  **`-0.77 s`** — negative wall-clock elapsed is not a flake, it is a stepped
  clock.
- `journalctl`: `systemd-journald: Time jumped backwards, rotating.` every
  27–28 s continuously (since at least Jul 19 22:20).
- Direct measurement (wall-vs-monotonic offset sampling): steps of −2.7 s,
  −0.8 s, −1.9 s inside one 35 s window; **net −5.4 s of wall time lost in
  35 s** — the guest clock gains ~10 % and Hyper-V host sync yanks it back.
- Cause: clocksource is `tsc` under the custom WSL2 RT kernel
  (6.18.6-WSL2-RT-STABLE+) with bad calibration. Fix (needs root, reverts on
  reboot):
  `echo hyperv_clocksource_tsc_page > /sys/devices/system/clocksource/clocksource0/current_clocksource`

Casualties (all re-run green in isolation, 7/7): negative-elapsed assert
(`test_brix_fault_proxy::test_rate_limit_throttles`), token freshness both
directions (`test_token_security` expired token accepted 201 — server clock
stepped back past `exp`; `test_cvmfs_qos` fresh token 401 — `iat` landed in
the future), GSI auth (`test_tpc_delegation`, `test_cmd_pblock_live
[pblock-meta-gsi]` — cert/token validity windows), and the **janitor
amplifier**: after a backward step, files written post-step have
`mtime < _IMPORT_TIME` of every worker, so `_wipe_stale_working_files`
deletes ACTIVE working files (`test_native_xrdcp_xrdfs_b::test_m9_mv`
NotFound mid-test, `test_tape_rest` locality NONE = file gone,
`test_conf_rename` stock-side src gone).

### Environmental pathology 2 — I/O stall window ~15:50 (Ceph demo-cluster startup)

The opt-out Ceph docker lab boots its demo cluster mid-run (OSD mkfs = heavy
fsync on WSL2). During a ~2 min window every blocking syscall crawled: gw3's
two client-tools `make` fixtures exceeded the 30 s pytest timeout (krb5 1 +
sss module fixture cached-error replay ×9 = the 10 ERRORs; the make is a
1.4 s no-op normally and the binaries were never rebuilt), gw11's `cc`
(`test_cvmfs_driver_units`), gw9's 60 s xrdcp (`test_ha_failover`), and one
TLS handshake severed mid-stall (`test_https_webdav_token_status_codes`
SSLEOFError). All re-run green in isolation (12/12).

### Real defects fixed this round (all verified green)

1. **Admin API per-IP rate limit vs the suite itself** (7 failures:
   `test_ipv6_cms_redirect` TestAdminBracketStrip ×6 +
   `test_ipv6_admin_ratelimit_metrics`, all `429 rate_limited`). The
   limiter (landed 2026-07-20, on by default, 120 writes/min keyed
   `admw:<ip>`) shares ONE bucket across all 12 xdist workers because every
   test client is `::1`/`127.0.0.1`. Fix: `brix_admin_rate_limit off;` in
   every fleet template's dashboard location (12 templates / 19 blocks) —
   EXCEPT `nginx_admin_ratelimit.conf`, whose `{RL_LINE}` placeholder is the
   limiter test's own knob (`test_admin_rate_limit.py` still green).
   Lesson: any new on-by-default per-IP guard will throttle a same-host test
   fleet; the fleet templates must opt out explicitly on day one.
2. **`test_conf_rename::test_rename_preserves_mtime`** backdated its fixture
   to 2020 in the shared interop root → janitor food (same class as the
   round-9 `test_write_sync_advances_mtime`). Fix: distinctive FUTURE stamp
   (`st_mtime + 7200`) — mtime-preservation is still proven, and future
   stamps are janitor-immune. Sweep confirmed no other test backdates
   mtimes inside `FLEET_OUR_DATA`/`FLEET_OFF_DATA`.
3. **`test_ha_failover` counted TIME_WAIT as a "handle leak"** (flaked to
   `1 orphaned` in isolation). TIME_WAIT holds no fd — it is kernel-only
   state lingering ~60 s whenever our side closes first, so ANY earlier test
   on those shared ports trips it. Fix: count CLOSE_WAIT only (the state
   where the peer closed and our process still holds the descriptor). Full
   file green.

**Round-11 precondition:** switch the clocksource (command above) before the
next full run — with the clock stepping backwards every 27 s, timing/token/
mtime-sensitive tests fail probabilistically regardless of code health.

---

## 6. Remaining open items (not fixed — real, documented)

- **`brixcvmfs_live` 3** (CVMFS leg of the former `test_cmd_*` cluster): still
  unverified, worth a focused pass.

**Fixed after the first draft of this doc** (kept here as a pointer):

- ~~`test_cmd_*` GSI/pblock live-scenario cluster (`pblock_live` 5,
  `tpc_fwd_live` 3, `fwd_matrix_live` 2)~~ — re-verified 2026-07-20: all 13
  non-CVMFS scenarios now exit 0 standalone (`python3 -m cmdscripts.pblock_live
  <s>` etc.); the earlier failures were cured by the §2.2 worker-ownership
  fixes (`pblock_worker_own`), the §2.4 `-g "user root;"` injection, and the
  TPC `tpc.org` host-string fix (f36eb208). Pytest wrappers confirmed green
  the same day: 15 passed, 1 xpassed (`fwd-brix-brix` xfail now xpasses).
- ~~Cosmetic: the s3 origin logs `op:"xattr"` for a served GET
  (`status:"other"`)~~ — fixed 2026-07-20: the served-GET usermeta/tagging
  probes hit `ENODATA` on objects with no optional attrs, and
  `brix_vfs_xattr_observe_count` (`src/fs/vfs/vfs_xattr.c`) booked that
  expected-absent probe as a failed op. It now observes ENODATA as a clean
  zero-byte `status:"ok"` (caller still sees `-1`/`ENODATA`; real errors
  still book as failures). Tests: `tests/test_metrics_vfs_ops.py` (3 new,
  7/7 green).
FRM stage ownership (FINDING-FRM-1) — `brix_stage_request_owner_check`
(`src/fs/xfer/stage_request_registry_query.c`) now gates DELETE and
body-less POST `/cancel` on the Tape REST API (403 for a foreign principal,
fail-open only for anonymous callers / owner-less records / absent reqids — no
enumeration oracle); regression suite `tests/test_frm_owner.py` (5 tests,
re-verified green 2026-07-20). Also:
`tpc_gsi_nginx_source` (the brix-*source* GSI key-rendezvous path, distinct from
the §3.2 destination fix) — green again as of 2026-07-20 (§3.2). Also: the
`shutdown_resume` upload-stage perms (§2.2), the `gsi-store-memo` observability
(§2.7), and the `cvmfs` trust-gate `-9` whitelist-parser bug (§3.5) were all
subsequently root-caused and fixed — see those sections. The `cvmfs` conformance
build-recipe drift they exposed was swept: only `test_cvmfs_conformance_fuse_whitelist.py`
actually needed the recipe update (`fuse_trust` was already patched; every other
`fuse_*`/`pin_root`/`prefetch`/`prewarm` suite runs the prebuilt `brixMount` and
needs no inline compile). Full cvmfs conformance-fuse surface is green
(~540 tests).
