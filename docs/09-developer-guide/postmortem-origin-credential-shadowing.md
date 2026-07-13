# Postmortem: "BriX cannot write through to the XRootD origin" (2026-07-08/09)

> A hyper-detailed account of a full-day debugging session that consumed ~17
> speculative RPM releases (`1.1.1-6` … `1.1.1-18`), began with a completely
> wrong theory (io_uring), passed through three real-but-unrelated segfaults,
> several dead-ends (TLS, cert mismatch, netem), and ended at a **five-bug
> chain** whose true blocker was a *silently shadowed duplicate config block*.
> This document is deliberately exhaustive so the next person spends minutes,
> not a day.

**Status:** RESOLVED (verified: a 100 MiB `xrdcp` lands byte-exact on the origin).
**Severity:** High — a fully configured cache/stage node could not write to its
origin; all client writes stranded in the local stage, the origin stayed empty.
**Primary author of the mess:** the debugging approach (see §12, Lessons).

---

## Table of contents

1. [Environment and topology](#1-environment-and-topology)
2. [The report, and the client-side illusion](#2-the-report-and-the-client-side-illusion)
3. [Phase 1 — the io_uring misdiagnosis (`-6`…`-10`)](#3-phase-1--the-io_uring-misdiagnosis)
4. [The three segfaults](#4-the-three-segfaults)
5. [The dead-ends](#5-the-dead-ends-things-that-looked-like-the-bug-but-were-not)
6. [The turning point](#6-the-turning-point)
7. [The five-bug chain, in forensic detail](#7-the-five-bug-chain-in-forensic-detail)
8. [The final fix and verification](#8-the-final-fix-and-verification)
9. [Every code change](#9-every-code-change-reference)
10. [The diagnostics we added](#10-the-diagnostics-we-added-with-sample-output)
11. [Regression tests](#11-regression-tests)
12. [Lessons](#12-lessons-the-durable-ones)
13. [Release timeline](#13-release-timeline)
14. [Appendix — raw evidence](#14-appendix--raw-evidence)

---

## 1. Environment and topology

`xrd1.edi.scotgrid.ac.uk`, AlmaLinux 9, kernel `6.15.4-1.el9.elrepo.x86_64`,
BriX installed as a **dynamic nginx module** from the RPM (`nginx-mod-brix-cache`,
loaded via `load_module`). This "dynamic module" detail turns out to be
load-bearing (Bug C).

Intended data flow: **client → BriX front (GSI) → local read cache + write stage
→ flush to a stock XRootD origin**.

```
                         BriX front (nginx + brix .so)             XRootD origin
  xrdcp (lhcb proxy) --> :1095 root:// (GSI)  --.                  :11094 root:// (GSI)
                         :443  davs:// (GSI)    |  cache /data/brix/cache
                         :80   http->https      |  stage /data/brix/staging  --> /data/xrootd
                                                '--- sd_xroot (GSI, host cert) ---'
```

Front config (the relevant parts, `/etc/nginx/nginx.conf`):

```nginx
stream {
    brix_credential origin {                     # line 32-36 (STREAM context)
        x509_cert /etc/grid-security/brix/hostcert.pem;
        x509_key  /etc/grid-security/brix/hostkey.pem;
        ca_dir    /etc/grid-security/certificates;
    }
    server {                                     # root:// on 1095
        brix_root on;  brix_export /data/brix/export;
        brix_auth gsi; brix_certificate /etc/grid-security/brix/hostcert.pem; ...
        brix_storage_backend    root://xrd1.edi.scotgrid.ac.uk:11094;
        brix_storage_credential origin;
        brix_cache_store        posix:/data/brix/cache;   brix_cache_export /;
        brix_stage on; brix_stage_store posix:/data/brix/staging; brix_stage_flush async;
    }
}
```

Crucially — and invisibly at the time — there were **two more** `brix_credential
origin` blocks (in `http{}` and in `conf.d/brix-cache.conf`) carrying
`x509_cert`+`x509_key`. That is Bug D.

Origin config (`/etc/xrootd/xrootd-brix.cfg`): `xrd.tls …`, `sec.protocol …
gsi …`, `sec.protbind * only gsi`, `all.export / writable`, gridmap trust for
the BriX host DN.

---

## 2. The report, and the client-side illusion

> *"the io_uring transfer stalls at ~8MB. this is required to be working even if
> it's only opt-in for now."*

Every reproduction looked like this:

```
$ xrdcp -f /tmp/t100.bin root://xrd1.edi.scotgrid.ac.uk:1095//via-brix.bin
[8MB/100MB][  8%][====>                          ][4MB/s]
Run: [ERROR] Server responded with an error: [3011] file not found (destination)
```

Two facts made "8 MiB stall" irresistible and wrong:

* `8388608` = `8 MiB` is **`queue_depth(256) × 32 KiB`** (io_uring ring depth ×
  a plausible chunk) — *and* **`pipeline_depth(8) × 1 MiB`** (xrdcp's default
  write chunk) — *and* xrdcp's own client-side buffer size. Three unrelated
  quantities collide at 8 MiB. It is a coincidence machine.
* The progress bar showed `[8MB/100MB]` then failed. That reads as "wrote 8 MiB
  then stuck." **It is not.** `xrdcp` buffers up to ~8 MiB locally and renders
  progress as it *queues*, before the server's error propagates back. The server
  had already rejected the operation; the client just hadn't noticed yet.

The evidence that should have killed the stall theory on day one (but did not,
for many hours):

```
# access log — the OPEN is rejected INSTANTLY (0ms), session dies at 113ms:
[..] SESS 2accf.. ATTEMPT path="/data/brix/export/x.bin" mode=write
[..] SESS 2accf.. RESULT fail path="/data/brix/export/x.bin" mode=write err="not-found"
[..] "OPEN /data/brix/export/x.bin wr" ERR 0 0ms "file\x20not\x20found"
[..] SESS 2accf.. END reason=client-disconnect dur=113
```

`dur=113ms`, `OPEN … 0ms` = a **fast failure**, not a hang. A hang has a live
socket and a busy or blocked worker. We had neither.

---

## 3. Phase 1 — the io_uring misdiagnosis

Believing it was the Phase-44 io_uring disk backend, we shipped a run of fixes,
each with a plausible mechanism, each wrong or unrelated:

### `-6`/`-7`: "the eventfd completion is never delivered"

Hypothesis: the registered-eventfd completion reaper never fires on this kernel,
so after one ring-full (256 in-flight) the worker wedges. We added an eventfd
`poll()` self-test at startup and an auto→pool fallback.

**Disproof:** a standalone probe (`tools/diag/uring_write_probe.c`, T1–T5) passed
*all* io_uring primitives on the box — submit, eventfd delivery, writes,
completions. The user, correctly exasperated:

> *"are. you. retarded. [probe all pass] this is looking more and more like an
> internal path handling issue than a fucking kernel bug."*

### `-8`: "completions drop under load; batch self-test"

Hypothesis: a single NOP completes but 256 under contention drop. We made the
self-test submit `queue_depth` NOPs and require all to drain.

**Disproof:** the batch self-test *passed* on xrd1 too, and writes still failed.

### `-9`: default `brix_io_uring auto → off`

Correct hardening (io_uring gave zero benefit for this workload — staged writes
are driver-backed and go through the thread pool regardless), and the honest
answer to "fix it without io_uring." **Kept.** But not the bug: the failure
persisted with io_uring off (it merely moved from the open to the async flush).

### `-10`: "recv/send pipeline lost-wakeup"

The decisive io_uring diagnostic (`tools/diag/uring_stall_diag.sh`) finally
proved the ring was **doing nothing**. During the "stall", captured `fdinfo` on
every worker's io_uring fd:

```
io_uring fd 26 fdinfo:
  SqHead: 257  SqTail: 257
  CqHead: 257  CqTail: 257
```

`257` is exactly the startup self-test count (256 NOPs + 1 eventfd poll). The
ring's submission and completion cursors **never moved for the transfer** — the
writes went through the thread pool, not io_uring. Every worker was idle:

```
--- worker 137292 : state=S cpu=0.0% wchan=ep_poll ---
  Thread 1 (LWP 137292): epoll_wait() ... ngx_epoll_process_events ...
  Threads 2-9 (pool): pthread_cond_wait ... ngx_thread_pool_cycle   (idle)
staged .part files:
  /data/brix/export/via-brix.bin.xrdresume.<hash>.part  8388608 bytes  (frozen)
```

**The crucial inference we drew (correctly) but applied to the wrong bug:** all
workers idle in `epoll_wait` ⇒ *zero posted events pending* ⇒ if there were a
parked write event it would have run before going idle. So we hypothesised a
lost wakeup in the recv→send pipeline (`brix_schedule_write_resume` only posting
the write event when `wev->ready`), and added `brix_ensure_write_event()` to post
unconditionally on a park. This is a **legitimate edge-triggered-epoll
hardening** and was kept — but it fixed a hang that did not exist here. `-10`
deployed and still failed at 8 MiB.

We could never reproduce the "stall" locally: WSL2 loopback drains acks
instantly, so the pipeline never saturates. We tried, at length:

* A raw `kXR_write` flood client (32 KiB then 1 MiB chunks, `SO_RCVBUF=4096` to
  simulate a slow remote reader) — it never reproduced the server-side wedge.
* `netem` in a `unshare -rn` user+net namespace (`tc qdisc add dev lo root
  netem delay 30ms`) — netem worked (63 ms RTT confirmed by ping) but the
  XRootD client would not complete a handshake over the delayed loopback in the
  sandbox. Abandoned.

---

## 4. The three segfaults

All real, all pre-existing, none the reported bug. Fixed in passing.

### `1.1.1-5` — tier-store instances allocated from the transient config pool

`brix_sd_instance_create()` allocated tier store instances from
`ngx_cycle->pool`. At **config parse** that is the *transient* init cycle, which
nginx destroys after startup. The store instances dangled; the first request
through a composed cache/stage tier dereferenced freed memory
(`cs->store->driver` garbage in `cstore_make_parents`) → SIGSEGV. This is why
the user saw crashes on xrd1's staged writes and on slice tests.

**Fix:** a private, process-lifetime registry pool for SD instances; the
signature dropped its `ngx_pool_t` argument (8 call sites).
**Lesson embedded:** never use `ngx_cycle->pool` for process-lifetime singletons
that may be built at config-parse.

### `-7`/`-8` — io_uring teardown use-after-free

A late CQE, arriving after a client disconnected, posted `&task->event` — an
`ngx_event_t` living inside the *freed* connection pool — into
`ngx_posted_events`. When the loop reached it, `handler` was garbage. Core
inspection (no module symbols on ngx-core frames, so register-level):

```
r12 = <ev addr>;  ngx_event_t layout: data@0, bitfields@8, available@12, handler@16
(gdb) info symbol *(unsigned long*)(ev+0x10)   # not a code pointer → freed/reused
```

**Fix:** io_uring slots carry `owner = c`; `brix_uring_orphan_owner(c)` (hooked
via `ngx_pool_cleanup_add` on `c->pool`, so it fires on *every* teardown, not
just the graceful `brix_on_disconnect` path — the latter is bypassed on RST) marks
in-flight slots orphaned; the reaper drops orphaned CQEs. `resume.c`'s
resume-fail path honours the deferred-teardown guard.

---

## 5. The dead-ends (things that looked like the bug but were not)

* **`.part` in the export, not the stage dir.** The upload-resume `.part` lands
  adjacent to the destination (`/data/brix/export/*.xrdresume.<hash>.part`), not
  in `/data/brix/staging`. Looked like a staging bug; was not.
* **"cert/key mismatch."** A direct `xrdcp` with the host cert as an
  `X509_USER_CERT` printed `TLS: ossl_x509_check_private_key: key values
  mismatch`. Chased as a broken host pair. **Red herring:** the moduli all
  matched — `hostcert.pem`, `hostkey.pem`, and `brix/hostkey.pem` were all
  `MD5=ddc46a888a44915279d8cf329aa9a4e4`. The "mismatch" was an xrdcp client-side
  quirk from handing it a raw EEC where it wanted a proxy.
* **"the origin requires gotoTLS and BriX only does TLS-from-start."** The origin
  has `xrd.tls` and sends `kXR_gotoTLS`; `origin_connection.c:166` does
  `SSL_connect` at connect time (TLS-from-start), not a mid-session upgrade.
  Plausible! **Disproved** by `XRD_LOGLEVEL=Dump xrdcp … root://…:11094`:

  ```
  Sending out kXR_login request, username: root ...
  Got a kXR_ok response to request kXR_open (file: /hosttest.bin ...)
  ```

  xrdcp logged in as `root` and opened the file with **no `kXR_auth`, no TLS, no
  GSI exchange at all** — the origin let a localhost `root` in unauthenticated.
  So TLS was not mandatory on that path; the gotoTLS theory was wrong. (BriX logs
  in as `xrd`, which *is* challenged for GSI — hence the later real error.)
* **The concurrent-agent worktree.** Mid-session, another agent's uncommitted
  work kept mutating the shared tree: `sd.h` gained code using `errno`/`ENOSYS`
  without `#include <errno.h>` (broke the ngx-free `shared/xrdproto` container
  build only — the host build masked it via transitive includes); `stage_engine.c`
  gained an unchecked `write()` tripping `-Werror=unused-result`; and
  `cred_mint.c`/`delegation.c` appeared in `./config` (needing a `./configure`
  refresh on scratch build trees). Each cost a build cycle to notice and work
  around. See §12, Lesson 7.

---

## 6. The turning point

Two changes broke the logjam, in this order:

**(a) Read the access log, not the client.** `dur=113ms` + `OPEN … 0ms` said
*fast failure*. Then, during a "stall", `ss -tinm 'sport = 1095'` returned **no
rows** — the connection was already gone. There was no hang to find.

**(b) Make `sd_xroot` log its own error (`-12`).** The backend collapsed every
origin failure to `errno = EIO`; the flush logged the useless
`"staged_open … (5: Input/output error)"`. One added line at the seam:

```c
/* src/fs/backend/xroot/sd_xroot.c — on origin open/staged-open failure */
ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
    "brix sd_xroot: origin staged-open \"%s\" failed: %s (kXR %d)",
    final_path,
    (t->err_msg[0] != '\0') ? t->err_msg : "(no detail)", t->xrd_error);
```

turned an opaque `EIO` into a *sequence* of specific messages that walked
straight down the real chain, one release at a time:

```
cache origin requires authentication (no credential set)            (Bug C/D)
   → certificate verification failed                                (local-PKI artifact)
   → Secgsi: ErrParseBuffer: wrong number of certificates in
       received bucket (received: 1, expected: >= 2): kXGC_cert      (Bug E)
```

**This should have been the *first* change, not the seventh.** (Lesson 2.)

---

## 7. The five-bug chain, in forensic detail

### Bug A — `sd_xroot` swallowed the origin error

`sd_xroot_errno()` maps `kXR_NotFound→ENOENT`, `kXR_NotAuthorized→EACCES`, else
`EIO`; the staged-flush caller (`stage_engine.c`) logged only the mapped errno.
The rich `brix_cache_fill.err_msg[256]` / `xrd_error` set by
`brix_cache_set_error()` was discarded. **Fix (`-12`, kept):** log it at the
seam (both the plain open and the staged open paths).

### Bug B — cert+key dropped on the tier-build path

A `brix_credential` may express a GSI identity two ways: a single **combined
proxy** PEM (`x509_proxy`), or a **separate cert + key** (`x509_cert` +
`x509_key`). Three code paths build a remote-origin `sd_xroot` instance, each
resolving the credential independently:

1. VFS backend registry (`vfs_backend_registry.c`) — from `e->origin_x509_proxy`.
2. **Tier build** (`tier_build.c` → `tier_resolve_creds`) — used when the backend
   is composed under a cache/stage tier (**exactly this deployment**).
3. Legacy cache fetch (`fetch.c`) — from `xcf->cache_origin_x509_proxy`.

`-11` wired the cert+key fallback into paths 1 and 3. But **path 2 read only
`c->x509_proxy` and hard-coded the key to `NULL`**:

```c
/* tier_build.c BEFORE: */
if (c->x509_proxy.len > 0) (void) brix_str_cbuf(proxy, pcap, &c->x509_proxy);
/* ... */
return brix_sd_xroot_create_origin(..., (proxy[0] != '\0') ? proxy : NULL,
    NULL /* x509_key: tier grammar uses a combined proxy PEM */, ...);
```

So a cache/stage node silently dropped a cert+key credential. **Fix (`-13`):**
`tier_resolve_creds()` gained the cert-chain + separate-key fallback and now
emits a key; all three build paths honour cert+key.

**The test trap that hid this:** the first regression test used `brix_cache …
cache_export` (the *legacy* fetch path), which uses `xcf->cache_origin_*` and so
passed — while the *tier* path was still broken. (Lesson 3.)

### Bug C — the credential did not reach dynamic-module workers

Even with B fixed, the request-handling workers built the origin instance with
an **empty** credential. Ground truth from an added build-time log:

```
# config-parse / `nginx -t` processes (transient, then exit) — WITH credential:
[..] 158089 origin backend build "...:11094" gsi-cert=.../hostcert.pem gsi-key=.../hostkey.pem
[..] 158090 origin backend build "...:11094" gsi-cert=.../hostcert.pem gsi-key=.../hostkey.pem
# the actual serving workers (children of master 158092) — EMPTY:
[..] 158093 origin backend build "...:11094" gsi-cert=(empty) gsi-key=(empty)
[..] 158094 origin backend build "...:11094" gsi-cert=(empty) ...
```

`ps -o pid,ppid -C nginx`: master `158092`; live workers `158093/94/105/110` —
exactly the ones building empty. And `grep 'backend credential'` (the
config-load NOTICE for `set_credential`) fired **only** from transient PIDs
(`157634/635`, `157869/870`, `158089/090`), **never** from the master or
workers.

Root cause: `brix_vfs_backend_set_credential()` runs only at
**postconfiguration**. For a **dynamic (.so) module**, the credential populated
there does not reach the serving workers' process-global backend registry — they
have the backend but an empty credential. This is **invisible to static
`--add-module` builds** (a static binary's process-global array is truly
inherited across `fork`; the .so path is not carried the same way). That is why
every local test passed while the RPM failed.

**Fix (`-16`):** re-apply the credential **per worker, in `init_process`**,
resolved from the credential block via `brix_credential_lookup()`, before any
request resolves the backend:

```c
/* src/core/config/process.c — inside the per-server init_process loop */
if (xcf->common.storage_credential.len > 0 && xcf->common.root_canon[0] != '\0') {
    cred = brix_credential_lookup(credz);
    if (cred != NULL) {
        brix_vfs_backend_cred_t bcred; ngx_memzero(&bcred, sizeof(bcred));
        bcred.x509_proxy = cred->x509_proxy.len ? (char*)cred->x509_proxy.data
                         : (cred->x509_cert.len ? (char*)cred->x509_cert.data : NULL);
        bcred.x509_key   = (cred->x509_proxy.len == 0 && cred->x509_key.len)
                         ? (char*)cred->x509_key.data : NULL;
        /* ... ca_dir, sss_keytab ... */
        brix_vfs_backend_set_credential(xcf->common.root_canon, &bcred);
    }
}
```

(Lesson 4: a static build cannot reproduce dynamic-module per-worker state bugs.)

### Bug D — silent duplicate `brix_credential` shadowing (THE blocker)

After A–C, and after pointing the config at a real 2-cert proxy, workers **still**
resolved the host cert+key. The credential the worker actually held (dumped by a
diagnostic):

```
DIAG init-cred[w1]: storage_credential=origin cred=found
    proxy="" cert="/etc/grid-security/brix/hostcert.pem" key="/etc/grid-security/brix/hostkey.pem"
```

`proxy=""` and `cert/key=host*` — the **opposite** of the (edited) stream block,
which had only `x509_proxy`. The worker's credential reflected a config we were
not editing. `nginx -T` (the authoritative dump of what nginx actually parsed)
revealed why — **three** `origin` blocks:

```
nginx.conf:33   (stream{})            x509_proxy       ← the one being edited
nginx.conf:208  (http{})              x509_cert+key    ← shadowing
conf.d/brix-cache.conf:10 (http{})    x509_cert+key    ← shadowing
```

`brix_credential` is a **single global, name-keyed registry**. The block handler
dedups "last write wins" — it finds the existing slot and **zeroes then
repopulates** it:

```c
/* credential_block.c — dedup: */
existing = brix_credential_lookup(name_z);
if (existing != NULL) cred = (brix_credential_t *) existing;   /* reuse slot */
/* ... */
ngx_memzero(cred, sizeof(*cred));                              /* WIPE, then repopulate */
```

So whichever `origin` block parsed last silently won. The `http`/`conf.d`
cert+key blocks overrode the stream proxy block, with **no diagnostic**. Editing
the stream block changed nothing because a shadowing block always re-won on
reload. This single silent behaviour cost roughly **ten** debugging rounds.

It originated in the **deploy bundle**, which duplicated the credential across
`stream{}` and `http{}`/`conf.d` with *inconsistent* content.

**Fix (config):** make every `brix_credential origin { … }` block identical.
**Fix (code, `-18` hardening):** config load now WARNs on a same-config
redefinition, distinguished from a benign reload re-parse by `cf->cycle` (new
`brix_credential_t.last_def_cycle`):

```c
existing = brix_credential_lookup(name_z);
if (existing != NULL) {
    cred = (brix_credential_t *) existing;
    dup_in_this_config = (existing->last_def_cycle == (void *) cf->cycle);
}
/* ... */
if (dup_in_this_config)
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
        "brix_credential \"%V\" is defined more than once ... the LAST "
        "definition silently overrides the earlier one(s) ... Make every "
        "\"brix_credential %V { ... }\" block IDENTICAL, or give them "
        "distinct names.", &value[1], &value[1]);
/* ... */
cred->last_def_cycle = (void *) cf->cycle;
```

(Lesson 5: a global, name-keyed, silent last-wins namespace is a trap; `nginx
-T` is ground truth.)

### Bug E — a stock XRootD requires a proxy chain, not a bare cert

With the proxy finally in use, the origin still rejected it:

```
Secgsi: ErrParseBuffer: wrong number of certificates in received bucket
    (received: 1, expected: >= 2): kXGC_cert
```

A stock XRootD GSI server requires a **delegated proxy chain** — proxy cert +
end-entity cert = **≥ 2 certs** — in the `kXGC_cert` bucket. A raw host cert is
**one** cert. BriX's cert-chain packing was correct all along
(`brix_gsi_build_cert_response` puts the whole `proxy_pem` into one `kXRS_x509`
bucket, and `load_proxy_pem` reads *all* PEM certs in the file); it had simply
never been handed a 2-cert source, because Bug D kept feeding it the 1-cert host
credential.

**Fix (config):** present a real RFC3820 proxy:

```bash
X509_USER_CERT=/etc/grid-security/brix/hostcert.pem \
X509_USER_KEY=/etc/grid-security/brix/hostkey.pem \
  voms-proxy-init -rfc -valid 720:00 -out /etc/grid-security/brix/proxy.pem
grep -c 'BEGIN CERTIFICATE' /etc/grid-security/brix/proxy.pem   # => 2
```

**Fix (code, `-18` hardening):** `brix_cache_origin_auth_gsi()` counts certs in
the credential PEM and, if `< 2`, WARNs up-front — naming the exact origin error
and the `voms-proxy-init` remedy — instead of letting the operator decode
`received: 1`.

**Operational:** proxies expire. Renew `proxy.pem` from cron; BriX re-reads it on
every origin connection (`load_proxy_pem` is called per handshake), so no reload
is needed. The proper end state is in-process proxy minting
(`src/fs/backend/cred_mint.c`, in progress) so `x509_cert`+`x509_key` work
against a stock XRootD with no external proxy.

---

## 8. The final fix and verification

Config change (the actual fix): all `brix_credential origin` blocks identical,
pointing at a 2-cert proxy. Then:

```
$ xrdcp -f /tmp/t100.bin root://xrd1.edi.scotgrid.ac.uk:1095//ok21.bin
$ ls -l /data/xrootd/ok21.bin
-rw-r--r--. 1 xrootd xrootd 104857600 Jul  8 23:50 /data/xrootd/ok21.bin   # ← byte-exact on the origin
# init-cred[wN]: proxy="/etc/grid-security/brix/proxy.pem" cert="" key=""
# origin backend build: gsi-cert=/etc/grid-security/brix/proxy.pem
# no "no credential set", no Secgsi error
```

Full chain confirmed: **client → BriX (GSI) → local stage → GSI-authenticated
flush → real XRootD origin.**

Baseline for comparison — with `brix_io_uring off` (before the credential fix),
the client write completed *to the stage* at 228 MB/s but the async flush failed:

```
"CLOSE /data/brix/export/x2.bin 228.95MB/s" OK 104857600
stage move: dest staged_open failed (xroot key="/x2.bin") (5: Input/output error)
```

This is the datum that finally reframed it from "io_uring stall" to "the flush to
the origin fails" — the write path was fine; the *origin auth* was broken.

---

## 9. Every code change (reference)

Load-bearing fixes (retained):

| File | Change | Rel |
|------|--------|-----|
| `src/fs/backend/xroot/sd_xroot.c` | log real origin error (`err_msg`+`kXR`) on open/staged-open failure | `-12` |
| `src/fs/tier/tier_build.c` | `tier_resolve_creds` cert+key fallback; thread `x509_key` into `create_origin`; http branch key buffer | `-13` |
| `src/fs/backend/xroot/sd_xroot.{c,h}` | `brix_sd_xroot_create_origin` gains an `x509_key` parameter → `synth->cache_origin_x509_key` | `-13` |
| `src/fs/cache/origin_auth.c` | `auth_gsi` loads the key from `cache_origin_x509_key` when set (separate cert+key) | `-13` |
| `src/fs/vfs/{vfs_backend_registry.*,vfs_backend_config.c,vfs_backend_internal.h}` | thread `origin_x509_key` through the registry entry + `bcred` | `-13` |
| `src/core/config/runtime_server.c` | `bcred`/`xcf` cert+key fallback; one-line resolved-credential NOTICE at config load | `-11`/`-13` |
| `src/core/types/config.h` | add `cache_origin_x509_key` | `-13` |
| `src/core/config/process.c` | per-worker credential re-apply in `init_process` from `brix_credential_lookup` | `-16` |
| `src/fs/backend/sd.h` | add `#include <errno.h>` (ngx-free build; concurrent-WIP casualty) | `-11` |

Hardening / coherent diagnostics (`-18`):

| File | Change |
|------|--------|
| `src/core/config/credential_block.{c,h}` | WARN on same-config duplicate `brix_credential` name; new `last_def_cycle` field (reload-safe) |
| `src/fs/cache/origin_auth.c` | WARN when the origin credential is `< 2` certs (bare cert vs required proxy chain), naming `voms-proxy-init` |
| `src/fs/cache/origin_protocol.c` | "no credential set" message now names the cause (unset/shadowed `brix_storage_credential`) |
| `src/core/config/process.c`, `sd_xroot.c`, `origin_protocol.c` | strip the `-14`/`-16`/`-17` diagnostic NOTICEs |

Also kept: `-9` (`brix_io_uring` default off), `-10`
(`brix_ensure_write_event` pipeline lost-wakeup hardening), `-5`/`-7`/`-8` (the
segfault fixes).

---

## 10. The diagnostics we added (with sample output)

1. **`sd_xroot` origin error** (`-12`, permanent):
   ```
   brix sd_xroot: origin staged-open "/x.bin" failed: cache origin requires
       authentication (no credential set) (kXR 3030)
   ```
2. **Duplicate `brix_credential`** (config load):
   ```
   [warn] brix_credential "origin" is defined more than once in this
       configuration. brix_credential is a single global name-keyed registry
       (shared across stream{} and http{}), so the LAST definition silently
       overrides the earlier one(s) ... Make every "brix_credential origin
       { ... }" block IDENTICAL, or give them distinct names.
   ```
3. **Single-cert credential vs required proxy** (origin GSI auth):
   ```
   [warn] brix: origin GSI credential "/etc/grid-security/brix/hostcert.pem"
       has 1 certificate(s); a stock XRootD origin requires a delegated PROXY
       chain (>= 2: proxy + end-entity cert). ... Generate a proxy, e.g.
       voms-proxy-init -rfc -cert <hostcert> -key <hostkey> -out <proxy.pem>,
       and point x509_proxy at it.
   ```
4. **Actionable "no credential set"**:
   ```
   origin requires authentication but this backend has NO credential — set
       brix_storage_credential to a brix_credential providing x509_proxy (or
       x509_cert+x509_key), a bearer token, or sss_keytab. If you did set one, a
       duplicate brix_credential block of the same name may be overriding it
       (see the 'defined more than once' warning at config load).
   ```
5. **Resolved backend credential** (config-load NOTICE, ops visibility):
   ```
   [notice] brix: backend credential "origin" for "/data/brix/export":
       gsi=/etc/grid-security/brix/proxy.pem key=(in-proxy/none) bearer=(none)
   ```

---

## 11. Regression tests

* **`tests/run_credential_dup_warn.sh`** — the direct guard for Bug D. Pure
  `nginx -t`: (1) two same-name `brix_credential` blocks → WARN present; (2) the
  duplicate does not turn into a hard error (config still loads); (3) a single
  block → no false warning; (4) two distinct names → no false warning.
* **`tests/run_credential_xroot_gsi_writeback.sh`** — end-to-end for Bugs B+C. A
  `brix_credential` (separate cert+key) authenticates a **write-through flush**
  to a GSI origin composed exactly as the deployment (`brix_storage_backend` +
  `brix_cache_store` + `brix_stage`); asserts the bytes land on the origin, and
  that a *no-credential* node's flush is rejected.
* **`tests/run_credential_xroot_gsi.sh`** — now includes a separate
  `x509_cert`+`x509_key` node on the read-fill path (Bug B on `fetch.c`).

```bash
NG=/tmp/nginx-1.28.3/objs/nginx
bash tests/run_credential_dup_warn.sh "$NG"            # ALL PASS
bash tests/run_credential_xroot_gsi_writeback.sh "$NG" # ALL PASS
bash tests/run_credential_xroot_gsi.sh "$NG"           # ALL PASS
```

**Coverage limit, stated honestly:** the static test binary cannot reproduce Bug
C (the dynamic-module per-worker credential loss) — that needs the `.so`. The
write-through test guards the *logic* (the per-worker re-apply runs in
`init_process` in both static and dynamic builds and must yield a working flush);
the dynamic-only manifestation is guarded operationally by the config-load
NOTICE and the duplicate WARN.

---

## 12. Lessons (the durable ones)

1. **Read durations and peer state before theorising.** `dur=113ms`, `OPEN …
   0ms`, and an empty `ss` all said "fast failure, not a hang" on day one.
2. **Never let a component swallow its own error.** One `ngx_log_error` at the
   `sd_xroot` seam exposed the entire chain. It should have been change #1.
3. **Test the deployment's exact compose**, not a simpler analogue. The legacy
   cache-fetch test passed while the tier path was broken.
4. **Static builds don't reproduce dynamic-module state bugs.** Local pass + RPM
   fail ⇒ suspect the `.so`/`fork`/postconfiguration boundary.
5. **Be loud on silent last-wins.** A global, name-keyed config namespace must
   warn on redefinition; `nginx -T` is authoritative for what parsed.
6. **When ≥3 fixes fail, question the model** (`superpowers:systematic-debugging`).
   The io_uring arc violated this repeatedly, shipping fix #N+1 instead of getting
   the ground-truth error string.
7. **A shared worktree with a concurrent agent is a hazard.** Three separate
   build breaks came from another session's uncommitted WIP appearing mid-build
   (`sd.h` missing `<errno.h>`, an unchecked `write()`, new `./config` sources).
   Prefer an isolated worktree for long debugging sessions.

---

## 13. Release timeline

| Rel | Change | Verdict |
|-----|--------|---------|
| `-5` | tier-store pool-lifetime SIGSEGV fix | real, unrelated (kept) |
| `-6` | io_uring eventfd self-test / auto-fallback | wrong theory |
| `-7` | io_uring teardown UAF fix (attempt 1) + eventfd | UAF real (kept); stall theory wrong |
| `-8` | batch NOP self-test + robust orphan guard | UAF fix solid; stall theory still wrong |
| `-9` | `brix_io_uring` default `auto→off` | correct hardening (kept) |
| `-10` | pipeline `brix_ensure_write_event` lost-wakeup | real edge-triggered hardening (kept); not the bug |
| `-11` | wire `x509_cert`+`x509_key` (config + fetch paths) | partial — missed the tier path |
| `-12` | **`sd_xroot` surfaces the real origin error** | the turning point |
| `-13` | **`tier_resolve_creds` cert+key** | load-bearing (Bug B) |
| `-14` | origin-auth diagnostics | diagnostic |
| `-15` | per-worker re-apply (attempt, srv-conf source) | superseded by `-16` |
| `-16` | **per-worker re-apply from `brix_credential_lookup`** | load-bearing (Bug C) |
| `-17` | credential-value dump diagnostics | diagnostic; exposed Bug D |
| — | **config: dedup `brix_credential`; present a 2-cert proxy** | the actual fix (Bugs D + E) |
| `-18` | strip diagnostics; add the duplicate + single-cert WARNs; regression tests; this doc | closeout |

---

## 14. Appendix — raw evidence

**io_uring ring quiescent during the "stall"** (all 4 workers, all 4 snapshots):
```
io_uring fd 26 fdinfo: SqHead:257 SqTail:257 CqHead:257 CqTail:257
worker state=S cpu=0.0% wchan=ep_poll ; pool threads in pthread_cond_wait
staged .part frozen at 8388608 bytes
```

**Fast-fail access log:** `OPEN … wr ERR 0 0ms "file not found"`, `END dur=113`.

**io_uring-off baseline:** client write completes to stage
(`CLOSE … 228.95MB/s OK 104857600`); async flush fails
(`stage move: dest staged_open failed (xroot key="/x2.bin") (5: Input/output error)`).

**Cert moduli (all match — the "mismatch" was a red herring):**
```
hostcert.pem   MD5(modulus)= ddc46a888a44915279d8cf329aa9a4e4
hostkey.pem    MD5(modulus)= ddc46a888a44915279d8cf329aa9a4e4
brix/hostkey   MD5(modulus)= ddc46a888a44915279d8cf329aa9a4e4
```

**Origin lets localhost `root` in unauthenticated (no TLS/GSI):**
```
kXR_login username: root  →  kXR_open kXR_ok   (no kXR_auth, no gotoTLS)
```

**Per-worker build split (Bug C):** config-parse PIDs build with the credential;
serving workers (`ps` children of master `158092`) build empty.

**`nginx -T` shows three `brix_credential origin` blocks (Bug D):** stream
`x509_proxy` at `nginx.conf:33`; http `x509_cert+key` at `nginx.conf:208`;
`conf.d/brix-cache.conf:10` `x509_cert+key`.

**Worker resolved the shadowing credential (Bug D):**
```
DIAG init-cred[w1]: cred=found proxy="" cert=".../hostcert.pem" key=".../hostkey.pem"
```

**Origin GSI rejection of the bare cert (Bug E):**
```
Secgsi: ErrParseBuffer: wrong number of certificates in received bucket
    (received: 1, expected: >= 2): kXGC_cert
```

**Success (`ok21.bin`, 104857600 bytes on `/data/xrootd/`).**
