# Troubleshooting runbook — symptom-indexed

Every entry here is a failure mode that actually happened and was
root-caused on this project. Start from the symptom, run the first check,
follow the section. Postmortems linked where they exist.

| Symptom | First check | Section |
|---|---|---|
| Connections stall under multi-worker concurrency; a worker looks frozen | `cat /proc/<worker-pid>/wchan` | [§1](#1-worker-frozen--multi-worker-connection-stalls) |
| `kXR_FileLocked` errors or 30 s hangs that won't clear | `pgrep -af nginx` for orphaned workers | [§2](#2-kxr_filelocked-hangs--cache-fill-pool-exhaustion) |
| root:// handshake timeouts + bogus `EXDEV` on staged PUT/MOVE | `mount \| grep fuse` | [§3](#3-phantom-exdev--handshake-timeouts-dead-fuse-mount) |
| Token/dedicated-port tests fail right after a src rebuild | which binary the dedicated instances run | [§4](#4-dedicated-fleet-desync-after-a-rebuild) |
| pytest aborts whole-run: "Different tests collected" / xdist workers crash | worker count and box health | [§5](#5-pytest-xdist-crashes-and-collection-aborts) |
| Manual TPC / fleet dead right after a pytest run | is the fleet still up? | [§6](#6-fleet-gone-after-a-pytest-run) |
| Module directives rejected / behavior missing after a build | `objs/nginx -V` output | [§7](#7-configure-silently-built-a-bare-nginx) |
| Connection refused on a test port | the ports registry | [§8](#8-connection-refused-on-a-test-port) |
| Auth failures (GSI/token) | cert dates / CA config shape | [§9](#9-auth-failures) |
| (any of the above) | debug tooling quick reference | [§10](#10-debug-tooling-quick-reference) |

---

## 1. Worker frozen / multi-worker connection stalls

**What you see:** connections stall 60–450 s under concurrency, only with
`worker_processes > 1`; an armed nginx timer never fires; `ss -tn` shows
Recv-Q > 0 on the affected port.

**Diagnose:**

```bash
ss -tn 'sport = :PORT'            # Recv-Q>0 = read-side stall
cat /proc/<worker-pid>/wchan      # futex_do_wait = blocked on a lock
                                  # do_epoll_wait = idle / lost notify
gdb -p <worker-pid> -batch -ex "thread apply all bt"
# for a suspect ngx_shmtx:
#   print *(int*)MUTEX.lock   and   *(int*)MUTEX.wait
#   0/0 with a thread in sem_wait = lost semaphore wakeup
```

**Root cause (seen live):** a shared-memory mutex created in POSIX-semaphore
mode loses wakeups under cross-worker contention — the worker blocks in
`sem_wait` forever with the lock already free, freezing its whole event
loop. Fix/prevention: every module SHM mutex goes through
`brix_shm_table_alloc()` / `brix_shm_table_mutex_create()` (spin+yield;
clears `mtx->semaphore`). Full analysis:
[postmortem-shmtx-semaphore-stall.md](../09-developer-guide/postmortem-shmtx-semaphore-stall.md).

Related: an SHM mutex stranded by a killed worker is force-unlocked by
nginx only if the mutex is bound to the worker's slot lock — the bind/session
table does this deliberately; keep it that way.

## 2. kXR_FileLocked hangs / cache-fill pool exhaustion

**What you see:** repeated `kXR_FileLocked` wire errors, 30 s client hangs,
cache fills that never complete; gets worse over hours.

**Root cause (seen live):** a killed test run leaves orphaned nginx workers
holding cache-fill O_EXCL locks, poisoning the box for every later run.
Dead-owner locks are reclaimed automatically (`kill(pid,0)==ESRCH` check),
but only if the owner is *gone* — an orphaned live worker is not dead.

**Fix:**

```bash
pgrep -af nginx                    # anything running from a wiped prefix?
pkill -9 nginx                     # NOT `pkill -f objs/nginx` — misses workers
tests/manage_test_servers.sh stop-all && tests/manage_test_servers.sh start-all
```

Harness rule: teardown must `killpg()` the master from the *correct*
pidfile; a wrong pidfile is how orphans happen.

## 3. Phantom EXDEV + handshake timeouts (dead FUSE mount)

**What you see:** root:// handshake timeouts on cache nodes AND fake
`EXDEV` (cross-device) failures on staged PUT/MOVE — looks exactly like a
cache/staging regression. It isn't.

**Root cause (seen live):** a crashed FUSE test left a dead mount (e.g.
`/tmp/fusetest/mnt`); unrelated workers touch it and block in
`request_wait_answer` (visible in `/proc/PID/wchan`).

**Fix:**

```bash
mount | grep fuse                  # find the corpse
fusermount -u -z /tmp/fusetest/mnt
# restart the affected node (nginx -p <prefix>)
```

## 4. Dedicated-fleet desync after a rebuild

**What you see:** token-conformance (11119/11250/11251/8446/9002) or other
dedicated-port suites fail right after a `src/` fix was built and
`start-all` was re-run from that session.

**Root cause (seen live):** dedicated instances keep running the *old*
binary after an in-place rebuild — a plain start-all doesn't recycle them.

**Fix:** clean `stop-all` + `start-all`, then re-run the full affected
suite (not just the failing test).

## 5. pytest xdist crashes and collection aborts

Known failure modes of the shared-fleet suite:

- **`-n16` crashes workers** — the fleet caps xdist at `-n12`. Repeated
  heavy runs degrade the box until even `-n12` crashes: reset (stop-all,
  clear `/tmp/xrd-test`, start-all) between heavy runs.
- **"Different tests collected" whole-run abort** — was a conftest
  `os.getcwd()` at import throwing when a worker's cwd was wiped; fixed
  (falls back to repo root), but the signature is worth knowing.
- **Load-flaky families** — large-read/VOMS tests can fail under `-n12`
  load and pass serially; rerun the failures serially before treating them
  as regressions.
- **`TEST_OWN_FLEET=1` must run SERIAL** — xdist workers would wipe the
  PKI concurrently.
- **`pgrep -f run_suite` matches your own shell** — beware exit 144
  self-matches in wrapper scripts.

## 6. Fleet gone after a pytest run

**What you see:** manual xrdcp/TPC against the fleet hangs or gets
connection-refused right after running tests.

**Root cause (historical, fixed):** conftest teardown used to stop-all and
`rmtree(/tmp/xrd-test)` on exit, orphaning root fds. Since 2026-06-30
conftest auto-attaches to a running fleet (no wipe); `TEST_OWN_FLEET=1`
forces a clean restart. If you see this again, check that the conftest
auto-attach notice printed — its absence means the fleet was owned (and
therefore stopped) by the test run.

## 7. `./configure` silently built a bare nginx

**What you see:** the build succeeds but brix directives are "unknown" or
module behavior is entirely absent.

**Root cause (seen repeatedly):** `--add-module=$REPO` with `REPO`
unset/empty expands to nothing — nginx configures happily without the
module. Same hazard: a background agent reconfiguring the shared
`/tmp/nginx-1.28.3` build tree against a *different* worktree.

**Fix / check:**

```bash
/tmp/nginx-1.28.3/objs/nginx -V 2>&1 | grep -o 'add-module=[^ ]*'   # must show YOUR repo path
export REPO=/path/to/repo   # or use a literal path in --add-module
# if a background agent reconfigured the shared tree:
rm -rf /tmp/nginx-1.28.3/objs && (cd /tmp/nginx-1.28.3 && ./configure ... --add-module=$REPO)
```

## 8. Connection refused on a test port

Look the port up in the
[test-fleet ports registry](../10-reference/test-fleet-ports.md) (what it
serves, which auth), then:

```bash
ss -tlnp | grep <port>                     # is anything listening?
tests/manage_test_servers.sh start-all     # bring the fleet up
tail -50 /tmp/xrd-test/logs/error.log      # if it should be up but isn't
```

## 9. Auth failures

- **Cert validity:** `openssl x509 -in cert.pem -noout -dates`.
- **`brix_trusted_ca` expects a FILE (e.g. `ca.pem`), not a directory** —
  a directory silently trusts nothing.
- **Proxy certs:** RFC 3820 proxies are accepted on both root:// and
  davs:// (the davs path was fixed 2026-07-06) — a 403 for a *valid* proxy
  on one protocol but not the other is a regression, report it.
- **Token clock skew:** port 11119 enforces zero skew by design — an
  `exp`/`iat` failure there but not on 11097 is the strict port doing its
  job.
- **ztn:** needs TLS and won't present via pyxrootd — use GSI + authdb-VO
  in tests instead.
- **ACL logic:** `src/auth/authz/` (see its README for the gate order:
  authdb → VO ACL → token scope).

## 10. Debug tooling quick reference

```bash
XRD_LOGLEVEL=Debug xrdcp root://localhost:11094//file /tmp/out   # client wire trace
# server block: error_log /tmp/xrd-test/logs/debug.log debug;
ls /tmp/xrd-test/logs/    # error.log, brix_access*.log, http_webdav_access.log, s3_access.log
pkill -9 nginx            # kill everything (never -f objs/nginx: misses workers)
```

Related deep dives:
[postmortem-shmtx-semaphore-stall.md](../09-developer-guide/postmortem-shmtx-semaphore-stall.md),
[postmortem-proxy-retry-leak.md](../09-developer-guide/postmortem-proxy-retry-leak.md),
[postmortem-proxy-splice-underdrain-stall.md](../09-developer-guide/postmortem-proxy-splice-underdrain-stall.md),
[reload-semantics.md](../09-developer-guide/reload-semantics.md).
