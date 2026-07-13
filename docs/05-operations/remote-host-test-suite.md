# Installing & running the test suite on a remote host

How to take the packaged BriX RPMs to a fresh machine, install them, prove the
module loads, and then run the ~8,700-test pytest suite against it — either the
way the suite is authored (a source build) or against the exact shipped `.so`.

This page is deliberately exhaustive: every command, every environment variable
the harness reads, every failure mode you will actually hit, and *why* each step
is there. If you only want to deploy the module and confirm a fast restart, stop
after [Part 1](#part-1--install-and-validate-the-deployment). Run the suite when
you want a green/red release signal on that host.

> **Which path do I want?**
> - **[Path A — source build](#path-a--full-suite-via-a-source-build-recommended)** is what the suite is
>   written and CI-validated against. The module is statically linked into
>   `nginx`, so the fleet config needs **zero** surgery. Use it for an
>   authoritative full run.
> - **[Path B — RPM dynamic module](#path-b--run-against-the-shipped-so-rpm-dynamic-module)** runs the fleet
>   against the exact `.so` you will deploy. It needs two `load_module` lines
>   injected into the fleet configs. Use it to prove the *packaged* bytes run.

---

## Background: why the fleet needs the module wired in

The suite does not test a running production server. It stands up its **own**
nginx fleet on fixed ports (`tests/manage_test_servers.sh start-all`), generated
from templates under `tests/configs/`, and drives that fleet with pytest.

The single thing that determines whether the fleet can start is: **does the
nginx binary the fleet launches contain the BriX module directives?**
(`brix_root`, `brix_auth`, `brix_storage_backend`, …). There are exactly two
ways that happens:

| | Module form | How the fleet gets it | Config surgery |
|---|---|---|---|
| **Path A** | Statically linked (`./configure --add-module`) | Every `brix_*` directive is compiled into `objs/nginx` | None — the templates work as-is |
| **Path B** | Dynamic `.so` (what the RPM ships) | Two `load_module` lines at the **top** of the fleet config | Prepend the `load_module` lines |

The fleet template `tests/configs/nginx_shared.conf` begins with
`worker_processes 1;` and contains **no** `load_module` line, because it was
authored for the static build. A stock `nginx` launched with
`-c conf/nginx.conf` does **not** read `/usr/share/nginx/modules/*.conf`, so the
production module-load fragment never applies to the fleet. Path B injects those
lines itself. See [upgrade-procedure.md](upgrade-procedure.md) for the module
layout and the **combined-`.so`-first** load-order rule.

---

## Part 1 — Install and validate the deployment

This installs the module + tools and confirms the restart-speed fix. It does
**not** run pytest.

### 1.1 Copy the RPMs to the remote host

From the build box (RPMs land in the `-o` directory of
`packaging/rpm/build-rpm-container.sh`, e.g. `/tmp/rpms`):

```bash
scp /tmp/rpms/*1.1.1-20*.rpm  you@REMOTE:/tmp/brix-rpms/
```

The relevant subpackages (ignore the `-debuginfo`/`-debugsource`/`.src.rpm`):

| RPM | Contains |
|---|---|
| `nginx-mod-brix-cache-*.x86_64.rpm` | The two module `.so`s + `mod-xrootd.conf` + example config |
| `brix-cache-client-*.x86_64.rpm` | `xrdcp`, `xrdfs`, `xrdgsiproxy`, … |
| `brix-tools-*.x86_64.rpm` | Sysadmin tooling (`xrdstorascan`, `xrddiag`, …) |
| `brix-cache-tests-*.noarch.rpm` | The pytest suite + fleet harness (only needed for Part 2 Path B) |

### 1.2 Install

```bash
sudo dnf install -y \
  /tmp/brix-rpms/nginx-mod-brix-cache-1.1.1-20.el9.x86_64.rpm \
  /tmp/brix-rpms/brix-cache-client-1.1.1-20.el9.x86_64.rpm \
  /tmp/brix-rpms/brix-tools-1.1.1-20.el9.x86_64.rpm
```

`dnf` resolves the runtime deps (`nginx`, `openssl`, `libcurl`, `krb5-libs`, …)
from the host's repos. The module package requires an ABI-matching `nginx`; if
`dnf` reports a version conflict, the host's `nginx` is a different build than
the RPM was compiled against — align them before proceeding (see
[upgrade-procedure.md](upgrade-procedure.md)).

**What lands where:**

| Path | Purpose |
|---|---|
| `/usr/lib64/nginx/modules/ngx_stream_brix_module.so` | Combined module (root:// + WebDAV + S3 + metrics + dashboard + CMS) |
| `/usr/lib64/nginx/modules/ngx_http_brix_xrdhttp_filter_module.so` | HTTP AUX output filter |
| `/usr/share/nginx/modules/mod-xrootd.conf` | The two `load_module` lines, **combined first** |
| `/etc/nginx/conf.d/brix-cache.conf.example` | Reference config (inactive until copied to a `.conf` name) |

### 1.3 Confirm the module loads

```bash
nginx -t
```

Expected: `syntax is ok` / `test is successful`. If instead you see
`unknown directive "brix_root"`, the `load_module` fragment is not being
included by your `nginx.conf` — confirm `/etc/nginx/nginx.conf` has
`include /usr/share/nginx/modules/*.conf;` near the top, or that
`mod-xrootd.conf` is symlinked into `/etc/nginx/modules-enabled/` per your
distro's convention.

### 1.4 Validate the fast-restart fix (`-20`)

The `-20` module marks every per-worker maintenance timer `cancelable`, so a
gracefully draining worker exits the instant its in-flight transfers finish
instead of lingering until `worker_shutdown_timeout`. Confirm the config knob is
sane first — the timer fix removes the *self-inflicted* delay, but a
`worker_shutdown_timeout` set **above** the systemd unit's `TimeoutStopSec`
still forces a SIGKILL wait on every restart:

```bash
grep -rn worker_shutdown_timeout /etc/nginx/          # want a small value, e.g. 2s
systemctl show nginx -p TimeoutStopUSec               # must be >= worker_shutdown_timeout
```

Then measure:

```bash
systemctl stop nginx ; time systemctl start nginx     # START phase alone
time systemctl restart nginx                          # full restart (STOP + START)
```

**Expected on a host that previously took ~9 s:** STOP drops from ~2–3 s to
sub-second; full restart trends toward ~2.5 s. If STOP is still multi-second,
re-check §1.4's `worker_shutdown_timeout` vs `TimeoutStopSec` relationship — see
[contrib/brix-cache.conf.example](../../contrib/brix-cache.conf.example) and
[reload-semantics.md](../09-developer-guide/reload-semantics.md). For
config-only changes prefer `systemctl reload` (SIGHUP), which has no stop-timeout
pressure at all.

---

## Part 2 — Run the test suite

### Prerequisites (both paths)

The suite drives real clients against a real fleet, so the host needs:

| Requirement | Why | Install |
|---|---|---|
| `python3-pytest`, `python3-pytest-xdist`, `python3-pytest-timeout` | The runner shards with `-n12` and enforces per-test timeouts | `sudo dnf install python3-pytest python3-pytest-xdist python3-pytest-timeout` |
| `python3-cryptography` | The harness mints its own test PKI (CA, host cert, user proxies) | `sudo dnf install python3-cryptography` |
| `brix-cache-client` (`xrdcp`/`xrdfs`) | Many tests copy/stat through the native client | Part 1.2 |
| A reference `xrootd` binary on `PATH` | Conformance & differential lanes cross-check against stock XRootD (`REF_BIN`, default `xrootd`) | Site XRootD RPM; **optional** — without it those lanes skip |
| A free block of fixed ports | The fleet binds `11094–11097`, `9100`, `8443/8444`, `8080`, `9001` (+ dedicated ports for slow lanes) | Ensure nothing else listens there |

> The suite runs against a **local** fleet it starts itself — it never touches
> the production `systemd` nginx from Part 1. Stop or leave that running; the
> fleet uses its own prefix (`TEST_ROOT`, default `/tmp/xrd-test`) and its own
> pidfiles. Do **not** run the suite against your production data root.

### Runner cheat-sheet

`tests/run_suite.sh` is the source of truth. It owns fleet lifecycle
(`TEST_OWN_FLEET=1`), runs a parallel bulk lane plus serial/dedicated lanes, and
re-runs only the failures on a now-quiet box to filter load-correlated flakes.
See [tests/README.md](../../tests/README.md) for the full rationale.

| Command | Runs | Time | Use when |
|---|---|---|---|
| `tests/run_suite.sh --fast` | Parallel `not slow and not serial` bulk | ~4 min | Fastest "did I break it" signal |
| `tests/run_suite.sh --pr` | The `not slow` set (~6,990) + serial lane + one flake re-run | <5 min | PR gate |
| `tests/run_suite.sh --nightly` | The deferred `slow` set (~1,770): resilience/chaos/perf/conformance/interop | ~8 min | Pre-release |
| `tests/run_suite.sh` | Full 4-lane suite with the complete flake-rerun ladder | ~10–12 min | Authoritative release gate |
| `PYTHONPATH=tests pytest tests/test_X.py -v` | One file/test | seconds | Focused debugging |

`--pr` + `--nightly` together cover the same tests as the bare full run.

### Environment variables the harness reads

Set these to point the fleet at the right binaries and paths (all have
defaults in `tests/manage_test_servers.sh` / `tests/lib/`):

| Variable | Default | Meaning |
|---|---|---|
| `NGINX_BIN` | `/tmp/nginx-1.28.3/objs/nginx` | The nginx binary the fleet launches — **the key knob** |
| `TEST_ROOT` | `/tmp/xrd-test` | Fleet prefix: data, PKI, logs, pidfiles |
| `REF_BIN` | `xrootd` | Reference XRootD for conformance/differential lanes |
| `TEST_OWN_FLEET` | (set by `run_suite.sh`) | Force a clean own-fleet start; never attach to a stale fleet |
| `NGINX_CONF_PREGENERATED` | `0` | If `1`, the caller already wrote `conf/nginx.conf`; skip templating |

---

### Path A — Full suite via a source build *(recommended)*

The module is compiled **into** `nginx`, so the fleet templates need no changes.
This is exactly how CI runs the suite.

**1. Build deps** (AlmaLinux/RHEL 9 names):

```bash
sudo dnf install -y gcc make pcre2-devel openssl-devel zlib-devel \
  libxml2-devel jansson-devel krb5-devel libcurl-devel \
  python3-pytest python3-pytest-xdist python3-pytest-timeout python3-cryptography
```

**2. Get the repo and nginx source.** Put the repo where you like; export its
path as `REPO` (the module's `config` script is read from there):

```bash
export REPO=/opt/nginx-xrootd            # your checkout of this repository
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xf nginx-1.28.3.tar.gz
```

> **Gotcha:** `REPO` must be a **literal, non-empty** absolute path when you
> configure. `REPO= ./configure --add-module=$REPO` expands to an empty
> `--add-module` and silently builds a **bare** nginx with none of the BriX
> directives — then every fleet config fails to parse. Confirm afterwards with
> `objs/nginx -V 2>&1 | grep -o add-module=\\S*`.

**3. Configure + build** the static module (the canonical line from the project
guide):

```bash
cd /tmp/nginx-1.28.3
"$REPO"/configure --with-stream --with-stream_ssl_module \
  --with-http_ssl_module --with-http_dav_module --with-threads \
  --add-module="$REPO"
make -j"$(nproc)"          # produces objs/nginx == the default NGINX_BIN
```

**4. Run the suite** from the repo root (the runner `cd`s to `$REPO` and uses
`NGINX_BIN=/tmp/nginx-1.28.3/objs/nginx` by default):

```bash
cd "$REPO"
tests/run_suite.sh --fast        # ~4 min smoke
tests/run_suite.sh --pr          # <5 min gate
tests/run_suite.sh               # ~10–12 min authoritative full run
```

If you built nginx somewhere else, export `NGINX_BIN=/that/path/objs/nginx`
before invoking the runner.

---

### Path B — Run against the shipped `.so` (RPM dynamic module)

Use this to exercise the **exact** module you will deploy. The RPM ships the
module as a dynamic `.so`; you inject the two `load_module` lines into the
fleet's top-level configs.

**1. Install the tests package** (Part 1.2 first, then):

```bash
sudo dnf install -y /tmp/brix-rpms/brix-cache-tests-1.1.1-20.el9.noarch.rpm
```

It installs to `/usr/share/brix/` (`conftest.py`, `pytest.ini`,
`requirements.txt`, and the whole `tests/` tree).

**2. Work from a writable copy.** The installed tree is root-owned and
read-only; the harness reads its templates from beside the script, so copy the
whole thing where you can edit it:

```bash
cp -r /usr/share/brix ~/brixtests
cd ~/brixtests
```

**3. Inject the module-load lines into every top-level fleet config.** The two
lines must appear at the very top (main context), **combined `.so` first** so
its symbols back the filter under `RTLD_GLOBAL` (same order the RPM's
`mod-xrootd.conf` uses). The loop targets only real standalone configs — those
containing an `events { … }` block, which is main-context-only — so it never
corrupts an `http`/`stream` fragment that is `include`d by another file:

```bash
LM='load_module "/usr/lib64/nginx/modules/ngx_stream_brix_module.so";\nload_module "/usr/lib64/nginx/modules/ngx_http_brix_xrdhttp_filter_module.so";\n'
for f in $(grep -rl 'events {' tests/configs/); do
  grep -q 'ngx_stream_brix_module.so' "$f" || sed -i "1s|^|$LM|" "$f"
done
# sanity: the shared template now starts with the two load_module lines
head -3 tests/configs/nginx_shared.conf
```

> Re-running the loop is safe (the `grep -q` guard skips already-injected
> files). If you later `cp -r /usr/share/brix` again for a clean copy, re-run it.

**4. Point the fleet at the stock nginx and run.** The stock binary picks up the
injected `load_module` lines from the fleet config it is handed with `-c`:

```bash
export NGINX_BIN=/usr/sbin/nginx      # the stock nginx the RPM's module targets
export REF_BIN=xrootd                 # optional: reference XRootD for conformance lanes
PYTHONPATH=tests tests/run_suite.sh --fast
```

**Scope caveat for a *full* Path B run:** the `events {`-guarded loop covers the
main fleet and the standalone dedicated configs under `tests/configs/`. A small
number of slow-lane scenarios generate configs from other subtrees (e.g.
`tests/configs/multiuser/`); if a `--nightly`/full Path B run reports a lane
failing to start with `unknown directive "brix_*"`, widen the loop to that
subtree (`grep -rl 'events {' tests/configs/multiuser/`) and re-run. For an
authoritative full run, **Path A is the reliable choice** — Path B is best for
`--fast`/`--pr` validation of the packaged `.so`.

---

## Failure modes & fixes

| Symptom | Cause | Fix |
|---|---|---|
| `unknown directive "brix_root"` when the fleet starts | Module not in the fleet's nginx | Path A: rebuild with a non-empty `--add-module=$REPO`. Path B: run the §B.3 injection loop |
| `nginx binary not found/executable: …` | `NGINX_BIN` points nowhere | Export `NGINX_BIN` to your `objs/nginx` (A) or `/usr/sbin/nginx` (B) |
| Conformance/differential tests error, not skip | `REF_BIN` (`xrootd`) missing or wrong | Install the site XRootD RPM, or accept those lanes as skipped for a non-conformance check |
| GSI tests fail `No protocols left to try` | Stale zombie fleet was attached to, PKI not regenerated | The runner sets `TEST_OWN_FLEET=1`; if you invoked pytest directly, run `tests/manage_test_servers.sh stop-all` then use `run_suite.sh` |
| `Connection refused` on a test port | Another process holds the fixed port, or the fleet did not start | `ss -tlnp | grep 11094`; see [test-fleet-ports.md](../10-reference/test-fleet-ports.md) |
| Whole run aborts: "Different tests collected" / xdist workers crash | Box overloaded (`-n16` crashes workers; the shared fleet caps useful parallelism at `-n12`) | Let the box settle, re-run; the runner already caps at `-n12` |
| `kXR_FileLocked` / 30 s hangs after a crashed run | Orphaned workers or a dead FUSE mount from a prior run | `tests/manage_test_servers.sh stop-all`; `pkill -9 nginx`; see [troubleshooting-runbook.md](troubleshooting-runbook.md) |
| Manual/fleet dead right after a pytest run | A lane's teardown reaped the fleet | Re-start with `run_suite.sh` (own-fleet) or `manage_test_servers.sh start-all` |

For the symptom-indexed master runbook (worker stalls, lock poisoning, dead
FUSE mounts, configure-built-a-bare-nginx, port lookup), see
[troubleshooting-runbook.md](troubleshooting-runbook.md).

---

## See also

- [tests/README.md](../../tests/README.md) — the runner's lane design and flake-rerun rationale
- [upgrade-procedure.md](upgrade-procedure.md) — RPM layout, 2-`.so` load order, rollback
- [test-fleet-ports.md](../10-reference/test-fleet-ports.md) — the fixed-port registry
- [reload-semantics.md](../09-developer-guide/reload-semantics.md) — reload vs restart, drain behavior
- [contrib/brix-cache.conf.example](../../contrib/brix-cache.conf.example) — `worker_shutdown_timeout` vs `TimeoutStopSec` guidance
