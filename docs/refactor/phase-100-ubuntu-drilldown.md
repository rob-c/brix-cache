# Phase 100 — Ubuntu Drilldown: developing and testing BriX-Cache on Ubuntu 24.04

> Number collision: "phase 100" also names the (unrelated) metalink + extreme
> copy feature phase, `phase-100-metalink-and-extreme-copy.md`. Both keep the
> number; this note is the disambiguation.

**Status:** ✅ COMPLETE (2026-08-09) — environment reproduced end to end, the
findings below triaged, and every open one since resolved: the full Python
suite reached green on this box (see the port-ladder/orphan-reaper landing and
the suite burndown), and the krb5 tier now provisions and PASSES (§6.2
resolution note). · **Owner:** platform
**Depends on:** nothing; purely additive documentation plus the small
portability fixes listed in §5.
**Scope:** `docs/refactor/` (this file), and the already-landed portability
changes in `config`, `src/protocols/cvmfs/upstreams.c`,
`shared/cvmfs/**`, `client/apps/fs/xrootdfs.c`,
`tests/test_cvmfs_conformance_srv_geo.py`.

---

## 0. Motivation

Every developer-facing document in this tree assumes AlmaLinux/EL: the RPM
build, `dnf` package names, `/usr/lib64`, SELinux, firewalld. The project builds
and runs perfectly well on Ubuntu, but getting there the first time means
rediscovering a long tail of differences — several of which fail in ways that
look like *code* bugs rather than *environment* gaps.

This phase records that first pass in full: what to install, what to build, what
breaks, and — for each broken thing — whether it is Ubuntu's fault, the
environment's fault, or ours.

The companion operator-facing document is `BUILD_INSTALL.md` §1U, which covers
*installing and running* on Ubuntu. This file covers *developing and testing* on
it, which is a strictly larger problem: the test suite needs a stock XRootD
server, a second nginx built a different way, and 177 fixed TCP ports.

---

## 1. Reference environment

Everything below was reproduced on:

| Component | Version |
|---|---|
| OS | Ubuntu 24.04.4 LTS (noble) |
| Kernel | 6.18.6-WSL2-RT-STABLE+ (WSL2) |
| gcc | 13.3.0 |
| distribution nginx | 1.24.0-2ubuntu7.15 |
| vendored nginx (suite) | 1.28.3 (built from source, §3.3) |
| OpenSSL | 3.0.13 |
| libcurl | 8.5.0 |
| libfuse3 | 3.14.0 |
| stock XRootD server/client | 5.6.9 |
| Python | 3.12.3 |
| pyxrootd | 6.1.0 (pip, source build — §2.3) |
| pytest | 7.4.4 |

Two properties of this host matter enough to call out, because they cause
failures that look like product bugs:

* **`RLIMIT_NOFILE` hard limit is 1073741816** (2^30). See §4.1.
* It is **WSL2 with mirrored networking**, so TCP listeners from outside this
  distro's PID namespace occupy ports here. See §4.2.

---

## 2. Packages

### 2.1 Build the nginx module

```bash
sudo apt install -y build-essential dpkg-dev pkg-config \
    nginx libnginx-mod-stream

# Required — ./configure aborts without these
sudo apt install -y libssl-dev libpcre2-dev zlib1g-dev \
    libxml2-dev libjansson-dev libcurl4-openssl-dev

# Optional — auto-detected, silently skipped when absent
sudo apt install -y libkrb5-dev libsqlite3-dev libseccomp-dev \
    libzstd-dev liblzma-dev libbrotli-dev libbz2-dev liblz4-dev \
    librados-dev libradospp-dev libradosstriper-dev libcephfs-dev \
    liburing-dev
```

Runtime-only (`dlopen`ed, no headers needed):

```bash
sudo apt install -y libvomsapi1t64
```

### 2.2 Build the client tools and FUSE drivers

```bash
sudo apt install -y libfuse3-dev fuse3   # xrootdfs, brixMount, brixcvmfs
sudo apt install -y libradospp-dev       # C++ Ceph tools need rados/librados.hpp
```

### 2.3 Run the Python test suite

```bash
sudo apt install -y python3-pytest python3-pytest-timeout \
    python3-pytest-xdist python3-pytest-rerunfailures \
    python3-boto3 python3-botocore python3-brotli python3-zstandard \
    python3-xattr python3-crc32c python3-venv python3-dev python3-pip

# stock XRootD — the fleet's reference server, and xrdcp/xrdfs for the tests
sudo apt install -y xrootd-server xrootd-server-plugins \
    xrootd-client xrootd-client-plugins

# needed to build the pyxrootd bindings from source (see below)
sudo apt install -y cmake uuid-dev libssl-dev zlib1g-dev
```

External tools individual lanes probe for with `shutil.which`:

```bash
sudo apt install -y krb5-user krb5-kdc krb5-admin-server \
    haproxy attr unzip bubblewrap globus-gass-copy-progs \
    strace valgrind clang varnish voms-clients-java podman
```

### 2.4 The two Python packages apt cannot supply

| Package | Problem | Resolution |
|---|---|---|
| `xrootd` (pyxrootd) | `requirements.txt` pins `xrootd>=6.0.0,<7`; **Ubuntu 24.04 ships 5.6.9** (`python3-xrootd`), below the floor. There is no 6.x anywhere in apt. | `pip install 'xrootd>=6.0.0,<7'` — a **source build** of the full XRootD tree, needs `cmake`, `uuid-dev`, `libssl-dev`, `zlib1g-dev`, `python3-dev`. Took several minutes; produced 6.1.0. |
| `requests-aws4auth` | Not packaged for Ubuntu at all. | `pip install 'requests-aws4auth>=1.1,<2'` |

Ubuntu 24.04 enforces **PEP 668** (`externally-managed-environment`), so plain
`pip install` into the system interpreter is refused. Use a venv that can still
see the apt-installed modules:

```bash
python3 -m venv --system-site-packages ~/.venvs/brix
~/.venvs/brix/bin/pip install 'xrootd>=6.0.0,<7' 'requests-aws4auth>=1.1,<2'
```

`--system-site-packages` is the load-bearing flag: without it the venv cannot
see `python3-pytest`, `python3-boto3` and friends, and you end up pip-building
everything.

Verify with the repo's own guard:

```bash
python3 tools/ci/check_python_deps.py     # → check_python_deps: OK
```

> **Note on the stock server/client version.** The *daemon* and CLI stay at
> Ubuntu's 5.6.9 — only the Python bindings are rebuilt at 6.x. The suite drives
> the daemon over the wire, so the mismatch is fine; but a lane that asserts a
> 6.x-only server behaviour would need XRootD built from source too.

---

## 3. Builds

Developing on Ubuntu means building nginx **twice**, for two different
consumers. This is the single most confusing part of the setup.

### 3.1 Which build do I need?

| Consumer | Build | Produces |
|---|---|---|
| Running the module on this host, against the distro nginx | dynamic module, `--add-dynamic-module` | `objs/*.so` → `/usr/lib/nginx/modules` |
| **The Python test suite** | static, `--add-module`, vendored nginx 1.28.3 | `/tmp/nginx-1.28.3/objs/nginx` |

`tests/settings.py:107` hardcodes the default:

```python
NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
```

so the suite will not run against the distro-module build. Override
`TEST_NGINX_BIN` if you keep it elsewhere.

### 3.2 Dynamic module against the distribution nginx

Full walkthrough in `BUILD_INSTALL.md` §1U. Short form: the module must be
compiled with `--with-compat` from the **same nginx version** Ubuntu installed,
whose source comes from `apt-get source nginx` (enable `deb-src` first).

### 3.3 Static nginx for the suite

```bash
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
            --with-http_dav_module --with-http_v2_module \
            --with-threads --with-file-aio \
            --add-module=/path/to/brix-cache
make -j"$(nproc)"
```

Builds clean on gcc 13: 0 errors, 0 warnings.

### 3.4 Client tools

`client/Makefile` has a `proto` target but `all` does **not** depend on it, so a
bare `make -C client` on a clean tree dies with
`No rule to make target '../shared/xrdproto/libxrdproto.a'`. Build the shared
core first:

```bash
make -C shared/xrdproto -j"$(nproc)"
make -C client          -j"$(nproc)"
```

Produces 29 artifacts in `client/bin/`.

---

## 4. Environment traps

### 4.1 `RLIMIT_NOFILE` wedges the stock XRootD server

**Symptom.** Every fleet start fails with
`RuntimeError: server did not become ready on 127.0.0.1:11098`. The instance's
`xrootd.log` stops mid-initialisation, right after:

```
Config maximum number of connections restricted to 178956970
```

and the process neither exits nor listens.

**Cause.** XRootD sizes its connection table from `RLIMIT_NOFILE`. This host's
**hard** limit is 1073741816 (2^30); 1073741816 / 6 = 178956969. XRootD raises
itself to the hard limit and then tries to provision ~179 million connection
slots.

**Fix.** Cap the limit in the shell that launches the fleet — children inherit
it:

```bash
ulimit -n 65536
ulimit -Hn 65536
```

With that, the same binary and the same config reach
`------ xrootd anon@host:11098 initialization completed.` immediately.

This is **not** Ubuntu-specific in principle — any host with a huge hard
`nofile` hits it — but Ubuntu-on-WSL2 ships exactly such a limit by default,
where EL hosts typically do not.

### 4.2 Fixed fleet ports may already be taken

`tests/settings.py` allocates **177 fixed listen ports**, and
`tests/fleet_ports.py` bands them all into 8080–32499 with a hard invariant that
every one stays **below the ephemeral floor** (`net.ipv4.ip_local_port_range[0]`,
32768). There is no global port-offset knob — each port has its own `TEST_*`
environment override.

On this host 156 of the 177 were already bound, by sockets owned by uid 1000
with **no owning process visible in this PID namespace** — WSL2 mirrored
networking surfacing another distro's fleet. Because the band invariant forbids
relocating them upward, and only 21 ports were free, per-port overrides were not
viable.

**Resolution: run the fleet and the suite in a private network namespace.**
Every port is free there, and nothing outside is disturbed:

```bash
sudo ip netns add brixtest
sudo ip netns exec brixtest ip link set lo up

# fleet
sudo ip netns exec brixtest python3 -m cmdscripts.manage_test_servers start-all
# suite
sudo ip netns exec brixtest python3 -m pytest tests/ ...
```

The suite is entirely loopback-based, so the namespace costs nothing. Only `lo`
exists inside it, so any lane needing outbound internet will fail there —
none were observed to.

### 4.3 Starting the fleet

```bash
cd tests
ulimit -n 65536; ulimit -Hn 65536
ip netns exec brixtest python3 -m cmdscripts.manage_test_servers start-all
```

Result on this host: **126 fleet instances launched**, 212 listeners. One
non-critical spec did not start — see §6.

---

## 5. Source changes this drilldown produced

All landed; listed here so the doc is a complete account.

| Change | Why Ubuntu forced it |
|---|---|
| `config` — probe before adding `-D_FORTIFY_SOURCE=2` | Ubuntu's nginx passes `-D_FORTIFY_SOURCE=3` via `--with-cc-opt`; two conflicting `-D` on one command line is a redefinition, and nginx builds with `-Werror`. |
| `src/protocols/cvmfs/upstreams.c` — format from a local buffer | gcc 13 at `-O3` with `_FORTIFY_SOURCE=3` rejects `snprintf`ing between two members of one struct (`-Werror=restrict`). |
| `src/**`, `client/apps/fs/brixcvmfs_transport.c` — libcurl guards | libcurl 8.5 deprecates `CURLOPT_PROTOCOLS`/`CURLINFO_CONTENT_LENGTH_DOWNLOAD`. Fixed upstream in `233f92977` with `CURL_AT_LEAST_VERSION`; `tools/ci/check_curl_enum_ifdef.py` now guards the `#ifdef`-an-enum mistake. |
| `shared/cvmfs/**` — per-object landing buffers | Not Ubuntu-specific, but found here: objects over 8 MiB were unreadable. |
| `client/apps/fs/xrootdfs.c` — daemonize before thread creation | Not Ubuntu-specific: the default (non-`-f`) mount hung on first read. |
| `tests/test_cvmfs_conformance_srv_geo.py` — fixed UUID in `parametrize` | See §6.1 — blocks **all** parallel runs, on any platform. |

---

## 6. Test-suite findings

### 6.1 Non-deterministic `parametrize` breaks every parallel run

**Symptom.** Any `pytest -n N` run aborts during collection, before a single
test executes:

```
ERROR collecting gw7
Different tests were collected between gw0 and gw7. The difference is:
-tests/test_cvmfs_conformance_srv_geo.py::test_rtt_caller_id_variants[53eecca7-...]
+tests/test_cvmfs_conformance_srv_geo.py::test_rtt_caller_id_variants[b38172d9-...]
```

**Cause.** `tests/test_cvmfs_conformance_srv_geo.py` parametrized a case with
`str(uuid.uuid4())`, evaluated at import time. Each xdist worker is a separate
process, so each generates a different id, and pytest-xdist requires every
worker to collect an identical test list.

**Scope.** Platform-independent — this breaks `-n` on EL just as thoroughly. It
survived because the documented CI lane and the local habit are serial.

**Fix (landed).** Replaced with a fixed opaque UUID literal; the case only ever
needed "an arbitrary opaque caller id". `import uuid` dropped as now-unused.
This was the *only* such site in the suite — a sweep for `uuid4`, `random.`,
`time()` and `os.getpid` inside `parametrize` found no others.

### 6.2 `krb5` fleet spec does not start

**Resolved (2026-08-09):** `krb5-kdc`, `krb5-admin-server` and `krb5-user` are
installed per §2.3, `kdc_helpers` produces the keytab, and the spec starts —
KDC (11117) and acceptor nginx (11116) both listening, `test_krb5_auth.py`
5/5 PASSED (no skips). The `/dev/shm/brix-creds` uid-33 wart below persists
until removed with root; it is warn-only and the tier runs regardless.

Original finding — non-critical; the fleet continues without it and reports:

```
[registry] non-critical spec 'krb5' did not start ...
nginx: [emerg] brix: cannot read krb5 keytab:
  Key table file '/tmp/xrd-test/krb5/xrootd.keytab' not found
```

The keytab is produced by `tests/kdc_helpers.py`, which needs a local KDC —
`krb5kdc` and `kadmind`, i.e. the `krb5-kdc` and `krb5-admin-server` packages.
Neither is installed by default on Ubuntu. Install them (§2.3) before starting
the fleet if you need the Kerberos lanes.

A second, softer warning appears on the same spec and is worth knowing:

```
nginx: [warn] brix: credential store "/dev/shm/brix-creds" is owned by uid 33
  but the workers run as uid 65534
```

— an artefact of the distro nginx having run first as `www-data` (uid 33) and
left the store behind, while the suite's nginx drops to `nobody` (uid 65534).
Remove `/dev/shm/brix-creds` between the two.

### 6.3 External tools the suite probes for

Lanes self-skip when their tool is absent, so a bare Ubuntu box quietly skips a
large amount rather than failing. Present by default after §2: `gcc`, `cc`,
`openssl`, `curl`, `pkg-config`, `rsync`, `fusermount3`, `xrdcp`, `xrdfs`,
`xrootd`, `xrdpfc_print`.

Absent by default, each gating at least one lane:

| Tool | Package | Notes |
|---|---|---|
| `kinit` | `krb5-user` | Kerberos client lanes |
| `krb5kdc`, `kadmind` | `krb5-kdc`, `krb5-admin-server` | the `krb5` fleet spec (§6.2) |
| `haproxy` | `haproxy` | HA / failover topology |
| `getfattr` | `attr` | xattr conformance |
| `globus-url-copy` | `globus-gass-copy-progs` | GridFTP interop |
| `bwrap` | `bubblewrap` | sandboxed lanes |
| `unzip` | `unzip` | zip/archive lanes |
| `strace`, `valgrind`, `clang` | same names | diagnostic / analysis lanes |
| `varnishd` | `varnish` | cache-interop lane |
| `voms-proxy-fake` | `voms-clients-java` | VOMS attribute lanes |
| `podman` | `podman` | container lanes (`docker` present here) |
| **`cvmfs2`** | **not packaged for Ubuntu** | needs the CernVM apt repo; the official CVMFS client is not in the Ubuntu archive |

---

## 7. Reproducing this from scratch

The whole path, in order, on a clean Ubuntu 24.04 box:

```bash
# 1. packages (§2)
sudo apt update && sudo apt install -y \
    build-essential dpkg-dev pkg-config cmake uuid-dev \
    nginx libnginx-mod-stream \
    libssl-dev libpcre2-dev zlib1g-dev libxml2-dev libjansson-dev \
    libcurl4-openssl-dev libkrb5-dev libsqlite3-dev libseccomp-dev \
    libzstd-dev liblzma-dev libbrotli-dev libbz2-dev liblz4-dev \
    librados-dev libradospp-dev libradosstriper-dev libcephfs-dev \
    liburing-dev libfuse3-dev fuse3 libvomsapi1t64 \
    xrootd-server xrootd-server-plugins xrootd-client xrootd-client-plugins \
    python3-pytest python3-pytest-timeout python3-pytest-xdist \
    python3-pytest-rerunfailures python3-boto3 python3-botocore \
    python3-brotli python3-zstandard python3-xattr python3-crc32c \
    python3-venv python3-dev python3-pip \
    krb5-user krb5-kdc krb5-admin-server haproxy attr unzip bubblewrap

# 2. the two pip-only Python packages (§2.4)
python3 -m venv --system-site-packages ~/.venvs/brix
~/.venvs/brix/bin/pip install 'xrootd>=6.0.0,<7' 'requests-aws4auth>=1.1,<2'

# 3. the suite's nginx (§3.3)
cd /tmp && curl -O https://nginx.org/download/nginx-1.28.3.tar.gz \
  && tar xzf nginx-1.28.3.tar.gz && cd nginx-1.28.3 \
  && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
                 --with-http_dav_module --with-http_v2_module \
                 --with-threads --with-file-aio --add-module=$REPO \
  && make -j"$(nproc)"

# 4. the client tools (§3.4)
make -C $REPO/shared/xrdproto -j"$(nproc)"
make -C $REPO/client          -j"$(nproc)"

# 5. environment (§4.1, §4.2)
ulimit -n 65536; ulimit -Hn 65536
sudo ip netns add brixtest && sudo ip netns exec brixtest ip link set lo up

# 6. fleet + suite
cd $REPO/tests
sudo ip netns exec brixtest ~/.venvs/brix/bin/python \
     -m cmdscripts.manage_test_servers start-all
cd $REPO
TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests sudo ip netns exec brixtest \
    ~/.venvs/brix/bin/python -m pytest tests/ -n 8 --dist loadgroup -q
```

Steps 5's `netns` is only needed when the fixed ports are already occupied
(§4.2); on a box that owns its own ports, drop every `ip netns exec` prefix.

