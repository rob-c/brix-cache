# Deployment Hardening Guide

**Status:** Reference for operators and package maintainers.  Covers the
hardened systemd unit shipped in `packaging/nginx-xrootd.service`, the
kernel-enforced sandbox directives, and how they interact with the impersonate
broker's privilege model.  Also cross-references the build-side hardening that
is already on by default.

---

## 1. Quick-start

```bash
# Install the unit (do this once):
install -m 644 packaging/nginx-xrootd.service /etc/systemd/system/
systemctl daemon-reload

# Create the dedicated nginx config from the example:
cp /etc/nginx/conf.d/brix-cache.conf.example /etc/nginx/nginx-xrootd.conf
# Edit nginx-xrootd.conf; ensure the top-level block contains:
#   pid /run/nginx-xrootd.pid;

# Enable and start:
systemctl enable --now nginx-xrootd

# Verify the sandbox score after start:
systemd-analyze security nginx-xrootd.service
```

The unit controls the system nginx binary (`/usr/sbin/nginx`) running a
**dedicated configuration file** (`/etc/nginx/nginx-xrootd.conf`).  It is a
separate systemd service, not a drop-in for `nginx.service`, so a site running
stock nginx for other purposes keeps its own service untouched.

---

## 2. Build-side hardening (already on by default)

Before the runtime sandbox is even reached, the binary has compile-time
protections applied by the build system.

### nginx module (`config`)

The module's `config` script (lines 28–30) injects the following linker flags
when they are not already present in `NGX_LD_OPT`:

```
-Wl,-z,relro   — read-only relocations (partial RELRO on data segments)
-Wl,-z,now     — bind all symbols at load (full RELRO; makes GOT read-only)
-Wl,-z,noexecstack — mark the stack non-executable in the ELF PT_GNU_STACK
```

Together these give the shared module **full RELRO + BIND_NOW + NX stack**,
matching what the RPM `%{build_ldflags}` macro produces on AlmaLinux / RHEL.

The RPM build also threads `%{build_ldflags}` through the client Makefile
(`make -C client LDFLAGS="%{build_ldflags}"`), so the native client binaries
and the FUSE mount additionally get **Position-Independent Executable (PIE)**
(`-pie`) — the Makefile applies `-pie` on every production link target
(`LDFLAGS_PIE := -pie`).

### What these mean at runtime

| Flag | Protection |
|---|---|
| Full RELRO + BIND_NOW | GOT is locked read-only after startup; no GOT overwrite attacks |
| NX stack | Stack cannot be executed; classic shellcode injection fails |
| PIE | Binary loads at a randomised base address (ASLR); ROP gadgets are harder to target |

These are build-time invariants — operators do not need to configure anything
to get them.  An operator building from source (not RPM) gets full RELRO +
BIND_NOW automatically via the `config` script; PIE requires passing `-pie` via
`LDFLAGS` (the RPM does this; a manual build does not unless `LDFLAGS` is set).

---

## 3. systemd sandbox directives

Every directive in `packaging/nginx-xrootd.service` is explained below.  The
commentary focuses on **why it is safe** given the impersonate broker's
capability model and nginx's I/O pattern.

### 3.1 Impersonate broker capability model (prerequisite reading)

The impersonate feature (`brix_impersonation map;` in nginx.conf) lets the
gateway perform file I/O as the requesting user's OS identity.  The broker is a
privileged helper forked at startup and accessed by workers over a UNIX socket.

After forking, the broker does the following in `src/auth/impersonate/lifecycle.c`
and `src/auth/impersonate/broker_creds.c`:

1. Drops its real uid/gid to a non-root service account (`imp_drop_to_service_user`).
2. Retains only `CAP_SETUID | CAP_SETGID` in the permitted+effective sets via `capset(2)` (`imp_capset_setuid_setgid`).
3. On each per-request open, switches to the target uid/gid via `setfsuid(2)` / `setfsgid(2)`, performs the syscall, and restores.

Workers call `imp_worker_drop_caps()` immediately after fork, which clears all
capabilities (including `CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`) from
both the effective+permitted sets AND the bounding set.  A compromised worker
cannot regain the broker's privileges.

### 3.2 Capability bounding set

```ini
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
```

| Capability | Reason retained |
|---|---|
| `CAP_SETUID` | Broker's `setresuid` + `setfsuid` per-request impersonation |
| `CAP_SETGID` | Broker's `setresgid` + `setfsgid` per-request impersonation |
| `CAP_NET_BIND_SERVICE` | nginx master binds ports < 1024 (XRootD 1094, HTTPS 443) |

`CAP_DAC_OVERRIDE` is **not** retained.  The broker's `lifecycle.c` explicitly
lists it in `kill_caps[]` and drops it from the bounding set at startup.
Including it here would be inconsistent with how the broker actually operates.

**Tightening when impersonation is disabled:** if `brix_impersonation` is set
to `off` or the module is built without the impersonate component, remove the
first two capabilities:

```ini
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

**Tightening when all ports > 1023:** if all `listen` directives use ports above
1023 (e.g., 11094 for testing, 8443 for WebDAV, 9001 for S3), also remove
`CAP_NET_BIND_SERVICE`:

```ini
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
```

### 3.3 Privilege non-escalation

```ini
NoNewPrivileges=true
```

Prevents any child process from gaining privileges through a setuid/setgid
**binary** at `execve` or via **file capabilities**.  This does not affect the
broker's inline `capset(2)` + `setresuid(2)` calls — those operate on the
permitted set already held, which `PR_SET_NO_NEW_PRIVS` does not restrict.

The broker itself also calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` unconditionally in
`imp_lock_to_service_user()`, so even if this unit directive were absent the
broker would self-impose the same constraint.

### 3.4 Filesystem isolation

```ini
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/log/nginx /var/lib/nginx-xrootd /run
```

`ProtectSystem=strict` makes `/usr`, `/boot`, and `/etc` read-only in the
service's mount namespace.  nginx reads (never writes) its configuration and
TLS certificates from `/etc`; those paths only need read access.

`ProtectHome=true` blocks access to `/home`, `/root`, and `/run/user`.  If the
export root (`brix_export`) or stage
dir lives under `/home`, add it to `ReadWritePaths` and either change
`ProtectHome` to `read-only` (read access to the rest of `/home`) or `false`
(no restriction).

`PrivateTmp=true` gives the service its own `/tmp` and `/var/tmp` namespaces,
invisible to other processes and cleaned on exit.  Staged upload partials that
land in the default system `/tmp` are isolated from other users on the host.

`PrivateDevices=true` removes real device nodes (block devices, `/dev/sd*`,
tape drives) from the service's `/dev`.  nginx never opens raw devices; this
closes the class of "read-only access to block devices via /dev" attacks.

`ReadWritePaths` must cover every directory the service writes to at runtime:

| Path | What is written |
|---|---|
| `/var/log/nginx` | Access logs (`brix_access*.log`, WebDAV, S3) |
| `/var/lib/nginx-xrootd` | Export root + default upload stage dir |
| `/run` | PID file (`/run/nginx-xrootd.pid`), nginx lock files, broker UNIX socket |

Additional paths to add when needed:

```ini
ReadWritePaths=/var/log/nginx /var/lib/nginx-xrootd /run \
               /mnt/fastcache/xrd-stage \   # if brix_stage_dir points here
               /var/cache/nginx-xrootd       # if proxy_cache_path is configured
```

### 3.5 Syscall filter

```ini
SystemCallFilter=@system-service @setuid
SystemCallFilter=~@debug @mount @reboot @swap @obsolete
SystemCallArchitectures=native
```

The `@system-service` group is the standard baseline for long-running daemons
(covers `read`, `write`, `epoll`, `clock_gettime`, `mmap`, `futex`, etc.).

`@setuid` adds the process-identity calls the broker needs: `setresuid`,
`setresgid`, `setgroups`, `setfsuid`, `setfsgid`.  Without this group, the
broker cannot perform per-request impersonation.

The `~` prefix (blocklist) removes dangerous groups that nginx never uses:

| Blocked group | What it contains |
|---|---|
| `@debug` | `ptrace`, `perf_event_open` — unnecessary and exploitable |
| `@mount` | `mount`, `umount2` — not used |
| `@reboot` | `reboot`, `kexec_load` — not used |
| `@swap` | `swapon`, `swapoff` — not used |
| `@obsolete` | Old SysV/BSD calls — not used |

`SystemCallArchitectures=native` blocks 32-bit `int 0x80` system calls on
x86_64, closing a class of seccomp filter bypass gadgets.

**Tightening when impersonation is disabled:** remove `@setuid` from the
allowlist — nginx itself does not make setuid/setresuid calls at runtime once
its workers are forked:

```ini
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @reboot @swap @obsolete @setuid
```

### 3.6 Memory execution protection

```ini
MemoryDenyWriteExecute=true
```

Prevents `mmap(PROT_WRITE|PROT_EXEC)` and `mprotect` to `PROT_EXEC`.  nginx
does not JIT-compile anything, and neither does the xrootd module.

**CAVEAT — PCRE2 JIT:** if nginx was compiled with `--with-pcre-jit`, PCRE2's
JIT engine allocates W+X pages and the service will crash at the first regex
match.  Check with:

```bash
nginx -V 2>&1 | grep pcre-jit
```

If `--with-pcre-jit` appears, either rebuild nginx without it or disable this
directive:

```ini
MemoryDenyWriteExecute=false
```

The system nginx on AlmaLinux / RHEL 8–10 is compiled without `--with-pcre-jit`
by default, so this directive is safe in the standard RPM deployment.

### 3.7 Remaining directives

```ini
RestrictNamespaces=true
```
Blocks `clone(CLONE_NEWNS|CLONE_NEWUSER|...)` and `unshare` — namespace
creation is not part of nginx's runtime and unnecessarily enlarges the
container-escape surface.

```ini
RestrictRealtime=true
```
Prevents acquiring real-time scheduling policies (`SCHED_FIFO`, `SCHED_RR`).
The gateway uses the standard event-loop + thread-pool model with no real-time
requirements.

```ini
RestrictSUIDSGID=true
```
Prevents the service from creating files with the setuid or setgid **file bit**
set.  This does not restrict the broker's **process** identity transitions
(`setresuid`/`setresgid`), which are governed by `@setuid` syscall filter and
`CapabilityBoundingSet` — not by this directive.  It remains `true` because
the broker never creates setuid/setgid files.

```ini
LockPersonality=true
```
Prevents `personality(2)` calls that switch the system-call ABI.  Not used by
nginx; blocks a class of seccomp bypass gadgets on x86_64.

```ini
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```
Limits socket creation to the three families the gateway actually uses.
`AF_INET` + `AF_INET6` cover all wire protocols (root://, WebDAV, S3, CMS,
metrics).  `AF_UNIX` covers nginx worker-master IPC and the thread-pool pipe
pair.  Raw sockets, Netlink, and all other families are blocked.

```ini
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
```
Make `/proc/sys`, kernel module loading, and the cgroup filesystem read-only.
None of these are modified by nginx or the xrootd module at runtime.

---

## 4. Measuring the sandbox score

After installing the unit on a systemd host:

```bash
systemd-analyze security nginx-xrootd.service
```

A stock (unmodified) nginx.service on AlmaLinux 9 typically scores around
**exposure 9.6** (UNSAFE).  The hardened unit targets **exposure ≤ 2.5**
(OK/SAFE range) — most of the improvement comes from `ProtectSystem=strict`,
`PrivateTmp`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, and the syscall
filter.

The output is a per-directive table; any line showing "UNSAFE" or "EXPOSED"
that is not already covered by the directives in this unit is a site-specific
gap (e.g., a supplementary unit drop-in adds `AmbientCapabilities` that the
tool counts against the score).

---

## 5. Checklist for operators

### Mandatory adjustments before go-live

- [ ] Edit `/etc/nginx/nginx-xrootd.conf`; set `pid /run/nginx-xrootd.pid;` at
  the top level so the PID file matches `PIDFile=` in the unit.
- [ ] Set `ReadWritePaths` to cover the actual export root (`brix_export`),
  log directory, and stage directory for this deployment.
- [ ] If the export root is under `/home`, adjust `ProtectHome=` accordingly.

### Optional tightening (impersonation disabled)

- [ ] Remove `CAP_SETUID CAP_SETGID` from `CapabilityBoundingSet`.
- [ ] Remove `@setuid` from the `SystemCallFilter` allowlist and add it to the
  blocklist.
- [ ] Set `RestrictSUIDSGID=true` (already the default in the shipped unit).

### Optional tightening (all ports > 1023)

- [ ] Remove `CAP_NET_BIND_SERVICE` from `CapabilityBoundingSet`.

### PCRE2 JIT check

```bash
nginx -V 2>&1 | grep 'pcre-jit'
# If present: set MemoryDenyWriteExecute=false
```

---

## 6. Relationship to the stock nginx.service

Sites that run the module under the distribution-provided `nginx.service` (not
this dedicated unit) can still gain most of the sandbox benefits by placing the
directives in a drop-in:

```bash
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/brix-hardening.conf <<'EOF'
[Service]
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service @setuid
SystemCallFilter=~@debug @mount @reboot @swap @obsolete
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE
ReadWritePaths=/var/log/nginx /var/lib/nginx-xrootd /run
EOF
systemctl daemon-reload && systemctl restart nginx
```

Adjust `ReadWritePaths` and the capability set to match the site deployment
exactly as described in §3 above.
