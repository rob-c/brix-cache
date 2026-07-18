# SELinux Hardening for BriX-Cache Deployments

**Audience:** experienced sysadmins who have never used SELinux. You know
Unix permissions, systemd, packet filters, and how a grid storage endpoint
gets attacked. This document explains what SELinux adds on top of all of
that, exactly how the shipped `nginx-mod-brix-cache-selinux` package confines
a BriX-Cache gateway, and how to operate, extend, and debug the policy
without ever typing `setenforce 0`.

Related: the systemd sandbox that stacks underneath this —
[deployment-hardening](../09-developer-guide/deployment-hardening.md); the
policy source lives in `packaging/selinux/brix.{te,fc,if}`.

---

## 1. Why you should care: what DAC cannot do for you

Everything you normally use to lock down a server — file modes, ownership,
groups, `umask` — is **Discretionary Access Control (DAC)**. "Discretionary"
means the *owner* of a resource decides who may touch it, and any process
running as that owner inherits every one of those decisions.

Now consider what a BriX-Cache gateway actually is: a long-running network
daemon that

- parses **five different wire protocols** (root://, WebDAV/HTTP, S3, CMS,
  Prometheus scrape) from the open internet or at least the WLCG,
- terminates TLS with grid X.509 proxy chains and VOMS extensions (complex
  parsing of attacker-supplied ASN.1),
- validates bearer tokens,
- writes attacker-named files into an export tree,
- holds the host's private key in memory,
- and on multiuser sites switches process identity per request via the
  impersonation broker.

If any one parser has a memory-corruption bug and an attacker turns it into
code execution inside an nginx worker, DAC gives you exactly one boundary:
"the worker runs as the `nginx` user". That user can still:

- read every world-readable file on the host (`/etc/passwd`, most of
  `/etc`, other services' configs and leaked secrets),
- open outbound TCP connections to *anywhere* — exfiltrate data, join a
  botnet, pivot to your batch system or database,
- execute `/usr/bin/python3`, `/usr/bin/ssh`, or a dropped binary in `/tmp`,
- read or trash anything else owned by or readable to `nginx` — including
  the stock web server's content on a shared host,
- probe every local UNIX socket and every localhost-only service.

**Mandatory Access Control (MAC)** — which is what SELinux implements —
removes the "discretionary" part. A system-wide policy, written by the
distribution and extended by packages like ours, decides what each *process*
may do with each *resource*, and the process owner cannot override it. Even
uid 0 is constrained: `root` inside a confined domain is not the `root` you
are used to.

The practical consequence for BriX-Cache: **a fully compromised nginx worker
on an enforcing host can read/write the export tree and the cache tree, talk
to the ports the policy names, and essentially nothing else.** The blast
radius shrinks from "the whole host as user nginx" to "the data the gateway
already serves".

That is the entire pitch. The rest of this document is mechanics.

---

## 2. SELinux in one page (the mental model)

Four ideas cover 95 % of daily operation:

### 2.1 Everything has a label

Every process and every kernel object (file, directory, socket, TCP port,
shared memory segment, …) carries a **security context**, a string of four
colon-separated fields:

```
system_u : object_r : httpd_t : s0
  user       role      type    level
```

For server administration on the default **targeted** policy you can ignore
the user, role, and level fields almost entirely. **The type (third field,
always ending in `_t`) is the thing.** This model is called Type
Enforcement (TE).

See labels with `-Z`, which nearly every core utility grew:

```console
$ ls -Z /var/lib/brix-cache/data
system_u:object_r:brix_var_lib_t:s0 file1.root

$ ps -eZ | grep nginx
system_u:system_r:httpd_t:s0    31337 ?  00:00:04 nginx

$ ss -tlnZ | grep 1094
LISTEN 0 511 *:1094 *:* users:(("nginx",pid=31337,proc_ctx=system_u:system_r:httpd_t:s0,fd=12))
```

A process's type is called its **domain**. nginx — and therefore every BriX
module, because dynamic modules run inside the nginx processes — runs in the
`httpd_t` domain.

### 2.2 Everything is denied unless a rule allows it

Policy is a large set of whitelist rules of the form:

```
allow <domain> <type> : <object class> { <permissions> };
```

e.g. from our shipped module:

```
allow httpd_t brix_port_t:tcp_socket { name_bind name_connect };
```

"A process in domain `httpd_t` may bind and connect TCP sockets to ports
labelled `brix_port_t`." No rule → denied → the syscall fails with `EACCES`
or `EPERM` **and** the kernel logs an AVC record (§7). The application just
sees a permission error; it does not know SELinux was the reason.

Crucially, this check happens **after** DAC. SELinux can only ever remove
access, never grant something file modes forbid. Your existing permission
discipline keeps working unchanged.

### 2.3 Labels come from the policy, not from you (mostly)

File labels are assigned from a database of path-regex → context mappings
(*file contexts*). Our package registers, among others:

```
/var/lib/brix-cache(/.*)?    system_u:object_r:brix_var_lib_t:s0
/etc/grid-security(/.*)?     system_u:object_r:cert_t:s0
```

New files inherit a label from their parent directory at creation time.
`restorecon -Rv <path>` re-applies the database to a tree; `matchpathcon
<path>` shows what the database *thinks* a path should be without changing
anything. The two classic footguns:

- **`mv` preserves labels, `cp` inherits them.** If you `mv` a file from
  `/root` into the export tree it keeps its old label (`admin_home_t`) and
  the gateway gets `EACCES` on it. Fix: `restorecon -Rv /var/lib/brix-cache`.
- **Data on a path the database doesn't know** keeps a generic label
  (`default_t`, `var_t`, …) that `httpd_t` cannot touch. Fix: register the
  path (§6.1), then `restorecon`.

### 2.4 Three modes

| Mode | Checks evaluated | Denials enforced | Use |
|---|---|---|---|
| `enforcing` | yes | yes | production |
| `permissive` | yes (logged) | **no** | debugging / dry-run |
| `disabled` | no | no | don't. Relabeling on re-enable is expensive |

`getenforce` shows the mode; `setenforce 0/1` flips between enforcing and
permissive **at runtime** (survives until reboot); `/etc/selinux/config`
sets the boot default. Permissive mode is your friend during bring-up: the
system behaves as if SELinux were off, but every would-be denial is logged,
so you can collect and review the complete set before enforcing. Even
better, §7.4 shows how to make *only* the gateway permissive while the rest
of the host stays enforcing.

---

## 3. What the shipped policy module does

Installing `nginx-mod-brix-cache` on a host that has `selinux-policy-targeted`
automatically pulls in `nginx-mod-brix-cache-selinux` (a rich RPM dependency
— on a SELinux-less host it is simply skipped). That subpackage loads a
policy module named `brix` at priority 200 and registers the port labels.
There is nothing to enable by hand.

Design decision worth understanding: the module does **not** invent a new
domain for the gateway. nginx already runs confined as `httpd_t` under the
targeted policy, with two decades of distro-maintained rules for the
webserver-shaped things it does (read config from `/etc/nginx`, write
`/var/log/nginx`, bind `http_port_t`, use the network). Our module *extends*
`httpd_t` with exactly the BriX data plane and nothing else — no broad
booleans, no `audit2allow` residue, no permissive domains.

### 3.1 New types

| Type | What it labels | Why it exists |
|---|---|---|
| `brix_port_t` | TCP 1094, 1095 (root:// cleartext/TLS), 9001 (S3), 9100 (metrics) | so `httpd_t` can bind *these* ports without being allowed every unreserved port |
| `brix_var_lib_t` | `/var/lib/brix-cache` — export root + stage dir (legacy `/var/lib/nginx-xrootd` stays labelled too) | the gateway's writable data, distinct from generic web content |
| `brix_cache_t` | `/var/cache/brix-cache` (+ legacy spelling) | cache/fill tier, separable onto scratch storage |

Two existing types are reused rather than duplicated:

| Existing type | Applied to | Note |
|---|---|---|
| `httpd_config_t` | `/etc/brix-cache` (JWKS, authdb, …) | read-only to `httpd_t`, like the rest of the nginx config |
| `cert_t` | `/etc/grid-security` (hostcert/hostkey, IGTF CAs, CRLs, vomsdir) | `httpd_t` may read `cert_t` out of the box; this replaces the manual `semanage fcontext` step older BriX docs prescribed |

### 3.2 Rules added to `httpd_t`

| Capability the gateway needs | Rule (simplified) |
|---|---|
| Listen on root://, S3, metrics ports; dial cache/stage-tier origins and native-TPC peers on 1094 | `allow httpd_t brix_port_t:tcp_socket { name_bind name_connect }` |
| Full ownership of export/stage/cache trees, incl. `mmap` (checksum-at-rest, xmeta) | `manage_*_pattern(httpd_t, brix_var_lib_t …)` + `file map`; same for `brix_cache_t` |
| Impersonation broker: per-request `setresuid`/`setresgid`, `capset()` shed at startup | `self:capability { setuid setgid }` + `self:process setcap` |
| Multiuser ownership: chown staged uploads to the mapped grid user, serve per-user `0700` trees while the worker is still uid `nginx` | `self:capability { chown fowner fsetid dac_override dac_read_search }` |
| Read grid credentials | `miscfiles_read_generic_certs` (`cert_t`) |
| WebDAV HTTP-TPC and https origins (443/8443) | connect to `http_port_t` |
| Kerberos against the site KDC | connect to kerberos ports |
| Ceph backends (`sd_ceph`/`sd_cephfs_ro`): mon 3300/6789, OSD/MDS 6800–7300 | connect to `ceph_port_t`, wrapped in `optional_policy` — applies only where the ceph policy module exists (it is absent from a stock EL9; see §6.2) |
| WebDAV TPC fork/execs `curl(1)` | `corecmd_exec_bin` — curl stays **in** `httpd_t` (no domain transition), so it is bound by the same connect rules |

Ports 443 and 8443 (WebDAV) need nothing: the stock policy already labels
them `http_port_t`.

Two stock port assignments collide with BriX defaults: tcp 9001 is
`tor_port_t` and tcp 9100 is `hplip_port_t` in the distribution policy. The
RPM `%post` resolves this with local overrides (`semanage port -m`), and the
`%postun` on erase reverts them. You will see them in `semanage port -l`:

```console
$ semanage port -l | grep brix
brix_port_t      tcp   9100, 9001, 1095, 1094
```

### 3.3 What is deliberately NOT allowed

This is the security payoff — a compromised worker on an enforcing host
still **cannot**:

- read `/etc/shadow`, `/root`, `/home/*`, other daemons' state under
  `/var/lib/*` (wrong types: `shadow_t`, `admin_home_t`, `user_home_t`, …),
- write anywhere outside `brix_var_lib_t` / `brix_cache_t` / nginx's own
  log+runtime types — not even `/tmp` beyond what `httpd_t` is granted,
- connect to arbitrary TCP ports: your database (`postgresql_port_t`), an
  SSH pivot (`ssh_port_t`), SMTP for spam (`smtp_port_t`), a random
  high-port C2 channel (`unreserved_port_t`) are all unlabeled-for-httpd
  and denied,
- execute a payload it just wrote (files it can create are
  `brix_var_lib_t`/`brix_cache_t`, and no rule grants `execute` on those),
- `ptrace` other processes, load kernel modules, or write kernel tunables,
- use capabilities beyond the enumerated set — no `CAP_NET_RAW`, no
  `CAP_SYS_ADMIN`, no `CAP_NET_BIND_SERVICE` shenanigans on ports the policy
  doesn't name.

Also deliberately omitted: the `io_uring` rules. The io_uring backends are
strictly opt-in (`brix_io_uring on`, default OFF), and the `io_uring` object
class does not exist in the EL8 base policy, so shipping the rules would
break the EL8 module build. Opt-in sites load a two-line local module — see
the note at the bottom of `packaging/selinux/brix.te` and §6.3.

### 3.4 How this stacks with the systemd sandbox

The shipped hardened unit (`packaging/brix-cache.service`) and SELinux are
independent kernel mechanisms that overlap on purpose; either one still
holds if the other is misconfigured or bypassed:

| Threat | systemd unit | SELinux |
|---|---|---|
| write outside data dirs | `ProtectSystem=strict` + `ReadWritePaths` | type enforcement on `brix_var_lib_t`/`brix_cache_t` |
| privilege escalation via setuid binaries | `NoNewPrivileges=yes` | no `setuid` file execution rules in `httpd_t` |
| raw capability abuse | `CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE` | `self:capability` limited to the enumerated set |
| exotic syscalls | seccomp `SystemCallFilter` | n/a (SELinux is not a syscall filter) |
| arbitrary outbound connections | n/a (no egress control in the unit) | **only SELinux covers this** — port-type `name_connect` |
| cross-service data access | partial (`ProtectHome`, `PrivateTmp`) | full — every other service's data has a different type |

Defense in depth is not redundancy; the two columns fail independently.

---

## 4. Rollout runbook: from fresh host to enforcing

Assume EL9 (Alma/Rocky/RHEL), packages built from this repo, SELinux never
consciously used before.

### Step 0 — verify the substrate

```console
$ sestatus
SELinux status:                 enabled
Loaded policy name:             targeted
Current mode:                   enforcing        # or permissive — both fine for now
```

If it says `disabled`, set `SELINUX=permissive` in `/etc/selinux/config`,
`touch /.autorelabel`, reboot (the relabel pass takes minutes), and come
back. Never jump from `disabled` straight to `enforcing`.

### Step 1 — install; confirm the policy landed

```console
$ dnf install -y ./nginx-mod-brix-cache-*.rpm
$ rpm -q nginx-mod-brix-cache-selinux           # pulled in automatically
$ semodule -l | grep brix
brix
$ semanage port -l | grep brix_port_t
brix_port_t                    tcp      9100, 9001, 1095, 1094
```

Or let the shipped verification suite do all of Step 1's checks (and more —
on-disk labels, label inheritance, and every `httpd_t` allow rule from
`brix.te`) in one shot, as root:

```console
$ dnf install -y brix-cache-tests libselinux-utils policycoreutils-python-utils setools-console
$ cd /usr/share/brix && python3 -m pytest tests/test_selinux_rpm.py -v
```

The suite self-skips without root, without SELinux, or without the policy
module, so a failing assertion always means a real gap between the loaded
policy/labels and what the RPM was supposed to install.

### Step 2 — put data and config where the labels are (or teach the labels)

Defaults that Just Work: export root under `/var/lib/brix-cache` (the RPM
ships it, `0750 nginx:nginx`, correctly labelled), JWKS/authdb under
`/etc/brix-cache`, grid credentials under `/etc/grid-security`.

Anything else — say the export root is a 400 TB filesystem mounted at
`/data/atlas` and the stage dir is `/mnt/fastcache/xrd-stage`:

```console
$ semanage fcontext -a -t brix_var_lib_t '/data/atlas(/.*)?'
$ semanage fcontext -a -t brix_var_lib_t '/mnt/fastcache/xrd-stage(/.*)?'
$ restorecon -Rv /data/atlas /mnt/fastcache/xrd-stage
```

(`semanage fcontext` writes the rule into the local database — persistent,
survives relabels and upgrades. `chcon` changes a label directly on the
inode — it does *not* survive a `restorecon` and has no place in a runbook;
if you see `chcon` in a wiki recipe, mentally replace it.)

Extra listener ports (a second root:// endpoint on 1096, a CMS listener):

```console
$ semanage port -a -t brix_port_t -p tcp 1096
```

### Step 3 — dry-run in permissive, exercise everything

```console
$ setenforce 0            # temporary; /etc/selinux/config still says enforcing
$ systemctl start brix-cache
```

Now run a **complete** workload rehearsal — this is the part sites skip and
regret: root:// read + write, a WebDAV PUT/GET/COPY (TPC both push and
pull), an S3 upload, a token-authenticated and an X.509-authenticated
request, a metrics scrape, a cache fill from the origin, and if configured,
a multiuser impersonated write and a Ceph-backend transfer. Then:

```console
$ ausearch -m AVC -ts recent
<no matches>
```

`<no matches>` is the goal. If there are denials, each one means a path or
port the policy doesn't know about — nearly always your site-specific
layout from Step 2 being incomplete. Fix with §6/§7, re-test, repeat until
silent.

### Step 4 — enforce

```console
$ setenforce 1
$ getenforce
Enforcing
```

Re-run the same rehearsal once more under enforcement. Done. Add
`ausearch -m AVC -ts today | wc -l` to your monitoring — a gateway that was
silent and suddenly produces AVCs is either being attacked or was just
reconfigured without re-reading this document; both are worth an alert.

---

## 5. Verifying the confinement is real (5-minute audit)

Worth running once after rollout, and after any major upgrade:

```console
# 1. The gateway actually runs confined:
$ ps -eZ | grep nginx | awk '{print $1}' | sort -u
system_u:system_r:httpd_t:s0

# 2. The data tree is labelled:
$ ls -dZ /var/lib/brix-cache /var/lib/brix-cache/data
system_u:object_r:brix_var_lib_t:s0 ...

# 3. Labels match the database (no drift):
$ restorecon -Rnv /var/lib/brix-cache /etc/grid-security   # -n = dry-run
<no output = no drift>

# 4. Negative test — enforcement actually bites.  As root, in httpd_t's
#    shoes via runcon; both must FAIL with Permission denied:
$ runcon -t httpd_t -- cat /etc/shadow
runcon: ... Permission denied
$ runcon -t httpd_t -- bash -c 'echo pwn > /root/x'
bash: /root/x: Permission denied
```

That last pair is the whole point of the exercise, demonstrated: uid 0,
wrong domain, no access.

---

## 6. Site customisation catalogue

### 6.1 Non-default paths

Covered in Step 2 above. General form:

```console
semanage fcontext -a -t <type> '<path-regex>(/.*)?'
restorecon -Rv <path>
```

`brix_var_lib_t` for anything the gateway must read **and write** (export
roots, stage dirs), `brix_cache_t` for cache tiers. To review or undo:
`semanage fcontext -l -C` (list local rules), `semanage fcontext -d '<regex>'`.

NFS/GPFS/Lustre caveat: network filesystems often mount with a single
per-mount label (`nfs_t`). Either mount with an explicit context —
`mount -o context=system_u:object_r:brix_var_lib_t:s0 …` — or, for NFS with
`security_label` support, label server-side and export normally. Check what
you actually got with `ls -dZ` on the mountpoint before debugging anything
else.

### 6.2 Ceph backends on a host without the ceph policy module

The shipped rule allowing `httpd_t → ceph_port_t` only takes effect where
`ceph_port_t` exists (Ceph server/SIG policy installed). On a stock EL9
gateway that merely *talks to* an external Ceph cluster, mon/OSD ports are
plain `unreserved_port_t`; label them:

```console
$ semanage port -a -t brix_port_t -p tcp 3300
$ semanage port -a -t brix_port_t -p tcp 6789
$ semanage port -a -t brix_port_t -p tcp 6800-7300
```

### 6.3 io_uring opt-in (EL9+)

Only if you set `brix_io_uring on` after platform validation. Create
`brix-uring.te`:

```
policy_module(brix-uring, 1.0.0)
gen_require(` type httpd_t; ')
allow httpd_t self:io_uring sqpoll;
allow httpd_t self:anon_inode { create map read write };
```

```console
$ make -f /usr/share/selinux/devel/Makefile brix-uring.pp   # needs selinux-policy-devel
$ semodule -i brix-uring.pp
```

### 6.4 TPC to origins on exotic ports

Outbound is restricted too (that's a feature). If a partner site serves
WebDAV on, say, 2880: `semanage port -a -t brix_port_t -p tcp 2880` — or if
it should be treated as generic web traffic, add it to `http_port_t`
instead. Resist the nuclear option (`setsebool -P httpd_can_network_connect
on`): it authorises `httpd_t` to connect *everywhere* and deletes the entire
egress-containment benefit of §3.3.

### 6.5 Things to refuse in code review of your own runbooks

| Anti-pattern | Why | Instead |
|---|---|---|
| `setenforce 0` "to fix" an outage | disables containment host-wide, hides the actual bug | §7.4 per-domain permissive |
| `SELINUX=disabled` | full relabel needed to come back; zero protection meanwhile | permissive if you must |
| `chcon` in provisioning scripts | silently reverted by any relabel | `semanage fcontext` + `restorecon` |
| `setsebool -P httpd_unified on`, `httpd_can_network_connect on` | blanket grants across every httpd_t service on the host | targeted port/path rules as above |
| blind `audit2allow -M mypol && semodule -i` | converts *whatever just happened* — including an attack — into permanent policy | read the AVC first (§7.2), prefer labels over new allow rules |

---

## 7. Reading denials and debugging like it's 2026

### 7.1 Where denials go

Every enforced (or permissive-logged) denial produces an **AVC** (Access
Vector Cache) record in the audit log:

```console
$ ausearch -m AVC -ts recent          # last 10 minutes
$ ausearch -m AVC -ts today -c nginx  # by command name
```

If a syscall fails with `EACCES`/`EPERM` and `ausearch` shows nothing,
check for *dontaudit* suppression: `semodule -DB` disables dontaudit rules
(re-enable with `semodule -B`). Rare, but it exists.

### 7.2 Anatomy of an AVC

```
type=AVC msg=audit(1789124631.337:4207): avc:  denied  { write } for
  pid=31337 comm="nginx" name="f.root" dev="dm-3" ino=8675309
  scontext=system_u:system_r:httpd_t:s0
  tcontext=unconfined_u:object_r:default_t:s0
  tclass=file permissive=0
```

Read it as a sentence: *process* (`scontext` = `httpd_t`, comm `nginx`)
was denied *permission* (`write`) on *object* (`tcontext` = `default_t`,
class `file`, name `f.root`).

The diagnosis is almost always in `tcontext`:

| `tcontext` type says | Meaning | Fix |
|---|---|---|
| `default_t`, `var_t`, `unlabeled_t` | path unknown to the label database | §6.1: `semanage fcontext` + `restorecon` |
| `admin_home_t`, `user_home_t`, `tmp_t` | file was `mv`ed / created somewhere else | `restorecon -Rv` the tree |
| `nfs_t` | unlabelled network mount | `context=` mount option (§6.1) |
| some `*_port_t` on `tclass=tcp_socket` | port not granted to `httpd_t` | `semanage port -a -t brix_port_t …` (§6.4) |
| a sensible type but a weird permission | possibly a genuine gap — or a genuine attack | think before allowing; ask upstream |

`sealert` (from `setroubleshoot-server`) will produce a prose explanation of
any AVC if you prefer: `sealert -a /var/log/audit/audit.log`.

### 7.3 `audit2allow` — as a *reading* aid

```console
$ ausearch -m AVC -ts recent | audit2allow
#============= httpd_t ==============
allow httpd_t default_t:file write;
```

This tells you compactly what rule *would* silence the denial — which is
usually exactly the wrong fix (`default_t` means "fix the label", not
"allow writing to unlabelled files"). Generate-and-load
(`audit2allow -M`) is a last resort for a verified functional gap, ideally
followed by a bug report to this repo so the shipped module grows the rule
properly.

### 7.4 Debugging without dropping the shield: per-domain permissive

The single most useful trick in this document. Instead of `setenforce 0`
(host-wide), make *only* the gateway's domain permissive:

```console
$ semanage permissive -a httpd_t     # gateway unconstrained-but-logged;
                                     # everything else stays enforcing
... reproduce, collect ausearch output, fix labels/ports ...
$ semanage permissive -d httpd_t     # re-arm
```

### 7.5 Quick reference card

| Task | Command |
|---|---|
| current mode | `getenforce` / `sestatus` |
| flip mode (runtime) | `setenforce 0` / `setenforce 1` |
| recent denials | `ausearch -m AVC -ts recent` |
| explain denials | `sealert -a /var/log/audit/audit.log` |
| what a path *should* be | `matchpathcon /path` |
| fix labels under a tree | `restorecon -Rv /path` |
| add a path rule | `semanage fcontext -a -t TYPE '/path(/.*)?'` |
| add a port | `semanage port -a -t brix_port_t -p tcp N` |
| list local customisations | `semanage fcontext -l -C` ; `semanage port -l -C` |
| loaded modules | `semodule -l` |
| per-domain permissive | `semanage permissive -a/-d httpd_t` |
| booleans affecting httpd | `getsebool -a \| grep httpd` (avoid the broad ones, §6.5) |

Tooling packages: `policycoreutils-python-utils` (`semanage`, pulled in by
the -selinux subpackage), `setroubleshoot-server` (`sealert`),
`policycoreutils-devel`/`selinux-policy-devel` (only needed to build local
modules like §6.3), `setools-console` (`seinfo`, `sesearch` for policy
archaeology, e.g. `sesearch -A -s httpd_t -t brix_var_lib_t`).

---

## 8. FAQ

**Does enforcing cost performance?**
The AVC is a cache — after the first check of a (domain, type, class)
triple, decisions are O(1) lookups. On a data gateway the syscall-heavy path
is sendfile/splice loops whose permission checks are cached; measured
overhead is low single-digit percent at worst, typically unmeasurable
against 100 GbE transfer noise. It is not a reason to skip this.

**We run the gateway in a container — still relevant?**
Yes, differently. On the host, container runtimes use SELinux (`container_t`
+ MCS categories) to isolate containers from the host and each other; the
policy in this package applies when BriX runs as an RPM-installed system
service. Inside a container image, this module is typically not loaded —
your isolation boundary is the runtime's policy instead.

**Why extend `httpd_t` instead of a dedicated `brix_t` domain?**
Because nginx is the process and the distro maintains `httpd_t` for it —
config paths, log paths, systemd integration, PID files, master/worker
signalling all come for free and stay correct across nginx updates. A
dedicated domain would duplicate hundreds of rules to express "…is a web
server" and then drift. The trade-off (other nginx vhosts on the same host
share the domain and therefore may touch `brix_var_lib_t`) is noted below —
don't co-host unrelated web apps on a storage gateway.

**Does the impersonation broker weaken the story?**
`setuid`/`setgid`/`setcap` are the sharpest rules in the module — they exist
so the broker can switch per-request identity. Two mitigations: DAC-wise the
broker drops to a service account and workers shed those caps immediately
after fork (see `deployment-hardening.md` §3); MAC-wise, changing *uid*
never changes *domain* — an impersonated request is still `httpd_t` and
still cannot touch anything outside the BriX types. Single-user sites that
disable impersonation can also tighten the systemd `CapabilityBoundingSet`.

**Anything SELinux does NOT protect here?**
Be honest in your threat model: (1) the gateway can, by design, read/write
the entire export tree — SELinux does not do per-VO isolation inside
`brix_var_lib_t`; that's the job of BriX's own authz (tokens, VOMS ACLs,
authdb). (2) Other processes legitimately in `httpd_t` (a co-hosted stock
nginx vhost, anything spawned by it) share the gateway's grants. (3) Kernel
vulnerabilities below the LSM layer bypass everything. Layers, not magic.

---

## 9. Pointers

- Policy source in-tree: `packaging/selinux/brix.te` (rules, heavily
  commented), `brix.fc` (path labels), `brix.if` (interfaces for other
  policies: `brix_read_data`, `brix_manage_data`, `brix_use_ports`).
- RPM wiring: `packaging/rpm/nginx-mod-brix-cache.spec` (the `-selinux`
  subpackage) and `packaging/rpm/README.md` § "SELinux".
- Systemd layer: [deployment-hardening](../09-developer-guide/deployment-hardening.md),
  `packaging/brix-cache.service`.
- Upstream reading: the SELinux Notebook (github.com/SELinuxProject/selinux-notebook)
  and your distro's SELinux User's and Administrator's Guide.
