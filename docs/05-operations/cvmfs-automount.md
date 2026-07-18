# /cvmfs automount with brixMount autofs

The native automount umbrella makes `/cvmfs` behave like a stock CVMFS client
installation — `ls /cvmfs/atlas.cern.ch` mounts the repository on first access
— with **zero dependency on the autofs kernel module or systemd**, so it works
out of the box on WSL2, in containers, and as an unprivileged user.

```
brixMount autofs <etc-root|-> <mountdir> [-f] [-o opts]
```

`-` uses the standard `/etc/cvmfs` configuration cascade (`default.conf` →
`default.d/*.conf` → `domain.d/<domain>.conf` → `config.d/<fqrn>.conf` →
`default.local`; `BRIXCVMFS_ETC` overrides the root).

## How it works (and why not a nested mount)

A plain FUSE umbrella **cannot** let children mount over its own virtual
subdirectories: the kernel serializes every lookup of one name on the
in-lookup dentry, so while the umbrella's lookup handler waits for the child
mount, the child's own `mount(2)` path walk of `<mnt>/<fqrn>` blocks in
`d_alloc_parallel` (D-state, unkillable) — a guaranteed deadlock. That kernel
assist is exactly why stock autofs is a kernel module.

The umbrella therefore uses a **symlink farm**: children mount in an external
farm directory the umbrella never path-walks (default `<cachebase>/.mnt/<fqrn>`,
override with `-o mntbase=`), and each repository appears in the umbrella as a
symlink. `readlink` is the blocking mount trigger, so ordinary path resolution
(`ls /cvmfs/x/file`, `cd /cvmfs/x`) automounts transparently, while `lstat`
and `readdir` (ghost listings, colorized `ls`) never spawn anything.

Per-repo children are separate `brixMount cvmfs` processes (a hung stratum
isolates to one repo), mounted with `nodev,nosuid`. Idle repos are expired
with `umount2(MNT_EXPIRE)` after `-o idle=` seconds (600 default, `0`
disables; root only — unprivileged umbrellas skip expiry). SIGTERM unmounts
every child, then the umbrella.

`CVMFS_REPOSITORIES` (or `-o repos=a:b`) plus `config.d/*.conf` entries make
the ghost list; `CVMFS_STRICT_MOUNT=yes` refuses everything not listed.

## Quickstart

```sh
# system service (RPM: brix-cvmfs-automount + brix-cvmfs-config)
systemctl enable --now brixcvmfs-automount
ls /cvmfs/sft.cern.ch

# by hand, as any user, no root needed
mkdir -p ~/cvmfs
brixMount autofs - ~/cvmfs -o cachebase=$HOME/.cache/brixcvmfs
ls ~/cvmfs/atlas.cern.ch
```

Zero-config mounts need the config+keys payload (`brix-cvmfs-config` RPM, or
`deploy/cvmfs/install-automount.sh` on non-RPM hosts): stratum-1 sets for
cern.ch / egi.eu / opensciencegrid.org and the upstream master public keys
(provenance in `/etc/cvmfs/keys/README.md`).

## WSL2

Recipe 1 — systemd (preferred, Windows 11 / recent WSL):

```ini
# /etc/wsl.conf
[boot]
systemd=true
```

then `wsl --shutdown` from Windows, and `systemctl enable --now
brixcvmfs-automount` inside the distro.

Recipe 2 — boot command (no systemd):

```ini
# /etc/wsl.conf
[boot]
command=/usr/local/sbin/brixcvmfs-automount-boot.sh
```

The helper (installed by `install-automount.sh`) mkdirs `/cvmfs`, starts the
umbrella under `setsid`, and returns immediately so boot is not delayed.
Logs go to `/var/log/brixcvmfs-automount.log`. Tunables via environment:
`BRIXCVMFS_MNT`, `BRIXCVMFS_CACHE_BASE`, `BRIXCVMFS_IDLE`, `BRIXMOUNT_BIN`.

Note `user_allow_other` in `/etc/fuse.conf` is only needed for *unprivileged*
umbrellas that pass `-o allow_other`; the root service and boot helper do not
require it.

## Classic autofs / mount(8) compatibility

The package also ships the stock integration points for sites that keep
autofs:

- `/sbin/mount.cvmfs` — `mount -t cvmfs atlas.cern.ch /mnt/atlas` works.
- `/etc/auto.cvmfs` + `/etc/auto.master.d/cvmfs.autofs` — the standard
  program-map wiring (`systemctl restart autofs`). Do not run the umbrella
  service and autofs on /cvmfs at the same time; the unit carries
  `Conflicts=autofs.service`.
- `brixcvmfs@.service` — static per-repo mounts:
  `systemctl enable --now brixcvmfs@atlas.cern.ch`.

## Package conflict matrix

| package | conflicts with | why |
|---|---|---|
| brix-cvmfs-automount | cvmfs | both own /sbin/mount.cvmfs and the /cvmfs automount role |
| brix-cvmfs-config | cvmfs-config-default / -egi / -osg | same /etc/cvmfs files; all Provide `cvmfs-config` |

`brix-cvmfs-fuse` itself co-installs with everything (the stock config
packages satisfy its `Recommends: cvmfs-config` just as well).

## Tuning & troubleshooting

- **Idle unmount**: `-o idle=1800` for build boxes; `idle=0` on batch workers
  where remount latency hurts.
- **First access is slow**: that's the child mount (network + catalog); the
  symlink answer itself blocks until the mount is live, so scripts like
  `ls /cvmfs/x && use x` behave exactly as with stock autofs.
- **`ls -l` shows symlinks**: expected — the target under
  `<cachebase>/.mnt/` is the real mount. Path-following tools are
  unaffected.
- **Unmount everything**: `systemctl stop brixcvmfs-automount` (or SIGTERM
  the umbrella); it reverse-unmounts children first. Emergency:
  `fusermount3 -uz <farm>/<fqrn>` then `fusermount3 -uz /cvmfs`.
- **Which repos are ghost-listed?** `ls /cvmfs` = `CVMFS_REPOSITORIES` ∪
  `config.d/*.conf` basenames. An empty `config.d/<fqrn>.conf` advertises a
  repo without overriding anything.
