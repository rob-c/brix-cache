# Upgrade & Rollback Procedure

How to upgrade the BriX-Cache module package safely, what the module-load layout
must look like, and how to roll back.

## Package layout (what the RPM installs)

The dynamic build ships **two** nginx modules, loaded by one config file:

| File | Purpose |
|---|---|
| `…/modules/ngx_stream_xrootd_module.so` | The **combined** module — stream (root://) + metrics + SRR + WebDAV + S3 + dashboard + CMS in one `.so` |
| `…/modules/ngx_http_xrootd_xrdhttp_filter_module.so` | The HTTP AUX output filter (kept separate) |
| `/etc/nginx/conf.d/mod-xrootd.conf` | The two `load_module` lines, **combined first** |

> **Why one combined `.so`?** The modules reference each other's symbols
> (dashboard ↔ webdav ↔ metrics ↔ stream). As separate `.so` files those references
> form a cross-`.so` cycle that `dlopen(RTLD_NOW)` cannot resolve, so `nginx -t`
> failed to load them. Bundling them into one `.so` makes the references resolve at
> link time. **Load order matters:** the combined module must be the *first*
> `load_module` line so its symbols back the filter via `RTLD_GLOBAL`. The RPM writes
> `mod-xrootd.conf` in the correct order; do not reorder it.

The other subpackages are independent: `nginx-xrootd-client` (the `xrdcp`/`xrdfs`/…
tools + FUSE), `nginx-xrootd-tests` (the pytest suite). Operational extras
(`grafana-dashboard.json`, `prometheus-alerts.yml`) install under
`/usr/share/nginx-xrootd/`; the example config is
`/etc/nginx/conf.d/brix-cache.conf.example` (inactive until you copy it to a `.conf` name).

## Upgrade

1. **Read the changelog**: `rpm -q --changelog nginx-mod-xrootd | head`. Note any
   directive or behaviour changes.
2. **ABI match**: the module must be built against the **running** nginx's version and
   `./configure` options. If you are upgrading nginx too, upgrade the module in the
   same transaction so they match — a mismatch fails `nginx -t` with
   *module is not binary compatible*.
3. **Install/upgrade**: `dnf upgrade nginx-mod-xrootd` (your `nginx.conf` and the
   `.example` are `%config(noreplace)`, so local edits are preserved).
4. **Validate before applying**: `nginx -t`. This dlopens both modules and parses your
   config. Fix any errors here — *do not* reload on a failing `-t`.
5. **Apply gracefully**: `systemctl reload nginx` (or `nginx -s reload`). New workers
   pick up the new module; established connections drain on the old workers. No drop.
6. **Verify**: `curl -s localhost:9100/healthz?verbose` returns 200 and `metrics_shm:
   mapped`; spot-check a root://, davs://, and s3:// request; watch
   `rate(xrootd_*_responses_total{status_class="5xx"}[5m])` stays flat.

## Host prerequisite: the libbz2 SONAME

The module links the bzip2 codec by its `libbz2.so.1.0` SONAME. Some distributions
ship only `libbz2.so.1`. If the worker fails to start with
`libbz2.so.1.0: cannot open shared object file`:

- Install the bzip2 runtime (`dnf install bzip2-libs`), and if the file is still only
  `libbz2.so.1`, add a symlink: `ln -s libbz2.so.1 /usr/lib64/libbz2.so.1.0`
  (or ship the `.so.1.0` SONAME in your bzip2 package). The RPM's auto-requires pulls
  in the bzip2 runtime, but the exact SONAME varies by distro.

## Rollback

1. **Downgrade the package**: `dnf downgrade nginx-mod-xrootd`
   (or `dnf install nginx-mod-xrootd-<previous>`). If you upgraded nginx alongside it,
   downgrade nginx in the same transaction to keep the ABI matched.
2. `nginx -t` → `systemctl reload nginx`.
3. Confirm with `/healthz` + the response/auth metrics.

Because every apply step is a graceful reload, both upgrade and rollback are
zero-downtime as long as `nginx -t` passes first.

See also: [Troubleshooting](troubleshooting.md) ·
[Certificate & Token Rotation](certificate-rotation.md) ·
[Capacity Planning](capacity-planning.md)
