# src/acc — XrdAcc-compatible authorization engine

A faithful in-C re-implementation of XRootD's **XrdAcc** authorization framework,
selectable at runtime with `xrootd_authdb_format xrdacc;`. It runs **alongside**
the original 6-bit, root://-only `native` engine (`src/path/authdb.c`), which
stays the default so existing deployments are unaffected.

When enabled, `xrdacc` authorizes **all three protocols** (root://, WebDAV, S3)
through one `xrootd_acc_access(tables, entity, path, op)` call, reproducing stock
XRootD `authdb` semantics bit-for-bit.

## What it adds over `native`

| Capability | `native` | `xrdacc` |
|---|---|---|
| Privilege model | 6 custom bits (`r/l/w/a/d/m/k`) | 9-bit XrdAcc model (`a/d/i/k/l/n/r/w`) + composites |
| Negative privileges (`-`) | no | yes (`pprivs & ~nprivs`) |
| Identity record types | `u/g/p/a` | `u/g/h/o/r/n/s/t/x/=` |
| Accumulation | single longest-prefix rule | additive across every matching identity |
| Templates (`@=`), exclusive (`x`), compound (`=`/`s`) | no | yes |
| Roles, orgs, netgroups, Unix groups | VO-only | full (incl. OS `/etc/group` + NIS) |
| Hot-reload (`authrefresh`), audit sink | no | yes |
| Protocol coverage | root:// only | root:// + WebDAV + S3 |

## Files

| File | XrdAcc analogue | Role |
|---|---|---|
| `privs.h` / `privs.c` | `XrdAccPrivs.hh`, `Test()`, `PrivsConvert()` | pure privilege algebra (no nginx deps; unit-testable) |
| `acc.h` | — | nginx-facing umbrella header |
| `authfile.c` | `XrdAccAuthFile.cc` | authdb grammar parser |
| `tables.c` | `XrdAccAccess.hh` | identity hash tables + rule lists |
| `capability.c` | `XrdAccCapability.cc` | path prefix + `@=` template matching |
| `entity.c` | `XrdAccEntity.cc` | identity → attribute tuples |
| `access.c` | `XrdAccAccess::Access()` | the decision engine |
| `groups.c` | `XrdAccGroups.cc` | Unix/NIS group resolution + cache + gidretran |
| `audit.c` | `XrdAccAudit.cc` | grant/deny audit logging |
| `resolve.c` | `XrdAccAccess::Resolve` | reverse-DNS peer for `h <host>`/`.domain` rules |
| `config.c` | `XrdAccConfig.cc` | directives + per-worker build (stream + HTTP hot-reload) |
| `refresh.c` | authrefresh thread | mtime hot-reload timer |
| `opmap.c` | — | operation → `xrootd_acc_op_t` maps (stream/WebDAV/S3) |

## Reference

Ported from `/tmp/xrootd-src/src/XrdAcc/`. Numeric privilege values and the
operation→privilege table are kept identical to `XrdAccPrivs.hh` /
`XrdAccAuthorize.hh` so a stock XRootD `authdb` file yields identical decisions.

> **Letter note:** in `native`, `a` = append-privilege; in `xrdacc`, `a` = *all*
> privileges (the engines use separate, non-shared parsers — no ambiguity).
