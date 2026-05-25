# Path Sources

This directory owns translation from untrusted XRootD client paths into safe
filesystem paths under `xrootd_root`, plus the small policy helpers that depend
on canonical path matching.

| File | Responsibility |
|---|---|
| `access_log.c` | Per-request access log formatting and sanitization use |
| `acl.c` | VO rule finalization and VO membership checks |
| `canonical.c` | Canonical export-root lookup |
| `extract.c` | Wire payload path extraction and CGI suffix stripping |
| `find_rule.c` | Longest-prefix matching for VO, group, and manager-map rules |
| `group_policy.c` | Parent group inheritance policy |
| `helpers.c` | Shared path component, log-string, and policy-rule finalization helpers |
| `merge.c` | Array inheritance helper used by config merging |
| `mkdir.c` | Recursive mkdir with optional group-policy application |
| `normalize.c` | Directive-time policy path normalization |
| `resolve.c` | Read, write, and create-style canonical path resolution |
| `stat_body.c` | XRootD `kXR_stat` body formatting |
| `strip_cgi.c` | Simple path query-string stripping |
| `path_internal.h` | Internal declarations shared only by path sources |
| `authdb.c` | Auth database: path-to-user/group mapping for ACL evaluation |
| `path.h` | Public path types and cross-file prototypes |
| `resolve_confined_helpers.c` | Confined path resolution helpers — prefix checks, parent traversal |
| `resolve_confined_ops.c` | Confined path operations — confined open, rename, mkdir wrappers |
| `resolve_path_variants.c` | Variant path resolution: read/write/create style differences |
