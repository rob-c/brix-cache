# Agent 23: Variable Naming Patterns

**Scope**: Sample of `.c` files from each layer  
**Focus**: Variable naming patterns, abbreviations, clarity  
**Date**: $(date +%Y-%m-%d)

---

## Methodology
Sampled variable declarations from:
- Core layer (context, types)
- FS layer (vfs, backend, cache)
- Network layer (dns, proxy)
- Auth layer (gsi, krb5)
- Protocols (root, webdav)

## Findings

### Common Variable Patterns

| Pattern | Usage | Clarity |
|---------|-------|---------|
| `ctx` | Context pointers | ✅ Clear |
| `c` | nginx connection | ✅ Standard |
| `fh` | File handle | ✅ Clear |
| `vfs_ctx` | VFS context | ✅ Clear |
| `opctx` | Export op context | ⚠️ Could be `export_op_ctx` |
| `n2n` | Name mapping | ⚠️ Abbreviation |
| `sd` | Storage driver | ⚠️ Abbreviation |

## Summary
- Most variables clearly named ✅
- 3 abbreviations could be clearer (low priority)
- Recommendation: Fix HIGH priority only (opctx)
