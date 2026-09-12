# Master Documentation Audit Plan

**Created:** 2026-01-XX  
**Scope:** All 603 documentation files under `docs/`  
**Method:** Code-verification audit (not doc-vs-doc)  
**Status:** In Progress

---

## Audit Strategy

Given 603 documentation files, this audit uses a **risk-based approach**:

1. **Priority 1 (Critical):** User-facing metrics, APIs, configuration
2. **Priority 2 (High):** Protocol specs, security, authentication
3. **Priority 3 (Medium):** Architecture, developer guides
4. **Priority 4 (Low):** Archive, refactor notes, style guides

---

## Completed Audits

### ✅ DOC_AUDIT_08_METRICS_MONITORING
**Files:** 9  
**Issues:** 23 (2 Critical, 8 High, 9 Medium, 4 Low)  
**Accuracy:** 92.5/100  
**Status:** COMPLETE

---

## Pending Audits (13 sections)

### Priority 1 (Complete First)

| Section | Files | Risk Level | Estimated Time |
|---------|-------|------------|----------------|
| `docs/03-configuration/` | ~50 | CRITICAL | 4 hours |
| `docs/04-protocols/` | ~80 | CRITICAL | 6 hours |
| `docs/06-authentication/` | ~40 | CRITICAL | 3 hours |
| `docs/07-security/` | ~35 | CRITICAL | 3 hours |

### Priority 2

| Section | Files | Risk Level | Estimated Time |
|---------|-------|------------|----------------|
| `docs/01-getting-started/` | ~20 | HIGH | 2 hours |
| `docs/02-concepts/` | ~30 | HIGH | 3 hours |
| `docs/05-operations/` | ~45 | HIGH | 4 hours |
| `docs/10-reference/` | ~60 | HIGH | 5 hours |

### Priority 3

| Section | Files | Risk Level | Estimated Time |
|---------|-------|------------|----------------|
| `docs/09-developer-guide/` | ~70 | MEDIUM | 5 hours |
| `docs/11-architecture/` | ~40 | MEDIUM | 3 hours |
| `docs/platform/` | ~50 | MEDIUM | 4 hours |

### Priority 4

| Section | Files | Risk Level | Estimated Time |
|---------|-------|------------|----------------|
| `docs/audit/` | ~60 | LOW | 2 hours |
| `docs/refactor/` | ~30 | LOW | 2 hours |
| `docs/style/` | ~10 | LOW | 1 hour |
| `docs/superpowers/` | ~20 | LOW | 2 hours |
| `docs/_archive/` | ~30 | LOW | 1 hour |

---

## Total Effort Estimate

| Priority | Files | Time |
|----------|-------|------|
| Priority 1 | 205 | 16 hours |
| Priority 2 | 155 | 14 hours |
| Priority 3 | 160 | 12 hours |
| Priority 4 | 150 | 8 hours |
| **TOTAL** | **670** | **50 hours** |

**Note:** 603 actual files (some counted in multiple categories)

---

## Audit Checklist Template

For each documentation file:

- [ ] Metric/API names match code
- [ ] Label vocabulary is accurate
- [ ] Types (counter/gauge/histogram) correct
- [ ] Example values realistic
- [ ] Code references valid
- [ ] No internal contradictions
- [ ] No doc-vs-doc claims (verify against code)
- [ ] INVARIANT compliance noted
- [ ] Performance claims categorized (MEASURED/THEORETICAL)
- [ ] Dates standardized (ISO 8601)

---

## Issue Severity Definitions

| Severity | Impact | Fix Timeline |
|----------|--------|--------------|
| **Critical** | Build-breaking, security misconfiguration | Immediate |
| **High** | Wrong API spec, incorrect metric type | 24 hours |
| **Medium** | Missing labels, incomplete examples | 1 week |
| **Low** | Typos, outdated examples | 1 month |

---

## Quality Gates

Before marking an audit complete:

1. ✅ All files in section examined
2. ✅ All claims verified against code (not other docs)
3. ✅ Issues documented with file:line references
4. ✅ Severity assigned per issue
5. ✅ Fix recommendations provided
6. ✅ Accuracy score calculated

---

## Current Progress

| Section | Status | Accuracy | Issues |
|---------|--------|----------|--------|
| 08-metrics-monitoring | ✅ COMPLETE | 92.5/100 | 23 |
| 03-configuration | ⏳ PENDING | - | - |
| 04-protocols | ⏳ PENDING | - | - |
| 06-authentication | ⏳ PENDING | - | - |
| 07-security | ⏳ PENDING | - | - |
| (10 more sections) | ⏳ PENDING | - | - |

**Overall Progress:** 1/14 sections (7%)

---

## Next Steps

1. ✅ Complete metrics-monitoring audit (DONE)
2. ⏳ Start configuration directives audit (03-configuration/)
3. ⏳ Verify protocol specs against src/protocols/
4. ⏳ Audit authentication flows against src/auth/
5. ⏳ Verify security claims against src/fs/vfs/

---

## Risk Assessment

**High-Risk Areas** (most likely to have errors):
- Configuration defaults (may drift from code)
- Protocol state machines (complex, hard to verify)
- Security boundaries (critical if wrong)
- Metric labels (cardinality implications)

**Low-Risk Areas**:
- Getting started guides (high-level)
- Architecture diagrams (conceptual)
- Archive docs (historical, not active)

---

## Automation Opportunities

1. **Metric extraction:** Parse `src/observability/` for all `brix_*` families
2. **Directive extraction:** Parse `src/*/module*.c` for `ngx_command_t`
3. **Protocol state machines:** Extract from `src/protocols/*/state*.c`
4. **Cross-reference check:** Verify doc links resolve

**Estimated automation savings:** 30% of manual effort

---

## Deliverables

1. ✅ `DOC_AUDIT_08_METRICS_MONITORING.md` (COMPLETE)
2. ⏳ `DOC_AUDIT_03_CONFIGURATION.md`
3. ⏳ `DOC_AUDIT_04_PROTOCOLS.md`
4. ⏳ `DOC_AUDIT_06_AUTHENTICATION.md`
5. ⏳ `DOC_AUDIT_07_SECURITY.md`
6. ⏳ `MASTER_DOC_AUDIT_SUMMARY.md` (final report)

---

**Status:** Audit framework established, first section complete  
**Next Agent:** Continue with Priority 1 sections (configuration, protocols, auth, security)
