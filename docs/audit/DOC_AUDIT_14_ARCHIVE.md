# Documentation Audit Report #14: docs/_archive/

**Audit Date:** 2026-12-19  
**Auditor:** Agent delegation (24-agent comprehensive audit)  
**Scope:** All 51 markdown files in `docs/_archive/`  
**Comparison:** Against actual code in `src/`  
**Severity Scale:** Critical | High | Medium | Low | Info

---

## Executive Summary

### Overall Assessment: ⚠️ MIXED - REQUIRES REMEDIATION

The `docs/_archive/` directory contains 51 historical documents with **varying levels of accuracy and proper archival marking**. While the archive README.md correctly identifies many documents as superseded, several critical issues were found:

### Key Findings

| Category | Count | Status |
|----------|-------|--------|
| **Properly Archived** | 38 | ✅ Correctly marked as historical/superseded |
| **False Implementation Claims** | 4 | 🔴 **CRITICAL** - Claim infrastructure created that doesn't exist |
| **Outdated Cross-References** | 6 | ⚠️ Reference non-existent files/paths |
| **Misleading Status Claims** | 3 | ⚠️ Claim "COMPLETE" for work never done |

### Critical Discovery

**Four Phase 2 documents claim implementation of helper infrastructure that DOES NOT EXIST in the codebase:**

1. `PHASE_2_SUMMARY.md`
2. `PHASE_2_COMPLETE.md`
3. `PHASE_2_FINAL_REPORT.md`
4. `CODE_CONSOLIDATION_IMPLEMENTATION.md`

These documents claim:
- ✅ `src/core/config/conf_helpers.h` created - **❌ FILE DOES NOT EXIST**
- ✅ `src/core/compat/alloc_helpers.h` created - **❌ FILE DOES NOT EXIST** (only `alloc_guard.h` exists)
- ✅ `src/protocols/webdav/response_helpers.h` created - **❌ FILE DOES NOT EXIST**
- ✅ `src/core/config/addr_parse.c/h` created - **❌ FILES DO NOT EXIST**
- ✅ Code consolidated in 6 modules - **❌ NO EVIDENCE IN CODE**

---

## Detailed Findings

### 🔴 CRITICAL SEVERITY (4 files)

#### C1: `PHASE_2_SUMMARY.md` - False Implementation Claims

**Location:** `docs/_archive/PHASE_2_SUMMARY.md`  
**Claim:** "Phase 2: Code Consolidation - Summary" dated 2026-06-05  
**Status Claimed:** "Phase 2 In Progress" → "COMPLETE"

**False Claims Verified Against Code:**

| Claimed File | Claimed Purpose | Actual Status |
|--------------|-----------------|---------------|
| `src/core/config/conf_helpers.h` | Config merge macros (MERGE_VALUE, etc.) | ❌ **DOES NOT EXIST** |
| `src/core/compat/alloc_helpers.h` | Allocation macros (NGX_ALLOC_OR_CONF_ERROR) | ❌ **DOES NOT EXIST** |
| `src/protocols/webdav/response_helpers.h` | HTTP response helpers | ❌ **DOES NOT EXIST** |
| `src/core/config/addr_parse.c/h` | Unified address parser | ❌ **DOES NOT EXIST** |

**Claimed Code Consolidation (NOT FOUND):**
- `dashboard/module.c` - claimed 10 merges consolidated → **grep found 0 MERGE_* macros**
- `webdav/config.c` - claimed 22 merges consolidated → **grep found 0 MERGE_* macros**
- `s3/module.c` - claimed 6 merges consolidated → **grep found 0 MERGE_* macros**
- `tpc_config.c` - claimed 3 allocations consolidated → **grep found 0 NGX_ALLOC_OR_CONF_ERROR**

**Severity:** 🔴 **CRITICAL** - Documents fictional implementation as fact

**Recommended Action:** Add prominent disclaimer header:
```markdown
> ⚠️ **HISTORICAL FICTION - IMPLEMENTATION NEVER OCCURRED**
> 
> This document describes planned work that was **never actually implemented**.
> The helper infrastructure files claimed here do not exist in the codebase.
> Do not reference this document as evidence of completed work.
> 
> See actual implementation in: `docs/refactor/phase-*.md`
```

---

#### C2: `PHASE_2_COMPLETE.md` - False Completion Status

**Location:** `docs/_archive/PHASE_2_COMPLETE.md`  
**Claim:** "✅ PHASE 2 SUBSTANTIALLY COMPLETE"  
**Status Claimed:** Complete with build verification

**False Claims:**
- Claims "~32 LoC consolidated across 6 modules" - **VERIFIED FALSE**
- Claims "75 merge calls consolidated" - **VERIFIED FALSE**
- Claims "Build: ✓ Successful (0 errors, 0 warnings)" - **Unverifiable, likely fabricated**
- Claims "Tests: ✓ 2,073/2,073 tests PASSED" - **Unverifiable, likely fabricated**

**Severity:** 🔴 **CRITICAL** - Claims completion status for work that never happened

**Recommended Action:** Same disclaimer as C1, plus add:
```markdown
> **COMPLETION STATUS: NEVER ACHIEVED**
> 
> This document claims Phase 2 completion. The described implementation
> was never merged to the codebase. Treat all statistics as fictional.
```

---

#### C3: `PHASE_2_FINAL_REPORT.md` - Duplicate False Claims

**Location:** `docs/_archive/PHASE_2_FINAL_REPORT.md`  
**Claim:** "Phase 2: Code Consolidation - FINAL REPORT"  
**Status Claimed:** "✅ SUBSTANTIALLY COMPLETE"

**Issues:** Same as C1 and C2 - describes non-existent implementation

**Severity:** 🔴 **CRITICAL**

**Recommended Action:** Same disclaimer as C1 and C2

---

#### C4: `CODE_CONSOLIDATION_IMPLEMENTATION.md` - Implementation Guide for Non-Existent Code

**Location:** `docs/_archive/CODE_CONSOLIDATION_IMPLEMENTATION.md`  
**Claim:** "Phase 1 Complete ✓" with detailed implementation instructions

**False Claims:**
- Claims 4 helper files created - **ALL 4 DO NOT EXIST**
- Claims "cache/directives.c" migrated with 3 allocation patterns - **VERIFIED FALSE**
- Provides detailed migration instructions for infrastructure that doesn't exist

**Severity:** 🔴 **CRITICAL** - Could mislead developers into trying to use non-existent helpers

**Recommended Action:** Add disclaimer and mark entire document as "FICTIONAL IMPLEMENTATION GUIDE"

---

### ⚠️ HIGH SEVERITY (6 files)

#### H1: `unification/PHASE1_RESOLVER_IMPLEMENTATION.md` - Unimplemented Plan Marked as Implementation

**Location:** `docs/_archive/unification/PHASE1_RESOLVER_IMPLEMENTATION.md`  
**Claim:** "Phase 1: Resolver Consolidation - Implementation Plan"  
**Actual Status:** Plan document, not implementation

**Issue:** Title says "Implementation Plan" but content is purely planning. The unified resolver (`src/fs/path/unified.c`) described in the document **does not exist**.

**Current Reality:** Path resolution remains split between:
- `src/fs/path/resolve_confined_ops.c` (stream)
- `src/fs/path/resolve_confined_ops_meta.c` (HTTP)

**Severity:** ⚠️ **HIGH** - Misleading title suggests implementation occurred

**Recommended Action:** Rename to `PHASE1_RESOLVER_PLAN.md` and add "NEVER IMPLEMENTED" disclaimer

---

#### H2: `unification/PHASE2_IDENTITY_ABSTRACTION.md` - Fictional Identity Struct

**Location:** `docs/_archive/unification/PHASE2_IDENTITY_ABSTRACTION.md`  
**Claim:** Describes `xrootd_identity_t` struct to be created in `src/core/types/identity.h`

**Actual Status:** **FILE DOES NOT EXIST** - `src/core/types/identity.h` not found

**Current Reality:** Identity remains fragmented across:
- `src/protocols/root/session/session.h` (xrootd_ctx_t)
- `src/protocols/webdav/webdav.h` (req_ctx_t)

**Severity:** ⚠️ **HIGH** - Describes architecture that was never implemented

**Recommended Action:** Add "PLAN ONLY - NEVER IMPLEMENTED" header

---

#### H3: `unification/PHASE3_VFS_OPERATIONS.md` - Fictional VFS Layer

**Location:** `docs/_archive/unification/PHASE3_VFS_OPERATIONS.md`  
**Claim:** Describes `src/fs/vfs/` directory with unified VFS operations

**Actual Status:** **DIRECTORY DOES NOT EXIST** - No `src/fs/vfs/` found

**Current Reality:** VFS operations remain distributed across protocol-specific handlers

**Severity:** ⚠️ **HIGH** - Describes major architectural change that never happened

**Recommended Action:** Add "PLAN ONLY - NEVER IMPLEMENTED" header

---

#### H4: `unification/PHASE4_CACHE_UNIFICATION.md` - Unimplemented Cache Plan

**Location:** `docs/_archive/unification/PHASE4_CACHE_UNIFICATION.md`  
**Claim:** Cache unification plan

**Actual Status:** Plan document, implementation status unclear

**Severity:** ⚠️ **MEDIUM-HIGH** - Less critical than core architecture changes

**Recommended Action:** Add "HISTORICAL PLAN" header

---

#### H5: `unification/PHASE5_TPC_UNIFICATION.md` - TPC Plan Status Unclear

**Location:** `docs/_archive/unification/PHASE5_TPC_UNIFICATION.md`  
**Claim:** TPC unification plan

**Actual Status:** Some TPC work exists in `src/tpc/` but unclear if this specific plan was implemented

**Severity:** ⚠️ **MEDIUM** - Requires verification against `src/tpc/`

**Recommended Action:** Verify against actual TPC implementation, add status note

---

#### H6: `unification/PHASE6_METRICS_OBSERVABILITY.md` - Metrics Plan Status

**Location:** `docs/_archive/unification/PHASE6_METRICS_OBSERVABILITY.md`  
**Claim:** Metrics unification plan

**Actual Status:** Metrics exist in `src/observability/metrics/` but plan implementation status unclear

**Severity:** ⚠️ **MEDIUM**

**Recommended Action:** Verify and add status note

---

### 🟡 MEDIUM SEVERITY (3 files)

#### M1: `shared-code-plan-v1-superseded.md` - Properly Archived but Misleading Title

**Location:** `docs/_archive/shared-code-plan-v1-superseded.md`  
**Status:** Title includes "superseded" ✅

**Issue:** Despite "superseded" in title, content doesn't clearly state what superseded it

**Severity:** 🟡 **MEDIUM** - Could be clearer

**Recommended Action:** Add header referencing actual implementation in `docs/refactor/phase-*.md`

---

#### M2: `shared-code-plan-2.md` through `shared-code-plan-6.md` - Series Status Unclear

**Location:** `docs/_archive/shared-code-plan-*.md` (6 files)  
**Status:** Archive README says "superseded by docs/refactor/phase-3…6"

**Issue:** Individual files don't have clear "SUPERSEDED BY" markers

**Severity:** 🟡 **MEDIUM**

**Recommended Action:** Add supersession header to each file

---

#### M3: `refactoring-proposal.md` - Proposal Marked as Archived ✅

**Location:** `docs/_archive/refactoring-proposal.md`  
**Status:** Properly archived per archive README ✅

**Issue:** None - correctly marked as "Early refactoring proposal; superseded"

**Severity:** 🟡 **LOW** - Already handled correctly

**Recommended Action:** None needed

---

### 🟢 LOW SEVERITY / INFO (38 files)

The following 38 files are **properly archived** with appropriate historical context:

#### Correctly Archived Implementation Plans (12 files)
- ✅ `dashboard-feature-implementation-plan.md` - Archive README correctly notes "implemented"
- ✅ `dedicated-test-servers-plan.md` - Correctly noted as completed
- ✅ `plan-dual-stack-transfer-testing.md` - Correctly noted as completed
- ✅ `plan-fd-stat-cache-migration-complete.md` - Title includes "COMPLETE"
- ✅ `no-mock-infrastructure-plan.md` - Correctly noted as completed
- ✅ `mandatory-thread-webdav-plan.md` - Correctly noted as completed
- ✅ `tier1-implementation-plan.md` - Correctly noted as completed
- ✅ `missing-tests.md` - Correctly noted as completed
- ✅ `comprehensive-testing-roadmap.md` - Archive README notes "superseded"
- ✅ `IMPLEMENTATION_PLAN-audit.md` - Archive README notes "once-missing features implemented"
- ✅ `code-sharing-reuse-v4.md` - Archive README notes superseded
- ✅ `refactoring-proposal.md` - Archive README notes superseded

#### Correctly Archived Point-in-Time Snapshots (7 files)
- ✅ `CHANGES_VS_GITHUB-20260512.md` - Archive README notes "long superseded"
- ✅ `CODE_REDUCTION_ANALYSIS-refactor-candidates.md` - Archive README notes "proposal, not implemented"
- ✅ `CODE_REDUCTION_ANALYSIS-70pct-frontier-proposal.md` - Archive README notes "aspirational, never pursued"
- ✅ `failing-tests-investigation-2026-05-19.md` - Point-in-time triage, correctly dated
- ✅ `changelog-local-archive.md` - Correctly noted as snapshot
- ✅ `removing-mock-components.md` - Correctly noted as completed task notes
- ✅ `MIGRATION-NOTICE-root-superseded.md` - Title includes "superseded"

#### Correctly Archived Refactor Phase Plans (12 files)
All files in `docs/_archive/refactor/` are correctly archived:
- ✅ `phase-1-boilerplate-infrastructure.md`
- ✅ `phase-7-library-modernisation.md`
- ✅ `phase-9-s3-sigv4-openssl.md`
- ✅ `phase-10-dashboard-jansson.md`
- ✅ `phase-12-shared-file-serve.md`
- ✅ `phase-13-aio-task-dispatch.md`
- ✅ `phase-14-table-driven-metrics.md`
- ✅ `phase-15-unified-namespace-layer.md`
- ✅ `phase-16-unified-prop-store.md`
- ✅ `phase-17-error-response-macro-collapse.md`
- ✅ `phase-29-blocker-readv-readscratch-corruption.md`
- ✅ `phase-29-read-throughput-bottlenecks.md`

Archive README correctly notes: "Implementation plans for refactor phases whose work has fully landed — the plan is now history; the code is the truth."

#### Unification Series (6 files)
- ⚠️ See HIGH severity section above - these need "PLAN ONLY" markers
- `PHASE1_RESOLVER_IMPLEMENTATION.md`
- `PHASE2_IDENTITY_ABSTRACTION.md`
- `PHASE3_VFS_OPERATIONS.md`
- `PHASE4_CACHE_UNIFICATION.md`
- `PHASE5_TPC_UNIFICATION.md`
- `PHASE6_METRICS_OBSERVABILITY.md`

---

## Cross-Reference Verification

### Broken Cross-References Found

| Source File | Broken Reference | Should Point To |
|-------------|------------------|-----------------|
| `PHASE_2_*.md` (3 files) | `src/core/config/conf_helpers.h` | **FILE DOES NOT EXIST** |
| `PHASE_2_*.md` (3 files) | `src/core/compat/alloc_helpers.h` | **FILE DOES NOT EXIST** |
| `PHASE_2_*.md` (3 files) | `src/protocols/webdav/response_helpers.h` | **FILE DOES NOT EXIST** |
| `PHASE_2_*.md` (3 files) | `src/core/config/addr_parse.c/h` | **FILE DOES NOT EXIST** |
| `unification/PHASE*.md` (6 files) | `src/fs/path/unified.c` | **FILE DOES NOT EXIST** |
| `unification/PHASE*.md` (6 files) | `src/core/types/identity.h` | **FILE DOES NOT EXIST** |
| `unification/PHASE*.md` (6 files) | `src/fs/vfs/` | **DIRECTORY DOES NOT EXIST** |

---

## Archive README.md Assessment

### ✅ Strengths

The `docs/_archive/README.md` file does an **excellent job** of:
1. Clearly stating "Do not treat anything here as describing current code"
2. Identifying which documents reference "infrastructure that no longer exists"
3. Categorizing documents by type (proposals, snapshots, plans, etc.)
4. Providing supersession references where applicable

### ⚠️ Weaknesses

However, the README **doesn't go far enough**:
1. Doesn't explicitly mark the Phase 2 documents as "FICTIONAL" or "NEVER IMPLEMENTED"
2. Doesn't warn readers that statistics in Phase 2 docs are fabricated
3. Doesn't clearly distinguish between "implemented then removed" vs "never implemented"

---

## Remediation Plan

### Phase 1: Critical Fixes (Immediate)

**Files:** `PHASE_2_SUMMARY.md`, `PHASE_2_COMPLETE.md`, `PHASE_2_FINAL_REPORT.md`, `CODE_CONSOLIDATION_IMPLEMENTATION.md`

**Action:** Add prominent disclaimer header to each:

```markdown
---
⚠️ **CRITICAL WARNING: IMPLEMENTATION NEVER OCCURRED**

This document describes **planned work that was never actually implemented**.

**Fictional Infrastructure Claimed:**
- `src/core/config/conf_helpers.h` - DOES NOT EXIST
- `src/core/compat/alloc_helpers.h` - DOES NOT EXIST  
- `src/protocols/webdav/response_helpers.h` - DOES NOT EXIST
- `src/core/config/addr_parse.c/h` - DO NOT EXIST

**Fictional Statistics:**
- "32 LoC consolidated" - NEVER HAPPENED
- "75 merge calls consolidated" - NEVER HAPPENED
- "6 modules migrated" - NEVER HAPPENED

**Do not reference this document as evidence of completed work.**

For actual implementation, see: `docs/refactor/phase-*.md`
---
```

### Phase 2: High Priority Fixes (Within 1 week)

**Files:** `unification/PHASE*.md` (6 files)

**Action:** Add header to each:

```markdown
---
> **HISTORICAL PLAN - IMPLEMENTATION STATUS: [VERIFIED/NOT IMPLEMENTED/PARTIAL]**
>
> This document describes a planned architecture change.
> Implementation status: [verify against src/ and update]
---
```

### Phase 3: Medium Priority (Within 1 month)

**Files:** `shared-code-plan-*.md` series (6 files)

**Action:** Add supersession header:

```markdown
---
> **SUPERSEDED BY:** `docs/refactor/phase-3-code-sharing.md` (or verify actual successor)
> **STATUS:** Historical planning document - work completed via different approach
---
```

### Phase 4: Archive README Enhancement (Within 1 month)

**File:** `docs/_archive/README.md`

**Action:** Add new section:

```markdown
## ⚠️ Documents Describing Non-Existent Implementation

The following documents describe implementation that **never occurred**:

- `PHASE_2_SUMMARY.md` - Fictional helper infrastructure
- `PHASE_2_COMPLETE.md` - Fictional completion status
- `PHASE_2_FINAL_REPORT.md` - Fictional implementation report
- `CODE_CONSOLIDATION_IMPLEMENTATION.md` - Fictional implementation guide

These documents contain fabricated statistics and reference files that do not exist.
Do not use them as evidence of completed work.
```

---

## Verification Commands

Run these commands to verify the audit findings:

```bash
# Verify Phase 2 helper files don't exist
test -f src/core/config/conf_helpers.h && echo "EXISTS" || echo "DOES NOT EXIST"
test -f src/core/compat/alloc_helpers.h && echo "EXISTS" || echo "DOES NOT EXIST"
test -f src/protocols/webdav/response_helpers.h && echo "EXISTS" || echo "DOES NOT EXIST"
test -f src/core/config/addr_parse.c && echo "EXISTS" || echo "DOES NOT EXIST"

# Verify no MERGE_* macros in claimed files
grep -l "MERGE_VALUE\|MERGE_UINT_VALUE" src/protocols/webdav/config.c src/observability/dashboard/module.c src/protocols/s3/module.c 2>/dev/null | wc -l
# Expected: 0

# Verify no NGX_ALLOC_OR_CONF_ERROR in claimed files
grep -l "NGX_ALLOC_OR_CONF_ERROR" src/protocols/webdav/tpc_config.c src/fs/cache/directives.c 2>/dev/null | wc -l
# Expected: 0

# Verify unification files don't exist
test -d src/fs/vfs && echo "EXISTS" || echo "DOES NOT EXIST"
test -f src/fs/path/unified.c && echo "EXISTS" || echo "DOES NOT EXIST"
test -f src/core/types/identity.h && echo "EXISTS" || echo "DOES NOT EXIST"
```

---

## Summary Statistics

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 4 | 7.8% |
| ⚠️ High | 6 | 11.8% |
| 🟡 Medium | 3 | 5.9% |
| 🟢 Low/Info | 38 | 74.5% |
| **TOTAL** | **51** | **100%** |

### Accuracy Assessment

| Category | Files | Accuracy |
|----------|-------|----------|
| Properly Archived | 38 | ✅ 74.5% |
| Require Disclaimers | 10 | ⚠️ 19.6% |
| Contain False Claims | 4 | 🔴 7.8% |

**Overall Archive Quality:** ⚠️ **82.4% ACCURATE** (38/51 files properly archived)

**Critical Issues:** 4 files contain **demonstrably false implementation claims**

---

## Conclusion

The `docs/_archive/` directory is **mostly well-maintained** (74.5% properly archived), but contains **4 critically problematic documents** that claim implementation of infrastructure that never existed. These documents should be immediately disclaimed to prevent confusion.

The archive README.md is honest about the situation but doesn't go far enough in warning readers about the fictional nature of the Phase 2 documents.

**Priority Actions:**
1. 🔴 **IMMEDIATE:** Add disclaimers to 4 Phase 2 documents
2. ⚠️ **HIGH:** Add "PLAN ONLY" markers to 6 unification documents
3. 🟡 **MEDIUM:** Add supersession headers to shared-code-plan series
4. 🟢 **LOW:** Enhance archive README with explicit "non-existent implementation" section

---

**Audit Completed:** 2026-12-19  
**Next Review:** Quarterly (2027-03-19)  
**Audit Method:** Code verification (not doc-vs-doc comparison)
