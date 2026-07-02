# Protocol Unification Strategy - Implementation Status

**Document:** docs/UNIFICATION_STRATEGY.md  
**Status:** PLANNING & DESIGN PHASE  
**Start Date:** 2026-06-05  
**Target Completion:** 2026-06-30 (estimated)  

---

## Project Overview

The Protocol Unification Initiative aims to consolidate XRootD (stream), WebDAV (HTTP), and S3 (HTTP REST) protocol handlers into shared services. This eliminates duplication and ensures identical security/behavior across protocols.

**Total Estimated Effort:** 3-4 weeks (3 phases)  
**Complexity:** HIGH (architectural refactoring)  
**Risk Level:** MEDIUM-HIGH (affects core I/O paths)

---

## Phase 1: Resolver Consolidation

**Status:** ✅ DESIGN COMPLETE, READY FOR IMPLEMENTATION  
**Effort:** 1 week (40-50 hours)  
**Risk:** HIGH (path security critical)

### What's Planned

Consolidate two separate path resolution implementations:
- **Stream Resolver** (`src/path/resolve_path_variants.c`) - XRootD protocol
- **HTTP Resolver** (`src/core/compat/path.c`) - WebDAV/S3 protocols

Into a single unified resolver: `src/path/unified.c`

### Design Artifacts Created

✅ **Comprehensive design document:** `docs/PHASE1_RESOLVER_IMPLEMENTATION.md`

Contains:
- New unified resolver architecture and API
- Full implementation of `xrootd_path_resolve()` function (400+ lines)
- Security validation steps with OWASP mitigation
- Migration path for stream and HTTP code
- Testing strategy (unit + integration + cross-protocol)
- Risk mitigation and timeline

### Key Implementation Details

#### New Function Signature
```c
ngx_int_t xrootd_path_resolve(
    ngx_conf_t *cf,
    const ngx_str_t *root_canon,
    const ngx_str_t *req_path,
    xrootd_path_opts_t opts,
    xrootd_path_result_t *result,
    ngx_log_t *log
);
```

#### Security Features
1. **Component Validation** - Reject "..", null bytes, control chars BEFORE any FS operations
2. **Depth Tracking** - Prevent symlink exhaustion attacks (max 256 components)
3. **Double-Check Confinement** - realpath() + string comparison ensures no escape
4. **Type Validation** - Enforce require_directory, allow_missing_tail flags

#### Options Flags
```c
typedef struct {
    unsigned int allow_missing_tail:1;      /* PUT/MKDIR: missing final component */
    unsigned int require_directory:1;       /* DIRLIST/MKCOL: must be directory */
    unsigned int allow_missing_parents:1;   /* PUT/COPY: create intermediate dirs */
    unsigned int skip_cache_check:1;        /* Direct origin access */
    unsigned int is_write_operation:1;      /* Write semantics for audit */
    unsigned int reject_symlinks:1;         /* Security: reject symlinks */
} xrootd_path_opts_t;
```

### Testing Requirements

- **Unit Tests:** Component validation, normalization, confinement checks
- **Integration Tests:** Stream, WebDAV, S3 code paths
- **Cross-Protocol Tests:** Verify identical behavior across all protocols
- **Security Tests:** Known traversal attacks (symlink loops, ".." escapes, null bytes)
- **Performance Tests:** Ensure <5% overhead vs original

### Success Criteria
- ✅ 0 security test failures
- ✅ All existing tests pass (2,073+ tests)
- ✅ Cross-protocol consistency verified
- ✅ Performance within 5% of original
- ✅ Code review approval

---

## Phase 2: Identity Abstraction

**Status:** PLANNING  
**Effort:** 1 week (30-40 hours)  
**Risk:** MEDIUM

### What's Planned

Consolidate identity/auth state currently scattered across:
- `xrootd_ctx_t` (Stream context)
- `ngx_http_xrootd_webdav_req_ctx_t` (HTTP context)

Into unified `xrootd_identity_t` structure.

### Key Benefits
1. **Unified Auth Path** - Single identity object passed through all protocols
2. **Consistent ACL Checking** - `xrootd_check_vo_acl()` works identically for all protocols
3. **Simplified Token Validation** - One place to validate JWT/GSI certificates
4. **Easier Feature Addition** - New auth methods automatically work for all protocols

### Design Outline

```c
typedef struct {
    ngx_str_t  dn;             /* GSI Distinguished Name */
    ngx_str_t  subject;        /* JWT 'sub' claim */
    ngx_array_t *vo_list;      /* Extracted VOMS/Groups */
    ngx_array_t *scopes;       /* Token write/read scopes */
    unsigned int is_authenticated:1;
    unsigned int is_admin:1;
} xrootd_identity_t;
```

### Workflow
1. **Auth Phase** - Extract credentials (Cert/Token) → populate `xrootd_identity_t`
2. **Policy Phase** - Pass identity to `xrootd_check_vo_acl()` or `xrootd_check_authdb()`
3. **Result** - Authorization logic becomes 100% protocol-neutral

---

## Phase 3: VFS & I/O Orchestration

**Status:** PLANNING  
**Effort:** 1-2 weeks (40-60 hours)  
**Risk:** MEDIUM-HIGH

### What's Planned

Consolidate I/O dispatch currently duplicated in:
- `src/read/read.c` (XRootD stream read)
- `src/webdav/get.c` (WebDAV HTTP GET)
- `src/s3/get.c` (S3 REST GET)

Into unified `src/fs/io_engine.c` I/O dispatcher.

### Benefits
1. **Single Cache Lookup** - All protocols check cache identically
2. **Unified AIO Dispatch** - Thread-pool management centralized
3. **Consistent Metrics** - All protocols update metrics through same interface
4. **Dashboard Updates** - Automatic transfer slot updates for all operations

### Architecture

```
[Stream: kXR_read] ─┐
[WebDAV: GET]      ├──→ Shared I/O Engine ─→ Cache Lookup ─→ AIO
[S3: GetObject]    ┘                          or Origin
                                              ↓
                                         Dashboard Update
                                              ↓
                                         Metrics Export
```

---

## Implementation Roadmap

### Timeline

```
Week 1 (Jun 5-11):   Phase 1 - Resolver Consolidation
  Mon: Design + start implementation
  Wed: Complete implementation + unit tests
  Fri: Stream integration + testing

Week 2 (Jun 12-18):  Phase 1 Completion + Phase 2 Start
  Mon: WebDAV/S3 integration + testing
  Wed: Cross-protocol testing + Phase 2 design
  Fri: Phase 2 implementation start

Week 3 (Jun 19-25):  Phase 2 Completion + Phase 3 Start
  Mon: Phase 2 testing + Phase 3 design
  Wed: Phase 3 implementation
  Fri: Phase 3 testing + integration

Week 4 (Jun 26-30):  Final Testing & Release
  Mon-Fri: Cross-protocol testing, performance profiling, code review
```

---

## Dependencies & Blockers

### Critical Path
Phase 1 (Resolver) → Phase 2 (Identity) → Phase 3 (I/O Engine)

Each phase can be independently tested but requires prior phases for full integration.

### Testing Dependency
Must maintain Golden Test Set of security attacks that pass at each phase:
- Symlink loop detection
- Path traversal attempts ("../../../etc/passwd")
- Null byte injection
- Directory traversal via symbolic links
- Deep path DoS attempts (256+ components)

---

## Resource Requirements

### Development
- 1 senior engineer (primary implementation)
- 1 code reviewer (security focus)
- 1 QA engineer (testing)

### Testing Infrastructure
- Existing test suite (2,073+ tests must pass)
- New security test suite (10+ attack scenarios per phase)
- Cross-protocol test framework

### Time Investment
- Phase 1: 40-50 hours
- Phase 2: 30-40 hours
- Phase 3: 40-60 hours
- Testing/Review: 30-40 hours
- **Total:** 140-190 hours (~4 weeks @ 40 hrs/week)

---

## Risk Assessment

### Phase 1 Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Security regression in path validation | CRITICAL | Golden Test Set must pass before merge |
| Performance regression (realpath loops) | HIGH | Profile & benchmark before/after |
| Stream/HTTP compatibility | HIGH | Cross-protocol test suite |
| Subtle symlink bugs | MEDIUM | Extensive symlink-specific tests |

### Phase 2 Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Auth inconsistency between protocols | HIGH | Unified identity struct eliminates this |
| Token validation edge cases | MEDIUM | Consolidate validation logic |
| VOMS/GSI certificate handling | MEDIUM | Test with real certificates |

### Phase 3 Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| AIO thread pool exhaustion | MEDIUM | Proper queue management in engine |
| Cache coherence bugs | HIGH | Existing cache tests must still pass |
| Metrics accuracy | LOW | Centralized metric increments |

---

## Success Metrics

### Phase 1 Success
- ✅ New resolver compiles without warnings
- ✅ All 2,073 existing tests pass
- ✅ Security test suite (10+ attacks) all pass
- ✅ Cross-protocol comparison tests all pass
- ✅ Performance within 5% of original

### Phase 2 Success
- ✅ Identity object properly populated in all protocols
- ✅ ACL checking produces identical results across protocols
- ✅ Token validation centralized without regressions
- ✅ All existing auth tests pass

### Phase 3 Success
- ✅ Single I/O engine handles all protocol requests
- ✅ Cache hits/misses identical across protocols
- ✅ Metrics accuracy within <1% of original
- ✅ Dashboard transfer tracking works for all protocols

### Overall Success
- 1.5-2% codebase LoC reduction (1,100-1,400 LoC eliminated)
- 100% security test pass rate
- Zero behavioral regressions
- Maintainability significantly improved

---

## Decision Checkpoints

### Phase 1 Checkpoint (Week 1-2)
**Questions before proceeding to Phase 2:**
- [ ] Are cross-protocol path resolution tests passing?
- [ ] Is performance within acceptable bounds?
- [ ] Have security auditors reviewed the design?
- [ ] Are all existing tests still passing?

**Decision:** Proceed to Phase 2? (YES/NO with rationale)

### Phase 2 Checkpoint (Week 3)
**Questions before proceeding to Phase 3:**
- [ ] Is identity abstraction working across all auth modes?
- [ ] Are ACL checks consistent across protocols?
- [ ] Have token validation edge cases been tested?

**Decision:** Proceed to Phase 3? (YES/NO with rationale)

### Phase 3 Checkpoint (Week 4)
**Questions before release:**
- [ ] Is I/O engine handling all protocol requests?
- [ ] Are metrics accurate?
- [ ] Have performance benchmarks been approved?
- [ ] Has security review been completed?

**Decision:** Ship to production? (YES/NO with rationale)

---

## Documentation Artifacts

### Created
- ✅ `docs/UNIFICATION_STRATEGY.md` - Overall strategy (proposal)
- ✅ `docs/PHASE1_RESOLVER_IMPLEMENTATION.md` - Phase 1 detailed design

### To Be Created
- `docs/PHASE2_IDENTITY_IMPLEMENTATION.md` - Phase 2 detailed design
- `docs/PHASE3_IO_ENGINE_IMPLEMENTATION.md` - Phase 3 detailed design
- `docs/UNIFICATION_SECURITY_REVIEW.md` - Security audit findings
- `docs/UNIFICATION_PERFORMANCE_REPORT.md` - Benchmark results

---

## Next Steps

### Immediate (Week 1)
1. **Code Review:** Review Phase 1 design with team
2. **Security Review:** Have security team review confinement logic
3. **Start Implementation:** Begin Phase 1 resolver implementation
4. **Create Test Suite:** Build Golden Test Set of known attacks

### Short-term (Week 2-3)
1. **Complete Phase 1:** Finish implementation + testing
2. **Cross-Protocol Testing:** Verify behavior consistency
3. **Performance Benchmarking:** Ensure <5% overhead
4. **Phase 2 Design:** Begin Phase 2 identity abstraction

### Medium-term (Week 4+)
1. **Phase 2 Implementation:** Identity consolidation
2. **Phase 3 Planning:** I/O engine architecture
3. **Documentation:** Create remaining design docs
4. **Release Planning:** Coordinate with release team

---

## Conclusion

The Protocol Unification Strategy is a significant architectural improvement that will:
- ✅ Eliminate ~1,200+ LoC of duplication
- ✅ Improve security through centralized validation
- ✅ Simplify future feature development
- ✅ Ensure identical behavior across all protocols

Phase 1 (Resolver Consolidation) is fully designed and ready for implementation. The detailed design in `PHASE1_RESOLVER_IMPLEMENTATION.md` provides everything needed to begin development.

---

**Document Version:** 1.0  
**Last Updated:** 2026-06-05  
**Status:** READY FOR PHASE 1 IMPLEMENTATION  
**Approval Required:** ☐ Security Team ☐ Code Architects ☐ QA Lead
