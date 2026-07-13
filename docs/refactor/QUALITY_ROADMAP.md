# Brix Code Quality Roadmap: 8.0 → 9.0 → 9.5

**Current Score:** 6.5/10  
**Target Milestones:** 8.0 (2 weeks) → 9.0 (8-11 weeks) → 9.5 (12-14 weeks)  
**Last Updated:** 2026-07-09

---

## Executive Summary

This plan details the strategic roadmap to elevate Brix (nginx-xrootd) from 6.5/10 to 9.5/10 code quality. The work is broken into three phases with clear deliverables, effort estimates, and success criteria at each milestone.

**Key Insight:** The first jump to 8.0 is quick (fixing hotspots). The path to 9.0+ requires systematic architectural work. The jump to 9.5 demands comprehensive documentation and cultural change.

---

## Scoring Model

### Current State Analysis
| Category | Score | Status | Blocker |
|----------|-------|--------|---------|
| Correctness | 7/10 | Good | No |
| Architecture | 7/10 | Solid | Partly (hotspots) |
| Formatting | 7/10 | Consistent | No |
| Readability | 6/10 | **Needs Work** | Yes (complexity) |
| Maintainability | 6/10 | **Needs Work** | Yes (hotspots) |
| Testing | 6/10 | **Needs Work** | Partly |
| Documentation | 4/10 | **Poor** | Yes |

### Scoring Breakdown by Milestone

```
CURRENT (6.5/10)
├─ Correctness: 7/10 ✓
├─ Architecture: 7/10 ✓
├─ Formatting: 7/10 ✓
├─ Readability: 6/10 ⚠
├─ Maintainability: 6/10 ⚠
├─ Testing: 6/10 ⚠
└─ Documentation: 4/10 ✗

8.0/10 TARGET
├─ Correctness: 8/10
├─ Architecture: 8/10
├─ Formatting: 7/10
├─ Readability: 8/10 ← Fixed hotspots
├─ Maintainability: 8/10 ← Fixed hotspots
├─ Testing: 7/10
└─ Documentation: 5/10

9.0/10 TARGET
├─ Correctness: 9/10
├─ Architecture: 9/10 ← Refactored
├─ Formatting: 8/10
├─ Readability: 9/10 ← Architecture + docs
├─ Maintainability: 9/10 ← Refactored
├─ Testing: 8/10 ← Improved coverage
└─ Documentation: 8/10 ← Comprehensive

9.5/10 TARGET
├─ Correctness: 9/10
├─ Architecture: 9/10
├─ Formatting: 9/10 ← Stricter enforcement
├─ Readability: 9/10
├─ Maintainability: 9/10
├─ Testing: 9/10 ← High coverage + integration
└─ Documentation: 9/10 ← Complete, detailed
```

---

## Phase 1: Reach 8.0/10 (2 Weeks)

**Goal:** Fix critical complexity hotspots and improve core readability

### 1.1 Refactor `brix_handle_open` Function

**Current State:**
- Location: Core open handler
- Size: 413 lines of code
- Cyclomatic Complexity: 114 (should be <10)
- Status: Nearly untestable

**Target State:**
- Split into 4-5 focused functions
- Max complexity per function: <10
- Each function is independently testable

**Breakdown:**

```c
// BEFORE (413 LOC, CCN=114)
int brix_handle_open(...)

// AFTER (4 functions, ~100 LOC each, CCN=8-10 per function)
int brix_open_root(...)      // ~100 LOC, CCN=8
int brix_open_s3(...)        // ~100 LOC, CCN=9
int brix_open_webdav(...)    // ~100 LOC, CCN=7
int brix_open_cvmfs(...)     // ~100 LOC, CCN=8
int brix_handle_open(...)    // Dispatcher, ~30 LOC, CCN=4
```

**Subtasks:**
- [ ] Extract root-specific logic → `brix_open_root()`
- [ ] Extract S3-specific logic → `brix_open_s3()`
- [ ] Extract WebDAV-specific logic → `brix_open_webdav()`
- [ ] Extract CVMFS-specific logic → `brix_open_cvmfs()`
- [ ] Create dispatcher that calls appropriate handler
- [ ] Update error handling for consistency
- [ ] Write unit tests for each handler

**Effort:** 4-6 hours  
**Owner:** [TBD]  
**Success Criteria:**
- [ ] All functions have CCN < 10
- [ ] Each function is <150 LOC
- [ ] All tests pass
- [ ] No behavior change

---

### 1.2 Simplify `brix_cvmfs_gate` Function

**Current State:**
- Location: CVMFS handler
- Cognitive Complexity: 84
- Nesting Depth: 5+ levels
- Status: Hard to follow control flow

**Target State:**
- Reduce cognitive complexity to <20
- Flatten nesting to 2-3 levels
- Clear control flow

**Breakdown:**

```c
// Identify macro-heavy sections
// Extract conditional logic to helper functions
// Flatten nested if/else chains

brix_cvmfs_check_auth(...)     // Extract auth logic
brix_cvmfs_validate_path(...)  // Extract path validation
brix_cvmfs_apply_rules(...)    // Extract rule application
```

**Subtasks:**
- [ ] Map out control flow (draw diagram)
- [ ] Identify independent concerns
- [ ] Extract helpers for each concern
- [ ] Replace nested conditionals with guard clauses
- [ ] Reduce macro complexity
- [ ] Add inline documentation for logic

**Effort:** 3-4 hours  
**Owner:** [TBD]  
**Success Criteria:**
- [ ] Cognitive complexity < 20
- [ ] Max nesting depth ≤ 3
- [ ] Function size < 200 LOC
- [ ] Control flow is obvious
- [ ] All tests pass

---

### 1.3 Extract & Name Magic Numbers

**Current State:**
- 100+ hardcoded constants throughout codebase
- Examples: `512`, `256`, `5000`, `0xcbf29ce484222325ull`
- Intent unclear, hard to maintain

**Target State:**
- All magic numbers extracted to named constants
- Each constant documented with purpose & unit
- Related constants grouped logically

**New Header File: `brix_constants.h`**

```c
// Buffer and I/O limits
#define BRIX_BUFFER_SIZE_SMALL      512   // Small buffer for protocol headers
#define BRIX_BUFFER_SIZE_MEDIUM     4096  // Medium buffer for data transfers
#define BRIX_BUFFER_SIZE_LARGE      65536 // Large buffer for bulk operations

// CVMFS specific
#define BRIX_CVMFS_TIMEOUT          5000  // CVMFS gateway timeout (ms)
#define BRIX_CVMFS_MAX_PATH_LENGTH  4096  // Maximum CVMFS path length

// Hashing constants
#define BRIX_FNV_OFFSET_BASIS       0xcbf29ce484222325ull // FNV-1a offset
#define BRIX_FNV_PRIME              0x100000001b3ull       // FNV-1a prime

// Pool limits
#define BRIX_CONNECTION_POOL_SIZE   256   // Max concurrent connections
#define BRIX_BUFFER_POOL_SIZE       512   // Max pooled buffers
```

**Subtasks:**
- [ ] Scan codebase for magic numbers
- [ ] Group by category (buffers, timeouts, limits, etc.)
- [ ] Create `brix_constants.h` with documented constants
- [ ] Replace all magic numbers with named constants
- [ ] Verify no behavior change
- [ ] Add to style guide

**Effort:** 2-3 hours  
**Owner:** [TBD]  
**Success Criteria:**
- [ ] Zero hardcoded numbers in code (except in constant definitions)
- [ ] All constants documented
- [ ] Constants named clearly
- [ ] All tests pass

---

### 1.4 Systematic Variable Renaming

> **STATUS: N/A (closed 2026-07-09).** The single-letter variables in the
> critical functions are canonical nginx idioms — `r`=`ngx_http_request_t*`,
> `c`=`ngx_connection_t*`, `s`=`ngx_stream_session_t*`, `cf`/`lcf`=conf,
> `ctx`=module context, `b`=`ngx_buf_t*`, `p`=parse cursor, `rc`=return code.
> Renaming them to verbose forms would break consistency with nginx core and all
> ~640 source files, violating the project rule "follow existing patterns
> strictly / no AI slop." The roadmap's generic `h,s,i → …` example does not
> apply to an nginx module. Rename only a genuinely cryptic *non-idiom* local
> case-by-case; no systematic sweep.

**Current State:**
- Single-letter variables throughout: `h`, `s`, `i`, `r`, `c`, `t`, `b`
- Especially problematic in complex functions
- Hurts readability significantly

**Target State:**
- All variables have meaningful names
- Names reflect purpose or type
- Consistency across codebase

**Priority Scope:** Critical functions in each module
- `brix_root_*` functions (3-4 key functions)
- `brix_s3_*` functions (2-3 key functions)
- `brix_webdav_*` functions (2-3 key functions)
- `brix_cvmfs_*` functions (3-4 key functions)

**Mapping Example:**
```c
// BEFORE
int handler(void *h, char *s, int i) {
    for (int r = 0; r < CACHE_SIZE; r++) {
        if (c = validate(s)) {
            t = process(h, s, r);
            b = store(t);
        }
    }
}

// AFTER
int handler(void *protocol_handler, char *stream_buffer, int timeout_ms) {
    for (int cache_idx = 0; cache_idx < CACHE_SIZE; cache_idx++) {
        if (validation_result = validate(stream_buffer)) {
            processed_data = process(protocol_handler, stream_buffer, cache_idx);
            store_result = store(processed_data);
        }
    }
}
```

**Subtasks:**
- [ ] Identify variables in critical functions
- [ ] Create naming convention guide (if not exists)
- [ ] Rename in priority functions (root module)
- [ ] Rename in S3 module
- [ ] Rename in WebDAV module
- [ ] Rename in CVMFS module
- [ ] Verify all tests pass

**Effort:** 2-3 hours  
**Owner:** [TBD]  
**Success Criteria:**
- [ ] No single-letter variables in critical functions
- [ ] All variable names meaningful
- [ ] Consistent naming across modules
- [ ] All tests pass

---

### Phase 1 Summary

| Task | Effort | Impact | Owner | Status |
|------|--------|--------|-------|--------|
| Refactor `brix_handle_open` | 4-6h | +0.5 | [ ] | [ ] |
| Simplify `brix_cvmfs_gate` | 3-4h | +0.3 | [ ] | [ ] |
| Extract magic numbers | 2-3h | +0.4 | [ ] | [ ] |
| Rename variables | 2-3h | +0.3 | [ ] | [ ] |
| **Phase 1 Total** | **11-16h** | **+1.5** | **→ 8.0/10** | [ ] |

**Timeline:** 2-3 weeks (with code review cycles)  
**Success Metric:** All tools confirm 8.0+ score

---

## Phase 2: Reach 9.0/10 (6-8 Weeks)

**Goal:** Comprehensive refactoring, documentation, and testing

### 2.1 Architectural Refactoring

**Objective:** Move from ad-hoc structure to systematic protocol handler architecture

#### 2.1.1 Create Protocol Handler Interface

**Current State:**
- Each protocol (root, s3, webdav, cvmfs) implemented ad-hoc
- Inconsistent approach to request/response handling
- Hard to add new protocols

**Target State:**
- Common `protocol_handler_t` interface
- Consistent request/response pipeline
- Easy to extend with new protocols

**New File: `brix_protocol.h`**

```c
// Protocol handler interface
typedef struct {
    const char *name;                    // Protocol name (e.g., "root", "s3")
    int (*init)(brix_config_t *config);  // Initialize protocol
    int (*open)(brix_request_t *req);    // Handle open request
    int (*read)(brix_request_t *req);    // Handle read request
    int (*write)(brix_request_t *req);   // Handle write request
    int (*close)(brix_request_t *req);   // Handle close request
    int (*finalize)(void);               // Cleanup
} protocol_handler_t;

// Register new protocol
int brix_register_protocol(protocol_handler_t *handler);
```

**Implementation:**

```c
// Root protocol
protocol_handler_t root_handler = {
    .name = "root",
    .init = brix_root_init,
    .open = brix_root_open,
    .read = brix_root_read,
    .write = brix_root_write,
    .close = brix_root_close,
    .finalize = brix_root_finalize,
};

// S3 protocol
protocol_handler_t s3_handler = {
    .name = "s3",
    .init = brix_s3_init,
    .open = brix_s3_open,
    // ... etc
};

// At startup
brix_register_protocol(&root_handler);
brix_register_protocol(&s3_handler);
brix_register_protocol(&webdav_handler);
brix_register_protocol(&cvmfs_handler);
```

**Subtasks:**
- [ ] Design protocol handler interface
- [ ] Create `brix_protocol.h` with interface definitions
- [ ] Create protocol registry system
- [ ] Refactor root handler to implement interface
- [ ] Refactor S3 handler to implement interface
- [ ] Refactor WebDAV handler to implement interface
- [ ] Refactor CVMFS handler to implement interface
- [ ] Update dispatcher to use registry
- [ ] Write integration tests for protocol dispatch

**Effort:** 2-3 weeks  
**Owner:** [TBD]  
**Impact:** +0.4 points

---

#### 2.1.2 Extract Module-Specific Logic

**Objective:** Move protocol-specific code to separate modules for clarity

**Target Structure:**

```
src/
├─ brix_core.c              # Common core functions (no protocol-specific code)
├─ brix_protocol.c          # Protocol dispatch & registry
├─ protocol/
│  ├─ root/
│  │  ├─ root.c            # Root protocol implementation
│  │  ├─ root.h
│  │  └─ root_priv.h       # Private definitions
│  ├─ s3/
│  │  ├─ s3.c
│  │  ├─ s3.h
│  │  └─ s3_priv.h
│  ├─ webdav/
│  │  ├─ webdav.c
│  │  ├─ webdav.h
│  │  └─ webdav_priv.h
│  └─ cvmfs/
│     ├─ cvmfs.c           # CVMFS implementation
│     ├─ cvmfs.h
│     ├─ cvmfs_gate.c      # Refactored gate handler
│     ├─ cvmfs_priv.h
│     └─ cvmfs_rules.c     # Rule evaluation
└─ utility/
   ├─ constants.h          # Shared constants
   ├─ logging.c            # Logging utilities
   └─ pool.c               # Buffer/connection pooling
```

**Subtasks:**
- [ ] Create directory structure
- [ ] Move root-specific code to `protocol/root/`
- [ ] Move S3-specific code to `protocol/s3/`
- [ ] Move WebDAV-specific code to `protocol/webdav/`
- [ ] Move CVMFS-specific code to `protocol/cvmfs/`
- [ ] Extract shared utilities to `utility/`
- [ ] Update build system (Makefile/CMake)
- [ ] Verify all tests pass
- [ ] Update include guards and dependencies

**Effort:** 1-2 weeks  
**Owner:** [TBD]  
**Impact:** +0.3 points (clearer architecture)

---

### 2.2 Comprehensive Documentation

**Objective:** Document architecture, design decisions, and code patterns

#### 2.2.1 Architecture Documentation

**New File: `docs/ARCHITECTURE.md`**

Contents:
- [ ] System overview (diagram)
- [ ] Protocol handling pipeline
- [ ] Request/response lifecycle
- [ ] Buffer management strategy
- [ ] Connection pooling
- [ ] Error handling philosophy
- [ ] Thread safety guarantees
- [ ] Performance considerations

**Effort:** 4-6 hours  
**Owner:** [TBD]

---

#### 2.2.2 Protocol Handler Documentation

**New File: `docs/protocol-handlers.md`**

For each protocol (root, S3, WebDAV, CVMFS):
- [ ] Protocol overview
- [ ] Handler interface implementation
- [ ] Request flow diagram
- [ ] Key functions and their purpose
- [ ] Edge cases and error conditions
- [ ] Performance characteristics
- [ ] Known limitations/TODOs

**Effort:** 6-8 hours (1.5-2h per protocol)  
**Owner:** [TBD]

---

#### 2.2.3 Code Documentation

**Objective:** Every public function documented

**Format:**
```c
/**
 * Brief description of what this function does.
 *
 * Longer explanation of the function's purpose, when to use it,
 * and any important caveats.
 *
 * @param param1  Description of param1 (type, valid ranges)
 * @param param2  Description of param2
 * @return        Description of return value and error conditions
 *
 * @note          Any important notes (e.g., thread-safety, side-effects)
 * @see           Related functions
 *
 * Example:
 *   int result = brix_root_open(&req);
 *   if (result != BRIX_OK) {
 *     // Handle error
 *   }
 */
int brix_root_open(brix_request_t *req);
```

**Scope:**
- [ ] All public functions in `brix_protocol.h`
- [ ] All handler interface functions
- [ ] All utility functions in `utility/`
- [ ] Key private functions in each protocol module

**Effort:** 1-2 weeks  
**Owner:** [TBD]

---

#### 2.2.4 Design Decisions Document

**New File: `docs/DESIGN_DECISIONS.md`**

Format:
```markdown
## Decision: Use Protocol Handler Interface

### Context
Previously, protocol-specific code was scattered throughout brix_handle_open,
making it hard to add new protocols or test existing ones.

### Decision
Implement a common protocol_handler_t interface that all protocols must implement.

### Consequences
- ✓ New protocols can be added by implementing the interface
- ✓ Each protocol can be tested independently
- ✓ Clear separation of concerns
- ✗ Initial refactoring effort required
- ✗ Runtime dispatch adds ~microseconds overhead

### Alternatives Considered
1. Keep monolithic brix_handle_open (rejected: not scalable)
2. Use virtual functions (rejected: C doesn't have native support)

### Status
Implemented in Phase 2
```

**Decisions to Document:**
- [ ] Why protocol handler interface was chosen
- [ ] Why directory structure was organized this way
- [ ] Buffer management strategy rationale
- [ ] Connection pooling design
- [ ] Error handling approach
- [ ] Any deviations from standard patterns

**Effort:** 4-6 hours  
**Owner:** [TBD]

---

### 2.3 Enhanced Testing

**Objective:** Improve test coverage from 60% to 85%+

#### 2.3.1 Unit Test Expansion

**Current State:**
- Basic tests exist for core functionality
- Coverage: ~60%
- Many edge cases untested

**Target State:**
- Coverage: 85%+
- All critical paths tested
- Edge cases covered

**Priority Test Areas:**

1. **Protocol dispatch tests**
   - [ ] Test each protocol is called correctly
   - [ ] Test unknown protocol rejection
   - [ ] Test protocol initialization failures
   - Effort: 4-6 hours

2. **Root protocol tests**
   - [ ] Valid open requests
   - [ ] Invalid paths (../../../etc/passwd)
   - [ ] Permission errors
   - [ ] Connection limits
   - Effort: 6-8 hours

3. **S3 protocol tests**
   - [ ] Bucket access
   - [ ] Key validation
   - [ ] AWS credential handling
   - [ ] Timeout behavior
   - Effort: 6-8 hours

4. **WebDAV protocol tests**
   - [ ] PROPFIND, MKCOL, etc.
   - [ ] Lock handling
   - [ ] Conflict resolution
   - Effort: 4-6 hours

5. **CVMFS protocol tests**
   - [ ] Gateway communication
   - [ ] Rule evaluation
   - [ ] Cache behavior
   - [ ] Fallback scenarios
   - Effort: 8-10 hours

6. **Buffer management tests**
   - [ ] Pool allocation/deallocation
   - [ ] Buffer limits
   - [ ] Leak detection
   - Effort: 4-6 hours

7. **Error handling tests**
   - [ ] Out of memory
   - [ ] Connection failures
   - [ ] Timeout handling
   - [ ] Graceful degradation
   - Effort: 6-8 hours

**Total Effort:** 2-3 weeks  
**Owner:** [TBD]

---

#### 2.3.2 Integration Tests

**Objective:** Test protocol interactions and end-to-end flows

**Test Scenarios:**

1. **Multi-protocol access**
   - [ ] Same connection handles multiple protocols
   - [ ] Protocol switching
   - [ ] State management across protocols
   - Effort: 4-6 hours

2. **Stress tests**
   - [ ] High concurrency
   - [ ] Large file transfers
   - [ ] Connection pool exhaustion
   - [ ] Memory limits
   - Effort: 6-8 hours

3. **Failure scenarios**
   - [ ] Backend server crash
   - [ ] Network partitions
   - [ ] Resource exhaustion
   - [ ] Cascading failures
   - Effort: 6-8 hours

**Total Effort:** 1-2 weeks  
**Owner:** [TBD]

---

#### 2.3.3 Coverage Tracking

**Subtasks:**
- [ ] Set up coverage reporting tool (gcov, clang coverage)
- [ ] Integrate into CI pipeline
- [ ] Set minimum coverage threshold (85%)
- [ ] Generate coverage reports
- [ ] Identify untested code paths
- [ ] Add tests for gaps

**Effort:** 2-3 days  
**Owner:** [TBD]

---

### 2.4 Code Review Discipline

**Objective:** Establish strict code review standards

#### 2.4.1 Review Checklist

All PRs must verify:
- [ ] No functions exceed CCN 10
- [ ] No functions exceed 150 LOC
- [ ] All new public functions documented
- [ ] Test coverage >= 85%
- [ ] No magic numbers (all extracted to constants)
- [ ] No single-letter variables (in new code)
- [ ] Style guide compliance
- [ ] No performance regressions
- [ ] Security review (if applicable)

**Effort:** Integrate into PR template (0.5 days)  
**Owner:** [TBD]

---

#### 2.4.2 Automated Checks

**Tool Setup:**

- [ ] CPPCheck integration in CI
- [ ] Clang-Tidy for complexity warnings
- [ ] Coverage threshold enforcement
- [ ] Cppcheck strict warnings
- [ ] Clang-Format enforcement

**CI Configuration:**
```yaml
# Example CI configuration
checks:
  complexity:
    max_ccn: 10
    max_lines: 150
  coverage:
    minimum: 85
  style:
    clang_format: enabled
  static_analysis:
    cppcheck: enabled
    clang_tidy: enabled
```

**Effort:** 2-3 days  
**Owner:** [TBD]

---

### Phase 2 Summary

| Task | Effort | Impact | Status |
|------|--------|--------|--------|
| Protocol handler interface | 2-3w | +0.4 | [ ] |
| Module extraction | 1-2w | +0.3 | [ ] |
| Architecture documentation | 0.5w | +0.2 | [ ] |
| Protocol documentation | 1w | +0.2 | [ ] |
| Code documentation | 1-2w | +0.2 | [ ] |
| Design decisions doc | 1w | +0.1 | [ ] |
| Unit test expansion | 2-3w | +0.3 | [ ] |
| Integration tests | 1-2w | +0.2 | [ ] |
| Coverage tracking | 2-3d | +0.1 | [ ] |
| Code review discipline | 2-3d | +0.2 | [ ] |
| **Phase 2 Total** | **6-8 weeks** | **+2.0** | **→ 9.0/10** | [ ] |

---

## Phase 3: Reach 9.5/10 (2-3 Weeks)

**Goal:** Polish, documentation excellence, and process maturity

### 3.1 Style Guide & Enforcement

**Objective:** 100% style consistency

**New File: `docs/STYLE_GUIDE.md`**

Contents:
- [ ] Naming conventions (functions, variables, constants)
- [ ] Indentation & spacing rules
- [ ] Comment style guidelines
- [ ] Error handling patterns
- [ ] Logging standards
- [ ] Include guard format
- [ ] Function organization
- [ ] Type definitions
- [ ] Example code snippets

**Effort:** 2-3 days  
**Owner:** [TBD]

---

### 3.2 API Documentation

**New File: `docs/API_REFERENCE.md`**

- [ ] Complete API reference
- [ ] Function signatures
- [ ] Parameter descriptions
- [ ] Return value descriptions
- [ ] Example usage for each function
- [ ] Common error codes and meanings
- [ ] Thread safety guarantees
- [ ] Performance characteristics

**Effort:** 1 week  
**Owner:** [TBD]

---

### 3.3 Developer Guide

**New File: `docs/DEVELOPER_GUIDE.md`**

Sections:
- [ ] Building from source
- [ ] Running tests
- [ ] Running static analysis
- [ ] Code coverage reports
- [ ] Adding a new protocol handler (step-by-step)
- [ ] Debugging tips
- [ ] Performance profiling
- [ ] Common gotchas

**Effort:** 1 week  
**Owner:** [TBD]

---

### 3.4 Extend Test Coverage to 90%+

**Objective:** Cover remaining edge cases

**Subtasks:**
- [ ] Identify untested paths in coverage report
- [ ] Write tests for identified gaps
- [ ] Add corner case tests
- [ ] Add chaos/fuzzing tests
- [ ] Achieve 90%+ coverage

**Effort:** 1-2 weeks  
**Owner:** [TBD]

---

### 3.5 Performance Documentation

**New File: `docs/PERFORMANCE.md`**

- [ ] Benchmark results (throughput, latency)
- [ ] Memory usage profiles
- [ ] CPU utilization patterns
- [ ] Buffer pool efficiency
- [ ] Connection pooling characteristics
- [ ] Scalability notes
- [ ] Performance optimization guidelines
- [ ] Profiling instructions

**Effort:** 1 week  
**Owner:** [TBD]

---

### 3.6 Security Documentation

**New File: `docs/SECURITY.md`**

- [ ] Security considerations
- [ ] Input validation approach
- [ ] Authentication/authorization
- [ ] Access control patterns
- [ ] Common vulnerabilities addressed
- [ ] Security testing approach
- [ ] Incident response guidelines
- [ ] Dependency security

**Effort:** 1 week  
**Owner:** [TBD]

---

### 3.7 Enforce 9.5+ Quality Gates

**Automated Checks:**
- [ ] All functions CCN < 8 (stricter than 9.0)
- [ ] All functions < 120 LOC (stricter than 9.0)
- [ ] Test coverage >= 90% (stricter than 9.0)
- [ ] Zero style violations
- [ ] Zero static analysis warnings
- [ ] No TODO/FIXME comments
- [ ] All functions documented
- [ ] All constants documented

**Effort:** 1-2 days  
**Owner:** [TBD]

---

### Phase 3 Summary

| Task | Effort | Impact | Status |
|------|--------|--------|--------|
| Style guide | 2-3d | +0.1 | [ ] |
| API reference | 1w | +0.1 | [ ] |
| Developer guide | 1w | +0.1 | [ ] |
| Extended testing (90%) | 1-2w | +0.1 | [ ] |
| Performance docs | 1w | +0.05 | [ ] |
| Security docs | 1w | +0.05 | [ ] |
| Stricter quality gates | 1-2d | +0.05 | [ ] |
| **Phase 3 Total** | **2-3 weeks** | **+0.5** | **→ 9.5/10** | [ ] |

---

## Complete Roadmap Timeline

```
Week 1-2:   Phase 1 (8.0/10)
            - Refactor hotspot functions
            - Extract magic numbers
            - Rename variables

Week 3-10:  Phase 2 (9.0/10)
            - Architectural refactoring
            - Comprehensive documentation
            - Enhanced testing
            - Code review discipline

Week 11-13: Phase 3 (9.5/10)
            - Polish & style guide
            - Extended documentation
            - Performance & security docs
            - Stricter quality gates

TOTAL:      12-14 weeks (3-3.5 months)
```

---

## Success Criteria by Milestone

### 8.0/10 Achieved When:
- [ ] `brix_handle_open` refactored to 4+ functions with CCN < 10
- [ ] `brix_cvmfs_gate` complexity reduced to <20
- [ ] All magic numbers extracted to named constants
- [ ] Single-letter variables renamed in critical functions
- [ ] All tests pass
- [ ] Code analysis tools report 8.0+

### 9.0/10 Achieved When:
- [ ] Protocol handler interface implemented
- [ ] Module structure reorganized by protocol
- [ ] Architecture documentation complete
- [ ] Protocol handler documentation complete
- [ ] All public functions documented
- [ ] Design decisions documented
- [ ] Test coverage >= 85%
- [ ] Integration tests added
- [ ] Code review discipline established
- [ ] Code analysis tools report 9.0+

### 9.5/10 Achieved When:
- [ ] Style guide created and enforced
- [ ] API reference documentation complete
- [ ] Developer guide complete
- [ ] Test coverage >= 90%
- [ ] Performance documentation complete
- [ ] Security documentation complete
- [ ] Zero style violations
- [ ] Zero static analysis warnings
- [ ] All functions documented
- [ ] Code analysis tools report 9.5+

---

## Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Refactoring introduces bugs | High | Comprehensive testing before refactor, run full test suite after each change |
| Large refactor breaks other code | High | Modularize changes, test each protocol independently |
| Documentation becomes stale | Medium | Document BEFORE code, include in code review checklist |
| Team adoption of standards | Medium | Training session, documented in style guide, enforce in CI |
| Timeline slips | Medium | Break phases into smaller chunks, track progress weekly |

---

## Resource Requirements

### Skills Needed
- 1-2 senior C developers (architectural decisions, mentoring)
- 1-2 mid-level developers (implementation)
- 1 QA engineer (test strategy, coverage)
- 1 tech writer (documentation)

### Tools Required
- Code coverage tool (gcov, clang coverage)
- Static analysis (CPPCheck, Clang-Tidy)
- CI/CD integration
- Documentation platform (markdown + hosting)

---

## Next Steps

1. **Assign Phase 1 tasks** to developers
2. **Schedule kickoff meeting** with team
3. **Set up CI integration** for automated checks
4. **Create task tracking** (tickets, burndown)
5. **Establish code review cadence** (daily reviews)
6. **Start Phase 1** immediately

---

## Appendix A: Complexity Metrics Explanation

**Cyclomatic Complexity (CCN):**
- Measures number of linearly independent paths through code
- CCN = 1-5: Simple, easy to understand
- CCN = 6-10: Moderate, still manageable
- CCN > 10: Complex, hard to maintain
- Current `brix_handle_open`: CCN=114 (broken)

**Cognitive Complexity:**
- Measures how hard code is to understand for humans
- Considers nesting depth, macro complexity, etc.
- More aligned with readability than CCN

**Lines of Code (LOC):**
- Physical line count
- Target: <150 LOC per function (avg 50-80)
- >200 LOC likely needs splitting

---

## Appendix B: Tool Integration

### Code Analysis Tools
```bash
# Run all analysis
clang-tidy src/**/*.c --
cppcheck src/ --enable=all
gcov --branches  # Coverage
```

### CI Configuration (GitHub Actions example)
```yaml
name: Quality Checks
on: [push, pull_request]
jobs:
  analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install tools
        run: apt-get install clang-tidy cppcheck
      - name: Clang-Tidy
        run: clang-tidy src/**/*.c
      - name: CPPCheck
        run: cppcheck src/
      - name: Coverage
        run: gcov --all --branches
      - name: Enforce Minimum
        run: |
          if coverage < 85; then exit 1; fi
          if complexity > 10; then exit 1; fi
```

---

## Document History

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2026-07-09 | 1.0 | [Name] | Initial draft |

