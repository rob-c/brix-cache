# Documentation Date Standardization Guideline

**Document Version**: 1.0  
**Created**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Status**: ✅ Active Standard

---

## Purpose

This guideline establishes consistent date formatting and update tracking across all BriX-Cache documentation to ensure accuracy, traceability, and maintainability.

---

## Date Format Standard

### Required Format: ISO 8601 (YYYY-MM-DD)

**✅ CORRECT**:
```markdown
**Last Updated**: 2025-12-19
**Date**: 2025-12-19
**Created**: 2025-12-19
```

**❌ INCORRECT**:
```markdown
Last Updated: December 19, 2025
Date: 12/19/2025
Updated: 19-12-2025
Last updated: 2025/12/19
```

### Rationale

1. **ISO 8601** is internationally recognized and unambiguous
2. **Sortable** - Chronological order is preserved in text sorting
3. **Machine-parseable** - Easy to extract and validate programmatically
4. **Consistent** - Single format across all documentation

---

## Update Tracking Requirements

### When to Update Dates

Update the "Last Updated" date when:
- ✅ Content is added or modified
- ✅ Statistics or metrics are corrected
- ✅ Technical information is updated
- ✅ Phase completion status changes
- ❌ Typographical fixes only (use version number instead)

### When NOT to Update Dates

Do NOT update dates for:
- Minor typo corrections
- Formatting changes only
- Link updates
- Spelling corrections

For these, increment the **Document Version** instead.

---

## Required Date Fields by Document Type

### Technical Documentation (Implementation Guides, API References)

```markdown
# Document Title

**Document Version**: X.Y  
**Last Updated**: YYYY-MM-DD  
**Status**: ✅ Complete | 🚧 In Progress | ⚠️ Outdated | 🔲 Planned
```

### Audit Reports

```markdown
# Audit Report Title

**Audit Date**: YYYY-MM-DD  
**Audit Scope**: [Description]  
**Auditor**: [Agent/Team]  
**Status**: ✅ Complete | ⚠️ Partial
```

### Status Reports (Phase Reports, Summaries)

```markdown
# Report Title

**Report Date**: YYYY-MM-DD  
**Phase**: Phase X  
**Status**: ✅ Complete | 🚧 In Progress
```

### Developer Guides

```markdown
# Guide Title

**Last Updated**: YYYY-MM-DD  
**Version**: X.Y  
**Applies To**: [Platform/Version]
```

---

## Date Location Guidelines

### Primary Location

Place date fields in the **document header**, immediately after the title:

```markdown
# Document Title

**Document Version**: 1.0  
**Last Updated**: 2025-12-19  
**Status**: ✅ Complete
```

### Secondary Location (Optional)

For long documents with multiple sections, include a **Revision History** table:

```markdown
## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-19 | Team | Phase 5 documentation fixes |
| 0.9 | 2025-12-15 | Team | Initial draft |
```

---

## Phase 5 Documentation Fixes

All files modified during Phase 5 (2025-12-19) should include:

```markdown
**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)
```

This notation indicates:
- The date of modification (2025-12-19)
- The reason for modification (Phase 5 Documentation Fixes)
- Enables tracking of Phase 5 impact across documentation

---

## Automated Validation

### Pre-commit Hook (Recommended)

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Check for non-ISO date formats in documentation
git diff --cached --name-only | grep '\.md$' | while read file; do
  if grep -qE 'Last Updated.*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}' "$file"; then
    echo "ERROR: Non-ISO date format in $file"
    exit 1
  fi
done
```

### Validation Script

```bash
#!/bin/bash
# tools/validate_dates.sh
find docs/ -name "*.md" -type f | while read file; do
  if grep -qE '\*\*Last Updated\*\*: [0-9]{4}-[0-9]{2}-[0-9]{2}' "$file"; then
    echo "✓ $file - Valid ISO date"
  else
    echo "⚠ $file - Missing or invalid date format"
  fi
done
```

---

## Examples

### Example 1: Platform Documentation

```markdown
# Platform Support Matrix

**Document Version**: 2.0  
**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Status**: ✅ Complete - 100% Platform Achievement

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | 2025-12-19 | Platform Team | Phase 5: Updated to 100% status |
| 1.0 | 2025-12-15 | Platform Team | Initial release |
```

### Example 2: Audit Report

```markdown
# Documentation Audit Report

**Audit Date**: 2025-12-19  
**Audit Scope**: All platform documentation vs. code implementation  
**Auditor**: 24-agent documentation audit team  
**Status**: ✅ Complete

---

## Findings

[Content]
```

### Example 3: Implementation Guide

```markdown
# Windows PAL Implementation Guide

**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Version**: 1.2  
**Applies To**: Windows x86_64, PAL API v1.0
```

---

## Compliance Checklist

Before publishing any documentation:

- [ ] Date format is ISO 8601 (YYYY-MM-DD)
- [ ] "Last Updated" date reflects actual content changes
- [ ] Document version incremented for minor changes
- [ ] Date is in document header (after title)
- [ ] Phase notation added if applicable (e.g., "Phase 5 Documentation Fixes")
- [ ] Revision history updated (if document has one)

---

## Enforcement

### Phase 5 Requirements

All documentation files modified in Phase 5 MUST:
1. Use ISO 8601 date format
2. Include "(Phase 5 Documentation Fixes)" notation
3. Reflect accurate content status (100% platform completion)

### Future Requirements

Starting Phase 6:
1. All new documentation must follow this guideline
2. Existing documentation updated on next modification
3. Automated validation in CI/CD pipeline

---

## References

- [ISO 8601 Standard](https://www.iso.org/iso-8601-date-and-time-format.html)
- [Markdown Best Practices](../09-developer-guide/markdown-style-guide.md)
- [Documentation Guidelines](./DOCUMENTATION_GUIDELINES.md)

---

**Document Version**: 1.0  
**Created**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Status**: ✅ Active Standard
