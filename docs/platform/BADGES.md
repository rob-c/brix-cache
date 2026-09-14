# Platform Badges for BriX-Cache

**Purpose**: Display real-time CI/CD status and platform support in README and documentation.

---

## Current Badges (README.md)

### CI/CD Status Badges

```markdown
[![ASan/UBSan](https://github.com/rob-c/brix-cache/actions/workflows/asan.yml/badge.svg)](https://github.com/rob-c/brix-cache/actions/workflows/asan.yml)
[![Invariant guards](https://github.com/rob-c/brix-cache/actions/workflows/guards.yml/badge.svg)](https://github.com/rob-c/brix-cache/actions/workflows/guards.yml)
[![Fuzzing](https://github.com/rob-c/brix-cache/actions/workflows/fuzz.yml/badge.svg)](https://github.com/rob-c/brix-cache/actions/workflows/fuzz.yml)
[![Platform Matrix](https://github.com/rob-c/brix-cache/actions/workflows/platform-matrix.yml/badge.svg)](https://github.com/rob-c/brix-cache/actions/workflows/platform-matrix.yml)
```

### Platform Support Badges

```markdown
[![Linux x86_64](https://img.shields.io/badge/Linux-x86_64-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
[![Linux ARM64](https://img.shields.io/badge/Linux-ARM64-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
[![macOS Intel](https://img.shields.io/badge/macOS-Intel-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
[![macOS ARM64](https://img.shields.io/badge/macOS-ARM64-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
[![Windows](https://img.shields.io/badge/Windows-x86_64-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
```

### Technology Badges

```markdown
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](../../LICENSE)
[![nginx 1.28.x](https://img.shields.io/badge/nginx-1.28.x-009639?logo=nginx&logoColor=white)](https://nginx.org)
[![XRootD protocol 5.2](https://img.shields.io/badge/XRootD_protocol-5.2-8a2be2)](../05-operations/operation-status.md)
```

---

## Badge Colors

| Status | Color | Hex Code |
|--------|-------|----------|
| Complete/Success | Green | `2ea44f` |
| In Progress | Yellow | `dbab09` |
| Planned | Blue | `007ec6` |
| Not Supported | Red | `cb2431` |
| Limited/Dev | Orange | `d65d0e` |

---

## Platform Completion Badges (Post-100%)

After achieving 100% Windows PAL completion, add:

```markdown
[![Windows PAL 100%](https://img.shields.io/badge/Windows%20PAL-100%25-2ea44f)](pal/windows/WINDOWS_PAL_100_PERCENT_COMPLETE.md)
```

---

## Dynamic Badge Generation

For real-time status badges, consider using:

1. **GitHub Actions Status**: Auto-updates based on workflow status
2. **Shields.io Custom Badges**: Static badges with custom text
3. **Badge API**: Dynamic badges from CI/CD results

### Example: Dynamic Platform Status

```markdown
[![Linux x86_64 Status](https://github.com/rob-c/brix-cache/actions/workflows/platform-matrix.yml/badge.svg?label=Linux%20x86_64)](https://github.com/rob-c/brix-cache/actions/workflows/platform-matrix.yml)
```

---

## Badge Placement

### README.md Header

Place badges in this order:
1. CI/CD status (ASan, guards, fuzzing, platform matrix)
2. Platform support (Linux, macOS, Windows)
3. Technology (license, nginx version, protocol)

### Documentation Pages

Include relevant badges in:
- Platform-specific guides (e.g., `macos-quickstart.md`)
- Architecture documentation
- Release notes

---

## Badge Maintenance

**Update Frequency**: As needed (when platform status changes)

**Responsible**: Release manager / documentation maintainer

**Update Checklist**:
- [ ] Verify platform completion percentage
- [ ] Update badge color if status changed
- [ ] Update linked documentation
- [ ] Test badge rendering

---

## Badge Examples by Status

### Production Ready (Green)
```markdown
[![Linux x86_64](https://img.shields.io/badge/Linux-x86_64-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
```

### Development Ready (Green - 100% PAL Complete)
```markdown
[![Windows](https://img.shields.io/badge/Windows-100%25-2ea44f)](PLATFORM_SUPPORT_MATRIX.md)
```

### Planned (Blue)
```markdown
[![Windows ARM64](https://img.shields.io/badge/Windows%20ARM64-Planned-007ec6)](PLATFORM_EXPANSION_PLAN.md)
```

---

## Badge Analytics

Track badge clicks via:
- GitHub Insights (for GitHub Actions badges)
- Shields.io analytics (for custom badges)
- Documentation site analytics

---

**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Badge Version**: 3.0 - 5-Platform Support
