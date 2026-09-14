# Platform Documentation

This directory contains documentation for the BriX-Cache Platform Abstraction Layer (PAL) and platform support.

The implementation reports below record their respective development phases.
For the current AlmaLinux build results and outstanding verification, see the
[build and verification log](../03-configuration/BUILD.md).

## Guide collections

- [PAL architecture and development guides](pal/): API design, workflow and build integration.
- [Platform test guide](testing/README.md) and [test reports](testing/): native test setup and recorded results.
- [Darwin implementation reports](pal/darwin/) and [Windows implementation reports](pal/windows/).
- [CI configuration reports](../audit/ci-cd/): workflow and matrix records.
- [PAL source index](../../src/platform/README.md): implementation ownership and source files.

## Executive Summary - Phase 3 Complete

**Overall Platform Completion**: 100% (5/5 platforms) ✅  
**Production Ready**: 4/5 platforms (Linux x86_64/ARM64, macOS x86_64/ARM64)  
**Development Ready**: Windows x86_64 (100% complete, 60/60 core PAL functions) ✅

**Phase History**:
- **Phase 1**: Initial PAL (Linux x86_64)
- **Phase 2**: ARM64 + macOS (91% platform support)
- **Phase 3**: Windows 100% (Phase 3 Complete platform completion) ✅
- **Phase 4**: Documentation Audit (24-agent comprehensive review)
- **Phase 5**: Documentation Fixes (current - updating all docs to reflect Phase 3 Complete)

## Documents

### Current Platforms
- **[PAL Architecture](pal/ARCHITECTURE.md)** - PAL design and API reference
- **[Platform Support Matrix](SUPPORT_MATRIX.md)** - Complete 5-platform comparison
- **[macOS Support](../refactor/macos-support-v3.0.md)** - macOS implementation details
- **[macOS Optimizations](../refactor/macos-optimizations.md)** - Apple performance tuning

### Platform Expansion Plans
- **[PLATFORM_EXPANSION_PLAN.md](PLATFORM_EXPANSION_PLAN.md)** - Complete roadmap for Windows & ARM64 support

### Implementation Status

| Platform | PAL Completion | Build | Runtime | Production | Key Features |
|----------|---------------|-------|---------|------------|--------------|
| Linux x86_64 | 60/60 core PAL (100%) | ✅ | ✅ | ✅ Yes | Baseline, io_uring, seccomp |
| Linux ARM64 | 60/60 core PAL (100%) | ✅ | ✅ | ✅ Yes | CRC32C 10x, NEON 4x |
| macOS x86_64 | 60/60 core PAL (100%) | ✅ | ✅ | ✅ Yes | Full feature parity |
| macOS ARM64 | 60/60 core PAL (100%) | ✅ | ✅ | ✅ Yes | Accelerate 7.5-10x, CPU topology |
| Windows x86_64 | 60/60 core PAL (100%) ✅ | ✅ | ✅ Testing | ⚠️ Dev/Test | NTFS ADS, HANDLE/fd, CopyFile2, Security stubs |
| Windows ARM64 | 🔲 Future | 🔲 | 🔲 | ❌ No | After x86_64 100% |

**Legend**: ✅ Complete, 🚧 In Progress, 🔲 Stub Needed, ❌ Not Supported

**Note**: Windows x86_64 PAL is 100% complete (60/60 core PAL functions) as of Phase 3. Security stubs are implemented with enhancement documentation for future Job Object/AppContainer integration.

## Quick Links

- [PAL API Reference](../../src/platform/platform_api.h)
- [Windows Implementation Skeleton](../../src/platform/windows/)
- [Platform Expansion Plan](PLATFORM_EXPANSION_PLAN.md)

## Contributing

When adding support for a new platform:

1. Create `src/platform/<platform>/` directory
2. Implement all PAL API functions from `platform_api.h`
3. Add build configuration to `config` script
4. Document platform-specific limitations
5. Add tests to `tests/platform/`

See [ARCHITECTURE.md](pal/ARCHITECTURE.md) for implementation guidelines.
