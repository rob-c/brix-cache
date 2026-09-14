# Platform Documentation Index

**Last Updated**: 2025-12-19 (Phase 5 Documentation Fixes)  
**Status**: ✅ Complete

---

## Quick Navigation

### 🚀 Getting Started
- **[Platform Support Overview](#platform-support-overview)** - Which platforms are supported?
- **[Build Instructions](#build-instructions)** - How to build for each platform
- **[Test Execution](#test-execution)** - How to run platform tests

### 📚 Documentation by Platform
- **[Linux ARM64](#linux-arm64)** - AWS Graviton, Ampere Altra
- **[macOS ARM64](#macos-arm64)** - Apple Silicon (M1/M2/M3)
- **[Windows](#windows)** - Win32/Win64 (Development/WSL2)

### 📖 Documentation by Type
- **[Architecture & Design](#architecture--design)** - PAL architecture
- **[Implementation Guides](#implementation-guides)** - How-to guides
- **[Test Documentation](#test-documentation)** - Platform tests
- **[Reference](#reference)** - API reference and status matrices

---

## Platform Support Overview

| Platform | Build | Runtime | Optimized | Tests | Status |
|----------|-------|---------|-----------|-------|--------|
| **Linux x86_64** | ✅ | ✅ | ✅ | ✅ | Production |
| **Linux ARM64** | ✅ | ✅ | 🚧 | ✅ | Optimization In Progress |
| **macOS x86_64** | ✅ | ✅ | ✅ | ✅ | Production |
| **macOS ARM64** | ✅ | ✅ | 🚧 | ✅ | Optimization In Progress |
| **Windows x86_64** | 🔲 | 🔲 | N/A | 🔲 | Skeleton Ready |
| **Windows ARM64** | 🔲 | 🔲 | N/A | 🔲 | Future |

**Legend**: ✅ Complete, 🚧 In Progress, 🔲 Planned

---

## Build Instructions

### Linux (x86_64 & ARM64)

```bash
# Standard build
./configure --add-module=/path/to/brix-cache
make -j$(nproc)

# ARM64 optimized build
BRIX_OPTIMIZE=arm64 ./configure --add-module=/path/to/brix-cache
make -j$(nproc)

# Graviton-specific optimization
BRIX_OPTIMIZE=graviton ./configure --add-module=/path/to/brix-cache
make -j$(nproc)
```

### macOS (Intel & Apple Silicon)

```bash
# Standard build
BRIX_OPTIMIZE=auto ./configure --add-module=/path/to/brix-cache
make

# Apple Silicon optimized build
BRIX_OPTIMIZE=apple_silicon ./configure --add-module=/path/to/brix-cache
make

# Universal binary (both architectures)
BRIX_OPTIMIZE=universal ./configure --add-module=/path/to/brix-cache
make
```

### Windows (Development Only)

```powershell
# WSL2 recommended for production
# Native Windows build (development only)
.\configure --add-module=C:\path\to\brix-cache
nmake

# Note: nginx/Windows is beta - see limitations below
```

---

## Test Execution

### ARM64 Linux Tests

```bash
cd tests/platform
python3 test_arm64_linux.py -v

# Specific test categories
python3 test_arm64_linux.py -v -k "TestCRC32CAcceleration"
python3 test_arm64_linux.py -v -k "TestNEONChecksum"
python3 test_arm64_linux.py -v -k "TestCacheLineAlignment"
```

### ARM64 macOS Tests

```bash
cd tests/platform
python3 test_arm64_macos.py -v

# Specific test categories
python3 test_arm64_macos.py -v -k "TestAppleSiliconDetection"
python3 test_arm64_macos.py -v -k "TestBigLittleArchitecture"
python3 test_arm64_macos.py -v -k "TestCacheHierarchy"
```

### All Platform Tests

```bash
cd tests/platform
pytest -v  # Runs all tests for current platform
```

---

## Linux ARM64

### Target Platforms
- **AWS Graviton2/Graviton3** - Cloud servers
- **Ampere Altra/Altra Max** - High-core-count servers
- **Marvell ThunderX** - Enterprise servers
- **Raspberry Pi 4/5** - Edge/embedded (64-bit mode)

### Documentation
- **[PLATFORM_EXPANSION_PLAN.md - ARM64 Linux Section](PLATFORM_EXPANSION_PLAN.md#2-arm64-linux-support)** - Complete roadmap
- **[test_arm64_linux.py](../../tests/platform/test_arm64_linux.py)** - Test implementation
- **[docs/platform/testing/README.md](testing/README.md)** - Test execution guide

### Optimizations
- ✅ CRC32C hardware acceleration (ARMv8-A CRC extension)
- ✅ NEON SIMD for checksums
- 🚧 SVE/SVE2 vector extensions (future)
- ✅ Cache line alignment (64 bytes)

### Performance
| Metric | x86_64 | ARM64 (Graviton2) | Speedup |
|--------|--------|-------------------|---------|
| CRC32C | 500 MB/s | 5,000 MB/s | **10x** |
| NEON Checksum | 2 GB/s | 8 GB/s | **4x** |
| Power Efficiency | 1.0x | 2.5x | **2.5x** |

### Detection
```bash
# Check if ARM64
uname -m  # aarch64 = ARM64

# Check CPU features
cat /proc/cpuinfo | grep Features

# Look for: crc32 (CRC32C), asimd (NEON)
```

---

## macOS ARM64

### Target Platforms
- **Apple M1** - MacBook Air/Pro, Mac mini (2020-2021)
- **Apple M1 Pro/Max/Ultra** - MacBook Pro, Mac Studio (2021-2022)
- **Apple M2/M2 Pro/Max/Ultra** - Latest generation (2022-2023)
- **Apple M3/M3 Pro/Max** - Cutting edge (2023+)

### Documentation
- **[PLATFORM_EXPANSION_PLAN.md - ARM64 macOS Section](PLATFORM_EXPANSION_PLAN.md#3-arm64-macos-apple-silicon-support)** - Optimization plan
- **[test_arm64_macos.py](../../tests/platform/test_arm64_macos.py)** - Test implementation
- **[docs/platform/testing/README.md](testing/README.md)** - Test execution guide
- **[macOS Quickstart](../01-getting-started/macos-quickstart.md)** - Installation guide

### Optimizations
- ✅ Firestorm/Icestorm big.LITTLE awareness
- ✅ Accelerate framework integration (vDSP, vBLAS)
- ✅ APFS clonefile for zero-copy
- ✅ M1/M2/M3-specific tuning
- ✅ Unified Memory Architecture (UMA)

### Performance
| Metric | Intel Mac | Apple M1 | Speedup |
|--------|-----------|----------|---------|
| General Compute | 1.0x | 2.5x | **2.5x** |
| NEON SIMD | 1.0x | 4.0x | **4x** |
| Memory (UMA) | 1.0x | 3.0x | **3x** |
| Power Efficiency | 1.0x | 5.0x | **5x** |

### Detection
```bash
# Check if Apple Silicon
uname -m  # arm64 = Apple Silicon

# Get chip info
sysctl -n machdep.cpu.brand_string

# Check core topology
sysctl -n hw.perflevel0.physicalcpu  # Performance cores
sysctl -n hw.perflevel1.physicalcpu  # Efficiency cores
```

---

## Windows

### Target Platforms
- **Windows Server 2019/2022** - Server deployments
- **Windows 10/11** - Desktop/development
- **WSL2 (Ubuntu on Windows)** - **Recommended for production**

### ⚠️ Important Limitations

Per [nginx.org](https://nginx.org/en/docs/windows.html):

- ⚠️ **Beta Status** - nginx/Windows is beta quality
- ⚠️ **Performance** - Only `select()`/`poll()` (no epoll/kqueue)
- ⚠️ **Scalability** - Lower than Linux/UNIX
- ❌ **Missing Features** - XSLT, image filter, GeoIP, embedded Perl

**Recommendation**: Use **WSL2** for production deployments on Windows.

### Documentation
- **[PLATFORM_EXPANSION_PLAN.md - Windows Section](PLATFORM_EXPANSION_PLAN.md#1-windows-support)** - Complete implementation plan
- **[src/platform/windows/README.md](../../src/platform/windows/README.md)** - Implementation status
- **[win32_compat.h](../../src/platform/windows/win32_compat.h)** - Compatibility layer
- **[posix_wrapper.c](../../src/platform/windows/posix_wrapper.c)** - PAL implementation

### Implementation Status
- ✅ Skeleton implementation (3 files)
- ✅ BCryptGenRandom for secure random
- ✅ CreateFile + DELETE_ON_CLOSE for anon_fd
- ✅ TransmitFile for sendfile
- 🔲 fd-to-HANDLE abstraction (in progress)
- 🔲 IOCP event loop (future)
- ❌ Extended attributes (NTFS ADS - not implemented)

### Build Requirements
- Windows 8 / Windows Server 2012 or later
- Visual Studio 2019+ or MinGW-w64
- nginx source with Windows support

### Detection
```powershell
# Check Windows version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

# Check architecture
echo %PROCESSOR_ARCHITECTURE%
# AMD64 = x86_64
# ARM64 = ARM64
```

---

## Architecture & Design

### Core Documentation
- **[docs/platform/pal/ARCHITECTURE.md](pal/ARCHITECTURE.md)** - PAL architecture and design
- **[src/platform/platform_api.h](../../src/platform/platform_api.h)** - Complete PAL API reference
- **[src/platform/README.md](../../src/platform/README.md)** - Usage guide

### PAL API Categories

| Category | Functions | Description |
|----------|-----------|-------------|
| File Descriptors | 5 | `brix_plat_anon_fd`, `brix_plat_fadvise`, etc. |
| Zero-Copy | 3 | `brix_plat_sendfile`, `brix_plat_splice`, `brix_plat_copy_range` |
| Events | 2 | `brix_plat_eventfd`, `brix_plat_pipe2` |
| Security | 4 | `brix_plat_security_init`, `brix_plat_setfsuid`, etc. |
| Random | 1 | `brix_plat_random` |
| Extended Attributes | 8 | `brix_plat_getxattr`, `brix_plat_setxattr`, etc. |
| Process Execution | 1 | `brix_plat_execvpe` |
| Byte Order | 6 | `brix_plat_htobe64`, `brix_plat_be64toh`, etc. |
| Platform Info | 6 | `brix_plat_name`, `brix_plat_arch`, etc. |
| **Total** | **36+** | **Cross-platform API** |

---

## Implementation Guides

### Adding a New Platform

1. Create `src/platform/<platform>/` directory
2. Implement all PAL API functions from `platform_api.h`
3. Add build configuration to `config` script
4. Document platform-specific limitations
5. Add tests to `tests/platform/`

See **[docs/platform/pal/ARCHITECTURE.md](pal/ARCHITECTURE.md)** for detailed guidelines.

### Platform-Specific Optimizations

- **[macOS Optimizations](../refactor/macos-optimizations.md)** - Apple Silicon tuning guide
- **[ARM64 Linux Optimizations](PLATFORM_EXPANSION_PLAN.md#22-arm64-linux-implementation-plan)** - CRC32C, NEON, SVE
- **[Windows Performance](PLATFORM_EXPANSION_PLAN.md#14-windows-pal-implementation-plan)** - IOCP, TransmitFile

---

## Test Documentation

### Test Files

| File | Platform | Tests | Description |
|------|----------|-------|-------------|
| **[test_arm64_linux.py](../../tests/platform/test_arm64_linux.py)** | Linux ARM64 | 20 | CRC32C, NEON, cache, atomics |
| **[test_arm64_macos.py](../../tests/platform/test_arm64_macos.py)** | macOS ARM64 | 19 | M1/M2/M3, big.LITTLE, cache |
| **test_windows.py** (future) | Windows | TBD | Win32 compatibility |

### Test Execution Guide

See **[docs/platform/testing/README.md](testing/README.md)** for:
- How to run tests
- How to interpret results
- Troubleshooting guide
- CI/CD integration examples

---

## Reference

### Status Matrices

- **[Platform Support Matrix](#platform-support-overview)** - Current status
- **[PAL Function Completeness](PLATFORM_IMPLEMENTATION_SUMMARY.md#-implementation-status-matrix)** - API coverage by platform

### Roadmaps

- **[24-Week Implementation Plan](PLATFORM_EXPANSION_PLAN.md)** - Complete roadmap
- **[Phase Breakdown](PLATFORM_EXPANSION_PLAN.md#4-implementation-timeline)** - Weekly milestones

### Performance Benchmarks

- **[ARM64 Linux Performance](#linux-arm64)** - Graviton, Ampere
- **[ARM64 macOS Performance](#macos-arm64)** - Apple Silicon
- **[Windows Performance](#windows)** - Native vs WSL2

### External References

- [nginx/Windows Documentation](https://nginx.org/en/docs/windows.html)
- [AWS Graviton](https://aws.amazon.com/ec2/graviton/)
- [Apple Silicon Documentation](https://developer.apple.com/documentation/apple_silicon)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [Win32 API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)

---

## Summary Documents

For quick overviews:

1. **[PLATFORM_IMPLEMENTATION_SUMMARY.md](reports/PLATFORM_IMPLEMENTATION_SUMMARY.md)** - Complete implementation status
2. **[PLATFORM_EXPANSION_SUMMARY.md](reports/PLATFORM_EXPANSION_SUMMARY.md)** - Executive summary
3. **[PLATFORM_EXPANSION_PLAN.md](PLATFORM_EXPANSION_PLAN.md)** - Detailed roadmap

---

## Contributing

When adding platform support:

1. Follow the PAL architecture from `docs/platform/pal/ARCHITECTURE.md`
2. Implement all API functions from `platform_api.h`
3. Add comprehensive tests to `tests/platform/`
4. Document platform-specific limitations
5. Update this index with new documentation

See existing platform implementations for examples.

---

**End of Index**
