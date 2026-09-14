# Platform Test Suite

The files described here remain in [`tests/platform/`](../../../tests/platform/).
Directory listings below refer to that source location; command working
directories are unchanged by this guide’s relocation.

Comprehensive test suite for BriX-Cache Platform Abstraction Layer (PAL) across all supported platforms.

## Test Organization

```
tests/platform/
├── run_platform_tests.py          # Multi-platform test runner
├── test_pal_api.py                # Common PAL API tests (all platforms)
├── test_windows.py                # Windows native & WSL2 tests
├── test_arm64_linux.py            # ARM64 Linux tests (Graviton, Ampere)
└── test_arm64_macos.py            # ARM64 macOS tests (Apple Silicon)
```

The associated documentation is now under `docs/`: [README.md](README.md).

The public `test_*.py` entry points retain their pytest node IDs and fixture
scopes. Larger suites re-export case classes through ordinary imports:

| Entry point | Case owners | Shared setup |
|---|---|---|
| [test_phase3_integration.py](../../../tests/platform/test_phase3_integration.py) | [I/O](../../../tests/platform/pal_cases_integration_io.py), [system APIs](../../../tests/platform/pal_cases_integration_system.py), [workflows](../../../tests/platform/pal_cases_integration_workflows.py) | [pal_integration_support.py](../../../tests/platform/pal_integration_support.py) |
| [test_windows.py](../../../tests/platform/test_windows.py) | [I/O](../../../tests/platform/pal_cases_windows_io.py), [system APIs](../../../tests/platform/pal_cases_windows_system.py) | [pal_windows_support.py](../../../tests/platform/pal_windows_support.py) |
| [test_windows_pal_100percent.py](../../../tests/platform/test_windows_pal_100percent.py) | [I/O](../../../tests/platform/pal_cases_windows_api_io.py), [metadata](../../../tests/platform/pal_cases_windows_api_metadata.py), [system APIs](../../../tests/platform/pal_cases_windows_api_system.py), [workflows](../../../tests/platform/pal_cases_windows_api_workflows.py) | [pal_windows_api_support.py](../../../tests/platform/pal_windows_api_support.py) |

Hardware reporting lives in [Linux ARM helpers](../../../tests/platform/pal_arm_linux_helpers.py) and
[Apple Silicon helpers](../../../tests/platform/pal_arm_macos_helpers.py). The
[integration helpers](../../../tests/platform/pal_integration_helpers.py) and
[Windows helpers](../../../tests/platform/pal_windows_helpers.py) own repeated workflow checks.
[report_coverage.py](../../../tests/platform/report_coverage.py) follows the explicit case imports using
[pal_coverage_sources.py](../../../tests/platform/pal_coverage_sources.py), which reads source without
loading platform libraries. Its decorator inventory describes declared tests;
it does not establish native coverage on platforms where those tests skip.

## Quick Start

### Run All Tests for Current Platform

```bash
cd tests/platform
python3 run_platform_tests.py
```

The runners use the current Python interpreter and preserve inherited pytest
options. The platform runner selects the common API suite plus the host's
architecture-specific file once. The integration runner accepts `--platform`
as a host requirement; a mismatched OS or architecture fails before pytest.
`--performance` selects the actual `TestPerformanceRegression` class.

```bash
python3 run_phase3_tests.py --platform linux --junit
python3 run_phase3_tests.py --performance
```

Optional `--html` and `--coverage` reports require `pytest-html` and `pytest-cov`.
Coverage describes the Python test adapter, not execution of native C code.
Child failures, an empty selection, and signal exits all remain nonzero.

### Run Specific Test Suite

```bash
# Windows tests
pytest test_windows.py -v

# ARM64 Linux tests
pytest test_arm64_linux.py -v

# Apple Silicon tests
pytest test_arm64_macos.py -v

# Common PAL API tests
pytest test_pal_api.py -v
```

### Run with Markers

```bash
# Windows: Native only
pytest test_windows.py -m "native_windows" -v

# Windows: WSL2 only
pytest test_windows.py -m "wsl2" -v

# ARM64 Linux: CRC32 hardware
pytest test_arm64_linux.py -m "crc32" -v

# ARM64 macOS: M1 chip
pytest test_arm64_macos.py -m "m1" -v

# ARM64 macOS: Accelerate framework
pytest test_arm64_macos.py -m "accelerate" -v
```

## Test Coverage

### Windows (`test_windows.py`)

| Category | Tests | Status |
|----------|-------|--------|
| Platform Detection | Version, Admin, WSL2 | ✅ Complete |
| HANDLE/fd Abstraction | anon_fd, conversion, sockets | ✅ Complete |
| Eventfd Emulation | Pipes, events, semantics | ✅ Complete |
| File System Watcher | ReadDirectoryChangesW | ✅ Complete |
| Zero-Copy Transfers | TransmitFile, CopyFile2 | ✅ Complete |
| Cryptographic RNG | BCryptGenRandom | ✅ Complete |
| WSL2 vs Native | Path, env, permissions | ✅ Complete |
| Administrator Tests | Privileges, tokens | ✅ Complete |

**Platform Markers**:
- `@pytest.mark.windows` - All Windows tests
- `@pytest.mark.native_windows` - Native Windows (not WSL2)
- `@pytest.mark.wsl2` - Windows Subsystem for Linux
- `@pytest.mark.server` - Windows Server 2019/2022
- `@pytest.mark.win10` - Windows 10/11
- `@pytest.mark.admin` - Requires Administrator

### ARM64 Linux (`test_arm64_linux.py`)

| Category | Tests | Status |
|----------|-------|--------|
| Platform Detection | CPU features, cloud provider | ✅ Complete |
| Endianness | Byte order validation | ✅ Complete |
| Cache Alignment | Line size detection | ✅ Complete |
| Atomic Operations | LSE support, counters | ✅ Complete |
| CRC32 Hardware | Feature detection, performance | ✅ Complete |
| NEON SIMD | Feature detection, vector ops | ✅ Complete |
| SVE/SVE2 | Vector extension detection | ✅ Complete |
| Performance | Bandwidth, integer ops | ✅ Complete |

**Platform Markers**:
- `@pytest.mark.arm64` - All ARM64 tests
- `@pytest.mark.arm64_linux` - ARM64 Linux specific
- `@pytest.mark.crc32` - CRC32 hardware acceleration
- `@pytest.mark.neon` - NEON SIMD tests
- `@pytest.mark.sve` - SVE/SVE2 extensions
- `@pytest.mark.graviton` - AWS Graviton specific
- `@pytest.mark.ampere` - Ampere Altra specific

### ARM64 macOS (`test_arm64_macos.py`)

| Category | Tests | Status |
|----------|-------|--------|
| Platform Detection | Chip detection, big.LITTLE | ✅ Complete |
| Unified Memory | Memory architecture | ✅ Complete |
| Rosetta 2 | Translation detection | ✅ Complete |
| Accelerate Framework | vecLib, vDSP, performance | ✅ Complete |
| APFS Clonefile | Availability, performance | ✅ Complete |
| NEON SIMD | Performance benchmarks | ✅ Complete |
| Crypto Extensions | ARM64 crypto, CoreCrypto | ✅ Complete |
| Performance | Bandwidth, single-thread | ✅ Complete |
| Thermal/Power | Efficiency characteristics | ✅ Complete |

**Platform Markers**:
- `@pytest.mark.arm64` - All ARM64 tests
- `@pytest.mark.arm64_macos` - ARM64 macOS specific
- `@pytest.mark.apple_silicon` - Apple Silicon tests
- `@pytest.mark.m1` - M1 chip tests
- `@pytest.mark.m2` - M2 chip tests
- `@pytest.mark.m3` - M3 chip tests
- `@pytest.mark.accelerate` - Accelerate framework
- `@pytest.mark.clonefile` - APFS clonefile

## Platform Detection

The test suite automatically detects:

### Windows
- Native Windows vs WSL2
- Windows version (10/11, Server 2019/2022)
- Administrator privileges
- Win32 API availability

### Linux ARM64
- CPU features (CRC32, NEON, SVE)
- Cloud provider (AWS Graviton, Ampere Altra)
- Cache line size
- Memory bandwidth

### macOS ARM64
- Chip generation (M1/M2/M3)
- CPU topology (Firestorm/Icestorm)
- Unified memory size
- Rosetta 2 translation status
- Accelerate framework availability

## Requirements

### All Platforms
- Python 3.8+
- pytest 7.0+
- NumPy (for performance tests)

### Windows
- Windows 10/11 or Windows Server 2019/2022
- Visual C++ Redistributable (for ctypes)

### Linux ARM64
- Linux kernel 4.15+
- /proc/cpuinfo access

### macOS ARM64
- macOS 10.12+ (for clonefile)
- Xcode Command Line Tools

## Example Output

### Windows Native
```
========================================
BriX-Cache Platform Test Runner
========================================
Platform: windows
Architecture: x86_64
WSL2: No

Running Windows platform tests...

----------------------------------------
Native Windows Tests
----------------------------------------
test_windows.py::TestHandleFdAbstraction::test_anon_fd_create PASSED
test_windows.py::TestHandleFdAbstraction::test_handle_to_fd_conversion PASSED
test_windows.py::TestEventfdEmulation::test_pipe_create PASSED

Created anonymous fd: 3
fd: 3 -> HANDLE: 0x12345678
Created pipe: read=256, write=260
Pipe read/write test passed: b'test'

========================================
Platform Tests Complete
========================================
```

### ARM64 Linux (Graviton)
```
========================================
BriX-Cache Platform Test Runner
========================================
Platform: linux
Architecture: arm64
WSL2: No

Running ARM64 Linux tests...

----------------------------------------
CRC32 Hardware Tests
----------------------------------------
test_arm64_linux.py::TestCRC32Hardware::test_crc32_feature_detection PASSED

✓ CRC32 hardware acceleration available
  -> ARMv8-A CRC extension present
  -> Use __crc32cb/__crc32cw/__crc32cd intrinsics

----------------------------------------
Performance Tests
----------------------------------------
test_arm64_linux.py::TestPerformanceComparison::test_memory_bandwidth PASSED

Memory bandwidth estimate:
  Array size: 100.0 MB
  Bandwidth: 85432.5 MB/s
  ✓ High bandwidth (server-grade)

========================================
Platform Tests Complete
========================================
```

### ARM64 macOS (M1)
```
========================================
BriX-Cache Platform Test Runner
========================================
Platform: darwin
Architecture: arm64
WSL2: No

Running Apple Silicon tests...

----------------------------------------
Apple Silicon Detection
----------------------------------------
test_arm64_macos.py::TestAppleSiliconDetection::test_chip_detection PASSED

Chip: Apple M1
  -> M1 generation

----------------------------------------
Accelerate Framework Tests
----------------------------------------
test_arm64_macos.py::TestAccelerateFramework::test_accelerate_availability PASSED

✓ Accelerate framework available
  Path: /System/Library/Frameworks/Accelerate.framework

----------------------------------------
APFS Clonefile Tests
----------------------------------------
test_arm64_macos.py::TestAPFSClonefile::test_clonefile_basic PASSED

✓ clonefile succeeded
  Source: /var/folders/.../brix_test
  Destination: /var/folders/.../brix_test.clone
  Size: 1024 bytes
  -> Zero-copy clone (APFS feature)

========================================
Platform Tests Complete
========================================
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Platform Tests

on: [push, pull_request]

jobs:
  test-windows:
    runs-on: windows-2022
    steps:
      - uses: actions/checkout@v3
      - name: Run Windows tests
        run: |
          cd tests/platform
          pytest test_windows.py -v -m "native_windows"

  test-arm64-linux:
    runs-on: [self-hosted, linux, arm64]
    steps:
      - uses: actions/checkout@v3
      - name: Run ARM64 Linux tests
        run: |
          cd tests/platform
          pytest test_arm64_linux.py -v

  test-apple-silicon:
    runs-on: macos-14  # M1 runner
    steps:
      - uses: actions/checkout@v3
      - name: Run Apple Silicon tests
        run: |
          cd tests/platform
          pytest test_arm64_macos.py -v
```

## Troubleshooting

### Tests Fail on Windows
- Ensure running as Administrator for privileged tests
- Check Visual C++ Redistributable is installed
- Verify Windows SDK paths

### Tests Fail on ARM64 Linux
- Ensure `/proc/cpuinfo` is readable
- Check kernel supports ARM64 features
- Verify cloud provider metadata access

### Tests Fail on macOS
- Ensure Xcode Command Line Tools installed
- Check System Integrity Protection (SIP) settings
- Verify Accelerate framework path

## Contributing

When adding new platform tests:

1. Use appropriate markers for platform/chip type
2. Include platform detection guards (`if not IS_WINDOWS: pytest.skip()`)
3. Provide clear output with `print()` statements
4. Test on multiple platform variants when possible
5. Document requirements in this README

## References

- [PAL API Documentation](../../../src/platform/platform_api.h)
- [Windows Implementation](../../../src/platform/windows/)
- [Platform Expansion Plan](../PLATFORM_EXPANSION_PLAN.md)
- [ARM64 Linux Optimizations](../PLATFORM_EXPANSION_PLAN.md#2-arm64-linux-support)
- [Apple Silicon Optimizations](../PLATFORM_EXPANSION_PLAN.md#3-arm64-macos-apple-silicon-support)
