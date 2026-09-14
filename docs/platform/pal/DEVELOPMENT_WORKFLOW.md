# Platform Development Workflow

**Quick Start**: See [Development Workflow](#development-workflow) below.

---

## Overview

Each platform directory (`linux/`, `darwin/`, `windows/`) includes a Makefile for **isolated development iteration**. These Makefiles enable rapid syntax checking, static analysis, and code quality validation **before** full integration builds with nginx.

---

## Makefile Targets

### Common Targets (All Platforms)

| Target | Description | Example |
|--------|-------------|---------|
| `make` | Build all object files | `make` |
| `make clean` | Remove `.o` files and coverage data | `make clean` |
| `make debug` | Debug build (`-g3 -O0`) | `make debug` |
| `make release` | Optimized build (`-O3 -march=native`) | `make release` |
| `make info` | Show build configuration | `make info` |
| `make analyze` | Static analysis (clang/gcc analyzer) | `make analyze` |
| `make coverage` | Build with coverage instrumentation | `make coverage` |

### Platform-Specific Targets

#### Linux
```bash
cd src/platform/linux/
make          # Standard build
make debug    # Debug symbols, no optimization
make release  # Native optimizations
```

#### macOS
```bash
cd src/platform/darwin/
make                # Auto-detect architecture
make intel          # x86_64 build
make apple_silicon  # ARM64 build (M1/M2/M3)
make universal      # Fat binary (both architectures)
```

#### Windows (Cross-compile from Linux/macOS)
```bash
cd src/platform/windows/
make          # MinGW-w64 x86_64 (default)
make x86      # MinGW-w64 i686 (32-bit)
make cross    # Cross-compile indicator
```

---

## Development Workflow

### 1. Daily Development Cycle

```bash
# Edit source files
vim src/platform/linux/posix_wrapper.c

# Quick syntax check
cd src/platform/linux/
make clean && make 2>&1 | grep -E "error:|warning:"

# Fix any issues
vim src/platform/linux/posix_wrapper.c

# Repeat until clean
```

### 2. Pre-Commit Validation

```bash
# Run static analysis
cd src/platform/linux/
make clean analyze

# Or on macOS
cd src/platform/darwin/
make clean analyze

# Check for common issues
clang-tidy src/platform/linux/*.c
```

### 3. Cross-Platform Validation

```bash
# Validate Linux code
cd src/platform/linux/
make clean && make 2>&1 | tail -5

# Validate macOS code
cd src/platform/darwin/
make clean && make 2>&1 | tail -5

# Validate Windows code (cross-compile)
cd src/platform/windows/
make clean && make 2>&1 | tail -5
```

### 4. Performance Testing

```bash
# Build release version
cd src/platform/linux/
make release

# Or for macOS with architecture-specific optimizations
cd src/platform/darwin/
make apple_silicon  # For M1/M2/M3
make intel          # For Intel Macs
```

### 5. Coverage Testing

```bash
# Build with coverage
cd src/platform/linux/
make coverage

# Run tests
cd ../../../../tests/
python3 -m pytest test_platform_*.py

# Generate coverage report
cd ../../src/platform/linux/
gcov *.c
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

---

## Important Notes

### ⚠️ Standalone vs Integrated Builds

**These Makefiles are for DEVELOPMENT ITERATION ONLY.**

They provide:
- ✅ Fast syntax checking
- ✅ Static analysis
- ✅ Code quality validation
- ✅ Isolated compilation tests

They do **NOT** provide:
- ❌ Full nginx integration (requires nginx build system)
- ❌ Linking with nginx core
- ❌ Runtime testing (use nginx test suite)

**For production builds**, always use the nginx build system:
```bash
cd /tmp/nginx-1.28.3/
./configure --add-module=/Users/rcurrie/src/brix-cache
make
```

### 📦 Dependencies

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential clang-tools gcovr

# RHEL/CentOS
sudo yum install gcc gcc-analyzer gcov
```

**macOS:**
```bash
# Xcode Command Line Tools
xcode-select --install

# Optional: clang-tidy
brew install llvm
```

**Windows (Cross-compile):**
```bash
# Ubuntu/Debian
sudo apt-get install mingw-w64

# macOS (Homebrew)
brew install mingw-w64
```

---

## Troubleshooting

### Error: `ngx_core.h: No such file or directory`

**Expected** - These Makefiles don't include nginx headers. They're for syntax checking only.

**Solution**: Use for syntax validation, then test with full nginx build.

### Error: `undefined reference to brix_plat_*`

**Expected** - PAL functions are defined across multiple files.

**Solution**: Build all files together or use nginx build system.

### Error: `unrecognized command line option '-march=armv8.5-a'`

**Cause**: Using old compiler that doesn't support ARM64 optimizations.

**Solution**: Update compiler or use generic flags:
```bash
make CFLAGS="-O3 -march=armv8-a"
```

---

## Best Practices

### 1. Always Run Static Analysis Before Committing

```bash
cd src/platform/linux/
make analyze 2>&1 | grep -v "note:"
```

### 2. Use Debug Builds During Development

```bash
make debug  # Enables assertions, debug symbols
```

### 3. Test on All Target Platforms

```bash
# Linux
cd src/platform/linux/ && make clean && make

# macOS
cd src/platform/darwin/ && make clean && make

# Windows (cross-compile)
cd src/platform/windows/ && make clean && make
```

### 4. Keep PAL API Consistent

When adding new functions:
1. Add declaration to `platform_api.h`
2. Implement in all platform directories
3. Use stubs (`return -ENOSYS`) for unavailable features
4. Update documentation

### 5. Document Platform Differences

```c
/*
 * Linux: Uses memfd_create()
 * macOS: Uses mkstemp() + unlink()
 * Windows: Uses CreateFile() + FILE_FLAG_DELETE_ON_CLOSE
 */
int brix_plat_anon_fd(const char *name, const char *dir);
```

---

## Example Session

```bash
# Working on Linux PAL improvements
cd /Users/rcurrie/src/brix-cache/src/platform/linux/

# Quick iteration cycle
vim posix_wrapper.c
make clean && make 2>&1 | grep error
# Fix compilation errors
vim posix_wrapper.c
make
# Success!

# Run static analysis
make analyze

# Build release version for performance testing
make release

# Now test with full nginx build
cd /tmp/nginx-1.28.3/
make clean
./configure --add-module=/Users/rcurrie/src/brix-cache
make
```

---

## File Structure

```
src/platform/
├── linux/
│   ├── Makefile           # ← This file's workflow
│   ├── posix_wrapper.c
│   ├── event_wrapper.c
│   └── ...
├── darwin/
│   ├── Makefile           # ← Intel/Apple Silicon builds
│   ├── posix_wrapper.c
│   └── ...
└── windows/
    ├── Makefile           # ← MinGW-w64 cross-compile
    ├── posix_wrapper.c
    └── ...
```

---

## Next Steps

1. **Daily Development**: Use `make clean && make` for quick validation
2. **Pre-Commit**: Run `make analyze` for static analysis
3. **Before Merge**: Test on all platforms (linux, darwin, windows)
4. **Release**: Use nginx build system for final binaries

For questions, see:
- [PAL Architecture](ARCHITECTURE.md)
- [Platform Expansion Plan](../PLATFORM_EXPANSION_PLAN.md)

---

**Last Updated**: 2025-12-12  
**Maintainer**: Platform Abstraction Layer Team
