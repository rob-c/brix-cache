# Platform Matrix CI/CD Quick Start

**Quick reference for using the BriX-Cache platform matrix workflow**

---

## 🚀 Quick Start

### 1. Automatic Testing (Push/PR)

The workflow automatically runs on:
- Push to `main` or `develop` branches
- Pull requests affecting platform code

**Trigger paths**:
```
src/platform/**
shared/cvmfs/platform/**
config
.github/workflows/platform-matrix.yml
```

### 2. Manual Testing (Workflow Dispatch)

Go to: **Actions** → **Platform Matrix Tests** → **Run workflow**

**Options**:
- `all` - Test all 5 platforms (default)
- `linux-x86_64` - Test only Linux Intel
- `linux-arm64` - Test only Linux ARM64
- `macos-intel` - Test only macOS Intel
- `macos-arm64` - Test only macOS Apple Silicon
- `windows` - Test only Windows

---

## 📊 View Results

### During Execution

1. Go to **Actions** tab
2. Select workflow run
3. Click on individual jobs to see logs

### After Completion

1. Check **Summary** section for pass/fail matrix
2. Download artifacts from workflow run page
3. View test results in JUnit XML format

**Artifacts** (retained for 30 days):
- `nginx-linux-x86_64` - Linux Intel binary
- `nginx-linux-arm64` - Linux ARM64 binary
- `nginx-macos-intel` - macOS Intel binary
- `nginx-macos-arm64` - macOS Apple Silicon binary
- `test-results-*` - JUnit XML test reports

---

## 🧪 Test Coverage

### What's Tested

**13 PAL API Tests**:
- ✅ Platform detection (name, arch, CPU count, memory)
- ✅ Byte-order operations (64-bit, 32-bit, 16-bit)
- ✅ File descriptor operations (anon_fd, pipe2)
- ✅ Random number generation
- ✅ File synchronization (fsync_data)
- ✅ Platform-specific features

### Test Output Example

```
tests/platform/test_pal_api.py::test_pal_platform_name PASSED
tests/platform/test_pal_api.py::test_pal_arch PASSED
tests/platform/test_pal_api.py::test_pal_cpu_count PASSED
tests/platform/test_pal_api.py::test_pal_memory PASSED
tests/platform/test_pal_api.py::test_pal_htobe64_roundtrip PASSED
tests/platform/test_pal_api.py::test_pal_htobe32_roundtrip PASSED
tests/platform/test_pal_api.py::test_pal_htobe16_roundtrip PASSED
tests/platform/test_pal_api.py::test_pal_anon_fd_basic PASSED
tests/platform/test_pal_api.py::test_pal_pipe2 PASSED
tests/platform/test_pal_api.py::test_pal_random_basic PASSED
tests/platform/test_pal_api.py::test_pal_fsync_data PASSED
tests/platform/test_pal_api.py::test_pal_linux_specific PASSED
tests/platform/test_pal_api.py::test_pal_darwin_specific PASSED

==================== 13 passed in 2.34s ====================
```

---

## 🔧 Local Testing

### Using `act` (GitHub Actions Local Runner)

```bash
# Install act
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run specific job
act push -j test-linux-x86_64
act push -j test-macos-arm64

# Run all jobs (requires significant resources)
act push

# Run with dry-run (validate workflow)
act -n
```

### Validate Workflow Syntax

```bash
# Install actionlint
brew install actionlint

# Validate workflow
actionlint .github/workflows/platform-matrix.yml

# Validate YAML syntax
yamllint .github/workflows/platform-matrix.yml
```

---

## 📈 Platform-Specific Checks

### Linux x86_64

```bash
# Check binary
file objs/nginx
# Expected: ELF 64-bit LSB executable, x86-64

# Check optimizations
objdump -d objs/nginx | grep -i "avx2"  # Should find AVX2 instructions
```

### Linux ARM64

```bash
# Check binary
file objs/nginx
# Expected: ELF 64-bit LSB executable, ARM aarch64

# Check ARM64 optimizations
objdump -d objs/nginx | grep -i "crc32"  # CRC32 instructions
objdump -d objs/nginx | grep -i "asimd"  # NEON/ASIMD instructions
```

### macOS Intel

```bash
# Check binary
file objs/nginx
# Expected: Mach-O 64-bit executable x86_64

# Check version
objs/nginx -v
# Expected: nginx version: nginx/1.28.3
```

### macOS Apple Silicon

```bash
# Check binary
file objs/nginx
# Expected: Mach-O 64-bit executable arm64

# Check architecture
otool -hv objs/nginx | grep -i "arm64"
```

### Windows

```powershell
# Check PAL layer compilation
cl /c src\platform\windows\posix_wrapper.c

# Check binary (if full build succeeds)
nginx.exe -v
```

---

## ⚠️ Troubleshooting

### Build Fails on One Platform

**Symptom**: Single platform job fails, others pass

**Action**:
1. Check job logs for platform-specific errors
2. Verify platform-specific dependencies
3. Check compiler flags for that platform
4. Review PAL implementation for platform bugs

**Example**:
```yaml
# If Linux ARM64 fails:
# Check if ARM64-specific code compiles
grep -r "BRIX_ARCH_ARM64" src/platform/
```

### Test Timeout

**Symptom**: Tests hang or timeout

**Action**:
1. Increase `TEST_TIMEOUT` in `tests/platform/test_pal_api.py`
2. Check for resource contention on runner
3. Review test for infinite loops

**Fix**:
```python
# In test_pal_api.py
TEST_TIMEOUT = 60  # Increase from 30 to 60 seconds
```

### Artifact Download Fails

**Symptom**: Artifacts not available after workflow

**Action**:
1. Check workflow run permissions
2. Verify artifact retention period (30 days)
3. Ensure workflow completed successfully

---

## 📚 Additional Resources

- **Full Documentation**: `.github/PLATFORM_MATRIX_CONFIG.md`
- **Workflow File**: `.github/workflows/platform-matrix.yml`
- **Test Suite**: `tests/platform/test_pal_api.py`
- **PAL API Reference**: `src/platform/platform_api.h`
- **Platform Expansion Plan**: `docs/platform/PLATFORM_EXPANSION_PLAN.md`

---

## 🎯 Common Workflows

### Test Before Merging PR

```bash
# 1. Push to feature branch
git push feature/my-platform-fix

# 2. Wait for workflow to complete (~10 minutes)

# 3. Check all 5 platforms passed

# 4. Merge PR
```

### Test Specific Platform After Changes

```bash
# 1. Go to Actions → Platform Matrix Tests

# 2. Click "Run workflow"

# 3. Select platform (e.g., "macos-arm64")

# 4. Click "Run workflow"

# 5. Check results in ~8 minutes
```

### Download and Test Binary Locally

```bash
# 1. Go to workflow run

# 2. Download artifact (e.g., nginx-macos-arm64)

# 3. Extract and test
tar xzf nginx-macos-arm64.tar.gz
./objs/nginx -t
./objs/nginx -v
```

---

**Last Updated**: 2025-12-12  
**Maintainer**: Platform Abstraction Layer Team
