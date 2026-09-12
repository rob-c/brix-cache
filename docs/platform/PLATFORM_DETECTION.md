# Platform Detection for BriX-Cache

**Purpose**: Automatically detect platform capabilities and configure optimal build settings.

---

## Overview

The `detect_platform_features.py` script provides runtime detection of:

- **Platform**: Linux, macOS, Windows
- **Architecture**: x86_64, ARM64, ARMv7, RISC-V
- **CPU Features**: SIMD extensions, crypto acceleration, etc.
- **Compiler Capabilities**: LTO, PGO support
- **Optimization Flags**: Recommended `-march`, `-mtune`, etc.
- **Runtime Environment**: CI detection, CPU count, memory

This enables:
- ✅ Automatic build optimization
- ✅ CI/CD platform-aware builds
- ✅ Performance tuning per deployment target
- ✅ Feature gating based on hardware capabilities

---

## Usage

### Basic Usage

```bash
# JSON output (default)
python3 tools/ci/detect_platform_features.py

# Verbose mode (summary to stderr, JSON to stdout)
python3 tools/ci/detect_platform_features.py --verbose

# CI-friendly format (key=value pairs)
python3 tools/ci/detect_platform_features.py --ci-format

# Save to file
python3 tools/ci/detect_platform_features.py --output /tmp/platform.json
```

### Integration with Build Systems

#### Makefile
```makefile
PLATFORM_INFO := $(shell python3 tools/ci/detect_platform_features.py --ci-format)
MARCH := $(shell echo "$(PLATFORM_INFO)" | grep "^optimization_flags=" | \
           python3 -c "import sys,json; print(json.loads(sys.stdin.read().split('=',1)[1])['march'][0])")

CFLAGS += $(MARCH) -O3
```

#### CMake
```cmake
execute_process(
    COMMAND python3 ${CMAKE_SOURCE_DIR}/tools/ci/detect_platform_features.py --output ${CMAKE_BINARY_DIR}/platform.json
)

file(READ ${CMAKE_BINARY_DIR}/platform_info/platform.json PLATFORM_JSON)
# Parse JSON with string manipulation or use a JSON library
```

#### Autotools (configure.ac)
```autoconf
AC_MSG_CHECKING([platform features])
PLATFORM_JSON=$(python3 "${srcdir}/tools/ci/detect_platform_features.py")
AC_MSG_RESULT([detected])

# Extract values
MARCH=$(echo "$PLATFORM_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['optimization_flags']['march'][0])")
CFLAGS="$CFLAGS $MARCH"
```

---

## Output Format

### JSON Output

```json
{
  "platform": {
    "name": "darwin",
    "system": "Darwin",
    "release": "24.6.0",
    "machine": "x86_64",
    "macos": {
      "version": "15.8",
      "build": "24H23"
    }
  },
  "architecture": {
    "raw": "x86_64",
    "normalized": "x86_64",
    "family": "x86_64",
    "features": {
      "has_sse": true,
      "has_avx2": true,
      "has_aes": true
    }
  },
  "compiler": {
    "name": "clang",
    "version": "17.0.0",
    "supports_lto": true,
    "supports_lto_thin": true
  },
  "optimization_flags": {
    "march": ["-march=x86-64-v3"],
    "mtune": ["-mtune=haswell"],
    "ldflags": ["-Wl,-dead_strip"]
  },
  "runtime": {
    "cpu_count": 12,
    "total_memory_mb": 32768,
    "is_ci": false
  },
  "recommendations": {
    "platform_flags": {
      "BRIX_PLATFORM_DARWIN": "1"
    },
    "enable_lto": "thin"
  }
}
```

### CI Format

```bash
platform={"name": "darwin", ...}
architecture={"raw": "x86_64", ...}
compiler={"name": "clang", ...}
optimization_flags={"march": ["-march=x86-64-v3"], ...}
runtime={"cpu_count": 12, ...}
recommendations={"enable_lto": "thin", ...}
```

---

## Detected Features by Architecture

### x86_64

| Feature | Detection Method | Build Flag |
|---------|-----------------|------------|
| SSE | `/proc/cpuinfo` flags | `-msse` |
| SSE2 | `/proc/cpuinfo` flags | `-msse2` (baseline) |
| SSE4.2 | `/proc/cpuinfo` flags | `-msse4.2` |
| AVX | `/proc/cpuinfo` flags | `-mavx` |
| AVX2 | `/proc/cpuinfo` flags | `-mavx2` |
| AVX-512 | `/proc/cpuinfo` flags | `-mavx512f` |
| AES-NI | `/proc/cpuinfo` flags | `-maes` |
| CRC32 | `/proc/cpuinfo` flags | `-mcrc32` |

**Microarchitecture Levels**:
- `x86-64-v2`: SSE4.2 (Core 2, Nehalem)
- `x86-64-v3`: AVX2 (Haswell, Zen)
- `x86-64-v4`: AVX-512 (Skylake-X, Zen 4)

### ARM64

| Feature | Detection Method | Build Flag |
|---------|-----------------|------------|
| CRC32 | `/proc/cpuinfo` Features | `-march=armv8-a+crc` |
| AES | `/proc/cpuinfo` Features | `+crypto` |
| SHA1/SHA2 | `/proc/cpuinfo` Features | `+crypto` |
| NEON | Always present | `-mfpu=neon` |
| LSE | `/proc/cpuinfo` Features | `+lse` |
| SVE | `/proc/cpuinfo` Features | `+sve` |

**Apple Silicon**:
- M1: `armv8.3-a`, `-mtune=apple-m1`
- M2: `armv8.4-a`, `-mtune=apple-m2`
- M3: `armv8.5-a`, `-mtune=apple-m3`

### ARMv7

| Feature | Detection Method | Build Flag |
|---------|-----------------|------------|
| NEON | `/proc/cpuinfo` Features | `-mfpu=neon` |
| VFPv3 | `/proc/cpuinfo` Features | `-mfpu=vfpv3` |
| VFPv4 | `/proc/cpuinfo` Features | `-mfpu=vfpv4` |

---

## Compiler Detection

### Supported Compilers

- **GCC**: Version detection, LTO, PGO support
- **Clang**: Version detection, thin LTO, PGO support
- **Apple Clang**: Version detection, thin LTO support

### Detected Capabilities

| Capability | Test Method | Flag |
|------------|-------------|------|
| LTO | Compile with `-flto` | `-flto` |
| Thin LTO | Compile with `-flto=thin` | `-flto=thin` |
| PGO | Compile with `-fprofile-generate` | `-fprofile-use` |

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Detect platform
  id: platform
  run: |
    python3 tools/ci/detect_platform_features.py --output /tmp/platform.json
    MARCH=$(jq -r '.optimization_flags.march[0]' /tmp/platform.json)
    echo "march=$MARCH" >> $GITHUB_OUTPUT

- name: Build
  run: |
    export CFLAGS="${{ steps.platform.outputs.march }} -O3"
    ./configure --add-module=...
    make
```

### GitLab CI

```yaml
variables:
  PLATFORM_JSON: $(python3 tools/ci/detect_platform_features.py)

build:
  script:
    - MARCH=$(echo $PLATFORM_JSON | jq -r '.optimization_flags.march[0]')
    - export CFLAGS="$MARCH -O3"
    - ./configure && make
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Detect Platform') {
            steps {
                script {
                    def platformInfo = sh(
                        script: 'python3 tools/ci/detect_platform_features.py',
                        returnStdout: true
                    ).trim()
                    env.MARCH = readJSON(text: platformInfo)
                        .optimization_flags.march[0]
                }
            }
        }
        stage('Build') {
            steps {
                sh '''
                    export CFLAGS="$MARCH -O3"
                    ./configure && make
                '''
            }
        }
    }
}
```

---

## Examples

### Example 1: Auto-Configure Build

```bash
#!/bin/bash
set -e

# Detect platform
PLATFORM=$(python3 tools/ci/detect_platform_features.py)

# Extract optimization flags
MARCH=$(echo "$PLATFORM" | jq -r '.optimization_flags.march[0]')
MTUNE=$(echo "$PLATFORM" | jq -r '.optimization_flags.mtune[0]')
ENABLE_LTO=$(echo "$PLATFORM" | jq -r '.recommendations.enable_lto')

# Set environment
export CFLAGS="$MARCH $MTUNE -O3"
if [ "$ENABLE_LTO" = "thin" ]; then
    export CFLAGS="$CFLAGS -flto=thin"
elif [ "$ENABLE_LTO" = "full" ]; then
    export CFLAGS="$CFLAGS -flto"
fi

# Configure and build
./configure --add-module=/path/to/brix-cache
make -j$(nproc)
```

### Example 2: Multi-Architecture CI

```bash
#!/bin/bash
# Run on multiple architectures and collect results

ARCHS=("x86_64" "arm64")
for ARCH in "${ARCHS[@]}"; do
    echo "=== Building for $ARCH ==="
    
    # Use cross-compiler or native runner
    docker run --rm -v $(pwd):/src ubuntu-$ARCH \
        python3 /src/tools/ci/detect_platform_features.py --verbose
    
    # Build and test...
done
```

### Example 3: Performance Benchmarking

```bash
#!/bin/bash
# Test different optimization levels

python3 tools/ci/detect_platform_features.py --verbose

# Baseline
CFLAGS="-O2" make clean && make && ./run_benchmark > baseline.txt

# Optimized
MARCH=$(python3 tools/ci/detect_platform_features.py | jq -r '.optimization_flags.march[0]')
CFLAGS="$MARCH -O3" make clean && make && ./run_benchmark > optimized.txt

# LTO
CFLAGS="$MARCH -O3 -flto=thin" make clean && make && ./run_benchmark > lto.txt

# Compare results
echo "=== Performance Comparison ==="
paste baseline.txt optimized.txt lto.txt
```

---

## Troubleshooting

### Issue: Script fails on Windows

**Solution**: Use WSL or install Python 3.x. Windows detection is limited.

```bash
# On WSL
python3 tools/ci/detect_platform_features.py

# Native Windows (PowerShell)
py -3 tools/ci/detect_platform_features.py
```

### Issue: Incorrect architecture detection

**Solution**: Check if running under emulation (Rosetta 2, QEMU).

```bash
# macOS Rosetta check
sysctl -n sysctl.proc_translated  # 1 = running under Rosetta

# Linux QEMU check
cat /proc/cpuinfo | grep "model name"
```

### Issue: Compiler not detected

**Solution**: Ensure compiler is in PATH and supports `--version`.

```bash
# Check compiler
which gcc clang cc
gcc --version
clang --version

# Set CC explicitly
export CC=gcc
python3 tools/ci/detect_platform_features.py
```

---

## API Reference

### Python Module Usage

```python
from tools.ci.detect_platform_features import (
    detect_platform,
    detect_architecture,
    detect_compiler_support,
    detect_optimization_flags,
)

# Detect platform
platform = detect_platform()
print(f"Running on {platform['name']} {platform['release']}")

# Detect architecture
arch = detect_architecture()
if arch['features'].get('has_avx2'):
    print("AVX2 available!")

# Get optimization flags
opt_flags = detect_optimization_flags()
print(f"Recommended: {' '.join(opt_flags['march'])}")
```

---

## Future Enhancements

- [ ] Runtime CPU feature detection (CPUID instruction)
- [ ] Cache line size detection
- [ ] NUMA topology detection
- [ ] GPU detection for offload
- [ ] More CI provider detection
- [ ] Build cache integration
- [ ] Performance regression tracking

---

## References

- [x86-64 Microarchitecture Levels](https://en.wikipedia.org/wiki/X86-64#Microarchitecture_levels)
- [ARM CPU Features](https://developer.arm.com/documentation/)
- [GCC Optimization Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [Clang Optimization Flags](https://clang.llvm.org/docs/UsersManual.html)
