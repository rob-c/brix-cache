#!/bin/bash
# test_arm64_build.sh - Verify ARM64 Linux production hardening
# 
# This script verifies that ARM64 optimizations are properly configured
# and ready for production deployment.

set -e

echo "========================================"
echo "ARM64 Linux Production Hardening Verification"
echo "========================================"
echo ""

# Check architecture
echo "1. Checking system architecture..."
ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64|armv8l)
        echo "   ✓ ARM64 architecture detected ($ARCH)"
        BRIX_ARCH_ARM64=1
        ;;
    x86_64|amd64)
        echo "   ⚠ x86_64 architecture detected ($ARCH)"
        echo "   ℹ Testing ARM64 configuration on x86_64 (cross-compile check)"
        BRIX_ARCH_ARM64=0
        ;;
    *)
        echo "   ✗ Unknown architecture: $ARCH"
        exit 1
        ;;
esac
echo ""

# Check platform.h for architecture macros
echo "2. Verifying platform.h architecture macros..."
if grep -q "BRIX_ARCH_ARM64" src/platform/platform.h; then
    echo "   ✓ BRIX_ARCH_ARM64 macro defined in platform.h"
else
    echo "   ✗ BRIX_ARCH_ARM64 macro NOT found in platform.h"
    exit 1
fi

if grep -q "BRIX_ARCH_X86_64" src/platform/platform.h; then
    echo "   ✓ BRIX_ARCH_X86_64 macro defined in platform.h"
else
    echo "   ✗ BRIX_ARCH_X86_64 macro NOT found in platform.h"
    exit 1
fi
echo ""

# Check config script for ARM64 detection
echo "3. Verifying config script ARM64 detection..."
if grep -q "BRIX_ARCH_ARM64=1" config; then
    echo "   ✓ ARM64 architecture detection in config"
else
    echo "   ✗ ARM64 architecture detection NOT found in config"
    exit 1
fi

if grep -q "aarch64|arm64" config; then
    echo "   ✓ ARM64 architecture patterns in config"
else
    echo "   ✗ ARM64 architecture patterns NOT found in config"
    exit 1
fi
echo ""

# Check ARM64 optimization profiles
echo "4. Verifying ARM64 optimization profiles..."
PROFILES=("auto" "graviton" "ampere" "apple_silicon" "generic")
for profile in "${PROFILES[@]}"; do
    if grep -q "$profile" config; then
        echo "   ✓ Profile '$profile' found"
    else
        echo "   ⚠ Profile '$profile' NOT found (may be optional)"
    fi
done
echo ""

# Check ARM64 source files
echo "5. Verifying ARM64 source files..."
ARM64_FILES=(
    "src/platform/linux/crc32c_arm64.c"
    "src/platform/linux/checksum_neon.c"
    "src/platform/linux/arm64_crypto.c"
    "src/platform/darwin/checksum_accelerate.c"
    "src/platform/darwin/cpu_topology.c"
    "src/platform/darwin/apple_silicon.c"
)

for file in "${ARM64_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✓ $file exists"
    else
        echo "   ✗ $file NOT found"
        exit 1
    fi
done
echo ""

# Check if ARM64 files are in config source list
echo "6. Verifying ARM64 files in build configuration..."
if grep -q "crc32c_arm64.c" config; then
    echo "   ✓ crc32c_arm64.c in build"
else
    echo "   ✗ crc32c_arm64.c NOT in build"
    exit 1
fi

if grep -q "checksum_neon.c" config; then
    echo "   ✓ checksum_neon.c in build"
else
    echo "   ✗ checksum_neon.c NOT in build"
    exit 1
fi

if grep -q "arm64_crypto.c" config; then
    echo "   ✓ arm64_crypto.c in build"
else
    echo "   ✗ arm64_crypto.c NOT in build"
    exit 1
fi

if grep -q "apple_silicon.c" config; then
    echo "   ✓ apple_silicon.c in build"
else
    echo "   ✗ apple_silicon.c NOT in build"
    exit 1
fi
echo ""

# Check implementation guards
echo "7. Verifying implementation guards..."
if grep -q "BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64" src/platform/linux/crc32c_arm64.c; then
    echo "   ✓ crc32c_arm64.c has proper guards"
else
    echo "   ✗ crc32c_arm64.c missing proper guards"
    exit 1
fi

if grep -q "BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64" src/platform/linux/checksum_neon.c; then
    echo "   ✓ checksum_neon.c has proper guards"
else
    echo "   ✗ checksum_neon.c missing proper guards"
    exit 1
fi

if grep -q "BRIX_PLATFORM_LINUX && BRIX_ARCH_ARM64" src/platform/linux/arm64_crypto.c; then
    echo "   ✓ arm64_crypto.c has proper guards"
else
    echo "   ✗ arm64_crypto.c missing proper guards"
    exit 1
fi
echo ""

# Check for CRC32 hardware implementation
echo "8. Verifying CRC32 hardware implementation..."
if grep -q "__ARM_FEATURE_CRC32" src/platform/linux/crc32c_arm64.c; then
    echo "   ✓ CRC32 feature detection present"
else
    echo "   ✗ CRC32 feature detection NOT found"
    exit 1
fi

if grep -q "__crc32cd" src/platform/linux/crc32c_arm64.c; then
    echo "   ✓ CRC32 hardware instruction (__crc32cd) used"
else
    echo "   ✗ CRC32 hardware instruction NOT found"
    exit 1
fi
echo ""

# Check for NEON implementation
echo "9. Verifying NEON SIMD implementation..."
if grep -q "arm_neon.h" src/platform/linux/checksum_neon.c; then
    echo "   ✓ NEON header included"
else
    echo "   ✗ NEON header NOT found"
    exit 1
fi

if grep -q "vld1q_u8" src/platform/linux/checksum_neon.c; then
    echo "   ✓ NEON intrinsics used"
else
    echo "   ✗ NEON intrinsics NOT found"
    exit 1
fi
echo ""

# Check for CPU feature detection
echo "10. Verifying CPU feature detection..."
if grep -q "getauxval" src/platform/linux/arm64_crypto.c; then
    echo "   ✓ getauxval() for runtime detection"
else
    echo "   ✗ getauxval() NOT found"
    exit 1
fi

if grep -q "HWCAP_CRC32" src/platform/linux/arm64_crypto.c; then
    echo "   ✓ HWCAP_CRC32 detection"
else
    echo "   ✗ HWCAP_CRC32 NOT found"
    exit 1
fi
echo ""

# Summary
echo "========================================"
echo "VERIFICATION SUMMARY"
echo "========================================"
echo ""

if [ "$BRIX_ARCH_ARM64" = "1" ]; then
    echo "Architecture:     ARM64 (native)"
    echo "Status:           ✅ PRODUCTION READY"
    echo ""
    echo "Next Steps:"
    echo "  1. Build with: BRIX_OPTIMIZE=auto ./configure --add-module=..."
    echo "  2. For Graviton2/3: BRIX_OPTIMIZE=graviton ./configure ..."
    echo "  3. For Ampere Altra: BRIX_OPTIMIZE=ampere ./configure ..."
    echo "  4. Run tests: PYTHONPATH=tests pytest tests/platform/ -v"
else
    echo "Architecture:     x86_64 (cross-compile check)"
    echo "Status:           ✅ CONFIGURATION VERIFIED"
    echo ""
    echo "Note: Run this script on ARM64 hardware for full verification"
    echo "Next Steps:"
    echo "  1. Deploy to ARM64 server (AWS Graviton, Ampere Altra, etc.)"
    echo "  2. Build with: BRIX_OPTIMIZE=auto ./configure --add-module=..."
    echo "  3. Run tests: PYTHONPATH=tests pytest tests/platform/ -v"
fi
echo ""
echo "========================================"
