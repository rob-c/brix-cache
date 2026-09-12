#!/bin/bash
# verify_macos_support.sh - Verify macOS support build integration
# 
# This script checks that the platform abstraction layer is correctly
# integrated into the build system.

set -e

echo "=========================================="
echo "BriX-Cache macOS Support Verification"
echo "=========================================="
echo

# Check platform
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"

case "$PLATFORM" in
    Linux)
        EXPECTED_PLATFORM="linux"
        ;;
    Darwin)
        EXPECTED_PLATFORM="darwin"
        ;;
    *)
        echo "ERROR: Unsupported platform: $PLATFORM"
        exit 1
        ;;
esac

echo

# Check that platform headers exist
echo "Checking platform headers..."
HEADERS_OK=true

for header in \
    "src/platform/platform.h" \
    "src/platform/platform_api.h"
do
    if [ -f "$header" ]; then
        echo "  ✓ $header"
    else
        echo "  ✗ $header (MISSING)"
        HEADERS_OK=false
    fi
done

if [ "$HEADERS_OK" != "true" ]; then
    echo "ERROR: Missing platform headers"
    exit 1
fi

echo

# Check that platform implementations exist
echo "Checking platform implementations..."
IMPLS_OK=true

# Common implementation
if [ -f "src/platform/platform.c" ]; then
    echo "  ✓ src/platform/platform.c"
else
    echo "  ✗ src/platform/platform.c (MISSING)"
    IMPLS_OK=false
fi

# Platform-specific implementations
if [ "$EXPECTED_PLATFORM" = "linux" ]; then
    for impl in \
        "src/platform/linux/posix_wrapper.c" \
        "src/platform/linux/event_wrapper.c" \
        "src/platform/linux/fs_watcher.c" \
        "src/platform/linux/security_wrapper.c" \
        "src/platform/linux/copy_range.c"
    do
        if [ -f "$impl" ]; then
            echo "  ✓ $impl"
        else
            echo "  ✗ $impl (MISSING)"
            IMPLS_OK=false
        fi
    done
elif [ "$EXPECTED_PLATFORM" = "darwin" ]; then
    for impl in \
        "src/platform/darwin/posix_wrapper.c" \
        "src/platform/darwin/event_wrapper.c" \
        "src/platform/darwin/fs_watcher.c" \
        "src/platform/darwin/security_wrapper.c" \
        "src/platform/darwin/copy_range.c"
    do
        if [ -f "$impl" ]; then
            echo "  ✓ $impl"
        else
            echo "  ✗ $impl (MISSING)"
            IMPLS_OK=false
        fi
    done
fi

if [ "$IMPLS_OK" != "true" ]; then
    echo "ERROR: Missing platform implementations"
    exit 1
fi

echo

# Check config file modifications
echo "Checking config file modifications..."
CONFIG_OK=true

if grep -q "BRIX_PLATFORM.*auto" config; then
    echo "  ✓ Platform detection added to config"
else
    echo "  ✗ Platform detection missing from config"
    CONFIG_OK=false
fi

if grep -q "BRIX_PLATFORM_LINUX" config; then
    echo "  ✓ BRIX_PLATFORM_LINUX macro defined"
else
    echo "  ✗ BRIX_PLATFORM_LINUX macro missing"
    CONFIG_OK=false
fi

if grep -q "BRIX_PLATFORM_DARWIN" config; then
    echo "  ✓ BRIX_PLATFORM_DARWIN macro defined"
else
    echo "  ✗ BRIX_PLATFORM_DARWIN macro missing"
    CONFIG_OK=false
fi

if [ "$EXPECTED_PLATFORM" = "darwin" ]; then
    if grep -q "framework Security" config; then
        echo "  ✓ macOS Security framework linked"
    else
        echo "  ✗ macOS Security framework not linked"
        CONFIG_OK=false
    fi
fi

if [ "$CONFIG_OK" != "true" ]; then
    echo "ERROR: Config file modifications incomplete"
    exit 1
fi

echo

# Check platform-specific feature gating
echo "Checking feature gating..."

if [ "$EXPECTED_PLATFORM" = "linux" ]; then
    if grep -q 'if \[ "\$BRIX_PLATFORM" = "linux" \].*io_uring' config; then
        echo "  ✓ io_uring gated for Linux"
    else
        echo "  ⚠ io_uring gating may be incomplete"
    fi
    
    if grep -q 'if \[ "\$BRIX_PLATFORM" = "linux" \].*seccomp' config; then
        echo "  ✓ seccomp gated for Linux"
    else
        echo "  ⚠ seccomp gating may be incomplete"
    fi
    
elif [ "$EXPECTED_PLATFORM" = "darwin" ]; then
    if grep -q 'BRIX_PLATFORM.*darwin.*io_uring.*disabled' config; then
        echo "  ✓ io_uring disabled on macOS"
    else
        echo "  ⚠ io_uring macOS disable message may be missing"
    fi
    
    if grep -q 'BRIX_PLATFORM.*darwin.*seccomp.*disabled' config; then
        echo "  ✓ seccomp disabled on macOS"
    else
        echo "  ⚠ seccomp macOS disable message may be missing"
    fi
    
    if grep -q 'BRIX_PLATFORM.*darwin.*ceph.*disabled' config; then
        echo "  ✓ Ceph disabled on macOS"
    else
        echo "  ⚠ Ceph macOS disable message may be missing"
    fi
fi

echo

# Try to run configure (dry run)
echo "Testing configure script..."
if [ -x configure ] || [ -f config ]; then
    echo "  ✓ config file exists"
    
    # Check syntax
    if bash -n config 2>/dev/null; then
        echo "  ✓ config syntax is valid"
    else
        echo "  ✗ config has syntax errors"
        exit 1
    fi
else
    echo "  ⚠ config not found (this is OK if running from different directory)"
fi

echo

echo "=========================================="
echo "Verification Complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "  1. Run ./configure --with-stream --with-threads --add-module=\$(pwd)"
echo "  2. Run make -j\$(nproc)  (Linux) or make -j\$(sysctl -n hw.ncpu)  (macOS)"
echo "  3. Verify module loads: objs/nginx -t"
echo
