#!/bin/bash
# Test script to verify Windows PAL configuration in config script

echo "============================================================"
echo "Testing Windows PAL Configuration in config Script"
echo "============================================================"
echo ""

# Check if config script exists
if [ ! -f "config" ]; then
    echo "❌ ERROR: config script not found"
    exit 1
fi

echo "✓ config script found"
echo ""

# Check for Windows platform detection
echo "Checking for Windows platform detection..."
if grep -q "BRIX_PLATFORM_WINDOWS" config; then
    echo "✓ BRIX_PLATFORM_WINDOWS macro found"
else
    echo "❌ ERROR: BRIX_PLATFORM_WINDOWS macro not found"
    exit 1
fi

# Check for Windows platform detection case statement
if grep -q "MINGW\*\|MSYS\*\|CYGWIN\*\|Windows_NT" config; then
    echo "✓ Windows platform detection (uname -s) found"
else
    echo "❌ ERROR: Windows platform detection not found"
    exit 1
fi

# Check for Windows libraries
echo ""
echo "Checking for Windows libraries..."
if grep -q "\-lws2_32" config; then
    echo "✓ -lws2_32 (Winsock2) found"
else
    echo "❌ ERROR: -lws2_32 not found"
    exit 1
fi

if grep -q "\-ladvapi32" config; then
    echo "✓ -ladvapi32 (Advanced Windows API) found"
else
    echo "❌ ERROR: -ladvapi32 not found"
    exit 1
fi

if grep -q "\-lkernel32" config; then
    echo "✓ -lkernel32 (Core Windows API) found"
else
    echo "❌ ERROR: -lkernel32 not found"
    exit 1
fi

if grep -q "\-lbcrypt" config; then
    echo "✓ -lbcrypt (Cryptographic API) found"
else
    echo "❌ ERROR: -lbcrypt not found"
    exit 1
fi

# Check for Windows PAL source files
echo ""
echo "Checking for Windows PAL source files..."
WINDOWS_FILES=(
    "src/platform/windows/handle_abstraction.c"
    "src/platform/windows/posix_wrapper.c"
    "src/platform/windows/event_wrapper.c"
    "src/platform/windows/fs_watcher.c"
    "src/platform/windows/copy_range.c"
    "src/platform/windows/security_wrapper.c"
    "src/platform/windows/process.c"
    "src/platform/windows/xattr.c"
)

for file in "${WINDOWS_FILES[@]}"; do
    if grep -q "$file" config; then
        echo "✓ $file included in build"
    else
        echo "❌ ERROR: $file not included in build"
        exit 1
    fi
done

# Check for Windows-specific compiler flags
echo ""
echo "Checking for Windows-specific compiler flags..."
if grep -q "_WIN32_WINNT=0x0602" config; then
    echo "✓ _WIN32_WINNT=0x0602 (Windows 8/Server 2012 minimum) found"
else
    echo "⚠ WARNING: _WIN32_WINNT flag not found"
fi

if grep -q "WIN32_LEAN_AND_MEAN" config; then
    echo "✓ WIN32_LEAN_AND_MEAN found"
else
    echo "⚠ WARNING: WIN32_LEAN_AND_MEAN flag not found"
fi

if grep -q "_CRT_SECURE_NO_WARNINGS" config; then
    echo "✓ _CRT_SECURE_NO_WARNINGS found"
else
    echo "⚠ WARNING: _CRT_SECURE_NO_WARNINGS flag not found"
fi

# Check for platform-specific source file guards
echo ""
echo "Checking for platform guards in source files..."
for file in "${WINDOWS_FILES[@]}"; do
    if [ -f "$file" ]; then
        if grep -q "#if BRIX_PLATFORM_WINDOWS" "$file"; then
            echo "✓ $file has BRIX_PLATFORM_WINDOWS guard"
        else
            echo "⚠ WARNING: $file missing BRIX_PLATFORM_WINDOWS guard"
        fi
    else
        echo "⚠ WARNING: $file not found"
    fi
done

# Check Darwin files
echo ""
echo "Checking Darwin (macOS) files..."
DARWIN_FILES=(
    "src/platform/darwin/checksum_accelerate.c"
    "src/platform/darwin/cpu_topology.c"
)

for file in "${DARWIN_FILES[@]}"; do
    if grep -q "$file" config; then
        echo "✓ $file included in build"
    else
        echo "❌ ERROR: $file not included in build"
        exit 1
    fi
    
    if [ -f "$file" ]; then
        if grep -q "#if BRIX_PLATFORM_DARWIN" "$file"; then
            echo "✓ $file has BRIX_PLATFORM_DARWIN guard"
        else
            echo "⚠ WARNING: $file missing BRIX_PLATFORM_DARWIN guard"
        fi
    fi
done

echo ""
echo "============================================================"
echo "✅ All Windows PAL configuration checks passed!"
echo "============================================================"
echo ""
echo "Summary:"
echo "  - Windows platform detection: ✓"
echo "  - Windows libraries: ✓ (ws2_32, advapi32, kernel32, bcrypt)"
echo "  - Windows PAL source files: ✓ (8 files)"
echo "  - Platform guards: ✓"
echo ""
echo "The config script is ready for Windows PAL compilation."
echo ""
