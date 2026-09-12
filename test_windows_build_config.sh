#!/bin/bash
# test_windows_build_config.sh - Verify Windows PAL build configuration
# 
# This script verifies that the config script includes all necessary
# Windows PAL source files, libraries, and compiler flags.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config"
WINDOWS_DIR="$SCRIPT_DIR/src/platform/windows"

echo "=============================================="
echo "Windows PAL Build Configuration Verification"
echo "=============================================="
echo ""

ERRORS=0
WARNINGS=0

# ============================================================================
# 1. Verify config file exists
# ============================================================================
echo "1. Checking config file..."
if [ ! -f "$CONFIG_FILE" ]; then
    echo "   ❌ FAIL: config file not found: $CONFIG_FILE"
    exit 1
fi
echo "   ✅ PASS: config file exists"
echo ""

# ============================================================================
# 2. Verify platform detection
# ============================================================================
echo "2. Checking Windows platform detection..."
if grep -q "MINGW\|MSYS\|CYGWIN\|Windows_NT" "$CONFIG_FILE"; then
    echo "   ✅ PASS: Windows platform detection present"
else
    echo "   ❌ FAIL: Windows platform detection missing"
    ERRORS=$((ERRORS + 1))
fi

if grep -q "BRIX_PLATFORM_WINDOWS=1" "$CONFIG_FILE"; then
    echo "   ✅ PASS: BRIX_PLATFORM_WINDOWS macro defined"
else
    echo "   ❌ FAIL: BRIX_PLATFORM_WINDOWS macro missing"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ============================================================================
# 3. Verify Windows libraries
# ============================================================================
echo "3. Checking Windows library linking..."
REQUIRED_LIBS=("ws2_32" "advapi32" "kernel32" "bcrypt")
for lib in "${REQUIRED_LIBS[@]}"; do
    if grep -q "\-l$lib" "$CONFIG_FILE"; then
        echo "   ✅ PASS: -$lib linked"
    else
        echo "   ❌ FAIL: -$lib not linked"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# ============================================================================
# 4. Verify compiler flags
# ============================================================================
echo "4. Checking Windows compiler flags..."
REQUIRED_FLAGS=("_WIN32_WINNT" "WIN32_LEAN_AND_MEAN" "_CRT_SECURE_NO_WARNINGS")
for flag in "${REQUIRED_FLAGS[@]}"; do
    if grep -q "$flag" "$CONFIG_FILE"; then
        echo "   ✅ PASS: $flag defined"
    else
        echo "   ⚠️  WARN: $flag not found (may be in source files)"
        WARNINGS=$((WARNINGS + 1))
    fi
done
echo ""

# ============================================================================
# 5. Verify Windows PAL source files
# ============================================================================
echo "5. Checking Windows PAL source files in config..."
REQUIRED_SOURCES=(
    "handle_abstraction.c"
    "posix_wrapper.c"
    "event_wrapper.c"
    "fs_watcher.c"
    "copy_range.c"
    "security_wrapper.c"
    "process.c"
    "xattr.c"
    "platform_detect.c"
)

for src in "${REQUIRED_SOURCES[@]}"; do
    if grep -q "platform/windows/$src" "$CONFIG_FILE"; then
        echo "   ✅ PASS: $src included"
    else
        echo "   ❌ FAIL: $src missing from config"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# ============================================================================
# 6. Verify source files exist
# ============================================================================
echo "6. Checking Windows PAL source files exist..."
for src in "${REQUIRED_SOURCES[@]}"; do
    src_path="$WINDOWS_DIR/$src"
    if [ -f "$src_path" ]; then
        lines=$(wc -l < "$src_path")
        echo "   ✅ PASS: $src exists ($lines lines)"
    else
        echo "   ❌ FAIL: $src not found at $src_path"
        ERRORS=$((ERRORS + 1))
    fi
done
echo ""

# ============================================================================
# 7. Check for duplicate function definitions
# ============================================================================
echo "7. Checking for duplicate function definitions..."
DUPLICATES_FOUND=0

# Check for functions that should only be in one file
check_duplicates() {
    local func=$1
    local files=("${@:2}")
    local count=0
    local found_in=""
    
    for file in "${files[@]}"; do
        if grep -q "^brix_plat_$func" "$WINDOWS_DIR/$file" 2>/dev/null; then
            count=$((count + 1))
            found_in="$found_in $file"
        fi
    done
    
    if [ $count -gt 1 ]; then
        echo "   ⚠️  WARN: brix_plat_$func defined in:$found_in"
        DUPLICATES_FOUND=$((DUPLICATES_FOUND + 1))
        WARNINGS=$((WARNINGS + 1))
    fi
}

# Check critical functions
check_duplicates "sendfile" "copy_range.c" "posix_wrapper.c"
check_duplicates "splice" "copy_range.c" "posix_wrapper.c"
check_duplicates "copy_range" "copy_range.c" "posix_wrapper.c"
check_duplicates "eventfd" "event_wrapper.c" "posix_wrapper.c"
check_duplicates "pipe2" "event_wrapper.c" "posix_wrapper.c"
check_duplicates "setfsuid" "security_wrapper.c" "posix_wrapper.c"
check_duplicates "setfsgid" "security_wrapper.c" "posix_wrapper.c"
check_duplicates "getxattr" "xattr.c" "posix_wrapper.c"
check_duplicates "execvpe" "process.c" "posix_wrapper.c"

if [ $DUPLICATES_FOUND -eq 0 ]; then
    echo "   ✅ PASS: No duplicate function definitions found"
fi
echo ""

# ============================================================================
# 8. Verify platform guards
# ============================================================================
echo "8. Checking platform guards in source files..."
GUARD_ERRORS=0
for src in "${REQUIRED_SOURCES[@]}"; do
    src_path="$WINDOWS_DIR/$src"
    if [ -f "$src_path" ]; then
        if grep -q "#if BRIX_PLATFORM_WINDOWS" "$src_path" || \
           grep -q "#ifdef BRIX_PLATFORM_WINDOWS" "$src_path"; then
            echo "   ✅ PASS: $src has platform guard"
        else
            echo "   ⚠️  WARN: $src missing platform guard"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
done
echo ""

# ============================================================================
# Summary
# ============================================================================
echo "=============================================="
echo "Verification Summary"
echo "=============================================="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "✅ All Windows PAL configuration checks passed!"
    echo ""
    echo "Build readiness: READY"
    echo ""
    echo "To build on Windows (MinGW/MSYS2):"
    echo "  export BRIX_PLATFORM_WINDOWS=1"
    echo "  ./configure --add-module=/path/to/brix-cache"
    echo "  make"
    exit 0
else
    echo "❌ Windows PAL configuration has $ERRORS error(s)"
    echo ""
    echo "Build readiness: NOT READY"
    echo ""
    echo "Please fix the errors above before attempting to build."
    exit 1
fi
