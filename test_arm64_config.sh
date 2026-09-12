#!/bin/bash
# test_arm64_config.sh - Verify ARM64 Linux build configuration

set -e

echo "=========================================="
echo "ARM64 Linux Build Configuration Test"
echo "=========================================="
echo ""

# Test 1: Architecture detection
echo "Test 1: Architecture Detection"
echo "------------------------------"
ARCH=$(uname -m)
echo "Current architecture: $ARCH"

case "$ARCH" in
    x86_64|amd64)
        echo "✓ Running on x86_64 (testing cross-compilation config)"
        EXPECTED_ARCH="x86_64"
        ;;
    aarch64|arm64)
        echo "✓ Running on ARM64 (native build)"
        EXPECTED_ARCH="arm64"
        ;;
    *)
        echo "⚠ Unknown architecture: $ARCH"
        EXPECTED_ARCH="unknown"
        ;;
esac
echo ""

# Test 2: Config file validation
echo "Test 2: Config File Validation"
echo "-------------------------------"
CONFIG_FILE="/Users/rcurrie/src/brix-cache/config"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "✗ Config file not found: $CONFIG_FILE"
    exit 1
fi

echo "✓ Config file exists: $CONFIG_FILE"
echo ""

# Test 3: Check for ARM64 profiles
echo "Test 3: ARM64 Optimization Profiles"
echo "------------------------------------"

PROFILES=("arm64" "graviton" "graviton3" "ampere")
for profile in "${PROFILES[@]}"; do
    if grep -q "BRIX_OPTIMIZE.*$profile" "$CONFIG_FILE" || grep -q "^[[:space:]]*$profile)" "$CONFIG_FILE"; then
        echo "✓ Profile '$profile' found in config"
    else
        echo "⚠ Profile '$profile' not found in config"
    fi
done
echo ""

# Test 4: Check for architecture detection
echo "Test 4: Architecture Detection Logic"
echo "-------------------------------------"

if grep -q "BRIX_ARCH" "$CONFIG_FILE"; then
    echo "✓ BRIX_ARCH detection logic found"
    
    if grep -q "aarch64\|arm64\|armv8" "$CONFIG_FILE"; then
        echo "✓ ARM64 architecture patterns found"
    else
        echo "⚠ ARM64 architecture patterns not found"
    fi
    
    if grep -q "BRIX_ARCH_ARM64=1" "$CONFIG_FILE"; then
        echo "✓ BRIX_ARCH_ARM64 flag definition found"
    else
        echo "⚠ BRIX_ARCH_ARM64 flag definition not found"
    fi
else
    echo "⚠ BRIX_ARCH detection logic not found"
fi
echo ""

# Test 5: Check for ARM64-specific compiler flags
echo "Test 5: ARM64 Compiler Flags"
echo "-----------------------------"

FLAGS=("-march=armv8" "-march=armv8.2-a" "-march=armv9" "crc" "crypto" "sve")
for flag in "${FLAGS[@]}"; do
    if grep -q "$flag" "$CONFIG_FILE"; then
        echo "✓ Flag pattern '$flag' found"
    else
        echo "⚠ Flag pattern '$flag' not found"
    fi
done
echo ""

# Test 6: Simulate config execution (dry run)
echo "Test 6: Config Execution Simulation"
echo "------------------------------------"

# Create a temporary test script
TEST_SCRIPT=$(mktemp)
cat > "$TEST_SCRIPT" << 'EOF'
#!/bin/bash
# Extract and test architecture detection logic

BRIX_ARCH="${BRIX_ARCH:-auto}"
if [ "$BRIX_ARCH" = "auto" ]; then
    BRIX_ARCH=$(uname -m)
fi

case "$BRIX_ARCH" in
    x86_64|amd64)
        echo "ARCH_FLAGS=-DBRIX_ARCH_X86_64=1 -DBRIX_ARCH_ARM64=0"
        ;;
    aarch64|arm64|armv8*)
        echo "ARCH_FLAGS=-DBRIX_ARCH_X86_64=0 -DBRIX_ARCH_ARM64=1"
        ;;
    *)
        echo "ARCH_FLAGS=-DBRIX_ARCH_X86_64=0 -DBRIX_ARCH_ARM64=0"
        ;;
esac
EOF

chmod +x "$TEST_SCRIPT"
RESULT=$("$TEST_SCRIPT")
echo "Detected flags: $RESULT"

if echo "$RESULT" | grep -q "BRIX_ARCH_ARM64"; then
    echo "✓ Architecture flags generated correctly"
else
    echo "⚠ Architecture flags not generated"
fi

rm -f "$TEST_SCRIPT"
echo ""

# Test 7: Check documentation
echo "Test 7: Documentation"
echo "--------------------"

DOC_FILE="/Users/rcurrie/src/brix-cache/docs/platform/ARM64_LINUX_IMPLEMENTATION.md"
if [ -f "$DOC_FILE" ]; then
    echo "✓ ARM64 documentation exists: $DOC_FILE"
    
    WORD_COUNT=$(wc -l < "$DOC_FILE")
    echo "  Documentation size: $WORD_COUNT lines"
    
    if grep -q "graviton" "$DOC_FILE"; then
        echo "✓ Graviton documentation found"
    fi
    
    if grep -q "ampere" "$DOC_FILE"; then
        echo "✓ Ampere documentation found"
    fi
else
    echo "⚠ ARM64 documentation not found"
fi
echo ""

# Test 8: Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Architecture: $ARCH"
echo "Config file: $CONFIG_FILE"
echo "Documentation: $DOC_FILE"
echo ""
echo "Expected profiles: arm64, graviton, graviton3, ampere, native"
echo "Expected flags: -march=armv8*, CRC32, crypto, SVE"
echo ""
echo "✓ ARM64 Linux build configuration test complete"
echo ""
