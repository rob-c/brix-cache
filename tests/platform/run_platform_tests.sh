#!/bin/bash
#
# run_platform_tests.sh - Multi-Platform Test Runner
#
# Runs platform-specific tests based on detected platform.
# Supports: Linux (x86_64/ARM64), macOS (x86_64/ARM64), Windows (native/WSL2)
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TEST_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}BriX-Cache Platform Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Detect platform
PLATFORM=""
ARCH=""
IS_WSL2=false

case "$(uname -s)" in
    Linux)
        PLATFORM="linux"
        if grep -qi microsoft /proc/version 2>/dev/null; then
            IS_WSL2=true
            echo -e "${YELLOW}Detected: WSL2 on Windows${NC}"
        fi
        ;;
    Darwin)
        PLATFORM="darwin"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        PLATFORM="windows"
        ;;
esac

case "$(uname -m)" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    aarch64|arm64|ARM64)
        ARCH="arm64"
        ;;
esac

echo -e "${GREEN}Platform:${NC} $PLATFORM"
echo -e "${GREEN}Architecture:${NC} $ARCH"
if [ "$IS_WSL2" = true ]; then
    echo -e "${YELLOW}WSL2:${NC} Yes"
fi
echo ""

# Function to run tests with markers
run_tests() {
    local test_file=$1
    local markers=$2
    local description=$3
    
    echo -e "${BLUE}----------------------------------------${NC}"
    echo -e "${BLUE}$description${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    
    if [ -f "$test_file" ]; then
        if [ -n "$markers" ]; then
            echo "Running: pytest $test_file -m \"$markers\" -v"
            PYTHONPATH="$TEST_DIR/../.." pytest "$test_file" -m "$markers" -v --tb=short
        else
            echo "Running: pytest $test_file -v"
            PYTHONPATH="$TEST_DIR/../.." pytest "$test_file" -v --tb=short
        fi
    else
        echo -e "${YELLOW}Test file not found: $test_file${NC}"
    fi
    
    echo ""
}

# Run platform-specific tests
case "$PLATFORM" in
    linux)
        echo -e "${GREEN}Running Linux platform tests...${NC}"
        echo ""
        
        if [ "$ARCH" = "arm64" ]; then
            # ARM64 Linux tests
            run_tests "test_arm64_linux.py" "" "ARM64 Linux Tests"
            run_tests "test_arm64_linux.py" "crc32" "CRC32 Hardware Tests"
            run_tests "test_arm64_linux.py" "neon" "NEON SIMD Tests"
            run_tests "test_arm64_linux.py" "graviton" "AWS Graviton Tests"
            run_tests "test_arm64_linux.py" "ampere" "Ampere Altra Tests"
        else
            # x86_64 Linux tests
            echo -e "${YELLOW}x86_64 Linux tests not yet implemented${NC}"
            echo "Running generic platform tests..."
        fi
        ;;
        
    darwin)
        echo -e "${GREEN}Running macOS platform tests...${NC}"
        echo ""
        
        if [ "$ARCH" = "arm64" ]; then
            # ARM64 macOS (Apple Silicon) tests
            run_tests "test_arm64_macos.py" "" "Apple Silicon Tests"
            run_tests "test_arm64_macos.py" "apple_silicon" "Apple Silicon Detection"
            run_tests "test_arm64_macos.py" "accelerate" "Accelerate Framework Tests"
            run_tests "test_arm64_macos.py" "clonefile" "APFS Clonefile Tests"
            run_tests "test_arm64_macos.py" "m1" "M1 Chip Tests"
            run_tests "test_arm64_macos.py" "m2" "M2 Chip Tests"
            run_tests "test_arm64_macos.py" "m3" "M3 Chip Tests"
        else
            # x86_64 macOS tests
            echo -e "${YELLOW}x86_64 macOS tests not yet implemented${NC}"
        fi
        ;;
        
    windows)
        echo -e "${GREEN}Running Windows platform tests...${NC}"
        echo ""
        
        if [ "$IS_WSL2" = true ]; then
            # WSL2 tests
            run_tests "test_windows.py" "wsl2" "WSL2 Tests"
        else
            # Native Windows tests
            run_tests "test_windows.py" "native_windows" "Native Windows Tests"
            run_tests "test_windows.py" "server" "Windows Server Tests"
            run_tests "test_windows.py" "win10" "Windows 10/11 Tests"
            run_tests "test_windows.py" "admin" "Administrator Privilege Tests"
        fi
        ;;
        
    *)
        echo -e "${RED}Unknown platform: $PLATFORM${NC}"
        exit 1
        ;;
esac

# Run common platform tests (all platforms)
echo -e "${BLUE}----------------------------------------${NC}"
echo -e "${BLUE}Common Platform Tests${NC}"
echo -e "${BLUE}----------------------------------------${NC}"

if [ -f "test_pal_api.py" ]; then
    echo "Running PAL API tests..."
    PYTHONPATH="$TEST_DIR/../.." pytest test_pal_api.py -v --tb=short
else
    echo -e "${YELLOW}Common PAL API tests not found${NC}"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Platform Tests Complete${NC}"
echo -e "${GREEN}========================================${NC}"
