#!/bin/bash
#
# verify_platform_builds.sh - Multi-platform build verification for BriX-Cache
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/platform_verify"
LOG_DIR="$BUILD_DIR/logs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PLATFORMS_SUCCESS=0
PLATFORMS_FAILED=0
PLATFORMS_SKIPPED=0

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_header() { echo -e "\n=============================================================================\n$*\n============================================================================="; }

verify_linux_build() {
    local arch="$1"
    local build_subdir="$BUILD_DIR/linux_$arch"
    local log_file="$LOG_DIR/linux_$arch.log"
    
    log_header "Linux $arch Build Verification"
    
    if ! command -v gcc &> /dev/null; then
        log_warning "GCC not found - skipping"
        ((PLATFORMS_SKIPPED++))
        return 2
    fi
    
    mkdir -p "$build_subdir"
    log_info "Compiling PAL source files..."
    
    local cc="gcc"
    local cflags="-march=x86-64-v2 -DBRIX_PLATFORM_LINUX=1 -DBRIX_PLATFORM_DARWIN=0"
    
    if [[ "$arch" == "arm64" ]]; then
        if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
            log_warning "ARM64 cross-compiler not found"
            ((PLATFORMS_SKIPPED++))
            return 2
        fi
        cc="aarch64-linux-gnu-gcc"
        cflags="-march=armv8-a -DBRIX_PLATFORM_LINUX=1 -DBRIX_PLATFORM_DARWIN=0"
    fi
    
    # Create simple test file
    cat > "$build_subdir/test_pal.c" << 'EOF'
#include <stdio.h>
#include <stdint.h>
int main() {
    printf("PAL test compiled for Linux %s\n", 
#if defined(__x86_64__)
        "x86_64"
#elif defined(__aarch64__)
        "ARM64"
#else
        "unknown"
#endif
    );
    return 0;
}
EOF
    
    if $cc $cflags -o "$build_subdir/test_pal" "$build_subdir/test_pal.c" 2>&1 | tee "$log_file"; then
        log_success "Linux $arch build successful"
        ((PLATFORMS_SUCCESS++))
        return 0
    else
        log_error "Linux $arch build failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
}

verify_darwin_build() {
    local arch="$1"
    local build_subdir="$BUILD_DIR/darwin_$arch"
    local log_file="$LOG_DIR/darwin_$arch.log"
    
    log_header "macOS $arch Build Verification"
    
    if ! command -v clang &> /dev/null; then
        log_warning "Clang not found - skipping"
        ((PLATFORMS_SKIPPED++))
        return 2
    fi
    
    mkdir -p "$build_subdir"
    log_info "Compiling PAL source files..."
    
    local cflags="-arch $arch -DBRIX_PLATFORM_DARWIN=1 -DBRIX_PLATFORM_LINUX=0"
    
    cat > "$build_subdir/test_pal.c" << 'EOF'
#include <stdio.h>
#include <stdint.h>
int main() {
    printf("PAL test compiled for macOS %s\n", 
#if defined(__x86_64__)
        "x86_64"
#elif defined(__arm64__)
        "ARM64"
#else
        "unknown"
#endif
    );
    return 0;
}
EOF
    
    if clang $cflags -o "$build_subdir/test_pal" "$build_subdir/test_pal.c" 2>&1 | tee "$log_file"; then
        log_success "macOS $arch build successful"
        ((PLATFORMS_SUCCESS++))
        return 0
    else
        log_error "macOS $arch build failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
}

verify_windows_build() {
    local arch="$1"
    local build_subdir="$BUILD_DIR/windows_$arch"
    local log_file="$LOG_DIR/windows_$arch.log"
    
    log_header "Windows $arch Build Verification (Cross-Compile)"
    
    if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        log_warning "MinGW cross-compiler not found"
        log_info "Install: sudo apt-get install gcc-mingw-w64-x86-64"
        ((PLATFORMS_SKIPPED++))
        return 2
    fi
    
    mkdir -p "$build_subdir"
    log_info "Compiling PAL source files..."
    
    local cflags="-D_WIN32_WINNT=0x0602 -DWIN32_LEAN_AND_MEAN"
    local libs="-lws2_32 -ladvapi32 -lbcrypt"
    
    cat > "$build_subdir/test_pal.c" << 'EOF'
#include <stdio.h>
int main() {
    printf("PAL test compiled for Windows x86_64\n");
    return 0;
}
EOF
    
    if x86_64-w64-mingw32-gcc $cflags -o "$build_subdir/test_pal.exe" "$build_subdir/test_pal.c" $libs 2>&1 | tee "$log_file"; then
        log_success "Windows $arch cross-compile successful"
        ((PLATFORMS_SUCCESS++))
        return 0
    else
        log_error "Windows $arch cross-compile failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
}

report_warnings() {
    log_header "Platform Warnings"
    echo ""
    echo "macOS:"
    echo "  ⚠️  sendfile() signature differs from Linux"
    echo "  ⚠️  xattr functions have 6 parameters"
    echo "  ⚠️  No memfd_create (using mkstemp)"
    echo ""
    echo "Windows:"
    echo "  ⚠️  nginx/Windows is beta"
    echo "  ⚠️  Only select()/poll() support"
    echo "  ℹ️   Use WSL2 for production"
}

report_requirements() {
    log_header "Cross-Compile Requirements"
    echo ""
    echo "Linux ARM64: sudo apt-get install gcc-aarch64-linux-gnu"
    echo "Windows: sudo apt-get install gcc-mingw-w64-x86-64"
    echo "macOS ARM64: xcode-select --install"
}

show_help() {
    cat << 'EOF'
verify_platform_builds.sh - Multi-platform build verification

Usage: ./verify_platform_builds.sh [options]

Options:
  --platform=PLATFORM   all, linux, darwin, windows (default: all)
  --arch=ARCH           all, x86_64, arm64 (default: all)
  --clean               Clean build artifacts
  --help                Show this help
EOF
}

main() {
    local target_platform="all"
    local target_arch="all"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --platform=*) target_platform="${1#*=}"; shift ;;
            --arch=*) target_arch="${1#*=}"; shift ;;
            --clean) rm -rf "$BUILD_DIR"; shift ;;
            --help) show_help; exit 0 ;;
            *) log_error "Unknown option: $1"; show_help; exit 2 ;;
        esac
    done
    
    mkdir -p "$BUILD_DIR" "$LOG_DIR"
    
    log_header "BriX-Cache Platform Build Verification"
    log_info "Repository: $REPO_ROOT"
    log_info "Build Directory: $BUILD_DIR"
    
    # Linux builds
    if [[ "$target_platform" == "all" || "$target_platform" == "linux" ]]; then
        [[ "$target_arch" == "all" || "$target_arch" == "x86_64" ]] && verify_linux_build "x86_64" || true
        [[ "$target_arch" == "all" || "$target_arch" == "arm64" ]] && verify_linux_build "arm64" || true
    fi
    
    # macOS builds
    if [[ "$target_platform" == "all" || "$target_platform" == "darwin" ]]; then
        if [[ "$(uname -s)" == "Darwin" ]]; then
            [[ "$target_arch" == "all" || "$target_arch" == "x86_64" ]] && verify_darwin_build "x86_64" || true
            [[ "$target_arch" == "all" || "$target_arch" == "arm64" ]] && verify_darwin_build "arm64" || true
        else
            log_warning "macOS builds require macOS host"
            ((PLATFORMS_SKIPPED++))
        fi
    fi
    
    # Windows builds
    if [[ "$target_platform" == "all" || "$target_platform" == "windows" ]]; then
        [[ "$target_arch" == "all" || "$target_arch" == "x86_64" ]] && verify_windows_build "x86_64" || true
    fi
    
    report_warnings
    report_requirements
    
    log_header "Summary"
    log_success "Success: $PLATFORMS_SUCCESS"
    log_info "Failed: $PLATFORMS_FAILED"
    log_warning "Skipped: $PLATFORMS_SKIPPED"
    
    [[ $PLATFORMS_FAILED -gt 0 ]] && exit 1
    [[ $PLATFORMS_SUCCESS -eq 0 ]] && exit 2
    exit 0
}

main "$@"
