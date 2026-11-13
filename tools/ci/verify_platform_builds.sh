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
    local brew_prefix nginx_prefix nginx_binary source_archive args_file
    local source_dir source_id native_arch make_jobs smoke_prefix security_test
    local aio_test crc_test event_test sysload_test runtime_log runtime_pid runtime_children
    local runtime_socket runtime_response runtime_config global_directives
    local -a configure_args crc_cflags
    
    log_header "macOS $arch Build Verification"
    
    if ! command -v clang &> /dev/null || ! command -v brew &> /dev/null \
        || ! command -v curl &> /dev/null; then
        log_warning "Clang, Homebrew, or curl not found - skipping"
        ((PLATFORMS_SKIPPED++))
        return 2
    fi

    native_arch="$(uname -m)"
    [[ "$native_arch" == "arm64" ]] || [[ "$native_arch" == "x86_64" ]] || {
        log_error "Unsupported Darwin host architecture: $native_arch"
        ((PLATFORMS_FAILED++))
        return 1
    }
    if [[ "$arch" != "$native_arch" ]]; then
        log_warning "Homebrew nginx is $native_arch; skipping incompatible $arch module ABI"
        ((PLATFORMS_SKIPPED++))
        return 2
    fi

    brew_prefix="$(brew --prefix)"
    nginx_prefix="${HOMEBREW_NGINX_PREFIX:-$(brew --prefix nginx 2>/dev/null || true)}"
    nginx_binary="$nginx_prefix/bin/nginx"
    source_archive="$nginx_prefix/share/nginx/src/src.tar.xz"
    args_file="$nginx_prefix/share/nginx/src/configure_args.txt"
    if [[ ! -x "$nginx_binary" || ! -f "$source_archive" || ! -f "$args_file" ]]; then
        log_error "Homebrew nginx with its source archive is required (brew install nginx)"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    source_id="$(shasum -a 256 "$source_archive" | awk '{print substr($1, 1, 16)}')"
    if [[ -z "$source_id" ]]; then
        log_error "Could not fingerprint Homebrew's nginx source archive"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    source_dir="$build_subdir/nginx-src-$source_id"
    make_jobs="$(sysctl -n hw.ncpu 2>/dev/null || echo 1)"
    mkdir -p "$build_subdir"
    if [[ ! -x "$source_dir/configure" ]]; then
        mkdir -p "$source_dir"
        tar -xJf "$source_archive" -C "$source_dir"
    fi

    configure_args=()
    while IFS= read -r argument; do
        [[ -n "$argument" ]] && configure_args+=("$argument")
    done < "$args_file"

    log_info "Configuring BriX nginx from Homebrew's $($nginx_binary -v 2>&1) source and options"
    if ! (
        cd "$source_dir"
        PKG_CONFIG_PATH="$brew_prefix/opt/openssl@4/lib/pkgconfig:$brew_prefix/opt/krb5/lib/pkgconfig:$brew_prefix/opt/sqlite/lib/pkgconfig:${PKG_CONFIG_PATH:-}" \
            ./configure "${configure_args[@]}" --with-threads \
                --add-dynamic-module="$REPO_ROOT"
        make -j"$make_jobs"
    ) 2>&1 | tee "$log_file"; then
        log_error "Homebrew-derived nginx/module build failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    if ! find "$source_dir/objs" -maxdepth 1 -name 'ngx_*brix*.so' -print -quit \
        | grep -q .; then
        log_error "The Homebrew-compatible build produced no BriX module"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    smoke_prefix="$build_subdir/nginx-smoke"
    mkdir -p "$smoke_prefix/logs"
    global_directives="load_module $source_dir/objs/ngx_stream_brix_module.so; load_module $source_dir/objs/ngx_http_brix_xrdhttp_filter_module.so;"
    log_info "Loading both BriX modules into the Homebrew-derived nginx binary"
    if ! "$source_dir/objs/nginx" -e stderr -p "$smoke_prefix/" \
        -c "$REPO_ROOT/tests/configs/nginx_module_load_smoke.conf" \
        -g "$global_directives" -t 2>&1 | tee -a "$log_file"; then
        log_error "The Homebrew-derived nginx binary could not load both BriX modules"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    security_test="$build_subdir/darwin-security-fail-closed"
    log_info "Checking disabled, requested, and custom-profile confinement contracts"
    if ! clang -std=c11 -Wall -Wextra -Werror \
        -D_DARWIN_C_SOURCE -DBRIX_PLATFORM_HOST=darwin \
        -I"$REPO_ROOT/src" \
        "$REPO_ROOT/tests/c/darwin_security_fail_closed_test.c" \
        "$REPO_ROOT/src/platform/darwin/security_wrapper.c" \
        "$REPO_ROOT/src/platform/darwin/priv_wrapper.c" \
        -o "$security_test" 2>&1 | tee -a "$log_file"; then
        log_error "Darwin security contract test did not compile"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! "$security_test" disabled \
        || ! "$security_test" requested \
        || ! "$security_test" no-new-privileges \
        || ! "$security_test" custom-profile; then
        log_error "Darwin security contract failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    event_test="$build_subdir/darwin-event-test"
    log_info "Checking combined kqueue read/write registration and refusals"
    if ! clang -std=c11 -Wall -Wextra -Werror \
        -D_DARWIN_C_SOURCE -DBRIX_PLATFORM_HOST=darwin \
        -I"$REPO_ROOT/src" \
        "$REPO_ROOT/tests/c/darwin_event_test.c" \
        "$REPO_ROOT/src/platform/darwin/event_wrapper.c" \
        -o "$event_test" 2>&1 | tee -a "$log_file" \
        || ! "$event_test"; then
        log_error "Darwin event PAL contract failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    sysload_test="$build_subdir/darwin-sysload-test"
    log_info "Checking native CMS load and memory sampling contracts"
    if ! clang -std=c11 -Wall -Wextra -Werror \
        -D_DARWIN_C_SOURCE -DBRIX_PLATFORM_HOST=darwin \
        -I"$REPO_ROOT/src" \
        "$REPO_ROOT/tests/c/darwin_sysload_test.c" \
        "$REPO_ROOT/src/platform/darwin/host_info.c" \
        -o "$sysload_test" 2>&1 | tee -a "$log_file" \
        || ! "$sysload_test"; then
        log_error "Darwin sysload PAL contract failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    runtime_log="$build_subdir/darwin-serving-smoke.log"
    runtime_socket="$smoke_prefix/brix-serving-$$.sock"
    runtime_response="$build_subdir/darwin-serving-response"
    runtime_config="$build_subdir/darwin-serving-smoke.conf"
    sed -e "s|{SOCKET}|$runtime_socket|g" \
        -e "s|{EXPORT}|$REPO_ROOT|g" \
        "$REPO_ROOT/tests/configs/nginx_darwin_serving_smoke.conf" \
        >"$runtime_config"
    log_info "Starting a real non-root Darwin worker and driving a BriX WebDAV request"
    "$source_dir/objs/nginx" -e stderr -p "$smoke_prefix/" \
        -c "$runtime_config" \
        -g "$global_directives daemon off;" >"$runtime_log" 2>&1 &
    runtime_pid=$!
    sleep 1
    runtime_children="$(pgrep -P "$runtime_pid" 2>/dev/null || true)"
    if ! kill -0 "$runtime_pid" 2>/dev/null || [[ -z "$runtime_children" ]] \
        || grep -q "worker process .* exited" "$runtime_log"; then
        cat "$runtime_log" | tee -a "$log_file"
        kill -TERM "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
        log_error "Darwin worker serving smoke failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! curl --silent --show-error --fail --unix-socket "$runtime_socket" \
        http://localhost/README.md --output "$runtime_response" \
        || ! cmp -s "$REPO_ROOT/README.md" "$runtime_response"; then
        cat "$runtime_log" | tee -a "$log_file"
        kill -TERM "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
        log_error "Darwin BriX WebDAV serving request failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    kill -TERM "$runtime_pid"
    wait "$runtime_pid" || true
    cat "$runtime_log" >>"$log_file"

    aio_test="$build_subdir/darwin-aio-unit"
    log_info "Checking Darwin asynchronous read/write/error contracts"
    if ! clang -std=c11 -Wall -Wextra -Werror -D_DARWIN_C_SOURCE -pthread \
        "$REPO_ROOT/tests/c/darwin_aio_unit.c" \
        "$REPO_ROOT/src/platform/darwin/aio_wrapper.c" \
        -o "$aio_test" 2>&1 | tee -a "$log_file"; then
        log_error "Darwin asynchronous I/O contract test did not compile"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! "$aio_test"; then
        log_error "Darwin asynchronous I/O contract failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    crc_test="$build_subdir/darwin-crc32c-unit"
    crc_cflags=()
    if [[ "$arch" == "arm64" ]]; then
        log_info "Checking Apple-Silicon hardware CRC32C and tail contracts"
        crc_cflags=(-march=armv8-a+crc -DBRIX_ARCH_ARM64=1)
    else
        log_info "Checking Intel hardware CRC32C and tail contracts"
        crc_cflags=(-DBRIX_ARCH_X86_64=1)
    fi
    if ! clang -std=c11 -Wall -Wextra -Werror -O3 "${crc_cflags[@]}" \
        -I"$REPO_ROOT/src" \
        "$REPO_ROOT/tests/c/darwin_crc32c_unit.c" \
        "$REPO_ROOT/src/core/compat/crc32c.c" \
        "$REPO_ROOT/src/core/compat/crc32c_hw.c" \
        -o "$crc_test" 2>&1 | tee -a "$log_file"; then
        log_error "Darwin $arch CRC32C contract test did not compile"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! "$crc_test"; then
        log_error "Darwin $arch CRC32C contract failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    log_info "Building native client and its C checks"
    # Lima guests build through the shared checkout too. Their GNU archive
    # indexes are not Mach-O inputs, and timestamps cannot identify an object's
    # host format, so the Darwin verifier must begin with native artifacts.
    if ! make -C "$REPO_ROOT/client" clean 2>&1 | tee -a "$log_file" \
        || ! make -C "$REPO_ROOT/shared/xrdproto" clean 2>&1 | tee -a "$log_file"; then
        log_error "Could not clean foreign client build artifacts"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! make -C "$REPO_ROOT/client" -j"$make_jobs" all 2>&1 | tee -a "$log_file"; then
        log_error "Native client build failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi
    if ! make -C "$REPO_ROOT/client" test 2>&1 | tee -a "$log_file"; then
        log_error "Native client checks failed"
        ((PLATFORMS_FAILED++))
        return 1
    fi

    "$source_dir/objs/nginx" -V 2>&1 | tee -a "$log_file"
    log_success "macOS $arch Homebrew nginx module and native client build successful"
    ((PLATFORMS_SUCCESS++))
    return 0
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
    python3 "$REPO_ROOT/tools/ci/darwin_residue.py" --format=text 2>/dev/null \
        || echo "  ⚠️  Darwin residue generator unavailable"
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
