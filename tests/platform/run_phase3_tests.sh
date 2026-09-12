#!/usr/bin/env python3
"""
run_phase3_tests.sh - Phase 3 PAL Integration Test Runner

Runs comprehensive PAL integration tests across all platforms with:
- Full test suite execution
- Platform-specific test filtering
- Performance regression testing
- Coverage reporting
- JUnit XML output for CI/CD
- HTML reports

Usage:
    ./run_phase3_tests.sh                    # Run all tests
    ./run_phase3_tests.sh --platform linux   # Linux only
    ./run_phase3_tests.sh --platform windows # Windows only
    ./run_phase3_tests.sh --performance      # Performance tests only
    ./run_phase3_tests.sh --coverage         # With coverage report
    ./run_phase3_tests.sh --html             # Generate HTML report
    ./run_phase3_tests.sh --help             # Show help

Platform: All (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64)
Minimum: Python 3.8+, pytest 7.0+
Author: BriX-Cache Development Team
Phase: 3 - Final Integration & Validation
"""

set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_FILE="${SCRIPT_DIR}/test_phase3_integration.py"
TEST_DIR="${SCRIPT_DIR}"
OUTPUT_DIR="${SCRIPT_DIR}/test_results"
COVERAGE_DIR="${SCRIPT_DIR}/coverage"
HTML_REPORT_DIR="${SCRIPT_DIR}/html_report"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
RUN_ALL=true
RUN_PERFORMANCE=false
RUN_COVERAGE=false
RUN_HTML=false
PLATFORM_FILTER=""
VERBOSITY="-v"
PYTEST_ARGS=""

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

show_help() {
    cat << EOF
Phase 3 PAL Integration Test Runner

Usage: $0 [OPTIONS]

Options:
    -p, --platform PLATFORM    Run tests for specific platform
                               (linux, darwin, windows, arm64, x86_64)
    --performance              Run performance regression tests only
    --coverage                 Generate coverage report
    --html                     Generate HTML report
    -q, --quiet                Quiet mode (minimal output)
    -v, --verbose              Verbose mode (detailed output)
    --junit                    Generate JUnit XML report
    --help                     Show this help message

Examples:
    $0                                    # Run all tests
    $0 --platform linux                   # Linux tests only
    $0 --platform windows --performance   # Windows performance tests
    $0 --coverage --html                  # Full test with reports

Output:
    Test results are saved to: ${OUTPUT_DIR}
    Coverage reports: ${COVERAGE_DIR}
    HTML reports: ${HTML_REPORT_DIR}

EOF
}

detect_platform() {
    local system=$(uname -s | tr '[:upper:]' '[:lower:]')
    local machine=$(uname -m | tr '[:upper:]' '[:lower:]')
    
    case "$system" in
        linux)
            echo "linux"
            ;;
        darwin)
            echo "darwin"
            ;;
        mingw*|msys*|cygwin*|windows_nt)
            echo "windows"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

detect_arch() {
    local machine=$(uname -m | tr '[:upper:]' '[:lower:]')
    
    case "$machine" in
        x86_64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64|armv8l)
            echo "arm64"
            ;;
        *)
            echo "$machine"
            ;;
    esac
}

check_dependencies() {
    print_header "Checking Dependencies"
    
    local missing=()
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    # Check pytest
    if ! python3 -m pytest --version &> /dev/null; then
        missing+=("pytest")
    fi
    
    # Check psutil (optional, for memory tests)
    if ! python3 -c "import psutil" 2>/dev/null; then
        print_info "psutil not installed (some tests will be skipped)"
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing[*]}"
        echo "Install with:"
        echo "  pip3 install pytest psutil"
        exit 1
    fi
    
    print_success "All required dependencies found"
}

setup_output_dirs() {
    print_header "Setting Up Output Directories"
    
    mkdir -p "${OUTPUT_DIR}"
    print_success "Output directory: ${OUTPUT_DIR}"
    
    if [ "$RUN_COVERAGE" = true ]; then
        mkdir -p "${COVERAGE_DIR}"
        print_success "Coverage directory: ${COVERAGE_DIR}"
    fi
    
    if [ "$RUN_HTML" = true ]; then
        mkdir -p "${HTML_REPORT_DIR}"
        print_success "HTML report directory: ${HTML_REPORT_DIR}"
    fi
}

# =============================================================================
# Test Execution
# =============================================================================

run_tests() {
    print_header "Running Phase 3 Integration Tests"
    
    local platform=$(detect_platform)
    local arch=$(detect_arch)
    
    print_info "Platform: ${platform}"
    print_info "Architecture: ${arch}"
    print_info "Python: $(python3 --version)"
    print_info "Pytest: $(python3 -m pytest --version 2>&1 | head -1)"
    
    # Build pytest command
    local pytest_cmd="python3 -m pytest"
    pytest_cmd+=" ${TEST_FILE}"
    pytest_cmd+=" ${VERBOSITY}"
    
    # Add platform filter
    if [ -n "${PLATFORM_FILTER}" ]; then
        case "${PLATFORM_FILTER}" in
            linux)
                pytest_cmd+=" -m linux"
                print_info "Filter: Linux tests only"
                ;;
            darwin|macos)
                pytest_cmd+=" -m darwin"
                print_info "Filter: macOS tests only"
                ;;
            windows)
                pytest_cmd+=" -m windows"
                print_info "Filter: Windows tests only"
                ;;
            arm64)
                pytest_cmd+=" -m arm64"
                print_info "Filter: ARM64 tests only"
                ;;
            x86_64)
                pytest_cmd+=" -m x86_64"
                print_info "Filter: x86_64 tests only"
                ;;
        esac
    fi
    
    # Add performance test filter
    if [ "$RUN_PERFORMANCE" = true ]; then
        pytest_cmd+=" -m performance"
        print_info "Filter: Performance tests only"
    fi
    
    # Add coverage
    if [ "$RUN_COVERAGE" = true ]; then
        pytest_cmd+=" --cov=src/platform"
        pytest_cmd+=" --cov-report=html:${COVERAGE_DIR}"
        pytest_cmd+=" --cov-report=term-missing"
        print_info "Coverage: Enabled"
    fi
    
    # Add HTML report
    if [ "$RUN_HTML" = true ]; then
        pytest_cmd+=" --html=${HTML_REPORT_DIR}/report.html"
        pytest_cmd+=" --self-contained-html"
        print_info "HTML Report: Enabled"
    fi
    
    # Add JUnit XML
    if [[ "${PYTEST_ARGS}" == *"--junit"* ]] || [ "$CI" = "true" ]; then
        local timestamp=$(date +%Y%m%d_%H%M%S)
        pytest_cmd+=" --junitxml=${OUTPUT_DIR}/test_results_${timestamp}.xml"
        print_info "JUnit XML: Enabled"
    fi
    
    # Add custom pytest args
    if [ -n "${PYTEST_ARGS}" ]; then
        pytest_cmd+=" ${PYTEST_ARGS}"
    fi
    
    # Run tests
    print_header "Executing Tests"
    echo "Command: ${pytest_cmd}"
    echo ""
    
    local start_time=$(date +%s)
    
    if eval "${pytest_cmd}"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        print_header "Test Execution Complete"
        print_success "All tests passed!"
        print_info "Duration: ${duration} seconds"
        
        # Show results location
        echo ""
        print_info "Results saved to: ${OUTPUT_DIR}"
        if [ "$RUN_COVERAGE" = true ]; then
            print_info "Coverage report: ${COVERAGE_DIR}/index.html"
        fi
        if [ "$RUN_HTML" = true ]; then
            print_info "HTML report: ${HTML_REPORT_DIR}/report.html"
        fi
        
        return 0
    else
        print_header "Test Execution Failed"
        print_error "Some tests failed"
        return 1
    fi
}

run_performance_tests() {
    print_header "Running Performance Regression Tests"
    
    RUN_PERFORMANCE=true
    PYTEST_ARGS+=" -v --tb=short"
    
    run_tests
}

run_with_coverage() {
    print_header "Running Tests with Coverage"
    
    RUN_COVERAGE=true
    PYTEST_ARGS+=" -v --tb=short"
    
    run_tests
    
    # Show coverage summary
    if [ -f "${COVERAGE_DIR}/index.html" ]; then
        echo ""
        print_info "Open coverage report: ${COVERAGE_DIR}/index.html"
    fi
}

run_with_html() {
    print_header "Running Tests with HTML Report"
    
    RUN_HTML=true
    PYTEST_ARGS+=" -v --tb=short"
    
    run_tests
    
    # Show HTML report location
    if [ -f "${HTML_REPORT_DIR}/report.html" ]; then
        echo ""
        print_info "Open HTML report: ${HTML_REPORT_DIR}/report.html"
    fi
}

# =============================================================================
# Main Entry Point
# =============================================================================

main() {
    print_header "Phase 3 PAL Integration Test Runner"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--platform)
                PLATFORM_FILTER="$2"
                shift 2
                ;;
            --performance)
                RUN_PERFORMANCE=true
                shift
                ;;
            --coverage)
                RUN_COVERAGE=true
                shift
                ;;
            --html)
                RUN_HTML=true
                shift
                ;;
            -q|--quiet)
                VERBOSITY="-q"
                shift
                ;;
            -v|--verbose)
                VERBOSITY="-vv"
                shift
                ;;
            --junit)
                PYTEST_ARGS+=" --junitxml"
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check dependencies
    check_dependencies
    
    # Setup output directories
    setup_output_dirs
    
    # Run tests
    if [ "$RUN_PERFORMANCE" = true ]; then
        run_performance_tests
    elif [ "$RUN_COVERAGE" = true ]; then
        run_with_coverage
    elif [ "$RUN_HTML" = true ]; then
        run_with_html
    else
        run_tests
    fi
}

# Run main function
main "$@"
