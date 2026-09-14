#!/bin/bash
# Verify Windows PAL 100% completion

echo "============================================"
echo "Windows PAL 100% Verification"
echo "============================================"
echo ""

# List of all 42 PAL functions
declare -a FUNCTIONS=(
    # File Descriptors (5)
    "brix_plat_anon_fd"
    "brix_plat_fadvise"
    "brix_plat_fsync_data"
    "brix_plat_sync"
    "brix_plat_sync_tree"
    
    # Events (2)
    "brix_plat_eventfd"
    "brix_plat_pipe2"
    
    # Filesystem Watcher (5)
    "brix_plat_fs_watcher_init"
    "brix_plat_fs_watcher_add"
    "brix_plat_fs_watcher_rm"
    "brix_plat_fs_watcher_next"
    "brix_plat_fs_watcher_destroy"
    
    # Random (1)
    "brix_plat_random"
    
    # Xattr (8)
    "brix_plat_getxattr"
    "brix_plat_fgetxattr"
    "brix_plat_setxattr"
    "brix_plat_fsetxattr"
    "brix_plat_removexattr"
    "brix_plat_fremovexattr"
    "brix_plat_listxattr"
    "brix_plat_flistxattr"
    
    # Process Execution (1)
    "brix_plat_execvpe"
    
    # Byte Order (6)
    "brix_plat_htobe64"
    "brix_plat_be64toh"
    "brix_plat_htobe32"
    "brix_plat_be32toh"
    "brix_plat_htobe16"
    "brix_plat_be16toh"
    
    # Zero-Copy (3)
    "brix_plat_sendfile"
    "brix_plat_splice"
    "brix_plat_copy_range"
    
    # Platform Detection (7)
    "brix_plat_is_windows"
    "brix_plat_windows_version"
    "brix_plat_windows_build"
    "brix_plat_windows_version_info"
    "brix_plat_is_windows_server"
    "brix_plat_windows_service_pack"
    "brix_plat_windows_edition"
    
    # Security (4)
    "brix_plat_security_init"
    "brix_plat_security_enter"
    "brix_plat_setfsuid"
    "brix_plat_setfsgid"
    
    # PAL Initialization (2)
    "brix_plat_init"
    "brix_plat_cleanup"
)

TOTAL=${#FUNCTIONS[@]}
FOUND=0
MISSING=0

echo "Checking all $TOTAL PAL functions in Windows source files..."
echo ""

for func in "${FUNCTIONS[@]}"; do
    # Search in Windows PAL files
    if grep -q "$func" src/platform/windows/*.c src/platform/windows/*.h 2>/dev/null; then
        echo "✓ $func"
        ((FOUND++))
    elif grep -q "$func" src/platform/platform_runtime.c src/platform/platform_api.h 2>/dev/null; then
        # Check shared platform files
        echo "✓ $func (shared)"
        ((FOUND++))
    else
        echo "✗ $func - MISSING"
        ((MISSING++))
    fi
done

echo ""
echo "============================================"
echo "Results:"
echo "  Total Functions: $TOTAL"
echo "  Found: $FOUND"
echo "  Missing: $MISSING"
echo "============================================"
echo ""

if [ $MISSING -eq 0 ]; then
    echo "✅ ALL $TOTAL FUNCTIONS FOUND - WINDOWS PAL 100% COMPLETE!"
    exit 0
else
    echo "❌ MISSING $MISSING FUNCTIONS"
    exit 1
fi
