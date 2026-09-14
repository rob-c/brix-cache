"""Platform context normalization, xattr workflow and summary rendering."""

import os


def normalize_platform(system):
    # Normalize platform name
    if system == "linux":
        plat_name = "linux"
    elif system == "darwin":
        plat_name = "darwin"
    elif system == "windows" or system.startswith("win"):
        plat_name = "windows"
    else:
        plat_name = "unknown"
    return plat_name


def normalize_architecture(machine):
    # Normalize architecture
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64", "armv8l"):
        arch = "arm64"
    else:
        arch = machine
    return arch


def check_and_remove_user_xattrs(test_file, attrs):
    assert_user_xattrs(test_file, attrs)
    for attr in attrs:
        if attr.startswith("user."):
            os.removexattr(str(test_file), attr)
    assert_user_xattrs_removed(test_file, attrs)


def assert_user_xattrs(test_file, attrs):
    for attr in attrs:
        if attr.startswith("user."):
            value = os.getxattr(str(test_file), attr)
            assert len(value) > 0


def assert_user_xattrs_removed(test_file, attrs):
    final_attrs = os.listxattr(str(test_file))
    for attr in attrs:
        if attr.startswith("user."):
            assert attr not in final_attrs


def print_coverage_summary(summary, platform_context, total_functions):
    # Print summary
    print("\n" + "="*70)
    print("PAL FUNCTION COVERAGE SUMMARY")
    print("="*70)
    print(f"Platform: {platform_context['platform']}")
    print(f"Architecture: {platform_context['architecture']}")
    print(f"Total Functions: {total_functions}")
    print(f"Timestamp: {summary['timestamp']}")
    print("\nCategories:")
    for category, info in summary["categories"].items():
        print(f"  {category}: {info['count']} functions")
    print("="*70)
