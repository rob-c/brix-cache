"""ARM Linux hardware-report probes shared by the architecture tests."""

import subprocess
import pytest


def report_cpu_features(cpuinfo):
    features_line = next((line for line in cpuinfo.split('\n')
                          if line.startswith('Features')), None)
    if not features_line:
        return
    features = features_line.split(':')[1].strip().split()
    print(f"\nCPU Features ({len(features)} total):")
    important_features = ['crc32', 'asimd', 'atomics', 'fp', 'pmull', 'sha3', 'sve', 'sve2']
    print("\nKey Features:")
    for feat in important_features:
        status = "✓" if feat in features else "✗"
        print(f"  {status} {feat}")
    mark_cpu_features(features)


def report_cpu_identity(cpuinfo):
    # Get CPU implementer and part number
    for line in cpuinfo.split('\n'):
        if line.startswith('CPU implementer'):
            implementer = int(line.split(':')[1].strip(), 16)
            print(f"\nCPU Implementer: 0x{implementer:02x}")

            # Decode implementer
            implementers = {
                0x41: "ARM Ltd",
                0x42: "Broadcom",
                0x43: "Cavium",
                0x44: "DEC",
                0x46: "Fujitsu",
                0x48: "HiSilicon",
                0x49: "Infineon",
                0x4d: "Motorola/Freescale",
                0x4e: "NVIDIA",
                0x50: "APM",
                0x51: "Qualcomm",
                0x53: "Samsung",
                0x56: "Marvell",
            }
            impl_name = implementers.get(implementer, "Unknown")
            print(f"  -> {impl_name}")

        if line.startswith('CPU part'):
            part = int(line.split(':')[1].strip(), 16)
            print(f"CPU Part: 0x{part:03x}")


def report_graviton():
    # Check for AWS Graviton
    try:
        with open('/sys/class/dmi/id/product_version', 'r') as f:
            product_version = f.read().strip()

        if 'Amazon' in product_version or 'Graviton' in product_version:
            print("\n✓ Running on AWS Graviton")
            pytest.mark.graviton

            # Try to determine Graviton generation
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()

            report_graviton_generation(cpuinfo)

    except FileNotFoundError:
        pass


def report_ampere():
    # Check for Ampere Altra
    try:
        with open('/sys/class/dmi/id/product_name', 'r') as f:
            product_name = f.read().strip()

        if 'Ampere' in product_name or 'Altra' in product_name:
            print("\n✓ Running on Ampere Altra")
            pytest.mark.ampere

    except FileNotFoundError:
        pass


def report_other_clouds():
    # Check for other cloud providers
    try:
        result = subprocess.run(
            ['dmidecode', '-t', 'system'],
            capture_output=True, text=True, timeout=5
        )

        if 'Google' in result.stdout:
            print("\n✓ Running on Google Cloud (ARM64)")
        elif 'Microsoft' in result.stdout:
            print("\n✓ Running on Azure (ARM64)")

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def report_lscpu_cache():
    # Try to get from lscpu
    try:
        result = subprocess.run(
            ['lscpu'],
            capture_output=True, text=True, timeout=5
        )

        for line in result.stdout.split('\n'):
            report_cache_line(line)

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def report_sysfs_cache():
    # Try sysfs
    try:
        with open('/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size', 'r') as f:
            cache_line_size = int(f.read().strip())
            print(f"Cache coherency line size: {cache_line_size} bytes")

            # ARM64 typically uses 64-byte cache lines
            if cache_line_size == 64:
                print("✓ Standard 64-byte cache line (expected)")
            else:
                print(f"⚠ Non-standard cache line size: {cache_line_size}")

    except FileNotFoundError:
        print("Could not determine cache line size from sysfs")


def mark_cpu_features(features):
    """Retain the architecture tests' feature-marker lookups."""
    if 'crc32' in features:
        pytest.mark.crc32
    if 'asimd' in features:
        pytest.mark.neon
    if 'sve' in features or 'sve2' in features:
        pytest.mark.sve


def report_graviton_generation(cpuinfo):
    if 'neoverse-n1' in cpuinfo.lower():
        print("  -> Graviton2 (Neoverse N1)")
    elif 'neoverse-v1' in cpuinfo.lower():
        print("  -> Graviton3 (Neoverse V1)")
    else:
        print("  -> Graviton (generation unknown)")


def report_cache_line(line):
    if 'Caches' in line and 'L1d' in line:
        # Parse: "L1d cache: 32K"
        parts = line.split(':')
        if len(parts) == 2:
            size_str = parts[1].strip()
            if 'K' in size_str:
                size = int(size_str.replace('K', '').strip())
                print(f"\nL1d cache size: {size}KB")

    if 'Coherence' in line:
        print(f"  {line.strip()}")
