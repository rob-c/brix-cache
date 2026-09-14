"""Apple Silicon hardware probes and benchmark predicates."""

import ctypes
import subprocess
import pytest


def report_chip_generation(chip_name):
    # Detect chip generation
    if 'M3' in chip_name:
        print("  -> M3 generation")
        pytest.mark.m3
    elif 'M2' in chip_name:
        print("  -> M2 generation")
        pytest.mark.m2
    elif 'M1' in chip_name:
        print("  -> M1 generation")
        pytest.mark.m1
    else:
        print("  -> Apple Silicon (generation unknown)")


def report_processor_fallback():
    # Fallback: check processor name
    try:
        result = subprocess.run(
            ['sysctl', '-n', 'machdep.cpu.name'],
            capture_output=True, text=True, timeout=5
        )

        if result.returncode == 0:
            print(f"\nProcessor: {result.stdout.strip()}")

    except:
        print("\nCould not detect chip details")





def report_core_configuration(perf_cores, eff_cores):
    # Typical configurations:
    # M1: 4 perf + 4 eff = 8 cores
    # M1 Pro: 6/2 or 8/2 = 8/10 cores
    # M1 Max: 8/2 = 10 cores
    # M2: 4/4 = 8 cores
    # M2 Pro: 6/4 or 8/4 = 10/12 cores

    if perf_cores == 4 and eff_cores == 4:
        print("  -> Standard 4+4 configuration (M1/M2 base)")
    elif perf_cores == 8 and eff_cores == 2:
        print("  -> 8+2 configuration (M1 Pro/Max)")


def report_clone_failure():
    errno = ctypes.get_errno()
    print(f"\n⚠ clonefile failed with errno {errno}")

    if errno == 1:  # EPERM
        print("  -> Not on APFS volume")
    elif errno == 45:  # ENOTSUP
        print("  -> clonefile not supported")


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def report_prime_performance(elapsed):
    # Apple Silicon Firestorm cores have excellent single-thread perf
    if elapsed < 1.0:
        print("  ✓ Excellent single-thread performance")
    elif elapsed < 2.0:
        print("  ⚠ Good single-thread performance")
    else:
        print("  ✗ Moderate single-thread performance")
