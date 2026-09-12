#!/usr/bin/env python3
"""
Platform Feature Detection Script for BriX-Cache CI

Detects platform, architecture, and CPU features at runtime.
Outputs JSON for CI/CD pipelines to configure build optimizations.

Usage:
    python3 detect_platform_features.py [--verbose] [--ci-format]

Output:
    JSON object with platform detection results
"""

import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def run_command(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.SubprocessError, OSError):
        return None


def detect_platform() -> Dict[str, Any]:
    """Detect platform information."""
    system = platform.system()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    
    # Normalize platform name
    if system == "Linux":
        plat_name = "linux"
    elif system == "Darwin":
        plat_name = "darwin"
    elif system == "Windows":
        plat_name = "windows"
    else:
        plat_name = system.lower()
    
    # Detect Linux distribution
    distro_info = {}
    if plat_name == "linux":
        # Try /etc/os-release
        os_release_path = Path("/etc/os-release")
        if os_release_path.exists():
            try:
                with open(os_release_path, 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            distro_info[key.lower()] = value.strip('"\'')
            except (IOError, ValueError):
                pass
        
        # Fallback: lsb_release
        if not distro_info:
            lsb = run_command(["lsb_release", "-a"])
            if lsb:
                distro_info['raw'] = lsb
    
    # Detect macOS version
    macos_info = {}
    if plat_name == "darwin":
        sw_vers = run_command(["sw_vers"])
        if sw_vers:
            macos_info['raw'] = sw_vers
        
        product_version = run_command(["sw_vers", "-productVersion"])
        if product_version:
            macos_info['version'] = product_version
        
        build_version = run_command(["sw_vers", "-buildVersion"])
        if build_version:
            macos_info['build'] = build_version
    
    return {
        "name": plat_name,
        "system": system,
        "release": release,
        "version": version,
        "machine": machine,
        "linux_distro": distro_info if distro_info else None,
        "macos": macos_info if macos_info else None,
    }


def detect_architecture() -> Dict[str, Any]:
    """Detect CPU architecture and variants."""
    machine = platform.machine().lower()
    
    # Normalize architecture names
    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
        "armv7hl": "armv7",
        "i386": "x86",
        "i686": "x86",
    }
    
    arch = arch_map.get(machine, machine)
    
    # Detect architecture family
    if arch.startswith("x86_64") or arch == "x86_64":
        family = "x86_64"
    elif arch.startswith("arm64") or arch.startswith("aarch64"):
        family = "arm64"
    elif arch.startswith("arm"):
        family = "arm"
    elif arch.startswith("x86"):
        family = "x86"
    elif arch.startswith("riscv"):
        family = "riscv"
    else:
        family = "unknown"
    
    # Detect architecture-specific features
    features = {}
    
    if family == "x86_64":
        features = detect_x86_features()
    elif family == "arm64":
        features = detect_arm64_features()
    elif family == "arm":
        features = detect_arm_features()
    
    return {
        "raw": machine,
        "normalized": arch,
        "family": family,
        "features": features,
    }


def detect_x86_features() -> Dict[str, Any]:
    """Detect x86_64 CPU features."""
    features = {
        "has_sse": False,
        "has_sse2": False,
        "has_sse3": False,
        "has_ssse3": False,
        "has_sse4_1": False,
        "has_sse4_2": False,
        "has_avx": False,
        "has_avx2": False,
        "has_avx512": False,
        "has_aes": False,
        "has_crc32": False,
        "has_vmx": False,  # Intel VT-x
        "has_svm": False,  # AMD-V
    }
    
    # Linux: read /proc/cpuinfo
    if platform.system() == "Linux":
        cpuinfo_path = Path("/proc/cpuinfo")
        if cpuinfo_path.exists():
            try:
                with open(cpuinfo_path, 'r') as f:
                    content = f.read()
                    # Find flags line
                    flags_match = re.search(r'flags\s*:\s*(.+)', content)
                    if flags_match:
                        flags = flags_match.group(1).split()
                        features["has_sse"] = "sse" in flags
                        features["has_sse2"] = "sse2" in flags
                        features["has_sse3"] = "sse3" in flags
                        features["has_ssse3"] = "ssse3" in flags
                        features["has_sse4_1"] = "sse4_1" in flags
                        features["has_sse4_2"] = "sse4_2" in flags
                        features["has_avx"] = "avx" in flags
                        features["has_avx2"] = "avx2" in flags
                        features["has_aes"] = "aes" in flags
                        features["has_crc32"] = "crc32" in flags
                        features["has_vmx"] = "vmx" in flags
                        features["has_svm"] = "svm" in flags
                        
                        # Check for AVX-512 variants
                        avx512_flags = [f for f in flags if f.startswith("avx512")]
                        features["has_avx512"] = len(avx512_flags) > 0
            except IOError:
                pass
    
    # macOS: use sysctl
    elif platform.system() == "Darwin":
        # macOS Intel Macs have SSE4.2, AVX2, AES by default on modern CPUs
        features["has_sse"] = True
        features["has_sse2"] = True
        features["has_sse3"] = True
        features["has_ssse3"] = True
        features["has_sse4_1"] = True
        features["has_sse4_2"] = True
        features["has_aes"] = True
        
        # Check for AVX2
        avx2 = run_command(["sysctl", "-n", "hw.optional.avx2_0"])
        if avx2 == "1":
            features["has_avx2"] = True
        
        # Check for AVX
        avx = run_command(["sysctl", "-n", "hw.optional.avx1_0"])
        if avx == "1":
            features["has_avx"] = True
    
    # Windows: use wmic or PowerShell
    elif platform.system() == "Windows":
        # Modern x86_64 Windows requires SSE2
        features["has_sse"] = True
        features["has_sse2"] = True
        
        # Try PowerShell to get CPU features
        ps_cmd = "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Caption"
        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                cpu_name = result.stdout.strip().lower()
                # Infer features from CPU name
                if "ryzen" in cpu_name or "epyc" in cpu_name:
                    features["has_avx2"] = True
                    features["has_aes"] = True
                    features["has_crc32"] = True
                elif "intel" in cpu_name:
                    if "i7" in cpu_name or "i9" in cpu_name or "xeon" in cpu_name:
                        features["has_avx2"] = True
                        features["has_aes"] = True
        except (subprocess.SubprocessError, OSError):
            pass
    
    return features


def detect_arm64_features() -> Dict[str, Any]:
    """Detect ARM64 CPU features."""
    features = {
        "has_crc32": False,
        "has_crypto": False,
        "has_aes": False,
        "has_sha1": False,
        "has_sha2": False,
        "has_neon": True,  # All ARM64 have NEON
        "has_fp": True,    # All ARM64 have FP
        "has_lse": False,  # Large System Extensions
        "has_sve": False,  # Scalable Vector Extension
        "has_sve2": False,
        "is_apple_silicon": False,
        "apple_chip": None,
    }
    
    # Linux: read /proc/cpuinfo
    if platform.system() == "Linux":
        cpuinfo_path = Path("/proc/cpuinfo")
        if cpuinfo_path.exists():
            try:
                with open(cpuinfo_path, 'r') as f:
                    content = f.read()
                    
                    # Check for features in CPU info
                    features_match = re.search(r'Features\s*:\s*(.+)', content)
                    if features_match:
                        feat_list = features_match.group(1).split()
                        features["has_crc32"] = "crc32" in feat_list
                        features["has_aes"] = "aes" in feat_list
                        features["has_sha1"] = "sha1" in feat_list
                        features["has_sha2"] = "sha2" in feat_list
                        features["has_crypto"] = "pmull" in feat_list or "asimd" in feat_list
                        features["has_lse"] = "atomics" in feat_list
                        features["has_sve"] = "sve" in feat_list
                        
                    # Check CPU implementer/part for Apple Silicon
                    implementer = re.search(r'CPU implementer\s*:\s*(\S+)', content)
                    if implementer:
                        impl = implementer.group(1).lower()
                        if impl in ["0x41", "0x61"]:  # Apple
                            features["is_apple_silicon"] = True
                            
            except IOError:
                pass
        
        # Try to detect SVE via auxiliary vector
        try:
            result = subprocess.run(
                ["ld.so", "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "hwcap" in result.stdout.lower():
                pass  # Could parse HWCAP values here
        except (subprocess.SubprocessError, OSError):
            pass
    
    # macOS: Apple Silicon detection
    elif platform.system() == "Darwin":
        # Check if ARM64 (Apple Silicon)
        if platform.machine() == "arm64":
            features["is_apple_silicon"] = True
            
            # Try to get chip name
            chip = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
            if chip:
                features["apple_chip"] = chip
            
            # Apple Silicon has all crypto extensions
            features["has_crc32"] = True
            features["has_crypto"] = True
            features["has_aes"] = True
            features["has_sha1"] = True
            features["has_sha2"] = True
            features["has_lse"] = True
            
            # Check for AMX (Apple Matrix Engine) - M3+
            # This is not exposed via sysctl, would need runtime detection
    
    return features


def detect_arm_features() -> Dict[str, Any]:
    """Detect ARMv7 CPU features."""
    features = {
        "has_neon": False,
        "has_vfpv3": False,
        "has_vfpv4": False,
        "has_thumb": False,
    }
    
    if platform.system() == "Linux":
        cpuinfo_path = Path("/proc/cpuinfo")
        if cpuinfo_path.exists():
            try:
                with open(cpuinfo_path, 'r') as f:
                    content = f.read()
                    features_match = re.search(r'Features\s*:\s*(.+)', content)
                    if features_match:
                        feat_list = features_match.group(1).split()
                        features["has_neon"] = "neon" in feat_list
                        features["has_vfpv3"] = "vfpv3" in feat_list
                        features["has_vfpv4"] = "vfpv4" in feat_list
                        features["has_thumb"] = "thumb" in feat_list
            except IOError:
                pass
    
    return features


def detect_compiler_support() -> Dict[str, Any]:
    """Detect compiler capabilities."""
    cc = os.environ.get("CC", "cc")
    
    # Get compiler version
    version_output = run_command([cc, "--version"])
    compiler_info = {
        "name": None,
        "version": None,
        "supports_lto": False,
        "supports_lto_thin": False,
        "supports_pgo": False,
    }
    
    if version_output:
        # Detect compiler type
        if "gcc" in version_output.lower():
            compiler_info["name"] = "gcc"
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_output)
            if version_match:
                compiler_info["version"] = version_match.group(1)
                
                # GCC supports LTO since 4.5, thin LTO not supported
                compiler_info["supports_lto"] = True
                compiler_info["supports_pgo"] = True
                
        elif "clang" in version_output.lower():
            compiler_info["name"] = "clang"
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_output)
            if version_match:
                compiler_info["version"] = version_match.group(1)
                
                # Clang supports both LTO variants
                compiler_info["supports_lto"] = True
                compiler_info["supports_lto_thin"] = True
                compiler_info["supports_pgo"] = True
        
        elif "apple" in version_output.lower():
            compiler_info["name"] = "apple-clang"
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_output)
            if version_match:
                compiler_info["version"] = version_match.group(1)
                compiler_info["supports_lto"] = True
                compiler_info["supports_lto_thin"] = True
                compiler_info["supports_pgo"] = True
    
    # Test actual compiler support
    test_code = "int main() { return 0; }"
    
    # Test LTO
    result = subprocess.run(
        [cc, "-x", "c", "-", "-o", "/dev/null", "-flto"],
        input=test_code,
        capture_output=True,
        text=True
    )
    compiler_info["supports_lto"] = (result.returncode == 0)
    
    # Test thin LTO (Clang only)
    if compiler_info["name"] in ["clang", "apple-clang"]:
        result = subprocess.run(
            [cc, "-x", "c", "-", "-o", "/dev/null", "-flto=thin"],
            input=test_code,
            capture_output=True,
            text=True
        )
        compiler_info["supports_lto_thin"] = (result.returncode == 0)
    
    return compiler_info


def detect_optimization_flags() -> Dict[str, List[str]]:
    """Detect recommended optimization flags for current platform."""
    arch = detect_architecture()
    platform_info = detect_platform()
    flags = {
        "march": [],
        "mtune": [],
        "cpu_features": [],
        "frameworks": [],
        "ldflags": [],
    }
    
    family = arch["family"]
    plat = platform_info["name"]
    
    if family == "x86_64":
        # Detect x86_64 microarchitecture level
        features = arch["features"]
        
        if features.get("has_avx512"):
            flags["march"].append("-march=x86-64-v4")
            flags["mtune"].append("-mtune=znver4")  # Default to modern AMD
        elif features.get("has_avx2"):
            flags["march"].append("-march=x86-64-v3")
            flags["mtune"].append("-mtune=haswell")
        elif features.get("has_sse4_2"):
            flags["march"].append("-march=x86-64-v2")
            flags["mtune"].append("-mtune=core2")
        else:
            flags["march"].append("-march=x86-64")
            flags["mtune"].append("-mtune=generic")
        
        # CPU-specific tuning
        if plat == "linux":
            # Try to detect specific CPU model
            cpu_model = run_command(["lscpu"])
            if cpu_model:
                if "AMD" in cpu_model and "Ryzen" in cpu_model:
                    flags["mtune"] = ["-mtune=znver4"]
                elif "Intel" in cpu_model:
                    if "12th" in cpu_model or "13th" in cpu_model or "14th" in cpu_model:
                        flags["mtune"] = ["-mtune=alderlake"]
                    elif "11th" in cpu_model:
                        flags["mtune"] = ["-mtune=tigerlake"]
    
    elif family == "arm64":
        if plat == "darwin":
            # Apple Silicon
            if arch["features"].get("is_apple_silicon"):
                chip = arch["features"].get("apple_chip", "")
                if "M3" in chip:
                    flags["march"].append("-march=armv8.5-a")
                    flags["mtune"].append("-mtune=apple-m3")
                elif "M2" in chip:
                    flags["march"].append("-march=armv8.4-a")
                    flags["mtune"].append("-mtune=apple-m2")
                elif "M1" in chip:
                    flags["march"].append("-march=armv8.3-a")
                    flags["mtune"].append("-mtune=apple-m1")
                else:
                    flags["march"].append("-march=armv8.5-a")
                    flags["mtune"].append("-mtune=apple-m1")
                
                # Link Accelerate framework for optimized math
                flags["frameworks"].append("-framework Accelerate")
        else:
            # Linux ARM64
            features = arch["features"]
            if features.get("has_crc32"):
                flags["march"].append("-march=armv8-a+crc")
            else:
                flags["march"].append("-march=armv8-a")
            
            if features.get("has_crypto"):
                flags["cpu_features"].append("+crypto")
            if features.get("has_sve"):
                flags["cpu_features"].append("+sve")
    
    elif family == "arm":
        # ARMv7
        flags["march"].append("-march=armv7-a")
        flags["mtune"].append("-mtune=cortex-a9")
        
        if arch["features"].get("has_neon"):
            flags["cpu_features"].append("+neon")
        if arch["features"].get("has_vfpv4"):
            flags["cpu_features"].append("+vfpv4")
    
    # Platform-specific linker flags
    if plat == "darwin":
        flags["ldflags"].extend([
            "-Wl,-dead_strip",
            "-Wl,-search_paths_first",
        ])
    elif plat == "linux":
        flags["ldflags"].extend([
            "-Wl,-z,relro",
            "-Wl,-z,now",
        ])
    
    return flags


def detect_runtime_info() -> Dict[str, Any]:
    """Detect runtime environment information."""
    info = {
        "python_version": platform.python_version(),
        "is_ci": os.environ.get("CI", "").lower() in ["true", "1", "yes"],
        "ci_provider": None,
        "cpu_count": os.cpu_count() or 1,
        "total_memory_mb": None,
        "available_memory_mb": None,
    }
    
    # Detect CI provider
    if os.environ.get("GITHUB_ACTIONS"):
        info["ci_provider"] = "github-actions"
    elif os.environ.get("GITLAB_CI"):
        info["ci_provider"] = "gitlab-ci"
    elif os.environ.get("TRAVIS"):
        info["ci_provider"] = "travis"
    elif os.environ.get("CIRCLECI"):
        info["ci_provider"] = "circleci"
    elif os.environ.get("JENKINS_URL"):
        info["ci_provider"] = "jenkins"
    
    # Detect memory
    if platform.system() == "Linux":
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        info["total_memory_mb"] = int(line.split()[1]) // 1024
                    elif line.startswith("MemAvailable:"):
                        info["available_memory_mb"] = int(line.split()[1]) // 1024
                        break
        except (IOError, ValueError):
            pass
    
    elif platform.system() == "Darwin":
        total_mem = run_command(["sysctl", "-n", "hw.memsize"])
        if total_mem:
            try:
                info["total_memory_mb"] = int(total_mem) // (1024 * 1024)
            except ValueError:
                pass
    
    return info


def generate_build_recommendations(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Generate build configuration recommendations based on detection."""
    recommendations = {
        "platform_flags": {},
        "optimization_level": "-O3",
        "enable_lto": False,
        "enable_pgo": False,
        "features_to_enable": [],
        "features_to_disable": [],
        "warnings": [],
    }
    
    plat = detection["platform"]["name"]
    arch = detection["architecture"]["family"]
    compiler = detection["compiler"]
    opt_flags = detection["optimization_flags"]
    
    # Platform-specific recommendations
    if plat == "linux":
        recommendations["platform_flags"]["BRIX_PLATFORM_LINUX"] = "1"
        recommendations["platform_flags"]["BRIX_PLATFORM_DARWIN"] = "0"
    elif plat == "darwin":
        recommendations["platform_flags"]["BRIX_PLATFORM_LINUX"] = "0"
        recommendations["platform_flags"]["BRIX_PLATFORM_DARWIN"] = "1"
        recommendations["platform_flags"]["_DARWIN_C_SOURCE"] = "1"
    elif plat == "windows":
        recommendations["platform_flags"]["BRIX_PLATFORM_WINDOWS"] = "1"
        recommendations["warnings"].append("Windows support is beta - use WSL2 for production")
    
    # Architecture-specific recommendations
    if arch == "x86_64":
        recommendations["features_to_enable"].extend([
            "sse4_2", "avx2", "aes"
        ])
    elif arch == "arm64":
        recommendations["features_to_enable"].extend([
            "crc32", "crypto", "neon"
        ])
        if plat == "darwin":
            recommendations["features_to_enable"].append("apple_silicon_opt")
    
    # LTO recommendation
    if compiler.get("supports_lto_thin"):
        recommendations["enable_lto"] = "thin"
    elif compiler.get("supports_lto"):
        recommendations["enable_lto"] = "full"
    
    # PGO recommendation for CI
    if detection["runtime"]["is_ci"] and compiler.get("supports_pgo"):
        recommendations["enable_pgo"] = True
    
    return recommendations


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Detect platform features for BriX-Cache build configuration"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--ci-format",
        action="store_true",
        help="Output in CI-friendly format (GitHub Actions compatible)"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path (default: stdout)"
    )
    
    args = parser.parse_args()
    
    # Run all detections
    detection_result = {
        "platform": detect_platform(),
        "architecture": detect_architecture(),
        "compiler": detect_compiler_support(),
        "optimization_flags": detect_optimization_flags(),
        "runtime": detect_runtime_info(),
        "recommendations": None,  # Filled in below
    }
    
    # Generate recommendations
    detection_result["recommendations"] = generate_build_recommendations(detection_result)
    
    # Add metadata
    detection_result["metadata"] = {
        "script": "detect_platform_features.py",
        "version": "1.0.0",
        "timestamp": subprocess.run(
            ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True,
            text=True
        ).stdout.strip() if platform.system() != "Windows" else "unknown",
    }
    
    # Format output
    if args.ci_format:
        # GitHub Actions compatible format
        output_lines = []
        for key, value in detection_result.items():
            output_lines.append(f"{key}={json.dumps(value)}")
        output = "\n".join(output_lines)
    else:
        output = json.dumps(detection_result, indent=2)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
            f.write("\n")
        if args.verbose:
            print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(output)
    
    # Verbose summary to stderr
    if args.verbose:
        print("\n=== Platform Detection Summary ===", file=sys.stderr)
        print(f"Platform: {detection_result['platform']['name']} "
              f"({detection_result['platform']['release']})", file=sys.stderr)
        print(f"Architecture: {detection_result['architecture']['normalized']} "
              f"({detection_result['architecture']['family']})", file=sys.stderr)
        print(f"Compiler: {detection_result['compiler']['name']} "
              f"{detection_result['compiler']['version']}", file=sys.stderr)
        print(f"CPU Cores: {detection_result['runtime']['cpu_count']}", file=sys.stderr)
        if detection_result['runtime']['total_memory_mb']:
            print(f"Memory: {detection_result['runtime']['total_memory_mb']} MB", file=sys.stderr)
        print(f"LTO Support: {detection_result['compiler']['supports_lto']}", file=sys.stderr)
        print(f"Recommended march: {' '.join(detection_result['optimization_flags']['march'])}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
