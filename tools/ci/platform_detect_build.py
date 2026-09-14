"""Compiler probes and the platform detector's existing build flag policy."""

import os
import re
import subprocess

from platform_detect_command import run_command
from platform_detect_cpu import detect_architecture
from platform_detect_host import detect_platform


def _compiler_identity(output):
    text = output.lower()
    for marker, name in (("gcc", "gcc"), ("clang", "clang"), ("apple", "apple-clang")):
        if marker in text:
            return name
    return None


def _compiler_version(output, information):
    if not output:
        return
    name = _compiler_identity(output)
    information["name"] = name
    version = re.search(r'(\d+\.\d+\.\d+)', output)
    if name is None or version is None:
        return
    information.update(version=version.group(1), supports_lto=True, supports_pgo=True)
    information["supports_lto_thin"] = name in ("clang", "apple-clang")


def _compiler_accepts(cc, flag):
    result = subprocess.run([cc, "-x", "c", "-", "-o", "/dev/null", flag],
                            input="int main() { return 0; }", capture_output=True,
                            text=True)
    return result.returncode == 0


def detect_compiler_support():
    """Probe full and thin LTO while preserving compiler identification order."""
    cc = os.environ.get("CC", "cc")
    information = {"name": None, "version": None, "supports_lto": False,
                   "supports_lto_thin": False, "supports_pgo": False}
    _compiler_version(run_command([cc, "--version"]), information)
    information["supports_lto"] = _compiler_accepts(cc, "-flto")
    if information["name"] in ("clang", "apple-clang"):
        information["supports_lto_thin"] = _compiler_accepts(cc, "-flto=thin")
    return information


def _x86_level(features):
    for feature, march, tune in (("has_avx512", "x86-64-v4", "znver4"),
                                 ("has_avx2", "x86-64-v3", "haswell"),
                                 ("has_sse4_2", "x86-64-v2", "core2")):
        if features.get(feature):
            return march, tune
    return "x86-64", "generic"


def _x86_model_tune(model):
    if "AMD" in model and "Ryzen" in model:
        return "znver4"
    if "Intel" not in model:
        return None
    if any(generation in model for generation in ("12th", "13th", "14th")):
        return "alderlake"
    if "11th" in model:
        return "tigerlake"
    return None


def _x86_flags(flags, features, host):
    march, tune = _x86_level(features)
    flags["march"].append("-march=" + march)
    flags["mtune"].append("-mtune=" + tune)
    if host == "linux":
        model = run_command(["lscpu"])
        observed = _x86_model_tune(model) if model else None
        if observed:
            flags["mtune"] = ["-mtune=" + observed]


def _apple_level(chip):
    for model, march, tune in (("M3", "armv8.5-a", "apple-m3"),
                               ("M2", "armv8.4-a", "apple-m2"),
                               ("M1", "armv8.3-a", "apple-m1")):
        if model in chip:
            return march, tune
    return "armv8.5-a", "apple-m1"


def _apple_flags(flags, features):
    if not features.get("is_apple_silicon"):
        return
    march, tune = _apple_level(features.get("apple_chip", ""))
    flags["march"].append("-march=" + march)
    flags["mtune"].append("-mtune=" + tune)
    flags["frameworks"].append("-framework Accelerate")


def _feature_flags(features, names):
    return ["+" + name for name in names if features.get("has_" + name)]


def _arm64_flags(flags, features, host):
    if host == "darwin":
        _apple_flags(flags, features)
        return
    march = "armv8-a+crc" if features.get("has_crc32") else "armv8-a"
    flags["march"].append("-march=" + march)
    flags["cpu_features"].extend(_feature_flags(features, ("crypto", "sve")))


def _arm_flags(flags, features, host):
    flags["march"].append("-march=armv7-a")
    flags["mtune"].append("-mtune=cortex-a9")
    flags["cpu_features"].extend(_feature_flags(features, ("neon", "vfpv4")))


def detect_optimization_flags():
    """Choose flags with independent architecture and linker policies."""
    architecture = detect_architecture()
    host = detect_platform()["name"]
    flags = {"march": [], "mtune": [], "cpu_features": [],
             "frameworks": [], "ldflags": []}
    configure = {"x86_64": _x86_flags, "arm64": _arm64_flags,
                 "arm": _arm_flags}.get(architecture["family"])
    if configure:
        configure(flags, architecture["features"], host)
    flags["ldflags"].extend({"darwin": ["-Wl,-dead_strip", "-Wl,-search_paths_first"],
                            "linux": ["-Wl,-z,relro", "-Wl,-z,now"]}.get(host, []))
    return flags


def _recommended_features(architecture, host):
    features = {"x86_64": ["sse4_2", "avx2", "aes"],
                "arm64": ["crc32", "crypto", "neon"]}.get(architecture, [])
    if architecture == "arm64" and host == "darwin":
        features.append("apple_silicon_opt")
    return features


def _recommended_lto(compiler):
    if compiler.get("supports_lto_thin"):
        return "thin"
    if compiler.get("supports_lto"):
        return "full"
    return False


def generate_build_recommendations(detection):
    """Keep the build recommendation schema and existing platform policy."""
    host = detection["platform"]["name"]
    architecture = detection["architecture"]["family"]
    compiler = detection["compiler"]
    platform_flags = {
        "linux": {"BRIX_PLATFORM_LINUX": "1", "BRIX_PLATFORM_DARWIN": "0"},
        "darwin": {"BRIX_PLATFORM_LINUX": "0", "BRIX_PLATFORM_DARWIN": "1",
                   "_DARWIN_C_SOURCE": "1"},
        "windows": {"BRIX_PLATFORM_WINDOWS": "1"},
    }
    warnings = []
    if host == "windows":
        warnings.append("Windows support is beta - use WSL2 for production")
    return {"platform_flags": platform_flags.get(host, {}),
            "optimization_level": "-O3", "enable_lto": _recommended_lto(compiler),
            "enable_pgo": bool(detection["runtime"]["is_ci"] and compiler.get("supports_pgo")),
            "features_to_enable": _recommended_features(architecture, host),
            "features_to_disable": [], "warnings": warnings}
