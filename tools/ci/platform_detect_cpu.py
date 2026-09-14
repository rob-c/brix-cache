"""Architecture normalization and host-specific CPU feature observations."""

import platform
import re

from platform_detect_command import read_optional, run_command


def _family(architecture):
    for prefixes, family in (
        (("x86_64",), "x86_64"), (("arm64", "aarch64"), "arm64"),
        (("arm",), "arm"), (("x86",), "x86"), (("riscv",), "riscv"),
    ):
        if architecture.startswith(prefixes):
            return family
    return "unknown"


def detect_architecture():
    """Normalize machine spelling and attach the existing feature schema."""
    machine = platform.machine().lower()
    aliases = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64",
               "arm64": "arm64", "armv7l": "armv7", "armv7hl": "armv7",
               "i386": "x86", "i686": "x86"}
    architecture = aliases.get(machine, machine)
    family = _family(architecture)
    probe = {"x86_64": detect_x86_features, "arm64": detect_arm64_features,
             "arm": detect_arm_features}.get(family, dict)
    return {"raw": machine, "normalized": architecture,
            "family": family, "features": probe()}


def _cpu_flags(content, label):
    match = re.search(label + r'\s*:\s*(.+)', content)
    return match.group(1).split() if match else []


def _set_flags(features, flags, mapping):
    for key, flag in mapping.items():
        features[key] = flag in flags


def _linux_x86(features):
    flags = _cpu_flags(read_optional("/proc/cpuinfo"), "flags")
    names = ("sse", "sse2", "sse3", "ssse3", "sse4_1", "sse4_2",
             "avx", "avx2", "aes", "crc32", "vmx", "svm")
    _set_flags(features, flags, {"has_" + name: name for name in names})
    features["has_avx512"] = any(flag.startswith("avx512") for flag in flags)


def _darwin_x86(features):
    for name in ("sse", "sse2", "sse3", "ssse3", "sse4_1", "sse4_2", "aes"):
        features["has_" + name] = True
    features["has_avx2"] = run_command(["sysctl", "-n", "hw.optional.avx2_0"]) == "1"
    features["has_avx"] = run_command(["sysctl", "-n", "hw.optional.avx1_0"]) == "1"


def _windows_cpu_features(name):
    if "ryzen" in name or "epyc" in name:
        return ("has_avx2", "has_aes", "has_crc32")
    if "intel" in name and any(model in name for model in ("i7", "i9", "xeon")):
        return ("has_avx2", "has_aes")
    return ()


def _windows_x86(features):
    features.update(has_sse=True, has_sse2=True)
    command = "Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Caption"
    name = run_command(["powershell", "-Command", command], timeout=5)
    if name is not None:
        features.update({key: True for key in _windows_cpu_features(name.lower())})


def detect_x86_features():
    """Keep the existing Linux, Darwin, and Windows feature interpretation."""
    names = ("sse", "sse2", "sse3", "ssse3", "sse4_1", "sse4_2", "avx",
             "avx2", "avx512", "aes", "crc32", "vmx", "svm")
    features = {"has_" + name: False for name in names}
    probe = {"Linux": _linux_x86, "Darwin": _darwin_x86,
             "Windows": _windows_x86}.get(platform.system())
    if probe:
        probe(features)
    return features


def _linux_arm64(features):
    content = read_optional("/proc/cpuinfo")
    flags = _cpu_flags(content, "Features")
    _set_flags(features, flags, {"has_crc32": "crc32", "has_aes": "aes",
               "has_sha1": "sha1", "has_sha2": "sha2", "has_lse": "atomics",
               "has_sve": "sve"})
    features["has_crypto"] = "pmull" in flags or "asimd" in flags
    implementer = re.search(r'CPU implementer\s*:\s*(\S+)', content)
    if implementer:
        features["is_apple_silicon"] = implementer.group(1).lower() in ("0x41", "0x61")
    # Preserve the optional auxiliary-vector probe; its output is not parsed.
    run_command(["ld.so", "--help"], timeout=5)


def _darwin_arm64(features):
    if platform.machine() != "arm64":
        return
    features["is_apple_silicon"] = True
    chip = run_command(["sysctl", "-n", "machdep.cpu.brand_string"])
    if chip:
        features["apple_chip"] = chip
    for name in ("crc32", "crypto", "aes", "sha1", "sha2", "lse"):
        features["has_" + name] = True


def detect_arm64_features():
    """Report ARM64 baseline capabilities and optional host observations."""
    features = {"has_crc32": False, "has_crypto": False, "has_aes": False,
                "has_sha1": False, "has_sha2": False, "has_neon": True,
                "has_fp": True, "has_lse": False, "has_sve": False,
                "has_sve2": False, "is_apple_silicon": False, "apple_chip": None}
    probe = {"Linux": _linux_arm64, "Darwin": _darwin_arm64}.get(platform.system())
    if probe:
        probe(features)
    return features


def detect_arm_features():
    """Report ARMv7 features when Linux exposes a CPU feature line."""
    names = ("neon", "vfpv3", "vfpv4", "thumb")
    features = {"has_" + name: False for name in names}
    if platform.system() == "Linux":
        flags = _cpu_flags(read_optional("/proc/cpuinfo"), "Features")
        _set_flags(features, flags, {"has_" + name: name for name in names})
    return features
