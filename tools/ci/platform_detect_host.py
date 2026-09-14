"""Host release, distribution, CI provider, and memory observations."""

import os
import platform

from platform_detect_command import read_optional, run_command


def _distribution_content():
    """Malformed release text triggers the same fallback as an absent file."""
    try:
        return read_optional("/etc/os-release")
    except ValueError:
        return ""


def _linux_distribution():
    information = {}
    for line in _distribution_content().splitlines():
        if '=' in line:
            key, value = line.strip().split('=', 1)
            information[key.lower()] = value.strip('\"\'')
    if not information:
        fallback = run_command(["lsb_release", "-a"])
        if fallback:
            information['raw'] = fallback
    return information


def _macos_release():
    information = {}
    for key, command in (("raw", ["sw_vers"]),
                         ("version", ["sw_vers", "-productVersion"]),
                         ("build", ["sw_vers", "-buildVersion"])):
        value = run_command(command)
        if value:
            information[key] = value
    return information


def detect_platform():
    """Detect platform information using the original JSON field names."""
    system = platform.system()
    name = system.lower()
    distro = _linux_distribution() if name == "linux" else {}
    macos = _macos_release() if name == "darwin" else {}
    return {"name": name, "system": system, "release": platform.release(),
            "version": platform.version(), "machine": platform.machine(),
            "linux_distro": distro or None, "macos": macos or None}


def _ci_provider():
    for variable, name in (("GITHUB_ACTIONS", "github-actions"),
                           ("GITLAB_CI", "gitlab-ci"), ("TRAVIS", "travis"),
                           ("CIRCLECI", "circleci"), ("JENKINS_URL", "jenkins")):
        if os.environ.get(variable):
            return name
    return None


def _linux_memory(info):
    try:
        for line in read_optional("/proc/meminfo").splitlines():
            if line.startswith("MemTotal:"):
                info["total_memory_mb"] = int(line.split()[1]) // 1024
            elif line.startswith("MemAvailable:"):
                info["available_memory_mb"] = int(line.split()[1]) // 1024
                break
    except ValueError:
        pass


def _darwin_memory(info):
    total = run_command(["sysctl", "-n", "hw.memsize"])
    if total:
        try:
            info["total_memory_mb"] = int(total) // (1024 * 1024)
        except ValueError:
            pass


def detect_runtime_info():
    """Report CI context and memory without requiring every host probe."""
    info = {"python_version": platform.python_version(),
            "is_ci": os.environ.get("CI", "").lower() in ("true", "1", "yes"),
            "ci_provider": _ci_provider(), "cpu_count": os.cpu_count() or 1,
            "total_memory_mb": None, "available_memory_mb": None}
    probe = {"Linux": _linux_memory, "Darwin": _darwin_memory}.get(platform.system())
    if probe:
        probe(info)
    return info
