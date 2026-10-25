"""Native Mach-O checks: PIE and W^X, without pretending ELF RELRO exists."""

import re
import subprocess


def check_header(header, *, executable):
    """Reject unknown image headers and explicit executable-stack opt-outs."""
    assert header.count("Mach header") == 1, "expected one native Mach-O image"
    assert "MH_MAGIC_64" in header, "missing 64-bit Mach-O header"
    assert "ALLOW_STACK_EXECUTION" not in header, "executable stack is enabled"
    if executable:
        assert "EXECUTE" in header and re.search(r"\bPIE\b", header), "executable is not PIE"
    else:
        assert re.search(r"\b(DYLIB|BUNDLE)\b", header), "module is not a loadable image"


def check_segments(commands):
    """No initially writable+executable segment; executable text is required."""
    segments = re.findall(r"segname\s+(\S+).*?initprot\s+(0x[0-9a-fA-F]+)",
                          commands, re.S)
    assert segments, "Mach-O segment commands are missing"
    assert any(name == "__TEXT" and int(protection, 16) & 4
               for name, protection in segments), "executable text segment is missing"
    for name, protection in segments:
        assert int(protection, 16) & 6 != 6, f"writable+executable segment: {name}"


def check_binary(path, *, executable):
    header = subprocess.run(["otool", "-hv", str(path)], check=True,
                            capture_output=True, text=True, timeout=15).stdout
    commands = subprocess.run(["otool", "-l", str(path)], check=True,
                              capture_output=True, text=True, timeout=15).stdout
    check_header(header, executable=executable)
    check_segments(commands)
