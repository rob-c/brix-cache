import re
from pathlib import Path


def get_supported_opcodes():
    root = Path(__file__).resolve().parent.parent
    doc = root / "docs" / "05-operations" / "operation-status.md"
    text = doc.read_text(encoding="utf-8")
    m = re.search(r"### Fully implemented\s*\n(.*?)\n### Not implemented", text, re.S)
    if m:
        table_text = m.group(1)
    else:
        start = text.find("### Fully implemented")
        if start == -1:
            raise RuntimeError("Cannot find '### Fully implemented' in docs/05-operations/operation-status.md")
        rest = text[start:]
        m2 = re.search(r"### Not implemented", rest)
        table_text = rest[: m2.start()] if m2 else rest

    ops = set(re.findall(r"`(kXR_[A-Za-z0-9_]+)`", table_text))
    if not ops:
        raise RuntimeError("No kXR_ opcodes found in the 'Fully implemented' section")
    return sorted(ops)


def test_all_supported_opcodes_have_tests():
    ops = get_supported_opcodes()
    test_dir = Path(__file__).resolve().parent
    file_texts = _read_sources(_python_files(test_dir))
    missing = _missing_opcodes(ops, file_texts)
    assert not missing, (
        "Missing tests for the following implemented opcodes: {}\n"
        "Add targeted tests or reference these opcodes in existing tests."
    ).format(
        ", ".join(missing)
    )


def _python_files(directory):
    return list(directory.rglob("*.py"))


def _read_sources(paths):
    return [path.read_text(encoding="utf-8", errors="ignore") for path in paths]


def _missing_opcodes(opcodes, file_texts):
    return [opcode for opcode in opcodes if not _opcode_is_covered(opcode, file_texts)]


def _opcode_is_covered(opcode, file_texts):
    if any(opcode in text for text in file_texts):
        return True
    short_name = opcode[len("kXR_"):]
    pattern = re.compile(r"\b" + re.escape(short_name) + r"\b", re.IGNORECASE)
    return any(pattern.search(text) for text in file_texts)
