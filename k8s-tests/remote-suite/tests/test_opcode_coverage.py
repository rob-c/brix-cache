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
    py_files = [p for p in test_dir.rglob("*.py")]
    file_texts = [p.read_text(encoding="utf-8", errors="ignore") for p in py_files]

    missing = []
    for op in ops:
        found = False
        # Exact `kXR_...` mention in any test file
        for text in file_texts:
            if op in text:
                found = True
                break
        if found:
            continue

        # Fallback: search for short name as whole word (e.g., 'pgread' for 'kXR_pgread')
        short = op[len("kXR_") :]
        pat = re.compile(r"\b" + re.escape(short) + r"\b", re.IGNORECASE)
        for text in file_texts:
            if pat.search(text):
                found = True
                break

        if not found:
            missing.append(op)

    assert not missing, (
        "Missing tests for the following implemented opcodes: {}\n"
        "Add targeted tests or reference these opcodes in existing tests."
    ).format(
        ", ".join(missing)
    )
