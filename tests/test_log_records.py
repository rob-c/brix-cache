from log_records import semantic_log_text


def test_semantic_log_text_decodes_printable_message_bytes():
    raw = r'message="export \x22/data\x22 \xe2\x80\x94 ready" truncated=0'
    assert 'message="export "/data" — ready" truncated=0' == semantic_log_text(raw)


def test_semantic_log_text_keeps_malformed_utf8_encoded():
    raw = r'message="bad \xff byte" truncated=0'
    assert semantic_log_text(raw) == raw


def test_semantic_log_text_never_materializes_control_bytes():
    raw = r'message="safe\x0aforged" truncated=0'
    assert semantic_log_text(raw) == raw
