"""A coverage improvement must retain every production line in its denominator."""

import pytest

from tools.ci.coverage_merge import line_rate, merge_execution


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return path


def _initial(tmp_path):
    return _write(tmp_path, "initial.info",
                  "TN:\nSF:/repo/src/worker.c\nFN:10,worker\nFNDA:0,worker\n"
                  "DA:10,0\nDA:11,0\nDA:12,0\nLF:3\nLH:0\nFNF:1\nFNH:0\nend_of_record\n"
                  "TN:\nSF:/repo/client/unused.c\nFN:1,unused\nFNDA:0,unused\n"
                  "DA:1,0\nLF:1\nLH:0\nend_of_record\n")


def test_request_and_unit_execution_merge_without_losing_unexecuted_code(tmp_path):
    initial = _initial(tmp_path)
    requests = _write(tmp_path, "requests.info",
                      "SF:/repo/src/worker.c\nDA:10,2\nDA:11,0\nFNDA:2,worker\nend_of_record\n")
    units = _write(tmp_path, "units.info",
                   "SF:/repo/src/worker.c\nDA:11,3\nFNDA:3,worker\nend_of_record\n")
    output = tmp_path / "coverage.info"
    merge_execution(initial, [requests, units], output)
    report = output.read_text()
    assert "DA:10,2\nDA:11,3\nDA:12,0\nLF:3" in report
    assert "FNDA:5,worker" in report and "LH:2" in report
    assert "SF:/repo/client/unused.c" in report and "DA:1,0" in report
    assert line_rate(output) == "50.0"


def test_harness_lines_and_alternate_build_branches_cannot_inflate_coverage(tmp_path):
    capture = _write(tmp_path, "units.info",
                     "SF:/repo/src/worker.c\nDA:999,100\nFNDA:100,test_main\nend_of_record\n"
                     "SF:/repo/client/tests/harness.c\nDA:1,100\nend_of_record\n"
                     "SF:/repo-other/src/worker.c\nDA:10,100\nend_of_record\n")
    output = tmp_path / "coverage.info"
    merge_execution(_initial(tmp_path), [capture], output)
    report = output.read_text()
    assert "999" not in report and "test_main" not in report
    assert "harness.c" not in report and "repo-other" not in report
    assert "DA:10,0\nDA:11,0\nDA:12,0" in report
    assert report.count("LH:0") == 2


@pytest.mark.parametrize("count", ["broken", "-1"])
def test_invalid_execution_counts_fail_without_publishing_a_report(tmp_path, count):
    capture = _write(tmp_path, "bad.info", f"SF:/repo/src/worker.c\nDA:10,{count}\nend_of_record\n")
    output = tmp_path / "coverage.info"
    with pytest.raises(ValueError):
        merge_execution(_initial(tmp_path), [capture], output)
    assert not output.exists()


def test_missing_capture_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        merge_execution(_initial(tmp_path), [tmp_path / "missing.info"], tmp_path / "result.info")


def test_empty_production_inventory_is_an_error(tmp_path):
    initial = _write(tmp_path, "initial.info", "TN:\n")
    with pytest.raises(ValueError, match="empty"):
        merge_execution(initial, [], tmp_path / "result.info")


def test_no_execution_retains_the_entire_zero_coverage_inventory(tmp_path):
    output = tmp_path / "result.info"
    merge_execution(_initial(tmp_path), [], output)
    report = output.read_text()
    assert report.count("SF:") == 2
    assert sum(row.startswith("DA:") for row in report.splitlines()) == 4
    assert report.count("LH:0") == 2
    assert line_rate(output) == "0.0"


def test_line_rate_does_not_round_a_below_target_result_up_to_eighty(tmp_path):
    rows = [f"DA:{number + 1},{int(number < 7999)}" for number in range(10000)]
    report = _write(tmp_path, "near-target.info",
                    "SF:/repo/src/worker.c\n" + "\n".join(rows) + "\nend_of_record\n")
    assert line_rate(report) == "79.99"
