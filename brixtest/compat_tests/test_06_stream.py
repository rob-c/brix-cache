"""File-linear streaming: tests in one file are one ordered pipeline.

The three stages below build on each other through a shared lane path
— each consumes exactly the state the previous stage left.  Serially
that is just collection order; under xdist the harness upgrades the
default distribution to ``loadfile`` (``HarnessConfig.file_linear``),
pinning every test in a file to one worker in file order, so the
pipeline holds under ``-n`` too.  Files stay independent of each
other — only the order *within* a file is promised.
"""


def _stream(brix):
    return brix.fleet.lane.tmp_dir / "stream-06.txt"


def test_stage_one_produces(brix):
    _stream(brix).write_text("one\n")   # a fresh pipeline every run


def test_stage_two_transforms(brix):
    path = _stream(brix)
    assert path.read_text() == "one\n", "stage two ran before stage one"
    path.write_text(path.read_text() + "two\n")


def test_stage_three_consumes(brix):
    assert _stream(brix).read_text() == "one\ntwo\n", (
        "the stream reached stage three out of order"
    )
