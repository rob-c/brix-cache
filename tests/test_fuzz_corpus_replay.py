"""Replay every maintained parser corpus with its original C invariants."""

from pathlib import Path
import shutil
import subprocess

import pytest

from cmdscripts.fuzz_all import BUILD_ARGS, FUZZ_DIR, fuzz_build_args


def replay_compiler():
    """Require a native compiler without changing the platform's normal SDK."""
    compiler = shutil.which('gcc') or shutil.which('cc')
    if compiler is None:
        pytest.skip('a C compiler is required for corpus replay')
    return compiler


@pytest.fixture(scope='module', params=sorted(BUILD_ARGS))
def corpus_driver(request, tmp_path_factory):
    """Reuse the fuzz build graph, replacing only libFuzzer's process driver."""
    compiler = replay_compiler()
    target = request.param
    arguments = [arg for arg in BUILD_ARGS[target][1:]
                 if not arg.startswith('-fsanitize=')]
    output = tmp_path_factory.mktemp(target) / 'replay'
    arguments[arguments.index('-o') + 1] = str(output)
    driver = Path(__file__).parent / 'c/fuzz_corpus_replay.c'
    result = subprocess.run(
        fuzz_build_args([compiler, *arguments, '-fsanitize=address,undefined',
                         str(driver)]), cwd=FUZZ_DIR,
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return target, output


def test_maintained_corpus_invariants(corpus_driver):
    """All retained valid, malformed and hostile seeds satisfy the fuzz checks."""
    target, binary = corpus_driver
    corpus = FUZZ_DIR / ('corpus_' + target.removeprefix('fuzz_'))
    seeds = sorted(path for path in corpus.iterdir() if path.is_file())
    assert seeds, f'{target} has no regression inputs'
    for start in range(0, len(seeds), 128):
        batch = seeds[start:start + 128]
        result = subprocess.run([str(binary), *map(str, batch)],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.endswith(f'replayed {len(batch)} corpus files\n')


def test_missing_corpus_is_a_failure(corpus_driver, tmp_path):
    """The replay driver cannot count an unreadable input as a passed test."""
    _target, binary = corpus_driver
    result = subprocess.run([str(binary), str(tmp_path / 'missing')],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'corpus replay failed:' in result.stderr


def test_oversized_corpus_is_rejected(corpus_driver, tmp_path):
    """A hostile corpus file cannot cause an unbounded replay allocation."""
    _target, binary = corpus_driver
    source = tmp_path / 'oversized'
    with source.open('wb') as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    result = subprocess.run([str(binary), str(source)], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 4
    assert 'corpus replay failed:' in result.stderr
