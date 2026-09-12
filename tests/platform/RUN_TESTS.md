# Running PAL Platform Tests

## Quick Start

```bash
cd /Users/rcurrie/src/brix-cache/tests

# Install dependencies
pip install pytest pytest-cov psutil

# Run all PAL tests
PYTHONPATH=. pytest platform/ -v

# Run with coverage report
PYTHONPATH=. pytest platform/ --cov=pal_test_helpers --cov-report=html --cov-report=term
```

## Test Execution Examples

### All Tests
```bash
PYTHONPATH=. pytest platform/ -v
```

### Specific Test Files
```bash
# Platform API tests
PYTHONPATH=. pytest platform/test_pal_api.py -v

# Byte order tests
PYTHONPATH=. pytest platform/test_byte_order.py -v

# Anonymous FD tests
PYTHONPATH=. pytest platform/test_anon_fd.py -v

# Random tests
PYTHONPATH=. pytest platform/test_random.py -v

# Extended attributes tests
PYTHONPATH=. pytest platform/test_xattr.py -v
```

### By Platform Marker
```bash
# Linux-only tests
PYTHONPATH=. pytest platform/ -m linux -v

# macOS-only tests
PYTHONPATH=. pytest platform/ -m darwin -v

# x86_64 architecture tests
PYTHONPATH=. pytest platform/ -m x86_64 -v

# ARM64 architecture tests
PYTHONPATH=. pytest platform/ -m arm64 -v
```

### Exclude Slow Tests
```bash
PYTHONPATH=. pytest platform/ -v -m "not slow"
```

### Generate Coverage Report
```bash
# HTML report
PYTHONPATH=. pytest platform/ --cov=pal_test_helpers --cov-report=html

# Terminal report
PYTHONPATH=. pytest platform/ --cov=pal_test_helpers --cov-report=term

# JSON report for CI
PYTHONPATH=. pytest platform/ --cov=pal_test_helpers --cov-report=json
```

### Custom Coverage Report
```bash
# Text format
python platform/report_coverage.py

# JSON format
python platform/report_coverage.py --json > coverage.json

# Markdown format
python platform/report_coverage.py --markdown > COVERAGE.md
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Install Test Dependencies
  run: pip install pytest pytest-cov psutil

- name: Run PAL Tests
  run: |
    cd tests
    PYTHONPATH=. pytest platform/ -v --cov=pal_test_helpers --cov-report=xml

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./tests/coverage.xml
```

### GitLab CI
```yaml
test:pal:
  stage: test
  image: python:3.11
  script:
    - cd tests
    - pip install pytest pytest-cov psutil
    - PYTHONPATH=. pytest platform/ -v --cov=pal_test_helpers
  coverage: '/TOTAL.*\s+(\d+%)/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: tests/coverage.xml
```

## Troubleshooting

### Import Errors
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=/Users/rcurrie/src/brix-cache/tests
```

### Missing Dependencies
```bash
pip install pytest pytest-cov psutil
```

### Permission Errors
```bash
# Some tests require root
sudo PYTHONPATH=. pytest platform/ -m requires_root -v
```

### Filesystem Support
```bash
# Xattr tests need filesystem support
# Run on ext4/APFS, not tmpfs
cd ~
PYTHONPATH=/Users/rcurrie/src/brix-cache/tests pytest tests/platform/test_xattr.py -v
```

## Expected Output

```
tests/platform/test_pal_api.py::test_brix_plat_name PASSED
tests/platform/test_pal_api.py::test_brix_plat_version PASSED
tests/platform/test_pal_api.py::test_brix_plat_arch PASSED
...
tests/platform/test_byte_order.py::test_htobe64_be64toh_roundtrip PASSED
...
tests/platform/test_random.py::test_random_basic PASSED
...
tests/platform/test_xattr.py::test_xattr_set_get_basic PASSED
...

===================== 50 passed in 2.34s ======================
```

## Coverage Thresholds

| Coverage | Status | Action |
|----------|--------|--------|
| ≥95% | ✅ Excellent | No action needed |
| ≥80% | ✅ Good | Continue testing |
| ≥50% | ⚠️ Acceptable | Add more tests |
| <50% | ❌ Poor | Priority testing needed |

Current coverage: **57%** (25/44 functions tested)

