FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        pytest \
        "pytest-timeout>=2.3" \
        "XRootD>=5.9" \
        cryptography \
        requests \
        urllib3

WORKDIR /test

COPY k8s-tests/test-runner/ .

ARG COPY_TESTS=false
RUN if [ "$COPY_TESTS" = "true" ]; then \
        cp -r /repo/tests/* /test/ 2>/dev/null || true; \
    fi

VOLUME /test-results

ENTRYPOINT ["python", "/test/run_tests.py"]
