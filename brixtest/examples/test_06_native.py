"""Two independently collected, supervised native-program examples."""

from brixtest import expect_output, native_test

test_c_program = native_test(
    "c-program",
    sources=("native/hello.c",),
    standard="c11",
    defines={"BRIX_ANSWER": 42},
    stdout=expect_output("brixtest C answer=42", excludes=("FAIL",)),
    observe=[],
    keep="never",
)


test_cpp_program = native_test(
    "cpp-program",
    sources=("native/hello.cc",),
    standard="c++17",
    args=("ready",),
    stdout=expect_output(regex=(r"^brixtest C\+\+ value=ready$",), strip=True),
    observe=[],
    keep="never",
)
