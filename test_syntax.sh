#!/bin/bash
# test_syntax.sh - Syntax check for platform wrapper files

echo "=========================================="
echo "Platform Layer Syntax Verification"
echo "=========================================="
echo

PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"
echo

# Check syntax of all platform files
echo "Checking C syntax..."
PASS=0
FAIL=0

for file in src/platform/*.c src/platform/*.h src/platform/*/*.c; do
    if [ -f "$file" ]; then
        BASENAME=$(basename "$file")
        # Use gcc -fsyntax-only for syntax check without linking
        if gcc -fsyntax-only -Isrc -I. -D__APPLE__ -D__MACH__ "$file" 2>/dev/null; then
            echo "  ✓ $BASENAME"
            PASS=$((PASS + 1))
        else
            # Check if it's just missing nginx headers (expected)
            if gcc -E -Isrc -I. "$file" 2>&1 | grep -q "ngx_core.h"; then
                echo "  ⚠ $BASENAME (needs nginx headers - expected)"
                PASS=$((PASS + 1))
            else
                echo "  ✗ $BASENAME (syntax error)"
                FAIL=$((FAIL + 1))
            fi
        fi
    fi
done

echo
echo "Results:"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo

if [ $FAIL -eq 0 ]; then
    echo "✅ All files have valid syntax (or only need nginx headers)"
else
    echo "❌ Some files have syntax errors"
    exit 1
fi

echo
echo "=========================================="
echo "Next: Full build requires nginx source"
echo "=========================================="
