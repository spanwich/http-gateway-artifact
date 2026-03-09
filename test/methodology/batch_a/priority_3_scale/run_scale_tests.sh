#!/bin/bash
#
# EverParse Scale Test Runner
# Tests M=[4, 8, 16, 32, 64] rule counts
#

set -e

# EVERPARSE requires the external everparse repo; generated C is already committed
EVERPARSE="everparse.sh"  # placeholder — only needed if re-generating from .3d
EVERPARSE_INC="."
CC="gcc"
CFLAGS="-Wall -Wextra -std=gnu99 -DEVERPARSE_NO_COPY"
TIMEOUT=120  # seconds

echo "=== EverParse Scale Test Results ==="
echo ""
printf "| %-4s | %-8s | %-18s | %-9s | %-11s | %-9s |\n" \
    "M" "Compiles" "EverParse Time (s)" "Verify OK" "Gen C Lines" "Func Test"
printf "| %-4s | %-8s | %-18s | %-9s | %-11s | %-9s |\n" \
    "----" "--------" "------------------" "---------" "-----------" "---------"

for M in 4 8 16 32 64; do
    COMPILES="NO"
    EP_TIME="-"
    VERIFY="NO"
    GEN_LINES="-"
    FUNC_TEST="-"

    # Generate 3D file and harness
    python3 generate_scale_test.py "$M" > /dev/null 2>&1

    SPEC="ScaleTest${M}.3d"
    MODULE="ScaleTest${M}"

    if [ ! -f "$SPEC" ]; then
        printf "| %-4s | %-8s | %-18s | %-9s | %-11s | %-9s |\n" \
            "$M" "GEN_FAIL" "$EP_TIME" "$VERIFY" "$GEN_LINES" "$FUNC_TEST"
        continue
    fi

    # Compile with EverParse (timed)
    START=$(date +%s%N)
    if timeout "$TIMEOUT" "$EVERPARSE" --batch "$SPEC" > "ep_${M}.log" 2>&1; then
        END=$(date +%s%N)
        ELAPSED=$(echo "scale=1; ($END - $START) / 1000000000" | bc)
        EP_TIME="$ELAPSED"
        COMPILES="YES"

        # Count generated C lines
        if [ -f "${MODULE}.c" ]; then
            GEN_LINES=$(wc -l < "${MODULE}.c")
        fi

        # Check F* verification succeeded (no errors in log)
        if ! grep -q "Error" "ep_${M}.log" 2>/dev/null; then
            VERIFY="YES"
        fi

        # Build functional test
        HARNESS="scale_func_test_${M}.c"
        TEST_BIN="scale_test_${M}"
        if $CC $CFLAGS -I. -I"$EVERPARSE_INC" -o "$TEST_BIN" \
            "$HARNESS" "${MODULE}.c" "${MODULE}Wrapper.c" 2> "gcc_${M}.log"; then

            # Run functional test
            if ./"$TEST_BIN" > "func_${M}.log" 2>&1; then
                FUNC_TEST="2/2"
            else
                # Check how many passed
                FUNC_TEST=$(grep -o '[0-9]*/[0-9]*' "func_${M}.log" | tail -1)
                if [ -z "$FUNC_TEST" ]; then
                    FUNC_TEST="FAIL"
                fi
            fi
        else
            FUNC_TEST="BUILD_FAIL"
        fi
    else
        EXIT_CODE=$?
        END=$(date +%s%N)
        ELAPSED=$(echo "scale=1; ($END - $START) / 1000000000" | bc)
        if [ "$EXIT_CODE" -eq 124 ]; then
            EP_TIME="TIMEOUT"
        else
            EP_TIME="$ELAPSED"
        fi
    fi

    printf "| %-4s | %-8s | %-18s | %-9s | %-11s | %-9s |\n" \
        "$M" "$COMPILES" "$EP_TIME" "$VERIFY" "$GEN_LINES" "$FUNC_TEST"

    # Clean up intermediate F* files
    rm -f *.fst *.fsti *.checked *.krml *.rsp 2>/dev/null
done

echo ""
echo "Done."
