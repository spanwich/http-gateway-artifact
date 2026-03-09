EVERPARSE_INC := .

CC := gcc
CFLAGS := -Wall -Wextra -std=gnu99 -I. -I$(EVERPARSE_INC) -DEVERPARSE_NO_COPY

# Functional tests: M=4,8,16 (generated C committed)
SCALE_SIZES := 4 8 16
FUNC_TARGETS := $(foreach M,$(SCALE_SIZES),scale_test_$(M))

.PHONY: all test test_func test_timeout clean

all: test

test: test_func test_timeout

# --- Functional tests (M=4,8,16): 2 tests each = 6 tests ---
test_func: $(FUNC_TARGETS)
	@PASS=0; FAIL=0; \
	for M in $(SCALE_SIZES); do \
		echo "--- M=$$M ---"; \
		if ./scale_test_$$M; then PASS=$$((PASS+1)); else FAIL=$$((FAIL+1)); fi; \
	done; \
	echo ""; echo "Scale func tests: $$PASS passed, $$FAIL failed"; \
	[ $$FAIL -eq 0 ]

$(foreach M,$(SCALE_SIZES),scale_test_$(M)): scale_test_%: scale_func_test_%.c ScaleTest%.c ScaleTest%Wrapper.c
	$(CC) $(CFLAGS) -o $@ $^

# --- Timeout demonstration (M=32,64): 4 tests ---
# Monolithic Z3 verification times out at M >= 32.
# These tests verify the .3d specs exist while the generated
# validators are absent, motivating the partitioned scheme (Batch D).
test_timeout: scale_timeout_test
	@echo "--- M=32,64 (timeout demonstration) ---"
	./scale_timeout_test

scale_timeout_test: scale_timeout_test.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f scale_test_* scale_timeout_test
	rm -f ep_*.log gcc_*.log func_*.log
