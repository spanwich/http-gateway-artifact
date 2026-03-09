# Methodology validation tests - top-level orchestrator
#
# Runs all test batches: root experiments + batch A-D

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.

.PHONY: all clean test root_tests batch_a batch_b batch_c batch_d mealy

all: test

test: root_tests batch_a batch_b mealy batch_c batch_d
	@echo ""
	@echo "========================================="
	@echo "All methodology tests passed."
	@echo "========================================="

# --- Root experiments (3 programs) ---
root_tests: test1_bin test2_bin test3_bin
	@echo "=== Root: EverParse DNF experiments ==="
	@./test1
	@echo ""
	@./test2
	@echo ""
	@./test3

test1_bin: test1_harness.c Test1Disjunction.c Test1DisjunctionWrapper.c
	$(CC) $(CFLAGS) -o test1 test1_harness.c Test1Disjunction.c Test1DisjunctionWrapper.c

test2_bin: test2_harness.c Test2Hybrid.c Test2HybridWrapper.c
	$(CC) $(CFLAGS) -o test2 test2_harness.c Test2Hybrid.c Test2HybridWrapper.c

test3_bin: test3_harness.c Test2Hybrid.c Test2HybridWrapper.c
	$(CC) $(CFLAGS) -o test3 test3_harness.c Test2Hybrid.c Test2HybridWrapper.c

# --- Batch A: RBAC + scale ---
batch_a:
	@echo ""
	@echo "=== Batch A: RBAC + Scale ==="
	$(MAKE) -C batch_a/priority_1_2_rbac test
	$(MAKE) -C batch_a/priority_3_scale test

# --- Batch B: Bitmask + arithmetic + range ---
batch_b:
	@echo ""
	@echo "=== Batch B: Bitmask/Arithmetic/Range ==="
	$(MAKE) -C batch_b/b1_bitmask test
	$(MAKE) -C batch_b/b2_arithmetic test
	$(MAKE) -C batch_b/b3_range test

# --- Mealy: State-dependent access control ---
mealy:
	@echo ""
	@echo "=== Mealy: State-Dependent Access Control ==="
	$(MAKE) -C mealy_auth_demo test

# --- Batch C: Multi-session pipeline ---
batch_c:
	@echo ""
	@echo "=== Batch C: Multi-Session Pipeline ==="
	$(MAKE) -C batch_c test

# --- Batch D: Partitioned verification ---
batch_d:
	@echo ""
	@echo "=== Batch D: Partitioned Verification ==="
	$(MAKE) -C batch_d test

clean:
	rm -f test1 test2 test3
	$(MAKE) -C batch_a/priority_1_2_rbac clean 2>/dev/null || true
	$(MAKE) -C batch_a/priority_3_scale clean 2>/dev/null || true
	$(MAKE) -C batch_b/b1_bitmask clean 2>/dev/null || true
	$(MAKE) -C batch_b/b2_arithmetic clean 2>/dev/null || true
	$(MAKE) -C batch_b/b3_range clean 2>/dev/null || true
	$(MAKE) -C batch_c clean 2>/dev/null || true
	$(MAKE) -C batch_d clean 2>/dev/null || true
	$(MAKE) -C mealy_auth_demo clean 2>/dev/null || true
