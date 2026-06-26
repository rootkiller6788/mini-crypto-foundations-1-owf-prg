# Makefile for mini-trapdoor-permutations
# Builds the TDP library, tests, and examples.

CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -Iinclude
LDFLAGS  := -lm

# Handle .exe suffix on Windows
EXEEXT   := $(if $(findstring mingw,$(shell $(CC) -dumpmachine 2>/dev/null || echo mingw)),.exe,)
ifeq ($(OS),Windows_NT)
  EXEEXT := .exe
endif

# Source files
SRC_CORE      := src/tdp_core.c
SRC_MODMATH   := src/modular_math.c
SRC_RSA        := src/rsa.c
SRC_RSA_KEYGEN := src/rsa_keygen.c
SRC_PKE        := src/tdp_pke.c
SRC_SIG        := src/tdp_signatures.c

LIB_SRC := $(SRC_CORE) $(SRC_MODMATH) $(SRC_RSA) $(SRC_RSA_KEYGEN) $(SRC_PKE) $(SRC_SIG)

# Test
TEST_SRC := tests/test_main.c
TEST_BIN := build/test_main$(EXEEXT)

# Examples
EXAMPLE_TDP  := build/example_tdp_basic$(EXEEXT)
EXAMPLE_RSA  := build/example_rsa_full$(EXEEXT)
EXAMPLE_SIGN := build/example_rsa_sign$(EXEEXT)

.PHONY: all test examples bench demo run-examples run-bench run-demo clean check-lean

all: test examples

# --- Build directory ---
build:
	mkdir -p build

# --- Library objects ---
build/tdp_core.o: src/tdp_core.c include/tdp_core.h include/modular_math.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/modular_math.o: src/modular_math.c include/modular_math.h include/tdp_core.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/rsa.o: src/rsa.c include/rsa.h include/tdp_core.h include/modular_math.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/rsa_keygen.o: src/rsa_keygen.c include/rsa_keygen.h include/tdp_core.h include/modular_math.h include/rsa.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tdp_pke.o: src/tdp_pke.c include/tdp_pke.h include/tdp_core.h include/rsa.h include/modular_math.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tdp_signatures.o: src/tdp_signatures.c include/tdp_signatures.h include/tdp_core.h include/rsa.h include/modular_math.h | build
	$(CC) $(CFLAGS) -c $< -o $@

LIB_OBJS := build/tdp_core.o build/modular_math.o build/rsa.o build/rsa_keygen.o build/tdp_pke.o build/tdp_signatures.o

# --- Test ---
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): tests/test_main.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# --- Examples ---
examples: $(EXAMPLE_TDP) $(EXAMPLE_RSA) $(EXAMPLE_SIGN)

$(EXAMPLE_TDP): examples/example_tdp_basic.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

$(EXAMPLE_RSA): examples/example_rsa_full.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

$(EXAMPLE_SIGN): examples/example_rsa_sign.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# --- Benchmarks ---
BENCH_BIN := build/bench_tdp$(EXEEXT)
bench: $(BENCH_BIN)
	./$(BENCH_BIN)

$(BENCH_BIN): benches/bench_tdp.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

run-bench: bench

# --- Demo ---
DEMO_BIN := build/demo_tdp_visual$(EXEEXT)
demo: $(DEMO_BIN)
	./$(DEMO_BIN)

$(DEMO_BIN): demos/demo_tdp_visual.c $(LIB_OBJS) | build
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

run-demo: demo

# --- Run all examples ---
run-examples: examples
	@echo "=== Running example_tdp_basic ==="
	./$(EXAMPLE_TDP)
	@echo ""
	@echo "=== Running example_rsa_full ==="
	./$(EXAMPLE_RSA)
	@echo ""
	@echo "=== Running example_rsa_sign ==="
	./$(EXAMPLE_SIGN)

# --- Check Lean formalization ---
check-lean:
	@echo "Lean formalization file exists: $$([ -f src/tdp.lean ] && echo YES || echo NO)"
	@echo "Theorems in src/tdp.lean: $$(grep -c 'theorem ' src/tdp.lean || echo 0)"
	@echo "No 'sorry' in Lean: $$(grep -c 'sorry' src/tdp.lean && echo FAIL || echo PASS)"
	@echo "No 'by trivial' on non-trivial: $$(grep -c 'trivial' src/tdp.lean > /dev/null && echo CHECK || echo PASS)"

# --- Clean ---
clean:
	rm -rf build
