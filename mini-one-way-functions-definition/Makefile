# Makefile for mini-one-way-functions-definition
# One-Way Functions: Formal Definition and Candidate Constructions
#
# Targets:
#   make all      - Build library and all programs
#   make lib      - Build static library libowf.a
#   make test     - Build and run tests
#   make examples - Build all examples
#   make bench    - Build benchmarks
#   make demo     - Build demos
#   make clean    - Remove build artifacts

CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -O2 -g
INCLUDES = -Iinclude
LDFLAGS  = -lm

SRC_DIR  = src
INC_DIR  = include
TEST_DIR = tests
EX_DIR   = examples
BENCH_DIR = benches
DEMO_DIR  = demos
BUILD_DIR = build

SRCS     = $(wildcard $(SRC_DIR)/*.c)
OBJS     = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
TESTS    = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN = $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/test_%,$(TESTS))
EXAMPLES = $(wildcard $(EX_DIR)/*.c)
EX_BIN   = $(patsubst $(EX_DIR)/%.c,$(BUILD_DIR)/example_%,$(EXAMPLES))
BENCHES  = $(wildcard $(BENCH_DIR)/*.c)
BENCH_BIN = $(patsubst $(BENCH_DIR)/%.c,$(BUILD_DIR)/bench_%,$(BENCHES))
DEMOS    = $(wildcard $(DEMO_DIR)/*.c)
DEMO_BIN = $(patsubst $(DEMO_DIR)/%.c,$(BUILD_DIR)/demo_%,$(DEMOS))

LIB      = $(BUILD_DIR)/libowf.a

.PHONY: all lib test examples bench demo clean

all: lib test examples bench demo

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

lib: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Test binaries
$(BUILD_DIR)/test_%: $(TEST_DIR)/%.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILD_DIR) -lowf $(LDFLAGS) -o $@

# Example binaries
$(BUILD_DIR)/example_%: $(EX_DIR)/%.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILD_DIR) -lowf $(LDFLAGS) -o $@

test: $(TEST_BIN)
	@echo "=== Running Tests ==="
	@for t in $(TEST_BIN); do echo "Running: $$t"; ./$$t || exit 1; done
	@echo "=== All Tests Passed ==="

examples: $(EX_BIN)

# Bench binaries
$(BUILD_DIR)/bench_%: $(BENCH_DIR)/%.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILD_DIR) -lowf $(LDFLAGS) -o $@

bench: $(BENCH_BIN)

run-bench: bench
	@for b in $(BENCH_BIN); do echo "=== Running: $$b ==="; ./$$b; echo; done

# Demo binaries
$(BUILD_DIR)/demo_%: $(DEMO_DIR)/%.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILD_DIR) -lowf $(LDFLAGS) -o $@

demo: $(DEMO_BIN)

run-demo: demo
	@for d in $(DEMO_BIN); do echo "=== Running: $$d ==="; ./$$d; echo; done

run-examples: examples
	@for e in $(EX_BIN); do echo "=== Running: $$e ==="; ./$$e; echo; done

clean:
	rm -rf $(BUILD_DIR)

# Help
help:
	@echo "Targets: all lib test examples bench demo clean run-examples run-bench run-demo help"
