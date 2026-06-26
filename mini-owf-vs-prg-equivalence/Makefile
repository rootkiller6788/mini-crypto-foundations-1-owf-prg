# Makefile — mini-owf-vs-prg-equivalence
# Builds the OWF ⇔ PRG equivalence library
#
# Targets:
#   make         — build the static library libowfprg.a
#   make test    — build and run all tests
#   make examples — build all examples
#   make clean   — remove build artifacts

CC       ?= gcc
CFLAGS   += -std=c99 -Wall -Wextra -pedantic -g -O2
CFLAGS   += -Iinclude
LDFLAGS  += -lm

# Source files
SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

# Test files
TEST_SRC = $(wildcard tests/*.c)
TEST_BIN = $(TEST_SRC:.c=.exe)

# Example files
EXAMPLE_SRC = $(wildcard examples/*.c)
EXAMPLE_BIN = $(EXAMPLE_SRC:.c=.exe)

# Demo files
DEMO_SRC = $(wildcard demos/*.c)
DEMO_BIN = $(DEMO_SRC:.c=.exe)

# Bench files
BENCH_SRC = $(wildcard benches/*.c)
BENCH_BIN = $(BENCH_SRC:.c=.exe)

# Library
LIB = build/libowfprg.a

# Default target
.PHONY: all
all: $(LIB)

# Build static library
$(LIB): $(OBJ)
	@mkdir -p build
	$(AR) rcs $@ $^

# Compile .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build and run tests
.PHONY: test
test: $(LIB) $(TEST_BIN)
	@echo "=== Running Tests ==="
	@for t in $(TEST_BIN); do \
		echo "--- $$(basename $$t) ---"; \
		./$$t || exit 1; \
	done
	@echo "=== All Tests Passed ==="

# Build test binaries
tests/%.exe: tests/%.c $(LIB)
	$(CC) $(CFLAGS) $< -Lbuild -lowfprg $(LDFLAGS) -o $@

# Build and run examples
.PHONY: examples
examples: $(EXAMPLE_BIN)
	@echo "=== Running Examples ==="
	@for e in $(EXAMPLE_BIN); do \
		echo "--- $$(basename $$e) ---"; \
		./$$e; \
	done

# Build example binaries
examples/%.exe: examples/%.c $(LIB)
	$(CC) $(CFLAGS) $< -Lbuild -lowfprg $(LDFLAGS) -o $@

# Build and run demos
.PHONY: demos
demos: $(DEMO_BIN)
	@echo "=== Running Demos ==="
	@for d in $(DEMO_BIN); do \
		echo "--- $$(basename $$d) ---"; \
		./$$d; \
	done

# Build demo binaries
demos/%.exe: demos/%.c $(LIB)
	$(CC) $(CFLAGS) $< -Lbuild -lowfprg $(LDFLAGS) -o $@

# Build and run benchmarks
.PHONY: benches
benches: $(BENCH_BIN)
	@echo "=== Running Benchmarks ==="
	@for b in $(BENCH_BIN); do \
		echo "--- $$(basename $$b) ---"; \
		./$$b; \
	done

# Build bench binaries
benches/%.exe: benches/%.c $(LIB)
	$(CC) $(CFLAGS) $< -Lbuild -lowfprg $(LDFLAGS) -o $@

# Clean
.PHONY: clean
clean:
	rm -f $(OBJ) $(TEST_BIN) $(EXAMPLE_BIN) $(DEMO_BIN) $(BENCH_BIN)
	rm -rf build/*.a
	rm -f src/*.o

# Help
.PHONY: help
help:
	@echo "Targets:"
	@echo "  make          — build libowfprg.a"
	@echo "  make test     — build and run tests"
	@echo "  make examples — build and run examples"
	@echo "  make demos    — build and run demos"
	@echo "  make benches  — build and run benchmarks"
	@echo "  make clean    — remove build artifacts"
