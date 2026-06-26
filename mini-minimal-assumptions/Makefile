# Makefile — mini-minimal-assumptions
# Cryptographic Minimal Assumptions Framework
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -g
INCDIR = include
SRCDIR = src
TESTDIR = tests
EXAMPLEDIR = examples
BUILDDIR = build

LDFLAGS = -lm

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
TESTS = $(wildcard $(TESTDIR)/*.c)
TESTBINS = $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/test_%,$(TESTS))
EXAMPLES = $(wildcard $(EXAMPLEDIR)/*.c)
EXAMPLEBINS = $(patsubst $(EXAMPLEDIR)/%.c,$(BUILDDIR)/example_%,$(EXAMPLES))

.PHONY: all clean test examples build check lines help _ensure_builddir

all: $(OBJS)
	@echo "=== Build Complete ==="

build: all

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | _ensure_builddir
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

_ensure_builddir:
	@mkdir -p $(BUILDDIR)

test: _ensure_builddir $(TESTBINS)
	@echo "=== Running Tests ==="
	@for t in $(TESTBINS); do echo "--- $$t ---"; ./$$t || exit 1; done
	@echo "=== All Tests Passed ==="

$(BUILDDIR)/test_%: $(TESTDIR)/%.c $(OBJS) | _ensure_builddir
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(OBJS) -o $@ $(LDFLAGS)

examples: _ensure_builddir $(EXAMPLEBINS)
	@echo "=== Running Examples ==="
	@for e in $(EXAMPLEBINS); do echo "--- $$e ---"; ./$$e; done
	@echo "=== All Examples Complete ==="

$(BUILDDIR)/example_%: $(EXAMPLEDIR)/%.c $(OBJS) | _ensure_builddir
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(OBJS) -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILDDIR)

check: $(OBJS)
	@echo "=== Compilation Check Passed ==="

lines:
	@echo "include/:"
	@wc -l $(INCDIR)/*.h
	@echo "src/:"
	@wc -l $(SRCDIR)/*.c
	@echo "---"
	@echo "Total (include+src):"
	@cat $(INCDIR)/*.h $(SRCDIR)/*.c | wc -l

help:
	@echo "make build    — compile all source files"
	@echo "make test     — compile and run all tests"
	@echo "make examples — compile and run all examples"
	@echo "make check    — quick compilation check"
	@echo "make clean    — remove build artifacts"
	@echo "make lines    — count lines of code"
