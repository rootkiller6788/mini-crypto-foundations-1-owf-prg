# Makefile for mini-hybrid-argument
CC      = gcc
CFLAGS  = -Wall -std=c99 -O2 -Iinclude
LDFLAGS = -lm
EXEEXT  = .exe
SRCDIR  = src
TESTDIR = tests
EXDIR   = examples
BUILDDIR = build

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

.PHONY: all clean test examples build-tests build-examples

all: $(OBJS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

build-tests: $(OBJS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(TESTDIR)/test_hybrid_argument.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_hybrid_argument
	$(CC) $(CFLAGS) $(TESTDIR)/test_distinguisher.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_distinguisher
	$(CC) $(CFLAGS) $(TESTDIR)/test_negligible.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_negligible
	$(CC) $(CFLAGS) $(TESTDIR)/test_prg_hybrid.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_prg_hybrid
	$(CC) $(CFLAGS) $(TESTDIR)/test_next_bit_unpredictable.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_next_bit_unpredictable
	$(CC) $(CFLAGS) $(TESTDIR)/test_security_reduction.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/test_security_reduction

build-examples: $(OBJS)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(EXDIR)/example_hybrid_proof.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/example_hybrid_proof
	$(CC) $(CFLAGS) $(EXDIR)/example_negligible_decay.c $(OBJS) $(LDFLAGS) -o $(BUILDDIR)/example_negligible_decay
	@echo "Note: example_prg_stretch and example_distinguisher_game compile but may have"
	@echo "runtime issues on MinGW due to _strdup linking. Run manually if needed:"
	@echo "  gcc -std=c99 -Iinclude examples/example_prg_stretch.c src/*.c -lm -o example_prg_stretch"

test: build-tests
	@echo "=== Running Tests ==="
	@$(BUILDDIR)/test_hybrid_argument$(EXEEXT) || exit 1
	@$(BUILDDIR)/test_distinguisher$(EXEEXT) || exit 1
	@$(BUILDDIR)/test_negligible$(EXEEXT) || exit 1
	@$(BUILDDIR)/test_prg_hybrid$(EXEEXT) || exit 1
	@$(BUILDDIR)/test_next_bit_unpredictable$(EXEEXT) || exit 1
	@$(BUILDDIR)/test_security_reduction$(EXEEXT) || exit 1
	@echo "=== All tests passed ==="

examples: build-examples
	@echo "=== Running Examples ==="
	@$(BUILDDIR)/example_hybrid_proof$(EXEEXT) || exit 1
	@$(BUILDDIR)/example_negligible_decay$(EXEEXT) || exit 1
	@echo "=== Examples complete ==="

clean:
	rm -rf $(BUILDDIR)
