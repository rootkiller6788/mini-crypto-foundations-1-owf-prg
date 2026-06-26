# Makefile — mini-hardcore-bit-goldreich-levin
# Goldreich-Levin Hardcore Bit & OWF → PRG Construction

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -I./include -O2
LDFLAGS = -lm

SRCDIR  = src
INCDIR  = include
TESTDIR = tests
BUILDDIR = build
EXAMPLEDIR = examples

SRCS = $(SRCDIR)/bit_operations.c \
       $(SRCDIR)/owf.c \
       $(SRCDIR)/hardcore_bit.c \
       $(SRCDIR)/goldreich_levin.c \
       $(SRCDIR)/list_decoding.c \
       $(SRCDIR)/security_proof.c \
       $(SRCDIR)/crypto_primitives.c \
       $(SRCDIR)/prg_from_owf.c

OBJS = $(SRCS:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

TESTS = $(BUILDDIR)/test_bit_operations \
        $(BUILDDIR)/test_owf \
        $(BUILDDIR)/test_hardcore_bit \
        $(BUILDDIR)/test_goldreich_levin \
        $(BUILDDIR)/test_security

EXAMPLES = $(BUILDDIR)/example_gl_theorem \
           $(BUILDDIR)/example_list_decoding \
           $(BUILDDIR)/example_prg_construction

.PHONY: all test examples clean

all: test examples

# --- Build Directory ---
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# --- Library Objects ---
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Tests ---
$(BUILDDIR)/test_bit_operations: $(TESTDIR)/test_bit_operations.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/test_owf: $(TESTDIR)/test_owf.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/test_hardcore_bit: $(TESTDIR)/test_hardcore_bit.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/test_goldreich_levin: $(TESTDIR)/test_goldreich_levin.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/test_security: $(TESTDIR)/test_security.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

# --- Examples ---
$(BUILDDIR)/example_gl_theorem: $(EXAMPLEDIR)/example_gl_theorem.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/example_list_decoding: $(EXAMPLEDIR)/example_list_decoding.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

$(BUILDDIR)/example_prg_construction: $(EXAMPLEDIR)/example_prg_construction.c $(OBJS)
	$(CC) $(CFLAGS) $< $(OBJS) $(LDFLAGS) -o $@

# --- Run ---
test: $(TESTS)
	@echo "=== Running Tests ==="
	@for t in $(TESTS); do echo ""; ./$$t; done

examples: $(EXAMPLES)
	@echo "=== Running Examples ==="
	@for e in $(EXAMPLES); do echo ""; ./$$e; done

clean:
	rm -rf $(BUILDDIR)

# --- Line Count ---
count:
	@echo "include/ lines: $$(find include -name '*.h' -exec cat {} + | wc -l)"
	@echo "src/ lines:     $$(find src -name '*.c' -exec cat {} + | wc -l)"
	@echo "total:          $$(find include src -name '*.h' -o -name '*.c' | xargs cat | wc -l)"
