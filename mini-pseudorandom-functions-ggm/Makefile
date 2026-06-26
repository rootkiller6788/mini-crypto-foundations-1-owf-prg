# Makefile for mini-pseudorandom-functions-ggm
# Goldreich-Goldwasser-Micali PRF Construction from PRG

CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11 -O2 -g
AR       = ar rcs
INCLUDES = -Iinclude
LIBS     = -lm
BUILDDIR = build

SRCS = src/prg.c src/prf.c src/crypto_utils.c src/ggm.c
OBJS = $(BUILDDIR)/prg.o $(BUILDDIR)/prf.o $(BUILDDIR)/crypto_utils.o $(BUILDDIR)/ggm.o
LIBFILE = $(BUILDDIR)/libggm.a

.PHONY: all clean test examples

all: $(LIBFILE)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/prg.o: src/prg.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR)/prf.o: src/prf.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR)/crypto_utils.o: src/crypto_utils.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BUILDDIR)/ggm.o: src/ggm.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIBFILE): $(OBJS)
	$(AR) $@ $^

test: $(LIBFILE) $(BUILDDIR)/test_prf $(BUILDDIR)/test_prg $(BUILDDIR)/test_crypto $(BUILDDIR)/test_ggm
	@echo "=== Running PRG Tests ===" && $(BUILDDIR)/test_prg
	@echo "=== Running PRF Tests ===" && $(BUILDDIR)/test_prf
	@echo "=== Running Crypto Tests ===" && $(BUILDDIR)/test_crypto
	@echo "=== Running GGM Tests ===" && $(BUILDDIR)/test_ggm
	@echo "=== ALL TESTS PASSED ==="

$(BUILDDIR)/test_prf: tests/test_prf.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

$(BUILDDIR)/test_prg: tests/test_prg.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

$(BUILDDIR)/test_crypto: tests/test_crypto.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

$(BUILDDIR)/test_ggm: tests/test_ggm.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

examples: $(BUILDDIR)/example_ggm_demo $(BUILDDIR)/example_kdf $(BUILDDIR)/example_security

$(BUILDDIR)/example_ggm_demo: examples/example_ggm_demo.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

$(BUILDDIR)/example_kdf: examples/example_kdf.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

$(BUILDDIR)/example_security: examples/example_security.c $(LIBFILE) | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(BUILDDIR) -lggm $(LIBS) -o $@

clean:
	rm -rf $(BUILDDIR)

help:
	@echo "Targets: all, test, examples, clean, help"
