# Makefile -- mini-pseudorandom-generators-crypto
CC       = gcc
CFLAGS   = -std=c11 -Wall -Wextra -pedantic -O2 -g
INCLUDES = -Iinclude
LDFLAGS  = -lm

SRC_DIR  = src
BUILD_DIR = build
TEST_DIR = tests
EX_DIR   = examples

SRCS     = src/prg_crypto.c src/prg_number_theory.c src/prg_hybrid.c \
           src/hardcore_bit.c src/blum_blum_shub.c src/blum_micali.c \
           src/prg_construction.c src/prg_applications.c
OBJS     = $(SRCS:src/%.c=build/%.o)

.PHONY: all clean test examples

all: test

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/test_prg: tests/test_prg.c $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) -o $@

build/example_bbs: examples/example_bbs.c $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) -o $@

build/example_bm: examples/example_bm.c $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) -o $@

build/example_hybrid: examples/example_hybrid.c $(OBJS)
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) $< $(OBJS) $(LDFLAGS) -o $@

test: build/test_prg
	@echo "=== Running Tests ==="
	./build/test_prg
	@echo "=== Tests Passed ==="

examples: build/example_bbs build/example_bm build/example_hybrid
	@echo "=== Running Examples ==="
	./build/example_bbs
	./build/example_bm
	./build/example_hybrid

clean:
	rm -rf build/*
