# Makefile: SPHINCS+ reference implementation built with BLAKE3 as the hash
# function.
#
# This build is fully self-contained in the blake3/ directory.  No file inside
# the upstream git repository (../ref) is modified: the shared SPHINCS+
# sources are compiled directly from ../ref, while the BLAKE3 hash
# instantiations (hash_blake3.c, thash_blake3_*.c) and the BLAKE3 library
# itself live in ./ref.
#
# The hash function is selected by the Makefile (exactly like the upstream
# ref/Makefile selects sha2/shake/haraka via the PARAMS name): here BLAKE3 is
# always used.  PARAMS only selects the SPHINCS+ parameter set, which for the
# BLAKE3 build must use the full 32-byte address layout, i.e. the
# sphincs-shake-* parameter headers (they pull in ../ref/shake_offsets.h).
#
# Usage:
#   make PARAMS=sphincs-shake-128f all            # tests + KAT + benchmark
#   make PARAMS=sphincs-shake-128f test           # run SPHINCS+ self-tests
#   make PARAMS=sphincs-shake-256f THASH=robust test
#   make blake3_test                              # BLAKE3 primitive self-test
#   make PQCgenKAT_sign                           # NIST KAT generator (-lcrypto)
#
# BLAKE3 SIMD acceleration:
#   SSE2 / SSE4.1 / AVX2 / AVX512 are enabled by default on x86-64.
#   Each SIMD source uses per-file CFLAGS for correct ISA targeting.
#   At runtime, blake3_dispatch.c probes CPUID and selects the best
#   implementation (portable fallback is always available).

PARAMS = sphincs-shake-128f
THASH  = simple

REFDIR = ../ref

CC     = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes \
         -DPARAMS=$(PARAMS) \
         -I$(REFDIR) -Iref \
         $(EXTRA_CFLAGS)

# Per-file ISA flags for SIMD intrinsics.  The portable base files get none.
SIMD_CFLAGS_sse2    = -msse2
SIMD_CFLAGS_sse41   = -msse4.1
SIMD_CFLAGS_avx2    = -mavx2
SIMD_CFLAGS_avx512  = -mavx512f -mavx512vl

LDLIBS =

# Shared SPHINCS+ sources (from the unmodified upstream tree).
SOURCES = $(REFDIR)/address.c $(REFDIR)/randombytes.c $(REFDIR)/merkle.c \
          $(REFDIR)/wots.c $(REFDIR)/wotsx1.c $(REFDIR)/utils.c \
          $(REFDIR)/utilsx1.c $(REFDIR)/fors.c $(REFDIR)/sign.c

# BLAKE3 hash instantiations plus the BLAKE3 library itself,
# including all SIMD-accelerated implementations.
SOURCES += ref/hash_blake3.c ref/thash_blake3_$(THASH).c \
           ref/blake3.c ref/blake3_portable.c ref/blake3_dispatch.c \
           ref/blake3_sse2.c ref/blake3_sse41.c ref/blake3_avx2.c \
           ref/blake3_avx512.c

HEADERS = $(REFDIR)/params.h $(REFDIR)/address.h $(REFDIR)/randombytes.h \
          $(REFDIR)/merkle.h $(REFDIR)/wots.h $(REFDIR)/wotsx1.h \
          $(REFDIR)/utils.h $(REFDIR)/utilsx1.h $(REFDIR)/fors.h \
          $(REFDIR)/api.h $(REFDIR)/hash.h $(REFDIR)/thash.h \
          ref/blake3.h ref/blake3_impl.h

# Deterministic variant of the sources (randombytes.c -> rng.c) for the NIST
# KAT generator, exactly as in the upstream ref/Makefile.
DET_SOURCES = $(SOURCES:$(REFDIR)/randombytes.c=$(REFDIR)/rng.c)

# BLAKE3-library-only sources, used by the standalone primitive self-test.
BLAKE3_SOURCES = ref/blake3.c ref/blake3_portable.c ref/blake3_dispatch.c \
                 ref/blake3_sse2.c ref/blake3_sse41.c ref/blake3_avx2.c \
                 ref/blake3_avx512.c

TESTS      = test_spx test_fors
BENCH_BIN  = bench_spx

.PHONY: all test tests benchmark clean

all: $(TESTS) $(BENCH_BIN) blake3_test

tests: $(TESTS)

test: $(TESTS)
	@./test_spx
	@./test_fors

benchmark: $(BENCH_BIN)
	@./$(BENCH_BIN)

# Pattern rule: compile a .c to .o, appending per-file SIMD flags.
# (Also supports linking directly without .o etch.)
%.o: %.c
	$(CC) $(CFLAGS) $(SIMD_FLAGS_$(*F)) -c -o $@ $<

# SPHINCS+ self-tests (keygen / sign / verify roundtrips through BLAKE3).
$(TESTS): $(REFDIR)/test/spx.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) \
	    ref/blake3_sse2.o: SIMD_FLAGS_blake3_sse2 = $(SIMD_CFLAGS_sse2) ; \
	    ref/blake3_sse41.o: SIMD_FLAGS_blake3_sse41 = $(SIMD_CFLAGS_sse41) ; \
	    ref/blake3_avx2.o: SIMD_FLAGS_blake3_avx2 = $(SIMD_CFLAGS_avx2) ; \
	    ref/blake3_avx512.o: SIMD_FLAGS_blake3_avx512 = $(SIMD_CFLAGS_avx512) ; \
	true

# Hmm, GNU make doesn't do per-target variable overrides this way.
# Use explicit compile-and-link with per-file CFLAGS instead.

# Explicit compile of SIMD sources with their required ISA flags.
BLAKE3_SIMD_OBJS = ref/blake3_sse2.o ref/blake3_sse41.o \
                   ref/blake3_avx2.o ref/blake3_avx512.o

ref/blake3_sse2.o: ref/blake3_sse2.c ref/blake3.h ref/blake3_impl.h
	$(CC) $(CFLAGS) $(SIMD_CFLAGS_sse2) -c -o $@ $<

ref/blake3_sse41.o: ref/blake3_sse41.c ref/blake3.h ref/blake3_impl.h
	$(CC) $(CFLAGS) $(SIMD_CFLAGS_sse41) -c -o $@ $<

ref/blake3_avx2.o: ref/blake3_avx2.c ref/blake3.h ref/blake3_impl.h
	$(CC) $(CFLAGS) $(SIMD_CFLAGS_avx2) -c -o $@ $<

ref/blake3_avx512.o: ref/blake3_avx512.c ref/blake3.h ref/blake3_impl.h
	$(CC) $(CFLAGS) $(SIMD_CFLAGS_avx512) -c -o $@ $<

# Base objects (no special SIMD flags)
BASE_OBJS = $(REFDIR)/address.o $(REFDIR)/randombytes.o $(REFDIR)/merkle.o \
            $(REFDIR)/wots.o $(REFDIR)/wotsx1.o $(REFDIR)/utils.o \
            $(REFDIR)/utilsx1.o $(REFDIR)/fors.o $(REFDIR)/sign.o \
            ref/hash_blake3.o ref/thash_blake3_$(THASH).o \
            ref/blake3.o ref/blake3_portable.o ref/blake3_dispatch.o

# Pattern rule for base object files
$(BASE_OBJS): %.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test_spx: $(REFDIR)/test/spx.c $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(BASE_OBJS) $(BLAKE3_SIMD_OBJS)

test_fors: $(REFDIR)/test/fors.c $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $< $(BASE_OBJS) $(BLAKE3_SIMD_OBJS)

$(BENCH_BIN): $(REFDIR)/test/benchmark.c $(REFDIR)/test/cycles.c \
              $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(REFDIR)/test/cycles.c $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) $< $(LDLIBS)

# NIST KAT generator (uses rng.c, requires the OpenSSL dev headers for
# AES256-CTR-DRBG).  Not part of `all`: it needs libssl-dev installed.
PQCgenKAT_sign: PQCgenKAT_sign.o $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) \
                ref/rng.o
	$(CC) $(CFLAGS) -o $@ PQCgenKAT_sign.o $(BASE_OBJS) $(BLAKE3_SIMD_OBJS) \
	    ref/rng.o -lcrypto

PQCgenKAT_sign.o: $(REFDIR)/PQCgenKAT_sign.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

ref/rng.o: $(REFDIR)/rng.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Standalone BLAKE3 primitive self-test against the official test vectors
# (test_vectors.json shipped in this directory).
blake3_test: test/blake3_test.c $(BLAKE3_SOURCES) ref/blake3.h
	$(CC) $(CFLAGS) \
	    $(SIMD_CFLAGS_sse2) $(SIMD_CFLAGS_sse41) \
	    $(SIMD_CFLAGS_avx2) $(SIMD_CFLAGS_avx512) \
	    -o $@ $(BLAKE3_SOURCES) $<

clean:
	-$(RM) $(TESTS) $(BENCH_BIN) PQCgenKAT_sign blake3_test
	-$(RM) *.o ref/*.o $(REFDIR)/*.o
	-$(RM) PQCsignKAT_*.req PQCsignKAT_*.rsp