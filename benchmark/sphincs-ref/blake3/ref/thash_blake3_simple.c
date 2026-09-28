/*
 * BLAKE3 "simple" thash: the counterpart of ref/thash_shake_simple.c.
 *
 * T(F, ADRS) = BLAKE3(PK.seed || ADRS || input), truncated to SPX_N bytes.
 * BLAKE3's XOF semantics (arbitrary output length) replace SHAKE directly.
 */
#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"

#include "blake3.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
           const spx_ctx *ctx, uint32_t addr[8])
{
    SPX_VLA(uint8_t, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    blake3_hasher hasher;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_ADDR_BYTES, in, inblocks * SPX_N);

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    blake3_hasher_finalize(&hasher, out, SPX_N);
}
