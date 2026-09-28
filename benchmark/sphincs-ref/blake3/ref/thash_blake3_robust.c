/*
 * BLAKE3 "robust" thash: the counterpart of ref/thash_shake_robust.c.
 *
 * Bitmask = BLAKE3(PK.seed || ADRS), squeezed to inblocks*n bytes;
 * out      = BLAKE3(PK.seed || ADRS || (input XOR bitmask)), truncated to n bytes.
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
    SPX_VLA(uint8_t, bitmask, inblocks * SPX_N);
    unsigned int i;
    blake3_hasher hasher;

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_ADDR_BYTES);

    /* Derive the bitmask. */
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buf, SPX_N + SPX_ADDR_BYTES);
    blake3_hasher_finalize(&hasher, bitmask, inblocks * SPX_N);

    for (i = 0; i < inblocks * SPX_N; i++) {
        buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
    }

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, buf, SPX_N + SPX_ADDR_BYTES + inblocks*SPX_N);
    blake3_hasher_finalize(&hasher, out, SPX_N);
}
