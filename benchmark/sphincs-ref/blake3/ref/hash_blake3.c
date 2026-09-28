/*
 * BLAKE3 instantiation of the SPHINCS+ hash interface (ref/hash.h).
 *
 * This file is the BLAKE3 counterpart of ref/hash_shake.c / ref/hash_sha2.c.
 * It implements the four functions declared in ref/hash.h using the BLAKE3
 * hasher API (blake3.h), which natively provides an extensible-output
 * function (XOF) as well as keyed hashing.
 *
 * Construction summary:
 *   - prf_addr         : BLAKE3 keyed hash.  Key   = PK.seed (padded to the
 *                        BLAKE3 key length of 32 bytes), input = ADRS || SK.seed.
 *   - gen_message_random: BLAKE3 XOF over SK.prf || R_opt || M, squeezed to n bytes.
 *   - hash_message     : BLAKE3 XOF over R || PK.seed || PK.root || M, squeezed to
 *                        SPX_DGST_BYTES bytes (BLAKE3 natively supports arbitrary
 *                        output lengths, so no MGF1 construction is needed).
 *   - initialize_hash_function: no-op, exactly like the SHAKE instantiation.
 *
 * Note: BLAKE3 keys are always 32 bytes (BLAKE3_KEY_LEN).  Since SPX_N is at
 * most 32, the n-byte public seed is zero-padded to a 32-byte key.  For
 * SPX_N == 32 (the sphincs-shake-256-* parameter sets) the key is the public
 * seed verbatim.
 */
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "blake3.h"

/* Expand the n-byte public seed into a 32-byte BLAKE3 key (zero-padded). */
static void blake3_key_from_pub_seed(uint8_t key[BLAKE3_KEY_LEN],
                                     const spx_ctx *ctx)
{
#if SPX_N > BLAKE3_KEY_LEN
    #error "BLAKE3 keyed mode assumes SPX_N <= 32"
#endif
    memcpy(key, ctx->pub_seed, SPX_N);
    memset(key + SPX_N, 0, BLAKE3_KEY_LEN - SPX_N);
}

/* For BLAKE3 there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx *ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, ADRS) = BLAKE3_keyed(key = PK.seed,
 * input = ADRS || SK.seed), truncated to SPX_N bytes.
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    blake3_hasher hasher;
    uint8_t key[BLAKE3_KEY_LEN];

    blake3_key_from_pub_seed(key, ctx);
    blake3_hasher_init_keyed(&hasher, key);
    blake3_hasher_update(&hasher, addr, SPX_ADDR_BYTES);
    blake3_hasher_update(&hasher, ctx->sk_seed, SPX_N);
    blake3_hasher_finalize(&hasher, out, SPX_N);
}

/**
 * Computes the message-dependent randomness R = BLAKE3(sk_prf || optrand || m),
 * squeezed to SPX_N bytes.
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    blake3_hasher hasher;

    (void)ctx;

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, sk_prf, SPX_N);
    blake3_hasher_update(&hasher, optrand, SPX_N);
    blake3_hasher_update(&hasher, m, (size_t)mlen);
    blake3_hasher_finalize(&hasher, R, SPX_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    blake3_hasher hasher;
    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;

    /* H_msg: BLAKE3(R || PK.seed || PK.root || M), squeezed to SPX_DGST_BYTES.
       BLAKE3 is an XOF, so no MGF1-style expansion is required. */
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, R, SPX_N);
    blake3_hasher_update(&hasher, pk, SPX_PK_BYTES);
    blake3_hasher_update(&hasher, m, (size_t)mlen);
    blake3_hasher_finalize(&hasher, buf, SPX_DGST_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    if (SPX_D == 1) {
        *tree = 0;
    } else {
        *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
        *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    }
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
