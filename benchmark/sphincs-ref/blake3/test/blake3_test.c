/*
 * Standalone BLAKE3 primitive self-test for the SPHINCS+ BLAKE3 build.
 *
 * This program does not depend on the SPHINCS+ sources at all: it only uses
 * the BLAKE3 library in blake3/ref/ and verifies it against the official
 * BLAKE3 test vectors (from the BLAKE3 repository's test_vectors.json,
 * https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json).
 *
 * What is checked:
 *   1. Unkeyed BLAKE3 hash (XOF) of inputs of length 0, 3, 1024 and 1025
 *      bytes (the BLAKE3 test generator uses input[i] = i % 251).
 *   2. Keyed BLAKE3 hash of the same inputs with the official 32-byte test
 *      key ("whats the Elvish word for friend").
 *   3. Arbitrary XOF output lengths: 32-byte vs 1-byte vs 57-byte squeeze of
 *      the same input must agree on the first bytes (this is what the
 *      SPHINCS+ hash_message uses, squeezing SPX_DGST_BYTES != 32 bytes).
 *   4. Incremental hashing equals one-shot hashing (SPHINCS+ feeds messages
 *      through blake3_hasher_update in several chunks).
 *   5. blake3_hasher_reset restores the initial state.
 *
 * Build (from blake3/):
 *   make blake3_test
 *   ./blake3_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"

static int failures = 0;

static void check_hex(const char *what, const uint8_t *got, size_t got_len,
                      const char *expect_hex, size_t expect_len)
{
    static const char hexdig[] = "0123456789abcdef";
    char *got_hex = malloc(2 * got_len + 1);
    size_t i;

    if (got_hex == NULL) {
        printf("  X %s: out of memory\n", what);
        failures++;
        return;
    }
    for (i = 0; i < got_len; i++) {
        got_hex[2*i]     = hexdig[got[i] >> 4];
        got_hex[2*i + 1] = hexdig[got[i] & 0xf];
    }
    got_hex[2*got_len] = '\0';

    if (got_len != expect_len || memcmp(got_hex, expect_hex, 2 * got_len) != 0) {
        printf("  X %s\n    got      %s\n    expected %s\n",
               what, got_hex, expect_hex);
        failures++;
    } else {
        printf("  o %s\n", what);
    }
    free(got_hex);
}

int main(void)
{
    /* Official vectors from test_vectors.json (master branch). */
    static const char key_hex[] = "77686174732074686520456c7669736820776f726420666f7220667269656e64"; /* "whats the Elvish word for friend" */
    static const char hash_0[]   = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    static const char hash_3[]   = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f";
    static const char hash_1024[]= "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7";
    static const char hash_1025[]= "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444";
    static const char keyed_0[]   = "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26";
    static const char keyed_3[]   = "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9";
    static const char keyed_1024[]="75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4";
    static const char keyed_1025[]="357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69";

    static const size_t lens[] = { 0, 3, 1024, 1025 };
    uint8_t key[BLAKE3_KEY_LEN];
    uint8_t input[1025];
    uint8_t out1[BLAKE3_OUT_LEN];
    uint8_t out2[BLAKE3_OUT_LEN];
    uint8_t out3[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    size_t i, k;

    printf("BLAKE3 version: %s\n", blake3_version());
    printf("BLAKE3 key len = %d, out len = %d, block len = %d, chunk len = %d\n",
           BLAKE3_KEY_LEN, BLAKE3_OUT_LEN, BLAKE3_BLOCK_LEN, BLAKE3_CHUNK_LEN);

    /* Test input: i % 251, as produced by the official vector generator. */
    for (i = 0; i < sizeof(input); i++) {
        input[i] = (uint8_t)(i % 251);
    }
    /* Official key bytes. */
    for (i = 0; i < BLAKE3_KEY_LEN; i++) {
        unsigned int byte;
        sscanf(key_hex + 2*i, "%2x", &byte);
        key[i] = (uint8_t)byte;
    }

    printf("1) Unkeyed BLAKE3 hash vs official vectors\n");
    {
        static const char *const expect[] = { hash_0, hash_3, hash_1024, hash_1025 };
        for (k = 0; k < sizeof(lens)/sizeof(lens[0]); k++) {
            char what[64];
            snprintf(what, sizeof(what), "hash(input_len=%zu)", lens[k]);
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, input, lens[k]);
            blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
            check_hex(what, out1, BLAKE3_OUT_LEN, expect[k], BLAKE3_OUT_LEN);
        }
    }

    printf("2) Keyed BLAKE3 hash vs official vectors\n");
    {
        static const char *const expect[] = { keyed_0, keyed_3, keyed_1024, keyed_1025 };
        for (k = 0; k < sizeof(lens)/sizeof(lens[0]); k++) {
            char what[64];
            snprintf(what, sizeof(what), "keyed_hash(key, input_len=%zu)", lens[k]);
            blake3_hasher_init_keyed(&hasher, key);
            blake3_hasher_update(&hasher, input, lens[k]);
            blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
            check_hex(what, out1, BLAKE3_OUT_LEN, expect[k], BLAKE3_OUT_LEN);
        }
    }

    printf("3) XOF arbitrary output length (32 vs 1 vs 57 bytes)\n");
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, 1025);
    blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, out2, 1);
    blake3_hasher_finalize(&hasher, out3, 57);
    if (out1[0] == out2[0] && memcmp(out1, out3, 1) == 0
            && memcmp(out1, out3, 32) == 0) {
        printf("  o XOF squeeze consistency (first 32 of 57 == 32-byte out)\n");
    } else {
        printf("  X XOF squeeze consistency\n");
        failures++;
    }

    printf("4) Incremental vs one-shot hashing\n");
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, 100);
    blake3_hasher_update(&hasher, input + 100, 700);
    blake3_hasher_update(&hasher, input + 800, 225);
    blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, 1025);
    blake3_hasher_finalize(&hasher, out2, BLAKE3_OUT_LEN);
    if (memcmp(out1, out2, BLAKE3_OUT_LEN) == 0) {
        printf("  o incremental == one-shot\n");
    } else {
        printf("  X incremental == one-shot\n");
        failures++;
    }

    printf("5) blake3_hasher_reset restores the initial state\n");
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, 1025);
    blake3_hasher_reset(&hasher);
    blake3_hasher_update(&hasher, input, 1025);
    blake3_hasher_finalize(&hasher, out1, BLAKE3_OUT_LEN);
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, 1025);
    blake3_hasher_finalize(&hasher, out2, BLAKE3_OUT_LEN);
    if (memcmp(out1, out2, BLAKE3_OUT_LEN) == 0) {
        printf("  o reset == fresh init\n");
    } else {
        printf("  X reset == fresh init\n");
        failures++;
    }

    if (failures == 0) {
        printf("\nAll BLAKE3 primitive checks passed.\n");
        return 0;
    }
    printf("\n%d check(s) FAILED.\n", failures);
    return 1;
}
