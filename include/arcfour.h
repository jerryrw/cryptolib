/*
 * RC4 is a legacy algorithm retained here for learning stream-cipher mechanics.
 * Ownership: rc4_init returns heap memory released with rc4_free. rc4_encrypt
 * returns a separate heap buffer released with free. Neither result may be used
 * after being freed. Contexts advance with use; a new context with the same key
 * is needed to reproduce the same stream for decryption.
 */

#ifndef ARCFOUR_H
#define ARCFOUR_H

#include <stddef.h>
#include <stdint.h>

/* Type definitions for RC4 */
typedef unsigned char rc4_byte_t;

/* Historical convenience macro: this actually discards 2049 bytes (0..2048).
 * x is a caller-supplied loop counter and y a context pointer. It expands to a
 * for statement, not a function. The volatile cast does not make the algorithm
 * secure; state changes, rather than the discarded return value, matter here. */
// used to skip the first 2048 bytes of output for statistical purposes
#define rc4_skip(x, y)         \
    for (x = 0; x < 2049; x++) \
        (volatile rc4_byte_t) rc4_byte(y); // explicitly tell compiler to not optimize

/* RC4 context structure - maintains state between operations */
typedef struct
{
    rc4_byte_t S[256]; /* S-box (substitution box) - permutation of 0-255 */
    rc4_byte_t i;      /* Index i for PRGA (MUST be 8-bit) */
    rc4_byte_t j;      /* Index j for PRGA (MUST be 8-bit) */
} rc4_ctx;

/* Function prototypes */
/* key must point to at least size readable bytes, with size > 0.
 * Returns NULL for missing/empty key or allocation failure. Key bytes are read
 * but not modified; the current signature does not express that with const. */
rc4_ctx *rc4_init(rc4_byte_t *key, size_t size);
/* Requires a valid initialized context; generates one byte and changes ctx. */
rc4_byte_t rc4_byte(rc4_ctx *ctx);
/* Read exactly size plaintext bytes; return size ciphertext bytes plus a
 * convenience zero terminator. The ciphertext is binary, so never use strlen
 * to recover its length. NULL plaintext is accepted only for size == 0.
 * Returns NULL for invalid input or allocation failure; does not change plaintext. */
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, rc4_byte_t *plaintext, size_t size);
void rc4_free(rc4_ctx *ctx);

#endif /* ARCFOUR_H */