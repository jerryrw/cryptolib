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
/* Discard exactly count keystream bytes. Returns 0 on success, -1 for NULL ctx.
 * Zero count leaves a valid context unchanged. This replaces the historical
 * rc4_skip(counter, ctx) macro; callers now use rc4_skip(ctx, 2048), for example.
 * Both peers must discard the same count to retain matching stream positions. */
int rc4_skip(rc4_ctx *ctx, size_t count);
/* Read exactly size plaintext bytes; return size ciphertext bytes plus a
 * convenience zero terminator. The ciphertext is binary, so never use strlen
 * to recover its length. NULL plaintext is accepted only for size == 0.
 * Returns NULL for invalid input or allocation failure; does not change plaintext. */
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, rc4_byte_t *plaintext, size_t size);
void rc4_free(rc4_ctx *ctx);

#endif /* ARCFOUR_H */