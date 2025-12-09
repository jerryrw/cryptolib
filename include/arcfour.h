#ifndef ARCFOUR_H
#define ARCFOUR_H

#include <stddef.h>
#include <stdint.h>

/* Type definitions for RC4 */
typedef unsigned char rc4_byte_t;

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
rc4_ctx *rc4_init(rc4_byte_t *key, size_t size);
rc4_byte_t rc4_byte(rc4_ctx *ctx);
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, rc4_byte_t *plaintext, size_t size);
void rc4_free(rc4_ctx *ctx);

#endif /* ARCFOUR_H */