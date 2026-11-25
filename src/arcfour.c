/*
 * RC4 is a legacy stream cipher shown here for educational study.
 * The key shuffles S into a permutation; each rc4_byte call then changes that
 * state and returns one keystream byte. Encrypt/decrypt by XORing the message
 * with the same keystream. Unlike a hash context, an RC4 context is consumed as
 * it runs: decryption needs a fresh context with the same key and stream position.
 */

#include "arcfour.h"
#include "cryptolib_internal.h"
#include <stdlib.h>
#include <string.h>

/*
 * RC4 (Rivest Cipher 4) Implementation
 * Keystream output is checked against RFC 6229 test vectors
 */

/*
 * rc4_init - Initialize RC4 context with a key
 * Key Scheduling Algorithm (KSA)
 */
rc4_ctx *rc4_init(const rc4_byte_t *key, size_t keylen)
{
    if (!key || keylen == 0) return NULL;
    rc4_ctx *ctx = malloc(sizeof(*ctx));
    if (!ctx) return NULL;
    if (rc4_init_checked(ctx, key, keylen) != CRYPTOLIB_SUCCESS) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

/* The checked initializer supports stack contexts without any allocation. */
int rc4_init_checked(rc4_ctx *ctx, const rc4_byte_t *key, size_t keylen)
{
    if (!ctx || !key || keylen == 0) return CRYPTOLIB_ERROR_INVALID_PARAM;
    /* Start with every byte value exactly once, then permute using the key. */
    for (unsigned int i = 0; i < 256; i++) ctx->S[i] = (rc4_byte_t)i;
    unsigned int j = 0;
    for (unsigned int i = 0; i < 256; i++) {
        /* Modulo cycles over key bytes and keeps j inside the 256-byte table. */
        j = (j + ctx->S[i] + key[i % keylen]) % 256;
        rc4_byte_t temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    ctx->i = ctx->j = 0;
    return CRYPTOLIB_SUCCESS;
}

/*
 * rc4_byte - Generate next keystream byte
 * Pseudo-Random Generation Algorithm (PRGA)
 */
/* ctx must be a valid initialized context. -> accesses a struct member
 * through a pointer. Mutations to i, j and S remain visible to later calls. */
rc4_byte_t rc4_byte(rc4_ctx *ctx)
{
    rc4_byte_t temp;
    unsigned int t;

    /* Increment i (with wrapping) */
    ctx->i = (ctx->i + 1) % 256;

    /* Add S[i] to j (with wrapping) */
    ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

    /* Swap S[i] and S[j] */
    temp = ctx->S[ctx->i];
    ctx->S[ctx->i] = ctx->S[ctx->j];
    ctx->S[ctx->j] = temp;

    /* Generate keystream byte */
    t = (ctx->S[ctx->i] + ctx->S[ctx->j]) % 256;

    return ctx->S[t];
}

/* A real function evaluates caller arguments once and is safe in if/else.
 * Count down rather than using i <= count, which could wrap at SIZE_MAX. */
int rc4_skip(rc4_ctx *ctx, size_t count)
{
    if (!ctx) return CRYPTOLIB_ERROR_INVALID_PARAM;
    while (count != 0) {
        (void)rc4_byte(ctx);
        count--;
    }
    return CRYPTOLIB_SUCCESS;
}

/*
 * rc4_encrypt - Encrypt data with RC4
 */
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, const rc4_byte_t *plaintext, size_t size)
{
    if (!ctx || (!plaintext && size != 0) || size == SIZE_MAX) return NULL;
    rc4_byte_t *ciphertext = malloc(size + 1);
    if (!ciphertext) return NULL;
    if (rc4_crypt_buffer(ctx, plaintext, size, ciphertext, size) != CRYPTOLIB_SUCCESS) {
        free(ciphertext);
        return NULL;
    }
    ciphertext[size] = '\0'; /* Convenience only: ciphertext is binary. */
    return ciphertext;
}

int rc4_crypt_buffer(rc4_ctx *ctx, const rc4_byte_t *input, size_t size,
                     rc4_byte_t *output, size_t output_capacity)
{
    if (!ctx || (size && (!input || !output))) return CRYPTOLIB_ERROR_INVALID_PARAM;
    if (output_capacity < size) return CRYPTOLIB_ERROR_BUFFER_TOO_SMALL;
    /* XOR is its own inverse; each call consumes the next keystream byte.
     * Check everything first so rejected calls cannot change stream position. */
    for (size_t i = 0; i < size; i++) output[i] = input[i] ^ rc4_byte(ctx);
    return CRYPTOLIB_SUCCESS;
}

void rc4_cleanup(rc4_ctx *ctx)
{
    cryptolib_wipe(ctx, sizeof(*ctx));
}

/*
 * rc4_free - Free RC4 context
 */
/* Free only contexts created by rc4_init. Wipe before releasing the storage. */
void rc4_free(rc4_ctx *ctx)
{
    if (ctx) {
        rc4_cleanup(ctx);
        free(ctx);
    }
}
