#include "include/arcfour.h"
#include <stdlib.h>
#include <string.h>

/*
 * RC4 (Rivest Cipher 4) Implementation
 * Exact implementation from RFC 6229
 */

/*
 * rc4_init - Initialize RC4 context with a key
 * Key Scheduling Algorithm (KSA)
 */
rc4_ctx *rc4_init(rc4_byte_t *key, size_t keylen)
{
    unsigned int i, j;
    rc4_byte_t temp;
    rc4_ctx *ctx;

    ctx = (rc4_ctx *)malloc(sizeof(rc4_ctx));
    if (ctx == NULL)
    {
        return NULL;
    }

    /* Initialize S-box */
    for (i = 0; i < 256; i++)
    {
        ctx->S[i] = (rc4_byte_t)i;
    }

    /* KSA main loop */
    j = 0;
    for (i = 0; i < 256; i++)
    {
        j = (j + ctx->S[i] + key[i % keylen]) % 256;

        /* Swap S[i] and S[j] */
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    /* Initialize PRGA indices */
    ctx->i = 0;
    ctx->j = 0;

    // for (int x = 0; x < 2049; x++)
    //     (volatile rc4_byte_t) rc4_byte(ctx); // explicitly tell compiler to not optimize

    return ctx;
}

/*
 * rc4_byte - Generate next keystream byte
 * Pseudo-Random Generation Algorithm (PRGA)
 */
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

/*
 * rc4_encrypt - Encrypt data with RC4
 */
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, rc4_byte_t *plaintext, size_t size)
{
    size_t x;
    rc4_byte_t *ciphertext;

    ciphertext = (rc4_byte_t *)malloc(size + 1);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    for (x = 0; x < size; x++)
    {
        ciphertext[x] = plaintext[x] ^ rc4_byte(ctx);
    }

    ciphertext[size] = '\0';
    return ciphertext;
}

/*
 * rc4_free - Free RC4 context
 */
void rc4_free(rc4_ctx *ctx)
{
    if (ctx != NULL)
    {
        free(ctx);
    }
}