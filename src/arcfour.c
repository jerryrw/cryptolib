/*
 * RC4 is a legacy stream cipher shown here for educational study.
 * The key shuffles S into a permutation; each rc4_byte call then changes that
 * state and returns one keystream byte. Encrypt/decrypt by XORing the message
 * with the same keystream. Unlike a hash context, an RC4 context is consumed as
 * it runs: decryption needs a fresh context with the same key and stream position.
 */

#include "arcfour.h"
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
rc4_ctx *rc4_init(rc4_byte_t *key, size_t keylen)
{
    unsigned int i, j;
    rc4_byte_t temp;
    rc4_ctx *ctx;

    if (!key || keylen == 0)
        return NULL;

/* malloc allocates heap storage that outlives this function. sizeof(rc4_ctx)
 * is the number of bytes needed for the struct. NULL means allocation failed;
 * the caller owns a successful result and must eventually call rc4_free. */
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
/* i % keylen cycles through the key bytes. The earlier zero-length check
 * prevents division by zero. % 256 keeps the permutation index in 0..255. */
        j = (j + ctx->S[i] + key[i % keylen]) % 256;

        /* Swap S[i] and S[j] */
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    /* Initialize PRGA indices */
    ctx->i = 0;
    ctx->j = 0;

/* The disabled discard loop below changes the stream position. The RFC
 * test vectors start at byte zero; discarding bytes requires both peers to
 * advance by exactly the same count. The current loop would discard 2049 bytes. */
    // this works for use but does not pass one test due to the nature of the test
    // for (int x = 0; x < 2049; x++)
    //     (volatile rc4_byte_t) rc4_byte(ctx); // explicitly tell compiler to not optimize

    return ctx;
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

/*
 * rc4_encrypt - Encrypt data with RC4
 */
rc4_byte_t *rc4_encrypt(rc4_ctx *ctx, rc4_byte_t *plaintext, size_t size)
{
    size_t x;
    rc4_byte_t *ciphertext;

    if (!ctx || (!plaintext && size != 0) || size == SIZE_MAX)
        return NULL;

/* Reserve an extra byte for a convenience zero terminator. Ciphertext is
 * still binary: zeros can appear anywhere, so use size, never strlen. Reject
 * SIZE_MAX above because adding one would wrap to a too-small allocation. */
    ciphertext = (rc4_byte_t *)malloc(size + 1);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    for (x = 0; x < size; x++)
    {
/* XOR is its own inverse: (message XOR stream) XOR stream = message.
 * rc4_byte advances ctx, so reuse of a consumed context changes the stream. */
        ciphertext[x] = plaintext[x] ^ rc4_byte(ctx);
    }

    ciphertext[size] = '\0';
    return ciphertext;
}

/*
 * rc4_free - Free RC4 context
 */
/* This releases the context allocation; it does not erase its contents.
 * A caller that wants to wipe it must do so before freeing it. The separately
 * allocated ciphertext from rc4_encrypt must be freed by the caller as well. */
void rc4_free(rc4_ctx *ctx)
{
    if (ctx != NULL)
    {
        free(ctx);
    }
}