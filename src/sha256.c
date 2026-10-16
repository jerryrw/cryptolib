/*
 * SHA-256 produces a 32-byte digest from an arbitrary sequence of bytes.
 * The context owns an unfinished 64-byte input block and eight running words.
 * init sets the starting state, update feeds bytes, and final pads and serializes.
 * uint32_t arithmetic intentionally wraps modulo 2^32; this is part of the hash,
 * not a signal that the program should use floating-point or wider arithmetic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

// SHA-256 constants
/* These 64 public constants are prescribed by SHA-256. static keeps the
 * name local to this file, and const prevents changing the table through K. */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Bitwise operations
/* Bit operations mix individual bits. A rotation preserves bits shifted
 * out of one end by bringing them back at the other. CH chooses y or z
 * according to x; MAJ gives the majority bit. EP/SIG combine rotations and
 * shifts. These macros require simple arguments without side effects. */
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// Initialize SHA-256 context
/* The hexadecimal starting words are fixed algorithm constants, not a key.
 * The caller passes &ctx to let us modify its original context rather than a copy. */
void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// Update context with more data
/* Each call may contain a fraction of a block or many blocks. datalen counts
 * bytes waiting in data; bitlen counts bits from blocks already compressed.
 * Once 64 bytes accumulate, consume them and reuse the buffer from index zero. */
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64)
        {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// Finalize hash computation
void sha256_final(SHA256_CTX *ctx, uint8_t *hash)
{
    size_t i = ctx->datalen;

/* SHA-256 appends a 1 bit, then zeros, then an 8-byte original bit count.
 * 56 = 64 - 8. If the current block has 56 or more bytes, use another block. */
    // Padding
    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;

        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

/* Include the unfinished bytes in the bit count. Store the length big-endian,
 * most significant byte first; right shifts select the byte to store. */
    // Append total bit length
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;

    sha256_transform(ctx, ctx->data);

    // Convert state to hash bytes
    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000FF;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000FF;
    }
}

// Main SHA-256 transformation function
void sha256_transform(SHA256_CTX *ctx, const uint8_t *data)
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

/* Load the first 16 schedule words from input in big-endian order. Cast
 * each byte to uint32_t before shifting to avoid signed-int promotion overflow. */
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];

/* Expand 16 input words into 64 schedule words. Each new word mixes
 * earlier words, so later rounds still depend on the whole input block. */
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

/* a..h are working copies of the running hash. Each round computes two
 * temporaries and moves the working words along. Assignment order matters: an
 * old value must be used before its variable is overwritten. */
    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

/* Feed forward the working result to the previous state. The next block
 * starts from this combined value, not from the initial constants. */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// Function to calculate SHA-256 hash of a file
/* FILE * is a C library stream handle, not the file contents. Read a
 * bounded number of bytes per iteration and hash only bytes_read, especially
 * on the short final read. The caller must provide at least 32 output bytes;
 * zero means success and -1 means an I/O failure. This function prints errors. */
int sha256_file(const char *filepath, uint8_t *hash)
{
    FILE *file;
    SHA256_CTX ctx;
    uint8_t buffer[4096];
    size_t bytes_read;

    // Open file
    file = fopen(filepath, "rb");
    if (!file)
    {
        perror("Error opening file");
        return -1;
    }

    // Initialize SHA-256 context
    sha256_init(&ctx);

    // Read and process file in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        sha256_update(&ctx, buffer, bytes_read);
    }

    // Check for file read errors
    if (ferror(file))
    {
        perror("Error reading file");
        fclose(file);
        return -1;
    }

    // Finalize hash
    sha256_final(&ctx, hash);

    // Close file
    fclose(file);

    return 0;
}

/* See src/example.c for a complete, built example using this API. */
