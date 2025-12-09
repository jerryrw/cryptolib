/*
 * SHA-3-256 (FIPS 202) - Pure C implementation
 * No external libraries, no dependencies
 * Works on any architecture (including Apple Silicon M1/M2/M3/M4)
 *
 * Features:
 * - Full SHA-3-256 (256-bit output)
 * - Hash strings / memory buffers
 * - Hash entire files efficiently
 * - Thoroughly commented
 * - Constant-time where required
 *
 * Public domain / CC0 - use freely
 */

#include "include/sha3.h"

/* Keccak-f[1600] round constants */
static const u64 keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL};

/* Rotation offsets for Keccak-f[1600] */
static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

/* Permutation offsets for rho/pi steps */
static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

/* Keccak-f[1600] permutation */
static void keccakf(u64 state[25])
{
    int round, i, j;
    u64 t, bc[5];

    for (round = 0; round < 24; round++)
    {

        /* Theta step */
        for (i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

        for (i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (j = 0; j < 25; j += 5)
                state[j + i] ^= t;
        }

        /* Rho and Pi steps */
        t = state[1];
        for (i = 0; i < 24; i++)
        {
            j = keccakf_piln[i];
            bc[0] = state[j];
            state[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        /* Chi step */
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
                bc[i] = state[j + i];
            for (i = 0; i < 5; i++)
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota step */
        state[0] ^= keccakf_rndc[round];
    }
}

/* SHA-3 context */
typedef struct
{
    u64 state[25];   // 1600-bit state
    u8 buffer[144];  // Input buffer (rate = 1088 bits = 136 bytes for SHA-3-256)
    size_t buf_len;  // Current bytes in buffer
    size_t rate;     // 136 for SHA-3-256
    size_t hash_len; // 32 for SHA-3-256
} sha3_256_ctx;

/* Initialize SHA-3-256 context */
void sha3_256_init(sha3_256_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = SHA3_256_BLOCK_SIZE; // 136 bytes
    ctx->hash_len = SHA3_256_HASH_SIZE;
}

/* Absorb data into the sponge */
static void sha3_absorb(sha3_256_ctx *ctx, const u8 *data, size_t len)
{
    while (len > 0)
    {
        size_t take = ctx->rate - ctx->buf_len;
        if (take > len)
            take = len;

        for (size_t i = 0; i < take; i++)
            ctx->buffer[ctx->buf_len + i] ^= data[i];

        data += take;
        len -= take;
        ctx->buf_len += take;

        if (ctx->buf_len == ctx->rate)
        {
            /* Full block: permute */
            u64 *state64 = (u64 *)ctx->buffer;
            for (int i = 0; i < 17; i++) // 136/8 = 17
                ctx->state[i] ^= state64[i];
            keccakf(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

/* Final padding and squeeze */
static void sha3_final(sha3_256_ctx *ctx, u8 *out)
{
    /* SHA-3 padding: "01" + zeros + "1" in the domain of 01 for SHA-3 */
    ctx->buffer[ctx->buf_len++] ^= 0x06; // Append 0110
    ctx->buffer[ctx->rate - 1] ^= 0x80;  // Append 1 at the end

    /* Absorb final block */
    u64 *state64 = (u64 *)ctx->buffer;
    for (int i = 0; i < 17; i++)
        ctx->state[i] ^= state64[i];
    keccakf(ctx->state);

    /* Squeeze out 32 bytes */
    memcpy(out, ctx->state, 32);
}

/* High-level: hash a buffer */
void sha3_256(const u8 *input, size_t len, u8 hash[32])
{
    sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_absorb(&ctx, input, len);
    sha3_final(&ctx, hash);
}

/* Hash a string (null-terminated) */
void sha3_256_string(const char *str, u8 hash[32])
{
    sha3_256((const u8 *)str, strlen(str), hash);
}

/* Hash an entire file */
int sha3_256_file(const char *path, u8 hash[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    u8 buffer[8192];
    size_t n;

    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0)
        sha3_absorb(&ctx, buffer, n);

    if (ferror(f))
    {
        fclose(f);
        return -1;
    }

    sha3_final(&ctx, hash);
    fclose(f);
    return 0;
}

/* Utility: print hash in hex */
void sha3_256_print(const u8 hash[32])
{
    for (int i = 0; i < 32; i++)
        printf("%02x", hash[i]);
    printf("\n");
}
