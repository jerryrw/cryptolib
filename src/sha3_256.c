/*
 * SHA3 uses a sponge: XOR input into part of a 200-byte state, permute that
 * state, then extract digest bytes. SHA3-256 accepts 136 bytes per absorb block
 * (the rate), while 64 bytes remain as the capacity. The state is represented
 * as 25 unsigned 64-bit lanes. Its indexing and byte order are explicit below.
 */

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
 * - Explicit byte-order handling for lane input/output
 *
 * Public domain / CC0 - use freely
 */

#include "sha3.h"

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
/* Permutation means a reversible rearrangement/mixing of the entire state.
 * The five named steps below repeat for 24 rounds. state[x + 5*y] is lane
 * (x,y) in a 5-by-5 grid; each lane contains 64 bits. */
static void keccakf(u64 state[25])
{
    int round, i, j;
    u64 t, bc[5];

    for (round = 0; round < 24; round++)
    {

        /* Theta: compute each column parity, then mix neighboring parities
         * into every lane. bc is temporary storage so old values stay available. */
        for (i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];

        for (i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (j = 0; j < 25; j += 5)
                state[j + i] ^= t;
        }

        /* Rho rotates the bits within lanes; Pi moves lanes to new positions.
         * t carries the displaced lane around the fixed permutation cycle. */
        t = state[1];
        for (i = 0; i < 24; i++)
        {
            j = keccakf_piln[i];
            bc[0] = state[j];
            state[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        /* Chi is a nonlinear row operation. Copy the row to bc first, since
         * later assignments need the original neighboring lane values. */
        for (j = 0; j < 25; j += 5)
        {
            for (i = 0; i < 5; i++)
                bc[i] = state[j + i];
            for (i = 0; i < 5; i++)
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota XORs a different round constant into lane 0. */
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
/* sizeof(*ctx) is the size of the entire struct, not the size of its pointer.
 * memset fills those bytes with zero; the state and buffer both start empty. */
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = SHA3_256_BLOCK_SIZE; // 136 bytes
    ctx->hash_len = SHA3_256_HASH_SIZE;
}

/* Absorb data into the sponge */
/* take is the smaller of remaining input and unused block space. Pointer
 * arithmetic moves data forward by bytes because u8 is an 8-bit element type.
 * Retain an incomplete block across calls; permute only when it is full. */
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
/* Load 17 lanes (136 / 8) little-endian: byte j contributes at bit 8*j.
 * The cast to u64 happens before shifting, so shifts up to 56 bits are valid. */
            for (int i = 0; i < 17; i++) // 136/8 = 17
                for (int j = 0; j < 8; j++)
                    ctx->state[i] ^= (u64)ctx->buffer[i * 8 + j] << (8 * j);
            keccakf(ctx->state);
/* The next block must start empty. Leaving old bytes here would XOR
 * the preceding message block into the next one and corrupt the digest. */
            memset(ctx->buffer, 0, ctx->rate);
            ctx->buf_len = 0;
        }
    }
}

/* Final padding and squeeze */
/* 0x06 contains the SHA3 domain-separation bits plus the first padding bit;
 * 0x80 adds the final padding bit. XOR handles both markers in one byte when
 * only one byte of rate space remains. These are SHA3 padding, not AES PKCS7. */
static void sha3_final(sha3_256_ctx *ctx, u8 *out)
{
    /* SHA-3 padding: "01" + zeros + "1" in the domain of 01 for SHA-3 */
    ctx->buffer[ctx->buf_len++] ^= 0x06; // Append 0110
    ctx->buffer[ctx->rate - 1] ^= 0x80;  // Append 1 at the end

    /* Absorb final block */
    for (int i = 0; i < 17; i++)
        for (int j = 0; j < 8; j++)
            ctx->state[i] ^= (u64)ctx->buffer[i * 8 + j] << (8 * j);
    keccakf(ctx->state);

    /* Squeeze out 32 bytes */
/* Extract 32 bytes in little-endian lane order. i / 8 chooses the lane;
 * i % 8 chooses its byte. This works independently of CPU byte order. */
    for (size_t i = 0; i < 32; i++)
        out[i] = (u8)(ctx->state[i / 8] >> (8 * (i % 8)));
}

/* High-level: hash a buffer */
/* A one-shot convenience API: the context lives in this call, so the caller
 * only supplies input bytes and at least 32 writable output bytes. No allocation
 * or ownership transfer occurs. Lengths describe binary data, not C strings. */
void sha3_256(const u8 *input, size_t len, u8 hash[32])
{
    sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_absorb(&ctx, input, len);
    sha3_final(&ctx, hash);
}

/* Hash a string (null-terminated) */
/* strlen stops at the first zero byte. For binary data containing zeros,
 * call sha3_256 with an explicit length instead. */
void sha3_256_string(const char *str, u8 hash[32])
{
    sha3_256((const u8 *)str, strlen(str), hash);
}

/* Hash an entire file */
/* Read fixed-size chunks so memory use does not grow with file size.
 * The 8192-byte I/O chunk need not match the 136-byte cryptographic block:
 * sha3_absorb retains partial blocks internally. Return 0 on success, -1 on error. */
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
