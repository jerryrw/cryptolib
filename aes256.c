/**
 * aes256.c
 *
 * AES-256 Implementation
 * Based on FIPS-197 specification
 */

#include "include/aes256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
<<<<<<< HEAD
//#include <Availability.h>
//#include <TargetConditionals.h>
=======
// #include <Availability.h>
// #include <TargetConditionals.h>
>>>>>>> cd80082118bd7178677e642f02a345df8504120d
#include <sys/random.h>
#include <stdlib.h>
#include <time.h>

/* AES S-Box (Substitution Box) - used in SubBytes transformation */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/* Inverse S-Box - used in InvSubBytes transformation for decryption */
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

/* Round constant (Rcon) - used in key expansion */
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/* Galois Field (2^8) multiplication by 2 - used in MixColumns */
/* cast and parenthesis to avoid promotion surprises */
#define xtime(x) ((uint8_t)((((uint8_t)(x)) << 1) ^ ((((uint8_t)(x)) >> 7) & 1 ? 0x1b : 0x00)))

/* Internal helper functions */

/**
 * Perform SubBytes transformation
 * Substitutes each byte in the state with a byte from the S-box
 */
static void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = sbox[state[i]];
    }
}

/**
 * Perform InvSubBytes transformation
 * Substitutes each byte in the state with a byte from the inverse S-box
 */
static void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] = inv_sbox[state[i]];
    }
}

/**
 * Perform ShiftRows transformation
 * Cyclically shifts the rows of the state
 * Row 0: no shift, Row 1: 1 byte left, Row 2: 2 bytes left, Row 3: 3 bytes left
 */
static void shift_rows(uint8_t *state)
{
    uint8_t temp;

    /* Row 1: shift left by 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    /* Row 2: shift left by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift left by 3 */
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

/**
 * Perform InvShiftRows transformation
 * Inverse of ShiftRows - shifts rows to the right
 */
static void inv_shift_rows(uint8_t *state)
{
    uint8_t temp;

    /* Row 1: shift right by 1 */
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    /* Row 2: shift right by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift right by 3 */
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

/**
 * Perform MixColumns transformation
 * Operates on columns of the state, treating each column as a polynomial
 */
static void mix_columns(uint8_t *state)
{
    uint8_t temp[16];

    for (int i = 0; i < 4; i++)
    {
        int col = i * 4;
        temp[col] = xtime(state[col]) ^ xtime(state[col + 1]) ^ state[col + 1] ^
                    state[col + 2] ^ state[col + 3];
        temp[col + 1] = state[col] ^ xtime(state[col + 1]) ^ xtime(state[col + 2]) ^
                        state[col + 2] ^ state[col + 3];
        temp[col + 2] = state[col] ^ state[col + 1] ^ xtime(state[col + 2]) ^
                        xtime(state[col + 3]) ^ state[col + 3];
        temp[col + 3] = xtime(state[col]) ^ state[col] ^ state[col + 1] ^
                        state[col + 2] ^ xtime(state[col + 3]);
    }

    memcpy(state, temp, 16);
}

/**
 * Galois Field multiplication - used in InvMixColumns
 */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;
        uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/**
 * Perform InvMixColumns transformation
 * Inverse of MixColumns
 */
static void inv_mix_columns(uint8_t *state)
{
    uint8_t temp[16];

    for (int i = 0; i < 4; i++)
    {
        int col = i * 4;
        temp[col] = gf_mul(state[col], 0x0e) ^ gf_mul(state[col + 1], 0x0b) ^
                    gf_mul(state[col + 2], 0x0d) ^ gf_mul(state[col + 3], 0x09);
        temp[col + 1] = gf_mul(state[col], 0x09) ^ gf_mul(state[col + 1], 0x0e) ^
                        gf_mul(state[col + 2], 0x0b) ^ gf_mul(state[col + 3], 0x0d);
        temp[col + 2] = gf_mul(state[col], 0x0d) ^ gf_mul(state[col + 1], 0x09) ^
                        gf_mul(state[col + 2], 0x0e) ^ gf_mul(state[col + 3], 0x0b);
        temp[col + 3] = gf_mul(state[col], 0x0b) ^ gf_mul(state[col + 1], 0x0d) ^
                        gf_mul(state[col + 2], 0x09) ^ gf_mul(state[col + 3], 0x0e);
    }

    memcpy(state, temp, 16);
}

/**
 * XOR state with round key
 */
static void add_round_key(uint8_t *state, const uint8_t *round_key)
{
    for (int i = 0; i < 16; i++)
    {
        state[i] ^= round_key[i];
    }
}

/**
 * Key expansion - generates round keys from the cipher key
 * AES-256 uses 60 words (240 bytes) for the key schedule
 */
static void key_expansion(const uint8_t *key, uint8_t *round_keys)
{
    uint8_t temp[4];
    int i = 0;

    /* First 8 words (32 bytes) are the cipher key */
    memcpy(round_keys, key, 32);
    i = 8;

    /* Generate remaining 52 words */
    while (i < 60)
    {
        /* Get the last 4 bytes */
        memcpy(temp, round_keys + (i - 1) * 4, 4);

        if (i % 8 == 0)
        {
            /* RotWord: rotate left by 1 byte */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubWord: apply S-box */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            /* XOR with round constant */
            temp[0] ^= rcon[i / 8];
        }
        else if (i % 8 == 4)
        {
            /* Additional SubWord for AES-256 */
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        /* XOR with word 8 positions earlier */
        for (int j = 0; j < 4; j++)
        {
            round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

/* Public API Implementation */

int aes256_init(aes256_context *ctx, const uint8_t *key, const uint8_t *iv)
{
    if (!ctx || !key)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    /* Expand the key */
    key_expansion(key, ctx->round_keys);

    /* Store IV if provided; otherwise generate a secure random IV */
    if (iv)
    {
        memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    }
    else
    {
#if defined(__APPLE__) || defined(BSD)
        /* arc4random_buf is available on macOS and recent BSDs */
        arc4random_buf(ctx->iv, AES_BLOCK_SIZE);
#else
        /* fall back to getrandom or /dev/urandom */
        if (getrandom(ctx->iv, AES_BLOCK_SIZE, 0) != AES_BLOCK_SIZE)
        {
            /* last resort: /dev/urandom */
            FILE *f = fopen("/dev/urandom", "rb");
            if (f)
            {
                fread(ctx->iv, 1, AES_BLOCK_SIZE, f);
                fclose(f);
            }
            else
            {
                /* as a final fallback zero (but this should not happen in normal environments) */
                memset(ctx->iv, 0, AES_BLOCK_SIZE);
            }
        }
#endif
    }

    return AES_SUCCESS;
}

/* Securely wipe context key material */
void aes256_cleanup(aes256_context *ctx)
{
    if (!ctx)
        return;
    aes256_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
    aes256_secure_zero(ctx->iv, sizeof(ctx->iv));
}

int aes256_encrypt_block(const aes256_context *ctx, const uint8_t *input, uint8_t *output)
{
    if (!ctx || !input || !output)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    uint8_t state[16];
    memcpy(state, input, 16);

    /* Initial round key addition */
    add_round_key(state, ctx->round_keys);

    /* Main rounds (13 rounds for AES-256) */
    for (int round = 1; round < AES_ROUNDS; round++)
    {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, ctx->round_keys + round * 16);
    }

    /* Final round (no MixColumns) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, ctx->round_keys + AES_ROUNDS * 16);

    memcpy(output, state, 16);
    return AES_SUCCESS;
}

int aes256_decrypt_block(const aes256_context *ctx, const uint8_t *input, uint8_t *output)
{
    if (!ctx || !input || !output)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    uint8_t state[16];
    memcpy(state, input, 16);

    /* Initial round key addition */
    add_round_key(state, ctx->round_keys + AES_ROUNDS * 16);

    /* Main rounds (13 rounds for AES-256) */
    for (int round = AES_ROUNDS - 1; round > 0; round--)
    {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, ctx->round_keys + round * 16);
        inv_mix_columns(state);
    }

    /* Final round (no InvMixColumns) */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, ctx->round_keys);

    memcpy(output, state, 16);
    return AES_SUCCESS;
}

int aes256_encrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len)
{
    if (!ctx || !input || !output || !output_len)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    /* Calculate padding length (PKCS7) */
    size_t padding = AES_BLOCK_SIZE - (input_len % AES_BLOCK_SIZE);
    size_t padded_len = input_len + padding;
    *output_len = padded_len;

    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, ctx->iv, AES_BLOCK_SIZE);

    /* Encrypt blocks using CBC mode */
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
    {
        uint8_t block[AES_BLOCK_SIZE];
        size_t block_len = (i + AES_BLOCK_SIZE <= input_len) ? AES_BLOCK_SIZE : (input_len - i);

        /* Copy and pad if necessary */
        memcpy(block, input + i, block_len);
        if (block_len < AES_BLOCK_SIZE)
        {
            memset(block + block_len, (uint8_t)padding, padding);
        }

        /* XOR with IV (CBC mode) */
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
        {
            block[j] ^= iv[j];
        }

        /* Encrypt block */
        aes256_encrypt_block(ctx, block, output + i);

        /* Update IV for next block */
        memcpy(iv, output + i, AES_BLOCK_SIZE);
    }

    /* Handle padding block if input was exact multiple of block size */
    if (input_len % AES_BLOCK_SIZE == 0)
    {
        uint8_t padding_block[AES_BLOCK_SIZE];
        memset(padding_block, (uint8_t)AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        for (int j = 0; j < AES_BLOCK_SIZE; j++)
        {
            padding_block[j] ^= iv[j];
        }

        aes256_encrypt_block(ctx, padding_block, output + input_len);
    }

    return AES_SUCCESS;
}

int aes256_decrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len)
{
    if (!ctx || !input || !output || !output_len)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    if (input_len % AES_BLOCK_SIZE != 0)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, ctx->iv, AES_BLOCK_SIZE);

    /* Decrypt blocks using CBC mode */
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE)
    {
        uint8_t next_iv[AES_BLOCK_SIZE];
        memcpy(next_iv, input + i, AES_BLOCK_SIZE);

        /* Decrypt block */
        aes256_decrypt_block(ctx, input + i, output + i);

        /* XOR with IV (CBC mode) */
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
        {
            output[i + j] ^= iv[j];
        }

        /* Update IV for next block */
        memcpy(iv, next_iv, AES_BLOCK_SIZE);
    }

    /* Remove PKCS7 padding */
    uint8_t padding = output[input_len - 1];
    if (padding > 0 && padding <= AES_BLOCK_SIZE)
    {
        *output_len = input_len - padding;
    }
    else
    {
        *output_len = input_len;
    }

    return AES_SUCCESS;
}

int aes256_decrypt_file(aes256_context *ctx, const char *input_file, const char *output_file)
{
    if (!ctx || !input_file || !output_file)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    FILE *fin = fopen(input_file, "rb");
    if (!fin)
    {
        return AES_ERROR_FILE_OPEN;
    }

    FILE *fout = fopen(output_file, "wb");
    if (!fout)
    {
        fclose(fin);
        return AES_ERROR_FILE_OPEN;
    }

    /* Read IV from input file */
    uint8_t iv[AES_BLOCK_SIZE];
    if (fread(iv, 1, AES_BLOCK_SIZE, fin) != AES_BLOCK_SIZE)
    {
        fclose(fin);
        fclose(fout);
        return AES_ERROR_FILE_READ;
    }

    uint8_t buffer[4096];
    uint8_t decrypted[4096];
    uint8_t prev_block[4096];
    size_t prev_bytes = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fin)) > 0)
    {
        /* Decrypt blocks */
        for (size_t i = 0; i < bytes_read; i += AES_BLOCK_SIZE)
        {
            uint8_t next_iv[AES_BLOCK_SIZE];
            memcpy(next_iv, buffer + i, AES_BLOCK_SIZE);

            aes256_decrypt_block(ctx, buffer + i, decrypted + i);

            /* XOR with IV */
            for (int j = 0; j < AES_BLOCK_SIZE; j++)
            {
                decrypted[i + j] ^= iv[j];
            }

            memcpy(iv, next_iv, AES_BLOCK_SIZE);
        }

        /* Write previous block if any (to handle padding) */
        if (prev_bytes > 0)
        {
            if (fwrite(prev_block, 1, prev_bytes, fout) != prev_bytes)
            {
                fclose(fin);
                fclose(fout);
                return AES_ERROR_FILE_WRITE;
            }
        }

        /* Store current block for next iteration */
        memcpy(prev_block, decrypted, bytes_read);
        prev_bytes = bytes_read;
    }

    /* Handle last block with padding removal */
    if (prev_bytes > 0)
    {
        uint8_t padding = prev_block[prev_bytes - 1];
        if (padding > 0 && padding <= AES_BLOCK_SIZE)
        {
            prev_bytes -= padding;
        }

        if (fwrite(prev_block, 1, prev_bytes, fout) != prev_bytes)
        {
            fclose(fin);
            fclose(fout);
            return AES_ERROR_FILE_WRITE;
        }
    }

    fclose(fin);
    fclose(fout);
    return AES_SUCCESS;
}

int aes256_encrypt_file(aes256_context *ctx, const char *input_file, const char *output_file)
{
    if (!ctx || !input_file || !output_file)
    {
        return AES_ERROR_INVALID_PARAM;
    }

    FILE *fin = fopen(input_file, "rb");
    if (!fin)
    {
        return AES_ERROR_FILE_OPEN;
    }

    FILE *fout = fopen(output_file, "wb");
    if (!fout)
    {
        fclose(fin);
        return AES_ERROR_FILE_OPEN;
    }

    /* Write IV to output file */
    if (fwrite(ctx->iv, 1, AES_BLOCK_SIZE, fout) != AES_BLOCK_SIZE)
    {
        fclose(fin);
        fclose(fout);
        return AES_ERROR_FILE_WRITE;
    }

    uint8_t iv[AES_BLOCK_SIZE];
    memcpy(iv, ctx->iv, AES_BLOCK_SIZE);

    uint8_t inbuf[4096];
    uint8_t outbuf[4096 + AES_BLOCK_SIZE]; /* room for pad block if needed */
    size_t tail_len = 0;
    uint8_t tail[AES_BLOCK_SIZE];

    while (1)
    {
        size_t n = fread(inbuf, 1, sizeof(inbuf) - tail_len, fin);
        if (n == 0 && feof(fin))
            break;
        if (ferror(fin))
        {
            fclose(fin);
            fclose(fout);
            return AES_ERROR_FILE_READ;
        }

        /* total available bytes = tail_len + n */
        size_t total = tail_len + n;
        /* copy new data after any tail */
        if (tail_len)
            memcpy(inbuf, tail, tail_len); /* move previous tail to front */
        /* Now process all full blocks except keep last partial (tail) */
        size_t process_up_to = (total / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        size_t processed = 0;
        while (processed < process_up_to)
        {
            uint8_t block[AES_BLOCK_SIZE];
            memcpy(block, inbuf + processed, AES_BLOCK_SIZE);
            /* XOR with IV */
            for (int j = 0; j < AES_BLOCK_SIZE; j++)
                block[j] ^= iv[j];
            aes256_encrypt_block(ctx, block, outbuf + processed);
            memcpy(iv, outbuf + processed, AES_BLOCK_SIZE);
            processed += AES_BLOCK_SIZE;
        }

        /* write processed bytes */
        if (process_up_to > 0)
        {
            if (fwrite(outbuf, 1, process_up_to, fout) != process_up_to)
            {
                fclose(fin);
                fclose(fout);
                return AES_ERROR_FILE_WRITE;
            }
        }

        /* store tail (remaining bytes) */
        tail_len = total - process_up_to;
        if (tail_len)
        {
            memcpy(tail, inbuf + process_up_to, tail_len);
        }

        /* if EOF reached break to pad tail */
        if (feof(fin))
            break;
    }

    /* pad tail and encrypt final block(s) */
    size_t padding = AES_BLOCK_SIZE - (tail_len % AES_BLOCK_SIZE);
    /* if tail_len == 0 then we'll create a full padding block (16 bytes = 0x10) */
    uint8_t final_block[AES_BLOCK_SIZE];
    if (tail_len > 0)
        memcpy(final_block, tail, tail_len);
    memset(final_block + tail_len, (uint8_t)padding, padding);

    /* XOR with IV and encrypt final block */
    for (int j = 0; j < AES_BLOCK_SIZE; j++)
        final_block[j] ^= iv[j];
    aes256_encrypt_block(ctx, final_block, outbuf);

    if (fwrite(outbuf, 1, AES_BLOCK_SIZE, fout) != AES_BLOCK_SIZE)
    {
        fclose(fin);
        fclose(fout);
        return AES_ERROR_FILE_WRITE;
    }

    fclose(fin);
    fclose(fout);
    return AES_SUCCESS;
}

void aes256_secure_zero(void *ptr, size_t len)
{
    if (!ptr)
        return;

    /* Volatile to prevent compiler optimization */
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}

void aes256_print_hex(const char *label, const uint8_t *data, size_t len)
{
    if (label)
    {
        printf("%s: ", label);
    }

    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i != len - 1)
        {
            printf("\n");
            if (label)
            {
                for (size_t j = 0; j < strlen(label) + 2; j++)
                {
                    printf(" ");
                }
            }
        }
    }
    printf("\n");
}