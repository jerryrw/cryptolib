/*
 * Reading this implementation:
 * 1. random_iv/unpad handle operating-system randomness and message padding.
 * 2. The lookup tables and small helpers implement AES's byte transformations.
 * 3. key_expansion prepares the per-round keys; block functions use those keys.
 * 4. Buffer functions add CBC chaining and padding around the block primitive.
 * 5. Stream functions process files; atomic_file owns opening/closing/publishing.
 *
 * C notes: uint8_t is an unsigned 8-bit byte. A pointer parameter gives access to
 * caller-owned storage; it does not carry a buffer length. size_t is an unsigned
 * size/count type. Most helpers are static, meaning other .c files cannot call
 * them by name. API functions return zero on success and negative error codes.
 * No function here authenticates ciphertext; valid padding is not proof of origin.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
/**
 * aes256.c
 *
 * AES-256 Implementation
 * Based on FIPS-197 specification
 */

#include "aes256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif

/* An IV is the starting block for CBC chaining; it is not the encryption key.
 * Platform #if branches are chosen while compiling, not while running.
 * Fail closed means report an error rather than inventing predictable bytes. */
static int random_iv(uint8_t iv[AES_BLOCK_SIZE])
{
#if defined(__APPLE__) || defined(BSD)
    arc4random_buf(iv, AES_BLOCK_SIZE);
    return AES_SUCCESS;
#else
#if defined(__linux__)
    size_t offset = 0;
    while (offset < AES_BLOCK_SIZE)
    {
/* getrandom may return fewer bytes than requested. ssize_t is signed so
 * negative error returns can be distinguished from nonnegative byte counts. */
        ssize_t n = getrandom(iv + offset, AES_BLOCK_SIZE - offset, 0);
/* A signal can interrupt a system call. Retry without advancing the offset. */
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        offset += (size_t)n;
    }
    if (offset == AES_BLOCK_SIZE)
        return AES_SUCCESS;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return AES_ERROR_RANDOM;
/* fread returns items read; item size is 1 here, so the result is bytes.
 * Check read and close errors separately so fclose always executes. */
    size_t n = fread(iv, 1, AES_BLOCK_SIZE, f);
    int failed = ferror(f);
    int close_result = fclose(f);
    return n == AES_BLOCK_SIZE && !failed && close_result == 0
        ? AES_SUCCESS : AES_ERROR_RANDOM;
#endif
}

/* Validate the complete final PKCS7 block before exposing a length. */
static int unpad(const uint8_t *data, size_t len, size_t *plain_len)
{
    if (len < AES_BLOCK_SIZE || len % AES_BLOCK_SIZE != 0)
        return AES_ERROR_INVALID_PARAM;
/* PKCS7 appends N copies of byte N. For example, three padding bytes are
 * 03 03 03. Even a whole-block plaintext gets a full block of padding. */
    uint8_t padding = data[len - 1];
    if (padding == 0 || padding > AES_BLOCK_SIZE)
        return AES_ERROR_INVALID_PARAM;
/* Check every required padding byte, not just the last one. In C a comparison
 * is 0 or 1; multiplication masks out positions outside the padding. OR (|=)
 * remembers any mismatch. This does not make the overall implementation
 * a constant-time or authenticated encryption implementation. */
    unsigned int invalid = 0;
    for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
        invalid |= (i < padding) * (data[len - 1 - i] ^ padding);
    if (invalid)
        return AES_ERROR_INVALID_PARAM;
    *plain_len = len - padding;
    return AES_SUCCESS;
}

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
/* The highest bit tells us whether shifting needs reduction by the AES
 * polynomial. XOR (^) acts as addition in this field; it is not exponentiation.
 * This macro is for simple byte expressions: macro arguments may be evaluated
 * more than once, so do not pass expressions with side effects such as i++. */
#define xtime(x) ((uint8_t)((((uint8_t)(x)) << 1) ^ ((((uint8_t)(x)) >> 7) & 1 ? 0x1b : 0x00)))

/* Internal helper functions */

/**
 * Perform SubBytes transformation
 * Substitutes each byte in the state with a byte from the S-box
 */
/* The 16-byte state represents a 4-by-4 matrix stored by columns:
 * indices 0,1,2,3 are column 0, and 4,5,6,7 are column 1. Thus one row
 * appears at offsets 0,4,8,12 rather than as four adjacent bytes. */
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
/* Each new column combines all four old column bytes. temp keeps writes
 * from overwriting a byte that a later calculation still needs. Multiplication
 * by 3 is multiplication by 2 XOR the original byte in AES arithmetic. */
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
/* This is shift-and-add multiplication over GF(2^8), not ordinary integers.
 * Inspect one multiplier bit per iteration. A left shift that drops the high
 * bit requires polynomial reduction (XOR with 0x1b). */
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
/* A word here means four bytes. AES-256 starts with 8 words and derives
 * 60 total: 15 round keys of 16 bytes, including the initial key addition.
 * Pointer + N advances by N elements; these uint8_t pointers advance in bytes. */
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

/* ctx belongs to the caller; we fill it rather than allocating it. key must
 * point to 32 readable bytes. An explicit IV needs 16 bytes; NULL requests
 * OS randomness. If randomness fails, erase the already-expanded key. */
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
        if (random_iv(ctx->iv) != AES_SUCCESS)
        {
            aes256_cleanup(ctx);
            return AES_ERROR_RANDOM;
        }
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

/* This primitive handles exactly 16 bytes and never pads them. Copying input
 * into a local array allows input and output to be the very same allocation.
 * Local state is modified round by round; the context key schedule is read-only. */
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

/* Undo the encryption transformations in reverse round order. Decryption
 * starts with the last expanded key and ends with the first one. */
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

/* Compute padding before allocation. size_t arithmetic wraps on overflow,
 * so check input_len > SIZE_MAX - padding before adding. *required writes
 * through a pointer to return a second value in addition to the status code. */
int aes256_encrypted_size(size_t input_len, size_t *required)
{
    if (!required)
        return AES_ERROR_INVALID_PARAM;
    *required = 0;
    size_t padding = AES_BLOCK_SIZE - input_len % AES_BLOCK_SIZE;
    if (input_len > SIZE_MAX - padding)
        return AES_ERROR_INVALID_PARAM;
    *required = input_len + padding;
    return AES_SUCCESS;
}

/* Compatibility entry points cannot check the caller's actual allocation. */
int aes256_encrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len)
{
    size_t capacity = 0;
    if (output_len) *output_len = 0;
    if (aes256_encrypted_size(input_len, &capacity) != AES_SUCCESS)
        return AES_ERROR_INVALID_PARAM;
    return aes256_encrypt_buffer_checked(ctx, input, input_len, output, capacity, output_len);
}

int aes256_decrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len)
{
    return aes256_decrypt_buffer_checked(ctx, input, input_len, output, input_len, output_len);
}

/* output_capacity is the size the caller actually allocated, while
 * *output_len is the size this call produced. Reset the latter before validation
 * so a failed operation cannot leave a misleading previous length behind. */
int aes256_encrypt_buffer_checked(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len)
{
    if (!output_len)
        return AES_ERROR_INVALID_PARAM;
    *output_len = 0;
    if (!ctx || (!input && input_len != 0) || !output)
        return AES_ERROR_INVALID_PARAM;
    size_t padded_len;
    if (aes256_encrypted_size(input_len, &padded_len) != AES_SUCCESS)
        return AES_ERROR_INVALID_PARAM;
    if (output_capacity < padded_len)
        return AES_ERROR_BUFFER_TOO_SMALL;
    size_t padding = padded_len - input_len;
    *output_len = padded_len;

/* CBC uses C[i] = AES(P[i] XOR C[i-1]), treating the IV as C[-1].
 * Use a local chaining value so the context IV remains unchanged. */
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

/* CBC decryption is P[i] = AES_inverse(C[i]) XOR C[i-1].
 * Save the ciphertext before writing plaintext so exact in-place calls work.
 * Capacity must cover complete ciphertext blocks, even though unpadding will
 * report a shorter plaintext. Invalid padding clears the produced bytes. */
int aes256_decrypt_buffer_checked(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len)
{
    if (!output_len)
        return AES_ERROR_INVALID_PARAM;
    *output_len = 0;
    if (!ctx || !input || !output || input_len == 0 || input_len % AES_BLOCK_SIZE != 0)
        return AES_ERROR_INVALID_PARAM;
    /* Decryption writes complete blocks before checking their padding. */
    if (output_capacity < input_len)
        return AES_ERROR_BUFFER_TOO_SMALL;

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
    int result = unpad(output, input_len, output_len);
    if (result != AES_SUCCESS)
        aes256_secure_zero(output, input_len);
    return result;
}

/* Stream into a private temporary file; only the wrapper publishes it. */
/* fread asks for one AES block at a time. A short final read gets padding;
 * when the file ends on a block boundary, the next read returns zero and we
 * write a full padding block. FILE buffering avoids a system call per byte. */
static int encrypt_stream(aes256_context *ctx, FILE *fin, FILE *fout)
{
    uint8_t iv[AES_BLOCK_SIZE], block[AES_BLOCK_SIZE], encrypted[AES_BLOCK_SIZE];
    memcpy(iv, ctx->iv, sizeof(iv));
    int result = AES_SUCCESS;
    if (fwrite(iv, 1, sizeof(iv), fout) != sizeof(iv))
        result = AES_ERROR_FILE_WRITE;
    while (result == AES_SUCCESS)
    {
        size_t n = fread(block, 1, sizeof(block), fin);
        if (ferror(fin)) { result = AES_ERROR_FILE_READ; break; }
        if (n < sizeof(block))
            memset(block + n, (int)(sizeof(block) - n), sizeof(block) - n);
        for (size_t i = 0; i < sizeof(block); i++) block[i] ^= iv[i];
        aes256_encrypt_block(ctx, block, encrypted);
        if (fwrite(encrypted, 1, sizeof(encrypted), fout) != sizeof(encrypted))
            result = AES_ERROR_FILE_WRITE;
        memcpy(iv, encrypted, sizeof(iv));
        if (n < sizeof(block)) break;
    }
    aes256_secure_zero(block, sizeof(block));
    aes256_secure_zero(iv, sizeof(iv));
    return result;
}

/* Keep one ciphertext block in reserve. Looking ahead tells us whether the
 * current block is the last one, whose padding must be removed before writing.
 * Memory usage stays fixed even for a very large file. */
static int decrypt_stream(aes256_context *ctx, FILE *fin, FILE *fout)
{
    uint8_t iv[AES_BLOCK_SIZE], block[AES_BLOCK_SIZE], next[AES_BLOCK_SIZE];
    uint8_t plain[AES_BLOCK_SIZE];
    int result = AES_ERROR_FILE_READ;
    if (fread(iv, 1, sizeof(iv), fin) != sizeof(iv)) goto cleanup;
    size_t n = fread(block, 1, sizeof(block), fin);
    if (ferror(fin)) goto cleanup;
    result = AES_ERROR_INVALID_PARAM;
    if (n != sizeof(block)) goto cleanup;
    for (;;)
    {
        n = fread(next, 1, sizeof(next), fin);
        if (ferror(fin)) { result = AES_ERROR_FILE_READ; break; }
        if (n != 0 && n != sizeof(next)) { result = AES_ERROR_INVALID_PARAM; break; }
        aes256_decrypt_block(ctx, block, plain);
        for (size_t i = 0; i < sizeof(plain); i++) plain[i] ^= iv[i];
        size_t write_len = sizeof(plain);
        if (n == 0)
        {
            result = unpad(plain, sizeof(plain), &write_len);
            if (result != AES_SUCCESS) break;
        }
        if (fwrite(plain, 1, write_len, fout) != write_len)
        { result = AES_ERROR_FILE_WRITE; break; }
        if (n == 0) { result = AES_SUCCESS; break; }
        memcpy(iv, block, sizeof(iv));
        memcpy(block, next, sizeof(block));
    }
cleanup:
    aes256_secure_zero(plain, sizeof(plain));
    aes256_secure_zero(iv, sizeof(iv));
    return result;
}

/* transform is a function pointer: the wrapper calls either encrypt_stream
 * or decrypt_stream with the same (context, input stream, output stream) shape.
 * This centralizes resource ownership and error cleanup for both operations.
 * A stream (FILE *) buffers I/O; its underlying descriptor is an integer. */
static int atomic_file(aes256_context *ctx, const char *input_file,
                       const char *output_file,
                       int (*transform)(aes256_context *, FILE *, FILE *))
{
    if (!ctx || !input_file || !output_file || !*output_file)
        return AES_ERROR_INVALID_PARAM;
    size_t len = strlen(output_file);
/* sizeof includes the terminating zero byte in this array. Appending the
 * suffix beside the destination puts the temporary file on the same filesystem,
 * which is required for rename-based atomic replacement. */
    const char suffix[] = ".tmp.XXXXXX";
    if (len > SIZE_MAX - sizeof(suffix)) return AES_ERROR_INVALID_PARAM;
    char *temporary = malloc(len + sizeof(suffix));
    if (!temporary) return AES_ERROR_MEMORY;
    memcpy(temporary, output_file, len);
    memcpy(temporary + len, suffix, sizeof(suffix));
    FILE *fin = fopen(input_file, "rb"), *fout = NULL;
    int result = AES_ERROR_FILE_OPEN;
    if (!fin) goto cleanup;
    /* Same-directory creation keeps rename atomic and restricts access to 0600. */
    int fd = mkstemp(temporary);
    if (fd < 0) goto cleanup;
/* mkstemp replaces XXXXXX with a unique name and opens the new file.
 * fdopen wraps that descriptor without opening another file. On success,
 * fclose(fout) owns closing fd; on failure, we must close fd ourselves. */
    fout = fdopen(fd, "wb");
    if (!fout)
    {
        close(fd);
        unlink(temporary);
        goto cleanup;
    }
    result = transform(ctx, fin, fout);
    if (fclose(fin) != 0 && result == AES_SUCCESS) result = AES_ERROR_FILE_READ;
    fin = NULL;
/* fflush drains C library buffers; fsync asks the OS to persist file data.
 * Do both before renaming. Short-circuit && avoids committing a failed transform.
 * Even on failure, fclose must still run to release the stream and descriptor. */
    if (result == AES_SUCCESS && (fflush(fout) != 0 || fsync(fileno(fout)) != 0))
        result = AES_ERROR_FILE_WRITE;
    if (fclose(fout) != 0 && result == AES_SUCCESS) result = AES_ERROR_FILE_WRITE;
    fout = NULL;
    if (result == AES_SUCCESS && rename(temporary, output_file) != 0)
        result = AES_ERROR_FILE_WRITE;
    if (result != AES_SUCCESS) unlink(temporary);
/* All branches converge here. NULL means a resource was never acquired
 * or has already been released, which prevents closing a stream twice. */
cleanup:
    if (fin) fclose(fin);
    free(temporary);
    return result;
}

int aes256_encrypt_file(aes256_context *ctx, const char *input_file, const char *output_file)
{
    return atomic_file(ctx, input_file, output_file, encrypt_stream);
}

int aes256_decrypt_file(aes256_context *ctx, const char *input_file, const char *output_file)
{
    return atomic_file(ctx, input_file, output_file, decrypt_stream);
}

/* An ordinary memset of dead data may be removed by an optimizing compiler.
 * Writing through a volatile-qualified pointer makes these byte writes observable
 * to the compiler. It does not erase other copies or memory already freed. */
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