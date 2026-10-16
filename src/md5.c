/*
 * MD5 is a legacy 128-bit hash, included for learning. A hash maps bytes to a
 * fixed-size digest; unlike encryption there is no decrypt operation or secret key.
 * Follow init -> update (one or more chunks) -> final. The context remembers
 * partial 64-byte blocks so chunk boundaries do not change the result.
 * All arithmetic on uint32_t intentionally wraps modulo 2^32.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "md5.h"

// Bit manipulation macros
/* These are preprocessor macros, expanded as source text before compilation.
 * &, |, ^ and ~ operate on individual bits (AND, OR, XOR and NOT).
 * Parentheses prevent an argument expression from changing operator grouping. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// Rotate left macro
/* Rotation differs from shifting: bits leaving the left edge re-enter at
 * the right. These call sites use counts from 1 to 31, avoiding shifts by 32. */
#define ROTLEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Transform round macros
/* Each macro performs one MD5 step: mix the working words with one message
 * word and a fixed constant, rotate, then add b. The four families differ in
 * their bitwise mixing rule. Do not pass arguments with side effects to macros. */
#define FF(a, b, c, d, x, s, ac)              \
    {                                         \
        (a) += F((b), (c), (d)) + (x) + (ac); \
        (a) = ROTLEFT((a), (s));              \
        (a) += (b);                           \
    }

#define GG(a, b, c, d, x, s, ac)              \
    {                                         \
        (a) += G((b), (c), (d)) + (x) + (ac); \
        (a) = ROTLEFT((a), (s));              \
        (a) += (b);                           \
    }

#define HH(a, b, c, d, x, s, ac)              \
    {                                         \
        (a) += H((b), (c), (d)) + (x) + (ac); \
        (a) = ROTLEFT((a), (s));              \
        (a) += (b);                           \
    }

#define II(a, b, c, d, x, s, ac)              \
    {                                         \
        (a) += I((b), (c), (d)) + (x) + (ac); \
        (a) = ROTLEFT((a), (s));              \
        (a) += (b);                           \
    }

// Initialize MD5 context
void md5_init(MD5_CTX *context)
{
    context->count = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

// Update context with more data
void md5_update(MD5_CTX *context, const uint8_t *input, size_t input_len)
{
    size_t i, index, part_len;

    // Compute number of bytes mod 64
/* count stores bits. Shifting right by 3 converts to bytes; masking with
 * 0x3F keeps the low six bits, equivalent to byte_count modulo 64. */
    index = (size_t)((context->count >> 3) & 0x3F);

    // Update number of bits
    context->count += ((uint64_t)input_len << 3);

    part_len = 64 - index;

    // Transform as many times as possible
    if (input_len >= part_len)
    {
        memcpy(&context->buffer[index], input, part_len);
        md5_transform(context, context->buffer);

/* After completing the buffered block, process whole blocks directly from
 * the caller input. &input[i] is the address of element i, not its byte value. */
        for (i = part_len; i + 63 < input_len; i += 64)
            md5_transform(context, &input[i]);

        index = 0;
    }
    else
    {
        i = 0;
    }

    // Buffer remaining input
    memcpy(&context->buffer[index], &input[i], input_len - i);
}

// Finalize MD5 hash
void md5_final(MD5_CTX *context, uint8_t digest[16])
{
    uint8_t bits[8];
    size_t index, pad_len;
    uint64_t count;

    // Save number of bits
/* Remember the original message length: adding padding with md5_update
 * will also change the context counter, but the encoded length must exclude it. */
    count = context->count;

    // Convert to bytes
    bits[0] = (uint8_t)(count & 0xFF);
    bits[1] = (uint8_t)((count >> 8) & 0xFF);
    bits[2] = (uint8_t)((count >> 16) & 0xFF);
    bits[3] = (uint8_t)((count >> 24) & 0xFF);
    bits[4] = (uint8_t)((count >> 32) & 0xFF);
    bits[5] = (uint8_t)((count >> 40) & 0xFF);
    bits[6] = (uint8_t)((count >> 48) & 0xFF);
    bits[7] = (uint8_t)((count >> 56) & 0xFF);

    // Compute index of buffer
    index = (size_t)((context->count >> 3) & 0x3F);
/* Reserve 8 bytes for the original bit length. If there is not enough room
 * in this 64-byte block, pad into a second block (120 = 2*64 - 8). */
    pad_len = (index < 56) ? (56 - index) : (120 - index);

    // Padding
/* 0x80 is binary 10000000: the first padding bit is 1, then zeros.
 * An array initializer with one value automatically zero-initializes the rest. */
    uint8_t padding[64] = {0x80};
    if (pad_len > 1)
        memset(padding + 1, 0, pad_len - 1);

    // Append length
    md5_update(context, padding, pad_len);
    md5_update(context, bits, 8);

    // Store state in digest
    for (int i = 0; i < 4; i++)
    {
        digest[i * 4] = (uint8_t)(context->state[i] & 0xFF);
        digest[i * 4 + 1] = (uint8_t)((context->state[i] >> 8) & 0xFF);
        digest[i * 4 + 2] = (uint8_t)((context->state[i] >> 16) & 0xFF);
        digest[i * 4 + 3] = (uint8_t)((context->state[i] >> 24) & 0xFF);
    }
}

// Core MD5 transformation
void md5_transform(MD5_CTX *context, const uint8_t block[64])
{
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t x[16];

    // Convert block to little-endian 32-bit words
/* MD5 reads little-endian words: the first byte is least significant.
 * Cast before shifting so byte promotion to signed int cannot overflow.
 * Explicit byte assembly avoids depending on the machine native byte order. */
    for (int i = 0; i < 16; i++)
    {
        x[i] = ((uint32_t)block[i * 4]) |
               (((uint32_t)block[i * 4 + 1]) << 8) |
               (((uint32_t)block[i * 4 + 2]) << 16) |
               (((uint32_t)block[i * 4 + 3]) << 24);
    }

    // Round 1: choose bits using b; constants and message order are fixed by MD5.
    FF(a, b, c, d, x[0], 7, 0xd76aa478);
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[2], 17, 0x242070db);
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);
    FF(d, a, b, c, x[5], 12, 0x4787c62a);
    FF(c, d, a, b, x[6], 17, 0xa8304613);
    FF(b, c, d, a, x[7], 22, 0xfd469501);
    FF(a, b, c, d, x[8], 7, 0x698098d8);
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12], 7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);

    // Round 2: a different mixing rule and message-word order spread changes.
    GG(a, b, c, d, x[1], 5, 0xf61e2562);
    GG(d, a, b, c, x[6], 9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[5], 5, 0xd62f105d);
    GG(d, a, b, c, x[10], 9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);
    GG(d, a, b, c, x[14], 9, 0xc33707d6);
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
    GG(c, d, a, b, x[7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    // Round 3: use XOR mixing. These 16 steps are written out for clarity.
    HH(a, b, c, d, x[5], 4, 0xfffa3942);
    HH(d, a, b, c, x[8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[1], 4, 0xa4beea44);
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[6], 23, 0x04881d05);
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);

    // Round 4: the last 16 steps complete the 64-step compression.
    II(a, b, c, d, x[0], 6, 0xf4292244);
    II(d, a, b, c, x[7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[5], 21, 0xfc93a039);
    II(a, b, c, d, x[12], 6, 0x655b59c3);
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[1], 21, 0x85845dd1);
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[4], 6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[9], 21, 0xeb86d391);

    // Update state
/* Feed the working words back into the saved state, linking this block
 * to all previous blocks. This is why update must use the same context. */
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
}

// Calculate MD5 hash of a file
/* Open in binary mode and read bounded chunks rather than loading the
 * whole file. fread returning zero can mean EOF or an error; ferror tells them
 * apart. The caller supplies at least 16 output bytes. No heap ownership is
 * transferred. This routine prints I/O diagnostics and returns -1 on failure. */
int md5_file(const char *filepath, uint8_t *hash)
{
    FILE *file;
    MD5_CTX ctx;
    uint8_t buffer[4096];
    size_t bytes_read;

    // Open file
    file = fopen(filepath, "rb");
    if (!file)
    {
        perror("Error opening file");
        return -1;
    }

    // Initialize MD5 context
    md5_init(&ctx);

    // Read and process file in chunks
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        md5_update(&ctx, buffer, bytes_read);
    }

    // Check for file read errors
    if (ferror(file))
    {
        perror("Error reading file");
        fclose(file);
        return -1;
    }

    // Finalize hash
    md5_final(&ctx, hash);

    // Close file
    fclose(file);

    return 0;
}

/* See src/example.c for a complete, built example using this API. */
