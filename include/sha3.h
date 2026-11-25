/*
 * SHA3-256 streaming and convenience interfaces. #pragma once asks the compiler to process
 * this header only once in a translation unit (one .c file plus its includes).
 * u8/u64 below are local shorthand typedefs, not different integer formats.
 * The caller supplies the 32-byte hash storage; these routines never allocate a
 * result for the caller to free. Void functions assume valid pointers.
 */

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "cryptolib.h"

/* SHA-3 uses 1600-bit state (200 bytes) arranged as 5x5x64-bit words */
typedef uint64_t u64;
typedef uint8_t u8;

#define SHA3_256_HASH_SIZE 32   // 256 bits = 32 bytes
#define SHA3_256_BLOCK_SIZE 136 // 1088 bits = 136 bytes (rate for SHA-3-256)

/* Streaming context, owned by the caller just like MD5_CTX/SHA256_CTX.
 * Fields are implementation state; initialize before use, do not edit them.
 * update can be repeated (NULL data is permitted only for zero length).
 * final writes 32 bytes; cleanup wipes state and accepts NULL. */
typedef struct {
    u64 state[25];
    u8 buffer[144];
    size_t buf_len;
    size_t rate;
    size_t hash_len;
} SHA3_256_CTX;
void sha3_256_init(SHA3_256_CTX *ctx);
void sha3_256_update(SHA3_256_CTX *ctx, const u8 *data, size_t len);
void sha3_256_final(SHA3_256_CTX *ctx, u8 hash[32]);
void sha3_256_cleanup(SHA3_256_CTX *ctx);

/* Hash text up to its first zero byte; that terminator is not included. */
void sha3_256_string(const char *str, u8 hash[32]);
/* Hash a file by path: CRYPTOLIB_SUCCESS or CRYPTOLIB_ERROR_*; hash is unchanged on failure. */
int sha3_256_file(const char *path, u8 hash[32]);
/* Print all 32 bytes as 64 hexadecimal characters followed by a newline. */
void sha3_256_print(const u8 hash[32]);
/* Hash exactly len bytes, including embedded zeros. input may be NULL only
 * when len is zero; hash still needs 32 writable bytes. In a parameter list,
 * hash[32] documents a requirement; C does not allocate or bounds-check it. */
void sha3_256(const u8 *input, size_t len, u8 hash[32]);
