/*
 * SHA3-256 convenience interface. #pragma once asks the compiler to process
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

/* SHA-3 uses 1600-bit state (200 bytes) arranged as 5x5x64-bit words */
typedef uint64_t u64;
typedef uint8_t u8;

#define SHA3_256_HASH_SIZE 32   // 256 bits = 32 bytes
#define SHA3_256_BLOCK_SIZE 136 // 1088 bits = 136 bytes (rate for SHA-3-256)

/* Hash text up to its first zero byte; that terminator is not included. */
void sha3_256_string(const char *str, u8 hash[32]);
/* Hash a file by path: 0 on success, -1 on open/read failure. */
int sha3_256_file(const char *path, u8 hash[32]);
/* Print all 32 bytes as 64 hexadecimal characters followed by a newline. */
void sha3_256_print(const u8 hash[32]);
/* Hash exactly len bytes, including embedded zeros. input may be NULL only
 * when len is zero; hash still needs 32 writable bytes. In a parameter list,
 * hash[32] documents a requirement; C does not allocate or bounds-check it. */
void sha3_256(const u8 *input, size_t len, u8 hash[32]);
