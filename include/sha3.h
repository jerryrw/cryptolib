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

/* Hash a string (null-terminated) */
void sha3_256_string(const char *str, u8 hash[32]);
/* Hash an entire file */
int sha3_256_file(const char *path, u8 hash[32]);
/* Utility: print hash in hex */
void sha3_256_print(const u8 hash[32]);
/* High-level: hash a buffer */
void sha3_256(const u8 *input, size_t len, u8 hash[32]);
