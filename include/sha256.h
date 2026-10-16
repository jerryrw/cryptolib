/*
 * SHA-256 streaming interface. A context remembers input between calls:
 * sha256_init(&ctx); sha256_update(&ctx, bytes, length); sha256_final(&ctx, hash);
 * update may be repeated; final must run once after all message bytes arrive.
 * hash needs at least 32 writable bytes. Reinitialize before a new message.
 * These low-level void functions expect valid pointers and do not report invalid
 * arguments. The caller owns every input/output buffer and the context itself.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

// SHA-256 context structure
typedef struct
{
    uint8_t data[64]; /* Partial block, filled until it reaches 64 bytes. */
    uint32_t datalen; /* Number of bytes currently buffered, normally 0..63. */
    unsigned long long bitlen; /* Bits compressed so far; final adds pending bytes. */
    uint32_t state[8]; /* Eight 32-bit running words: 8 * 4 = 32 digest bytes. */
} SHA256_CTX;

// Function prototypes
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);
/* Compression consumes exactly one 64-byte block. Prefer update for normal
 * use because it handles incomplete input and length accounting for you. */
void sha256_transform(SHA256_CTX *ctx, const uint8_t *data);
/* Return 0 on success, -1 on I/O failure. The implementation opens/closes
 * the stream, prints I/O diagnostics on failure, and writes hash on success. */
int sha256_file(const char *filepath, uint8_t *hash);

#endif