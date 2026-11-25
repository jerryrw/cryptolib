/*
 * MD5 streaming interface (legacy educational algorithm).
 * Declare MD5_CTX ctx; call md5_init(&ctx), then md5_update for each input chunk,
 * then md5_final(&ctx, digest). digest must have at least 16 writable bytes.
 * Pointers must be valid for the stated byte lengths; these void functions do not
 * return validation errors. Reinitialize the context before hashing a new message.
 * #include <stdint.h> supplies fixed-width integers; <stddef.h> supplies size_t.
 */

#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>
#include "cryptolib.h"

// MD5 context structure
typedef struct
{
    uint32_t state[4]; /* Four running words; final digest is their byte encoding. */
    uint64_t count;    /* Total input length in bits, including updates during final. */
    uint8_t buffer[64]; /* An unfinished 64-byte compression block. */
} MD5_CTX;

/* Wipe a caller-owned context; NULL is accepted. Reinitialize before reuse. */
void md5_cleanup(MD5_CTX *ctx);

// Function prototypes
void md5_init(MD5_CTX *context);
/* input_len counts bytes, including embedded zeros. Zero length permits NULL input. const means the function
 * may read input but must not modify its bytes through this pointer. */
void md5_update(MD5_CTX *context, const uint8_t *input, size_t input_len);
void md5_final(MD5_CTX *context, uint8_t digest[16]);
/* Low-level compression helper: reads exactly 64 bytes. Normal callers use
 * update, which assembles whole blocks and maintains the message-length counter. */
void md5_transform(MD5_CTX *context, const uint8_t block[64]);
/* Open a path, hash the file, and close it internally. Return 0 on success
 * or a CRYPTOLIB_ERROR_* status on failure. The caller supplies 16 output bytes.
 * No diagnostics are printed; output is unchanged on failure. */
int md5_file(const char *filepath, uint8_t *hash);

#endif