/*
 * Public AES interface: this header describes how callers use src/aes256.c.
 * An include guard (#ifndef/#define/#endif) prevents duplicate type definitions
 * when several headers include this one. Including a header supplies declarations;
 * the linker still needs the compiled implementation to supply function bodies.
 *
 * Pointers carry addresses, not allocation sizes. The key, IV, block and output
 * sizes below are requirements the caller must satisfy. Prefer checked buffer APIs
 * for variable-length data; a status return of zero means success.
 */

/**
 * aes256.h
 *
 * AES-256 Encryption/Decryption Implementation
 * Pure C implementation with no external dependencies
 * Compatible with macOS ARM (Apple Silicon M series)
 *
 * This implementation follows FIPS-197 specification for AES
 * Block size: 128 bits (16 bytes)
 * Key size: 256 bits (32 bytes)
 * Number of rounds: 14
 */

#ifndef AES256_H
#define AES256_H

#include <stdint.h>
#include <stddef.h>

/* AES-256 Constants */
#define AES_BLOCK_SIZE 16         /* 128 bits */
#define AES_KEY_SIZE 32           /* 256 bits */
#define AES_ROUNDS 14             /* Number of rounds for AES-256 */
#define AES_KEY_SCHEDULE_SIZE 240 /* 60 32-bit words = 240 bytes */

/* Return codes */
#define AES_SUCCESS 0
#define AES_ERROR_INVALID_PARAM -1
#define AES_ERROR_FILE_OPEN -2
#define AES_ERROR_FILE_READ -3
#define AES_ERROR_FILE_WRITE -4
#define AES_ERROR_MEMORY -5
#define AES_ERROR_RANDOM -6
#define AES_ERROR_BUFFER_TOO_SMALL -7

/**
 * AES-256 Context Structure
 * Holds the expanded key schedule for encryption/decryption
 */
/* A context groups related state into one object. Keep it alive during calls,
 * initialize before use, and call aes256_cleanup when done. Cleanup wipes the
 * object but does not free it: it is usually a caller-owned local variable. */
typedef struct
{
    uint8_t round_keys[AES_KEY_SCHEDULE_SIZE]; /* Expanded key schedule */
    uint8_t iv[AES_BLOCK_SIZE];                /* Initialization vector for CBC mode */
} aes256_context;

/* Core AES-256 Functions */

/**
 * Initialize AES-256 context with a 256-bit key
 *
 * @param ctx Pointer to AES context structure
 * @param key Pointer to 32-byte encryption key
 * @param iv Pointer to 16-byte initialization vector (NULL generates a random IV)
 * @return AES_SUCCESS on success, error code otherwise
 */
int aes256_init(aes256_context *ctx, const uint8_t *key, const uint8_t *iv);

/**
 * Encrypt a single 16-byte block (ECB mode)
 *
 * @param ctx Pointer to initialized AES context
 * @param input Pointer to 16-byte input block
 * @param output Pointer to 16-byte output buffer
 * @return AES_SUCCESS on success, error code otherwise
 */
/* An array passed to a function becomes a pointer to its first element.
 * These pointers must each address at least 16 bytes; the API cannot discover
 * a smaller allocation. Block functions neither pad nor use the CBC IV. */
int aes256_encrypt_block(const aes256_context *ctx, const uint8_t *input, uint8_t *output);

/**
 * Decrypt a single 16-byte block (ECB mode)
 *
 * @param ctx Pointer to initialized AES context
 * @param input Pointer to 16-byte input block
 * @param output Pointer to 16-byte output buffer
 * @return AES_SUCCESS on success, error code otherwise
 */
int aes256_decrypt_block(const aes256_context *ctx, const uint8_t *input, uint8_t *output);

/* Memory Buffer Operations (CBC Mode with PKCS7 Padding)
 * Legacy entry points below assume sufficient capacity. Prefer the checked API.
 */

/**
 * Encrypt a memory buffer using CBC mode with PKCS7 padding
 *
 * @param ctx Pointer to initialized AES context (must have IV set)
 * @param input Pointer to input data
 * @param input_len Length of input data in bytes
 * @param output Pointer to output buffer (must be large enough for padded data)
 * @param output_len Pointer to store actual output length
 * @return AES_SUCCESS on success, error code otherwise
 *
 * Note: Output buffer must be at least input_len + AES_BLOCK_SIZE bytes
 */
int aes256_encrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len);

/**
 * Decrypt a memory buffer using CBC mode with PKCS7 padding
 *
 * @param ctx Pointer to initialized AES context (must have IV set)
 * @param input Pointer to encrypted input data
 * @param input_len Length of input data in bytes (must be a nonzero multiple of AES_BLOCK_SIZE)
 * @param output Pointer to output buffer
 * @param output_len Pointer to store actual output length (zero on malformed ciphertext)
 * @return AES_SUCCESS on success, error code otherwise
 */
int aes256_decrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len);

/* Preferred capacity-checked API. All failures set *output_len to zero when
 * output_len is non-NULL. Insufficient capacity leaves output untouched.
 * Encryption permits NULL input only when input_len is zero.
 * Decryption needs input_len bytes of capacity, including padding space.
 * Exact in-place operation is supported; partial overlap is not supported.
 */
/* Required ciphertext capacity, including a complete PKCS7 padding block.
 * On overflow, return AES_ERROR_INVALID_PARAM and set *required to zero. */
/* Example: 0 input bytes need 16 output bytes, 15 need 16, and 16 need 32.
 * required must be non-NULL. This helper allocates nothing; the caller may use
 * the reported capacity for malloc, then supply it to the checked encrypt call. */
int aes256_encrypted_size(size_t input_len, size_t *required);
/* Both checked functions borrow buffers: the caller allocates and frees them.
 * A non-NULL output_len points to a size_t variable to receive the result.
 * On padding failure decryption wipes input_len bytes in output; on capacity
 * failure neither checked function writes output. Capacity must be truthful. */
int aes256_encrypt_buffer_checked(aes256_context *ctx, const uint8_t *input,
    size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len);
int aes256_decrypt_buffer_checked(aes256_context *ctx, const uint8_t *input,
    size_t input_len, uint8_t *output, size_t output_capacity, size_t *output_len);

/* File Operations
 * Write to a private (0600) temporary file beside the destination, then rename
 * after successful processing and flush/close. Failure preserves the destination.
 * Input and output may name the same file. Successful replacement creates a new
 * file rather than preserving the destination's permissions or inode.
 * Atomic replacement does not guarantee directory durability after a power loss.
 */

/**
 * Encrypt a file using CBC mode with PKCS7 padding
 *
 * @param ctx Pointer to initialized AES context (must have IV set)
 * @param input_file Path to input file
 * @param output_file Path to output file
 * @return AES_SUCCESS on success, error code otherwise
 *
 * Note: The IV is prepended to the output file for decryption
 */
int aes256_encrypt_file(aes256_context *ctx, const char *input_file,
                        const char *output_file);

/**
 * Decrypt a file using CBC mode with PKCS7 padding
 *
 * @param ctx Pointer to initialized AES context
 * @param input_file Path to encrypted input file
 * @param output_file Path to output file
 * @return AES_SUCCESS on success, error code otherwise
 *
 * Note: Reads the IV from the beginning of the input file
 * Invalid block lengths or PKCS7 padding return AES_ERROR_INVALID_PARAM.
 * On failure the destination remains unchanged.
 */
int aes256_decrypt_file(aes256_context *ctx, const char *input_file,
                        const char *output_file);

/* Utility Functions */

/**
 * Securely zero out sensitive data
 *
 * @param ptr Pointer to memory to clear
 * @param len Number of bytes to clear
 */
void aes256_secure_zero(void *ptr, size_t len);

/**
 * Zero and release sensitive material inside context
 */
void aes256_cleanup(aes256_context *ctx);

/**
 * Print a byte array in hexadecimal format (for debugging)
 *
 * @param label Label to print before the data
 * @param data Pointer to data
 * @param len Length of data in bytes
 */
/* Debug output is hexadecimal text, two characters per byte. Printing key
 * bytes discloses the key; normal example runs avoid displaying generated keys. */
void aes256_print_hex(const char *label, const uint8_t *data, size_t len);

#endif /* AES256_H */