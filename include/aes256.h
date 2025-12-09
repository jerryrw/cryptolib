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

/**
 * AES-256 Context Structure
 * Holds the expanded key schedule for encryption/decryption
 */
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
 * @param iv Pointer to 16-byte initialization vector (can be NULL for ECB mode)
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

/* Memory Buffer Operations (CBC Mode with PKCS7 Padding) */

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
 * @param input_len Length of input data in bytes (must be multiple of AES_BLOCK_SIZE)
 * @param output Pointer to output buffer
 * @param output_len Pointer to store actual output length (after padding removal)
 * @return AES_SUCCESS on success, error code otherwise
 */
int aes256_decrypt_buffer(aes256_context *ctx, const uint8_t *input,
                          size_t input_len, uint8_t *output, size_t *output_len);

/* File Operations */

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
void aes256_print_hex(const char *label, const uint8_t *data, size_t len);

#endif /* AES256_H */