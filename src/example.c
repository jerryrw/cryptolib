/*
 * Start reading the project here. This executable demonstrates the public APIs
 * without exposing generated key bytes. Each library owns its algorithm state;
 * this program owns the buffers and decides when to clean them up.
 * main returns EXIT_SUCCESS (0) or EXIT_FAILURE so a shell or CI can detect errors.
 * The detailed AES-only walkthrough is in src/example-aes.c.
 */

/* Build: make example; run: ./example */
#include "sha3.h"
#include "sha256.h"
#include "md5.h"
#include "aes256.h"
#include "arcfour.h"
#include "example_helpers.h"
#include <stdlib.h>
#include <string.h>

static void print_hash(const char *name, const uint8_t *hash, size_t len)
{
    printf("%s: ", name);
    for (size_t i = 0; i < len; i++)
        printf("%02x", hash[i]);
    putchar('\n');
}

int main(void)
{
/* This array includes a trailing zero for printing as a C string. sizeof
 * measures the complete array here, so subtract 1 to hash/encrypt only the text.
 * Unlike strlen, an explicit byte count can also represent binary data. */
    uint8_t message[] = "The quick brown fox jumps over the lazy dog";
    const size_t len = sizeof(message) - 1;
    uint8_t hash[32], key[AES_KEY_SIZE] = {0};
    uint8_t encrypted[sizeof(message) + AES_BLOCK_SIZE] = {0};
    uint8_t decrypted[sizeof(encrypted)] = {0};
/* Initialize resources before any possible goto cleanup. A zeroed context
 * and NULL pointers can safely take the common cleanup path even if setup fails. */
    aes256_context aes = {0};
    rc4_ctx *rc4_enc = NULL, *rc4_dec = NULL;
    uint8_t *rc4_cipher = NULL, *rc4_plain = NULL;
    int result = EXIT_FAILURE;

    printf("Message: %s\n", (const char *)message);
    sha3_256(message, len, hash);
    print_hash("SHA3-256", hash, 32);
/* The address operator & passes access to the same context across calls.
 * update receives the original message; final writes the digest into hash. */
    SHA256_CTX sha;
    sha256_init(&sha);
    sha256_update(&sha, message, len);
    sha256_final(&sha, hash);
    print_hash("SHA-256", hash, 32);
    MD5_CTX md5;
    md5_init(&md5);
    md5_update(&md5, message, len);
    md5_final(&md5, hash);
    print_hash("MD5 (legacy demonstration)", hash, 16);

/* The key uses OS randomness. NULL in the IV position requests a separately
 * generated IV from aes256_init; it does not mean a zero IV. */
    if (example_random_bytes(key, sizeof(key)) != 0 ||
        aes256_init(&aes, key, NULL) != AES_SUCCESS)
        goto cleanup;
/* Use an overflow-checked size calculation, then pass the actual allocated
 * capacities. &&/|| evaluate left-to-right and short-circuit, so a failed step
 * prevents later steps from using an invalid result. */
    size_t enc_len = 0, dec_len = 0, required = 0;
    if (aes256_encrypted_size(len, &required) != AES_SUCCESS || required > sizeof(encrypted))
        goto cleanup;
    if (aes256_encrypt_buffer_checked(&aes, message, len, encrypted, sizeof(encrypted), &enc_len) != AES_SUCCESS ||
        aes256_decrypt_buffer_checked(&aes, encrypted, enc_len, decrypted, sizeof(decrypted), &dec_len) != AES_SUCCESS ||
        dec_len != len || memcmp(message, decrypted, len) != 0)
        goto cleanup;
    puts("AES-256 CBC round-trip passed (CBC does not authenticate data)");

    /* RC4 is included for learning about legacy algorithms. */
    aes256_secure_zero(key, sizeof(key));
    if (example_random_bytes(key, sizeof(key)) != 0)
        goto cleanup;
/* Two contexts start at the same keystream position. Reusing rc4_enc for
 * decryption would continue from the end and produce different bytes. */
    rc4_enc = rc4_init(key, sizeof(key));
    rc4_dec = rc4_init(key, sizeof(key));
    if (!rc4_enc || !rc4_dec)
        goto cleanup;
    rc4_cipher = rc4_encrypt(rc4_enc, message, len);
    if (!rc4_cipher)
        goto cleanup;
    rc4_plain = rc4_encrypt(rc4_dec, rc4_cipher, len);
    if (!rc4_plain || memcmp(message, rc4_plain, len) != 0)
        goto cleanup;
    puts("RC4 legacy round-trip passed");
    result = EXIT_SUCCESS;

/* goto is used only to converge error paths on one cleanup section. Wipe
 * sensitive buffers while they are still valid, then free heap allocations.
 * Stack objects need wiping if sensitive, but must never be passed to free. */
cleanup:
    aes256_cleanup(&aes);
    aes256_secure_zero(key, sizeof(key));
    aes256_secure_zero(decrypted, sizeof(decrypted));
    if (rc4_plain) aes256_secure_zero(rc4_plain, len);
    if (rc4_cipher) aes256_secure_zero(rc4_cipher, len);
    if (rc4_enc) aes256_secure_zero(rc4_enc, sizeof(*rc4_enc));
    if (rc4_dec) aes256_secure_zero(rc4_dec, sizeof(*rc4_dec));
    free(rc4_plain);
    free(rc4_cipher);
    rc4_free(rc4_enc);
    rc4_free(rc4_dec);
    if (result != EXIT_SUCCESS)
        fputs("Example failed\n", stderr);
    return result;
}
