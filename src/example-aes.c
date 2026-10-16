/*
 * A step-by-step AES demonstration with realistic resource management.
 * The feature-test macros below expose POSIX/macOS declarations such as mkdtemp;
 * they must appear before system headers. Local static functions are private to
 * this executable. Each example returns 0 on success and -1 on failure, and main
 * turns any failure into a nonzero process exit status.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
/* Build: make example-aes; run: ./example-aes */
#include "aes256.h"
#include "example_helpers.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* This helper owns three heap buffers. capacity includes encryption padding,
 * while len is the original message size and enc_len/dec_len are produced sizes.
 * Keeping these concepts separate avoids writing beyond allocated memory. */
static int example_buffer(const char *label, size_t len)
{
    aes256_context ctx = {0};
    uint8_t key[AES_KEY_SIZE] = {0};
    uint8_t *input = NULL, *encrypted = NULL, *decrypted = NULL;
    int result = -1;
    size_t enc_len = 0, dec_len = 0, capacity = 0;
    if (aes256_encrypted_size(len, &capacity) != AES_SUCCESS)
        goto cleanup;
/* malloc does not initialize bytes. Reserve one byte even for an empty input
 * so behavior does not depend on whether malloc(0) returns NULL on this system. */
    input = malloc(len ? len : 1);
    encrypted = malloc(capacity);
    decrypted = malloc(capacity);
    if (!input || !encrypted || !decrypted ||
        example_random_bytes(key, sizeof(key)) != 0 ||
        aes256_init(&ctx, key, NULL) != AES_SUCCESS)
        goto cleanup;
    for (size_t i = 0; i < len; i++) input[i] = (uint8_t)(i & 0xff);

/* clock measures process CPU time, not wall-clock elapsed time. Do not
 * report a rate unless the clock worked and the measured interval is positive. */
    clock_t start = clock();
    if (aes256_encrypt_buffer_checked(&ctx, input, len, encrypted, capacity, &enc_len) != AES_SUCCESS)
        goto cleanup;
    clock_t end = clock();
    /* Buffer operations leave ctx.iv unchanged, so no reset is necessary. */
    if (aes256_decrypt_buffer_checked(&ctx, encrypted, enc_len, decrypted, capacity, &dec_len) != AES_SUCCESS ||
        dec_len != len || memcmp(input, decrypted, len) != 0)
        goto cleanup;
    printf("%s: %zu bytes -> %zu encrypted bytes; round-trip passed\n", label, len, enc_len);
    if (start != (clock_t)-1 && end != (clock_t)-1 && end > start) {
        double seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("  Encryption CPU time: %.3f ms, %.2f MiB/s\n",
               seconds * 1000, (len / (1024.0 * 1024.0)) / seconds);
    }
    result = 0;
/* All failures jump here. Wipe using allocation capacities, not lengths
 * that a failed crypto call may never have set. free(NULL) is safe in C. */
cleanup:
    aes256_cleanup(&ctx);
    aes256_secure_zero(key, sizeof(key));
    if (input) aes256_secure_zero(input, len);
    if (encrypted) aes256_secure_zero(encrypted, capacity);
    if (decrypted) aes256_secure_zero(decrypted, capacity);
    free(input); free(encrypted); free(decrypted);
    return result;
}

/* Compare bytes and EOF together; a read error is always a failure. */
/* fgetc returns int, not char, because it must represent all byte values
 * plus the distinct EOF marker. Read both streams on every iteration so an
 * extra byte in either file is detected. EOF without ferror is normal completion. */
static int files_match(FILE *left, FILE *right)
{
    for (;;) {
        int a = fgetc(left), b = fgetc(right);
        if (ferror(left) || ferror(right) || a != b)
            return 0;
        if (a == EOF)
            return 1;
    }
}

static int example_file(void)
{
    char dir[] = "/tmp/cryptolib-example-XXXXXX";
    char input[128], encrypted[128], decrypted[128];
    const char content[] = "AES-256 CBC file example with PKCS7 padding.\n";
    aes256_context ctx = {0};
    uint8_t key[AES_KEY_SIZE] = {0};
    FILE *writer = NULL, *left = NULL, *right = NULL;
    int result = -1;
/* The template must be a writable array: mkdtemp replaces XXXXXX in place.
 * It creates a private unique directory, so the filenames below cannot collide
 * with pre-existing user files in the working directory. */
    if (!mkdtemp(dir))
        return -1;
    /* These fixed-size paths fit the fixed template above. */
    snprintf(input, sizeof(input), "%s/input", dir);
    snprintf(encrypted, sizeof(encrypted), "%s/encrypted", dir);
    snprintf(decrypted, sizeof(decrypted), "%s/decrypted", dir);
    if (example_random_bytes(key, sizeof(key)) != 0 ||
        aes256_init(&ctx, key, NULL) != AES_SUCCESS)
        goto cleanup;
    writer = fopen(input, "wb");
    if (!writer)
        goto cleanup;
/* Check the actual byte count and close status. Buffered writes can seem
 * to succeed until fclose tries to flush the remaining bytes to the OS. */
    size_t written = fwrite(content, 1, sizeof(content) - 1, writer);
    int closed = fclose(writer);
    writer = NULL;
    if (written != sizeof(content) - 1 || closed != 0)
        goto cleanup;
    if (aes256_encrypt_file(&ctx, input, encrypted) != AES_SUCCESS ||
        aes256_decrypt_file(&ctx, encrypted, decrypted) != AES_SUCCESS)
        goto cleanup;
    left = fopen(input, "rb");
    right = fopen(decrypted, "rb");
    if (!left || !right || !files_match(left, right))
        goto cleanup;
    result = 0;
cleanup:
    if (writer && fclose(writer) != 0) result = -1;
    if (left && fclose(left) != 0) result = -1;
    if (right && fclose(right) != 0) result = -1;
    aes256_cleanup(&ctx);
    aes256_secure_zero(key, sizeof(key));
    /* Only remove files inside the private directory this run created. */
/* This array holds pointers to three local path strings. sizeof(paths) /
 * sizeof(paths[0]) counts its elements; that formula works for arrays here,
 * but would not work for a pointer parameter in another function. */
    const char *paths[] = {input, encrypted, decrypted};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], F_OK) == 0 && remove(paths[i]) != 0)
            result = -1;
    }
    if (rmdir(dir) != 0) result = -1;
    if (result == 0) puts("File encryption: round-trip passed; temporary files removed");
    return result;
}

/* A known-answer test checks actual ciphertext, not merely a round-trip.
 * An incorrect encrypt/decrypt pair could agree with itself, so comparing
 * against an independent published value catches a different class of bug. */
static int example_fixed_key(void)
{
    /* Deterministic FIPS-197 single-block vector, not a key for real messages. */
    uint8_t key[AES_KEY_SIZE];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    const uint8_t input[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t expected[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    uint8_t encrypted[16] = {0}, decrypted[16] = {0}, iv[16] = {0};
    aes256_context ctx = {0};
    int result = -1;
    /* Single-block operations do not use the IV. */
    if (aes256_init(&ctx, key, iv) != AES_SUCCESS ||
        aes256_encrypt_block(&ctx, input, encrypted) != AES_SUCCESS ||
        memcmp(encrypted, expected, sizeof(expected)) != 0 ||
        aes256_decrypt_block(&ctx, encrypted, decrypted) != AES_SUCCESS ||
        memcmp(decrypted, input, sizeof(input)) != 0)
        goto cleanup;
    puts("Fixed test key: FIPS-197 block encryption and decryption passed");
    result = 0;
cleanup:
    aes256_cleanup(&ctx);
    aes256_secure_zero(key, sizeof(key));
    aes256_secure_zero(decrypted, sizeof(decrypted));
    return result;
}

int main(void)
{
    puts("Educational AES-256 examples; CBC does not authenticate data.");
/* Stop on the first error. || skips subsequent examples after a failure;
 * only the path where every call returns 0 prints the success message. */
    if (example_buffer("Small buffer", 50) != 0 ||
        example_buffer("Large buffer", 1024 * 1024) != 0 ||
        example_file() != 0 || example_fixed_key() != 0) {
        fputs("AES example failed\n", stderr);
        return EXIT_FAILURE;
    }
    puts("All AES examples completed successfully");
    return EXIT_SUCCESS;
}
