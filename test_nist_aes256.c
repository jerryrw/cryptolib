/**
 * test_vectors.c
 *
 * AES-256 Test Vectors
 * Tests against NIST FIPS-197 test vectors and custom tests
 *
 */

#include "include/aes256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ANSI color codes for output */
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RED "\x1b[31m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

/**
 * Compare two byte arrays
 */
static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

/**
 * Print test result
 */
static void print_result(const char *test_name, int passed)
{
    if (passed)
    {
        printf(COLOR_GREEN "✓ PASS" COLOR_RESET " %s\n", test_name);
        tests_passed++;
    }
    else
    {
        printf(COLOR_RED "✗ FAIL" COLOR_RESET " %s\n", test_name);
        tests_failed++;
    }
}

/**
 * Test 1: NIST FIPS-197 AES-256 ECB Test Vector
 * Appendix C.3
 */
static void test_nist_ecb_vector(void)
{
    printf("\n=== Test 1: NIST FIPS-197 AES-256 ECB ===\n");

    /* Test key (256 bits) */
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    /* Plaintext block */
    uint8_t plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    /* Expected ciphertext */
    uint8_t expected_ciphertext[16] = {
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes256_context ctx;
    aes256_init(&ctx, key, NULL);

    /* Test encryption */
    aes256_encrypt_block(&ctx, plaintext, ciphertext);

    printf("Key:        ");
    aes256_print_hex(NULL, key, 32);
    printf("Plaintext:  ");
    aes256_print_hex(NULL, plaintext, 16);
    printf("Ciphertext: ");
    aes256_print_hex(NULL, ciphertext, 16);
    printf("Expected:   ");
    aes256_print_hex(NULL, expected_ciphertext, 16);

    int encrypt_pass = compare_bytes(ciphertext, expected_ciphertext, 16);
    print_result("ECB Encryption", encrypt_pass);

    /* Test decryption */
    aes256_decrypt_block(&ctx, ciphertext, decrypted);

    printf("Decrypted:  ");
    aes256_print_hex(NULL, decrypted, 16);

    int decrypt_pass = compare_bytes(decrypted, plaintext, 16);
    print_result("ECB Decryption", decrypt_pass);

    aes256_secure_zero(&ctx, sizeof(ctx));
}

/**
 * Test 2: All-zeros encryption
 */
static void test_all_zeros(void)
{
    printf("\n=== Test 2: All-zeros Block ===\n");

    uint8_t key[32] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes256_context ctx;
    aes256_init(&ctx, key, NULL);

    aes256_encrypt_block(&ctx, plaintext, ciphertext);
    aes256_decrypt_block(&ctx, ciphertext, decrypted);

    printf("Plaintext:  ");
    aes256_print_hex(NULL, plaintext, 16);
    printf("Ciphertext: ");
    aes256_print_hex(NULL, ciphertext, 16);
    printf("Decrypted:  ");
    aes256_print_hex(NULL, decrypted, 16);

    int pass = compare_bytes(decrypted, plaintext, 16);
    print_result("All-zeros round-trip", pass);

    aes256_secure_zero(&ctx, sizeof(ctx));
}

/**
 * Test 3: Buffer encryption/decryption with CBC mode
 */
static void test_buffer_cbc(void)
{
    printf("\n=== Test 3: Buffer CBC Mode ===\n");

    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    const char *message = "This is a test message for AES-256 CBC encryption!";
    size_t msg_len = strlen(message);

    uint8_t encrypted[256];
    uint8_t decrypted[256];
    size_t encrypted_len, decrypted_len;

    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    printf("Original message: %s\n", message);
    printf("Message length: %zu bytes\n", msg_len);

    /* Encrypt */
    int ret = aes256_encrypt_buffer(&ctx, (uint8_t *)message, msg_len,
                                    encrypted, &encrypted_len);

    printf("Encrypted length: %zu bytes\n", encrypted_len);
    printf("Encrypted data (first 32 bytes): ");
    aes256_print_hex(NULL, encrypted, encrypted_len > 32 ? 32 : encrypted_len);

    /* Reset IV for decryption */
    memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

    /* Decrypt */
    ret |= aes256_decrypt_buffer(&ctx, encrypted, encrypted_len,
                                 decrypted, &decrypted_len);

    decrypted[decrypted_len] = '\0'; /* Null-terminate */
    printf("Decrypted message: %s\n", (char *)decrypted);
    printf("Decrypted length: %zu bytes\n", decrypted_len);

    int pass = (ret == AES_SUCCESS) &&
               (decrypted_len == msg_len) &&
               (memcmp(message, decrypted, msg_len) == 0);

    print_result("CBC Buffer round-trip", pass);

    aes256_secure_zero(&ctx, sizeof(ctx));
    aes256_secure_zero(encrypted, sizeof(encrypted));
    aes256_secure_zero(decrypted, sizeof(decrypted));
}

/**
 * Test 4: Large buffer encryption
 */
static void test_large_buffer(void)
{
    printf("\n=== Test 4: Large Buffer (10KB) ===\n");

    uint8_t key[32];
    uint8_t iv[16];

    /* Generate pseudo-random key and IV */
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)(i * 7 + 13);
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(i * 11 + 17);

    size_t buffer_size = 10240; /* 10KB */
    uint8_t *plaintext = malloc(buffer_size);
    uint8_t *encrypted = malloc(buffer_size + AES_BLOCK_SIZE);
    uint8_t *decrypted = malloc(buffer_size + AES_BLOCK_SIZE);

    if (!plaintext || !encrypted || !decrypted)
    {
        printf(COLOR_RED "Memory allocation failed\n" COLOR_RESET);
        free(plaintext);
        free(encrypted);
        free(decrypted);
        return;
    }

    /* Fill with pattern */
    for (size_t i = 0; i < buffer_size; i++)
    {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }

    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    size_t encrypted_len, decrypted_len;

    /* Encrypt */
    int ret = aes256_encrypt_buffer(&ctx, plaintext, buffer_size,
                                    encrypted, &encrypted_len);

    printf("Original size: %zu bytes\n", buffer_size);
    printf("Encrypted size: %zu bytes\n", encrypted_len);

    /* Reset IV for decryption */
    memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

    /* Decrypt */
    ret |= aes256_decrypt_buffer(&ctx, encrypted, encrypted_len,
                                 decrypted, &decrypted_len);

    printf("Decrypted size: %zu bytes\n", decrypted_len);

    int pass = (ret == AES_SUCCESS) &&
               (decrypted_len == buffer_size) &&
               (memcmp(plaintext, decrypted, buffer_size) == 0);

    print_result("Large buffer round-trip", pass);

    aes256_secure_zero(&ctx, sizeof(ctx));
    aes256_secure_zero(plaintext, buffer_size);
    aes256_secure_zero(encrypted, encrypted_len);
    aes256_secure_zero(decrypted, decrypted_len);

    free(plaintext);
    free(encrypted);
    free(decrypted);
}

/**
 * Test 5: File encryption/decryption
 */
static void test_file_operations(void)
{
    printf("\n=== Test 5: File Encryption/Decryption ===\n");

    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    uint8_t iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    const char *test_file = "test_input.txt";
    const char *encrypted_file = "test_encrypted.bin";
    const char *decrypted_file = "test_decrypted.txt";

    /* Create test file */
    FILE *f = fopen(test_file, "w");
    if (!f)
    {
        printf(COLOR_RED "Failed to create test file\n" COLOR_RESET);
        return;
    }

    const char *content = "This is a test file for AES-256 encryption.\n"
                          "It contains multiple lines of text.\n"
                          "The file encryption should handle this properly.\n"
                          "Testing... 1, 2, 3!\n";

    fprintf(f, "%s", content);
    fclose(f);

    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    /* Encrypt file */
    int ret = aes256_encrypt_file(&ctx, test_file, encrypted_file);
    if (ret != AES_SUCCESS)
    {
        printf(COLOR_RED "File encryption failed with code %d\n" COLOR_RESET, ret);
        return;
    }

    printf("File encrypted successfully\n");

    /* Decrypt file */
    ret = aes256_decrypt_file(&ctx, encrypted_file, decrypted_file);
    if (ret != AES_SUCCESS)
    {
        printf(COLOR_RED "File decryption failed with code %d\n" COLOR_RESET, ret);
        return;
    }

    printf("File decrypted successfully\n");

    /* Compare original and decrypted */
    FILE *f1 = fopen(test_file, "rb");
    FILE *f2 = fopen(decrypted_file, "rb");

    int match = 1;
    if (f1 && f2)
    {
        int c1, c2;
        while ((c1 = fgetc(f1)) != EOF && (c2 = fgetc(f2)) != EOF)
        {
            if (c1 != c2)
            {
                match = 0;
                break;
            }
        }
        if (fgetc(f1) != EOF || fgetc(f2) != EOF)
        {
            match = 0; /* Different lengths */
        }
    }
    else
    {
        match = 0;
    }

    if (f1)
        fclose(f1);
    if (f2)
        fclose(f2);

    print_result("File round-trip", match);

    /* Cleanup */
    remove(test_file);
    remove(encrypted_file);
    remove(decrypted_file);

    aes256_secure_zero(&ctx, sizeof(ctx));
}

/**
 * Test 6: Padding edge cases
 */
static void test_padding_edge_cases(void)
{
    printf("\n=== Test 6: Padding Edge Cases ===\n");

    uint8_t key[32];
    uint8_t iv[16];
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++)
        iv[i] = (uint8_t)(16 - i);

    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    /* Test exact block size (16 bytes) */
    uint8_t msg16[16] = "0123456789ABCDEF";
    uint8_t enc16[64], dec16[64];
    size_t enc16_len, dec16_len;

    aes256_encrypt_buffer(&ctx, msg16, 16, enc16, &enc16_len);
    memcpy(ctx.iv, iv, 16);
    aes256_decrypt_buffer(&ctx, enc16, enc16_len, dec16, &dec16_len);

    int pass1 = (dec16_len == 16) && (memcmp(msg16, dec16, 16) == 0);
    print_result("16-byte message (exact block)", pass1);

    /* Test 15 bytes (one byte short of block) */
    uint8_t msg15[15] = "012345678ABCDE";
    uint8_t enc15[64], dec15[64];
    size_t enc15_len, dec15_len;

    memcpy(ctx.iv, iv, 16);
    aes256_encrypt_buffer(&ctx, msg15, 15, enc15, &enc15_len);
    memcpy(ctx.iv, iv, 16);
    aes256_decrypt_buffer(&ctx, enc15, enc15_len, dec15, &dec15_len);

    int pass2 = (dec15_len == 15) && (memcmp(msg15, dec15, 15) == 0);
    print_result("15-byte message", pass2);

    /* Test 1 byte */
    uint8_t msg1[1] = "X";
    uint8_t enc1[64], dec1[64];
    size_t enc1_len, dec1_len;

    memcpy(ctx.iv, iv, 16);
    aes256_encrypt_buffer(&ctx, msg1, 1, enc1, &enc1_len);
    memcpy(ctx.iv, iv, 16);
    aes256_decrypt_buffer(&ctx, enc1, enc1_len, dec1, &dec1_len);

    int pass3 = (dec1_len == 1) && (dec1[0] == 'X');
    print_result("1-byte message", pass3);

    aes256_secure_zero(&ctx, sizeof(ctx));
}

/**
 * Main test runner
 */
int main(void)
{
    printf(COLOR_YELLOW "╔════════════════════════════════════════╗\n");
    printf("║   AES-256 Test Vector Suite            ║\n");

#ifdef __APPLE__
    printf("║   macOS ARM (Apple Silicon) Build      ║\n");
#elif __linux__
    printf("║   Linux Build                          ║\n");
#endif

    printf("╚════════════════════════════════════════╝\n" COLOR_RESET);

    test_nist_ecb_vector();
    test_all_zeros();
    test_buffer_cbc();
    test_large_buffer();
    test_file_operations();
    test_padding_edge_cases();

    printf("\n" COLOR_YELLOW "═══════════════════════════════════════\n" COLOR_RESET);
    printf("Total Tests: %d\n", tests_passed + tests_failed);
    printf(COLOR_GREEN "Passed: %d\n" COLOR_RESET, tests_passed);

    if (tests_failed > 0)
    {
        printf(COLOR_RED "Failed: %d\n" COLOR_RESET, tests_failed);
        return 1;
    }
    else
    {
        printf(COLOR_GREEN "\n✓ All tests passed!\n" COLOR_RESET);
        return 0;
    }
}