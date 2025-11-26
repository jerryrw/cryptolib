/**
 * examples.c
 *
 * AES-256 Usage Examples
 * Demonstrates encryption/decryption of memory buffers and files
 *
 * Compile: gcc -o examples examples.c aes256.c
 * Run: ./examples
 */

#include "aes256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Generate a random key (in production, use a proper CSPRNG)
 */
static void generate_random_key(uint8_t *key, size_t len)
{
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++)
    {
        key[i] = (uint8_t)(rand() & 0xFF);
    }
}

/**
 * Example 1: Basic memory buffer encryption and decryption
 */
static void example_basic_buffer_encryption(void)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  Example 1: Basic Memory Buffer Encryption            ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    /* Generate a 256-bit key */
    uint8_t key[AES_KEY_SIZE];
    generate_random_key(key, AES_KEY_SIZE);

    /* Generate a 128-bit initialization vector */
    uint8_t iv[AES_BLOCK_SIZE];
    generate_random_key(iv, AES_BLOCK_SIZE);

    printf("Generated Key:\n");
    aes256_print_hex("  ", key, AES_KEY_SIZE);

    printf("\nGenerated IV:\n");
    aes256_print_hex("  ", iv, AES_BLOCK_SIZE);

    /* Original message */
    const char *message = "Hello, World! This is a secret message.";
    size_t message_len = strlen(message);

    printf("\nOriginal Message:\n");
    printf("  \"%s\"\n", message);
    printf("  Length: %zu bytes\n", message_len);

    /* Allocate buffers for encrypted and decrypted data */
    /* Encrypted size needs padding, so allocate extra space */
    uint8_t *encrypted = malloc(message_len + AES_BLOCK_SIZE);
    uint8_t *decrypted = malloc(message_len + AES_BLOCK_SIZE);

    if (!encrypted || !decrypted)
    {
        printf("Memory allocation failed!\n");
        free(encrypted);
        free(decrypted);
        return;
    }

    /* Initialize AES context */
    aes256_context ctx;
    if (aes256_init(&ctx, key, iv) != AES_SUCCESS)
    {
        printf("Failed to initialize AES context!\n");
        free(encrypted);
        free(decrypted);
        return;
    }

    /* Encrypt the message */
    size_t encrypted_len;
    if (aes256_encrypt_buffer(&ctx, (uint8_t *)message, message_len,
                              encrypted, &encrypted_len) != AES_SUCCESS)
    {
        printf("Encryption failed!\n");
        free(encrypted);
        free(decrypted);
        return;
    }

    printf("\nEncrypted Data:\n");
    printf("  Length: %zu bytes\n", encrypted_len);
    aes256_print_hex("  ", encrypted, encrypted_len);

    /* Reset IV for decryption (CBC mode modifies the IV) */
    memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

    /* Decrypt the message */
    size_t decrypted_len;
    if (aes256_decrypt_buffer(&ctx, encrypted, encrypted_len,
                              decrypted, &decrypted_len) != AES_SUCCESS)
    {
        printf("Decryption failed!\n");
        free(encrypted);
        free(decrypted);
        return;
    }

    /* Null-terminate the decrypted string for printing */
    decrypted[decrypted_len] = '\0';

    printf("\nDecrypted Message:\n");
    printf("  \"%s\"\n", (char *)decrypted);
    printf("  Length: %zu bytes\n", decrypted_len);

    /* Verify the decryption */
    if (decrypted_len == message_len &&
        memcmp(message, decrypted, message_len) == 0)
    {
        printf("\n✓ SUCCESS: Decryption matches original message!\n");
    }
    else
    {
        printf("\n✗ ERROR: Decryption does not match original message!\n");
    }

    /* Securely clear sensitive data */
    aes256_secure_zero(&ctx, sizeof(ctx));
    aes256_secure_zero(key, AES_KEY_SIZE);
    aes256_secure_zero(encrypted, encrypted_len);
    aes256_secure_zero(decrypted, decrypted_len);

    free(encrypted);
    free(decrypted);
}

/**
 * Example 2: Large buffer encryption
 */
static void example_large_buffer_encryption(void)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  Example 2: Large Buffer Encryption (1MB)             ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    /* Generate key and IV */
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    generate_random_key(key, AES_KEY_SIZE);
    generate_random_key(iv, AES_BLOCK_SIZE);

    /* Allocate 1MB buffer */
    size_t buffer_size = 1024 * 1024; /* 1MB */
    uint8_t *plaintext = malloc(buffer_size);
    uint8_t *encrypted = malloc(buffer_size + AES_BLOCK_SIZE);
    uint8_t *decrypted = malloc(buffer_size + AES_BLOCK_SIZE);

    if (!plaintext || !encrypted || !decrypted)
    {
        printf("Memory allocation failed!\n");
        free(plaintext);
        free(encrypted);
        free(decrypted);
        return;
    }

    /* Fill buffer with pattern */
    printf("Generating 1MB of test data...\n");
    for (size_t i = 0; i < buffer_size; i++)
    {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }

    /* Initialize AES context */
    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    /* Encrypt */
    printf("Encrypting...\n");
    clock_t start = clock();

    size_t encrypted_len;
    if (aes256_encrypt_buffer(&ctx, plaintext, buffer_size,
                              encrypted, &encrypted_len) != AES_SUCCESS)
    {
        printf("Encryption failed!\n");
        free(plaintext);
        free(encrypted);
        free(decrypted);
        return;
    }

    clock_t end = clock();
    double encrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;

    printf("  Encrypted %zu bytes to %zu bytes\n", buffer_size, encrypted_len);
    printf("  Encryption time: %.2f ms\n", encrypt_time);
    printf("  Throughput: %.2f MB/s\n",
           (buffer_size / (1024.0 * 1024.0)) / (encrypt_time / 1000.0));

    /* Reset IV for decryption */
    memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

    /* Decrypt */
    printf("\nDecrypting...\n");
    start = clock();

    size_t decrypted_len;
    if (aes256_decrypt_buffer(&ctx, encrypted, encrypted_len,
                              decrypted, &decrypted_len) != AES_SUCCESS)
    {
        printf("Decryption failed!\n");
        free(plaintext);
        free(encrypted);
        free(decrypted);
        return;
    }

    end = clock();
    double decrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;

    printf("  Decrypted %zu bytes to %zu bytes\n", encrypted_len, decrypted_len);
    printf("  Decryption time: %.2f ms\n", decrypt_time);
    printf("  Throughput: %.2f MB/s\n",
           (decrypted_len / (1024.0 * 1024.0)) / (decrypt_time / 1000.0));

    /* Verify */
    printf("\nVerifying data integrity...\n");
    if (decrypted_len == buffer_size &&
        memcmp(plaintext, decrypted, buffer_size) == 0)
    {
        printf("✓ SUCCESS: All 1MB verified successfully!\n");
    }
    else
    {
        printf("✗ ERROR: Data corruption detected!\n");
    }

    /* Cleanup */
    aes256_secure_zero(&ctx, sizeof(ctx));
    aes256_secure_zero(plaintext, buffer_size);
    aes256_secure_zero(encrypted, encrypted_len);
    aes256_secure_zero(decrypted, decrypted_len);

    free(plaintext);
    free(encrypted);
    free(decrypted);
}

/**
 * Example 3: File encryption and decryption
 */
static void example_file_encryption(void)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  Example 3: File Encryption                           ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    /* Generate key and IV */
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_BLOCK_SIZE];
    generate_random_key(key, AES_KEY_SIZE);
    generate_random_key(iv, AES_BLOCK_SIZE);

    printf("Generated Key:\n");
    aes256_print_hex("  ", key, AES_KEY_SIZE);
    printf("\nGenerated IV:\n");
    aes256_print_hex("  ", iv, AES_BLOCK_SIZE);

    /* Create a test file */
    const char *input_file = "example_input.txt";
    const char *encrypted_file = "example_encrypted.bin";
    const char *decrypted_file = "example_decrypted.txt";

    printf("\nCreating test file: %s\n", input_file);
    FILE *f = fopen(input_file, "w");
    if (!f)
    {
        printf("Failed to create input file!\n");
        return;
    }

    /* Write some content */
    const char *content =
        "AES-256 File Encryption Example\n"
        "================================\n\n"
        "This is a demonstration of file encryption using AES-256.\n"
        "The file is encrypted using CBC mode with PKCS7 padding.\n\n"
        "Key features:\n"
        "- 256-bit key strength\n"
        "- CBC mode of operation\n"
        "- PKCS7 padding\n"
        "- IV stored with encrypted file\n\n"
        "This implementation is compatible with macOS ARM (Apple Silicon).\n";

    fprintf(f, "%s", content);
    fclose(f);

    printf("  File created with %zu bytes\n", strlen(content));

    /* Initialize AES context */
    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    /* Encrypt the file */
    printf("\nEncrypting file to: %s\n", encrypted_file);
    if (aes256_encrypt_file(&ctx, input_file, encrypted_file) != AES_SUCCESS)
    {
        printf("File encryption failed!\n");
        remove(input_file);
        return;
    }

    printf("  ✓ File encrypted successfully\n");

    /* Decrypt the file */
    printf("\nDecrypting file to: %s\n", decrypted_file);
    if (aes256_decrypt_file(&ctx, encrypted_file, decrypted_file) != AES_SUCCESS)
    {
        printf("File decryption failed!\n");
        remove(input_file);
        remove(encrypted_file);
        return;
    }

    printf("  ✓ File decrypted successfully\n");

    /* Verify the files match */
    printf("\nVerifying files...\n");
    FILE *f1 = fopen(input_file, "rb");
    FILE *f2 = fopen(decrypted_file, "rb");

    int match = 1;
    if (f1 && f2)
    {
        int c1, c2;
        size_t bytes = 0;
        while ((c1 = fgetc(f1)) != EOF && (c2 = fgetc(f2)) != EOF)
        {
            bytes++;
            if (c1 != c2)
            {
                match = 0;
                break;
            }
        }
        if (fgetc(f1) != EOF || fgetc(f2) != EOF)
        {
            match = 0;
        }
        printf("  Compared %zu bytes\n", bytes);
    }
    else
    {
        match = 0;
    }

    if (f1)
        fclose(f1);
    if (f2)
        fclose(f2);

    if (match)
    {
        printf("  ✓ SUCCESS: Files match perfectly!\n");
    }
    else
    {
        printf("  ✗ ERROR: Files do not match!\n");
    }

    /* Display file sizes */
    FILE *fe = fopen(encrypted_file, "rb");
    if (fe)
    {
        fseek(fe, 0, SEEK_END);
        long encrypted_size = ftell(fe);
        fclose(fe);
        printf("\nFile sizes:\n");
        printf("  Original:  %zu bytes\n", strlen(content));
        printf("  Encrypted: %ld bytes (includes IV: %d bytes)\n",
               encrypted_size, AES_BLOCK_SIZE);
    }

    /* Cleanup */
    printf("\nCleaning up temporary files...\n");
    remove(input_file);
    remove(encrypted_file);
    remove(decrypted_file);

    aes256_secure_zero(&ctx, sizeof(ctx));
    aes256_secure_zero(key, AES_KEY_SIZE);
}

/**
 * Example 4: Using a fixed key (useful for testing)
 */
static void example_fixed_key(void)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  Example 4: Using a Fixed Key                         ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    /* Use a fixed key (in hex for clarity) */
    uint8_t key[AES_KEY_SIZE] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    uint8_t iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    printf("Fixed Key (hex):\n");
    aes256_print_hex("  ", key, AES_KEY_SIZE);

    printf("\nFixed IV (hex):\n");
    aes256_print_hex("  ", iv, AES_BLOCK_SIZE);

    /* Message to encrypt */
    const char *messages[] = {
        "Short message",
        "This is a longer message that spans multiple blocks",
        "AES-256 is a symmetric encryption algorithm"};

    aes256_context ctx;
    aes256_init(&ctx, key, iv);

    for (int i = 0; i < 3; i++)
    {
        printf("\n--- Message %d ---\n", i + 1);
        const char *msg = messages[i];
        size_t msg_len = strlen(msg);

        printf("Original: \"%s\"\n", msg);
        printf("Length: %zu bytes\n", msg_len);

        uint8_t encrypted[256];
        uint8_t decrypted[256];
        size_t enc_len, dec_len;

        /* Reset IV */
        memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

        /* Encrypt */
        aes256_encrypt_buffer(&ctx, (uint8_t *)msg, msg_len, encrypted, &enc_len);

        printf("Encrypted (%zu bytes):\n", enc_len);
        aes256_print_hex("  ", encrypted, enc_len);

        /* Reset IV */
        memcpy(ctx.iv, iv, AES_BLOCK_SIZE);

        /* Decrypt */
        aes256_decrypt_buffer(&ctx, encrypted, enc_len, decrypted, &dec_len);
        decrypted[dec_len] = '\0';

        printf("Decrypted: \"%s\"\n", (char *)decrypted);

        if (dec_len == msg_len && memcmp(msg, decrypted, msg_len) == 0)
        {
            printf("✓ Match\n");
        }
        else
        {
            printf("✗ Mismatch\n");
        }

        aes256_secure_zero(encrypted, enc_len);
        aes256_secure_zero(decrypted, dec_len);
    }

    aes256_secure_zero(&ctx, sizeof(ctx));
}

/**
 * Main function
 */
int main(void)
{
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║         AES-256 Encryption Examples                   ║\n");
    printf("║         macOS ARM (Apple Silicon) Build               ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    example_basic_buffer_encryption();
    example_large_buffer_encryption();
    example_file_encryption();
    example_fixed_key();

    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  All examples completed successfully!                 ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("Important Security Notes:\n");
    printf("• Always use a cryptographically secure random number generator\n");
    printf("  for keys and IVs in production (e.g., /dev/urandom on macOS)\n");
    printf("• Never reuse the same IV with the same key\n");
    printf("• Store keys securely (consider using keychain on macOS)\n");
    printf("• Use authenticated encryption (AES-GCM) for production systems\n");
    printf("• This implementation is for educational purposes\n\n");

    return 0;
}