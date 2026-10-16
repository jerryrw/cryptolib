/*
 * Regression tests keep previously discovered bugs from coming back.
 * assert(condition) aborts with a file/line diagnostic when the condition is false.
 * Many assertions here also perform setup: never compile these tests with NDEBUG,
 * which disables assert expressions entirely. size boundary values are intentional;
 * they should be rejected before any read from a deliberately small input buffer.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "md5.h"
#include "sha256.h"
#include "sha3.h"
#include "aes256.h"
#include "arcfour.h"
#include <assert.h>
#include <unistd.h>

/* The digest table is independent of this implementation. Values around
 * 136 test transitions into and out of SHA3 rate blocks. i % 251 generates
 * repeatable binary input, including zero bytes that strlen could not measure. */
static void test_sha3(void)
{
    /* Expected digests generated independently with Python hashlib.sha3_256. */
    const struct { size_t len; const char *hex; } vectors[] = {
    {0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {1, "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"},
    {135, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"},
    {136, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"},
    {137, "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca"},
    {271, "0153fcdb6825d836b10835ccb3999dc1d8b68492f77e7e38afa31f8e244bd7af"},
    {272, "b7ccd55b6c2c3fa144c9e0624059294975a348b02f321abe289701d3012f7794"},
    {273, "4827800416bd25b01f53360454943ef688112eaee40422929a59af596a2c0be7"},
    {8192, "ae1e2d41aabdd5f20028d82dbd03bb02c64de6021b9c5afb5db3bec5b415528c"},
    {10000, "372077ac20022c94bcce5d0de3c8dd6149e1d5c5dc93934fac2725671365673b"},
    };
    uint8_t input[10000], digest[32];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = i % 251;
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        sha3_256(input, vectors[i].len, digest);
        for (size_t j = 0; j < sizeof(digest); j++) {
            unsigned int expected;
            assert(sscanf(vectors[i].hex + 2*j, "%2x", &expected) == 1);
            assert(digest[j] == expected);
        }
    }
}

/* Exercise the compatibility API and padding rejection. Encrypt deliberately
 * bad plaintext padding with the raw block primitive to construct ciphertext
 * that decrypts correctly at the block level but must fail PKCS7 validation. */
static void test_aes_buffers(void)
{
    aes256_context ctx;
    uint8_t key[32] = {0}, iv[16] = {0};
    uint8_t input[64] = {0}, encrypted[80], output[80];
    size_t len = 99, encrypted_len;
    assert(aes256_init(&ctx, key, iv) == AES_SUCCESS);
    assert(aes256_decrypt_buffer(&ctx, input, 0, output, &len) != AES_SUCCESS);
    assert(len == 0);
    assert(aes256_decrypt_buffer(&ctx, input, 15, output, &len) != AES_SUCCESS);
    assert(aes256_encrypt_buffer(&ctx, input, SIZE_MAX, output, &len) != AES_SUCCESS);
    for (size_t n = 0; n <= sizeof(input); n++) {
        assert(aes256_encrypt_buffer(&ctx, input, n, encrypted, &encrypted_len) == AES_SUCCESS);
        assert(aes256_decrypt_buffer(&ctx, encrypted, encrypted_len, output, &len) == AES_SUCCESS);
        assert(len == n && memcmp(input, output, n) == 0);
    }
/* Only a last byte of 1 is valid after fifteen literal A bytes. Larger
 * padding values require multiple matching trailing bytes, which are absent. */
    for (unsigned int padding = 0; padding <= 17; padding++) {
        memset(input, 'A', 16);
        input[15] = padding;
        assert(aes256_encrypt_block(&ctx, input, encrypted) == AES_SUCCESS);
        int result = aes256_decrypt_buffer(&ctx, encrypted, 16, output, &len);
        assert((result == AES_SUCCESS) == (padding == 1));
        if (padding != 1) assert(len == 0);
    }
/* Start with an entire valid padding block and corrupt one position at a
 * time. Every one of the sixteen padding bytes must be checked. */
    for (size_t i = 0; i < 16; i++) {
        memset(input, 16, 16);
        input[i] = 15;
        assert(aes256_encrypt_block(&ctx, input, encrypted) == AES_SUCCESS);
        assert(aes256_decrypt_buffer(&ctx, encrypted, 16, output, &len) != AES_SUCCESS);
    }
    assert(aes256_init(&ctx, key, NULL) == AES_SUCCESS);
    aes256_cleanup(&ctx);
}

/* Use sentinel byte 0xA5 to detect any output write when capacity is short.
 * Check exact allocation boundaries, arithmetic overflow without large allocation,
 * NULL contracts, and input == output. Output lengths are separate size_t values. */
static void test_checked_buffers(void)
{
    aes256_context ctx;
    uint8_t key[32] = {0}, iv[16] = {0};
    uint8_t input[64] = {0}, encrypted[80], output[80];
    size_t required = 99, length = 99, encrypted_len;
    assert(aes256_init(&ctx, key, iv) == AES_SUCCESS);
    assert(aes256_encrypted_size(SIZE_MAX, &required) == AES_ERROR_INVALID_PARAM && required == 0);
    assert(aes256_encrypted_size(SIZE_MAX - 15, &required) == AES_ERROR_INVALID_PARAM);
    assert(aes256_encrypted_size(SIZE_MAX - 16, &required) == AES_SUCCESS && required == SIZE_MAX - 15);
    assert(aes256_encrypted_size(0, NULL) == AES_ERROR_INVALID_PARAM);
    for (size_t n = 0; n <= sizeof(input); n++) {
        assert(aes256_encrypted_size(n, &required) == AES_SUCCESS);
        assert(required == (n / 16 + 1) * 16);
        memset(encrypted, 0xA5, sizeof(encrypted));
        assert(aes256_encrypt_buffer_checked(&ctx, input, n, encrypted, required - 1, &length) == AES_ERROR_BUFFER_TOO_SMALL);
        assert(length == 0);
        for (size_t i = 0; i < sizeof(encrypted); i++) assert(encrypted[i] == 0xA5);
        assert(aes256_encrypt_buffer_checked(&ctx, input, n, encrypted, required, &encrypted_len) == AES_SUCCESS);
        memset(output, 0xA5, sizeof(output));
        assert(aes256_decrypt_buffer_checked(&ctx, encrypted, encrypted_len, output, encrypted_len - 1, &length) == AES_ERROR_BUFFER_TOO_SMALL);
        assert(length == 0);
        for (size_t i = 0; i < sizeof(output); i++) assert(output[i] == 0xA5);
        assert(aes256_decrypt_buffer_checked(&ctx, encrypted, encrypted_len, output, encrypted_len, &length) == AES_SUCCESS);
        assert(length == n && memcmp(input, output, n) == 0);
        memcpy(output, input, n);
        assert(aes256_encrypt_buffer_checked(&ctx, output, n, output, sizeof(output), &length) == AES_SUCCESS);
        assert(length == encrypted_len && memcmp(output, encrypted, length) == 0);
        assert(aes256_decrypt_buffer_checked(&ctx, output, length, output, sizeof(output), &length) == AES_SUCCESS);
        assert(length == n && memcmp(output, input, n) == 0);
    }
    assert(aes256_encrypt_buffer_checked(&ctx, NULL, 0, encrypted, sizeof(encrypted), &length) == AES_SUCCESS);
    assert(aes256_encrypt_buffer_checked(&ctx, NULL, 1, encrypted, sizeof(encrypted), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_encrypt_buffer_checked(NULL, input, 1, encrypted, sizeof(encrypted), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_encrypt_buffer_checked(&ctx, input, 1, NULL, 0, &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_encrypt_buffer_checked(&ctx, input, 1, encrypted, sizeof(encrypted), NULL) == AES_ERROR_INVALID_PARAM);
    assert(aes256_decrypt_buffer_checked(&ctx, input, 0, output, sizeof(output), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_decrypt_buffer_checked(&ctx, input, 15, output, sizeof(output), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_decrypt_buffer_checked(NULL, input, 16, output, sizeof(output), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_decrypt_buffer_checked(&ctx, NULL, 16, output, sizeof(output), &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_decrypt_buffer_checked(&ctx, input, 16, NULL, 0, &length) == AES_ERROR_INVALID_PARAM && length == 0);
    assert(aes256_decrypt_buffer_checked(&ctx, input, 16, output, sizeof(output), NULL) == AES_ERROR_INVALID_PARAM);
    aes256_cleanup(&ctx);
}

/* A unique directory isolates fixtures. Compare file ciphertext to buffer
 * ciphertext as well as round-tripping: this detects file-format drift that
 * matching encrypt/decrypt mistakes could otherwise conceal. */
static void test_files(void)
{
    char dir[] = "/tmp/cryptolib-regression-XXXXXX";
    assert(mkdtemp(dir));
    char input_path[128], encrypted_path[128], output_path[128];
    snprintf(input_path, sizeof(input_path), "%s/input", dir);
    snprintf(encrypted_path, sizeof(encrypted_path), "%s/encrypted", dir);
    snprintf(output_path, sizeof(output_path), "%s/output", dir);
    aes256_context ctx;
    uint8_t key[32] = {0}, iv[16] = {0}, input[8193], output[8194], digest[32], file_digest[32];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = i % 251;
    assert(aes256_init(&ctx, key, iv) == AES_SUCCESS);
    size_t lengths[] = {0,1,15,16,17,4095,4096,4097,8193};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
        FILE *f = fopen(input_path, "wb"); assert(f);
        assert(fwrite(input, 1, lengths[i], f) == lengths[i]); assert(fclose(f) == 0);
        sha3_256(input, lengths[i], digest);
        assert(sha3_256_file(input_path, file_digest) == 0);
        assert(memcmp(digest, file_digest, 32) == 0);
        assert(aes256_encrypt_file(&ctx, input_path, encrypted_path) == AES_SUCCESS);
        uint8_t expected[8208], actual[8224]; size_t expected_len;
        assert(aes256_encrypt_buffer_checked(&ctx, input, lengths[i], expected, sizeof(expected), &expected_len) == AES_SUCCESS);
        f = fopen(encrypted_path, "rb"); assert(f);
        assert(fread(actual, 1, sizeof(actual), f) == expected_len + AES_BLOCK_SIZE);
        assert(memcmp(actual, iv, AES_BLOCK_SIZE) == 0);
        assert(memcmp(actual + AES_BLOCK_SIZE, expected, expected_len) == 0);
        assert(fclose(f) == 0);
        assert(aes256_decrypt_file(&ctx, encrypted_path, output_path) == AES_SUCCESS);
        f = fopen(output_path, "rb"); assert(f);
        assert(fread(output, 1, sizeof(output), f) == lengths[i]);
        assert(memcmp(input, output, lengths[i]) == 0); assert(fclose(f) == 0);
    }
    for (size_t n = 0; n < 49; n++) {
        if (n == 32 || n == 48) continue;
        FILE *f = fopen(encrypted_path, "wb"); assert(f);
        assert(fwrite(input, 1, n, f) == n); assert(fclose(f) == 0);
        assert(aes256_decrypt_file(&ctx, encrypted_path, output_path) != AES_SUCCESS);
    }
    uint8_t bad[32] = {0};
    memset(input, 'A', 16); input[15] = 2;
    assert(aes256_encrypt_block(&ctx, input, bad + 16) == AES_SUCCESS);
    FILE *f = fopen(encrypted_path, "wb"); assert(f);
    assert(fwrite(bad, 1, sizeof(bad), f) == sizeof(bad)); assert(fclose(f) == 0);
    assert(aes256_decrypt_file(&ctx, encrypted_path, output_path) != AES_SUCCESS);
    aes256_cleanup(&ctx);
    assert(unlink(input_path) == 0); assert(unlink(encrypted_path) == 0);
    assert(unlink(output_path) == 0); assert(rmdir(dir) == 0);
}

/* Invalid arguments must fail before modulo, dereference, or allocation
 * size arithmetic. The empty result still has its convenience zero terminator. */
static void test_rc4(void)
{
    uint8_t key[] = {1}, input[] = {0};
    assert(rc4_init(NULL, 1) == NULL);
    assert(rc4_init(key, 0) == NULL);
    rc4_ctx *ctx = rc4_init(key, sizeof(key)); assert(ctx);
    assert(rc4_encrypt(NULL, input, 1) == NULL);
    assert(rc4_encrypt(ctx, NULL, 1) == NULL);
    assert(rc4_encrypt(ctx, input, SIZE_MAX) == NULL);
    uint8_t *empty = rc4_encrypt(ctx, NULL, 0); assert(empty && empty[0] == 0);
    free(empty); rc4_free(ctx);
}

int main(void)
{
    test_sha3(); test_aes_buffers(); test_checked_buffers(); test_files(); test_rc4();
    puts("Regression tests passed");
    return 0;
}
