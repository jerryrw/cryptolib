#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
/* Contract checks complement independent algorithm checks: exact status values,
 * no writes/state advancement on rejection, NULL-safe cleanup, and const input. */
#include "test_support.h"
#include "aes256.h"
#include "arcfour.h"
#include "md5.h"
#include "sha256.h"
#include "sha3.h"

static int is_zero(const void *pointer, size_t length)
{
    const uint8_t *bytes = pointer;
    for (size_t i = 0; i < length; i++) if (bytes[i]) return 0;
    return 1;
}

static void test_cleanup(void)
{
    MD5_CTX md5; SHA256_CTX sha; SHA3_256_CTX sha3; rc4_ctx rc4;
    memset(&md5, 0xA5, sizeof(md5)); md5_cleanup(&md5); CHECK(is_zero(&md5, sizeof(md5)));
    memset(&sha, 0xA5, sizeof(sha)); sha256_cleanup(&sha); CHECK(is_zero(&sha, sizeof(sha)));
    memset(&sha3, 0xA5, sizeof(sha3)); sha3_256_cleanup(&sha3); CHECK(is_zero(&sha3, sizeof(sha3)));
    memset(&rc4, 0xA5, sizeof(rc4)); rc4_cleanup(&rc4); CHECK(is_zero(&rc4, sizeof(rc4)));
    md5_cleanup(NULL); sha256_cleanup(NULL); sha3_256_cleanup(NULL); rc4_cleanup(NULL);
    rc4_free(NULL);
}

static void test_rc4_checked(void)
{
    const uint8_t key[] = {1,2,3,4,5}, input[] = {0,1,2,3};
    uint8_t output[4];
    rc4_ctx ctx, snapshot, decrypt;
    CHECK(rc4_init_checked(NULL, key, sizeof(key)) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_init_checked(&ctx, NULL, sizeof(key)) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_init_checked(&ctx, key, 0) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_init_checked(&ctx, key, sizeof(key)) == CRYPTOLIB_SUCCESS);
    snapshot = ctx;
    memset(output, 0xA5, sizeof(output));
    CHECK(rc4_crypt_buffer(&ctx, input, sizeof(input), output, 3) == CRYPTOLIB_ERROR_BUFFER_TOO_SMALL);
    CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
    for (size_t i = 0; i < sizeof(output); i++) CHECK(output[i] == 0xA5);
    CHECK(rc4_crypt_buffer(NULL, input, 4, output, 4) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_crypt_buffer(&ctx, NULL, 4, output, 4) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_crypt_buffer(&ctx, input, 4, NULL, 4) == CRYPTOLIB_ERROR_INVALID_PARAM);
    CHECK(rc4_crypt_buffer(&ctx, NULL, 0, NULL, 0) == CRYPTOLIB_SUCCESS);
    CHECK(memcmp(&ctx, &snapshot, sizeof(ctx)) == 0);
    CHECK(rc4_crypt_buffer(&ctx, input, 4, output, 4) == CRYPTOLIB_SUCCESS);
    CHECK(rc4_init_checked(&decrypt, key, sizeof(key)) == CRYPTOLIB_SUCCESS);
    CHECK(rc4_crypt_buffer(&decrypt, output, 4, output, 4) == CRYPTOLIB_SUCCESS);
    CHECK(memcmp(output, input, 4) == 0);
    /* Compatibility wrappers accept const inputs too, and still allocate. */
    rc4_ctx *heap = rc4_init(key, sizeof(key)); CHECK(heap);
    uint8_t *cipher = rc4_encrypt(heap, input, sizeof(input)); CHECK(cipher);
    CHECK(cipher[sizeof(input)] == 0);
    free(cipher); rc4_free(heap);
    rc4_cleanup(&ctx); rc4_cleanup(&snapshot); rc4_cleanup(&decrypt);
}

static void test_hash_files(void)
{
    test_fixture fixture;
    CHECK(test_fixture_init(&fixture) == 0);
    const uint8_t message[] = {0,1,0,255,5};
    FILE *f = fopen(fixture.input, "wb"); CHECK(f);
    CHECK(fwrite(message, 1, sizeof(message), f) == sizeof(message)); CHECK(fclose(f) == 0);
    int (*files[])(const char *, uint8_t *) = {md5_file, sha256_file, sha3_256_file};
    uint8_t expected[3][32] = {{0}}, digest[32], unchanged[32];
    MD5_CTX md5; SHA256_CTX sha; SHA3_256_CTX sha3;
    md5_init(&md5); md5_update(&md5, NULL, 0); md5_update(&md5, message, sizeof(message)); md5_final(&md5, expected[0]);
    sha256_init(&sha); sha256_update(&sha, NULL, 0); sha256_update(&sha, message, sizeof(message)); sha256_final(&sha, expected[1]);
    sha3_256_init(&sha3); sha3_256_update(&sha3, NULL, 0);
    sha3_256_update(&sha3, message, 1); sha3_256_update(&sha3, message + 1, sizeof(message) - 1); sha3_256_final(&sha3, expected[2]);
    size_t sizes[] = {16,32,32};
    for (size_t i = 0; i < 3; i++) {
        memset(digest, 0xA5, sizeof(digest)); memcpy(unchanged, digest, sizeof(digest));
        CHECK(files[i](NULL, digest) == CRYPTOLIB_ERROR_INVALID_PARAM);
        CHECK(files[i](fixture.input, NULL) == CRYPTOLIB_ERROR_INVALID_PARAM);
        CHECK(files[i](fixture.output, digest) == CRYPTOLIB_ERROR_FILE_OPEN);
        CHECK(files[i](fixture.directory, digest) == CRYPTOLIB_ERROR_FILE_READ);
        CHECK(memcmp(digest, unchanged, sizeof(digest)) == 0);
        CHECK(files[i](fixture.input, digest) == CRYPTOLIB_SUCCESS);
        CHECK(memcmp(digest, expected[i], sizes[i]) == 0);
    }
    md5_cleanup(&md5); sha256_cleanup(&sha); sha3_256_cleanup(&sha3);
    CHECK(test_fixture_cleanup(&fixture) == 0);
    CHECK(AES_ERROR_FILE_READ == CRYPTOLIB_ERROR_FILE_READ);
    CHECK(AES_ERROR_BUFFER_TOO_SMALL == CRYPTOLIB_ERROR_BUFFER_TOO_SMALL);
}

int main(void)
{
    test_cleanup(); test_rc4_checked(); test_hash_files();
    puts("API status, const-input, streaming, and cleanup checks passed");
    return 0;
}
