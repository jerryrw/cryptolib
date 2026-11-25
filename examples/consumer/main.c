/* This example uses installed public headers and libraries only. It can be
 * copied outside the repository; its Makefile has no source-tree dependencies. */
#include <cryptolib/sha256.h>
#include <cryptolib/md5.h>
#include <cryptolib/aes256.h>
#include <cryptolib/sha3.h>
#include <cryptolib/arcfour.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const uint8_t message[] = "abc";
    const uint8_t expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, message, sizeof(message) - 1);
    sha256_final(&ctx, hash);
    sha256_cleanup(&ctx);
    if (memcmp(hash, expected, sizeof(hash)) != 0) return 1;
    printf("Installed SHA-256: ");
    for (size_t i = 0; i < sizeof(hash); i++) printf("%02x", hash[i]);
    putchar('\n');
    MD5_CTX md5;
    const uint8_t md5_expected[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
    md5_init(&md5); md5_update(&md5, message, 3); md5_final(&md5, hash); md5_cleanup(&md5);
    if (memcmp(hash, md5_expected, sizeof(md5_expected)) != 0) return 1;
    /* Fixed keys/IVs below are demonstration fixtures only. */
    uint8_t aes_key[32] = {0}, iv[16] = {0}, aes_cipher[16], aes_plain[16];
    size_t cipher_len = 0, plain_len = 0;
    aes256_context aes;
    if (aes256_init(&aes, aes_key, iv) != CRYPTOLIB_SUCCESS) return 1;
    int aes_result = aes256_encrypt_buffer_checked(&aes, message, 3, aes_cipher, sizeof(aes_cipher), &cipher_len);
    if (aes_result == CRYPTOLIB_SUCCESS)
        aes_result = aes256_decrypt_buffer_checked(&aes, aes_cipher, cipher_len, aes_plain, sizeof(aes_plain), &plain_len);
    aes256_cleanup(&aes);
    if (aes_result != CRYPTOLIB_SUCCESS || plain_len != 3 || memcmp(aes_plain, message, 3) != 0) return 1;
    SHA3_256_CTX sha3;
    sha3_256_init(&sha3);
    sha3_256_update(&sha3, message, 1);
    sha3_256_update(&sha3, message + 1, 2);
    sha3_256_final(&sha3, hash);
    sha3_256_cleanup(&sha3);
    const uint8_t key[] = {1,2,3,4,5}; /* Fixed test fixture, not a real secret. */
    rc4_ctx enc, dec;
    uint8_t ciphertext[3], plaintext[3];
    if (rc4_init_checked(&enc, key, sizeof(key)) != CRYPTOLIB_SUCCESS ||
        rc4_init_checked(&dec, key, sizeof(key)) != CRYPTOLIB_SUCCESS) return 1;
    int result = rc4_crypt_buffer(&enc, message, 3, ciphertext, sizeof(ciphertext));
    if (result == CRYPTOLIB_SUCCESS)
        result = rc4_crypt_buffer(&dec, ciphertext, 3, plaintext, sizeof(plaintext));
    rc4_cleanup(&enc); rc4_cleanup(&dec);
    if (result != CRYPTOLIB_SUCCESS || memcmp(plaintext, message, 3) != 0) return 1;
    puts("Installed library consumer passed");
    return 0;
}
