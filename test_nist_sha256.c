// ...new file...
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "include/sha256.h"

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hexlen = strlen(hex);
    if (hexlen != out_len * 2)
        return -1;
    for (size_t i = 0; i < out_len; i++)
    {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        unsigned int b;
        if (sscanf(byte_str, "%02x", &b) != 1)
            return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static int run_sha256_vector(const char *msg, const char *expected_hex)
{
    uint8_t expected[32];
    if (hex_to_bytes(expected_hex, expected, sizeof(expected)) != 0)
    {
        printf("Invalid expected hex\n");
        return 1;
    }

    uint8_t digest[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)msg, strlen(msg));
    sha256_final(&ctx, digest);

    if (memcmp(digest, expected, sizeof(digest)) != 0)
    {
        printf("SHA256 FAIL: \"%s\"\n", msg);
        printf("  got     : ");
        print_hex(digest, sizeof(digest));
        printf("\n");
        printf("  expected: %s\n", expected_hex);
        return 1;
    }
    else
    {
        printf("SHA256 PASS: \"%s\"\n", msg);
        return 0;
    }
}

static int run_sha256_file_test(const char *msg, const char *expected_hex)
{
    const char *tmpfile = "tmp_nist_sha256.bin";
    FILE *f = fopen(tmpfile, "wb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }
    fwrite(msg, 1, strlen(msg), f);
    fclose(f);

    uint8_t expected[32];
    hex_to_bytes(expected_hex, expected, sizeof(expected));

    uint8_t digest[32];
    if (sha256_file(tmpfile, digest) != 0)
    {
        printf("sha256_file failed\n");
        remove(tmpfile);
        return 1;
    }

    remove(tmpfile);

    if (memcmp(digest, expected, sizeof(digest)) == 0)
    {
        printf("SHA256 file PASS\n");
        return 0;
    }
    else
    {
        printf("SHA256 file FAIL\n");
        printf("  got     : ");
        print_hex(digest, sizeof(digest));
        printf("\n");
        printf("  expected: %s\n", expected_hex);
        return 1;
    }
}

int main(void)
{
    int fails = 0;

    fails += run_sha256_vector("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    fails += run_sha256_vector("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    fails += run_sha256_vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    fails += run_sha256_file_test("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    printf("SHA256 tests %s\n", (fails == 0) ? "PASSED" : "FAILED");
    return (fails == 0) ? 0 : 2;
}