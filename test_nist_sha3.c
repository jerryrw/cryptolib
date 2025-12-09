// ...new file...
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "include/sha3.h"

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

static int run_sha3_vector(const char *msg, const char *expected_hex)
{
    uint8_t expected[SHA3_256_HASH_SIZE];
    if (hex_to_bytes(expected_hex, expected, sizeof(expected)) != 0)
    {
        printf("Invalid expected hex\n");
        return 1;
    }

    uint8_t digest[SHA3_256_HASH_SIZE];
    /* use the high-level provided API */
    sha3_256((const uint8_t *)msg, strlen(msg), digest);

    if (memcmp(digest, expected, sizeof(digest)) != 0)
    {
        printf("SHA3-256 FAIL: \"%s\"\n", msg);
        printf("  got     : ");
        print_hex(digest, sizeof(digest));
        printf("\n");
        printf("  expected: %s\n", expected_hex);
        return 1;
    }
    else
    {
        printf("SHA3-256 PASS: \"%s\"\n", msg);
        return 0;
    }
}

static int run_sha3_file_test(const char *msg, const char *expected_hex)
{
    const char *tmpfile = "tmp_nist_sha3.bin";
    FILE *f = fopen(tmpfile, "wb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }
    fwrite(msg, 1, strlen(msg), f);
    fclose(f);

    uint8_t expected[SHA3_256_HASH_SIZE];
    hex_to_bytes(expected_hex, expected, sizeof(expected));

    uint8_t digest[SHA3_256_HASH_SIZE];
    if (sha3_256_file(tmpfile, digest) != 0)
    {
        printf("sha3_256_file failed\n");
        remove(tmpfile);
        return 1;
    }

    remove(tmpfile);

    if (memcmp(digest, expected, sizeof(digest)) == 0)
    {
        printf("SHA3-256 file PASS\n");
        return 0;
    }
    else
    {
        printf("SHA3-256 file FAIL\n");
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

    fails += run_sha3_vector("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    fails += run_sha3_vector("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    fails += run_sha3_file_test("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

    printf("SHA3-256 tests %s\n", (fails == 0) ? "PASSED" : "FAILED");
    return (fails == 0) ? 0 : 2;
}