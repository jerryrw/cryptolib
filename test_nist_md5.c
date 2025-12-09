// ...new file...
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "include/md5.h"

/* ANSI color codes for output */
#define COLOR_GREEN "\x1b[32m"
#define COLOR_RED "\x1b[31m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET "\x1b[0m"

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

static int run_md5_vector(const char *msg, const char *expected_hex)
{
    uint8_t expected[16];
    if (hex_to_bytes(expected_hex, expected, sizeof(expected)) != 0)
    {
        printf("Invalid expected hex\n");
        return 1;
    }

    uint8_t digest[16];
    MD5_CTX ctx;
    md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)msg, strlen(msg));
    md5_final(&ctx, digest);

    if (memcmp(digest, expected, sizeof(digest)) != 0)
    {
        printf(COLOR_RED "✗  MD5 FAIL:" COLOR_RESET "\"%s\"\n", msg);
        printf("  got     : ");
        print_hex(digest, sizeof(digest));
        printf("\n");
        printf("  expected: %s\n", expected_hex);
        return 1;
    }
    else
    {
        printf(COLOR_GREEN "✓ MD5 PASS:" COLOR_RESET "\"%s\"\n", msg);
        return 0;
    }
}

static int run_md5_file_test(const char *msg, const char *expected_hex)
{
    const char *tmpfile = "tmp_nist_md5.bin";
    FILE *f = fopen(tmpfile, "wb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }
    fwrite(msg, 1, strlen(msg), f);
    fclose(f);

    uint8_t expected[16];
    hex_to_bytes(expected_hex, expected, sizeof(expected));

    uint8_t digest[16];
    if (md5_file(tmpfile, digest) != 0)
    {
        printf("md5_file failed\n");
        remove(tmpfile);
        return 1;
    }

    remove(tmpfile);

    if (memcmp(digest, expected, sizeof(digest)) == 0)
    {
        printf(COLOR_GREEN "✓ MD5 file PASS" COLOR_RESET "\n");
        return 0;
    }
    else
    {
        printf(COLOR_RED "✗  MD5 file FAIL" COLOR_RESET "\n");
        printf("  got     : ");
        print_hex(digest, sizeof(digest));
        printf("\n");
        printf("  expected: %s\n", expected_hex);
        return 1;
    }
}

int main(void)
{
    printf(COLOR_YELLOW "╔════════════════════════════════════════╗\n");
    printf("║   MD5 Test Vector Suite                ║\n");
#ifdef __APPLE__
    printf("║   macOS ARM (Apple Silicon) Build      ║\n");
#elif __linux__
    printf("║   Linux Build                          ║\n");
#endif
    printf("╚════════════════════════════════════════╝\n" COLOR_RESET);

    int fails = 0;

    fails += run_md5_vector("", "d41d8cd98f00b204e9800998ecf8427e");
    fails += run_md5_vector("a", "0cc175b9c0f1b6a831c399e269772661");
    fails += run_md5_vector("abc", "900150983cd24fb0d6963f7d28e17f72");
    fails += run_md5_vector("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    fails += run_md5_vector("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
    fails += run_md5_vector("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f");
    fails += run_md5_vector("12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                            "57edf4a22be3c955ac49da2e2107b67a");
    fails += run_md5_file_test("abc", "900150983cd24fb0d6963f7d28e17f72");

    printf("MD5 tests %s\n", (fails == 0) ? COLOR_GREEN "✓ PASSED" COLOR_RESET : COLOR_RED "✗  FAILED" COLOR_RESET);
    printf("\n" COLOR_YELLOW "═══════════════════════════════════════\n" COLOR_RESET);
    return (fails == 0) ? 0 : 2;
}