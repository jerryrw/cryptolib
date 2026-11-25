#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
/* Test-only substitutions imitate errors that regular temporary files rarely
 * produce. No real resources leak: the close wrapper always really closes. */
#include "test_support.h"
#include "md5.h"
#include "sha256.h"
#include "sha3.h"
static int fail_read, fail_close;
static int test_error(FILE *f) { return fail_read || ferror(f); }
static int test_close(FILE *f) { int result = fclose(f); return fail_close ? EOF : result; }
#define ferror test_error
#define fclose test_close
#include "../src/md5.c"
#include "../src/sha256.c"
#include "../src/sha3_256.c"
#undef ferror
#undef fclose

int main(void)
{
    test_fixture fixture;
    CHECK(test_fixture_init(&fixture) == 0);
    FILE *f = fopen(fixture.input, "wb"); CHECK(f);
    CHECK(fputs("hash file failure fixture", f) >= 0); CHECK(fclose(f) == 0);
    int (*files[])(const char *, uint8_t *) = {md5_file, sha256_file, sha3_256_file};
    for (size_t i = 0; i < 3; i++) {
        for (int mode = 0; mode < 2; mode++) {
            uint8_t output[32], sentinel[32];
            memset(output, 0xA5, sizeof(output)); memcpy(sentinel, output, sizeof(output));
            fail_read = mode == 0; fail_close = mode == 1;
            CHECK(files[i](fixture.input, output) == CRYPTOLIB_ERROR_FILE_READ);
            CHECK(memcmp(output, sentinel, sizeof(output)) == 0);
        }
    }
    fail_read = fail_close = 0;
    CHECK(test_fixture_cleanup(&fixture) == 0);
    puts("Hash read/close failure checks passed");
    return 0;
}
