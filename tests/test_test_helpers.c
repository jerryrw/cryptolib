#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
/* Test the tests: deliberate library/I/O failures must make the AES suite fail.
 * Wrappers apply only to the included vector test, not the linked library. */
#include "test_support.h"
#include "aes256.h"
#include <sys/wait.h>

static enum { NORMAL, ENCRYPT_FAIL, DECRYPT_FAIL, TRUNCATE_OUTPUT,
              OPEN_FAIL, WRITE_FAIL, CLOSE_FAIL, INIT_FAIL, ALLOC_FAIL } mode;
static char last_directory[64];
static int fixture_init(test_fixture *fixture)
{
    int result = test_fixture_init(fixture);
    if (result == 0) strcpy(last_directory, fixture->directory);
    return result;
}
static int encrypt_file(aes256_context *ctx, const char *input, const char *output)
{
    if (mode == ENCRYPT_FAIL) return AES_ERROR_FILE_WRITE;
    return aes256_encrypt_file(ctx, input, output);
}
static int decrypt_file(aes256_context *ctx, const char *input, const char *output)
{
    if (mode == DECRYPT_FAIL) return AES_ERROR_FILE_READ;
    int result = aes256_decrypt_file(ctx, input, output);
    if (mode == TRUNCATE_OUTPUT && result == AES_SUCCESS) {
        FILE *f = fopen(output, "rb+"); CHECK(f);
        CHECK(fseek(f, 0, SEEK_END) == 0);
        long length = ftell(f); CHECK(length > 0);
        CHECK(ftruncate(fileno(f), length - 1) == 0);
        CHECK(fclose(f) == 0);
    }
    return result;
}
static FILE *open_file(const char *path, const char *flags)
{
    if (mode == OPEN_FAIL) return NULL;
    return fopen(path, flags);
}
static size_t write_file(const void *p, size_t size, size_t count, FILE *f)
{
    if (mode == WRITE_FAIL) return 0;
    return fwrite(p, size, count, f);
}
static int close_file(FILE *f)
{
    int result = fclose(f); /* Still release resources when simulating an error. */
    return mode == CLOSE_FAIL ? EOF : result;
}
static int init_aes(aes256_context *ctx, const uint8_t *key, const uint8_t *iv)
{
    if (mode == INIT_FAIL) return AES_ERROR_INVALID_PARAM;
    return aes256_init(ctx, key, iv);
}
static void *allocate(size_t size)
{
    return mode == ALLOC_FAIL ? NULL : malloc(size);
}
#define test_fixture_init fixture_init
#define aes256_encrypt_file encrypt_file
#define aes256_decrypt_file decrypt_file
#define aes256_init init_aes
#define fopen open_file
#define fwrite write_file
#define fclose close_file
#define malloc allocate
#define main aes_vector_main
#include "test_nist_aes256.c"
#undef main
#undef malloc
#undef fclose
#undef fwrite
#undef fopen
#undef aes256_init
#undef aes256_decrypt_file
#undef aes256_encrypt_file
#undef test_fixture_init

static void test_comparison(void)
{
    const char *a[] = {"", "a", "ab", "ab", "ab", "", "ab"};
    const char *b[] = {"", "", "a", "ab", "abc", "a", "ac"};
    for (size_t i = 0; i < sizeof(a) / sizeof(a[0]); i++) {
        FILE *left = tmpfile(), *right = tmpfile(); CHECK(left && right);
        CHECK(fputs(a[i], left) >= 0 && fputs(b[i], right) >= 0);
        rewind(left); rewind(right);
        CHECK(test_files_equal(left, right) == (strcmp(a[i], b[i]) == 0));
        CHECK(fclose(left) == 0 && fclose(right) == 0);
    }
    FILE *left = tmpfile(), *right = tmpfile(); CHECK(left && right);
    CHECK(close(fileno(left)) == 0); /* Force a read error, rather than normal EOF. */
    CHECK(test_files_equal(left, right) == 0);
    CHECK(ferror(left));
    fclose(left); /* Descriptor was intentionally closed, so this may report failure. */
    CHECK(fclose(right) == 0);
}

static void test_always_active_check(void)
{
    int evaluations = 0;
    if (1) CHECK(++evaluations == 1); else evaluations = 99;
    CHECK(evaluations == 1);
    CHECK(fflush(NULL) == 0); /* Do not duplicate buffered output across fork. */
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        CHECK(0); /* Must terminate with failure even when compiled with NDEBUG. */
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
}

int main(void)
{
    test_always_active_check();
    test_comparison();
    for (mode = ENCRYPT_FAIL; mode <= INIT_FAIL; mode++) {
        tests_failed = tests_passed = 0;
        test_file_operations();
        CHECK(tests_failed == 1 && tests_passed == 0);
        CHECK(last_directory[0] && access(last_directory, F_OK) != 0);
    }
    mode = ALLOC_FAIL;
    tests_failed = tests_passed = 0;
    test_large_buffer();
    CHECK(tests_failed == 1 && tests_passed == 0);
    mode = NORMAL;
    tests_failed = tests_passed = 0;
    test_file_operations();
    CHECK(tests_failed == 0 && tests_passed == 1);
    /* Test main itself: printing FAIL must lead to a nonzero process status. */
    mode = ENCRYPT_FAIL;
    tests_failed = tests_passed = 0;
    CHECK(aes_vector_main() == EXIT_FAILURE);
    puts("Test infrastructure regression checks passed");
    return EXIT_SUCCESS;
}
