/*
 * Test the example applications, including paths difficult to trigger by hand.
 * Wrappers below replace selected calls only while including the example source.
 * The real library remains linked normally. Macros act as compile-time name
 * substitution; failure flags choose behavior at runtime. No production code is
 * modified to enable injection. assert failures abort the test; do not set NDEBUG.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include "aes256.h"

/* Inject failures at the examples' OS-randomness boundary, not the library. */
static int fail_random, fail_short_read, fail_read_error, fail_close;
static int corrupt_plaintext;
static char temporary_dir[128];
/* Remember the actual generated path so we can later prove cleanup removed
 * it, including when a failure happens after directory creation. */
static char *test_mkdtemp(char *path)
{
    char *result = mkdtemp(path);
    if (result) snprintf(temporary_dir, sizeof(temporary_dir), "%s", result);
    return result;
}
/* Keep decryption real, then flip one returned bit. The example must detect
 * a mismatch and fail even when the API itself reported success. */
static int test_decrypt(aes256_context *ctx, const uint8_t *input, size_t n,
                        uint8_t *output, size_t capacity, size_t *length)
{
    int result = aes256_decrypt_buffer_checked(ctx, input, n, output, capacity, length);
    if (corrupt_plaintext && result == AES_SUCCESS && *length) output[0] ^= 1;
    return result;
}
static FILE *random_stream;
/* Intercept only the random-byte path. All other files still use normal
 * stdio, which keeps the fixture close to the real example behavior. */
static FILE *test_open(const char *path, const char *mode)
{
    if (strcmp(path, "/dev/urandom") == 0) {
        if (fail_random) { errno = EIO; return NULL; }
        random_stream = fopen(path, mode);
        return random_stream;
    }
    return fopen(path, mode);
}
/* Imitate an incomplete random-byte read. Returning fewer items is legal
 * for fread and must not be mistaken for a complete key. */
static size_t test_read(void *p, size_t size, size_t count, FILE *f)
{
    if (f == random_stream && fail_short_read)
        return fread(p, size, count ? count - 1 : 0, f);
    return fread(p, size, count, f);
}
static int test_error(FILE *f)
{
    return (f == random_stream && fail_read_error) || ferror(f);
}
/* Actually close the stream before faking an error; the test should not
 * leak resources just because it is checking someone else cleanup path. */
static int test_close(FILE *f)
{
    int failed = f == random_stream && fail_close;
    if (f == random_stream) random_stream = NULL;
    int result = fclose(f);
    return failed ? EOF : result;
}

/* These macros affect only subsequent source text. Including the .c file
 * makes its static helpers callable by tests in this translation unit. #undef
 * restores normal names afterward; otherwise test setup would also be mocked. */
#define fopen test_open
#define fread test_read
#define ferror test_error
#define fclose test_close
#define mkdtemp test_mkdtemp
#define aes256_decrypt_buffer_checked test_decrypt
#define main aes_example_main
#include "../src/example-aes.c"
#undef main
#undef mkdtemp
#undef aes256_decrypt_buffer_checked
#undef fopen
#undef fread
#undef ferror
#undef fclose

int general_example_main(void);
void general_example_set_random_failure(int failed);

/* Each row pairs two file contents: equal, empty, shorter, and longer.
 * tmpfile creates an automatically removed stream; rewind resets its read position. */
static void test_comparison(void)
{
    const char *a[] = {"", "a", "ab", "ab", "ab", ""};
    const char *b[] = {"", "", "a", "ab", "abc", "a"};
    for (size_t i = 0; i < 6; i++) {
        FILE *left = tmpfile(), *right = tmpfile(); assert(left && right);
        assert(fputs(a[i], left) >= 0 && fputs(b[i], right) >= 0);
        rewind(left); rewind(right);
        assert(files_match(left, right) == (strcmp(a[i], b[i]) == 0));
        assert(fclose(left) == 0 && fclose(right) == 0);
    }
    FILE *left = tmpfile(), *right = tmpfile(); assert(left && right);
/* Deliberately invalidate one underlying descriptor to force a read error.
 * The stream still needs fclose for its C-library resources; close and fclose
 * are different layers of ownership, normally managed together by fclose. */
    int fd = fileno(left);
    assert(close(fd) == 0);
    assert(!files_match(left, right));
    assert(ferror(left));
    fclose(left); /* The intentionally closed descriptor makes fclose fail. */
    assert(fclose(right) == 0);
}

/* Inspect the entry point status and captured output on failure. */
/* entry is a pointer to a no-argument function returning int. Save standard
 * output with dup, redirect it with dup2, call entry, then restore it before
 * checking results. fflush prevents buffered output from crossing redirects. */
static void check_failure_status(int (*entry)(void), const char *success)
{
    FILE *capture = tmpfile(); assert(capture);
    assert(fflush(stdout) == 0);
    int saved = dup(STDOUT_FILENO); assert(saved >= 0);
    assert(dup2(fileno(capture), STDOUT_FILENO) >= 0);
    int result = entry();
    assert(fflush(stdout) == 0);
    assert(dup2(saved, STDOUT_FILENO) >= 0);
    assert(close(saved) == 0);
    assert(result == EXIT_FAILURE);
    rewind(capture);
/* Leave one byte for a zero terminator so strstr can search safely. The
 * zero initializer supplies it even though fread does not terminate text. */
    char output[4096] = {0};
    size_t n = fread(output, 1, sizeof(output) - 1, capture);
    assert(n < sizeof(output) - 1 && !ferror(capture));
    assert(strstr(output, success) == NULL);
    assert(fclose(capture) == 0);
}

int main(void)
{
    test_comparison();
    uint8_t key[32];
    fail_random = 1;
    assert(example_random_bytes(key, sizeof(key)) != 0);
    check_failure_status(aes_example_main, "All AES examples completed successfully");
    assert(example_file() == -1);
    assert(temporary_dir[0] && access(temporary_dir, F_OK) != 0);
    fail_random = 0;
    corrupt_plaintext = 1;
    check_failure_status(aes_example_main, "All AES examples completed successfully");
    corrupt_plaintext = 0;
    assert(example_buffer("overflow", SIZE_MAX) == -1);
    fail_short_read = 1;
    assert(example_random_bytes(key, sizeof(key)) != 0);
    fail_short_read = 0; fail_read_error = 1;
    assert(example_random_bytes(key, sizeof(key)) != 0);
    fail_read_error = 0; fail_close = 1;
    assert(example_random_bytes(key, sizeof(key)) != 0);
    fail_close = 0;
    general_example_set_random_failure(1);
    check_failure_status(general_example_main, "AES-256 CBC round-trip passed");
    general_example_set_random_failure(0);
    puts("Example failure tests passed");
    return 0;
}
