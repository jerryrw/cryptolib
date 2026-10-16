/*
 * Fault injection tests for atomic output. A small wrapper imitates one I/O
 * failure while using real temporary files for all other operations. The crucial
 * oracle is an existing sentinel destination: after every failure its bytes must
 * still match, and temporary files must be gone. Including aes256.c here is an
 * intentional test-only technique; do not also link its normal object into this
 * executable. assert performs checks/setup, so build this file without NDEBUG.
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/* Exercise real filesystem work, injecting one failure at a time. */
/* enum assigns consecutive integer values to named failure modes. Static
 * variables start at zero, so the initial mode is NONE without extra setup. */
enum { NONE, READ_FAIL, WRITE_FAIL, FLUSH_FAIL, SYNC_FAIL, CLOSE_FAIL,
       RENAME_FAIL, FDOPEN_FAIL, OPEN_FAIL, INPUT_CLOSE_FAIL, TEMP_FAIL };
static int failure;
static char last_temporary[256];
static FILE *read_stream, *write_stream;
static FILE *test_fopen(const char *path, const char *mode)
{
    if (failure == OPEN_FAIL) return NULL;
    read_stream = fopen(path, mode);
    return read_stream;
}
static FILE *test_fdopen(int fd, const char *mode)
{
    if (failure == FDOPEN_FAIL) return NULL;
    write_stream = fdopen(fd, mode);
    return write_stream;
}
/* Record the concrete filename after XXXXXX is replaced. Cleanup checks
 * both that path and a directory listing to catch orphaned temporary files. */
static int test_mkstemp(char *path)
{
    last_temporary[0] = 0;
    if (failure == TEMP_FAIL) { errno = EACCES; return -1; }
    int fd = mkstemp(path);
    if (fd >= 0) snprintf(last_temporary, sizeof(last_temporary), "%s", path);
    return fd;
}
static size_t test_fwrite(const void *p, size_t size, size_t n, FILE *f)
{
    if (failure == WRITE_FAIL && f == write_stream) return 0;
    return fwrite(p, size, n, f);
}
static int test_ferror(FILE *f)
{
    return (failure == READ_FAIL && f == read_stream) || ferror(f);
}
static int test_fflush(FILE *f)
{
    if (failure == FLUSH_FAIL && f == write_stream) return EOF;
    return fflush(f);
}
static int test_fsync(int fd)
{
    if (failure == SYNC_FAIL) return -1;
    return fsync(fd);
}
/* Run the real close before returning a simulated close error. This verifies
 * error handling without leaking the stream in the test itself. */
static int test_fclose(FILE *f)
{
    int failed = (failure == CLOSE_FAIL && f == write_stream) ||
                 (failure == INPUT_CLOSE_FAIL && f == read_stream);
    if (f == write_stream) write_stream = NULL;
    if (f == read_stream) read_stream = NULL;
    int result = fclose(f);
    return failed ? EOF : result;
}
static int test_rename(const char *a, const char *b)
{
    if (failure == RENAME_FAIL) return -1;
    return rename(a, b);
}
/* Replace names only while compiling the included implementation. The
 * wrappers above were compiled before these macros, so their calls still refer
 * to real stdio functions rather than recursively calling themselves. */
#define fopen test_fopen
#define fdopen test_fdopen
#define mkstemp test_mkstemp
#define fwrite test_fwrite
#define ferror test_ferror
#define fflush test_fflush
#define fsync test_fsync
#define fclose test_fclose
#define rename test_rename
#include "../src/aes256.c"
#undef fopen
#undef fdopen
#undef mkstemp
#undef fwrite
#undef ferror
#undef fflush
#undef fsync
#undef fclose
#undef rename

/* Write a fixture with known bytes, including embedded zeros if any.
 * The caller supplies its length; this helper does not assume text. */
static void put(const char *path, const void *data, size_t n)
{
    FILE *f = fopen(path, "wb"); assert(f);
    assert(fwrite(data, 1, n, f) == n); assert(fclose(f) == 0);
}
/* Read more than the expected length so unexpected trailing bytes are
 * noticed too. Compare only after verifying the exact number read. */
static void expect(const char *path, const void *data, size_t n)
{
    uint8_t buffer[128]; assert(n <= sizeof(buffer));
    FILE *f = fopen(path, "rb"); assert(f);
    assert(fread(buffer, 1, sizeof(buffer), f) == n);
    assert(memcmp(buffer, data, n) == 0); assert(fclose(f) == 0);
}
/* DIR/readdir enumerate directory entries. strstr searches names for the
 * temporary-file marker. closedir releases the directory handle, like fclose. */
static void no_temporary_files(const char *path)
{
    if (last_temporary[0]) assert(access(last_temporary, F_OK) != 0);
    DIR *dir = opendir(path); assert(dir);
    struct dirent *entry;
    while ((entry = readdir(dir))) assert(strstr(entry->d_name, ".tmp.") == NULL);
    assert(closedir(dir) == 0);
}
int main(void)
{
    char dir[] = "/tmp/cryptolib-file-failures-XXXXXX"; assert(mkdtemp(dir));
    char input[128], encrypted[128], output[128], missing[128];
    snprintf(input, sizeof(input), "%s/input", dir);
    snprintf(encrypted, sizeof(encrypted), "%s/encrypted", dir);
    snprintf(output, sizeof(output), "%s/output", dir);
    snprintf(missing, sizeof(missing), "%s/missing", dir);
    const char message[] = "Preserve the destination on every failure.";
    const char sentinel[] = "existing destination";
    aes256_context ctx; uint8_t key[32] = {0}, iv[16] = {0};
    assert(aes256_init(&ctx, key, iv) == AES_SUCCESS);
    put(input, message, sizeof(message));
    assert(aes256_encrypt_file(&ctx, input, encrypted) == AES_SUCCESS);
/* stat obtains metadata. The octal mask 0777 keeps permission bits; 0600
 * means read/write for the owner only. Leading zero denotes octal in C. */
    struct stat st; assert(stat(encrypted, &st) == 0 && (st.st_mode & 0777) == 0600);
/* An array of function pointers lets the same failure matrix exercise both
 * encryption and decryption. operations[op](...) calls the selected function. */
    int (*operations[])(aes256_context *, const char *, const char *) = {
        aes256_encrypt_file, aes256_decrypt_file};
    for (size_t op = 0; op < 2; op++) {
        const char *source = op ? encrypted : input;
/* Reset the sentinel and activate one failure per trial. Turn injection off
 * before examining results, so a deliberately failed open does not break
 * the test own verification code. */
        for (int f = READ_FAIL; f <= TEMP_FAIL; f++) {
            put(output, sentinel, sizeof(sentinel));
            failure = f;
            assert(operations[op](&ctx, source, output) != AES_SUCCESS);
            failure = NONE;
            expect(output, sentinel, sizeof(sentinel));
            no_temporary_files(dir);
        }
        assert(operations[op](&ctx, missing, output) == AES_ERROR_FILE_OPEN);
        expect(output, sentinel, sizeof(sentinel));
        /* An existing directory cannot be replaced with a regular file. */
        assert(operations[op](&ctx, source, dir) == AES_ERROR_FILE_WRITE);
        no_temporary_files(dir);
    }
    /* Malformed ciphertext after a complete block cannot publish partial plaintext. */
    uint8_t malformed[49] = {0};
    put(encrypted, malformed, sizeof(malformed));
    assert(aes256_decrypt_file(&ctx, encrypted, output) != AES_SUCCESS);
    expect(output, sentinel, sizeof(sentinel));
    /* Valid block lengths with bad final padding must also preserve output. */
    uint8_t block[16], ciphertext[48] = {0};
    memset(block, 'A', sizeof(block));
    assert(aes256_encrypt_block(&ctx, block, ciphertext + 16) == AES_SUCCESS);
    block[15] = 2; /* The preceding 'A' is not a matching padding byte. */
    for (size_t i = 0; i < sizeof(block); i++) block[i] ^= ciphertext[16 + i];
    assert(aes256_encrypt_block(&ctx, block, ciphertext + 32) == AES_SUCCESS);
    put(encrypted, ciphertext, sizeof(ciphertext));
    assert(aes256_decrypt_file(&ctx, encrypted, output) == AES_ERROR_INVALID_PARAM);
    expect(output, sentinel, sizeof(sentinel));
    assert(unlink(output) == 0);
    assert(aes256_decrypt_file(&ctx, encrypted, output) != AES_SUCCESS);
    assert(access(output, F_OK) != 0);
    no_temporary_files(dir);
    /* Successful replacement and same-path round-trip are supported. */
    assert(aes256_encrypt_file(&ctx, input, input) == AES_SUCCESS);
    assert(aes256_decrypt_file(&ctx, input, input) == AES_SUCCESS);
    expect(input, message, sizeof(message));
    aes256_cleanup(&ctx);
    assert(unlink(input) == 0 && unlink(encrypted) == 0 && rmdir(dir) == 0);
    puts("Atomic file failure tests passed");
    return 0;
}
