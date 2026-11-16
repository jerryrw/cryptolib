#ifndef CRYPTOLIB_TEST_SUPPORT_H
#define CRYPTOLIB_TEST_SUPPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* Unlike assert(), CHECK always evaluates its expression, even with NDEBUG.
 * Evaluate once; report the original expression and its location on failure.
 * do/while makes the macro behave like one statement inside an if/else. */
#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expression); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

/* Each fixture owns three paths inside a newly created private directory. */
typedef struct {
    char directory[64];
    char input[128];
    char encrypted[128];
    char output[128];
} test_fixture;

static inline int test_fixture_init(test_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    strcpy(fixture->directory, "/tmp/cryptolib-test-XXXXXX");
    if (!mkdtemp(fixture->directory)) {
        fixture->directory[0] = '\0';
        return -1;
    }
    /* The fixed template plus each suffix fits in these arrays. */
    snprintf(fixture->input, sizeof(fixture->input), "%s/input", fixture->directory);
    snprintf(fixture->encrypted, sizeof(fixture->encrypted), "%s/encrypted", fixture->directory);
    snprintf(fixture->output, sizeof(fixture->output), "%s/output", fixture->directory);
    return 0;
}

static inline int test_fixture_cleanup(test_fixture *fixture)
{
    if (!fixture->directory[0]) return 0;
    const char *paths[] = {fixture->input, fixture->encrypted, fixture->output};
    int result = 0;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (remove(paths[i]) != 0 && errno != ENOENT) result = -1;
    if (rmdir(fixture->directory) != 0) result = -1;
    return result;
}

/* Reading both bytes together detects a one-byte difference in either length.
 * fgetc uses int so EOF remains distinct from every possible byte value. */
static inline int test_files_equal(FILE *left, FILE *right)
{
    for (;;) {
        int a = fgetc(left), b = fgetc(right);
        if (ferror(left) || ferror(right) || a != b) return 0;
        if (a == EOF) return 1;
    }
}

#endif
