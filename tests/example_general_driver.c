/*
 * Compile the general example as part of the example test executable.
 * Renaming main avoids a duplicate entry point. Only this translation unit sees
 * the fopen replacement, which lets tests simulate unavailable OS randomness.
 * Other test code uses the exported renamed entry point and setter.
 */

#include <stdio.h>
#include <string.h>
static int fail_random;
static FILE *test_open(const char *path, const char *mode)
{
    if (fail_random && strcmp(path, "/dev/urandom") == 0) return NULL;
    return fopen(path, mode);
}
/* The macro applies inside the included helper header too. This file has
 * its own preprocessor state, separate from tests/test_examples.c. */
#define fopen test_open
#define main general_example_main
#include "../src/example.c"
#undef main
#undef fopen
/* An ordinary externally visible function lets the test executable control
 * this file private static failure flag without exposing the flag itself. */
void general_example_set_random_failure(int failed) { fail_random = failed; }
