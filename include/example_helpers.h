/*
 * Shared helper for the example programs, not part of the cryptographic API.
 * static inline lets each .c file include this small function without defining
 * conflicting external linker symbols. inline allows, but does not require, the
 * compiler to place its body at call sites. The OS still supplies the randomness.
 */

#ifndef EXAMPLE_HELPERS_H
#define EXAMPLE_HELPERS_H

#include <stdint.h>
#include <stdio.h>

/* Read all requested bytes from the OS random source, or fail closed. */
static inline int example_random_bytes(uint8_t *out, size_t len)
{
/* The path names the operating system random-byte source on macOS/Linux.
 * "rb" means read binary. FILE * is a stream handle; NULL means open failed. */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
/* out is caller-owned storage for len bytes. sizeof cannot recover its
 * capacity from the pointer, so the caller must pass a truthful length. A short
 * read fails rather than pretending that the unfilled bytes are random. */
    size_t n = fread(out, 1, len, f);
    int failed = ferror(f);
/* Close even if reading failed. Evaluating fclose inside a short-circuit
 * boolean expression could skip it and leak a descriptor. */
    int closed = fclose(f);
    return n == len && !failed && closed == 0 ? 0 : -1;
}

#endif
