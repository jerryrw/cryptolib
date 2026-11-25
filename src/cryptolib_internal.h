#ifndef CRYPTOLIB_INTERNAL_H
#define CRYPTOLIB_INTERNAL_H
#include <stddef.h>

/* Private shared helper: no extra library link dependency. Wipe before freeing;
 * volatile keeps these writes observable to the compiler. NULL is a no-op. */
static inline void cryptolib_wipe(void *pointer, size_t length)
{
    if (!pointer) return;
    volatile unsigned char *bytes = (volatile unsigned char *)pointer;
    while (length--) *bytes++ = 0;
}
#endif
