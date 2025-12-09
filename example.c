
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdint.h>
#include "include/sha3.h"
#include "include/sha256.h"
#include "include/md5.h"

// typedef uint8_t u8;
// typedef uint32_t u32;

/* Example usage */
int main()
{
    SHA256_CTX ctx;
    const char *msg = "The quick brown fox jumps over the lazy dog";
    size_t msglen;
    u8 hash[32];

    /* Hash a string */
    sha3_256_string(msg, hash);
    printf("SHA-3-256('%s') = ", msg);
    sha3_256_print(hash);

    /* Hash empty string (known test vector) */
    sha3_256((const u8 *)"", 0, hash);
    printf("SHA-3-256(\"\") = ");
    sha3_256_print(hash); // Should be: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

    /* Hash a file (replace with real path) */
    // if (sha3_256_file("myfile.bin", hash) == 0) {
    //     printf("File hash: ");
    //     sha3_256_print(hash);
    // }

    return 0;
}