/*
 * Create initial inputs that get the fuzzer beyond superficial length checks.
 * These deterministic ciphertexts use a zero test key and IV, matching the fuzz
 * harness. They are test fixtures, not a demonstration of key generation.
 * argv[1] names a directory Make has already created; each file is one fuzz input.
 */

#include "aes256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* argc counts command-line arguments, including the program name. argv is
 * an array of pointers to zero-terminated argument strings. */
int main(int argc, char **argv)
{
    if (argc != 2) return EXIT_FAILURE;
    aes256_context ctx;
    uint8_t key[32] = {0}, iv[16] = {0}, input[273], encrypted[288];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)i;
    if (aes256_init(&ctx, key, iv) != AES_SUCCESS) return EXIT_FAILURE;
/* Lengths around 16-byte boundaries exercise PKCS7 extra-block behavior.
 * The largest ciphertext is 288 bytes, fitting the local output array. */
    size_t sizes[] = {0,1,15,16,17,31,32,135,136,137,272,273};
    for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
        size_t n; char path[1024];
        if (aes256_encrypt_buffer_checked(&ctx, input, sizes[i], encrypted, sizeof(encrypted), &n) != AES_SUCCESS)
            return EXIT_FAILURE;
/* snprintf limits writes to sizeof(path). Its return is how many characters
 * would be required without the limit, so len >= sizeof(path) means truncation.
 * Check negativity before converting the signed result to unsigned size_t. */
        int len = snprintf(path, sizeof(path), "%s/valid-%zu", argv[1], sizes[i]);
        if (len < 0 || (size_t)len >= sizeof(path)) return EXIT_FAILURE;
        FILE *f = fopen(path, "wb"); if (!f) return EXIT_FAILURE;
        size_t written = fwrite(encrypted, 1, n, f);
        if (fclose(f) != 0 || written != n) return EXIT_FAILURE;
    }
    aes256_cleanup(&ctx);
    return EXIT_SUCCESS;
}
