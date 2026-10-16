/*
 * libFuzzer repeatedly calls LLVMFuzzerTestOneInput with bytes it mutates.
 * There is no main here; the fuzzing runtime supplies it. data is borrowed input
 * valid for size bytes. Reject oversized cases to bound work/memory per trial.
 * The oracles are: no memory error, no write on capacity failure, zero output
 * length on error, and exact re-encryption when padding is valid. Assertions must
 * stay enabled. Finding no crash in a bounded run is not a proof of correctness.
 */

#include "aes256.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;
    uint8_t key[32] = {0}, iv[16] = {0};
    aes256_context ctx;
    assert(aes256_init(&ctx, key, iv) == AES_SUCCESS);
    uint8_t *output = malloc(size ? size : 1);
    assert(output);
/* Start with a nonzero sentinel: an error path must explicitly replace it
 * with zero, not accidentally pass because it already happened to be zero. */
    size_t length = 123;
    int result = aes256_decrypt_buffer_checked(&ctx, data, size, output, size, &length);
/* For valid padding, re-encrypting with the same key and IV must reproduce
 * every original ciphertext byte. This is an invariant, a property that must
 * hold for all successful inputs even when no expected plaintext is known. */
    if (result == AES_SUCCESS) {
        assert(length < size && size - length <= AES_BLOCK_SIZE);
        size_t capacity;
        assert(aes256_encrypted_size(length, &capacity) == AES_SUCCESS && capacity == size);
        uint8_t *encrypted = malloc(capacity); assert(encrypted);
        size_t enc_len;
        assert(aes256_encrypt_buffer_checked(&ctx, output, length, encrypted, capacity, &enc_len) == AES_SUCCESS);
        assert(enc_len == size && memcmp(encrypted, data, size) == 0);
        free(encrypted);
    } else assert(length == 0);
/* Repeat with capacity one byte too small and a recognizable fill pattern.
 * Any change means the checked API wrote before validating capacity. */
    if (size > 0) {
        memset(output, 0xA5, size);
        result = aes256_decrypt_buffer_checked(&ctx, data, size, output, size - 1, &length);
        assert(result != AES_SUCCESS && length == 0);
        for (size_t i = 0; i < size; i++) assert(output[i] == 0xA5);
    }
    aes256_cleanup(&ctx);
    free(output);
    return 0;
}
