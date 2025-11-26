# A simple cryptographic library for educational use only

## It includes: AES-256 Encryption, MD5 hash, sha256 hash and sha3256 hash in pure C with no external dependencies. Optimized for macOS ARM (Apple Silicon M series processors).

## Features

- ✅ **Pure C Implementation** - No external libraries required
- ✅ **AES-256 Standard** - Follows FIPS-197 specification
- ✅ **CBC Mode** - Cipher Block Chaining with PKCS7 padding
- ✅ **Memory Buffers** - Encrypt/decrypt data in memory
- ✅ **File Operations** - Direct file encryption/decryption
- ✅ **Apple Silicon Ready** - Optimized for macOS ARM (M1/M2/M3/M4)
- ✅ **Comprehensive Tests** - Includes NIST test vectors
- ✅ **Well Documented** - Extensive inline comments
- ✅ **Secure** - Implements secure memory clearing

## Building

### Requirements

- GCC or Clang compiler
- macOS (tested on Apple Silicon, but portable to other platforms)
- Make (optional, but recommended)

### Security Considerations

⚠️ **Important**: This implementation is for educational purposes and includes standard AES-256. For production use, consider:

1. **Key Generation**: Use cryptographically secure random number generators

   - On macOS: `/dev/urandom` or Security framework
   - Never use `rand()` or `srand()` for cryptographic keys

2. **IV Management**:

   - Generate a new IV for each encryption operation
   - Never reuse an IV with the same key
   - IVs don't need to be secret but must be unpredictable

3. **Authenticated Encryption**:

   - Consider using AES-GCM instead of CBC for production
   - CBC mode alone doesn't provide authentication
   - Add HMAC for data integrity verification

4. **Key Storage**:

   - Never hardcode keys in source code
   - Use macOS Keychain for secure key storage
   - Clear keys from memory after use

5. **Side-Channel Attacks**:
   - This implementation is not hardened against timing attacks
   - For high-security applications, use constant-time implementations

## Test Vectors

The implementation includes comprehensive tests:

1. **NIST FIPS-197 Test Vectors** - Official AES-256 test cases
2. **Edge Cases** - Tests for various input sizes and padding scenarios
3. **Large Buffers** - Performance tests with multi-MB data
4. **File Operations** - Complete file encryption/decryption workflows

Run tests with:

```bash
make test
```

## Performance

Approximate performance on Apple M2 (varies by system):

- **Small buffers** (<1KB): ~0.1 ms
- **Medium buffers** (100KB): ~5 ms
- **Large buffers** (1MB): ~40-50 ms
- **Throughput**: ~20-25 MB/s (single-threaded)

## Error Codes

```c
AES_SUCCESS              0   // Operation successful
AES_ERROR_INVALID_PARAM -1   // Invalid parameter passed
AES_ERROR_FILE_OPEN     -2   // Failed to open file
AES_ERROR_FILE_READ     -3   // Failed to read from file
AES_ERROR_FILE_WRITE    -4   // Failed to write to file
AES_ERROR_MEMORY        -5   // Memory allocation failed
```

## Best Practices

1. **Always check return codes**:

   ```c
   if (aes256_init(&ctx, key, iv) != AES_SUCCESS) {
       // Handle error
   }
   ```

2. **Clear sensitive data**:

   ```c
   aes256_secure_zero(key, sizeof(key));
   aes256_secure_zero(&ctx, sizeof(ctx));
   ```

3. **Reset IV for CBC mode**:

   ```c
   // After encryption, if you need to decrypt:
   memcpy(ctx.iv, original_iv, AES_BLOCK_SIZE);
   ```

4. **Allocate enough space for encrypted data**:
   ```c
   // Encryption may add up to one block of padding
   uint8_t *encrypted = malloc(plaintext_len + AES_BLOCK_SIZE);
   ```

## License

This implementation is provided as-is for educational purposes. Feel free to use, modify, and distribute.

## References

- [FIPS-197: AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [RFC 2315: PKCS #7 (Padding)](https://tools.ietf.org/html/rfc2315)

**Note**: This is an educational implementation. For production systems, consider using established libraries like OpenSSL, libsodium, or Apple's CommonCrypto framework.
