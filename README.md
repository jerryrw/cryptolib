# A simple cryptographic library for educational use only

Pure C implementations of AES-256, SHA-256, SHA3-256, MD5, and RC4, with no external library dependencies.

This is an educational project for myself to learn many things including makefiles and working with MacOS libraries.

The project builds separate shared libraries, example programs, and tests. It is tested on macOS Apple Silicon; GitHub Actions is configured to check both macOS and Linux builds. Hosted CI results are available after pushing the changes.

## Features

- ✅ **Pure C Implementation** - No external libraries required
- ✅ **AES-256 Standard** - Follows FIPS-197 specification
- ✅ **CBC Mode** - Cipher Block Chaining with PKCS7 padding
- ✅ **Memory Buffers** - Encrypt/decrypt data in memory
- ✅ **File Operations** - Direct file encryption/decryption
- ✅ **Native Builds** - Compiler optimization for the build machine with `-march=native` and `-mtune=native`
- ✅ **Tests** - Known-answer vectors, boundary cases, and malformed-input regressions
- ✅ **Well Documented** - Extensive inline comments
- ✅ **Memory Clearing** - Explicit helpers for wiping AES keys and contexts

## Learning the Code

Start with [Reading the code as a C beginner](docs/READING_THE_CODE.md). It gives
a reading order and explains pointers, array lengths, memory ownership, bit
operations, file streams, tests, and the build process. Inline comments throughout
`src/`, `include/`, `tests/`, and the Makefile explain the local decisions.

## Project Layout

- `src/`: library implementations and example programs
- `include/`: library headers and `example_helpers.h`, the examples’ shared random-byte helper
- `tests/`: test vectors, regression and failure tests, and the AES fuzz harness
- `obj/`: generated objects, dependencies, sanitizer binaries, and fuzz artifacts
- `.github/workflows/ci.yml`: macOS and Linux checks on pushes and pull requests
- `Makefile`: build libraries, examples, and tests in the project root

## Building

### Requirements

- GCC or Clang compiler
- macOS or Linux (macOS Apple Silicon tested)
- GNU Make

```bash
make -j4                 # Build libraries, the general example, and run tests
make example-aes         # Build the AES-specific example
make aes256             # Build a single library
make clean              # Remove generated objects, dependencies, libraries, and executables
```

Shared libraries (`lib*.dylib` on macOS or `lib*.so` on Linux) and executables
are written to the project root. Intermediate `.o` and `.d` files go in `obj/`.
Header dependencies are tracked automatically. To disable machine-specific
optimization, override the compiler flags:

```bash
make clean
make CFLAGS="-std=c11 -Wall -O2"
```

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

The suite includes:

1. Known-answer vectors for AES-256, MD5, SHA-256, SHA3-256, and RC4.
2. SHA3 boundary and multi-block inputs, with independently generated expected digests.
3. AES buffer and file round-trips, including empty plaintext and chunk boundaries.
4. Rejection of malformed AES lengths and padding, plus RC4 invalid parameters.
5. Standalone compilation of every header in `include/`.
6. Example randomness failures, unequal-length file comparisons, read errors,
   mismatch reporting, and failure exit statuses.
7. Atomic output preservation under malformed input and injected open, read,
   write, flush, sync, close, temporary-file, and rename failures.

Run tests with:

```bash
make test
```

## Development Checks

```bash
make check              # Full test suite and both example programs
make sanitize           # Tests and examples with ASan and UBSan
```

Sanitizer binaries are built separately in `obj/sanitize/`; they do not change
the normal build's compiler flags. Use `CC=clang` or `CC=gcc` to select a compiler
with the sanitizer runtimes installed.

GitHub Actions runs `make check` and `make sanitize` on macOS and Linux. The Linux
job also runs the fuzz smoke test. These jobs run on pushes, pull requests, or a
manual workflow dispatch.

### Fuzzing AES Decryption

A Clang distribution with libFuzzer is required. Select it with `FUZZ_CC` if the
default `clang` lacks that runtime (for example, some Apple Clang installations).

```bash
make fuzz-smoke FUZZ_CC=/path/to/clang   # Default: 2,000 runs
make fuzz-smoke FUZZ_CC=/path/to/clang FUZZ_RUNS=10000
make fuzz FUZZ_CC=/path/to/clang         # Build and populate valid seed inputs
obj/fuzz/aes_decrypt -max_total_time=60 -max_len=4096 -artifact_prefix=obj/fuzz/ obj/fuzz/corpus
```

The harness checks arbitrary ciphertext, insufficient output capacities, and
re-encryption of successfully decrypted inputs. Both address and undefined
behavior sanitizers are enabled. The corpus and crash artifacts live under
`obj/fuzz/` and are preserved by `make clean` for investigation and later runs.

## Running the Examples

```bash
make example example-aes
./example
./example-aes
```

`example` demonstrates SHA3-256, SHA-256, MD5, AES-256 CBC, and RC4.
MD5 and RC4 are included as legacy educational demonstrations.
`example-aes` demonstrates small and large buffers, temporary file encryption,
and a deterministic FIPS-197 block vector. Both programs check failures and
return a nonzero exit status on error. Keys come from `/dev/urandom` and are
cleared after use; the file example removes its private temporary directory.

## Performance

Run `./example-aes` to measure encryption CPU time and throughput for its
1 MiB buffer example. Results depend on the machine, compiler flags, and load.

## Error Codes

```c
AES_SUCCESS              0   // Operation successful
AES_ERROR_INVALID_PARAM -1   // Invalid parameter, ciphertext length, or padding
AES_ERROR_FILE_OPEN     -2   // Failed to open file
AES_ERROR_FILE_READ     -3   // Failed to read from file
AES_ERROR_FILE_WRITE    -4   // Failed to write to file
AES_ERROR_MEMORY        -5   // Memory allocation failed
AES_ERROR_RANDOM        -6   // Secure IV generation failed
AES_ERROR_BUFFER_TOO_SMALL -7 // Output capacity is insufficient
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
   aes256_cleanup(&ctx);
   ```

3. **Manage IVs explicitly**:

   Passing `NULL` as the IV to `aes256_init` generates an IV using OS randomness.
   Buffer operations leave `ctx.iv` unchanged, so decrypting the same ciphertext
   with the same context needs no IV reset. Initialize with a fresh IV for each
   new encryption operation. File encryption prepends the IV; file decryption
   reads it from the input file.

4. **Use the capacity-checked buffer API**:

   ```c
   size_t capacity = 0, encrypted_len = 0;
   if (aes256_encrypted_size(plaintext_len, &capacity) != AES_SUCCESS) {
       return AES_ERROR_INVALID_PARAM; // Size would overflow.
   }
   uint8_t *encrypted = malloc(capacity);
   if (!encrypted) {
       return AES_ERROR_MEMORY;
   }
   int result = aes256_encrypt_buffer_checked(
       &ctx, plaintext, plaintext_len, encrypted, capacity, &encrypted_len);
   // Use encrypted only when result == AES_SUCCESS.
   aes256_secure_zero(encrypted, capacity);
   free(encrypted);
   ```

For `aes256_decrypt_buffer_checked`, supply the actual output capacity. It must
be at least the ciphertext length, including padding. Both checked operations
set the output length to zero on failure; insufficient capacity returns
`AES_ERROR_BUFFER_TOO_SMALL` without writing output. Exact in-place operation is
supported; partially overlapping buffers are not supported. The original buffer
functions remain available for compatibility but cannot verify allocation sizes.

AES decryption rejects empty ciphertext, non-block-aligned lengths, and invalid
PKCS7 padding. An encrypted empty plaintext still contains one padding block.
Padding validation does not authenticate ciphertext.

### Atomic File Output

Both file operations write a private temporary file beside the destination,
flush and sync its contents, close it, and rename it into place only on success.
Errors preserve any existing destination, and failed temporary output is removed.
Input and output may name the same path. The file format remains the 16-byte IV
followed by CBC ciphertext with PKCS7 padding.

Successful replacement creates a new file with mode `0600`; it does not preserve
the old destination's permissions or inode. Atomic replacement is not a guarantee
of directory durability across power loss, and a forcibly terminated process can
leave a temporary file behind.

## License

MIT License. See [LICENSE.md](LICENSE.md) for the terms.

## References

- [FIPS-197: AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [NIST Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [RFC 2315: PKCS #7 (Padding)](https://tools.ietf.org/html/rfc2315)

**Note**: This is an educational implementation. For production systems, consider using established libraries like OpenSSL, libsodium, or Apple's CommonCrypto framework.
