# Reading this project as a C beginner

The comments in the source explain local decisions. This guide connects those
pieces and suggests a reading order. The algorithms are educational implementations;
understanding their C mechanics does not make them production cryptography.

## Suggested reading order

1. Read `src/example.c` for how a program calls the library. Read the corresponding
   declarations in `include/` alongside each call.
2. Read `src/example-aes.c` for buffer allocation, checked sizes, error returns,
   file handles, and one shared cleanup path.
3. Read `src/sha256.c`: follow `init`, `update`, and `final` before studying the
   bit operations inside `transform`.
4. Read `src/md5.c` to compare a different streaming hash and byte order.
5. Read `src/sha3_256.c` for the sponge construction and 64-bit lane representation.
6. Read `src/aes256.c`: start with the checked buffer functions, then block
   encryption, its transformation helpers, and finally file output.
7. Read `src/arcfour.c` for a small example of mutable state and heap ownership.
8. Read `tests/test_regressions.c`, then the fault-injection and fuzz tests.
   Their extra preprocessor machinery is for testing, not ordinary application code.
9. Read the Makefile comments to connect source files, object files, libraries,
   executable programs, and the CI workflow.

`oldstuff/` is an archive of earlier build notes and files. It is not part of the
current build or the commented walkthrough.

## What a header does

A `.h` file declares types, constants, and function signatures. A `.c` file defines
what functions do. `#include "aes256.h"` asks the preprocessor to insert that
header before compiling. `-Iinclude` tells the compiler where to find it.

Each `.c` file and its included text form a translation unit. The compiler checks
that unit and emits an object file. The linker then resolves calls to functions
in other objects or libraries. Including a declaration alone does not supply its
implementation to the linker.

Include guards (`#ifndef`, `#define`, `#endif`) and `#pragma once` prevent the same
header's type definitions from being processed repeatedly within one unit.
A `static` function or file-scope variable is private to its translation unit.
A function declared in a header without `static` normally refers to an externally
linked implementation. The example helper is `static inline` so each including
unit can have its own small implementation without duplicate external symbols.

## Values, pointers, arrays, and contexts

```c
aes256_context ctx = {0};
uint8_t key[AES_KEY_SIZE];
size_t written = 0;
```

`ctx` is a struct: one object grouping a key schedule and an IV. `{0}` initializes
its members to zero. It is not a substitute for calling `aes256_init`.
`key` is an array with room for 32 unsigned bytes. Uninitialized local arrays do
not contain useful values; fill this one with random bytes before using it.
`size_t` is an unsigned type suitable for sizes and indexes.

`&ctx` means the address of `ctx`. Passing that address lets a function update the
original object. If `p` points to a struct, `p->iv` accesses its IV member; this is
another spelling of `(*p).iv`. If `output_len` points to `written`, assigning
`*output_len = 16` changes `written` in the calling function.

An array usually becomes a pointer to its first element when passed to a
function. The pointer has no allocation-size metadata. Even a parameter written
`uint8_t hash[32]` does not allocate 32 bytes or enforce a bound.

`sizeof(array)` in the scope of an actual array reports its complete size.
`sizeof(pointer)` reports the pointer's size, not the pointed-to allocation.
`sizeof(*p)` reports the size of one object of the pointed-to type.

`const uint8_t *input` means the function cannot modify input bytes through that
pointer. It does not mean that the address is always valid or that the storage
can never be modified through another pointer. `NULL` means no object is pointed
to; dereference it only when the API explicitly permits no object, usually by
skipping the dereference entirely for an empty input.

## Binary data versus strings

A C string ends at the first zero byte. Binary plaintext, ciphertext, keys, and
digests can contain zero anywhere. Track their lengths explicitly. `strlen`
measures text up to its terminator; it cannot measure arbitrary ciphertext.

`memcpy(destination, source, n)` copies exactly `n` bytes and requires sufficient,
nonoverlapping storage. `memcmp(a, b, n)` returns zero when those bytes match.
Hex printing produces two text characters per byte, making binary output readable.

## Ownership and cleanup

Local arrays and structs have automatic storage duration: they remain valid until
their enclosing block exits. Do not return pointers to them for use afterward,
and do not pass them to `free`.

`malloc(n)` obtains heap storage. Check for `NULL`, retain the allocation size,
and eventually call `free` exactly once. Freeing does not erase data, and accessing
an allocation after freeing it is invalid. Wipe sensitive material before freeing
it. The AES cleanup function wipes a context but does not release its storage.

`rc4_init` returns an owned context that needs `rc4_free`. `rc4_encrypt` returns a
separate owned buffer that needs `free`. Most other APIs borrow caller buffers;
they do not allocate output or transfer ownership.

The examples initialize resource pointers to `NULL` and use `goto cleanup` to
release everything in one place. This keeps cleanup consistent after failure at
any setup step. `free(NULL)` is safe. Closing an already closed `FILE *` is not:
reset a pointer after releasing it when more cleanup code might inspect it.

## Sizes, integers, and bit operations

Unsigned arithmetic wraps. If `len + padding` would exceed `SIZE_MAX`, it could
become a small number and cause an undersized allocation. The size helper checks
`len > SIZE_MAX - padding` before adding. This is different from the intentional
modulo arithmetic on `uint32_t` words inside a hash algorithm.

`^` is bitwise XOR, `&` AND, `|` OR, and `~` NOT. `<<` and `>>` shift bits. These
are different from the logical `&&` and `||` operators, which work on truth
values and skip evaluating their right operand when the result is already known.
A rotation combines two shifts so bits wrap around rather than being discarded.

Small integer types such as `uint8_t` are promoted during arithmetic, often to
signed `int`. Cast to a sufficiently wide unsigned type *before* a large shift.
The explicit casts in hash word loading are needed for correctness, not style.

Little-endian encodes a word's least significant byte first; big-endian encodes
its most significant byte first. MD5 and SHA3 use little-endian word/lane
encodings here; SHA-256 uses big-endian. Explicit byte assembly makes these rules
independent of the CPU's native byte order.

## Following the algorithms

For a streaming hash, `init` establishes the fixed starting state. `update`
consumes bytes and retains incomplete blocks. `final` adds algorithm-specific
padding and the appropriate ending information, then writes the digest. Hashing
the same byte sequence in different chunk sizes should give the same result.

AES encrypts exactly 16 bytes at a time with an expanded key. CBC XORs each
plaintext block with the previous ciphertext block before encryption, starting
with the IV. During decryption, save each ciphertext block before overwriting it
with plaintext. PKCS7 fills unused block space with repeated padding-length bytes;
whole-block messages need an extra padding block. Padding checks are not message
authentication.

RC4 produces a byte stream by repeatedly modifying its context. XORing with that
stream encrypts, and XORing with the same stream again decrypts. Separate contexts
must begin with the same key and position to reproduce that stream.

## File streams and atomic output

A `FILE *` is a buffered C-library stream. Its OS file descriptor is an integer.
`fread` returns the number of items read: the code uses item size 1, so the result
counts bytes. A short read can be EOF or failure; check `ferror`. `fclose` can fail
when buffered output is finally written, so check it too.

The AES file wrapper creates a private temporary file beside the destination.
`fdopen` turns its already-open descriptor into a stream. The transform writes
only there. On success, the wrapper flushes, syncs, closes, and renames it into
place. Errors leave an existing destination unchanged. This is a file-publication
property, not a cryptographic authenticity check or a complete power-loss guarantee.

## Understanding test results

Known-answer tests compare against independent expected values. Round-trips test
that encrypt and decrypt agree; they cannot alone prove agreement with the
standard. Regression tests concentrate on boundaries and past mistakes. Fault
injection makes specific calls fail so cleanup and preservation can be checked.
Fuzzing repeatedly mutates inputs and checks invariants under sanitizers.

`assert(expression)` aborts when its expression is false. These tests also perform
setup inside assertions: **do not define `NDEBUG` when building them**, because it
removes those expressions entirely. Applications instead use explicit checks and
return codes; assertions are not a replacement for validating external input.

Run `make check`, `make sanitize`, and (with a compatible Clang) `make fuzz-smoke`.
A successful bounded fuzz run only reports that no tested input triggered a
failure; it is not an exhaustive proof. Failure-injection tests intentionally print
example error messages while verifying that the tests themselves succeed.
