#!/usr/bin/env python3
"""Independent binary interoperability checks; no third-party Python packages.

hashlib is the hash oracle and the OpenSSL CLI is the AES-CBC oracle. A fixed
PRNG seed makes failures reproducible; these generated keys are test-only.
ctypes signatures describe the C ABI explicitly so pointers are not truncated.
"""
import argparse
import ctypes as c
import hashlib
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile


class MD5(c.Structure):
    _fields_ = [("state", c.c_uint32 * 4), ("count", c.c_uint64), ("buffer", c.c_uint8 * 64)]


class SHA256(c.Structure):
    _fields_ = [("data", c.c_uint8 * 64), ("datalen", c.c_uint32),
                ("bitlen", c.c_ulonglong), ("state", c.c_uint32 * 8)]


class SHA3(c.Structure):
    _fields_ = [("state", c.c_uint64 * 25), ("buffer", c.c_uint8 * 144),
                ("buf_len", c.c_size_t), ("rate", c.c_size_t), ("hash_len", c.c_size_t)]


class AES(c.Structure):
    _fields_ = [("round_keys", c.c_uint8 * 240), ("iv", c.c_uint8 * 16)]


def require(condition, message):
    # Python assert can be disabled; verification must always execute.
    if not condition:
        raise RuntimeError(message)


def signature(lib, name, arguments, result=None):
    function = getattr(lib, name)
    function.argtypes = arguments
    function.restype = result
    return function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--libdir", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"))
    args = parser.parse_args()
    suffix = "dylib" if sys.platform == "darwin" else "so"
    rng = random.Random(0xC0DEC0DE)
    def random_bytes(n):
        return bytes(rng.randrange(256) for _ in range(n))
    lengths = [0, 1, 15, 16, 17, 55, 56, 63, 64, 65, 135, 136, 137,
               255, 256, 4095, 4096, 4097, 8192]
    lengths += [rng.randrange(0, 16385) for _ in range(24)]
    messages = [random_bytes(n) for n in lengths]
    messages += [b"\0" * 272, b"\xff" * 137, bytes(range(256))]
    bindings = []
    for library, prefix, context, oracle in [
        ("md5", "md5", MD5, hashlib.md5),
        ("sha256", "sha256", SHA256, hashlib.sha256),
        ("sha3", "sha3_256", SHA3, hashlib.sha3_256),
    ]:
        lib = c.CDLL(str((args.libdir / f"lib{library}.{suffix}").resolve()))
        init = signature(lib, prefix + "_init", [c.POINTER(context)])
        update = signature(lib, prefix + "_update", [c.POINTER(context), c.c_void_p, c.c_size_t])
        final = signature(lib, prefix + "_final", [c.POINTER(context), c.c_void_p])
        cleanup = signature(lib, prefix + "_cleanup", [c.POINTER(context)])
        file_hash = signature(lib, prefix + "_file", [c.c_char_p, c.c_void_p], c.c_int)
        bindings.append((prefix, context, oracle, init, update, final, cleanup, file_hash))
    aes = c.CDLL(str((args.libdir / f"libaes256.{suffix}").resolve()))
    init = signature(aes, "aes256_init", [c.POINTER(AES), c.c_void_p, c.c_void_p], c.c_int)
    cleanup = signature(aes, "aes256_cleanup", [c.POINTER(AES)])
    size_for = signature(aes, "aes256_encrypted_size", [c.c_size_t, c.POINTER(c.c_size_t)], c.c_int)
    buffer_args = [c.POINTER(AES), c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
    encrypt = signature(aes, "aes256_encrypt_buffer_checked", buffer_args, c.c_int)
    decrypt = signature(aes, "aes256_decrypt_buffer_checked", buffer_args, c.c_int)
    encrypt_file = signature(aes, "aes256_encrypt_file", [c.POINTER(AES), c.c_char_p, c.c_char_p], c.c_int)
    decrypt_file = signature(aes, "aes256_decrypt_file", [c.POINTER(AES), c.c_char_p, c.c_char_p], c.c_int)
    version = subprocess.run([args.openssl, "version"], check=True, capture_output=True, text=True)
    print("AES oracle:", version.stdout.strip())
    with tempfile.TemporaryDirectory(prefix="cryptolib-crosscheck-") as directory:
        path = Path(directory)
        for case, message in enumerate(messages):
            (path / "input").write_bytes(message)
            for prefix, context, oracle, start, update, final, wipe, file_hash in bindings:
                expected = oracle(message).digest()
                # One complete update, byte-at-a-time, and irregular chunks exercise
                # buffering independently of the digest's block boundaries.
                for strategy in ("whole", "bytes", "irregular"):
                    ctx, digest = context(), c.create_string_buffer(len(expected))
                    start(c.byref(ctx))
                    update(c.byref(ctx), None, 0)
                    position = 0
                    while position < len(message):
                        chunk = len(message) if strategy == "whole" else (1 if strategy == "bytes" else rng.randrange(1, 300))
                        part = message[position:position + chunk]
                        update(c.byref(ctx), part, len(part))
                        position += len(part)
                    final(c.byref(ctx), digest)
                    require(digest.raw == expected, f"{prefix} case {case}, {strategy}")
                    wipe(c.byref(ctx))
                    require(bytes(ctx) == bytes(c.sizeof(ctx)), f"{prefix} cleanup")
                digest = c.create_string_buffer(len(expected))
                require(file_hash(os.fsencode(path / "input"), digest) == 0, f"{prefix} file status")
                require(digest.raw == expected, f"{prefix} file case {case}")
            key, iv = random_bytes(32), random_bytes(16)
            command = [args.openssl, "enc", "-aes-256-cbc", "-nosalt", "-K", key.hex(), "-iv", iv.hex()]
            expected = subprocess.run(command, input=message, check=True, capture_output=True).stdout
            ctx, capacity, written = AES(), c.c_size_t(), c.c_size_t()
            require(init(c.byref(ctx), key, iv) == 0, "AES init")
            require(size_for(len(message), c.byref(capacity)) == 0, "AES size")
            encrypted = c.create_string_buffer(capacity.value)
            require(encrypt(c.byref(ctx), message, len(message), encrypted, capacity.value, c.byref(written)) == 0, "AES encrypt")
            actual = encrypted.raw[:written.value]
            require(actual == expected, f"OpenSSL encrypt case {case}")
            plain = c.create_string_buffer(len(expected))
            require(decrypt(c.byref(ctx), expected, len(expected), plain, len(expected), c.byref(written)) == 0, "AES decrypt")
            require(plain.raw[:written.value] == message, f"OpenSSL decrypt case {case}")
            require(subprocess.run(command + ["-d"], input=actual, check=True, capture_output=True).stdout == message,
                    f"OpenSSL reads library ciphertext case {case}")
            require(encrypt_file(c.byref(ctx), os.fsencode(path / "input"), os.fsencode(path / "encrypted")) == 0, "AES file encrypt")
            require((path / "encrypted").read_bytes() == iv + expected, f"AES file wire format case {case}")
            # Explicitly feed independently produced ciphertext to file decryption.
            (path / "encrypted").write_bytes(iv + expected)
            require(decrypt_file(c.byref(ctx), os.fsencode(path / "encrypted"), os.fsencode(path / "plain")) == 0, "AES file decrypt")
            require((path / "plain").read_bytes() == message, f"AES file plaintext case {case}")
            cleanup(c.byref(ctx))
    print(f"Independent cross-checks passed: {len(messages)} binary inputs, 3 hashes, 3 streaming patterns, AES buffers/files")


if __name__ == "__main__":
    main()
