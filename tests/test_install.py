#!/usr/bin/env python3
"""Stage install/uninstall and compile a consumer outside the source checkout.

No files go into the actual system prefix. A path containing spaces checks shell
quoting, and unrelated sentinel files verify uninstall only removes owned files.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--make", default="make")
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    # Python closes inherited jobserver descriptors. Drop Make's parallel flags
    # rather than passing stale descriptor numbers to the nested serial builds.
    environment = os.environ.copy()
    environment.pop("MAKEFLAGS", None)
    environment.pop("MFLAGS", None)
    with tempfile.TemporaryDirectory(prefix="cryptolib install ") as directory:
        staging = Path(directory) / "stage"
        prefix = "/usr/local/cryptolib-test"
        installed = staging / prefix.lstrip("/")
        command = [args.make, "-C", str(root), f"DESTDIR={staging}", f"PREFIX={prefix}", f"CC={args.cc}"]
        subprocess.run(command + ["install"], check=True, env=environment)
        public = {"cryptolib.h", "aes256.h", "arcfour.h", "md5.h", "sha256.h", "sha3.h"}
        if {p.name for p in (installed / "include/cryptolib").iterdir()} != public:
            raise RuntimeError("Installation did not contain exactly the public headers")
        outside = Path(directory) / "external consumer"
        shutil.copytree(root / "examples/consumer", outside,
                        ignore=shutil.ignore_patterns("consumer", "consumer-shared"))
        subprocess.run([args.make, "-C", str(outside), f"PREFIX={installed}", f"CC={args.cc}", "consumer", "consumer-shared"], check=True, env=environment)
        for program in ("consumer", "consumer-shared"):
            subprocess.run([str(outside / program)], cwd=outside, check=True, env=environment)
        sentinel = installed / "lib/unrelated.txt"
        sentinel.write_text("keep me")
        subprocess.run(command + ["uninstall"], check=True, env=environment)
        subprocess.run(command + ["uninstall"], check=True, env=environment)  # Idempotent removal.
        if sentinel.read_text() != "keep me":
            raise RuntimeError("Uninstall modified an unrelated file")
        remaining = {str(p.relative_to(installed)) for p in installed.rglob("*") if p.is_file()}
        if remaining != {"lib/unrelated.txt"}:
            raise RuntimeError(f"Unexpected files after uninstall: {remaining}")
    print("Staged install, independent static/shared consumers, and uninstall passed")


if __name__ == "__main__":
    main()
