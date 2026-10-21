#!/usr/bin/env python3
"""
Failure reproduction script for stateful indexer fuzzing.

Cross-platform runner (Windows/Linux/macOS) to deterministically replay
stateful indexer operations and reproduce any invariant violations.

Usage:
  python scripts/reproduce_stateful_fuzz.py --ops 50000
  python scripts/reproduce_stateful_fuzz.py --seed 0x5EEDF00D12345678 --ops 5000
  python scripts/reproduce_stateful_fuzz.py --file <path_to_crash_artifact>
"""

import sys
import subprocess
import os

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    os.chdir(repo_root)

    print("[stateful-fuzz-repro] Building stateful indexer fuzzer in release mode...")
    manifest_path = os.path.join("fuzz", "Cargo.toml")
    build_cmd = ["cargo", "build", "--release", "--manifest-path", manifest_path, "--bin", "stateful_indexer_fuzz"]
    build_res = subprocess.run(build_cmd)
    if build_res.returncode != 0:
        print("[stateful-fuzz-repro] ERROR: Build failed", file=sys.stderr)
        sys.exit(build_res.returncode)

    print(f"[stateful-fuzz-repro] Executing stateful fuzzer runner with arguments: {sys.argv[1:]}")
    run_cmd = ["cargo", "run", "--release", "--manifest-path", manifest_path, "--bin", "stateful_indexer_fuzz", "--"] + sys.argv[1:]
    env = os.environ.copy()
    env["RUST_BACKTRACE"] = "1"
    run_res = subprocess.run(run_cmd, env=env)
    sys.exit(run_res.returncode)

if __name__ == "__main__":
    main()
