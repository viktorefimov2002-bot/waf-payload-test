#!/usr/bin/env python3
"""Run run_suite.py with sequential high-RPS k6 scenarios enabled."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    suite = Path(__file__).with_name("run_suite.py")
    if not suite.is_file():
        print(f"ERROR: {suite} does not exist", file=sys.stderr)
        return 2

    args = list(sys.argv[1:])
    if "--mode" in args:
        position = args.index("--mode")
        if position + 1 >= len(args):
            print("ERROR: --mode requires a value", file=sys.stderr)
            return 2
        del args[position:position + 2]

    env = os.environ.copy()
    env["RUN_MODE"] = "high-rps"

    command = [sys.executable, str(suite), "--mode", "fast", *args]
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
