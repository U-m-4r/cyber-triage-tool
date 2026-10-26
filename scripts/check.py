"""Project-root verification without downloads, dataset access or production training."""

import argparse
import ast
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    print("Running: " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="Also run backend tests and frontend tests/build")
    args = parser.parse_args()
    sources = [
        p
        for folder in ("backend", "ml", "forensics", "evaluation", "scripts", "tests")
        for p in (ROOT / folder).rglob("*.py")
        if "__pycache__" not in p.parts
    ]
    for path in sources:
        ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    print(f"Python syntax: {len(sources)} files passed", flush=True)
    run([sys.executable, "-m", "pip", "check"])
    run([sys.executable, "-m", "ruff", "check", "."])
    run(
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--check",
            "backend/config.py",
            "tests/test_foundation.py",
            "scripts/check.py",
        ]
    )
    run([sys.executable, "-m", "flask", "--app", "backend.app", "check-config"])
    run(["git", "diff", "--check"])
    if args.all:
        run([sys.executable, "-m", "pytest", "-q"])
        npm = shutil.which("npm.cmd" if sys.platform == "win32" else "npm")
        if not npm:
            raise RuntimeError("npm not found. Install the documented Node version.")
        run([npm, "--prefix", "frontend", "run", "check"])


if __name__ == "__main__":
    main()
