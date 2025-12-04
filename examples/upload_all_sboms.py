#!/usr/bin/env python3
"""Upload every SBOM artifact in the examples directory via scripts/upload_sbom."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SBOM_DIR = Path(__file__).resolve().parent
UPLOAD_SCRIPT = REPO_ROOT / "scripts" / "upload_sbom"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload all example SBOMs using scripts/upload_sbom",
    )
    parser.add_argument(
        "--glob",
        default="*sbom*.json",
        help="Pattern (relative to examples/) used to find SBOM files.",
    )
    parser.add_argument(
        "--project-name",
        help=(
            "Optional project name override passed through to scripts/upload_sbom. "
            "If omitted, each upload uses the default from the uploader script."
        ),
    )
    parser.add_argument(
        "--no-auto-create",
        action="store_true",
        help="Pass --no-auto-create to scripts/upload_sbom for each upload.",
    )
    return parser.parse_args()


def find_sboms(pattern: str) -> list[Path]:
    return sorted(SBOM_DIR.glob(pattern))


def upload(sbom: Path, args: argparse.Namespace) -> int:
    cmd = [str(UPLOAD_SCRIPT), str(sbom)]
    if args.project_name:
        cmd.extend(["--project-name", args.project_name])
    if args.no_auto_create:
        cmd.append("--no-auto-create")
    print(f"Uploading {sbom.relative_to(REPO_ROOT)} ...", flush=True)
    completed = subprocess.run(cmd, check=False)
    if completed.returncode != 0:
        print(f"Failed to upload {sbom.name}", file=sys.stderr)
    return completed.returncode


def main() -> int:
    if not UPLOAD_SCRIPT.exists():
        print(f"Uploader script missing: {UPLOAD_SCRIPT}", file=sys.stderr)
        return 2

    args = parse_args()
    sboms = find_sboms(args.glob)
    if not sboms:
        print(f"No SBOMs matched pattern '{args.glob}'", file=sys.stderr)
        return 1

    for sbom in sboms:
        if upload(sbom, args) != 0:
            return 1

    print(f"Uploaded {len(sboms)} SBOM(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

