#!/usr/bin/env python3
"""VKScan CLI and main entry point."""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import Set

import tkinter as tk

from .constants import (
    VERSION, DEFAULT_EXCLUSIONS, PHASH_DISTANCE_THRESHOLD, DEFAULT_WORKERS,
)
from .config import _config
from .models import ScanOptions
from .scanner import DuplicateScanner
from .export import export_txt, export_csv
from .utils import format_size
from .gui import DuplicateFinderApp

def main() -> None:
    """Main entry point — CLI with argparse or GUI."""
    parser = argparse.ArgumentParser(
        prog="vkscan",
        description="VKScan \u2014 Voight-Kampff Scanner for duplicate files"
    )
    parser.add_argument(
        "--scan", nargs="+", metavar="PATH",
        help="Scan one or more directories for duplicates (CLI mode)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Export results to FILE (.csv or .txt)"
    )
    parser.add_argument(
        "--no-perceptual", action="store_true",
        help="Skip perceptual (image similarity) hashing"
    )
    parser.add_argument(
        "--exclude", action="append", metavar="PATTERN",
        help="Exclude paths matching PATTERN (repeatable)"
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help=f"Number of worker threads (default: {DEFAULT_WORKERS})"
    )
    parser.add_argument(
        "--threshold", type=int, default=None,
        help=f"Perceptual hash distance threshold (default: {PHASH_DISTANCE_THRESHOLD})"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"VKScan v{VERSION}"
    )

    args = parser.parse_args()

    # --- GUI mode (no --scan) ---
    if args.scan is None:
        root = tk.Tk()
        DuplicateFinderApp(root)
        root.mainloop()
        return

    # --- CLI mode ---
    # Apply config overrides
    if args.workers is not None:
        _config.workers = max(1, args.workers)
    if args.threshold is not None:
        _config.image_similarity_threshold = max(0, args.threshold)

    # Build exclusions
    exclusions: Set[str] = set()
    for line in DEFAULT_EXCLUSIONS.splitlines():
        stripped = line.strip()
        if stripped:
            exclusions.add(stripped)
    if args.exclude:
        for pattern in args.exclude:
            exclusions.add(pattern.strip())

    perceptual = not args.no_perceptual

    # Validate paths
    valid_paths = []
    for p in args.scan:
        resolved = str(Path(p).resolve())
        if os.path.isdir(resolved):
            valid_paths.append(resolved)
        else:
            print(f"Warning: '{p}' is not a valid directory, skipping.")
    if not valid_paths:
        print("Error: No valid directories to scan.")
        sys.exit(1)

    # Progress callback for CLI
    def cli_progress(percent: int, message: str) -> None:
        print(f"\r[{percent:3d}%] {message}", end="", flush=True)

    print(f"VKScan v{VERSION} \u2014 CLI Mode")
    print(f"Scanning: {', '.join(valid_paths)}")
    print(f"Workers: {_config.workers} | Perceptual: {perceptual} | Threshold: {_config.image_similarity_threshold}")
    print()

    scanner = DuplicateScanner(progress_callback=cli_progress)
    start_time = time.time()

    # Collect files
    files = scanner.collect_files(valid_paths, exclusions)
    print()  # newline after progress
    print(f"Collected {len(files)} files.")

    # Find duplicates
    groups = scanner.find_duplicates(files, perceptual_images=perceptual)
    elapsed = time.time() - start_time
    print()  # newline after progress

    # --- Print results ---
    if not groups:
        print("\nNo duplicates found.")
    else:
        total_recoverable = 0
        print(f"\n{'=' * 60}")
        print(f"  DUPLICATE GROUPS FOUND: {len(groups)}")
        print(f"{'=' * 60}\n")

        for i, group in enumerate(groups, 1):
            recoverable = group.recoverable_size()
            total_recoverable += recoverable
            type_str = "similar" if group.is_perceptual else "exact"
            verified_str = " [verified]" if group.verified else ""
            print(f"Group {i} ({type_str}, {group.similarity:.1f}%{verified_str})  "
                  f"\u2014 {len(group.files)} files, recoverable: {format_size(recoverable)}")
            for fi in group.files:
                mtime_str = datetime.fromtimestamp(fi.mtime).strftime(
                    "%Y-%m-%d %H:%M"
                ) if fi.mtime else ""
                print(f"    {fi.path}  ({format_size(fi.size)}, {mtime_str})")
            print()

        print(f"{'=' * 60}")
        print(f"  Total duplicate groups : {len(groups)}")
        print(f"  Total recoverable space: {format_size(total_recoverable)}")
        print(f"  Scan time              : {elapsed:.1f}s")
        print(f"{'=' * 60}")

    # --- Export if requested ---
    if args.output:
        out = args.output
        try:
            if out.lower().endswith(".csv"):
                export_csv(out, groups)
            else:
                export_txt(out, groups)
            print(f"\nReport saved to: {out}")
        except (PermissionError, OSError) as e:
            print(f"\nError: Could not write report: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
