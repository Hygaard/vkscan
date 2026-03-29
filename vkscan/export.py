#!/usr/bin/env python3
"""VKScan export functions for TXT and CSV reports."""

import csv
from datetime import datetime
from typing import List

from .models import DuplicateGroup
from .utils import format_size


def export_txt(path: str, duplicate_groups: List[DuplicateGroup]) -> None:
    """Export report as formatted text."""
    with open(path, "w", encoding="utf-8") as f:
        f.write("VKScan Report\n")
        f.write("=" * 50 + "\n\n")

        total_recoverable = 0
        for i, group in enumerate(duplicate_groups, 1):
            recoverable = group.recoverable_size()
            total_recoverable += recoverable

            type_str = "(similar)" if group.is_perceptual else "(exact)"
            if group.verified:
                type_str += " [verified]"
            f.write(
                f"Group {i}: {len(group.files)} file(s), "
                f"Similarity: {group.similarity:.1f}% {type_str}\n"
            )
            f.write(f"  Recoverable: {format_size(recoverable)}\n")
            for file_info in group.files:
                mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                    "%Y-%m-%d %H:%M"
                ) if file_info.mtime else ""
                f.write(f"  {file_info.path}  ({format_size(file_info.size)}, {mtime_str})\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write(
            f"Total groups: {len(duplicate_groups)}\n"
            f"Total recoverable: {format_size(total_recoverable)}\n"
        )


def export_csv(path: str, duplicate_groups: List[DuplicateGroup]) -> None:
    """Export report as CSV for spreadsheet use."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Group", "Type", "Similarity", "File Path", "Size (bytes)", "Size", "Modified"])
        for i, group in enumerate(duplicate_groups, 1):
            type_str = "similar" if group.is_perceptual else "exact"
            for file_info in group.files:
                mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ) if file_info.mtime else ""
                writer.writerow([
                    i, type_str, f"{group.similarity:.1f}%",
                    file_info.path, file_info.size, format_size(file_info.size),
                    mtime_str
                ])
