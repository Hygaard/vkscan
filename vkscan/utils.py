#!/usr/bin/env python3
"""VKScan utility functions."""

import os
import math
import filecmp

from .constants import PHASH_BIT_COUNT
from .config import _config

# Optional: send2trash for safe deletion
try:
    from send2trash import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable size string."""
    if size_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = min(int(math.floor(math.log(size_bytes, 1024))), len(units) - 1)
    scaled_size = size_bytes / (1024 ** unit_index)
    return f"{scaled_size:.1f} {units[unit_index]}"


def hamming_distance(hash1: str, hash2: str) -> int:
    """Calculate Hamming distance between two hex-encoded hashes."""
    try:
        xor_result = int(hash1, 16) ^ int(hash2, 16)
        return bin(xor_result).count("1")
    except (ValueError, TypeError):
        return PHASH_BIT_COUNT  # Maximum distance on error


def calculate_similarity(distance: int, max_bits: int = PHASH_BIT_COUNT) -> float:
    """Convert Hamming distance to percentage similarity."""
    if max_bits <= 0:
        return 0.0
    similarity = 100.0 * (1.0 - distance / max_bits)
    return max(0.0, min(100.0, similarity))


def safe_path_match(path: str, pattern: str) -> bool:
    """Safe pattern matching that handles edge cases."""
    path_lower = path.lower()
    pattern_lower = pattern.lower().strip()

    if not pattern_lower or pattern_lower in ("..", ".", "*", "?"):
        return False

    return pattern_lower in path_lower


def files_are_identical(path1: str, path2: str) -> bool:
    """Byte-level comparison of two files. Returns True if identical."""
    try:
        return filecmp.cmp(path1, path2, shallow=False)
    except (OSError, PermissionError):
        return False


def safe_delete(path: str) -> None:
    """Delete a file using trash if available, otherwise os.remove.
    
    Raises OSError or PermissionError on failure.
    """
    if _config.use_trash and HAS_SEND2TRASH:
        send2trash(path)
    else:
        os.remove(path)
