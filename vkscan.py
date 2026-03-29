#!/usr/bin/env python3
# Copyright (C) 2026 Hygaard
# Licensed under the GNU General Public License v3.0 — see LICENSE for details.
"""
VKScan with GUI - v1.1.0

A comprehensive duplicate file detection tool featuring:
- Exact duplicate detection via SHA-256 hashing with byte-level verification
- Perceptual hashing for similar image detection
- GUI with preview and comparison capabilities
- Threaded scanning with progress tracking
- Memory-efficient design for large file collections
- Safe deletion via trash/staging directory

Version: 1.1.0
"""

import os
import sys
import hashlib
import threading
import math
import shutil
import filecmp
import time
import csv
import subprocess
import queue
import json
import argparse
import re
import sqlite3
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Callable
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from PIL import Image, ImageTk
from imagehash import phash

# Optional: send2trash for safe deletion
try:
    from send2trash import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False

# Optional: tkinterdnd2 for native drag-and-drop
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Version
VERSION = "1.1.0"

# Security: Limit maximum image pixels to prevent DoS via large images
MAX_IMAGE_PIXELS = 100_000_000  # ~100 megapixels (modern phones shoot 50-108MP)

# Perceptual hash configuration
PHASH_BLOCK_SIZE = 16  # Creates 16x16 = 256-bit hash (higher resolution = fewer false positives)
PHASH_BIT_COUNT = PHASH_BLOCK_SIZE * PHASH_BLOCK_SIZE  # 256 bits total
PHASH_DISTANCE_THRESHOLD = 8  # Hamming distance threshold; 0=exact, 256=completely different

# Preview configuration
MAX_PREVIEW_SIZE = 500  # Max dimension for preview images in pixels
TEXT_PREVIEW_LINES = 100  # Max lines to show in text preview

# File processing limits
HASH_BLOCK_SIZE = 1024 * 1024  # 1MB chunks for hashing (saturates modern SSDs better than 64KB)
QUICK_HASH_SIZE = 4096  # 4KB quick-reject hash to skip early mismatches
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024 * 1024  # 100GB max file size (VMs, video archives)
MAX_IMAGE_FILE_BYTES = 1024 * 1024 * 1024  # 1GB max for image processing (pro RAW files)

# Parallelism
DEFAULT_WORKERS = max(2, (os.cpu_count() or 4) - 2)  # Thread pool size, cpu_count - 2 with floor of 2

# UI configuration
MIN_WINDOW_SIZE = (800, 600)
DEFAULT_WINDOW_SIZE = (1200, 800)

# Supported image extensions (PIL-compatible only; SVG excluded)
IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".tiff", ".tif", ".webp", ".ico"
}

# Platform-aware default exclusions
if sys.platform == "win32":
    DEFAULT_EXCLUSIONS = "System32\nWindows\nProgram Files\n$Recycle.Bin\nAppData\\Local\\Temp"
else:
    DEFAULT_EXCLUSIONS = "/proc\n/sys\n/dev\n/run\n/snap\n/tmp\n.cache\n__pycache__\nnode_modules"

# Minimum file size to bother deduplicating (skip zero-byte files)
MIN_FILE_SIZE_BYTES = 1

# Minimum number of images to justify ProcessPoolExecutor overhead
# Below this, ThreadPoolExecutor is used (avoids process spawn cost)
PROCESS_POOL_THRESHOLD = 50

# Settings persistence
if sys.platform == "win32":
    CONFIG_DIR = Path(os.environ.get('APPDATA', '~')) / 'VKScan'
else:
    CONFIG_DIR = Path.home() / '.config' / 'vkscan'
CONFIG_FILE = CONFIG_DIR / 'settings.json'


# =============================================================================
# RUNTIME CONFIGURATION
# =============================================================================

class Config:
    """Runtime configuration storage with defaults from constants."""
    image_similarity_threshold: int = PHASH_DISTANCE_THRESHOLD
    max_file_size_bytes: int = MAX_FILE_SIZE_BYTES
    use_trash: bool = True  # Prefer trash/recycle bin over permanent delete
    skip_empty_files: bool = True  # Skip zero-byte files
    workers: int = DEFAULT_WORKERS  # Thread pool size for parallel hashing
    suppress_similarity_warning: bool = False  # Don't warn about non-100% auto-select

_config = Config()

# Saved scan settings (populated by load_settings)
_saved_scan_paths: List[str] = []
_saved_scan_exclusions: List[str] = []
_saved_scan_perceptual: bool = True


def save_settings(scan_paths: Optional[List[str]] = None,
                  scan_exclusions: Optional[List[str]] = None,
                  scan_perceptual: Optional[bool] = None) -> None:
    global _saved_scan_paths, _saved_scan_exclusions, _saved_scan_perceptual
    if scan_paths is not None:
        _saved_scan_paths = list(scan_paths)
    if scan_exclusions is not None:
        _saved_scan_exclusions = list(scan_exclusions)
    if scan_perceptual is not None:
        _saved_scan_perceptual = scan_perceptual
    data = {
        "image_similarity_threshold": _config.image_similarity_threshold,
        "workers": _config.workers,
        "use_trash": _config.use_trash,
        "skip_empty_files": _config.skip_empty_files,
        "scan_paths": _saved_scan_paths,
        "scan_exclusions": _saved_scan_exclusions,
        "scan_perceptual": _saved_scan_perceptual,
    }
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_settings() -> None:
    global _saved_scan_paths, _saved_scan_exclusions, _saved_scan_perceptual
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if "image_similarity_threshold" in data:
            _config.image_similarity_threshold = int(data["image_similarity_threshold"])
        if "workers" in data:
            _config.workers = max(1, int(data["workers"]))
        if "use_trash" in data:
            _config.use_trash = bool(data["use_trash"])
        if "skip_empty_files" in data:
            _config.skip_empty_files = bool(data["skip_empty_files"])
        if "scan_paths" in data and isinstance(data["scan_paths"], list):
            _saved_scan_paths = [str(p) for p in data["scan_paths"]]
        if "scan_exclusions" in data and isinstance(data["scan_exclusions"], list):
            _saved_scan_exclusions = [str(e) for e in data["scan_exclusions"]]
        if "scan_perceptual" in data:
            _saved_scan_perceptual = bool(data["scan_perceptual"])
    except Exception:
        pass


# =============================================================================
# HASH CACHE (SQLite)
# =============================================================================

CACHE_DB = CONFIG_DIR / 'hash_cache.db'


class HashCache:
    """Persistent hash cache backed by SQLite.

    Caches SHA-256 and perceptual hashes keyed by (path, mtime, size).
    If a file's mtime or size changes, the cached hash is considered stale
    and will be recomputed. Thread-safe via check_same_thread=False and
    a threading lock for writes.

    The cache is stored alongside settings in the VKScan config directory.
    """

    def __init__(self, db_path: Path = CACHE_DB):
        self._lock = threading.Lock()
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS hash_cache (
                    path TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT,
                    quick_hash TEXT,
                    phash TEXT,
                    PRIMARY KEY (path, mtime, size)
                )
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_path ON hash_cache(path)
            """)
            # Invalidate cached phash values if they don't match current hash size.
            # 256-bit (hash_size=16) = 64 hex chars; 64-bit (hash_size=8) = 16 hex chars.
            # If the stored hash length doesn't match PHASH_BLOCK_SIZE**2 / 4, wipe all.
            expected_hex_len = (PHASH_BLOCK_SIZE * PHASH_BLOCK_SIZE) // 4  # bits -> hex chars
            try:
                sample = self._conn.execute(
                    "SELECT phash FROM hash_cache WHERE phash IS NOT NULL LIMIT 1"
                ).fetchone()
                if sample and len(sample[0]) != expected_hex_len:
                    self._conn.execute("UPDATE hash_cache SET phash = NULL")
            except Exception:
                pass
            self._conn.commit()
            self._enabled = True
        except Exception:
            self._conn = None
            self._enabled = False

    def get(self, path: str, mtime: float, size: int) -> Dict[str, Optional[str]]:
        """Look up cached hashes for a file.

        Returns dict with keys 'sha256', 'quick_hash', 'phash' (any may be None).
        Returns empty dict on miss.
        """
        if not self._enabled:
            return {}
        try:
            row = self._conn.execute(
                "SELECT sha256, quick_hash, phash FROM hash_cache WHERE path=? AND mtime=? AND size=?",
                (path, mtime, size)
            ).fetchone()
            if row:
                return {"sha256": row[0], "quick_hash": row[1], "phash": row[2]}
        except Exception:
            pass
        return {}

    def put(self, path: str, mtime: float, size: int,
            sha256: Optional[str] = None, quick_hash: Optional[str] = None,
            phash: Optional[str] = None) -> None:
        """Store or update cached hashes for a file."""
        if not self._enabled:
            return
        with self._lock:
            try:
                self._conn.execute(
                    """INSERT OR REPLACE INTO hash_cache
                       (path, mtime, size, sha256, quick_hash, phash)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (path, mtime, size, sha256, quick_hash, phash)
                )
                self._conn.commit()
            except Exception:
                pass

    def put_batch(self, entries: List[Tuple]) -> None:
        """Batch insert/update cached hashes.

        Each entry is (path, mtime, size, sha256, quick_hash, phash).
        """
        if not self._enabled or not entries:
            return
        with self._lock:
            try:
                self._conn.executemany(
                    """INSERT OR REPLACE INTO hash_cache
                       (path, mtime, size, sha256, quick_hash, phash)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    entries
                )
                self._conn.commit()
            except Exception:
                pass

    def prune_missing(self) -> int:
        """Remove entries for files that no longer exist. Returns count removed."""
        if not self._enabled:
            return 0
        with self._lock:
            try:
                rows = self._conn.execute("SELECT path FROM hash_cache").fetchall()
                missing = [r[0] for r in rows if not os.path.exists(r[0])]
                if missing:
                    self._conn.executemany(
                        "DELETE FROM hash_cache WHERE path=?",
                        [(p,) for p in missing]
                    )
                    self._conn.commit()
                return len(missing)
            except Exception:
                return 0

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass

    @property
    def enabled(self) -> bool:
        return self._enabled


# Global hash cache instance (lazy-initialized)
_hash_cache: Optional[HashCache] = None


def get_hash_cache() -> HashCache:
    """Get or create the global hash cache instance."""
    global _hash_cache
    if _hash_cache is None:
        _hash_cache = HashCache()
    return _hash_cache


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class FileInfo:
    """Information about a single file."""
    path: str
    size: int
    hash: str = ""
    p_hash: Optional[str] = None
    is_image: bool = False
    inode: Optional[Tuple[int, int]] = None  # (inode, device) for hard link detection
    mtime: float = 0.0  # Last modification time (epoch)

    def __hash__(self):
        return hash(self.path)


@dataclass
class DuplicateGroup:
    """A group of duplicate or similar files."""
    files: List[FileInfo] = field(default_factory=list)
    similarity: float = 100.0
    is_perceptual: bool = False
    verified: bool = False  # True if byte-level verified

    def recoverable_size(self) -> int:
        """Calculate space recoverable by keeping only one file."""
        if len(self.files) < 2:
            return 0
        return sum(f.size for f in self.files[1:])

    def file_count(self) -> int:
        """Number of files in this group."""
        return len(self.files)


@dataclass
class ScanOptions:
    """Options for a scan operation."""
    paths: List[str]
    exclusions: Set[str]
    perceptual: bool = True


@dataclass
class ScanResult:
    """Result of a scan operation."""
    duplicate_groups: List[DuplicateGroup]
    total_files_scanned: int
    total_duplicates: int
    recoverable_size: int
    scan_time_seconds: float


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

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


# =============================================================================
# EXPORT FUNCTIONS (used by both GUI and CLI)
# =============================================================================

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


def export_json(path: str, duplicate_groups: List[DuplicateGroup]) -> None:
    """Export report as JSON for programmatic consumption."""
    data = {
        "version": VERSION,
        "total_groups": len(duplicate_groups),
        "total_recoverable_bytes": sum(g.recoverable_size() for g in duplicate_groups),
        "total_recoverable": format_size(sum(g.recoverable_size() for g in duplicate_groups)),
        "groups": []
    }
    for i, group in enumerate(duplicate_groups, 1):
        group_data = {
            "group": i,
            "type": "similar" if group.is_perceptual else "exact",
            "similarity": round(group.similarity, 1),
            "verified": group.verified,
            "recoverable_bytes": group.recoverable_size(),
            "recoverable": format_size(group.recoverable_size()),
            "files": []
        }
        for file_info in group.files:
            mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                "%Y-%m-%dT%H:%M:%S"
            ) if file_info.mtime else ""
            group_data["files"].append({
                "path": file_info.path,
                "size_bytes": file_info.size,
                "size": format_size(file_info.size),
                "modified": mtime_str,
                "sha256": file_info.hash or None,
                "phash": file_info.p_hash or None,
            })
        data["groups"].append(group_data)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =============================================================================
# BK-TREE FOR HAMMING DISTANCE SEARCH
# =============================================================================

class BKTree:
    """Burkhard-Keller tree for efficient Hamming distance nearest-neighbor search.

    Instead of comparing every hash pair O(n^2), BKTree indexes hashes
    and finds all neighbors within a threshold in O(n log n) average case.
    This is critical for large image collections (10k+ images).

    Each node stores a hash string and children keyed by Hamming distance.
    The triangle inequality of Hamming distance allows pruning subtrees
    that cannot contain matches.
    """

    def __init__(self):
        self._root: Optional[Tuple[str, Dict]] = None
        self._size = 0

    def insert(self, hash_str: str) -> None:
        """Insert a hash into the tree."""
        if self._root is None:
            self._root = (hash_str, {})
            self._size += 1
            return

        node = self._root
        while True:
            node_hash, children = node
            d = hamming_distance(hash_str, node_hash)
            if d == 0:
                return  # Duplicate hash, already present
            if d in children:
                node = children[d]
            else:
                children[d] = (hash_str, {})
                self._size += 1
                return

    def find_within(self, query: str, threshold: int) -> List[Tuple[str, int]]:
        """Find all hashes within the given Hamming distance threshold.

        Args:
            query: Hash string to search for
            threshold: Maximum Hamming distance (inclusive)

        Returns:
            List of (hash, distance) tuples for all matches
        """
        if self._root is None:
            return []

        results: List[Tuple[str, int]] = []
        stack = [self._root]

        while stack:
            node_hash, children = stack.pop()
            d = hamming_distance(query, node_hash)

            if d <= threshold:
                results.append((node_hash, d))

            # Triangle inequality: only visit children where
            # |d - threshold| <= child_distance <= d + threshold
            low = max(0, d - threshold)
            high = d + threshold
            for child_dist, child_node in children.items():
                if low <= child_dist <= high:
                    stack.append(child_node)

        return results

    def __len__(self) -> int:
        return self._size


# =============================================================================
# TOP-LEVEL FUNCTIONS FOR MULTIPROCESSING
# =============================================================================
# ProcessPoolExecutor requires picklable (top-level) functions.
# These are standalone versions of compute methods for cross-process use.

def _compute_perceptual_hash_standalone(args: Tuple[str, float, int]) -> Optional[str]:
    """Compute perceptual hash of an image (top-level for ProcessPoolExecutor).

    Must be a module-level function so it can be pickled and sent to
    worker processes. Duplicates the logic from DuplicateScanner but
    without any instance state.

    Args:
        args: Tuple of (path, mtime, size) for cache support

    Returns:
        Hex-encoded perceptual hash or None on error
    """
    path, mtime, size = args

    # Each worker process gets its own cache connection
    try:
        cache = get_hash_cache()
        cached = cache.get(path, mtime, size)
        if cached and cached.get("phash"):
            return cached["phash"]
    except Exception:
        cache = None

    try:
        file_size = os.path.getsize(path)
        if file_size > MAX_IMAGE_FILE_BYTES:
            return None

        with Image.open(path) as img:
            if img.width * img.height > MAX_IMAGE_PIXELS:
                return None
            img.verify()

        with Image.open(path) as img:
            if img.width * img.height > MAX_IMAGE_PIXELS:
                return None

            if img.mode not in ("RGB",):
                img = img.convert("RGB")

            ph = phash(img, hash_size=PHASH_BLOCK_SIZE)
            result = str(ph)

            # Store in cache
            if cache:
                try:
                    cache.put(path, mtime, size, phash=result)
                except Exception:
                    pass

            return result

    except (PermissionError, OSError, ValueError):
        return None
    except Exception:
        return None


# =============================================================================
# DUPLICATE SCANNER
# =============================================================================

class DuplicateScanner:
    """Thread-safe scanner for finding duplicate files."""

    def __init__(self, progress_callback: Optional[Callable[[int, str], None]] = None):
        """Initialize scanner with optional progress callback.

        Args:
            progress_callback: Function(percent, message) called during scan
        """
        self.progress_callback = progress_callback
        self.cancelled = False
        self._update_progress(0, "Initializing...")

    def _update_progress(self, percent: int, message: str) -> None:
        """Update progress if callback is registered."""
        if self.progress_callback:
            try:
                self.progress_callback(percent, message)
            except Exception:
                pass

    def is_image(self, path: str) -> bool:
        """Check if file is an image based on extension."""
        return Path(path).suffix.lower() in IMAGE_EXTENSIONS

    def compute_quick_hash(self, path: str, mtime: float = 0, size: int = 0) -> Optional[str]:
        """Compute a fast hash of the first 4KB of a file for quick-reject.

        Files that differ in their first 4KB cannot be duplicates,
        so this avoids reading the entire file for obvious mismatches.
        Uses the hash cache when mtime/size are provided.

        Returns:
            Hex-encoded SHA-256 hash of header bytes, or None on error
        """
        # Check cache first
        if mtime and size:
            cache = get_hash_cache()
            cached = cache.get(path, mtime, size)
            if cached and cached.get("quick_hash"):
                return cached["quick_hash"]

        try:
            with open(path, "rb") as f:
                header = f.read(QUICK_HASH_SIZE)
                if not header:
                    return None
                result = hashlib.sha256(header).hexdigest()

                # Store in cache
                if mtime and size:
                    cache = get_hash_cache()
                    cache.put(path, mtime, size, quick_hash=result)

                return result
        except (PermissionError, OSError):
            return None

    def compute_hash(self, path: str, mtime: float = 0, size: int = 0) -> Optional[str]:
        """Compute SHA-256 hash of a file.

        Uses the hash cache when mtime/size are provided.

        Args:
            path: Path to file
            mtime: File modification time (for cache lookup)
            size: File size in bytes (for cache lookup)

        Returns:
            Hex-encoded SHA-256 hash or None on error
        """
        # Check cache first
        if mtime and size:
            cache = get_hash_cache()
            cached = cache.get(path, mtime, size)
            if cached and cached.get("sha256"):
                return cached["sha256"]

        try:
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while not self.cancelled:
                    chunk = f.read(HASH_BLOCK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
            if self.cancelled:
                return None  # Don't return partial hash on cancel
            result = hasher.hexdigest()

            # Store in cache
            if mtime and size:
                cache = get_hash_cache()
                cache.put(path, mtime, size, sha256=result)

            return result
        except (PermissionError, OSError):
            return None

    def compute_perceptual_hash(self, path: str, mtime: float = 0, size: int = 0) -> Optional[str]:
        """Compute perceptual hash of an image.

        Uses the hash cache when mtime/size are provided.

        Args:
            path: Path to image file
            mtime: File modification time (for cache lookup)
            size: File size in bytes (for cache lookup)

        Returns:
            Hex-encoded perceptual hash or None on error
        """
        # Check cache first
        if mtime and size:
            cache = get_hash_cache()
            cached = cache.get(path, mtime, size)
            if cached and cached.get("phash"):
                return cached["phash"]

        try:
            file_size = os.path.getsize(path)
            if file_size > MAX_IMAGE_FILE_BYTES:
                return None

            with Image.open(path) as img:
                if img.width * img.height > MAX_IMAGE_PIXELS:
                    return None
                img.verify()

            with Image.open(path) as img:
                if img.width * img.height > MAX_IMAGE_PIXELS:
                    return None

                if img.mode not in ("RGB",):
                    img = img.convert("RGB")

                ph = phash(img, hash_size=PHASH_BLOCK_SIZE)
                result = str(ph)

                # Store in cache
                if mtime and size:
                    cache = get_hash_cache()
                    cache.put(path, mtime, size, phash=result)

                return result

        except (PermissionError, OSError, ValueError):
            return None
        except Exception:
            return None

    def collect_files(
        self,
        root_paths: List[str],
        exclusions: Set[str]
    ) -> List[FileInfo]:
        """Collect file information from root directories.

        Args:
            root_paths: List of directories to scan
            exclusions: Set of patterns to exclude

        Returns:
            List of FileInfo objects
        """
        files: List[FileInfo] = []
        seen_inodes: Dict[Tuple[int, int], str] = {}
        all_root_paths: Set[str] = set()

        for root in root_paths:
            try:
                root_path = Path(root).resolve()
                if root_path.exists() and root_path.is_dir():
                    all_root_paths.add(str(root_path))
            except Exception:
                continue

        file_count = 0
        for root_path in all_root_paths:
            if self.cancelled:
                break

            self._update_progress(0, f"STAGE:1/4:Scanning Files|0|Scanning {root_path}...")

            try:
                for path in Path(root_path).rglob("*"):
                    if self.cancelled:
                        break

                    try:
                        if not path.is_file():
                            continue
                    except (PermissionError, OSError):
                        continue

                    path_str = str(path)

                    if any(safe_path_match(path_str, exc) for exc in exclusions):
                        continue

                    try:
                        stat = path.stat()

                        if stat.st_size > MAX_FILE_SIZE_BYTES:
                            continue

                        # Skip empty files if configured
                        if _config.skip_empty_files and stat.st_size < MIN_FILE_SIZE_BYTES:
                            continue

                        inode_key = (stat.st_ino, stat.st_dev)
                        if inode_key in seen_inodes:
                            continue
                        seen_inodes[inode_key] = path_str

                        files.append(FileInfo(
                            path=path_str,
                            size=stat.st_size,
                            is_image=self.is_image(path_str),
                            inode=inode_key,
                            mtime=stat.st_mtime
                        ))
                        file_count += 1
                        if file_count % 200 == 0:
                            self._update_progress(0, f"STAGE:1/4:Scanning Files|0|{file_count:,} files found...")
                    except (PermissionError, OSError):
                        continue

            except (PermissionError, OSError):
                continue

        self._update_progress(0, f"STAGE:1/4:Scanning Files|100|Found {len(files):,} files")
        return files

    def _verify_hash_group(self, group_files: List[FileInfo]) -> List[List[FileInfo]]:
        """Byte-level verify a group of files that share the same hash.
        
        Returns a list of verified sub-groups (files confirmed identical).
        Since SHA-256 collisions are astronomically unlikely, this is
        defense-in-depth rather than a practical necessity.
        """
        if len(group_files) < 2:
            return []

        verified_groups: List[List[FileInfo]] = []
        assigned: Set[str] = set()

        for i, fi in enumerate(group_files):
            if fi.path in assigned:
                continue

            current_group = [fi]
            assigned.add(fi.path)

            for j in range(i + 1, len(group_files)):
                fj = group_files[j]
                if fj.path in assigned:
                    continue

                if files_are_identical(fi.path, fj.path):
                    current_group.append(fj)
                    assigned.add(fj.path)

            if len(current_group) >= 2:
                verified_groups.append(current_group)

        return verified_groups

    def find_duplicates(
        self,
        files: List[FileInfo],
        perceptual_images: bool = True,
        group_callback: Optional[Callable[[DuplicateGroup], None]] = None
    ) -> List[DuplicateGroup]:
        """Find duplicate files using hashing and byte-level verification.

        Uses ThreadPoolExecutor for parallel I/O on hashing and image analysis.
        Three-stage pipeline:
          1. Quick-hash (first 4KB) to reject obvious non-matches
          2. Full SHA-256 hash on remaining candidates (parallel)
          3. Byte-level verification on hash matches

        Args:
            files: List of files to analyze
            perceptual_images: Whether to use perceptual hashing for images

        Returns:
            List of DuplicateGroup objects
        """
        workers = _config.workers

        # Group by size first
        size_groups: Dict[int, List[FileInfo]] = defaultdict(list)
        for f in files:
            size_groups[f.size].append(f)

        candidate_files = [f for size, group in size_groups.items()
                          if len(group) >= 2 for f in group]
        total_to_hash = len(candidate_files)

        if not candidate_files:
            self._update_progress(55, "STAGE:2/4:Quick Hash|100|No size matches found")
            if perceptual_images:
                return self._find_perceptual_duplicates(files, [], workers)
            self._update_progress(100, "Scan complete!")
            return []

        # --- Stage 1: Quick-hash (first 4KB) to reject early mismatches ---
        self._update_progress(5, f"STAGE:2/4:Quick Hash|0|0 / {total_to_hash:,} files")
        quick_hash_groups: Dict[str, List[FileInfo]] = defaultdict(list)
        processed = 0
        last_update = time.monotonic()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_file = {
                pool.submit(self.compute_quick_hash, fi.path, fi.mtime, fi.size): fi
                for fi in candidate_files
            }

            for future in as_completed(future_to_file):
                if self.cancelled:
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

                fi = future_to_file[future]
                try:
                    qhash = future.result()
                except Exception:
                    qhash = None

                if qhash:
                    # Build a composite key: size + quick_hash
                    key = f"{fi.size}:{qhash}"
                    quick_hash_groups[key].append(fi)
                processed += 1

                now = time.monotonic()
                if now - last_update > 0.1:  # Throttle UI updates to 10/sec
                    last_update = now
                    stage_pct = int((processed / total_to_hash) * 100)
                    self._update_progress(5 + int(stage_pct * 0.1), f"STAGE:2/4:Quick Hash|{stage_pct}|{processed:,} / {total_to_hash:,} files")

        # Only full-hash files that passed the quick-hash filter
        full_hash_candidates = [f for group in quick_hash_groups.values()
                                if len(group) >= 2 for f in group]
        skipped = total_to_hash - len(full_hash_candidates)

        self._update_progress(
            15, f"STAGE:2/4:Quick Hash|100|{len(full_hash_candidates):,} candidates ({skipped:,} rejected)"
        )

        # --- Stage 2: Full SHA-256 hash (parallel) ---
        hash_groups: Dict[str, List[FileInfo]] = defaultdict(list)
        total_full = len(full_hash_candidates)
        processed = 0
        last_update = time.monotonic()

        if full_hash_candidates:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_to_file = {
                    pool.submit(self.compute_hash, fi.path, fi.mtime, fi.size): fi
                    for fi in full_hash_candidates
                }

                for future in as_completed(future_to_file):
                    if self.cancelled:
                        pool.shutdown(wait=False, cancel_futures=True)
                        break

                    fi = future_to_file[future]
                    try:
                        file_hash = future.result()
                    except Exception:
                        file_hash = None

                    if file_hash:
                        fi.hash = file_hash
                        hash_groups[file_hash].append(fi)
                    processed += 1

                    now = time.monotonic()
                    if now - last_update > 0.1:
                        last_update = now
                        stage_pct = int((processed / max(total_full, 1)) * 100)
                        self._update_progress(
                            15 + int(stage_pct * 0.3),
                            f"STAGE:3/4:Full Hash ({workers} threads)|{stage_pct}|{processed:,} / {total_full:,} files"
                        )

        # --- Stage 3: Byte-level verify hash matches ---
        self._update_progress(48, "STAGE:4/4:Verifying|0|Verifying duplicates...")
        duplicate_groups: List[DuplicateGroup] = []
        verify_count = 0
        groups_to_verify = [g for g in hash_groups.values() if len(g) >= 2]

        for group_files in groups_to_verify:
            if self.cancelled:
                break

            verified_subgroups = self._verify_hash_group(group_files)
            for subgroup in verified_subgroups:
                dg = DuplicateGroup(
                    files=subgroup,
                    similarity=100.0,
                    is_perceptual=False,
                    verified=True
                )
                duplicate_groups.append(dg)
                if group_callback:
                    group_callback(dg)
            verify_count += 1

            stage_pct = int((verify_count / max(len(groups_to_verify), 1)) * 50)
            self._update_progress(48 + int(stage_pct * 0.07), f"STAGE:4/4:Verifying|{stage_pct}|{verify_count:,} / {len(groups_to_verify):,} groups")

        self._update_progress(
            55,
            f"STAGE:4/4:Verifying|50|Found {len(duplicate_groups)} verified group(s)"
        )

        # --- Stage 4: Perceptual image comparison (parallel) ---
        if perceptual_images and not self.cancelled:
            perceptual_groups = self._find_perceptual_duplicates(
                files, duplicate_groups, workers, group_callback
            )
            duplicate_groups.extend(perceptual_groups)

        self._update_progress(100, "Scan complete!")
        return duplicate_groups

    def _find_perceptual_duplicates(
        self,
        files: List[FileInfo],
        existing_groups: List[DuplicateGroup],
        workers: int,
        group_callback: Optional[Callable[[DuplicateGroup], None]] = None
    ) -> List[DuplicateGroup]:
        """Find perceptually similar images using parallel hashing.

        Returns new DuplicateGroup entries (does not include existing_groups).
        """
        duplicate_groups: List[DuplicateGroup] = []

        exact_dup_paths = {
            f.path
            for dg in existing_groups
            if not dg.is_perceptual
            for f in dg.files
        }

        image_files = [
            f for f in files
            if f.is_image and f.path not in exact_dup_paths
        ]

        if not image_files or self.cancelled:
            return duplicate_groups

        # Parallel perceptual hashing — use ProcessPoolExecutor for CPU-bound
        # DCT work when there are enough images to justify process spawn overhead.
        # Falls back to ThreadPoolExecutor for small batches.
        use_processes = len(image_files) >= PROCESS_POOL_THRESHOLD
        pool_label = "processes" if use_processes else "threads"
        self._update_progress(60, f"STAGE:4/4:Verifying|55|Image hashes: 0 / {len(image_files):,} ({workers} {pool_label})")
        phash_groups: Dict[str, List[FileInfo]] = defaultdict(list)
        processed = 0
        last_update = time.monotonic()

        PoolClass = ProcessPoolExecutor if use_processes else ThreadPoolExecutor

        with PoolClass(max_workers=workers) as pool:
            if use_processes:
                # ProcessPoolExecutor: use top-level picklable function (takes tuple)
                future_to_file = {
                    pool.submit(_compute_perceptual_hash_standalone, (fi.path, fi.mtime, fi.size)): fi
                    for fi in image_files
                }
            else:
                # ThreadPoolExecutor: use instance method (no pickle needed)
                future_to_file = {
                    pool.submit(self.compute_perceptual_hash, fi.path, fi.mtime, fi.size): fi
                    for fi in image_files
                }

            for future in as_completed(future_to_file):
                if self.cancelled:
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

                fi = future_to_file[future]
                try:
                    ph = future.result()
                except Exception:
                    ph = None

                if ph:
                    fi.p_hash = ph
                    phash_groups[ph].append(fi)
                processed += 1

                now = time.monotonic()
                if now - last_update > 0.1:
                    last_update = now
                    stage_pct = 55 + int((processed / len(image_files)) * 25)
                    self._update_progress(
                        60 + int((processed / len(image_files)) * 20),
                        f"STAGE:4/4:Verifying|{stage_pct}|Image hashes: {processed:,} / {len(image_files):,} ({workers} {pool_label})"
                    )

        if not self.cancelled and phash_groups:
            self._update_progress(80, "STAGE:4/4:Verifying|80|Building BK-tree for similarity search...")

            hash_keys = list(phash_groups.keys())
            total_hashes = len(hash_keys)

            # Build BK-tree — O(n log n) insert
            bk_tree = BKTree()
            for ph in hash_keys:
                bk_tree.insert(ph)

            merged_groups: Set[str] = set()
            grouped_paths: Set[str] = set()  # Track all paths already in a group
            last_update = time.monotonic()

            # Query each hash for neighbors — O(n log n) total vs O(n^2) brute force
            for idx, ph1 in enumerate(hash_keys):
                if self.cancelled:
                    break

                if ph1 in merged_groups:
                    continue

                files1 = phash_groups[ph1]
                if not files1:
                    continue

                # Find all hashes within threshold (includes self at distance 0)
                neighbors = bk_tree.find_within(ph1, _config.image_similarity_threshold)

                # Separate exact matches (distance=0) from similar matches
                similar_hashes = [(nh, d) for nh, d in neighbors if d > 0 and nh not in merged_groups]

                if similar_hashes:
                    # Merge all similar hashes into one group with this hash
                    combined = list(files1)
                    min_distance = min(d for _, d in similar_hashes)

                    for nh, d in similar_hashes:
                        nh_files = phash_groups[nh]
                        if nh_files:
                            combined.extend(nh_files)
                            merged_groups.add(nh)
                            phash_groups[nh] = []

                    combined_paths = {f.path for f in combined}
                    if not (combined_paths & grouped_paths):
                        similarity = calculate_similarity(min_distance)
                        dg = DuplicateGroup(
                            files=combined,
                            similarity=similarity,
                            is_perceptual=True
                        )
                        duplicate_groups.append(dg)
                        grouped_paths.update(combined_paths)
                        if group_callback:
                            group_callback(dg)

                    merged_groups.add(ph1)

                now = time.monotonic()
                if now - last_update > 0.1:
                    last_update = now
                    stage_pct = 80 + int((idx / max(total_hashes, 1)) * 20)
                    self._update_progress(
                        80 + int((idx / max(total_hashes, 1)) * 15),
                        f"STAGE:4/4:Verifying|{stage_pct}|BK-tree search: {idx:,} / {total_hashes:,} hashes"
                    )

            # Exact perceptual hash matches (same hash, different files)
            for ph, img_files in phash_groups.items():
                if self.cancelled:
                    break

                if ph in merged_groups:
                    continue

                if len(img_files) >= 2:
                    img_paths = {f.path for f in img_files}
                    if not (img_paths & grouped_paths):
                        dg = DuplicateGroup(
                            files=img_files,
                            similarity=100.0,
                            is_perceptual=True
                        )
                        duplicate_groups.append(dg)
                        grouped_paths.update(img_paths)
                        if group_callback:
                            group_callback(dg)

        return duplicate_groups


# =============================================================================
# GUI APPLICATION
# =============================================================================

class DuplicateFinderApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        """Initialize the application."""
        self.root = root
        self.root.title(f"VKScan v{VERSION}")
        self.root.geometry("x".join(map(str, DEFAULT_WINDOW_SIZE)))
        self.root.minsize(*MIN_WINDOW_SIZE)

        # Set application icon
        self._set_app_icon(self.root)

        self.duplicate_groups: List[DuplicateGroup] = []
        self.scanner: Optional[DuplicateScanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self._populating = False  # Guard flag for tree population
        self._active_dropdown = None  # Currently open dropdown menu
        self._is_scanning = False  # True while scan is running
        self._last_scan_options: Optional[ScanOptions] = None
        self._stage_start_time: Optional[float] = None
        self._current_stage_key: str = ""
        self._detached_items: Dict[str, Tuple[str, int]] = {}  # Filter: item_id -> (parent, index)

        load_settings()

        self._setup_styles()
        self._apply_dark_titlebar(self.root)
        self._create_menu()
        self._create_main_ui()

        # Keyboard shortcuts
        self.root.bind("<Delete>", lambda e: self._delete_selected())
        self.root.bind("<Control-c>", lambda e: self._cancel_scan())
        self.root.bind("<Control-a>", lambda e: self._select_all())
        self.root.bind("<Control-e>", lambda e: self._export_report())
        self.root.bind("<Control-o>", lambda e: self._open_file_location())
        self.root.bind("<Escape>", lambda e: self._deselect_all())
        self.root.bind("<Control-f>", lambda e: self._focus_filter_search())

    # Dark theme color palette
    BG_DARK = "#1e1e2e"
    BG_MEDIUM = "#2a2a3d"
    BG_LIGHT = "#363650"
    ACCENT = "#7c3aed"
    ACCENT_HOVER = "#6d28d9"
    TEXT_PRIMARY = "#e2e8f0"
    TEXT_SECONDARY = "#94a3b8"
    TEXT_MUTED = "#64748b"
    SUCCESS = "#22c55e"
    WARNING = "#f59e0b"
    DANGER = "#ef4444"
    BORDER = "#4a4a6a"
    ROW_ODD = "#252540"
    ROW_EVEN = "#2a2a45"
    GROUP_HEADER = "#1a1a35"
    SELECTION = "#7c3aed"

    def _setup_styles(self) -> None:
        """Configure ttk styles with modern dark theme."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.root.configure(bg=self.BG_DARK)

        # TFrame
        style.configure("TFrame", background=self.BG_DARK)

        # TLabel
        style.configure("TLabel", background=self.BG_DARK, foreground=self.TEXT_PRIMARY,
                         font=("Segoe UI", 10))

        # TButton (accent)
        style.configure("TButton", background=self.ACCENT, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("TButton",
                   background=[("active", self.ACCENT_HOVER), ("disabled", self.BG_LIGHT)],
                   foreground=[("disabled", self.TEXT_MUTED)])

        # Accent.TButton
        style.configure("Accent.TButton", background=self.ACCENT, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10, "bold"), padding=(12, 5))
        style.map("Accent.TButton",
                   background=[("active", self.ACCENT_HOVER), ("disabled", self.BG_LIGHT)])

        # Danger.TButton
        style.configure("Danger.TButton", background=self.DANGER, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("Danger.TButton",
                   background=[("active", "#dc2626"), ("disabled", self.BG_LIGHT)])

        # Warning.TButton
        style.configure("Warning.TButton", background=self.WARNING, foreground="#1e1e2e",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("Warning.TButton",
                   background=[("active", "#d97706"), ("disabled", self.BG_LIGHT)])

        # Treeview
        style.configure("Treeview", background=self.BG_LIGHT, foreground=self.TEXT_PRIMARY,
                         fieldbackground=self.BG_LIGHT, rowheight=28,
                         font=("Segoe UI", 10), borderwidth=0)
        style.map("Treeview",
                   background=[("selected", self.SELECTION)],
                   foreground=[("selected", "#ffffff")])

        # Treeview.Heading
        style.configure("Treeview.Heading", background=self.BG_MEDIUM,
                         foreground=self.TEXT_PRIMARY,
                         font=("Segoe UI", 10, "bold"), borderwidth=1,
                         relief="flat")
        style.map("Treeview.Heading",
                   background=[("active", self.BG_LIGHT)])

        # Progressbar
        style.configure("TProgressbar", background=self.ACCENT,
                         troughcolor=self.BG_LIGHT, borderwidth=0, thickness=8)
        style.configure("Horizontal.TProgressbar", background=self.ACCENT,
                         troughcolor=self.BG_LIGHT, borderwidth=0, thickness=8)

        # TCheckbutton
        style.configure("TCheckbutton", background=self.BG_DARK,
                         foreground=self.TEXT_PRIMARY, font=("Segoe UI", 10))
        style.map("TCheckbutton",
                   background=[("active", self.BG_MEDIUM)])

        # TScale
        style.configure("TScale", background=self.BG_DARK,
                         troughcolor=self.BG_LIGHT)

        # TNotebook
        style.configure("TNotebook", background=self.BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.BG_MEDIUM,
                         foreground=self.TEXT_PRIMARY, padding=(10, 4),
                         font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                   background=[("selected", self.ACCENT), ("active", self.BG_LIGHT)],
                   foreground=[("selected", "#ffffff")])

        # TSeparator
        style.configure("TSeparator", background=self.BORDER)

        # Stage label style (bold)
        style.configure("Stage.TLabel", background=self.BG_DARK,
                         foreground=self.TEXT_PRIMARY,
                         font=("Segoe UI", 11, "bold"))

        # Detail label style (muted)
        style.configure("Detail.TLabel", background=self.BG_DARK,
                         foreground=self.TEXT_SECONDARY,
                         font=("Segoe UI", 9))

        # Overall label style (small muted)
        style.configure("Overall.TLabel", background=self.BG_DARK,
                         foreground=self.TEXT_MUTED,
                         font=("Segoe UI", 8))

        # Status bar style
        style.configure("Status.TLabel", background=self.BG_MEDIUM,
                         foreground=self.TEXT_SECONDARY,
                         font=("Segoe UI", 9), padding=(6, 3))

    @staticmethod
    def _apply_dark_titlebar(window) -> None:
        """Apply dark title bar on Windows 10/11 using DWM API.

        Uses DWMWA_USE_IMMERSIVE_DARK_MODE (attribute 20) to tell Windows
        to render the title bar in dark mode. No-op on Linux/macOS.
        """
        if sys.platform != "win32":
            return
        try:
            import ctypes
            window.update()  # Ensure the window has a valid HWND
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)
            )
        except Exception:
            pass

    def _get_resource_path(self, filename: str) -> Path:
        """Get path to a bundled resource file.

        Works both when running from source and from a PyInstaller .exe.
        PyInstaller extracts bundled data files to sys._MEIPASS.
        """
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS) / filename
        return Path(__file__).parent / filename

    def _set_app_icon(self, window) -> None:
        """Set the application icon on a window.

        Uses iconbitmap for .ico (sets both titlebar and taskbar icon on Windows).
        Falls back to iconphoto with .png (cross-platform).
        Stores the PhotoImage on the instance to prevent garbage collection.
        """
        try:
            ico_path = self._get_resource_path("vkscan_icon.ico")
            if ico_path.exists():
                window.iconbitmap(str(ico_path))
                return
        except Exception:
            pass

        try:
            png_path = self._get_resource_path("vkscan_icon.png")
            if png_path.exists():
                if not hasattr(self, '_icon_photo'):
                    self._icon_photo = tk.PhotoImage(file=str(png_path))
                window.iconphoto(True, self._icon_photo)
        except Exception:
            pass

    def _center_dialog(self, dialog: tk.Toplevel, width: int, height: int) -> None:
        """Position a dialog centered over the main window."""
        self.root.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        x = root_x + (root_w - width) // 2
        y = root_y + (root_h - height) // 2
        # Ensure it stays on screen
        x = max(0, x)
        y = max(0, y)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

    def _create_menu(self) -> None:
        """Create a fully custom dark menu bar with pure tkinter widgets.

        Both tk.Menu (native) and tk.Menubutton (uses tk.Menu internally)
        are rendered by the OS on Windows, ignoring colors and always
        drawing system borders. This implementation uses tk.Toplevel
        popups with tk.Label items — zero native menu widgets.
        """
        # Remove native menubar
        self.root.config(menu="")

        # Custom menu bar frame
        self._menubar = tk.Frame(self.root, bg=self.BG_DARK, bd=0)
        self._menubar.pack(side=tk.TOP, fill=tk.X)

        # Thin separator line under the menu bar
        tk.Frame(self.root, bg=self.BORDER, height=1).pack(side=tk.TOP, fill=tk.X)

        # Define menus: (label, [(item_label, command, shortcut), ...])
        # Use None for separator
        menus = [
            ("File", [
                ("Scan...", self._start_scan_dialog, ""),
                ("Export Report", self._export_report, "Ctrl+E"),
                None,
                ("Exit", self.root.quit, ""),
            ]),
            ("Edit", [
                ("Select All", self._select_all, "Ctrl+A"),
                ("Deselect All", self._deselect_all, "Esc"),
                ("Auto-Select Duplicates", self._auto_select_duplicates, ""),
                None,
                ("Delete Selected", self._delete_selected, "Del"),
                ("Move Selected", self._move_selected, ""),
            ]),
            ("View", [
                ("Preview", self._show_preview, ""),
                ("Compare", self._compare_selected, ""),
                ("Open File Location", self._open_file_location, "Ctrl+O"),
            ]),
            ("Help", [
                ("About", self._show_about, ""),
            ]),
        ]

        for menu_label, items in menus:
            btn = tk.Label(
                self._menubar, text=f"  {menu_label}  ",
                bg=self.BG_DARK, fg=self.TEXT_PRIMARY,
                font=("Segoe UI", 10), cursor="hand2", padx=4, pady=4
            )
            btn.pack(side=tk.LEFT)
            btn.bind("<Button-1>", lambda e, b=btn, it=items: self._toggle_dropdown(b, it))
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.BG_LIGHT))
            btn.bind("<Leave>", lambda e, b=btn: self._menu_btn_leave(b))

        # Close dropdown when clicking elsewhere
        self.root.bind("<Button-1>", self._maybe_close_dropdown, add="+")

    def _menu_btn_leave(self, btn) -> None:
        """Reset menu button bg, unless its dropdown is currently open."""
        if self._active_dropdown and self._active_dropdown[0] == btn:
            return  # Keep highlighted while dropdown is open
        btn.config(bg=self.BG_DARK)

    def _toggle_dropdown(self, btn, items) -> None:
        """Open or close a dropdown menu panel."""
        # If this dropdown is already open, close it
        if self._active_dropdown and self._active_dropdown[0] == btn:
            self._close_dropdown()
            return

        # Close any other open dropdown first
        self._close_dropdown()

        # Calculate position below the button
        btn.update_idletasks()
        x = btn.winfo_rootx()
        y = btn.winfo_rooty() + btn.winfo_height()

        # Create dropdown as an undecorated Toplevel
        dropdown = tk.Toplevel(self.root)
        dropdown.overrideredirect(True)  # No title bar, no OS borders
        dropdown.configure(bg=self.BORDER)  # Thin border color
        dropdown.attributes("-topmost", True)

        # Inner frame for content (1px padding = border effect)
        inner = tk.Frame(dropdown, bg=self.BG_DARK, bd=0)
        inner.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)

        # Build menu items
        for item in items:
            if item is None:
                # Separator
                tk.Frame(inner, bg=self.BORDER, height=1).pack(fill=tk.X, padx=8, pady=3)
                continue

            label_text, command, shortcut = item
            row = tk.Frame(inner, bg=self.BG_DARK, cursor="hand2")
            row.pack(fill=tk.X)

            lbl = tk.Label(
                row, text=f"  {label_text}", anchor=tk.W,
                bg=self.BG_DARK, fg=self.TEXT_PRIMARY,
                font=("Segoe UI", 10), padx=8, pady=5
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

            if shortcut:
                shortcut_lbl = tk.Label(
                    row, text=f"{shortcut}  ", anchor=tk.E,
                    bg=self.BG_DARK, fg=self.TEXT_MUTED,
                    font=("Segoe UI", 9), padx=8, pady=5
                )
                shortcut_lbl.pack(side=tk.RIGHT)
                # Hover effect for shortcut label too
                for widget in (row, lbl, shortcut_lbl):
                    widget.bind("<Enter>", lambda e, r=row, l=lbl, s=shortcut_lbl: (
                        r.config(bg=self.ACCENT), l.config(bg=self.ACCENT, fg="#ffffff"),
                        s.config(bg=self.ACCENT, fg="#ffffff")
                    ))
                    widget.bind("<Leave>", lambda e, r=row, l=lbl, s=shortcut_lbl: (
                        r.config(bg=self.BG_DARK), l.config(bg=self.BG_DARK, fg=self.TEXT_PRIMARY),
                        s.config(bg=self.BG_DARK, fg=self.TEXT_MUTED)
                    ))
                    widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))
            else:
                for widget in (row, lbl):
                    widget.bind("<Enter>", lambda e, r=row, l=lbl: (
                        r.config(bg=self.ACCENT), l.config(bg=self.ACCENT, fg="#ffffff")
                    ))
                    widget.bind("<Leave>", lambda e, r=row, l=lbl: (
                        r.config(bg=self.BG_DARK), l.config(bg=self.BG_DARK, fg=self.TEXT_PRIMARY)
                    ))
                    widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))

        dropdown.geometry(f"+{x}+{y}")
        btn.config(bg=self.BG_LIGHT)
        self._active_dropdown = (btn, dropdown)

    def _dropdown_click(self, command) -> None:
        """Handle click on a dropdown menu item."""
        self._close_dropdown()
        self.root.after(10, command)  # Small delay so dropdown closes visually first

    def _close_dropdown(self) -> None:
        """Close the currently open dropdown."""
        if self._active_dropdown:
            btn, dropdown = self._active_dropdown
            if btn is not None:
                btn.config(bg=self.BG_DARK)
            dropdown.destroy()
            self._active_dropdown = None

    def _maybe_close_dropdown(self, event) -> None:
        """Close dropdown if click is outside the menu bar and dropdown."""
        if not self._active_dropdown:
            return
        # Check if click is on the menubar or dropdown
        widget = event.widget
        btn, dropdown = self._active_dropdown
        try:
            if widget == dropdown or str(widget).startswith(str(dropdown)):
                return
            if widget == self._menubar or widget.master == self._menubar:
                return
        except Exception:
            pass
        self._close_dropdown()

    def _create_main_ui(self) -> None:
        """Create main user interface."""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_control_panel(main_frame)
        self._create_filter_bar(main_frame)

        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("path", "size", "modified", "similarity"),
            show="tree headings",
            selectmode="extended",
            yscrollcommand=y_scroll.set
        )

        self.tree.heading("#0", text="Files")
        self.tree.heading("path", text="Path")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Modified")
        self.tree.heading("similarity", text="Similarity")

        self.tree.column("#0", width=300)
        self.tree.column("path", width=300)
        self.tree.column("size", width=80)
        self.tree.column("modified", width=140)
        self.tree.column("similarity", width=80)

        # Sortable column headers
        for col in ("path", "size", "modified", "similarity"):
            self.tree.heading(col, command=lambda c=col: self._sort_column(c, False))

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        y_scroll.config(command=self.tree.yview)

        # Double-click on treeview to preview all files in the group
        def _on_double_click(event):
            region = self.tree.identify_region(event.x, event.y)
            if region in ("cell", "tree"):
                item = self.tree.identify_row(event.y)
                if item:
                    self._preview_item_or_group(item)
        self.tree.bind("<Double-Button-1>", _on_double_click)

        # Right-click context menu (custom dark, same as main menu dropdowns)
        self._context_items = [
            ("Preview", self._show_preview, ""),
            ("Open File Location", self._open_file_location, ""),
            None,
            ("Compare Selected", self._compare_selected, ""),
            None,
            ("Delete Selected", self._delete_selected, ""),
            ("Move Selected", self._move_selected, ""),
        ]
        self.tree.bind("<Button-3>", self._show_context_menu)  # Windows/Linux
        self.tree.bind("<Button-2>", self._show_context_menu)  # macOS

        # Alternating row colors for readability (dark theme)
        self.tree.tag_configure("odd_row", background=self.ROW_ODD, foreground=self.TEXT_PRIMARY)
        self.tree.tag_configure("even_row", background=self.ROW_EVEN, foreground=self.TEXT_PRIMARY)
        self.tree.tag_configure("group_header", background=self.GROUP_HEADER,
                                foreground=self.TEXT_PRIMARY, font=("Segoe UI", 10, "bold"))

        # Update status bar when selection changes
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_selection_status())

        self._create_status_bar(main_frame)

    def _create_control_panel(self, parent: tk.Frame) -> None:
        """Create control panel with buttons and progress display."""
        # Button row
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(
            btn_frame, text="▶ Scan", command=self._start_scan_dialog,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Options", command=self._show_options
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Compare", command=self._compare_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Delete", command=self._delete_selected,
            style="Danger.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Move", command=self._move_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Auto-Select",
            command=self._auto_select_duplicates
        ).pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_scan,
            state="disabled", style="Warning.TButton"
        )
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        self.rescan_btn = ttk.Button(
            btn_frame, text="\u27f3 Rescan", command=self._rescan,
            state="disabled"
        )
        self.rescan_btn.pack(side=tk.LEFT, padx=5)

        # Progress area
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, pady=(0, 5))

        # Stage label (bold, prominent)
        self.stage_label = ttk.Label(progress_frame, text="Ready",
                                      style="Stage.TLabel")
        self.stage_label.pack(anchor=tk.W)

        # Per-stage progress bar
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(
            progress_frame, variable=self.progress_var, maximum=100,
            mode="determinate", length=400
        ).pack(fill=tk.X, pady=(3, 2))

        # Bottom row: detail on left, overall on right
        detail_row = ttk.Frame(progress_frame)
        detail_row.pack(fill=tk.X)

        self.detail_label = ttk.Label(detail_row, text="",
                                       style="Detail.TLabel")
        self.detail_label.pack(side=tk.LEFT)

        self.overall_label = ttk.Label(detail_row, text="",
                                        style="Overall.TLabel")
        self.overall_label.pack(side=tk.RIGHT)

        # Keep progress_label as a hidden reference for compatibility
        self.progress_label = self.stage_label

    def _create_filter_bar(self, parent: tk.Frame) -> None:
        """Create filter bar for filtering scan results.
        
        Provides: text search (filename/path), type filter (All/Exact/Similar),
        and minimum size filter. Filters use detach/reattach on treeview items
        so no data is lost — just visually hidden.
        """
        filter_frame = tk.Frame(parent, bg=self.BG_MEDIUM, bd=0)
        filter_frame.pack(fill=tk.X, pady=(5, 0))

        # Inner padding
        inner = tk.Frame(filter_frame, bg=self.BG_MEDIUM, bd=0)
        inner.pack(fill=tk.X, padx=8, pady=4)

        # Search icon + entry
        tk.Label(
            inner, text="🔍", bg=self.BG_MEDIUM, fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_search_var = tk.StringVar()
        self._filter_search_var.trace_add("write", lambda *_: self._apply_filters())
        search_entry = tk.Entry(
            inner, textvariable=self._filter_search_var, width=25,
            bg=self.BG_LIGHT, fg=self.TEXT_PRIMARY,
            insertbackground=self.TEXT_PRIMARY,
            relief="flat", font=("Segoe UI", 10), bd=0,
            highlightthickness=1, highlightcolor=self.ACCENT,
            highlightbackground=self.BORDER
        )
        search_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=2)
        self._filter_search_entry = search_entry  # Store ref for Ctrl+F focus

        # Placeholder text
        def _on_focus_in(e):
            if search_entry.get() == "":
                pass  # placeholder handled by StringVar
        def _on_focus_out(e):
            pass
        search_entry.bind("<FocusIn>", _on_focus_in)
        search_entry.bind("<FocusOut>", _on_focus_out)

        # Type filter: All / Exact / Similar
        tk.Label(
            inner, text="Type:", bg=self.BG_MEDIUM, fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_type_var = tk.StringVar(value="All")
        for label in ("All", "Exact", "Similar"):
            rb = tk.Radiobutton(
                inner, text=label, variable=self._filter_type_var, value=label,
                bg=self.BG_MEDIUM, fg=self.TEXT_PRIMARY,
                selectcolor=self.BG_LIGHT, activebackground=self.BG_MEDIUM,
                activeforeground=self.TEXT_PRIMARY,
                font=("Segoe UI", 9), bd=0, highlightthickness=0,
                command=self._apply_filters
            )
            rb.pack(side=tk.LEFT, padx=2)

        # Separator
        tk.Frame(inner, bg=self.BORDER, width=1).pack(
            side=tk.LEFT, fill=tk.Y, padx=8, pady=2
        )

        # Min size filter
        tk.Label(
            inner, text="Min size:", bg=self.BG_MEDIUM, fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_size_var = tk.StringVar(value="Any")
        size_options = ["Any", "1 KB", "100 KB", "1 MB", "10 MB", "100 MB", "1 GB"]
        size_menu = tk.OptionMenu(inner, self._filter_size_var, *size_options,
                                  command=lambda _: self._apply_filters())
        size_menu.config(
            bg=self.BG_LIGHT, fg=self.TEXT_PRIMARY,
            activebackground=self.ACCENT, activeforeground="#ffffff",
            highlightthickness=0, bd=0, font=("Segoe UI", 9),
            relief="flat"
        )
        size_menu["menu"].config(
            bg=self.BG_LIGHT, fg=self.TEXT_PRIMARY,
            activebackground=self.ACCENT, activeforeground="#ffffff",
            font=("Segoe UI", 9), bd=0
        )
        size_menu.pack(side=tk.LEFT, padx=(0, 10))

        # Clear filters button
        clear_btn = tk.Label(
            inner, text="✕ Clear", bg=self.BG_MEDIUM, fg=self.TEXT_MUTED,
            font=("Segoe UI", 9), cursor="hand2", padx=4
        )
        clear_btn.pack(side=tk.LEFT, padx=(0, 4))
        clear_btn.bind("<Button-1>", lambda e: self._clear_filters())
        clear_btn.bind("<Enter>", lambda e: clear_btn.config(fg=self.TEXT_PRIMARY))
        clear_btn.bind("<Leave>", lambda e: clear_btn.config(fg=self.TEXT_MUTED))

        # Match count label
        self._filter_count_label = tk.Label(
            inner, text="", bg=self.BG_MEDIUM, fg=self.TEXT_MUTED,
            font=("Segoe UI", 9)
        )
        self._filter_count_label.pack(side=tk.RIGHT)

    def _focus_filter_search(self) -> None:
        """Focus the filter search entry (Ctrl+F)."""
        try:
            self._filter_search_entry.focus_set()
            self._filter_search_entry.select_range(0, tk.END)
        except (tk.TclError, AttributeError):
            pass

    def _clear_filters(self) -> None:
        """Reset all filters to defaults."""
        self._filter_search_var.set("")
        self._filter_type_var.set("All")
        self._filter_size_var.set("Any")
        self._apply_filters()

    def _parse_min_size_bytes(self) -> int:
        """Parse the min size dropdown value to bytes."""
        SIZE_MAP = {
            "Any": 0, "1 KB": 1024, "100 KB": 102400,
            "1 MB": 1048576, "10 MB": 10485760,
            "100 MB": 104857600, "1 GB": 1073741824
        }
        return SIZE_MAP.get(self._filter_size_var.get(), 0)

    def _apply_filters(self) -> None:
        """Apply all active filters to the treeview using detach/reattach.
        
        This preserves all data — items are just visually hidden when filtered out.
        When filters are cleared, all items reappear in their original positions.
        """
        if self._is_scanning or self._populating:
            return

        search_text = self._filter_search_var.get().lower().strip()
        type_filter = self._filter_type_var.get()  # "All", "Exact", "Similar"
        min_size = self._parse_min_size_bytes()
        SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

        # First, reattach everything that was previously detached
        for item_id, (parent, idx) in list(self._detached_items.items()):
            try:
                self.tree.reattach(item_id, parent, idx)
            except tk.TclError:
                pass  # Item may have been deleted
        self._detached_items.clear()

        visible_groups = 0
        total_groups = 0

        # Now evaluate each group
        for group_id in list(self.tree.get_children()):
            total_groups += 1
            header = self.tree.item(group_id, "text")
            children = list(self.tree.get_children(group_id))

            # Type filter: check group header
            if type_filter == "Exact" and "(similar)" in header:
                # Detach entire group
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
                continue
            elif type_filter == "Similar" and "(similar)" not in header:
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
                continue

            # For each child, check search text and min size
            visible_children = 0
            for child_id in children:
                values = self.tree.item(child_id, "values")
                if not values:
                    continue

                path = values[0].lower() if values[0] else ""
                filename = Path(path).name if path else ""

                # Parse size
                size_bytes = 0
                try:
                    parts = values[1].split()
                    size_bytes = int(float(parts[0]) * SIZE_MULT.get(parts[1] if len(parts) > 1 else "B", 1))
                except (ValueError, IndexError):
                    pass

                # Check filters
                match = True
                if search_text and search_text not in path and search_text not in filename:
                    match = False
                if min_size > 0 and size_bytes < min_size:
                    match = False

                if not match:
                    idx = self.tree.index(child_id)
                    self._detached_items[child_id] = (group_id, idx)
                    self.tree.detach(child_id)
                else:
                    visible_children += 1

            # If no children visible, hide the group too
            remaining = list(self.tree.get_children(group_id))
            if not remaining:
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
            else:
                visible_groups += 1

        # Update count label
        is_filtered = bool(search_text or type_filter != "All" or min_size > 0)
        if is_filtered:
            self._filter_count_label.config(
                text=f"Showing {visible_groups} / {total_groups} groups"
            )
        else:
            self._filter_count_label.config(text="")

    def _create_status_bar(self, parent: tk.Frame) -> None:
        """Create status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        trash_status = ""
        if HAS_SEND2TRASH and _config.use_trash:
            trash_status = " | 🗑️ Trash enabled"
        else:
            trash_status = " | ⚠️ Permanent delete (install send2trash for trash support)"

        self.status_label = ttk.Label(
            status_frame,
            text=f"Click Scan to begin.{trash_status}",
            style="Status.TLabel", anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)

    def _update_selection_status(self) -> None:
        """Update status bar to reflect current treeview selection."""
        if self._is_scanning or self._populating:
            return

        selected = self.tree.selection()
        paths = [self.tree.item(item, "values")[0]
                 for item in selected
                 if self.tree.item(item, "values")]
        count = len(paths)

        if count == 0:
            # No selection — show scan summary if we have results
            if self.duplicate_groups:
                total_recoverable = sum(g.recoverable_size() for g in self.duplicate_groups)
                total_files = sum(len(g.files) for g in self.duplicate_groups)
                self.status_label.config(
                    text=(
                        f"{len(self.duplicate_groups)} group(s), "
                        f"{total_files} files | "
                        f"Recoverable: {format_size(total_recoverable)}"
                    )
                )
            else:
                self.status_label.config(text="Click Scan to begin.")
        elif count == 1:
            self.status_label.config(text=f"Selected: {paths[0]}")
        else:
            total_size = 0
            for p in paths:
                try:
                    total_size += os.path.getsize(p)
                except OSError:
                    pass
            self.status_label.config(
                text=f"{count} files selected ({format_size(total_size)})"
            )

    def _cancel_scan(self) -> None:
        """Cancel the current scan operation."""
        if self.scanner:
            self.scanner.cancelled = True
            self.progress_label.config(text="Cancelling...")

    def _start_scan_dialog(self) -> None:
        """Open scan dialog."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Busy", "Please wait or cancel current scan.")
            return

        dialog = ScanDialog(self.root)
        self._center_dialog(dialog.top, 550, 420)
        self._apply_dark_titlebar(dialog.top)
        self.root.wait_window(dialog.top)

        if dialog.result:
            self._perform_scan(dialog.result)

    def _rescan(self) -> None:
        if self._last_scan_options is None:
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Busy", "Please wait or cancel current scan.")
            return
        self._perform_scan(self._last_scan_options)

    def _perform_scan(self, options: ScanOptions) -> None:
        """Perform the actual scan operation."""
        self._last_scan_options = options
        self._stage_start_time = None
        self._current_stage_key = ""
        save_settings(scan_paths=options.paths, scan_exclusions=list(options.exclusions), scan_perceptual=options.perceptual)
        self.cancel_btn.config(state="normal")
        self.progress_var.set(0)
        self.progress_label.config(text="Scanning...")
        self._scan_start_time = time.monotonic()
        self._is_scanning = True
        self._dim_column_headers(True)

        # Queue-based progress: scan thread writes here, GUI polls it
        self._progress_queue: queue.Queue = queue.Queue()
        self._scan_finished = False
        self._live_group_count = 0  # Track groups added during scan

        # Clear filters and detached items before new scan
        self._detached_items.clear()
        self._clear_filters()

        # Clear tree for fresh scan
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scanner = DuplicateScanner(progress_callback=self._enqueue_progress)

        def group_callback(group: DuplicateGroup) -> None:
            """Called from scanner when a new duplicate group is found."""
            self._progress_queue.put(("_group", 0, group))

        def scan_task() -> None:
            try:
                files = self.scanner.collect_files(options.paths, options.exclusions)

                if not self.scanner.cancelled:
                    self.duplicate_groups = self.scanner.find_duplicates(
                        files, options.perceptual,
                        group_callback=group_callback
                    )

                    if not self.scanner.cancelled:
                        self._progress_queue.put(("_done", 0, ""))
                    else:
                        self._progress_queue.put(("_cancelled", 0, ""))
            except Exception as e:
                self._progress_queue.put(("_error", 0, str(e)))
            finally:
                self._scan_finished = True

        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()

        # Start the GUI poll loop
        self._poll_progress()

    def _enqueue_progress(self, percent: int, message: str) -> None:
        """Called from scan thread — puts progress onto the queue (never touches tkinter)."""
        try:
            self._progress_queue.put(("progress", int(percent), str(message)))
        except Exception:
            pass

    # Max groups to insert into the treeview per poll cycle.
    # Higher = more responsive results, but each insert does tree ops.
    # 5 keeps each poll under ~10ms even with large groups.
    _MAX_GROUPS_PER_POLL = 5

    def _poll_progress(self) -> None:
        """Main-thread poll loop: drains the queue and updates the GUI.

        Runs every 50ms via root.after(), giving tkinter plenty of time
        to process mouse clicks, window drags, and button presses between polls.
        Group insertions are capped per cycle to prevent "Not Responding".
        """
        try:
            # Drain all pending messages (but only apply the latest progress)
            latest_percent = None
            latest_message = None
            groups_added = 0

            while True:
                try:
                    msg_type, percent, message = self._progress_queue.get_nowait()
                except queue.Empty:
                    break

                if msg_type == "progress":
                    latest_percent = percent
                    latest_message = message
                elif msg_type == "_group":
                    if groups_added < self._MAX_GROUPS_PER_POLL:
                        group = message  # message is actually a DuplicateGroup
                        self._add_group_to_tree(group)
                        groups_added += 1
                    else:
                        # Put it back for the next poll cycle
                        self._progress_queue.put((msg_type, percent, message))
                        break  # Stop draining — let the event loop breathe
                elif msg_type == "_done":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    # Final re-sort and status update (groups already in tree)
                    self._finalize_tree()
                    self.cancel_btn.config(state="disabled")
                    self.rescan_btn.config(state="normal")
                    self.stage_label.config(text="Scan Complete")
                    self.detail_label.config(text="")
                    self.overall_label.config(text="")
                    return  # Stop polling
                elif msg_type == "_cancelled":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    self.stage_label.config(text="Cancelled")
                    self.detail_label.config(text="")
                    self.overall_label.config(text="")
                    self.cancel_btn.config(state="disabled")
                    self.root.after(2000, lambda: self.progress_var.set(0))
                    return  # Stop polling
                elif msg_type == "_error":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    messagebox.showerror("Error", message)
                    self.cancel_btn.config(state="disabled")
                    return  # Stop polling

            # Apply latest progress update (skip intermediate ones)
            if latest_message is not None:
                # Parse STAGE format: "STAGE:N/M:StageName|percent|detail"
                if latest_message.startswith("STAGE:"):
                    try:
                        header, stage_pct_str, detail = latest_message[6:].split("|", 2)
                        stage_num_str, stage_name = header.split(":", 1)
                        stage_pct = int(stage_pct_str)
                        # ETA computation
                        if stage_num_str != self._current_stage_key:
                            self._current_stage_key = stage_num_str
                            self._stage_start_time = time.monotonic()
                        if stage_pct > 5 and self._stage_start_time is not None:
                            elapsed = time.monotonic() - self._stage_start_time
                            if elapsed >= 2.0:
                                eta_seconds = elapsed / stage_pct * (100 - stage_pct)
                                if eta_seconds < 60:
                                    eta_str = f"{int(eta_seconds)}s"
                                elif eta_seconds < 3600:
                                    eta_str = f"{int(eta_seconds // 60)}m {int(eta_seconds % 60)}s"
                                else:
                                    eta_str = f"{int(eta_seconds // 3600)}h {int((eta_seconds % 3600) // 60)}m"
                                detail = f"{detail}  (ETA: ~{eta_str})"
                        self.stage_label.config(text=f"Stage {stage_num_str}: {stage_name}")
                        self.progress_var.set(stage_pct)
                        self.detail_label.config(text=detail)
                        self.overall_label.config(text=f"Stage {stage_num_str}")
                    except (ValueError, IndexError):
                        # Fallback if parsing fails
                        self.stage_label.config(text=latest_message)
                        if latest_percent is not None:
                            self.progress_var.set(latest_percent)
                else:
                    self.stage_label.config(text=latest_message)
                    self.detail_label.config(text="")
                    if latest_percent is not None:
                        self.progress_var.set(latest_percent)
            elif latest_percent is not None:
                self.progress_var.set(latest_percent)

        except Exception:
            pass

        # Schedule next poll in 50ms — keeps the GUI responsive
        self.root.after(50, self._poll_progress)

    def _add_group_to_tree(self, group: DuplicateGroup) -> None:
        """Add a single duplicate group to the treeview during scanning.

        Appends to the end for speed — sorting happens after the scan
        completes via _finalize_tree or user-triggered column sorts.
        """
        self._live_group_count += 1
        recoverable = group.recoverable_size()

        # Build header text
        header = (
            f"{len(group.files)} file(s) | "
            f"Recover: {format_size(recoverable)} | "
            f"{group.similarity:.1f}%"
        )
        if group.is_perceptual:
            header += " (similar)"
        elif group.verified:
            header += " ✓ verified"

        # Append at end (fast) — final sort happens after scan completes
        group_id = self.tree.insert("", "end", open=True,
                                     text=header, tags=("group_header", str(recoverable)))

        for idx, file_info in enumerate(group.files):
            mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                "%Y-%m-%d %H:%M"
            ) if file_info.mtime else ""
            row_tag = "odd_row" if idx % 2 else "even_row"
            self.tree.insert(
                group_id, "end",
                text=Path(file_info.path).name,
                values=(
                    file_info.path,
                    format_size(file_info.size),
                    mtime_str,
                    f"{group.similarity:.1f}%"
                ),
                tags=(row_tag, f"sz:{file_info.size}")
            )

        # Update status with running count
        self.status_label.config(
            text=f"Found {self._live_group_count} duplicate group(s) so far..."
        )

    def _finalize_tree(self) -> None:
        """Sort tree by recoverable size and update status after scan completes."""
        # Sort groups by recoverable size (largest first) using the tag we stored
        all_groups = list(self.tree.get_children())
        if all_groups:
            def recoverable_key(gid):
                tags = self.tree.item(gid, "tags")
                try:
                    return int(tags[1]) if len(tags) > 1 else 0
                except (ValueError, IndexError):
                    return 0

            sorted_groups = sorted(all_groups, key=recoverable_key, reverse=True)
            for i, gid in enumerate(sorted_groups):
                self.tree.move(gid, "", i)

        total_recoverable = 0
        total_files = 0
        for group in self.duplicate_groups:
            total_recoverable += group.recoverable_size()
            total_files += len(group.files)

        trash_note = ""
        if HAS_SEND2TRASH and _config.use_trash:
            trash_note = " | 🗑️ Trash"

        elapsed = ""
        if hasattr(self, "_scan_start_time"):
            secs = time.monotonic() - self._scan_start_time
            if secs >= 60:
                elapsed = f" | {int(secs // 60)}m {int(secs % 60)}s"
            else:
                elapsed = f" | {secs:.1f}s"

        self.status_label.config(
            text=(
                f"{len(self.duplicate_groups)} group(s), "
                f"{total_files} files | "
                f"Recoverable: {format_size(total_recoverable)}"
                f"{elapsed}{trash_note}"
            )
        )
        self.root.after(3000, lambda: self.progress_var.set(0))

    def _populate_tree(self) -> None:
        """Populate treeview with duplicate groups (used for refresh after delete/move)."""
        if self._populating:
            return
        self._populating = True

        try:
            for item in self.tree.get_children():
                self.tree.delete(item)

            self.duplicate_groups.sort(key=lambda g: -g.recoverable_size())

            total_recoverable = 0

            for group in self.duplicate_groups:
                group_id = self.tree.insert("", "end", open=True)
                recoverable = group.recoverable_size()
                total_recoverable += recoverable

                header = (
                    f"{len(group.files)} file(s) | "
                    f"Recover: {format_size(recoverable)} | "
                    f"{group.similarity:.1f}%"
                )

                if group.is_perceptual:
                    header += " (similar)"
                elif group.verified:
                    header += " ✓ verified"

                self.tree.item(group_id, text=header, tags=("group_header",))

                for idx, file_info in enumerate(group.files):
                    mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    ) if file_info.mtime else ""
                    row_tag = "odd_row" if idx % 2 else "even_row"
                    self.tree.insert(
                        group_id,
                        "end",
                        text=Path(file_info.path).name,
                        values=(
                            file_info.path,
                            format_size(file_info.size),
                            mtime_str,
                            f"{group.similarity:.1f}%"
                        ),
                        tags=(row_tag, f"sz:{file_info.size}")
                    )

            trash_note = ""
            if HAS_SEND2TRASH and _config.use_trash:
                trash_note = " | 🗑️ Trash"

            elapsed = ""
            if hasattr(self, "_scan_start_time"):
                secs = time.monotonic() - self._scan_start_time
                if secs >= 60:
                    elapsed = f" | {int(secs // 60)}m {int(secs % 60)}s"
                else:
                    elapsed = f" | {secs:.1f}s"

            total_files = sum(len(g.files) for g in self.duplicate_groups)
            self.status_label.config(
                text=(
                    f"{len(self.duplicate_groups)} group(s), "
                    f"{total_files} files | "
                    f"Recoverable: {format_size(total_recoverable)}"
                    f"{elapsed}{trash_note}"
                )
            )

            self.root.after(2000, lambda: self.progress_var.set(0))

        finally:
            self._populating = False

    def _dim_column_headers(self, dimmed: bool) -> None:
        """Dim or restore column headers to indicate sorting availability."""
        col_names = {"path": "Path", "size": "Size", "modified": "Modified", "similarity": "Similarity"}
        if dimmed:
            # Grey out headers and show scanning note
            style = ttk.Style()
            style.configure("Treeview.Heading",
                            foreground=self.TEXT_MUTED,
                            background=self.BG_DARK)
            for c, name in col_names.items():
                self.tree.heading(c, text=f"{name}")
        else:
            # Restore normal header style
            style = ttk.Style()
            style.configure("Treeview.Heading",
                            foreground=self.TEXT_PRIMARY,
                            background=self.BG_MEDIUM)
            for c, name in col_names.items():
                self.tree.heading(c, text=name,
                                  command=lambda _c=c: self._sort_column(_c, False))

    def _get_group_paths(self, group_id: str) -> List[str]:
        """Get all file paths from a group's children."""
        paths = []
        for child in self.tree.get_children(group_id):
            values = self.tree.item(child, "values")
            if values:
                paths.append(values[0])
        return paths

    def _get_selected_paths(self) -> List[str]:
        """Get paths of selected items."""
        if self._populating:
            return []
        items = self.tree.selection()
        paths = []
        for item in items:
            values = self.tree.item(item, "values")
            if values:
                paths.append(values[0])
        return paths

    def _preview_item_or_group(self, item: str) -> None:
        """Preview all files in the group containing the clicked item.

        If a file item is clicked, finds its parent group and previews all siblings.
        If a group header is clicked, previews all children directly.
        """
        values = self.tree.item(item, "values")
        if values:
            # File item — find its parent group
            parent = self.tree.parent(item)
            if parent:
                paths = self._get_group_paths(parent)
            else:
                paths = [values[0]]
        else:
            # Group header — get all children
            paths = self._get_group_paths(item)

        if paths:
            pw = PreviewWindow(self.root, paths, on_delete=self._on_preview_delete)
            self._center_dialog(pw.top, 700, 500)
            self._apply_dark_titlebar(pw.top)

    def _show_preview(self) -> None:
        """Show preview of selected files, expanding to full group if single item selected."""
        selected = self.tree.selection()
        if not selected:
            return

        # If only one item selected, preview its whole group
        if len(selected) == 1:
            self._preview_item_or_group(selected[0])
            return

        # Multiple items selected — preview just those
        paths = self._get_selected_paths()
        if paths:
            pw = PreviewWindow(self.root, paths, on_delete=self._on_preview_delete)
            self._center_dialog(pw.top, 700, 500)
            self._apply_dark_titlebar(pw.top)

    def _compare_selected(self) -> None:
        """Compare selected files side by side."""
        paths = self._get_selected_paths()
        if len(paths) >= 2:
            cw = ComparisonWindow(self.root, paths[:2], on_delete=self._on_preview_delete)
            self._center_dialog(cw.top, 900, 600)
            self._apply_dark_titlebar(cw.top)

    def _delete_selected(self) -> None:
        """Delete selected files (via trash if available)."""
        paths = self._get_selected_paths()
        if not paths:
            return

        file_list = "\n".join(f"  {Path(p).name}" for p in paths[:10])
        if len(paths) > 10:
            file_list += f"\n  ... and {len(paths) - 10} more"

        method = "move to trash" if (HAS_SEND2TRASH and _config.use_trash) else "PERMANENTLY delete"
        if not messagebox.askyesno(
            "Confirm Delete",
            f"{method.capitalize()} these files?\n\n{file_list}"
        ):
            return

        deleted = 0
        errors: List[str] = []

        for path in paths:
            if not os.path.exists(path):
                errors.append(f"Not found: {path}")
                continue

            try:
                safe_delete(path)
                deleted += 1
            except PermissionError:
                errors.append(f"Permission denied: {path}")
            except OSError as e:
                errors.append(f"Error: {path} - {e}")

        # Remove deleted files from duplicate_groups so tree stays in sync
        self._purge_missing_files()

        msg = f"{'Trashed' if HAS_SEND2TRASH and _config.use_trash else 'Deleted'} {deleted} file(s)."
        if errors:
            msg += "\n\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n... and {len(errors) - 5} more"

        messagebox.showinfo("Done", msg)
        self._populate_tree()

    def _move_selected(self) -> None:
        """Move selected files to another location."""
        paths = self._get_selected_paths()
        if not paths:
            return

        dest = filedialog.askdirectory(title="Destination Folder")
        if not dest:
            return

        moved = 0
        errors: List[str] = []

        for path in paths:
            if not os.path.exists(path):
                errors.append(f"Not found: {path}")
                continue

            dest_path = os.path.join(dest, os.path.basename(path))
            if os.path.exists(dest_path):
                errors.append(f"Already exists at destination: {os.path.basename(path)}")
                continue

            try:
                shutil.move(path, dest)
                moved += 1
            except PermissionError:
                errors.append(f"Permission denied: {path}")
            except OSError as e:
                errors.append(f"Error: {path} - {e}")

        # Remove moved files from duplicate_groups so tree stays in sync
        self._purge_missing_files()

        msg = f"Moved {moved} file(s)."
        if errors:
            msg += "\n\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n... and {len(errors) - 5} more"

        messagebox.showinfo("Done", msg)
        self._populate_tree()

    def _show_context_menu(self, event) -> None:
        """Show right-click context menu at cursor position using custom dark popup."""
        # Select the item under cursor if not already selected
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item not in self.tree.selection():
            self.tree.selection_set(item)

        # Close any existing context popup
        self._close_dropdown()

        # Reuse the same Toplevel dropdown system as the menu bar
        # Use None for the button ref (context menus have no anchor button)
        x = event.x_root
        y = event.y_root

        dropdown = tk.Toplevel(self.root)
        dropdown.overrideredirect(True)
        dropdown.configure(bg=self.BORDER)
        dropdown.attributes("-topmost", True)

        inner = tk.Frame(dropdown, bg=self.BG_DARK, bd=0)
        inner.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)

        for ctx_item in self._context_items:
            if ctx_item is None:
                tk.Frame(inner, bg=self.BORDER, height=1).pack(fill=tk.X, padx=8, pady=3)
                continue

            label_text, command, shortcut = ctx_item
            row = tk.Frame(inner, bg=self.BG_DARK, cursor="hand2")
            row.pack(fill=tk.X)

            lbl = tk.Label(
                row, text=f"  {label_text}", anchor=tk.W,
                bg=self.BG_DARK, fg=self.TEXT_PRIMARY,
                font=("Segoe UI", 10), padx=8, pady=5
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

            for widget in (row, lbl):
                widget.bind("<Enter>", lambda e, r=row, l=lbl: (
                    r.config(bg=self.ACCENT), l.config(bg=self.ACCENT, fg="#ffffff")
                ))
                widget.bind("<Leave>", lambda e, r=row, l=lbl: (
                    r.config(bg=self.BG_DARK), l.config(bg=self.BG_DARK, fg=self.TEXT_PRIMARY)
                ))
                widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))

        dropdown.geometry(f"+{x}+{y}")
        self._active_dropdown = (None, dropdown)

    def _open_file_location(self) -> None:
        """Open the containing folder of the selected file in the system file manager."""
        paths = self._get_selected_paths()
        if not paths:
            return

        path = paths[0]
        folder = os.path.dirname(path)

        if not os.path.exists(folder):
            messagebox.showwarning("Not Found", f"Folder no longer exists:\n{folder}")
            return

        try:
            if sys.platform == "win32":
                # Select the file in Explorer
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                # Linux: open the containing folder
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file location:\n{e}")

    def _auto_select_duplicates(self) -> None:
        """Select all files except the first (oldest) in each duplicate group.
        
        Keeps the oldest file in each group unselected as the 'original'.
        Warns if any groups have less than 100% similarity (perceptual matches).
        """
        if not self.duplicate_groups:
            return

        # Check for non-100% similarity groups and warn
        has_similar = any(
            g.similarity < 100.0 or g.is_perceptual
            for g in self.duplicate_groups
        )

        if has_similar and not _config.suppress_similarity_warning:
            warn_win = tk.Toplevel(self.root)
            warn_win.title("⚠ Auto-Select Warning")
            warn_win.transient(self.root)
            warn_win.grab_set()
            warn_win.configure(bg=self.BG_DARK)
            self._center_dialog(warn_win, 480, 250)
            self._apply_dark_titlebar(warn_win)
            self._set_app_icon(warn_win)

            ttk.Label(
                warn_win,
                text="⚠  Some groups are similar but NOT identical",
                style="Stage.TLabel"
            ).pack(pady=(15, 5), padx=15)

            ttk.Label(
                warn_win,
                text=(
                    "Auto-Select will also select files from perceptual\n"
                    "match groups (less than 100% similarity).\n\n"
                    "These files look alike but may not be exact duplicates.\n"
                    "Review them carefully before deleting."
                ),
                style="Detail.TLabel", justify=tk.LEFT
            ).pack(padx=15, pady=(0, 10))

            dont_show_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                warn_win,
                text="Don't show this warning again",
                variable=dont_show_var
            ).pack(pady=(0, 5))

            # "select_all" = select from all groups, "exact_only" = skip similar groups
            user_choice = {"action": "cancel"}

            def on_select_all():
                user_choice["action"] = "select_all"
                if dont_show_var.get():
                    _config.suppress_similarity_warning = True
                warn_win.destroy()

            def on_exact_only():
                user_choice["action"] = "exact_only"
                warn_win.destroy()

            def on_cancel():
                warn_win.destroy()

            btn_frame = ttk.Frame(warn_win)
            btn_frame.pack(pady=10, padx=15, fill=tk.X)
            ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(btn_frame, text="Select All", command=on_select_all,
                       style="Warning.TButton").pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(btn_frame, text="Exact Only", command=on_exact_only,
                       style="Accent.TButton").pack(side=tk.RIGHT)

            warn_win.bind("<Return>", lambda e: on_exact_only())
            warn_win.bind("<Escape>", lambda e: on_cancel())
            self.root.wait_window(warn_win)

            if user_choice["action"] == "cancel":
                return
            exact_only = (user_choice["action"] == "exact_only")
        else:
            exact_only = False

        # Perform the auto-selection
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(*sel)
        selected_count = 0

        skipped_groups = 0
        for group_id in self.tree.get_children():
            children = self.tree.get_children(group_id)
            if len(children) < 2:
                continue

            # If exact_only, skip groups that aren't 100% exact matches
            if exact_only:
                header = self.tree.item(group_id, "text")
                if "(similar)" in header or "100.0%" not in header:
                    skipped_groups += 1
                    continue

            # Determine which file to KEEP (don't select it for deletion)
            keep_idx = self._pick_best_file(children)

            # Select all except the best
            for i, child in enumerate(children):
                if i != keep_idx:
                    self.tree.selection_add(child)
                    selected_count += 1

        if exact_only:
            similar_note = f" (skipped {skipped_groups} similar group(s))"
        elif has_similar:
            similar_note = " (includes similar matches)"
        else:
            similar_note = ""
        self.status_label.config(
            text=f"Auto-selected {selected_count} duplicate(s) (keeping best quality in each group){similar_note}"
        )

    @staticmethod
    def _get_size_from_tags(tags) -> int:
        """Extract raw file size in bytes from treeview item tags.
        
        Tags include 'sz:12345' where 12345 is the exact byte count,
        avoiding lossy re-parsing of display strings like '1.5 MB'.
        """
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("sz:"):
                try:
                    return int(tag[3:])
                except ValueError:
                    pass
        return 0

    def _pick_best_file(self, children) -> int:
        """Determine which file in a group to KEEP (index to not select).

        For image groups: keeps the highest resolution file, using file size
        as tiebreaker (larger = less compression = better quality).
        For non-image groups: keeps the oldest file (likely the original).

        Returns the index of the file to keep.
        """
        # Gather info about each child
        file_info = []  # [(index, path, size_bytes, mtime_timestamp)]
        for i, child in enumerate(children):
            values = self.tree.item(child, "values")
            if not values:
                file_info.append((i, "", 0, float("inf")))
                continue

            path = values[0]

            # Read exact size from tag (no lossy display-string parsing)
            tags = self.tree.item(child, "tags")
            size_bytes = self._get_size_from_tags(tags)

            # Parse mtime
            mtime = float("inf")
            if values[2]:
                try:
                    mtime = datetime.strptime(values[2], "%Y-%m-%d %H:%M").timestamp()
                except ValueError:
                    pass

            file_info.append((i, path, size_bytes, mtime))

        if not file_info:
            return 0

        # Check if this is an image group (any file has an image extension)
        is_image_group = any(
            Path(path).suffix.lower() in IMAGE_EXTENSIONS
            for _, path, _, _ in file_info if path
        )

        if is_image_group:
            # For images: pick the highest resolution, then largest file size
            best_idx = 0
            best_pixels = -1
            best_size = -1

            for i, path, size_bytes, _ in file_info:
                if not path:
                    continue
                pixels = 0
                try:
                    with Image.open(path) as img:
                        pixels = img.width * img.height
                except Exception:
                    pass

                # Higher resolution wins; if tied, larger file wins (less compression)
                if (pixels, size_bytes) > (best_pixels, best_size):
                    best_pixels = pixels
                    best_size = size_bytes
                    best_idx = i

            return best_idx
        else:
            # For non-images: keep the oldest file (smallest mtime = earliest)
            oldest_idx = 0
            oldest_mtime = float("inf")
            for i, _, _, mtime in file_info:
                if mtime < oldest_mtime:
                    oldest_mtime = mtime
                    oldest_idx = i
            return oldest_idx

    def _select_all(self) -> None:
        """Select all file items (not group headers) in the tree."""
        all_items = []
        for group_id in self.tree.get_children():
            all_items.extend(self.tree.get_children(group_id))
        if all_items:
            self.tree.selection_set(*all_items)

    def _deselect_all(self) -> None:
        """Clear all selections in the tree."""
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(*sel)

    def _make_sort_key(self, col: str, col_idx: int):
        """Create a sort key function for the given column.

        Returned as a standalone function (not a closure inside a loop)
        to avoid Python closure-over-loop-variable issues.
        """
        SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

        def sort_key(item_id):
            values = self.tree.item(item_id, "values")
            if not values or col_idx >= len(values):
                return ""
            val = values[col_idx]
            if col == "size":
                try:
                    parts = val.split()
                    return float(parts[0]) * SIZE_MULT.get(parts[1] if len(parts) > 1 else "B", 1)
                except (ValueError, IndexError):
                    return 0
            if col == "similarity":
                try:
                    return float(val.rstrip("%"))
                except (ValueError, TypeError):
                    return 0.0
            return val

        return sort_key

    def _sort_column(self, col: str, reverse: bool) -> None:
        """Sort treeview at both levels: groups by representative value, files within groups.

        Disabled during active scans to prevent freezes from concurrent
        tree modifications. Uses detach/reattach pattern to batch all
        tree moves into a single redraw.
        """
        if self._is_scanning:
            return  # Don't sort while scan is actively adding groups

        col_names = {"path": "Path", "size": "Size", "modified": "Modified", "similarity": "Similarity"}
        col_idx_map = {"path": 0, "size": 1, "modified": 2, "similarity": 3}

        # Update arrow indicators on column headers
        for c, name in col_names.items():
            if c == col:
                arrow = " ▼" if reverse else " ▲"
                self.tree.heading(c, text=name + arrow)
            else:
                self.tree.heading(c, text=name)

        sort_key = self._make_sort_key(col, col_idx_map.get(col, 0))
        all_groups = list(self.tree.get_children())

        # --- Pre-compute group representative values and child sort orders ---
        # Do all reads first, then batch all moves, to minimize redraws.
        group_data = []  # [(group_id, representative_value, sorted_child_ids)]
        for group_id in all_groups:
            children = list(self.tree.get_children(group_id))
            if children:
                child_key_pairs = [(c, sort_key(c)) for c in children]
                child_key_pairs.sort(key=lambda p: p[1], reverse=reverse)
                sorted_child_ids = [p[0] for p in child_key_pairs]
                values = [p[1] for p in child_key_pairs if p[1] != ""]
                rep = (max(values) if reverse else min(values)) if values else ""
            else:
                sorted_child_ids = []
                rep = ""
            group_data.append((group_id, rep, sorted_child_ids))

        # Sort groups by representative value
        group_data.sort(key=lambda g: g[1], reverse=reverse)

        # --- Batch apply: detach all, reattach in order ---
        # Detaching prevents incremental redraws during reordering
        for group_id, _, _ in group_data:
            self.tree.detach(group_id)

        for i, (group_id, _, sorted_children) in enumerate(group_data):
            self.tree.reattach(group_id, "", i)
            # Reorder children within the group
            for j, child_id in enumerate(sorted_children):
                self.tree.move(child_id, group_id, j)

        # Update ALL column heading commands (toggle direction for the active one)
        for c in col_names:
            if c == col:
                self.tree.heading(c, command=lambda _c=c: self._sort_column(_c, not reverse))
            else:
                self.tree.heading(c, command=lambda _c=c: self._sort_column(_c, False))

    def _on_preview_delete(self, path: str) -> None:
        """Called when a file is deleted from a preview/comparison window."""
        self._purge_missing_files()
        self._populate_tree()

    def _purge_missing_files(self) -> None:
        """Remove files that no longer exist from duplicate_groups."""
        for group in self.duplicate_groups:
            group.files = [f for f in group.files if os.path.exists(f.path)]
        # Drop groups that no longer have 2+ files
        self.duplicate_groups = [g for g in self.duplicate_groups if len(g.files) >= 2]

    def _export_report(self) -> None:
        """Export duplicate report to file."""
        if not self.duplicate_groups:
            messagebox.showinfo("No Data", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
            ],
            title="Save Report As"
        )

        if path:
            try:
                lower = path.lower()
                if lower.endswith(".csv"):
                    self._export_csv(path)
                elif lower.endswith(".json"):
                    self._export_json(path)
                else:
                    self._export_txt(path)
                messagebox.showinfo("Done", f"Report saved to:\n{path}")
            except (PermissionError, OSError) as e:
                messagebox.showerror("Error", f"Could not write file: {e}")

    def _export_txt(self, path: str) -> None:
        """Export report as formatted text."""
        export_txt(path, self.duplicate_groups)

    def _export_csv(self, path: str) -> None:
        """Export report as CSV for spreadsheet use."""
        export_csv(path, self.duplicate_groups)

    def _export_json(self, path: str) -> None:
        """Export report as JSON for programmatic consumption."""
        export_json(path, self.duplicate_groups)

    def _show_options(self) -> None:
        """Show options dialog."""
        od = OptionsDialog(self.root)
        self._center_dialog(od.top, 380, 420)
        self._apply_dark_titlebar(od.top)

    def _show_about(self) -> None:
        """Show about dialog."""
        trash_info = "Trash: enabled (send2trash)" if HAS_SEND2TRASH else "Trash: not available (pip install send2trash)"
        workers = _config.workers
        cpu = os.cpu_count() or "?"
        messagebox.showinfo(
            "About",
            f"VKScan v{VERSION}\n\n"
            "A comprehensive duplicate file detection tool.\n\n"
            "Features:\n"
            "• Exact duplicate detection (SHA-256 + byte verify)\n"
            "• Similar image detection (perceptual hashing)\n"
            "• Parallel scanning with live results\n"
            "• Preview, compare, and manage duplicates\n"
            f"\n{trash_info}\n"
            f"Workers: {workers} threads (CPU: {cpu} cores)\n"
            "\n─────────────────────────────────\n\n"
            "Copyright © 2026 Hygaard.\n\n"
            "Licensed under the GNU General Public License v3.0\n"
            "See LICENSE file for details.\n\n"
            "DISCLAIMER: This software is provided \"as is\", without\n"
            "warranty of any kind, express or implied. In no event\n"
            "shall the authors be liable for any claim, damages, or\n"
            "other liability arising from the use of this software.\n"
            "Use at your own risk. Always maintain backups before\n"
            "deleting or moving files."
        )


# =============================================================================
# DIALOGS
# =============================================================================

class ScanDialog:
    """Dialog for configuring scan options."""

    def __init__(self, parent: tk.Tk):
        self.result: Optional[ScanOptions] = None
        self.top = tk.Toplevel(parent)
        self.top.title("Scan Options")
        self.top.geometry("550x420")
        self.top.minsize(400, 300)
        self.top.transient(parent)
        self.top.grab_set()
        self.top.configure(bg=DuplicateFinderApp.BG_DARK)

        # Make content expand when dialog is resized
        content = ttk.Frame(self.top, padding=10)
        content.pack(fill=tk.BOTH, expand=True)

        ttk.Label(content, text="Locations to Scan:").pack(anchor=tk.W)
        self.paths_text = scrolledtext.ScrolledText(
            content, height=4,
            bg=DuplicateFinderApp.BG_LIGHT, fg=DuplicateFinderApp.TEXT_PRIMARY,
            insertbackground=DuplicateFinderApp.TEXT_PRIMARY)
        self.paths_text.pack(fill=tk.BOTH, expand=True, pady=(2, 5))

        # Native drag-and-drop (requires tkinterdnd2)
        if HAS_DND:
            try:
                self.paths_text.drop_target_register(DND_FILES)
                self.paths_text.dnd_bind('<<Drop>>', self._on_drop)
                dnd_hint = " (or drag && drop folders here)"
            except Exception:
                dnd_hint = ""
        else:
            dnd_hint = ""

        # Clipboard paste support (Ctrl+V inserts folder paths)
        self.paths_text.bind("<Control-v>", self._on_paste)

        btn_frame = ttk.Frame(content)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(btn_frame, text="📁 Add Folder", command=self._add_folder).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="💿 Add Drive", command=self._add_drive).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: self.paths_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        if dnd_hint:
            ttk.Label(btn_frame, text=dnd_hint, foreground=DuplicateFinderApp.TEXT_MUTED,
                      font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=5)

        ttk.Label(content, text="Exclusions (one per line):").pack(anchor=tk.W)
        self.excl_text = scrolledtext.ScrolledText(
            content, height=3,
            bg=DuplicateFinderApp.BG_LIGHT, fg=DuplicateFinderApp.TEXT_PRIMARY,
            insertbackground=DuplicateFinderApp.TEXT_PRIMARY)
        self.excl_text.pack(fill=tk.BOTH, expand=True, pady=(2, 5))
        if _saved_scan_exclusions:
            self.excl_text.insert(1.0, "\n".join(_saved_scan_exclusions))
        else:
            self.excl_text.insert(1.0, DEFAULT_EXCLUSIONS)

        # Pre-populate paths from saved settings
        if _saved_scan_paths:
            self.paths_text.insert(1.0, "\n".join(_saved_scan_paths) + "\n")

        self.perceptual_var = tk.BooleanVar(value=_saved_scan_perceptual)
        ttk.Checkbutton(
            content,
            text="Perceptual image comparison (slower but finds similar images)",
            variable=self.perceptual_var
        ).pack(anchor=tk.W, pady=5)

        # Action buttons
        action_frame = ttk.Frame(content)
        action_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(action_frame, text="Cancel", command=self.top.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        scan_btn = ttk.Button(action_frame, text="▶  Start Scan", command=self._on_scan)
        scan_btn.pack(side=tk.RIGHT)

        # Enter key starts scan, Escape closes
        self.top.bind("<Return>", lambda e: self._on_scan())
        self.top.bind("<Escape>", lambda e: self.top.destroy())
        self.top.focus_set()

    def _on_drop(self, event) -> None:
        """Handle drag-and-drop of files/folders onto the paths text area."""
        # tkinterdnd2 returns paths in various formats depending on OS
        data = event.data
        if not data:
            return
        # On Windows, paths with spaces are wrapped in {curly braces}
        # On Linux/macOS, paths are space-separated
        paths = []
        if '{' in data:
            # Windows format: {C:\path with spaces} {D:\another path}
            paths = re.findall(r'\{([^}]+)\}', data)
            # Also capture unbraced paths
            remaining = re.sub(r'\{[^}]+\}', '', data).strip()
            if remaining:
                paths.extend(remaining.split())
        else:
            paths = data.split()

        for p in paths:
            p = p.strip()
            if p and os.path.isdir(p):
                self.paths_text.insert(tk.END, p + "\n")

    def _on_paste(self, event) -> None:
        """Handle Ctrl+V paste — extract valid directory paths from clipboard.
        
        Handles plain paths, quoted paths, and file:// URIs from file managers.
        """
        try:
            clipboard = self.top.clipboard_get()
        except tk.TclError:
            return  # Empty clipboard

        if not clipboard:
            return

        # Try to extract paths from the clipboard (one per line, or space-separated)
        added = False
        for line in clipboard.replace('\r', '').split('\n'):
            line = line.strip().strip('"').strip("'")
            # Handle file:// URIs (from file managers)
            if line.startswith("file:///"):
                if sys.platform == "win32":
                    line = line[8:]  # file:///C:/path -> C:/path
                else:
                    line = line[7:]  # file:///path -> /path
                # Decode percent-encoded characters (%20 -> space, etc.)
                try:
                    from urllib.parse import unquote
                    line = unquote(line)
                except ImportError:
                    pass
            if line and os.path.isdir(line):
                self.paths_text.insert(tk.END, line + "\n")
                added = True

        if added:
            return "break"  # Prevent default paste behavior

    def _add_folder(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self.paths_text.insert(tk.END, folder + "\n")

    def _add_drive(self) -> None:
        if sys.platform == "win32":
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if mask & (1 << (ord(c) - ord("A"))):
                    self.paths_text.insert(tk.END, f"{c}:\\\n")
        else:
            # On Linux/macOS, add /home instead of / to avoid scanning system dirs
            home = str(Path.home())
            self.paths_text.insert(tk.END, home + "\n")

    def _on_scan(self) -> None:
        paths = [
            p.strip()
            for p in self.paths_text.get(1.0, tk.END).split("\n")
            if p.strip()
        ]

        exclusions = {
            e.strip()
            for e in self.excl_text.get(1.0, tk.END).split("\n")
            if e.strip()
        }

        if not paths:
            messagebox.showwarning("Warning", "Please add at least one location to scan.")
            return

        self.result = ScanOptions(
            paths=paths,
            exclusions=exclusions,
            perceptual=self.perceptual_var.get()
        )
        self.top.destroy()


class OptionsDialog:
    """Dialog for application options."""

    def __init__(self, parent: tk.Tk):
        self.top = tk.Toplevel(parent)
        self.top.title("Options")
        self.top.geometry("380x420")
        self.top.transient(parent)
        self.top.grab_set()
        self.top.configure(bg=DuplicateFinderApp.BG_DARK)

        # Similarity threshold
        ttk.Label(self.top, text="Image Similarity Threshold:").pack(pady=10)
        ttk.Label(
            self.top,
            text="Maximum Hamming distance for similar images",
            font=("", 8), foreground="gray"
        ).pack()

        self.scale = ttk.Scale(
            self.top, from_=0, to=64, orient=tk.HORIZONTAL,
            command=self._on_scale_change
        )
        self.scale.set(_config.image_similarity_threshold)
        self.scale.pack(fill=tk.X, padx=20)

        self.threshold_label = ttk.Label(
            self.top, text=str(_config.image_similarity_threshold),
            font=("", 12, "bold")
        )
        self.threshold_label.pack()

        ttk.Label(
            self.top,
            text="Lower = stricter, Higher = more lenient",
            font=("", 8), foreground="gray"
        ).pack(pady=5)

        # Trash option
        self.trash_var = tk.BooleanVar(value=_config.use_trash)
        trash_text = "Use trash/recycle bin for deletions"
        if not HAS_SEND2TRASH:
            trash_text += " (send2trash not installed)"
        trash_cb = ttk.Checkbutton(
            self.top, text=trash_text, variable=self.trash_var
        )
        if not HAS_SEND2TRASH:
            trash_cb.config(state="disabled")
        trash_cb.pack(pady=5)

        # Skip empty files
        self.skip_empty_var = tk.BooleanVar(value=_config.skip_empty_files)
        ttk.Checkbutton(
            self.top, text="Skip empty (0-byte) files",
            variable=self.skip_empty_var
        ).pack(pady=5)

        # Worker threads
        ttk.Separator(self.top, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=5)
        ttk.Label(self.top, text="Worker Threads:").pack()
        ttk.Label(
            self.top,
            text="Parallel threads for hashing (higher = faster, more CPU/disk I/O)",
            font=("", 8), foreground="gray"
        ).pack()

        self.workers_scale = ttk.Scale(
            self.top, from_=1, to=max(16, (os.cpu_count() or 4)), orient=tk.HORIZONTAL,
            command=self._on_workers_change
        )
        self.workers_scale.set(_config.workers)
        self.workers_scale.pack(fill=tk.X, padx=20)

        self.workers_label = ttk.Label(
            self.top, text=str(_config.workers),
            font=("", 12, "bold")
        )
        self.workers_label.pack()

        ttk.Button(self.top, text="OK", command=self._on_ok).pack(pady=10)

    def _on_ok(self) -> None:
        _config.image_similarity_threshold = int(self.scale.get())
        _config.use_trash = self.trash_var.get()
        _config.skip_empty_files = self.skip_empty_var.get()
        _config.workers = max(1, int(self.workers_scale.get()))
        save_settings()
        self.top.destroy()

    def _on_scale_change(self, value: str) -> None:
        try:
            self.threshold_label.config(text=str(int(float(value))))
        except (ValueError, TypeError):
            pass

    def _on_workers_change(self, value: str) -> None:
        try:
            self.workers_label.config(text=str(max(1, int(float(value)))))
        except (ValueError, TypeError):
            pass


# =============================================================================
# PREVIEW WINDOWS
# =============================================================================

class PreviewWindow:
    """Window for previewing files with navigation and fit-to-window scaling."""

    # Color shortcuts
    BG = DuplicateFinderApp.BG_DARK
    BG2 = DuplicateFinderApp.BG_MEDIUM
    FG = DuplicateFinderApp.TEXT_PRIMARY
    FG2 = DuplicateFinderApp.TEXT_SECONDARY
    FG3 = DuplicateFinderApp.TEXT_MUTED
    ACCENT = DuplicateFinderApp.ACCENT

    def __init__(self, parent: tk.Tk, paths: List[str], on_delete: Optional[Callable] = None):
        self.top = tk.Toplevel(parent)
        self.top.title("Preview")
        self.top.geometry("800x600")
        self.top.minsize(500, 400)
        self.top.configure(bg=self.BG)

        self.paths = paths
        self.current_index = 0
        self._photo_ref = None  # Strong ref for current image
        self._pil_images: Dict[int, Image.Image] = {}  # Cache loaded PIL images
        self._on_delete = on_delete

        self._build_ui()
        self._show_current()

        # Keyboard navigation
        self.top.bind("<Left>", lambda e: self._navigate(-1))
        self.top.bind("<Right>", lambda e: self._navigate(1))
        self.top.bind("<Up>", lambda e: self._navigate(-1))
        self.top.bind("<Down>", lambda e: self._navigate(1))
        self.top.bind("<Escape>", lambda e: self._on_close())
        self.top.bind("<Delete>", lambda e: self._delete_current())

        # Resize re-renders the image to fit
        self.top.bind("<Configure>", self._on_resize)
        self._last_size = (0, 0)

        self.top.protocol("WM_DELETE_WINDOW", self._on_close)
        self.top.focus_set()

    def _build_ui(self) -> None:
        """Build the preview UI layout."""
        # Top: navigation bar
        nav_frame = tk.Frame(self.top, bg=self.BG2, bd=0)
        nav_frame.pack(fill=tk.X, side=tk.TOP)

        self._prev_btn = tk.Label(
            nav_frame, text="  ◀  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=self.FG, padx=8, pady=4
        )
        self._prev_btn.pack(side=tk.LEFT)
        self._prev_btn.bind("<Button-1>", lambda e: self._navigate(-1))
        self._prev_btn.bind("<Enter>", lambda e: self._prev_btn.config(bg=self.ACCENT, fg="#fff"))
        self._prev_btn.bind("<Leave>", lambda e: self._prev_btn.config(bg=self.BG2, fg=self.FG))

        self._counter_label = tk.Label(
            nav_frame, text="", font=("Segoe UI", 10),
            bg=self.BG2, fg=self.FG2
        )
        self._counter_label.pack(side=tk.LEFT, padx=10)

        self._next_btn = tk.Label(
            nav_frame, text="  ▶  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=self.FG, padx=8, pady=4
        )
        self._next_btn.pack(side=tk.LEFT)
        self._next_btn.bind("<Button-1>", lambda e: self._navigate(1))
        self._next_btn.bind("<Enter>", lambda e: self._next_btn.config(bg=self.ACCENT, fg="#fff"))
        self._next_btn.bind("<Leave>", lambda e: self._next_btn.config(bg=self.BG2, fg=self.FG))

        self._filename_label = tk.Label(
            nav_frame, text="", font=("Segoe UI", 10, "bold"),
            bg=self.BG2, fg=self.FG, anchor=tk.W
        )
        self._filename_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        self._trash_btn = tk.Label(
            nav_frame, text="  🗑  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=DuplicateFinderApp.DANGER, padx=8, pady=4
        )
        self._trash_btn.pack(side=tk.RIGHT)
        self._trash_btn.bind("<Button-1>", lambda e: self._delete_current())
        self._trash_btn.bind("<Enter>", lambda e: self._trash_btn.config(bg=DuplicateFinderApp.DANGER, fg="#fff"))
        self._trash_btn.bind("<Leave>", lambda e: self._trash_btn.config(bg=self.BG2, fg=DuplicateFinderApp.DANGER))

        # Bottom: metadata bar
        self._meta_label = tk.Label(
            self.top, text="", font=("Segoe UI", 9),
            bg=self.BG2, fg=self.FG3, anchor=tk.W, padx=8, pady=3
        )
        self._meta_label.pack(fill=tk.X, side=tk.BOTTOM)

        # Center: content area
        self._content_frame = tk.Frame(self.top, bg=self.BG, bd=0)
        self._content_frame.pack(fill=tk.BOTH, expand=True)

        # Image display label (centered)
        self._image_label = tk.Label(self._content_frame, bg=self.BG, bd=0)
        self._image_label.pack(fill=tk.BOTH, expand=True)

        # Text display (hidden by default, shown for text files)
        self._text_widget = None

    def _navigate(self, delta: int) -> None:
        """Move to the next/previous file."""
        new_index = self.current_index + delta
        if 0 <= new_index < len(self.paths):
            self.current_index = new_index
            self._show_current()

    def _show_current(self) -> None:
        """Display the current file."""
        if not self.paths:
            return

        path = self.paths[self.current_index]
        total = len(self.paths)
        name = Path(path).name

        # Update navigation
        self._counter_label.config(text=f"{self.current_index + 1} / {total}")
        self._filename_label.config(text=name)
        self.top.title(f"Preview — {name}")

        # Update navigation button states
        self._prev_btn.config(fg=self.FG if self.current_index > 0 else self.FG3)
        self._next_btn.config(fg=self.FG if self.current_index < total - 1 else self.FG3)

        # Build metadata
        meta = path
        try:
            stat = os.stat(path)
            size_str = format_size(stat.st_size)
            mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            meta = f"{path}   |   {size_str}   |   {mtime_str}"
            if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
                try:
                    with Image.open(path) as img:
                        meta += f"   |   {img.width}×{img.height}   |   {img.mode}"
                except Exception:
                    pass
        except OSError:
            pass
        self._meta_label.config(text=meta)

        # Clear previous content
        self._image_label.config(image="", text="")
        if self._text_widget:
            self._text_widget.destroy()
            self._text_widget = None
        self._photo_ref = None

        # Try image
        if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
            try:
                if self.current_index not in self._pil_images:
                    img = Image.open(path)
                    if img.mode not in ("RGB", "RGBA"):
                        img = img.convert("RGBA")
                    self._pil_images[self.current_index] = img
                self._render_image()
                return
            except Exception:
                pass

        # Try text
        try:
            self._text_widget = scrolledtext.ScrolledText(
                self._content_frame, wrap=tk.WORD,
                bg=DuplicateFinderApp.BG_LIGHT, fg=self.FG,
                insertbackground=self.FG, font=("Consolas", 10),
                bd=0, relief="flat"
            )
            self._text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[:TEXT_PREVIEW_LINES]
                self._text_widget.insert(1.0, "".join(lines))
            self._text_widget.config(state=tk.DISABLED)
            return
        except Exception:
            pass

        self._image_label.config(text="[Binary file — cannot preview]", fg=self.FG3)

    def _render_image(self) -> None:
        """Render the current PIL image scaled to fill the content area."""
        pil_img = self._pil_images.get(self.current_index)
        if not pil_img:
            return

        # Get available space
        self._content_frame.update_idletasks()
        avail_w = max(self._content_frame.winfo_width() - 10, 100)
        avail_h = max(self._content_frame.winfo_height() - 10, 100)

        # Scale to fit (maintain aspect ratio, fill one axis)
        img_w, img_h = pil_img.size
        ratio = min(avail_w / img_w, avail_h / img_h)
        new_w = max(1, int(img_w * ratio))
        new_h = max(1, int(img_h * ratio))

        resized = pil_img.resize((new_w, new_h), Image.LANCZOS)
        self._photo_ref = ImageTk.PhotoImage(resized)
        resized.close()

        self._image_label.config(image=self._photo_ref)

    def _on_resize(self, event) -> None:
        """Re-render image when window is resized."""
        if event.widget != self.top:
            return
        new_size = (event.width, event.height)
        if new_size == self._last_size:
            return
        self._last_size = new_size

        # Only re-render if we're showing an image
        if self.current_index in self._pil_images and self._text_widget is None:
            # Debounce: cancel previous scheduled render, schedule new one
            if hasattr(self, '_resize_after_id'):
                self.top.after_cancel(self._resize_after_id)
            self._resize_after_id = self.top.after(50, self._render_image)

    def _delete_current(self) -> None:
        """Delete the currently displayed file."""
        if not self.paths:
            return
        path = self.paths[self.current_index]
        name = Path(path).name
        if not messagebox.askyesno("Confirm Delete", f"Delete '{name}'?", parent=self.top):
            return
        try:
            safe_delete(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {e}", parent=self.top)
            return
        # Remove from cached images
        if self.current_index in self._pil_images:
            try:
                self._pil_images[self.current_index].close()
            except Exception:
                pass
            del self._pil_images[self.current_index]
        deleted_path = self.paths.pop(self.current_index)
        # Rebuild image cache keys
        new_cache: Dict[int, Image.Image] = {}
        for k, v in self._pil_images.items():
            new_key = k if k < self.current_index else k - 1
            new_cache[new_key] = v
        self._pil_images = new_cache
        if not self.paths:
            self._on_close()
        else:
            if self.current_index >= len(self.paths):
                self.current_index = len(self.paths) - 1
            self._show_current()
        if self._on_delete:
            self._on_delete(deleted_path)

    def _on_close(self) -> None:
        """Cleanup on window close."""
        # Close cached PIL images
        for img in self._pil_images.values():
            try:
                img.close()
            except Exception:
                pass
        self._pil_images.clear()
        self._photo_ref = None
        self.top.destroy()


class ComparisonWindow:
    """Window for comparing two files side by side."""

    def __init__(self, parent: tk.Tk, paths: List[str], on_delete: Optional[Callable] = None):
        self.top = tk.Toplevel(parent)
        self.top.title("Compare")
        self.top.geometry("800x500")
        self.top.configure(bg=DuplicateFinderApp.BG_DARK)
        self._image_refs: List[ImageTk.PhotoImage] = []
        self._on_delete = on_delete
        self._paths = paths

        if len(paths) < 2:
            self.top.destroy()
            return

        left = ttk.Frame(self.top)
        right = ttk.Frame(self.top)

        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._add_panel(left, paths[0], "File A")
        self._add_panel(right, paths[1], "File B")

        # Delete buttons
        del_frame = ttk.Frame(self.top)
        del_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        ttk.Button(
            del_frame, text="Delete A", command=lambda: self._delete_file(0),
            style="Danger.TButton"
        ).pack(side=tk.LEFT, padx=10)
        ttk.Button(
            del_frame, text="Delete B", command=lambda: self._delete_file(1),
            style="Danger.TButton"
        ).pack(side=tk.RIGHT, padx=10)

        self.top.protocol("WM_DELETE_WINDOW", self._on_close)

    def _delete_file(self, index: int) -> None:
        """Delete file A (index=0) or file B (index=1)."""
        if index >= len(self._paths):
            return
        path = self._paths[index]
        name = Path(path).name
        label = "A" if index == 0 else "B"
        if not messagebox.askyesno("Confirm Delete", f"Delete File {label}: '{name}'?", parent=self.top):
            return
        try:
            safe_delete(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {e}", parent=self.top)
            return
        self._on_close()
        if self._on_delete:
            self._on_delete(path)

    def _on_close(self) -> None:
        self._image_refs.clear()
        self.top.destroy()

    def _add_panel(self, parent: tk.Frame, path: str, title: str) -> None:
        ttk.Label(
            parent, text=f"{title}: {Path(path).name}",
            font=("", 10, "bold")
        ).pack(anchor=tk.W)

        ttk.Label(parent, text=path, wraplength=350, foreground=DuplicateFinderApp.TEXT_SECONDARY).pack(anchor=tk.W, pady=2)

        # Compact metadata
        try:
            stat = os.stat(path)
            size_str = format_size(stat.st_size)
            mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            meta = f"{size_str} | {mtime_str}"
            if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
                try:
                    with Image.open(path) as img:
                        meta += f" | {img.width}×{img.height}"
                except Exception:
                    pass
            ttk.Label(parent, text=meta, foreground=DuplicateFinderApp.TEXT_MUTED, font=("", 8)).pack(anchor=tk.W)
        except OSError:
            pass

        content = ttk.Frame(parent)
        content.pack(fill=tk.BOTH, expand=True)

        try:
            with Image.open(path) as img:
                if img.width > MAX_PREVIEW_SIZE or img.height > MAX_PREVIEW_SIZE:
                    ratio = min(MAX_PREVIEW_SIZE / img.width, MAX_PREVIEW_SIZE / img.height)
                    resized = img.resize(
                        (int(img.width * ratio), int(img.height * ratio))
                    )
                else:
                    resized = img.copy()

            photo = ImageTk.PhotoImage(resized)
            resized.close()
            self._image_refs.append(photo)
            ttk.Label(content, image=photo).pack(fill=tk.BOTH, expand=True)
            return
        except Exception:
            pass

        try:
            txt = scrolledtext.ScrolledText(
                content, wrap=tk.WORD,
                bg=DuplicateFinderApp.BG_LIGHT, fg=DuplicateFinderApp.TEXT_PRIMARY,
                insertbackground=DuplicateFinderApp.TEXT_PRIMARY)
            txt.pack(fill=tk.BOTH, expand=True)
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[:TEXT_PREVIEW_LINES]
                txt.insert(1.0, "".join(lines))
            return
        except Exception:
            pass

        ttk.Label(content, text="[Binary]").pack()


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

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
        help="Export results to FILE (.csv, .txt, or .json)"
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
        "--delete", action="store_true",
        help="Delete duplicates (keeps oldest file in each exact group). Requires --confirm"
    )
    parser.add_argument(
        "--move-to", metavar="DIR",
        help="Move duplicates to DIR (keeps oldest file in each exact group). Requires --confirm"
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Required with --delete or --move-to to prevent accidental data loss"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"VKScan v{VERSION}"
    )

    args = parser.parse_args()

    # --- GUI mode (no --scan) ---
    if args.scan is None:
        # Use TkinterDnD.Tk if available for native drag-and-drop support
        if HAS_DND:
            root = TkinterDnD.Tk()
        else:
            root = tk.Tk()
        DuplicateFinderApp(root)
        root.mainloop()
        return

    # --- CLI mode ---
    # Validate --delete / --move-to require --confirm
    if (args.delete or args.move_to) and not args.confirm:
        print("Error: --delete and --move-to require --confirm flag for safety.", file=sys.stderr)
        print("  Example: vkscan --scan /path --delete --confirm", file=sys.stderr)
        sys.exit(1)

    if args.delete and args.move_to:
        print("Error: --delete and --move-to are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    if args.move_to and not os.path.isdir(args.move_to):
        try:
            os.makedirs(args.move_to, exist_ok=True)
            print(f"Created destination directory: {args.move_to}")
        except OSError as e:
            print(f"Error: Cannot create destination directory: {e}", file=sys.stderr)
            sys.exit(1)

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
            lower = out.lower()
            if lower.endswith(".csv"):
                export_csv(out, groups)
            elif lower.endswith(".json"):
                export_json(out, groups)
            else:
                export_txt(out, groups)
            print(f"\nReport saved to: {out}")
        except (PermissionError, OSError) as e:
            print(f"\nError: Could not write report: {e}", file=sys.stderr)
            sys.exit(1)

    # --- Delete or move duplicates if requested ---
    if groups and (args.delete or args.move_to):
        # Only act on exact (100% verified) groups for safety
        exact_groups = [g for g in groups if g.verified and g.similarity == 100.0]
        if not exact_groups:
            print("\nNo exact-match groups found. Skipping delete/move (only acts on verified 100% duplicates).")
        else:
            action = "delete" if args.delete else f"move to {args.move_to}"
            # Collect files to remove (keep oldest in each group)
            to_remove = []
            for group in exact_groups:
                sorted_files = sorted(group.files, key=lambda f: f.mtime)
                # Keep the oldest (first), remove the rest
                to_remove.extend(sorted_files[1:])

            print(f"\n{'=' * 60}")
            print(f"  ACTION: {action.upper()}")
            print(f"  Groups: {len(exact_groups)} exact-match groups")
            print(f"  Files to {action}: {len(to_remove)}")
            print(f"  Space to recover: {format_size(sum(f.size for f in to_remove))}")
            print(f"{'=' * 60}")

            deleted = 0
            errors = []

            for fi in to_remove:
                try:
                    if args.delete:
                        safe_delete(fi.path)
                    else:
                        dest_path = os.path.join(args.move_to, os.path.basename(fi.path))
                        # Handle name collisions in destination
                        if os.path.exists(dest_path):
                            base, ext = os.path.splitext(os.path.basename(fi.path))
                            counter = 1
                            while os.path.exists(dest_path):
                                dest_path = os.path.join(args.move_to, f"{base}_{counter}{ext}")
                                counter += 1
                        shutil.move(fi.path, dest_path)
                    deleted += 1
                except (PermissionError, OSError) as e:
                    errors.append(f"  {fi.path}: {e}")

            verb = "Deleted" if args.delete else "Moved"
            print(f"\n{verb} {deleted} / {len(to_remove)} files.")
            if errors:
                print(f"\nErrors ({len(errors)}):")
                for err in errors[:10]:
                    print(err)
                if len(errors) > 10:
                    print(f"  ... and {len(errors) - 10} more")


if __name__ == "__main__":
    main()