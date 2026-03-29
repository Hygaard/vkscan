#!/usr/bin/env python3
"""VKScan constants and configuration values."""

import os
import sys
from pathlib import Path

# Version
VERSION = "1.1.9"

# Security: Limit maximum image pixels to prevent DoS via large images
MAX_IMAGE_PIXELS = 100_000_000  # ~100 megapixels

# Perceptual hash configuration
PHASH_BLOCK_SIZE = 16  # Creates 16x16 = 256-bit hash (higher resolution = fewer false positives)
PHASH_BIT_COUNT = PHASH_BLOCK_SIZE * PHASH_BLOCK_SIZE  # 256 bits total
PHASH_DISTANCE_THRESHOLD = 8  # Hamming distance threshold; 0=exact, 256=completely different

# Preview configuration
MAX_PREVIEW_SIZE = 500  # Max dimension for preview images in pixels
TEXT_PREVIEW_LINES = 100  # Max lines to show in text preview

# File processing limits
HASH_BLOCK_SIZE = 1024 * 1024  # 1MB chunks for hashing
QUICK_HASH_SIZE = 4096  # 4KB quick-reject hash
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024 * 1024  # 100GB max file size
MAX_IMAGE_FILE_BYTES = 1024 * 1024 * 1024  # 1GB max for image processing

# Parallelism
DEFAULT_WORKERS = max(2, (os.cpu_count() or 4) - 2)

# Minimum number of images to justify ProcessPoolExecutor overhead
PROCESS_POOL_THRESHOLD = 50

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

# Settings persistence
if sys.platform == "win32":
    CONFIG_DIR = Path(os.environ.get('APPDATA', '~')) / 'VKScan'
else:
    CONFIG_DIR = Path.home() / '.config' / 'vkscan'
CONFIG_FILE = CONFIG_DIR / 'settings.json'
CACHE_DB = CONFIG_DIR / 'hash_cache.db'

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
