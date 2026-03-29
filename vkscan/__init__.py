#!/usr/bin/env python3
"""
VKScan - Voight-Kampff Scanner for duplicate files.

A comprehensive duplicate file detection tool featuring:
- Exact duplicate detection via SHA-256 hashing with byte-level verification
- Perceptual hashing for similar image detection
- GUI with preview and comparison capabilities
- Threaded scanning with progress tracking
- Memory-efficient design for large file collections
- Safe deletion via trash/staging directory
"""

from .constants import VERSION, PHASH_BIT_COUNT, CONFIG_DIR, CONFIG_FILE
from .config import Config, _config, save_settings, load_settings
from .models import FileInfo, DuplicateGroup, ScanOptions, ScanResult
from .utils import format_size, hamming_distance, calculate_similarity, safe_path_match
from .scanner import DuplicateScanner
from .cache import HashCache, get_hash_cache
from .bktree import BKTree
from .export import export_txt, export_csv

__version__ = VERSION
__all__ = [
    "VERSION", "Config", "_config", "save_settings", "load_settings",
    "FileInfo", "DuplicateGroup", "ScanOptions", "ScanResult",
    "format_size", "hamming_distance", "calculate_similarity", "safe_path_match",
    "DuplicateScanner", "HashCache", "get_hash_cache", "BKTree",
    "export_txt", "export_csv",
]
