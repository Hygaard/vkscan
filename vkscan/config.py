#!/usr/bin/env python3
"""VKScan runtime configuration and settings persistence."""

import json
from typing import List, Optional

from .constants import (
    CONFIG_DIR, CONFIG_FILE, PHASH_DISTANCE_THRESHOLD,
    MAX_FILE_SIZE_BYTES, DEFAULT_WORKERS
)


class Config:
    """Runtime configuration storage with defaults from constants."""
    image_similarity_threshold: int = PHASH_DISTANCE_THRESHOLD
    max_file_size_bytes: int = MAX_FILE_SIZE_BYTES
    use_trash: bool = True
    skip_empty_files: bool = True
    workers: int = DEFAULT_WORKERS
    suppress_similarity_warning: bool = False


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
