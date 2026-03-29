#!/usr/bin/env python3
"""VKScan data classes for file info, duplicate groups, and scan results."""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


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
