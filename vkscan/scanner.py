#!/usr/bin/env python3
"""VKScan duplicate file scanner engine."""

import os
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple, Callable
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

from PIL import Image
from imagehash import phash

from .constants import (
    IMAGE_EXTENSIONS, MAX_IMAGE_PIXELS, PHASH_BLOCK_SIZE,
    MAX_IMAGE_FILE_BYTES, MAX_FILE_SIZE_BYTES, HASH_BLOCK_SIZE,
    QUICK_HASH_SIZE, MIN_FILE_SIZE_BYTES, PROCESS_POOL_THRESHOLD,
)
from .config import _config
from .models import FileInfo, DuplicateGroup
from .utils import (
    hamming_distance, calculate_similarity, safe_path_match,
    files_are_identical,
)
from .cache import get_hash_cache
from .bktree import BKTree


# =============================================================================
# TOP-LEVEL FUNCTION FOR MULTIPROCESSING
# =============================================================================

def _compute_perceptual_hash_standalone(args: Tuple[str, float, int]) -> Optional[str]:
    """Compute perceptual hash of an image (top-level for ProcessPoolExecutor).

    Must be a module-level function so it can be pickled and sent to
    worker processes.

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

        Uses the hash cache when mtime/size are provided.

        Returns:
            Hex-encoded SHA-256 hash of header bytes, or None on error
        """
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

                if mtime and size:
                    cache = get_hash_cache()
                    cache.put(path, mtime, size, quick_hash=result)

                return result
        except (PermissionError, OSError):
            return None

    def compute_hash(self, path: str, mtime: float = 0, size: int = 0) -> Optional[str]:
        """Compute SHA-256 hash of a file.

        Uses the hash cache when mtime/size are provided.

        Returns:
            Hex-encoded SHA-256 hash or None on error
        """
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
                return None
            result = hasher.hexdigest()

            if mtime and size:
                cache = get_hash_cache()
                cache.put(path, mtime, size, sha256=result)

            return result
        except (PermissionError, OSError):
            return None

    def compute_perceptual_hash(self, path: str, mtime: float = 0, size: int = 0) -> Optional[str]:
        """Compute perceptual hash of an image.

        Uses the hash cache when mtime/size are provided.

        Returns:
            Hex-encoded perceptual hash or None on error
        """
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
        """Collect file information from root directories."""
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
        """Byte-level verify a group of files that share the same hash."""
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
        """Find duplicate files using hashing and byte-level verification."""
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

        # --- Stage 1: Quick-hash ---
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
                    key = f"{fi.size}:{qhash}"
                    quick_hash_groups[key].append(fi)
                processed += 1

                now = time.monotonic()
                if now - last_update > 0.1:
                    last_update = now
                    stage_pct = int((processed / total_to_hash) * 100)
                    self._update_progress(5 + int(stage_pct * 0.1), f"STAGE:2/4:Quick Hash|{stage_pct}|{processed:,} / {total_to_hash:,} files")

        full_hash_candidates = [f for group in quick_hash_groups.values()
                                if len(group) >= 2 for f in group]
        skipped = total_to_hash - len(full_hash_candidates)

        self._update_progress(
            15, f"STAGE:2/4:Quick Hash|100|{len(full_hash_candidates):,} candidates ({skipped:,} rejected)"
        )

        # --- Stage 2: Full SHA-256 hash ---
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

        # --- Stage 3: Byte-level verify ---
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

        # --- Stage 4: Perceptual image comparison ---
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
        """Find perceptually similar images using parallel hashing and BK-tree."""
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

        use_processes = len(image_files) >= PROCESS_POOL_THRESHOLD
        pool_label = "processes" if use_processes else "threads"
        self._update_progress(60, f"STAGE:4/4:Verifying|55|Image hashes: 0 / {len(image_files):,} ({workers} {pool_label})")
        phash_groups: Dict[str, List[FileInfo]] = defaultdict(list)
        processed = 0
        last_update = time.monotonic()

        PoolClass = ProcessPoolExecutor if use_processes else ThreadPoolExecutor

        with PoolClass(max_workers=workers) as pool:
            if use_processes:
                future_to_file = {
                    pool.submit(_compute_perceptual_hash_standalone, (fi.path, fi.mtime, fi.size)): fi
                    for fi in image_files
                }
            else:
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

            bk_tree = BKTree()
            for ph in hash_keys:
                bk_tree.insert(ph)

            merged_groups: Set[str] = set()
            grouped_paths: Set[str] = set()
            last_update = time.monotonic()

            for idx, ph1 in enumerate(hash_keys):
                if self.cancelled:
                    break

                if ph1 in merged_groups:
                    continue

                files1 = phash_groups[ph1]
                if not files1:
                    continue

                neighbors = bk_tree.find_within(ph1, _config.image_similarity_threshold)
                similar_hashes = [(nh, d) for nh, d in neighbors if d > 0 and nh not in merged_groups]

                if similar_hashes:
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

            # Exact perceptual hash matches
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
