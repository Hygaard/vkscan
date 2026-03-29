#!/usr/bin/env python3
"""VKScan persistent hash cache backed by SQLite."""

import os
import threading
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import CACHE_DB


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
            from .constants import PHASH_BLOCK_SIZE
            expected_hex_len = (PHASH_BLOCK_SIZE * PHASH_BLOCK_SIZE) // 4
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
