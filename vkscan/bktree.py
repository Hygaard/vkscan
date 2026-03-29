#!/usr/bin/env python3
"""BK-tree for efficient Hamming distance nearest-neighbor search."""

from typing import Dict, List, Optional, Tuple

from .utils import hamming_distance


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
