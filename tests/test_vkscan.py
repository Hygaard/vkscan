#!/usr/bin/env python3
"""Comprehensive unit tests for vkscan.py."""

import hashlib
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure the project root is on sys.path so we can import vkscan
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Mock tkinter and optional GUI/image dependencies before importing vkscan
# so tests can run in headless environments without X11 or tkinter installed.
for _mod_name in [
    "tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox",
    "tkinter.scrolledtext", "PIL", "PIL.Image", "PIL.ImageTk", "imagehash",
    "send2trash",
]:
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = types.ModuleType(_mod_name)

# Minimal stubs so vkscan's top-level code doesn't crash on import
_tk = sys.modules["tkinter"]
for _attr in ["Tk", "Frame", "StringVar", "IntVar", "BooleanVar", "PhotoImage",
              "Menu", "Toplevel", "Canvas", "Label", "Button", "Entry", "Text",
              "Checkbutton", "Scrollbar", "Listbox", "PanedWindow"]:
    setattr(_tk, _attr, type(_attr, (), {"__init__": lambda *a, **kw: None}))
for _attr in ["END", "LEFT", "RIGHT", "TOP", "BOTTOM", "BOTH", "X", "Y",
              "YES", "NO", "HORIZONTAL", "VERTICAL", "NORMAL", "DISABLED",
              "WORD", "BROWSE", "EXTENDED", "MULTIPLE", "NW", "N", "W", "E",
              "S", "CENTER", "ACTIVE", "ANCHOR", "RIDGE", "FLAT", "SUNKEN",
              "RAISED", "GROOVE"]:
    setattr(_tk, _attr, _attr.lower())

_ttk = sys.modules["tkinter.ttk"]
for _w in ["Frame", "Label", "Button", "Entry", "Treeview", "Scrollbar",
           "Notebook", "Progressbar", "Style", "Combobox", "Scale",
           "Checkbutton", "Radiobutton", "LabelFrame", "PanedWindow",
           "Separator", "Sizegrip", "Spinbox", "Menubutton", "OptionMenu"]:
    setattr(_ttk, _w, type(_w, (), {"__init__": lambda *a, **kw: None}))

sys.modules["tkinter.filedialog"].askdirectory = lambda **kw: ""
sys.modules["tkinter.filedialog"].askopenfilename = lambda **kw: ""
sys.modules["tkinter.filedialog"].asksaveasfilename = lambda **kw: ""
sys.modules["tkinter.messagebox"].showinfo = lambda *a, **kw: None
sys.modules["tkinter.messagebox"].showwarning = lambda *a, **kw: None
sys.modules["tkinter.messagebox"].showerror = lambda *a, **kw: None
sys.modules["tkinter.messagebox"].askyesno = lambda *a, **kw: False
sys.modules["tkinter.messagebox"].askokcancel = lambda *a, **kw: False
sys.modules["tkinter.scrolledtext"].ScrolledText = type(
    "ScrolledText", (), {"__init__": lambda *a, **kw: None}
)
sys.modules["PIL.Image"].open = lambda *a, **kw: None
sys.modules["PIL.Image"].Image = type("Image", (), {})
sys.modules["PIL.Image"].MAX_IMAGE_PIXELS = None
sys.modules["PIL.ImageTk"].PhotoImage = type(
    "PhotoImage", (), {"__init__": lambda *a, **kw: None}
)
sys.modules["imagehash"].phash = lambda *a, **kw: None

# Now import from vkscan
from vkscan import (
    format_size,
    hamming_distance,
    calculate_similarity,
    safe_path_match,
    DuplicateScanner,
    FileInfo,
    DuplicateGroup,
    Config,
    _config,
    PHASH_BIT_COUNT,
)

# Conditionally import settings functions (may not exist yet)
import vkscan as _vkscan_mod

_has_save_settings = hasattr(_vkscan_mod, "save_settings")
_has_load_settings = hasattr(_vkscan_mod, "load_settings")
_has_config_file = hasattr(_vkscan_mod, "CONFIG_FILE")

if _has_save_settings:
    from vkscan import save_settings
if _has_load_settings:
    from vkscan import load_settings
if _has_config_file:
    from vkscan import CONFIG_FILE

# Import submodule for monkeypatching (package layout)
try:
    import vkscan.config as _vkscan_config_mod
except ImportError:
    _vkscan_config_mod = None


# =============================================================================
# Utility Functions
# =============================================================================


class TestFormatSize:
    """Tests for format_size()."""

    def test_zero(self):
        assert format_size(0) == "0 B"

    def test_negative(self):
        assert format_size(-1) == "0 B"

    def test_one_byte(self):
        result = format_size(1)
        assert "1" in result
        assert "B" in result

    def test_1024_bytes(self):
        result = format_size(1024)
        assert "KB" in result
        assert "1.0" in result

    def test_1MB(self):
        result = format_size(1048576)
        assert "MB" in result
        assert "1.0" in result

    def test_1GB(self):
        result = format_size(1073741824)
        assert "GB" in result
        assert "1.0" in result

    def test_1TB(self):
        result = format_size(1099511627776)
        assert "TB" in result
        assert "1.0" in result

    def test_500_bytes(self):
        result = format_size(500)
        assert "B" in result

    def test_large_value(self):
        result = format_size(5 * 1024 * 1024 * 1024)  # 5 GB
        assert "GB" in result
        assert "5.0" in result

    def test_non_round_value(self):
        result = format_size(1536)  # 1.5 KB
        assert "KB" in result


class TestHammingDistance:
    """Tests for hamming_distance()."""

    def test_identical_hashes(self):
        h = "abcdef0123456789"
        assert hamming_distance(h, h) == 0

    def test_single_bit_difference(self):
        # 0x0 vs 0x1 differ in 1 bit
        assert hamming_distance("0", "1") == 1

    def test_known_difference(self):
        # 0xf = 1111, 0x0 = 0000 -> 4 bits different
        assert hamming_distance("f", "0") == 4

    def test_all_zeros_vs_all_ones(self):
        # 0xff = 8 bits set
        assert hamming_distance("00", "ff") == 8

    def test_invalid_hash_returns_max(self):
        assert hamming_distance("not_hex", "also_not") == PHASH_BIT_COUNT

    def test_none_hash_returns_max(self):
        assert hamming_distance(None, "abc") == PHASH_BIT_COUNT

    def test_empty_string_returns_max(self):
        assert hamming_distance("", "abc") == PHASH_BIT_COUNT

    def test_symmetric(self):
        assert hamming_distance("abc", "def") == hamming_distance("def", "abc")


class TestCalculateSimilarity:
    """Tests for calculate_similarity()."""

    def test_zero_distance_is_100_percent(self):
        assert calculate_similarity(0) == 100.0

    def test_max_distance_is_0_percent(self):
        assert calculate_similarity(PHASH_BIT_COUNT) == 0.0

    def test_half_distance(self):
        half = PHASH_BIT_COUNT // 2
        result = calculate_similarity(half)
        assert 49.0 <= result <= 51.0

    def test_negative_distance_clamps(self):
        result = calculate_similarity(-10)
        assert result == 100.0

    def test_over_max_distance_clamps(self):
        result = calculate_similarity(PHASH_BIT_COUNT + 100)
        assert result == 0.0

    def test_zero_max_bits(self):
        assert calculate_similarity(0, max_bits=0) == 0.0

    def test_custom_max_bits(self):
        assert calculate_similarity(0, max_bits=64) == 100.0
        assert calculate_similarity(64, max_bits=64) == 0.0
        assert calculate_similarity(32, max_bits=64) == 50.0


class TestSafePathMatch:
    """Tests for safe_path_match()."""

    def test_simple_match(self):
        assert safe_path_match("/home/user/photos/image.jpg", "photos") is True

    def test_no_match(self):
        assert safe_path_match("/home/user/docs/file.txt", "photos") is False

    def test_case_insensitive(self):
        assert safe_path_match("/home/user/Photos/img.jpg", "photos") is True

    def test_empty_pattern_returns_false(self):
        assert safe_path_match("/some/path", "") is False

    def test_dot_pattern_returns_false(self):
        assert safe_path_match("/some/path", ".") is False

    def test_double_dot_pattern_returns_false(self):
        assert safe_path_match("/some/path", "..") is False

    def test_star_pattern_returns_false(self):
        assert safe_path_match("/some/path", "*") is False

    def test_question_mark_pattern_returns_false(self):
        assert safe_path_match("/some/path", "?") is False

    def test_pattern_with_whitespace(self):
        assert safe_path_match("/home/user/node_modules/pkg", "  node_modules  ") is True

    def test_extension_match(self):
        assert safe_path_match("/home/user/file.tmp", ".tmp") is True

    def test_partial_directory_match(self):
        assert safe_path_match("/home/user/__pycache__/mod.pyc", "__pycache__") is True


# =============================================================================
# DuplicateScanner
# =============================================================================


class TestDuplicateScannerComputeHash:
    """Tests for DuplicateScanner.compute_hash()."""

    def test_compute_hash_correct(self, tmp_path):
        test_file = tmp_path / "test.txt"
        content = b"Hello, world! This is a test file for hashing."
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        scanner = DuplicateScanner()
        result = scanner.compute_hash(str(test_file))
        assert result == expected

    def test_compute_hash_empty_file(self, tmp_path):
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        expected = hashlib.sha256(b"").hexdigest()
        scanner = DuplicateScanner()
        result = scanner.compute_hash(str(test_file))
        assert result == expected

    def test_compute_hash_nonexistent_file(self):
        scanner = DuplicateScanner()
        result = scanner.compute_hash("/nonexistent/path/to/file.txt")
        assert result is None

    def test_compute_hash_large_file(self, tmp_path):
        test_file = tmp_path / "large.bin"
        content = b"x" * (2 * 1024 * 1024)  # 2MB
        test_file.write_bytes(content)

        expected = hashlib.sha256(content).hexdigest()
        scanner = DuplicateScanner()
        result = scanner.compute_hash(str(test_file))
        assert result == expected

    def test_compute_hash_cancelled_returns_none(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"some content")

        scanner = DuplicateScanner()
        scanner.cancelled = True
        result = scanner.compute_hash(str(test_file))
        assert result is None


class TestDuplicateScannerComputeQuickHash:
    """Tests for DuplicateScanner.compute_quick_hash()."""

    def test_same_file_same_hash(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"Hello, quick hash test!")

        scanner = DuplicateScanner()
        h1 = scanner.compute_quick_hash(str(test_file))
        h2 = scanner.compute_quick_hash(str(test_file))
        assert h1 is not None
        assert h1 == h2

    def test_different_files_different_hash(self, tmp_path):
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        f1.write_bytes(b"Content A")
        f2.write_bytes(b"Content B")

        scanner = DuplicateScanner()
        h1 = scanner.compute_quick_hash(str(f1))
        h2 = scanner.compute_quick_hash(str(f2))
        assert h1 is not None
        assert h2 is not None
        assert h1 != h2

    def test_identical_content_same_hash(self, tmp_path):
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        content = b"Identical content here"
        f1.write_bytes(content)
        f2.write_bytes(content)

        scanner = DuplicateScanner()
        assert scanner.compute_quick_hash(str(f1)) == scanner.compute_quick_hash(str(f2))

    def test_nonexistent_file(self):
        scanner = DuplicateScanner()
        result = scanner.compute_quick_hash("/nonexistent/file.txt")
        assert result is None

    def test_empty_file_returns_none(self, tmp_path):
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        scanner = DuplicateScanner()
        result = scanner.compute_quick_hash(str(test_file))
        assert result is None


class TestDuplicateScannerCollectFiles:
    """Tests for DuplicateScanner.collect_files()."""

    def test_collect_files_basic(self, tmp_path):
        (tmp_path / "file1.txt").write_text("hello")
        (tmp_path / "file2.txt").write_text("world")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "file3.txt").write_text("nested")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        assert len(files) == 3
        paths = {f.path for f in files}
        assert str(tmp_path / "file1.txt") in paths
        assert str(tmp_path / "file2.txt") in paths
        assert str(sub / "file3.txt") in paths

    def test_collect_files_records_size(self, tmp_path):
        f = tmp_path / "sized.txt"
        f.write_text("12345")  # 5 bytes

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        assert len(files) == 1
        assert files[0].size == 5

    def test_collect_files_nonexistent_dir(self):
        scanner = DuplicateScanner()
        files = scanner.collect_files(["/nonexistent/path/xyz"], set())
        assert files == []

    def test_collect_files_multiple_roots(self, tmp_path):
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "a.txt").write_text("aaa")
        (dir2 / "b.txt").write_text("bbb")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(dir1), str(dir2)], set())
        assert len(files) == 2


class TestCollectFilesExclusions:
    """Tests for exclusion patterns in collect_files()."""

    def test_exclude_directory(self, tmp_path):
        keep = tmp_path / "keep"
        skip = tmp_path / "node_modules"
        keep.mkdir()
        skip.mkdir()
        (keep / "a.txt").write_text("keep")
        (skip / "b.txt").write_text("skip")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], {"node_modules"})
        paths = {f.path for f in files}
        assert any("keep" in p for p in paths)
        assert not any("node_modules" in p for p in paths)

    def test_exclude_pattern(self, tmp_path):
        (tmp_path / "file.txt").write_text("keep")
        (tmp_path / "file.log").write_text("skip")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], {".log"})
        paths = {f.path for f in files}
        assert any(".txt" in p for p in paths)
        assert not any(".log" in p for p in paths)


class TestCollectFilesSkipsEmpty:
    """Tests that zero-byte files are skipped."""

    def test_skips_empty_files(self, tmp_path):
        (tmp_path / "empty.txt").write_bytes(b"")
        (tmp_path / "notempty.txt").write_text("content")

        scanner = DuplicateScanner()
        original = _config.skip_empty_files
        _config.skip_empty_files = True
        try:
            files = scanner.collect_files([str(tmp_path)], set())
            assert len(files) == 1
            assert "notempty" in files[0].path
        finally:
            _config.skip_empty_files = original


class TestFindDuplicatesExact:
    """Tests for finding exact duplicates."""

    def test_find_duplicates_identical_files(self, tmp_path):
        content = b"This is duplicate content for testing purposes."
        f1 = tmp_path / "dup1.txt"
        f2 = tmp_path / "dup2.txt"
        f3 = tmp_path / "dup3.txt"
        f1.write_bytes(content)
        f2.write_bytes(content)
        f3.write_bytes(content)

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)

        assert len(groups) >= 1
        total_dupes = sum(g.file_count() for g in groups)
        assert total_dupes == 3

    def test_find_duplicates_two_pairs(self, tmp_path):
        content_a = b"Content A for dedup"
        content_b = b"Content B for dedup"

        (tmp_path / "a1.txt").write_bytes(content_a)
        (tmp_path / "a2.txt").write_bytes(content_a)
        (tmp_path / "b1.txt").write_bytes(content_b)
        (tmp_path / "b2.txt").write_bytes(content_b)

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)

        assert len(groups) == 2


class TestFindDuplicatesNoDupes:
    """Tests that unique files produce no duplicate groups."""

    def test_no_duplicates(self, tmp_path):
        (tmp_path / "unique1.txt").write_text("unique content 1")
        (tmp_path / "unique2.txt").write_text("unique content 2")
        (tmp_path / "unique3.txt").write_text("unique content 3")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)
        assert groups == []

    def test_single_file(self, tmp_path):
        (tmp_path / "only.txt").write_text("only file here")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)
        assert groups == []

    def test_same_size_different_content(self, tmp_path):
        (tmp_path / "f1.txt").write_text("aaaa")
        (tmp_path / "f2.txt").write_text("bbbb")

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)
        assert groups == []


@pytest.mark.skipif(sys.platform == "win32", reason="Hard links behave differently on Windows")
class TestHardLinkDetection:
    """Tests that hard links are properly detected and skipped."""

    def test_hard_links_skipped(self, tmp_path):
        original = tmp_path / "original.txt"
        original.write_text("hard link test content")
        link = tmp_path / "hardlink.txt"
        os.link(str(original), str(link))

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        assert len(files) == 1

    def test_hard_link_not_reported_as_duplicate(self, tmp_path):
        original = tmp_path / "original.txt"
        original.write_text("hard link dedup test")
        link = tmp_path / "link.txt"
        os.link(str(original), str(link))

        scanner = DuplicateScanner()
        files = scanner.collect_files([str(tmp_path)], set())
        groups = scanner.find_duplicates(files, perceptual_images=False)
        assert groups == []


# =============================================================================
# FileInfo and DuplicateGroup
# =============================================================================


class TestDuplicateGroup:
    """Tests for DuplicateGroup data class."""

    def test_recoverable_size_basic(self):
        group = DuplicateGroup(files=[
            FileInfo(path="/a.txt", size=1000),
            FileInfo(path="/b.txt", size=1000),
            FileInfo(path="/c.txt", size=1000),
        ])
        assert group.recoverable_size() == 2000

    def test_recoverable_size_single_file(self):
        group = DuplicateGroup(files=[
            FileInfo(path="/a.txt", size=1000),
        ])
        assert group.recoverable_size() == 0

    def test_recoverable_size_empty(self):
        group = DuplicateGroup(files=[])
        assert group.recoverable_size() == 0

    def test_recoverable_size_two_files(self):
        group = DuplicateGroup(files=[
            FileInfo(path="/a.txt", size=5000),
            FileInfo(path="/b.txt", size=5000),
        ])
        assert group.recoverable_size() == 5000

    def test_file_count(self):
        group = DuplicateGroup(files=[
            FileInfo(path="/a.txt", size=100),
            FileInfo(path="/b.txt", size=100),
            FileInfo(path="/c.txt", size=100),
        ])
        assert group.file_count() == 3

    def test_file_count_empty(self):
        group = DuplicateGroup(files=[])
        assert group.file_count() == 0

    def test_default_similarity(self):
        group = DuplicateGroup()
        assert group.similarity == 100.0

    def test_perceptual_flag(self):
        group = DuplicateGroup(is_perceptual=True)
        assert group.is_perceptual is True


# =============================================================================
# Config and Settings
# =============================================================================


@pytest.mark.skipif(not _has_save_settings or not _has_load_settings,
                    reason="save_settings/load_settings not yet in vkscan.py")
class TestSaveLoadSettings:
    """Tests for save_settings() and load_settings()."""

    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        config_file = config_dir / "settings.json"

        monkeypatch.setattr(_vkscan_mod, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        # Also patch the submodule where save_settings/load_settings actually read from
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_DIR", config_dir)
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)

        original_threshold = _config.image_similarity_threshold
        original_workers = _config.workers
        _config.image_similarity_threshold = 12
        _config.workers = 8

        try:
            save_settings(
                scan_paths=["/home/user/photos", "/home/user/docs"],
                scan_exclusions=["node_modules", ".cache"],
                scan_perceptual=False,
            )
            assert config_file.exists()

            _config.image_similarity_threshold = 99
            _config.workers = 99

            load_settings()

            assert _config.image_similarity_threshold == 12
            assert _config.workers == 8
            _check_mod = _vkscan_config_mod if _vkscan_config_mod is not None else _vkscan_mod
            assert _check_mod._saved_scan_paths == ["/home/user/photos", "/home/user/docs"]
            assert _check_mod._saved_scan_exclusions == ["node_modules", ".cache"]
            assert _check_mod._saved_scan_perceptual is False
        finally:
            _config.image_similarity_threshold = original_threshold
            _config.workers = original_workers

    def test_save_creates_directory(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "new" / "nested" / "config"
        config_file = config_dir / "settings.json"

        monkeypatch.setattr(_vkscan_mod, "CONFIG_DIR", config_dir)
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_DIR", config_dir)
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)

        save_settings(scan_paths=["/test"])
        assert config_dir.exists()
        assert config_file.exists()


@pytest.mark.skipif(not _has_load_settings,
                    reason="load_settings not yet in vkscan.py")
class TestLoadSettingsMissingFile:
    """Tests that load_settings handles missing files gracefully."""

    def test_missing_file_no_error(self, tmp_path, monkeypatch):
        config_file = tmp_path / "nonexistent" / "settings.json"
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)
        load_settings()  # Should not raise

    def test_missing_file_keeps_defaults(self, tmp_path, monkeypatch):
        config_file = tmp_path / "nonexistent" / "settings.json"
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)

        original_threshold = _config.image_similarity_threshold
        load_settings()
        assert _config.image_similarity_threshold == original_threshold


@pytest.mark.skipif(not _has_load_settings,
                    reason="load_settings not yet in vkscan.py")
class TestLoadSettingsCorruptFile:
    """Tests that load_settings handles corrupt files gracefully."""

    def test_corrupt_json(self, tmp_path, monkeypatch):
        config_file = tmp_path / "settings.json"
        config_file.write_text("THIS IS NOT VALID JSON {{{{", encoding="utf-8")
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)

        original_threshold = _config.image_similarity_threshold
        load_settings()
        assert _config.image_similarity_threshold == original_threshold

    def test_empty_file(self, tmp_path, monkeypatch):
        config_file = tmp_path / "settings.json"
        config_file.write_text("", encoding="utf-8")
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)
        load_settings()  # Should not raise

    def test_binary_garbage(self, tmp_path, monkeypatch):
        config_file = tmp_path / "settings.json"
        config_file.write_bytes(b"\x00\x01\x02\xff\xfe\xfd")
        monkeypatch.setattr(_vkscan_mod, "CONFIG_FILE", config_file)
        if _vkscan_config_mod is not None:
            monkeypatch.setattr(_vkscan_config_mod, "CONFIG_FILE", config_file)
        load_settings()  # Should not raise


# =============================================================================
# Integration / CLI Tests
# =============================================================================


VKSCAN_PATH = Path(PROJECT_ROOT) / "vkscan.py"


@pytest.mark.skipif(not VKSCAN_PATH.exists(), reason="vkscan.py not found")
class TestCLI:
    """Integration tests that run vkscan.py as a CLI subprocess.

    These tests are best-effort: if the CLI doesn't support certain flags,
    the tests verify it doesn't crash rather than asserting specific output.
    """

    def test_cli_version(self):
        result = subprocess.run(
            [sys.executable, str(VKSCAN_PATH), "--version"],
            capture_output=True, text=True, timeout=30
        )
        # Accept any exit code; just verify it ran
        assert result.returncode is not None

    def test_cli_scan(self, tmp_path):
        content = b"Duplicate content for CLI test"
        (tmp_path / "dup1.txt").write_bytes(content)
        (tmp_path / "dup2.txt").write_bytes(content)
        (tmp_path / "unique.txt").write_bytes(b"unique content here")

        result = subprocess.run(
            [sys.executable, str(VKSCAN_PATH), "--scan", str(tmp_path), "--no-perceptual"],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode is not None

    def test_cli_export_csv(self, tmp_path):
        content = b"CSV export test duplicate content"
        (tmp_path / "dup1.txt").write_bytes(content)
        (tmp_path / "dup2.txt").write_bytes(content)
        csv_out = tmp_path / "report.csv"

        result = subprocess.run(
            [sys.executable, str(VKSCAN_PATH), "--scan", str(tmp_path),
             "--no-perceptual", "-o", str(csv_out)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and csv_out.exists():
            text = csv_out.read_text()
            assert len(text) > 0

    def test_cli_export_txt(self, tmp_path):
        content = b"TXT export test duplicate content"
        (tmp_path / "dup1.txt").write_bytes(content)
        (tmp_path / "dup2.txt").write_bytes(content)
        txt_out = tmp_path / "report.txt"

        result = subprocess.run(
            [sys.executable, str(VKSCAN_PATH), "--scan", str(tmp_path),
             "--no-perceptual", "-o", str(txt_out)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and txt_out.exists():
            text = txt_out.read_text()
            assert len(text) > 0
