# VKScan v1.1.0

**Voight-Kampff Scanner** — a GUI tool for finding and managing duplicate and similar files on your computer. Named after the [Voight-Kampff test](https://bladerunner.fandom.com/wiki/Voight-Kampff_test) from *Blade Runner*, which detects replicants hiding among originals.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## Features

- **Exact Duplicate Detection** — SHA-256 hashing with byte-level verification
- **Similar Image Detection** — Perceptual hashing (pHash) finds visually similar images
- **Parallel Scanning** — Multi-threaded hashing with quick-reject for fast results
- **Multi-Process pHash** — CPU-bound perceptual hashing uses `ProcessPoolExecutor` for true multi-core utilization
- **Hash Cache** — SQLite-backed persistent cache skips re-hashing unchanged files on rescan
- **BK-Tree Search** — Efficient O(n log n) perceptual similarity matching instead of brute-force O(n²)
- **Live Results** — Duplicates appear in the treeview as they're discovered, sorted by wasted space
- **Filter Bar** — Search by filename/path, filter by type (Exact/Similar), and minimum file size
- **Hard Link Detection** — Automatically identifies and skips hard links
- **Safe Deletion** — Trash/recycle bin support via send2trash
- **Modern Dark UI** — Dark theme with staged progress display and ETA
- **Preview & Compare** — Preview files with navigation, compare side-by-side with metadata
- **Export Reports** — Save findings as TXT, CSV, or JSON
- **Drag & Drop** — Drop folders into the scan dialog (requires tkinterdnd2) or paste paths with Ctrl+V
- **CLI Mode** — Full command-line interface with scan, export, delete, and move capabilities
- **Cross-Platform** — Works on Windows, macOS, and Linux

## Quick Start

### Download (Windows)

Pre-built Windows `.exe` files are available on the [Releases](../../releases) page — no Python installation required.

### Run from Source

```bash
pip install -r requirements.txt
python vkscan.py
```

### Build an Executable

See [README_BUILD.md](README_BUILD.md) for build instructions using PyInstaller.

## GUI Usage

1. Click **▶ Scan** to open the scan options dialog
2. Add folders or drives to scan (or drag & drop folders)
3. Configure exclusions (system directories are excluded by default)
4. Optionally enable perceptual image comparison
5. Press **Enter** or click **Start Scan**

### Managing Results

- **Filter** — Use the filter bar to search by name, filter by type, or set minimum file size
- **Auto-Select** — Selects all duplicates except the best file in each group
- **Double-click** a file to preview it
- **Right-click** for context menu (Preview, Open Location, Compare, Delete, Move)
- **Click column headers** to sort (▲ ascending / ▼ descending)
- **Compare** — Side-by-side view of two selected files with metadata
- **Export** — File > Export Report (TXT, CSV, or JSON)

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+F` | Focus filter search |
| `Delete` | Delete selected files |
| `Ctrl+C` | Cancel current scan |
| `Ctrl+A` | Select all files |
| `Ctrl+E` | Export report |
| `Ctrl+O` | Open file location |
| `Escape` | Deselect all |

## CLI Usage

VKScan includes a full command-line interface for scripted workflows:

```bash
# Scan directories and print results
python vkscan.py --scan /path/to/photos /path/to/backups

# Export results to JSON
python vkscan.py --scan ~/Documents -o report.json

# Export as CSV
python vkscan.py --scan ~/Documents -o report.csv

# Skip perceptual image comparison (faster)
python vkscan.py --scan /data --no-perceptual

# Delete duplicates (keeps oldest file in each exact group)
python vkscan.py --scan /data --delete --confirm

# Move duplicates to a staging directory
python vkscan.py --scan /data --move-to /tmp/duplicates --confirm

# Customize worker threads and similarity threshold
python vkscan.py --scan /data --workers 16 --threshold 12
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--scan PATH [PATH...]` | Scan one or more directories (CLI mode) |
| `-o, --output FILE` | Export results to FILE (.txt, .csv, or .json) |
| `--no-perceptual` | Skip perceptual image hashing |
| `--exclude PATTERN` | Exclude paths matching PATTERN (repeatable) |
| `--workers N` | Number of worker threads |
| `--threshold N` | Perceptual hash distance threshold (0=exact, higher=more lenient) |
| `--delete` | Delete duplicates (keeps oldest). Requires `--confirm` |
| `--move-to DIR` | Move duplicates to DIR. Requires `--confirm` |
| `--confirm` | Required with `--delete` or `--move-to` for safety |
| `--version` | Show version |

## How It Works

1. **File Discovery** — Walks directories, collects file metadata, skips hard links
2. **Size Grouping** — Groups files by size (different sizes can't be duplicates)
3. **Quick Hash** — Hashes the first 4KB to reject obvious non-matches early
4. **Full Hash** — SHA-256 of remaining candidates (parallel, multi-threaded)
5. **Byte Verification** — Confirms hash matches with `filecmp.cmp` (defense-in-depth)
6. **Perceptual Hashing** — Optional pHash comparison for similar images (parallel, multi-process for large sets)
7. **BK-Tree Matching** — Efficient nearest-neighbor search by Hamming distance

### Performance

- Multi-threaded I/O via `ThreadPoolExecutor` for SHA-256 hashing
- `ProcessPoolExecutor` for CPU-bound perceptual hashing (50+ images)
- SQLite hash cache — rescanning unchanged directories is near-instant
- BK-tree for O(n log n) perceptual similarity search
- Default workers: `cpu_count - 2` (reserves cores for OS and GUI)
- 1MB read buffer (optimized for modern SSDs/NVMe)
- Quick-reject typically eliminates 30-70% of candidates before full hashing
- Queue-based GUI updates keep the interface responsive during scans

### Security

- Image pixel limit (100MP) to prevent decompression bombs
- File size limits (100GB general, 1GB for image processing)
- Image verification (`img.verify()`) before processing
- Safe path matching (rejects dangerous glob patterns)
- CLI delete/move requires explicit `--confirm` flag
- CLI only acts on verified 100% exact-match groups

## Troubleshooting

### "Module not found" errors

```bash
pip install pillow imagehash send2trash
```

### Enable drag & drop (optional)

```bash
pip install tkinterdnd2
```

### Slow scans

- Disable perceptual image comparison for faster scans
- Add more exclusions to reduce the number of files scanned
- Increase worker threads in Options

## Requirements

- Python 3.8+
- Pillow (image processing)
- imagehash (perceptual hashing)
- send2trash (optional, for safe deletion)
- tkinterdnd2 (optional, for native drag & drop)

## What's New in v1.1.0

- **ProcessPoolExecutor** for perceptual hashing — true multi-core CPU utilization
- **SQLite hash cache** — skip re-hashing unchanged files on rescan
- **BK-tree** for perceptual similarity — O(n log n) instead of O(n²)
- **Filter bar** — search, type filter, minimum size filter
- **JSON export** — structured output for programmatic consumption
- **CLI delete/move** — `--delete` and `--move-to` flags with `--confirm` safety
- **Drag & drop** — optional tkinterdnd2 support + Ctrl+V paste
- **Module split** — clean `vkscan/` package alongside the monolith
- Fixed: size parsing in auto-select now uses exact bytes (no display-string rounding)
- Fixed: context menu memory leak (orphan widgets)
- Fixed: VERSION constant replaces all hardcoded version strings

## License

Copyright © 2026 Hygaard.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](LICENSE) for more details.

## Disclaimer

**Use at your own risk.** Always maintain backups before deleting or moving files. The authors assume no responsibility for data loss resulting from the use of this tool.

## Contributing

Issues and pull requests welcome! See the codebase — both `vkscan.py` (monolith) and the `vkscan/` package are maintained in parallel.
