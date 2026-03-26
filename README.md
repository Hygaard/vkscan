# VKScan v1.0.0

**Voight-Kampff Scanner** — a GUI tool for finding and managing duplicate and similar files on your computer. Named after the [Voight-Kampff test](https://bladerunner.fandom.com/wiki/Voight-Kampff_test) from *Blade Runner*, which detects replicants hiding among originals.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## Features

- **Exact Duplicate Detection** — SHA-256 hashing with byte-level verification
- **Similar Image Detection** — Perceptual hashing (pHash) finds visually similar images
- **Parallel Scanning** — Multi-threaded hashing with quick-reject for fast results
- **Live Results** — Duplicates appear in the treeview as they're discovered, sorted by wasted space
- **Hard Link Detection** — Automatically identifies and skips hard links
- **Safe Deletion** — Trash/recycle bin support via send2trash
- **Modern Dark UI** — Dark theme with staged progress display
- **Preview & Compare** — Preview files in tabs, compare side-by-side with metadata
- **Export Reports** — Save findings as TXT or CSV
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

## Usage

1. Click **▶ Scan** to open the scan options dialog
2. Add folders or drives to scan
3. Configure exclusions (system directories are excluded by default)
4. Optionally enable perceptual image comparison
5. Press **Enter** or click **Start Scan**

### Managing Results

- **Auto-Select** — Selects all duplicates except the oldest in each group
- **Double-click** a file to preview it
- **Right-click** for context menu (Preview, Open Location, Compare, Delete, Move)
- **Click column headers** to sort (▲ ascending / ▼ descending)
- **Compare** — Side-by-side view of two selected files with metadata
- **Export** — File > Export Report (TXT or CSV)

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Delete` | Delete selected files |
| `Ctrl+C` | Cancel current scan |
| `Ctrl+A` | Select all files |
| `Ctrl+E` | Export report |
| `Ctrl+O` | Open file location |
| `Escape` | Deselect all |

## How It Works

1. **File Discovery** — Walks directories, collects file metadata, skips hard links
2. **Size Grouping** — Groups files by size (different sizes can't be duplicates)
3. **Quick Hash** — Hashes the first 4KB to reject obvious non-matches early
4. **Full Hash** — SHA-256 of remaining candidates (parallel, multi-threaded)
5. **Byte Verification** — Confirms hash matches with `filecmp.cmp` (defense-in-depth)
6. **Perceptual Hashing** — Optional pHash comparison for similar images (parallel)

### Performance

- Multi-threaded I/O via `ThreadPoolExecutor` (configurable worker count)
- Default workers: `cpu_count - 2` (reserves cores for OS and GUI)
- 1MB read buffer (optimized for modern SSDs/NVMe)
- Quick-reject typically eliminates 30-70% of candidates before full hashing
- Queue-based GUI updates keep the interface responsive during scans

### Security

- Image pixel limit (100MP) to prevent decompression bombs
- File size limits (100GB general, 1GB for image processing)
- Image verification (`img.verify()`) before processing
- Safe path matching (rejects dangerous glob patterns)

## Troubleshooting

### "Module not found" errors

```bash
pip install pillow imagehash send2trash
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

## License

Copyright © 2026 Hygaard.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](LICENSE) for more details.

## Disclaimer

**Use at your own risk.** Always maintain backups before deleting or moving files. The authors assume no responsibility for data loss resulting from the use of this tool.

## Contributing

Issues and pull requests welcome! Key areas for improvement:
- Unit tests
- Support for more file types (PDFs, documents)
- Command-line interface
- Drag-and-drop folder selection
