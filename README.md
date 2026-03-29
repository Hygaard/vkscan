# VKScan

Find and clean up duplicate files on your computer.

VKScan scans your folders, finds exact copies and similar-looking images, and lets you review and delete the extras. It works on Windows, macOS, and Linux.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-green.svg)

## Download

Grab the latest build from the [Releases](../../releases) page — no Python needed.

| Platform | File |
|----------|------|
| Windows | `VKScan-Windows.exe` |
| Linux | `VKScan-Linux` |
| macOS | `VKScan-macOS` |

Or run from source:

```bash
pip install -r requirements.txt
python vkscan.py
```

## What It Does

- **Finds exact duplicates** — matches files byte-for-byte using SHA-256
- **Finds similar images** — spots photos that look alike even if resized, cropped, or recompressed
- **Shows you everything first** — preview files, compare side-by-side, then decide what to delete
- **Sends to trash** — deleted files go to your recycle bin, not gone forever
- **Filters results** — search by name, filter by type or size, sort by any column

## How to Use

1. Click **Scan**, pick your folders
2. Wait for results (progress bar shows each stage)
3. Click **Auto-Select** to mark duplicates for deletion (keeps the best copy)
4. Review, then click **Delete** or **Move**

## Command Line

```bash
# Scan and show results
python vkscan.py --scan ~/Photos ~/Backups

# Save report
python vkscan.py --scan ~/Photos -o report.json

# Auto-delete duplicates (keeps oldest file)
python vkscan.py --scan ~/Photos --delete --confirm
```

## License

GPL v3 — Copyright © 2026 Hygaard

**Use at your own risk.** Always keep backups before bulk-deleting files.
