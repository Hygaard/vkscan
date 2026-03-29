# VKScan

Find and clean up duplicate files on your computer.

VKScan scans your folders, finds exact copies, similar-looking images, and near-duplicate documents — then lets you review and delete the extras. Works on Windows, macOS, and Linux.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License: GPL v3](https://img.shields.io/badge/license-GPL%20v3-green.svg)

## Download

Grab the latest build from the [Releases](../../releases) page — no Python needed.

### Windows

Download `VKScan-Windows.exe` and double-click to run.

### macOS

```bash
# Download, make executable, and run
chmod +x VKScan-macOS-arm64
./VKScan-macOS-arm64
```

If macOS blocks it: go to **System Settings → Privacy & Security** and click **Open Anyway**.

### Linux

```bash
# Download, make executable, and run
chmod +x VKScan-Linux-x86_64
./VKScan-Linux-x86_64
```

### Run from source (any platform)

```bash
pip install -r requirements.txt
python vkscan.py
```

## What It Does

- **Finds exact duplicates** — matches files byte-for-byte using SHA-256
- **Finds similar images** — spots photos that look alike even if resized, cropped, or recompressed
- **Finds similar documents** — detects near-duplicate text files, PDFs, Word docs, spreadsheets, and code files
- **Shows you everything first** — preview files, compare side-by-side, then decide what to delete
- **Sends to trash** — deleted files go to your recycle bin, not gone forever
- **Filters results** — search by name, filter by type or size, sort by any column

## How to Use

1. Click **Scan**, pick your folders
2. Choose what to scan for (exact duplicates, similar images, similar documents)
3. Wait for results (progress bar shows each stage)
4. Click **Auto-Select** to mark duplicates for deletion (keeps the best copy)
5. Review, then click **Delete** or **Move**

## Supported Document Formats

VKScan can extract and compare text from:

| Format | Extensions | Requires |
|--------|-----------|----------|
| Plain text & code | .txt .md .py .js .java .c .html .sql etc. | Nothing |
| PDF | .pdf | pdfplumber |
| Word | .docx | python-docx |
| Excel | .xlsx | openpyxl |
| OpenDocument | .odt .ods | odfpy |

Document libraries are optional — install what you need, skip what you don't.

## Command Line

```bash
# Scan and show results
python vkscan.py --scan ~/Photos ~/Backups

# Save report as JSON
python vkscan.py --scan ~/Photos -o report.json

# Skip image or document comparison for faster scans
python vkscan.py --scan ~/Code --no-perceptual
python vkscan.py --scan ~/Photos --no-documents

# Auto-delete duplicates (keeps oldest file)
python vkscan.py --scan ~/Photos --delete --confirm
```

## License

GPL v3 — Copyright © 2026 Hygaard

**Use at your own risk.** Always keep backups before bulk-deleting files.
