# Building VKScan for Windows

## Pre-Built Downloads

Pre-built Windows `.exe` files are available on the [Releases](../../releases) page.

---

## Building Locally (on a Windows machine)

### Quick Build (One-Liner)

```batch
pip install pyinstaller pillow imagehash send2trash && pyinstaller --onefile --windowed --name VKScan --icon vkscan_icon.ico vkscan.py
```

The executable will be in `dist\VKScan.exe`

### Step-by-Step Build

#### 1. Install Dependencies

```batch
pip install pyinstaller pillow imagehash send2trash
```

#### 2. Run the Build Script

```batch
build_exe.bat
```

The script handles everything: dependency installation, cleanup, icon inclusion, and build verification.

Or build manually with all hidden imports:

```batch
pyinstaller --onefile ^
    --windowed ^
    --name "VKScan" ^
    --icon "vkscan_icon.ico" ^
    --hidden-import=tkinter ^
    --hidden-import=tkinter.ttk ^
    --hidden-import=tkinter.filedialog ^
    --hidden-import=tkinter.messagebox ^
    --hidden-import=tkinter.scrolledtext ^
    --hidden-import=PIL ^
    --hidden-import=PIL.Image ^
    --hidden-import=PIL.ImageTk ^
    --hidden-import=imagehash ^
    --hidden-import=send2trash ^
    vkscan.py
```

#### 3. Find Your Executable

```
dist\VKScan.exe
```

### Using the .spec File

For repeatable builds, use the included spec file:

```batch
pyinstaller vkscan.spec
```

This uses the same configuration as `build_exe.bat` but is version-controlled and consistent.

---

## Build Options Explained

| Option | Description |
|--------|-------------|
| `--onefile` | Bundles everything into a single `.exe` |
| `--windowed` | No console window (GUI-only app) |
| `--name VKScan` | Sets the executable name |
| `--icon vkscan_icon.ico` | Embeds the app icon |
| `--hidden-import=...` | Ensures dynamically-imported modules are included |

---

## Distribution Notes

### Single File Mode (`--onefile`)
- ✅ Easy to distribute (one file)
- ⚠️ Slightly slower startup (extracts to temp on first run)
- ⚠️ Antivirus may flag the temp extraction — see Troubleshooting below

### One-Directory Mode (remove `--onefile`)
- ⚡ Faster startup
- ✅ More trustworthy to antivirus
- ⚠️ Need to distribute the entire folder (zip it up)

---

## Troubleshooting

### "Module not found" errors at runtime

If the `.exe` crashes with a missing module, add it as a hidden import:

```batch
pyinstaller --onefile --windowed --hidden-import=some.module vkscan.py
```

Common ones are already included in `build_exe.bat` and the `.spec` file.

### Large file size (~50-70 MB)

This is normal — the `.exe` bundles the Python interpreter and all dependencies. To reduce size:
- Enable UPX compression (on by default in the spec file)
- Use `--exclude-module` to drop unused stdlib modules

### Antivirus false positives

PyInstaller executables are commonly flagged by antivirus software. Options:
1. Sign the executable with a code signing certificate
2. Use one-directory mode instead of `--onefile`
3. Submit the `.exe` to your AV vendor as a false positive
4. Ask users to whitelist the file/folder

## File Sizes (Approximate)

| Build Type | Size |
|------------|------|
| Single file (`.exe`) | ~50-70 MB |
| One directory (zipped) | ~50-70 MB (split across files) |

The size includes the Python 3.12 interpreter and all dependencies (Pillow, imagehash, send2trash, tkinter).
