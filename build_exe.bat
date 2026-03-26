@echo off
REM Build script for VKScan Windows executable
REM 
REM Prerequisites:
REM   - Python 3.8+ installed
REM   - pip install pyinstaller pillow imagehash send2trash
REM
REM Note: Uses vkscan_icon.ico if present

echo ============================================
echo Building VKScan v1.0.0
echo ============================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+ first.
    pause
    exit /b 1
)

REM Install build dependencies
echo Installing dependencies...
pip install --quiet pyinstaller pillow imagehash send2trash
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

REM Clean previous build
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "VKScan.spec" del "VKScan.spec"

REM Build with PyInstaller (include icon if present)
echo Building executable...
if exist vkscan_icon.ico (
    echo Using icon: vkscan_icon.ico
    pyinstaller --onefile ^
        --windowed ^
        --name "VKScan" ^
        --icon "vkscan_icon.ico" ^
        --add-data "vkscan_icon.ico;." ^
        --add-data "vkscan_icon.png;." ^
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
) else (
    echo No icon file found, building without icon...
    pyinstaller --onefile ^
        --windowed ^
        --name "VKScan" ^
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
)

if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo Build complete!
echo ============================================
echo Executable location: dist\VKScan.exe
echo.
echo To test: cd dist && VKScan.exe
echo.
pause
