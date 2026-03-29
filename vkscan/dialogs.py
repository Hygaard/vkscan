#!/usr/bin/env python3
"""VKScan scan and options dialogs."""

import os
import sys
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from .constants import (
    BG_DARK, BG_LIGHT, TEXT_PRIMARY, DEFAULT_EXCLUSIONS,
)
from .config import (
    _config, save_settings,
    _saved_scan_paths, _saved_scan_exclusions, _saved_scan_perceptual,
)
from .models import ScanOptions
from .utils import HAS_SEND2TRASH

class ScanDialog:
    """Dialog for configuring scan options."""

    def __init__(self, parent: tk.Tk):
        self.result: Optional[ScanOptions] = None
        self.top = tk.Toplevel(parent)
        self.top.title("Scan Options")
        self.top.geometry("550x420")
        self.top.minsize(400, 300)
        self.top.transient(parent)
        self.top.grab_set()
        self.top.configure(bg=BG_DARK)

        # Make content expand when dialog is resized
        content = ttk.Frame(self.top, padding=10)
        content.pack(fill=tk.BOTH, expand=True)

        ttk.Label(content, text="Locations to Scan:").pack(anchor=tk.W)
        self.paths_text = scrolledtext.ScrolledText(
            content, height=4,
            bg=BG_LIGHT, fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY)
        self.paths_text.pack(fill=tk.BOTH, expand=True, pady=(2, 5))

        btn_frame = ttk.Frame(content)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(btn_frame, text="📁 Add Folder", command=self._add_folder).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="💿 Add Drive", command=self._add_drive).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: self.paths_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)

        ttk.Label(content, text="Exclusions (one per line):").pack(anchor=tk.W)
        self.excl_text = scrolledtext.ScrolledText(
            content, height=3,
            bg=BG_LIGHT, fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY)
        self.excl_text.pack(fill=tk.BOTH, expand=True, pady=(2, 5))
        if _saved_scan_exclusions:
            self.excl_text.insert(1.0, "\n".join(_saved_scan_exclusions))
        else:
            self.excl_text.insert(1.0, DEFAULT_EXCLUSIONS)

        # Pre-populate paths from saved settings
        if _saved_scan_paths:
            self.paths_text.insert(1.0, "\n".join(_saved_scan_paths) + "\n")

        self.perceptual_var = tk.BooleanVar(value=_saved_scan_perceptual)
        ttk.Checkbutton(
            content,
            text="Perceptual image comparison (slower but finds similar images)",
            variable=self.perceptual_var
        ).pack(anchor=tk.W, pady=5)

        # Action buttons
        action_frame = ttk.Frame(content)
        action_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(action_frame, text="Cancel", command=self.top.destroy).pack(side=tk.RIGHT, padx=(5, 0))
        scan_btn = ttk.Button(action_frame, text="▶  Start Scan", command=self._on_scan)
        scan_btn.pack(side=tk.RIGHT)

        # Enter key starts scan, Escape closes
        self.top.bind("<Return>", lambda e: self._on_scan())
        self.top.bind("<Escape>", lambda e: self.top.destroy())
        self.top.focus_set()

    def _add_folder(self) -> None:
        folder = filedialog.askdirectory()
        if folder:
            self.paths_text.insert(tk.END, folder + "\n")

    def _add_drive(self) -> None:
        if sys.platform == "win32":
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if mask & (1 << (ord(c) - ord("A"))):
                    self.paths_text.insert(tk.END, f"{c}:\\\n")
        else:
            # On Linux/macOS, add /home instead of / to avoid scanning system dirs
            home = str(Path.home())
            self.paths_text.insert(tk.END, home + "\n")

    def _on_scan(self) -> None:
        paths = [
            p.strip()
            for p in self.paths_text.get(1.0, tk.END).split("\n")
            if p.strip()
        ]

        exclusions = {
            e.strip()
            for e in self.excl_text.get(1.0, tk.END).split("\n")
            if e.strip()
        }

        if not paths:
            messagebox.showwarning("Warning", "Please add at least one location to scan.")
            return

        self.result = ScanOptions(
            paths=paths,
            exclusions=exclusions,
            perceptual=self.perceptual_var.get()
        )
        self.top.destroy()


class OptionsDialog:
    """Dialog for application options."""

    def __init__(self, parent: tk.Tk):
        self.top = tk.Toplevel(parent)
        self.top.title("Options")
        self.top.geometry("380x420")
        self.top.transient(parent)
        self.top.grab_set()
        self.top.configure(bg=BG_DARK)

        # Similarity threshold
        ttk.Label(self.top, text="Image Similarity Threshold:").pack(pady=10)
        ttk.Label(
            self.top,
            text="Maximum Hamming distance for similar images",
            font=("", 8), foreground="gray"
        ).pack()

        self.scale = ttk.Scale(
            self.top, from_=0, to=64, orient=tk.HORIZONTAL,
            command=self._on_scale_change
        )
        self.scale.set(_config.image_similarity_threshold)
        self.scale.pack(fill=tk.X, padx=20)

        self.threshold_label = ttk.Label(
            self.top, text=str(_config.image_similarity_threshold),
            font=("", 12, "bold")
        )
        self.threshold_label.pack()

        ttk.Label(
            self.top,
            text="Lower = stricter, Higher = more lenient",
            font=("", 8), foreground="gray"
        ).pack(pady=5)

        # Trash option
        self.trash_var = tk.BooleanVar(value=_config.use_trash)
        trash_text = "Use trash/recycle bin for deletions"
        if not HAS_SEND2TRASH:
            trash_text += " (send2trash not installed)"
        trash_cb = ttk.Checkbutton(
            self.top, text=trash_text, variable=self.trash_var
        )
        if not HAS_SEND2TRASH:
            trash_cb.config(state="disabled")
        trash_cb.pack(pady=5)

        # Skip empty files
        self.skip_empty_var = tk.BooleanVar(value=_config.skip_empty_files)
        ttk.Checkbutton(
            self.top, text="Skip empty (0-byte) files",
            variable=self.skip_empty_var
        ).pack(pady=5)

        # Worker threads
        ttk.Separator(self.top, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=5)
        ttk.Label(self.top, text="Worker Threads:").pack()
        ttk.Label(
            self.top,
            text="Parallel threads for hashing (higher = faster, more CPU/disk I/O)",
            font=("", 8), foreground="gray"
        ).pack()

        self.workers_scale = ttk.Scale(
            self.top, from_=1, to=max(16, (os.cpu_count() or 4)), orient=tk.HORIZONTAL,
            command=self._on_workers_change
        )
        self.workers_scale.set(_config.workers)
        self.workers_scale.pack(fill=tk.X, padx=20)

        self.workers_label = ttk.Label(
            self.top, text=str(_config.workers),
            font=("", 12, "bold")
        )
        self.workers_label.pack()

        ttk.Button(self.top, text="OK", command=self._on_ok).pack(pady=10)

    def _on_ok(self) -> None:
        _config.image_similarity_threshold = int(self.scale.get())
        _config.use_trash = self.trash_var.get()
        _config.skip_empty_files = self.skip_empty_var.get()
        _config.workers = max(1, int(self.workers_scale.get()))
        save_settings()
        self.top.destroy()

    def _on_scale_change(self, value: str) -> None:
        try:
            self.threshold_label.config(text=str(int(float(value))))
        except (ValueError, TypeError):
            pass

    def _on_workers_change(self, value: str) -> None:
        try:
            self.workers_label.config(text=str(max(1, int(float(value)))))
        except (ValueError, TypeError):
            pass


