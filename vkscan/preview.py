#!/usr/bin/env python3
"""VKScan preview and comparison windows."""

import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from PIL import Image, ImageTk

from .constants import (
    BG_DARK, BG_MEDIUM, BG_LIGHT, ACCENT, TEXT_PRIMARY,
    TEXT_SECONDARY, TEXT_MUTED, DANGER,
    IMAGE_EXTENSIONS, MAX_PREVIEW_SIZE, TEXT_PREVIEW_LINES,
)
from .utils import format_size, safe_delete

class PreviewWindow:
    """Window for previewing files with navigation and fit-to-window scaling."""

    # Color shortcuts
    BG = BG_DARK
    BG2 = BG_MEDIUM
    FG = TEXT_PRIMARY
    FG2 = TEXT_SECONDARY
    FG3 = TEXT_MUTED
    ACCENT = ACCENT

    def __init__(self, parent: tk.Tk, paths: List[str], on_delete: Optional[Callable] = None):
        self.top = tk.Toplevel(parent)
        self.top.title("Preview")
        self.top.geometry("800x600")
        self.top.minsize(500, 400)
        self.top.configure(bg=self.BG)

        self.paths = paths
        self.current_index = 0
        self._photo_ref = None  # Strong ref for current image
        self._pil_images: Dict[int, Image.Image] = {}  # Cache loaded PIL images
        self._on_delete = on_delete

        self._build_ui()
        self._show_current()

        # Keyboard navigation
        self.top.bind("<Left>", lambda e: self._navigate(-1))
        self.top.bind("<Right>", lambda e: self._navigate(1))
        self.top.bind("<Up>", lambda e: self._navigate(-1))
        self.top.bind("<Down>", lambda e: self._navigate(1))
        self.top.bind("<Escape>", lambda e: self._on_close())
        self.top.bind("<Delete>", lambda e: self._delete_current())

        # Resize re-renders the image to fit
        self.top.bind("<Configure>", self._on_resize)
        self._last_size = (0, 0)

        self.top.protocol("WM_DELETE_WINDOW", self._on_close)
        self.top.focus_set()

    def _build_ui(self) -> None:
        """Build the preview UI layout."""
        # Top: navigation bar
        nav_frame = tk.Frame(self.top, bg=self.BG2, bd=0)
        nav_frame.pack(fill=tk.X, side=tk.TOP)

        self._prev_btn = tk.Label(
            nav_frame, text="  ◀  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=self.FG, padx=8, pady=4
        )
        self._prev_btn.pack(side=tk.LEFT)
        self._prev_btn.bind("<Button-1>", lambda e: self._navigate(-1))
        self._prev_btn.bind("<Enter>", lambda e: self._prev_btn.config(bg=self.ACCENT, fg="#fff"))
        self._prev_btn.bind("<Leave>", lambda e: self._prev_btn.config(bg=self.BG2, fg=self.FG))

        self._counter_label = tk.Label(
            nav_frame, text="", font=("Segoe UI", 10),
            bg=self.BG2, fg=self.FG2
        )
        self._counter_label.pack(side=tk.LEFT, padx=10)

        self._next_btn = tk.Label(
            nav_frame, text="  ▶  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=self.FG, padx=8, pady=4
        )
        self._next_btn.pack(side=tk.LEFT)
        self._next_btn.bind("<Button-1>", lambda e: self._navigate(1))
        self._next_btn.bind("<Enter>", lambda e: self._next_btn.config(bg=self.ACCENT, fg="#fff"))
        self._next_btn.bind("<Leave>", lambda e: self._next_btn.config(bg=self.BG2, fg=self.FG))

        self._filename_label = tk.Label(
            nav_frame, text="", font=("Segoe UI", 10, "bold"),
            bg=self.BG2, fg=self.FG, anchor=tk.W
        )
        self._filename_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        self._trash_btn = tk.Label(
            nav_frame, text="  🗑  ", font=("Segoe UI", 14), cursor="hand2",
            bg=self.BG2, fg=DANGER, padx=8, pady=4
        )
        self._trash_btn.pack(side=tk.RIGHT)
        self._trash_btn.bind("<Button-1>", lambda e: self._delete_current())
        self._trash_btn.bind("<Enter>", lambda e: self._trash_btn.config(bg=DANGER, fg="#fff"))
        self._trash_btn.bind("<Leave>", lambda e: self._trash_btn.config(bg=self.BG2, fg=DANGER))

        # Bottom: metadata bar
        self._meta_label = tk.Label(
            self.top, text="", font=("Segoe UI", 9),
            bg=self.BG2, fg=self.FG3, anchor=tk.W, padx=8, pady=3
        )
        self._meta_label.pack(fill=tk.X, side=tk.BOTTOM)

        # Center: content area
        self._content_frame = tk.Frame(self.top, bg=self.BG, bd=0)
        self._content_frame.pack(fill=tk.BOTH, expand=True)

        # Image display label (centered)
        self._image_label = tk.Label(self._content_frame, bg=self.BG, bd=0)
        self._image_label.pack(fill=tk.BOTH, expand=True)

        # Text display (hidden by default, shown for text files)
        self._text_widget = None

    def _navigate(self, delta: int) -> None:
        """Move to the next/previous file."""
        new_index = self.current_index + delta
        if 0 <= new_index < len(self.paths):
            self.current_index = new_index
            self._show_current()

    def _show_current(self) -> None:
        """Display the current file."""
        if not self.paths:
            return

        path = self.paths[self.current_index]
        total = len(self.paths)
        name = Path(path).name

        # Update navigation
        self._counter_label.config(text=f"{self.current_index + 1} / {total}")
        self._filename_label.config(text=name)
        self.top.title(f"Preview — {name}")

        # Update navigation button states
        self._prev_btn.config(fg=self.FG if self.current_index > 0 else self.FG3)
        self._next_btn.config(fg=self.FG if self.current_index < total - 1 else self.FG3)

        # Build metadata
        meta = path
        try:
            stat = os.stat(path)
            size_str = format_size(stat.st_size)
            mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            meta = f"{path}   |   {size_str}   |   {mtime_str}"
            if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
                try:
                    with Image.open(path) as img:
                        meta += f"   |   {img.width}×{img.height}   |   {img.mode}"
                except Exception:
                    pass
        except OSError:
            pass
        self._meta_label.config(text=meta)

        # Clear previous content
        self._image_label.config(image="", text="")
        if self._text_widget:
            self._text_widget.destroy()
            self._text_widget = None
        self._photo_ref = None

        # Try image
        if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
            try:
                if self.current_index not in self._pil_images:
                    img = Image.open(path)
                    if img.mode not in ("RGB", "RGBA"):
                        img = img.convert("RGBA")
                    self._pil_images[self.current_index] = img
                self._render_image()
                return
            except Exception:
                pass

        # Try text
        try:
            self._text_widget = scrolledtext.ScrolledText(
                self._content_frame, wrap=tk.WORD,
                bg=BG_LIGHT, fg=self.FG,
                insertbackground=self.FG, font=("Consolas", 10),
                bd=0, relief="flat"
            )
            self._text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[:TEXT_PREVIEW_LINES]
                self._text_widget.insert(1.0, "".join(lines))
            self._text_widget.config(state=tk.DISABLED)
            return
        except Exception:
            pass

        self._image_label.config(text="[Binary file — cannot preview]", fg=self.FG3)

    def _render_image(self) -> None:
        """Render the current PIL image scaled to fill the content area."""
        pil_img = self._pil_images.get(self.current_index)
        if not pil_img:
            return

        # Get available space
        self._content_frame.update_idletasks()
        avail_w = max(self._content_frame.winfo_width() - 10, 100)
        avail_h = max(self._content_frame.winfo_height() - 10, 100)

        # Scale to fit (maintain aspect ratio, fill one axis)
        img_w, img_h = pil_img.size
        ratio = min(avail_w / img_w, avail_h / img_h)
        new_w = max(1, int(img_w * ratio))
        new_h = max(1, int(img_h * ratio))

        resized = pil_img.resize((new_w, new_h), Image.LANCZOS)
        self._photo_ref = ImageTk.PhotoImage(resized)
        resized.close()

        self._image_label.config(image=self._photo_ref)

    def _on_resize(self, event) -> None:
        """Re-render image when window is resized."""
        if event.widget != self.top:
            return
        new_size = (event.width, event.height)
        if new_size == self._last_size:
            return
        self._last_size = new_size

        # Only re-render if we're showing an image
        if self.current_index in self._pil_images and self._text_widget is None:
            # Debounce: cancel previous scheduled render, schedule new one
            if hasattr(self, '_resize_after_id'):
                self.top.after_cancel(self._resize_after_id)
            self._resize_after_id = self.top.after(50, self._render_image)

    def _delete_current(self) -> None:
        """Delete the currently displayed file."""
        if not self.paths:
            return
        path = self.paths[self.current_index]
        name = Path(path).name
        if not messagebox.askyesno("Confirm Delete", f"Delete '{name}'?", parent=self.top):
            return
        try:
            safe_delete(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {e}", parent=self.top)
            return
        # Remove from cached images
        if self.current_index in self._pil_images:
            try:
                self._pil_images[self.current_index].close()
            except Exception:
                pass
            del self._pil_images[self.current_index]
        deleted_path = self.paths.pop(self.current_index)
        # Rebuild image cache keys
        new_cache: Dict[int, Image.Image] = {}
        for k, v in self._pil_images.items():
            new_key = k if k < self.current_index else k - 1
            new_cache[new_key] = v
        self._pil_images = new_cache
        if not self.paths:
            self._on_close()
        else:
            if self.current_index >= len(self.paths):
                self.current_index = len(self.paths) - 1
            self._show_current()
        if self._on_delete:
            self._on_delete(deleted_path)

    def _on_close(self) -> None:
        """Cleanup on window close."""
        # Close cached PIL images
        for img in self._pil_images.values():
            try:
                img.close()
            except Exception:
                pass
        self._pil_images.clear()
        self._photo_ref = None
        self.top.destroy()


class ComparisonWindow:
    """Window for comparing two files side by side."""

    def __init__(self, parent: tk.Tk, paths: List[str], on_delete: Optional[Callable] = None):
        self.top = tk.Toplevel(parent)
        self.top.title("Compare")
        self.top.geometry("800x500")
        self.top.configure(bg=BG_DARK)
        self._image_refs: List[ImageTk.PhotoImage] = []
        self._on_delete = on_delete
        self._paths = paths

        if len(paths) < 2:
            self.top.destroy()
            return

        left = ttk.Frame(self.top)
        right = ttk.Frame(self.top)

        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self._add_panel(left, paths[0], "File A")
        self._add_panel(right, paths[1], "File B")

        # Delete buttons
        del_frame = ttk.Frame(self.top)
        del_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)
        ttk.Button(
            del_frame, text="Delete A", command=lambda: self._delete_file(0),
            style="Danger.TButton"
        ).pack(side=tk.LEFT, padx=10)
        ttk.Button(
            del_frame, text="Delete B", command=lambda: self._delete_file(1),
            style="Danger.TButton"
        ).pack(side=tk.RIGHT, padx=10)

        self.top.protocol("WM_DELETE_WINDOW", self._on_close)

    def _delete_file(self, index: int) -> None:
        """Delete file A (index=0) or file B (index=1)."""
        if index >= len(self._paths):
            return
        path = self._paths[index]
        name = Path(path).name
        label = "A" if index == 0 else "B"
        if not messagebox.askyesno("Confirm Delete", f"Delete File {label}: '{name}'?", parent=self.top):
            return
        try:
            safe_delete(path)
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {e}", parent=self.top)
            return
        self._on_close()
        if self._on_delete:
            self._on_delete(path)

    def _on_close(self) -> None:
        self._image_refs.clear()
        self.top.destroy()

    def _add_panel(self, parent: tk.Frame, path: str, title: str) -> None:
        ttk.Label(
            parent, text=f"{title}: {Path(path).name}",
            font=("", 10, "bold")
        ).pack(anchor=tk.W)

        ttk.Label(parent, text=path, wraplength=350, foreground=TEXT_SECONDARY).pack(anchor=tk.W, pady=2)

        # Compact metadata
        try:
            stat = os.stat(path)
            size_str = format_size(stat.st_size)
            mtime_str = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            meta = f"{size_str} | {mtime_str}"
            if Path(path).suffix.lower() in IMAGE_EXTENSIONS:
                try:
                    with Image.open(path) as img:
                        meta += f" | {img.width}×{img.height}"
                except Exception:
                    pass
            ttk.Label(parent, text=meta, foreground=TEXT_MUTED, font=("", 8)).pack(anchor=tk.W)
        except OSError:
            pass

        content = ttk.Frame(parent)
        content.pack(fill=tk.BOTH, expand=True)

        try:
            with Image.open(path) as img:
                if img.width > MAX_PREVIEW_SIZE or img.height > MAX_PREVIEW_SIZE:
                    ratio = min(MAX_PREVIEW_SIZE / img.width, MAX_PREVIEW_SIZE / img.height)
                    resized = img.resize(
                        (int(img.width * ratio), int(img.height * ratio))
                    )
                else:
                    resized = img.copy()

            photo = ImageTk.PhotoImage(resized)
            resized.close()
            self._image_refs.append(photo)
            ttk.Label(content, image=photo).pack(fill=tk.BOTH, expand=True)
            return
        except Exception:
            pass

        try:
            txt = scrolledtext.ScrolledText(
                content, wrap=tk.WORD,
                bg=BG_LIGHT, fg=TEXT_PRIMARY,
                insertbackground=TEXT_PRIMARY)
            txt.pack(fill=tk.BOTH, expand=True)
            with open(path, "r", errors="replace") as f:
                lines = f.readlines()[:TEXT_PREVIEW_LINES]
                txt.insert(1.0, "".join(lines))
            return
        except Exception:
            pass

        ttk.Label(content, text="[Binary]").pack()


