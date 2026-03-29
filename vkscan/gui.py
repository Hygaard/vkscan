#!/usr/bin/env python3
"""VKScan main GUI application."""

import os
import sys
import threading
import queue
import time
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from PIL import Image, ImageTk

from .constants import (
    VERSION, BG_DARK, BG_MEDIUM, BG_LIGHT, ACCENT, ACCENT_HOVER,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED, SUCCESS, WARNING, DANGER,
    BORDER, ROW_ODD, ROW_EVEN, GROUP_HEADER, SELECTION,
    IMAGE_EXTENSIONS, DEFAULT_WINDOW_SIZE, MIN_WINDOW_SIZE,
    DEFAULT_EXCLUSIONS, MAX_PREVIEW_SIZE, TEXT_PREVIEW_LINES,
)
from .config import (
    _config, save_settings, load_settings,
    _saved_scan_paths, _saved_scan_exclusions, _saved_scan_perceptual,
)
from .models import FileInfo, DuplicateGroup, ScanOptions
from .utils import format_size, safe_delete, HAS_SEND2TRASH
from .scanner import DuplicateScanner
from .export import export_txt, export_csv
from .dialogs import ScanDialog, OptionsDialog
from .preview import PreviewWindow, ComparisonWindow

class DuplicateFinderApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        """Initialize the application."""
        self.root = root
        self.root.title(f"VKScan v{VERSION}")
        self.root.geometry("x".join(map(str, DEFAULT_WINDOW_SIZE)))
        self.root.minsize(*MIN_WINDOW_SIZE)

        # Set application icon
        self._set_app_icon(self.root)

        self.duplicate_groups: List[DuplicateGroup] = []
        self.scanner: Optional[DuplicateScanner] = None
        self.scan_thread: Optional[threading.Thread] = None
        self._populating = False  # Guard flag for tree population
        self._active_dropdown = None  # Currently open dropdown menu
        self._is_scanning = False  # True while scan is running
        self._last_scan_options: Optional[ScanOptions] = None
        self._stage_start_time: Optional[float] = None
        self._current_stage_key: str = ""
        self._detached_items: Dict[str, tuple] = {}  # Filter: item_id -> (parent, index)

        load_settings()

        self._setup_styles()
        self._apply_dark_titlebar(self.root)
        self._create_menu()
        self._create_main_ui()

        # Keyboard shortcuts
        self.root.bind("<Delete>", lambda e: self._delete_selected())
        self.root.bind("<Control-c>", lambda e: self._cancel_scan())
        self.root.bind("<Control-a>", lambda e: self._select_all())
        self.root.bind("<Control-e>", lambda e: self._export_report())
        self.root.bind("<Control-o>", lambda e: self._open_file_location())
        self.root.bind("<Escape>", lambda e: self._deselect_all())
        self.root.bind("<Control-f>", lambda e: self._focus_filter_search())


    def _setup_styles(self) -> None:
        """Configure ttk styles with modern dark theme."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.root.configure(bg=BG_DARK)

        # TFrame
        style.configure("TFrame", background=BG_DARK)

        # TLabel
        style.configure("TLabel", background=BG_DARK, foreground=TEXT_PRIMARY,
                         font=("Segoe UI", 10))

        # TButton (accent)
        style.configure("TButton", background=ACCENT, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("TButton",
                   background=[("active", ACCENT_HOVER), ("disabled", BG_LIGHT)],
                   foreground=[("disabled", TEXT_MUTED)])

        # Accent.TButton
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10, "bold"), padding=(12, 5))
        style.map("Accent.TButton",
                   background=[("active", ACCENT_HOVER), ("disabled", BG_LIGHT)])

        # Danger.TButton
        style.configure("Danger.TButton", background=DANGER, foreground="#ffffff",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("Danger.TButton",
                   background=[("active", "#dc2626"), ("disabled", BG_LIGHT)])

        # Warning.TButton
        style.configure("Warning.TButton", background=WARNING, foreground="#1e1e2e",
                         borderwidth=0, font=("Segoe UI", 10), padding=(10, 4))
        style.map("Warning.TButton",
                   background=[("active", "#d97706"), ("disabled", BG_LIGHT)])

        # Treeview
        style.configure("Treeview", background=BG_LIGHT, foreground=TEXT_PRIMARY,
                         fieldbackground=BG_LIGHT, rowheight=28,
                         font=("Segoe UI", 10), borderwidth=0)
        style.map("Treeview",
                   background=[("selected", SELECTION)],
                   foreground=[("selected", "#ffffff")])

        # Treeview.Heading
        style.configure("Treeview.Heading", background=BG_MEDIUM,
                         foreground=TEXT_PRIMARY,
                         font=("Segoe UI", 10, "bold"), borderwidth=1,
                         relief="flat")
        style.map("Treeview.Heading",
                   background=[("active", BG_LIGHT)])

        # Progressbar
        style.configure("TProgressbar", background=ACCENT,
                         troughcolor=BG_LIGHT, borderwidth=0, thickness=8)
        style.configure("Horizontal.TProgressbar", background=ACCENT,
                         troughcolor=BG_LIGHT, borderwidth=0, thickness=8)

        # TCheckbutton
        style.configure("TCheckbutton", background=BG_DARK,
                         foreground=TEXT_PRIMARY, font=("Segoe UI", 10))
        style.map("TCheckbutton",
                   background=[("active", BG_MEDIUM)])

        # TScale
        style.configure("TScale", background=BG_DARK,
                         troughcolor=BG_LIGHT)

        # TNotebook
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_MEDIUM,
                         foreground=TEXT_PRIMARY, padding=(10, 4),
                         font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                   background=[("selected", ACCENT), ("active", BG_LIGHT)],
                   foreground=[("selected", "#ffffff")])

        # TSeparator
        style.configure("TSeparator", background=BORDER)

        # Stage label style (bold)
        style.configure("Stage.TLabel", background=BG_DARK,
                         foreground=TEXT_PRIMARY,
                         font=("Segoe UI", 11, "bold"))

        # Detail label style (muted)
        style.configure("Detail.TLabel", background=BG_DARK,
                         foreground=TEXT_SECONDARY,
                         font=("Segoe UI", 9))

        # Overall label style (small muted)
        style.configure("Overall.TLabel", background=BG_DARK,
                         foreground=TEXT_MUTED,
                         font=("Segoe UI", 8))

        # Status bar style
        style.configure("Status.TLabel", background=BG_MEDIUM,
                         foreground=TEXT_SECONDARY,
                         font=("Segoe UI", 9), padding=(6, 3))

    @staticmethod
    def _apply_dark_titlebar(window) -> None:
        """Apply dark title bar on Windows 10/11 using DWM API.

        Uses DWMWA_USE_IMMERSIVE_DARK_MODE (attribute 20) to tell Windows
        to render the title bar in dark mode. No-op on Linux/macOS.
        """
        if sys.platform != "win32":
            return
        try:
            import ctypes
            window.update()  # Ensure the window has a valid HWND
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            value = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)
            )
        except Exception:
            pass

    def _get_resource_path(self, filename: str) -> Path:
        """Get path to a bundled resource file.

        Works both when running from source and from a PyInstaller .exe.
        PyInstaller extracts bundled data files to sys._MEIPASS.
        """
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            return Path(sys._MEIPASS) / filename
        return Path(__file__).parent / filename

    def _set_app_icon(self, window) -> None:
        """Set the application icon on a window.

        Uses iconbitmap for .ico (sets both titlebar and taskbar icon on Windows).
        Falls back to iconphoto with .png (cross-platform).
        Stores the PhotoImage on the instance to prevent garbage collection.
        """
        try:
            ico_path = self._get_resource_path("vkscan_icon.ico")
            if ico_path.exists():
                window.iconbitmap(str(ico_path))
                return
        except Exception:
            pass

        try:
            png_path = self._get_resource_path("vkscan_icon.png")
            if png_path.exists():
                if not hasattr(self, '_icon_photo'):
                    self._icon_photo = tk.PhotoImage(file=str(png_path))
                window.iconphoto(True, self._icon_photo)
        except Exception:
            pass

    def _center_dialog(self, dialog: tk.Toplevel, width: int, height: int) -> None:
        """Position a dialog centered over the main window."""
        self.root.update_idletasks()
        root_x = self.root.winfo_x()
        root_y = self.root.winfo_y()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        x = root_x + (root_w - width) // 2
        y = root_y + (root_h - height) // 2
        # Ensure it stays on screen
        x = max(0, x)
        y = max(0, y)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

    def _create_menu(self) -> None:
        """Create a fully custom dark menu bar with pure tkinter widgets.

        Both tk.Menu (native) and tk.Menubutton (uses tk.Menu internally)
        are rendered by the OS on Windows, ignoring colors and always
        drawing system borders. This implementation uses tk.Toplevel
        popups with tk.Label items — zero native menu widgets.
        """
        # Remove native menubar
        self.root.config(menu="")

        # Custom menu bar frame
        self._menubar = tk.Frame(self.root, bg=BG_DARK, bd=0)
        self._menubar.pack(side=tk.TOP, fill=tk.X)

        # Thin separator line under the menu bar
        tk.Frame(self.root, bg=BORDER, height=1).pack(side=tk.TOP, fill=tk.X)

        # Define menus: (label, [(item_label, command, shortcut), ...])
        # Use None for separator
        menus = [
            ("File", [
                ("Scan...", self._start_scan_dialog, ""),
                ("Export Report", self._export_report, "Ctrl+E"),
                None,
                ("Exit", self.root.quit, ""),
            ]),
            ("Edit", [
                ("Select All", self._select_all, "Ctrl+A"),
                ("Deselect All", self._deselect_all, "Esc"),
                ("Auto-Select Duplicates", self._auto_select_duplicates, ""),
                None,
                ("Delete Selected", self._delete_selected, "Del"),
                ("Move Selected", self._move_selected, ""),
            ]),
            ("View", [
                ("Preview", self._show_preview, ""),
                ("Compare", self._compare_selected, ""),
                ("Open File Location", self._open_file_location, "Ctrl+O"),
            ]),
            ("Help", [
                ("About", self._show_about, ""),
            ]),
        ]

        for menu_label, items in menus:
            btn = tk.Label(
                self._menubar, text=f"  {menu_label}  ",
                bg=BG_DARK, fg=TEXT_PRIMARY,
                font=("Segoe UI", 10), cursor="hand2", padx=4, pady=4
            )
            btn.pack(side=tk.LEFT)
            btn.bind("<Button-1>", lambda e, b=btn, it=items: self._toggle_dropdown(b, it))
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg=BG_LIGHT))
            btn.bind("<Leave>", lambda e, b=btn: self._menu_btn_leave(b))

        # Close dropdown when clicking elsewhere
        self.root.bind("<Button-1>", self._maybe_close_dropdown, add="+")

    def _menu_btn_leave(self, btn) -> None:
        """Reset menu button bg, unless its dropdown is currently open."""
        if self._active_dropdown and self._active_dropdown[0] == btn:
            return  # Keep highlighted while dropdown is open
        btn.config(bg=BG_DARK)

    def _toggle_dropdown(self, btn, items) -> None:
        """Open or close a dropdown menu panel."""
        # If this dropdown is already open, close it
        if self._active_dropdown and self._active_dropdown[0] == btn:
            self._close_dropdown()
            return

        # Close any other open dropdown first
        self._close_dropdown()

        # Calculate position below the button
        btn.update_idletasks()
        x = btn.winfo_rootx()
        y = btn.winfo_rooty() + btn.winfo_height()

        # Create dropdown as an undecorated Toplevel
        dropdown = tk.Toplevel(self.root)
        dropdown.overrideredirect(True)  # No title bar, no OS borders
        dropdown.configure(bg=BORDER)  # Thin border color
        dropdown.attributes("-topmost", True)

        # Inner frame for content (1px padding = border effect)
        inner = tk.Frame(dropdown, bg=BG_DARK, bd=0)
        inner.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)

        # Build menu items
        for item in items:
            if item is None:
                # Separator
                tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=8, pady=3)
                continue

            label_text, command, shortcut = item
            row = tk.Frame(inner, bg=BG_DARK, cursor="hand2")
            row.pack(fill=tk.X)

            lbl = tk.Label(
                row, text=f"  {label_text}", anchor=tk.W,
                bg=BG_DARK, fg=TEXT_PRIMARY,
                font=("Segoe UI", 10), padx=8, pady=5
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

            if shortcut:
                shortcut_lbl = tk.Label(
                    row, text=f"{shortcut}  ", anchor=tk.E,
                    bg=BG_DARK, fg=TEXT_MUTED,
                    font=("Segoe UI", 9), padx=8, pady=5
                )
                shortcut_lbl.pack(side=tk.RIGHT)
                # Hover effect for shortcut label too
                for widget in (row, lbl, shortcut_lbl):
                    widget.bind("<Enter>", lambda e, r=row, l=lbl, s=shortcut_lbl: (
                        r.config(bg=ACCENT), l.config(bg=ACCENT, fg="#ffffff"),
                        s.config(bg=ACCENT, fg="#ffffff")
                    ))
                    widget.bind("<Leave>", lambda e, r=row, l=lbl, s=shortcut_lbl: (
                        r.config(bg=BG_DARK), l.config(bg=BG_DARK, fg=TEXT_PRIMARY),
                        s.config(bg=BG_DARK, fg=TEXT_MUTED)
                    ))
                    widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))
            else:
                for widget in (row, lbl):
                    widget.bind("<Enter>", lambda e, r=row, l=lbl: (
                        r.config(bg=ACCENT), l.config(bg=ACCENT, fg="#ffffff")
                    ))
                    widget.bind("<Leave>", lambda e, r=row, l=lbl: (
                        r.config(bg=BG_DARK), l.config(bg=BG_DARK, fg=TEXT_PRIMARY)
                    ))
                    widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))

        dropdown.geometry(f"+{x}+{y}")
        btn.config(bg=BG_LIGHT)
        self._active_dropdown = (btn, dropdown)

    def _dropdown_click(self, command) -> None:
        """Handle click on a dropdown menu item."""
        self._close_dropdown()
        self.root.after(10, command)  # Small delay so dropdown closes visually first

    def _close_dropdown(self) -> None:
        """Close the currently open dropdown."""
        if self._active_dropdown:
            btn, dropdown = self._active_dropdown
            btn.config(bg=BG_DARK)
            dropdown.destroy()
            self._active_dropdown = None

    def _maybe_close_dropdown(self, event) -> None:
        """Close dropdown if click is outside the menu bar and dropdown."""
        if not self._active_dropdown:
            return
        # Check if click is on the menubar or dropdown
        widget = event.widget
        btn, dropdown = self._active_dropdown
        try:
            if widget == dropdown or str(widget).startswith(str(dropdown)):
                return
            if widget == self._menubar or widget.master == self._menubar:
                return
        except Exception:
            pass
        self._close_dropdown()

    def _create_main_ui(self) -> None:
        """Create main user interface."""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_control_panel(main_frame)
        self._create_filter_bar(main_frame)

        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("path", "size", "modified", "similarity"),
            show="tree headings",
            selectmode="extended",
            yscrollcommand=y_scroll.set
        )

        self.tree.heading("#0", text="Files")
        self.tree.heading("path", text="Path")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Modified")
        self.tree.heading("similarity", text="Similarity")

        self.tree.column("#0", width=300)
        self.tree.column("path", width=300)
        self.tree.column("size", width=80)
        self.tree.column("modified", width=140)
        self.tree.column("similarity", width=80)

        # Sortable column headers
        for col in ("path", "size", "modified", "similarity"):
            self.tree.heading(col, command=lambda c=col: self._sort_column(c, False))

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        y_scroll.config(command=self.tree.yview)

        # Double-click on treeview to preview all files in the group
        def _on_double_click(event):
            region = self.tree.identify_region(event.x, event.y)
            if region in ("cell", "tree"):
                item = self.tree.identify_row(event.y)
                if item:
                    self._preview_item_or_group(item)
        self.tree.bind("<Double-Button-1>", _on_double_click)

        # Right-click context menu (custom dark, same as main menu dropdowns)
        self._context_items = [
            ("Preview", self._show_preview, ""),
            ("Open File Location", self._open_file_location, ""),
            None,
            ("Compare Selected", self._compare_selected, ""),
            None,
            ("Delete Selected", self._delete_selected, ""),
            ("Move Selected", self._move_selected, ""),
        ]
        self.tree.bind("<Button-3>", self._show_context_menu)  # Windows/Linux
        self.tree.bind("<Button-2>", self._show_context_menu)  # macOS

        # Alternating row colors for readability (dark theme)
        self.tree.tag_configure("odd_row", background=ROW_ODD, foreground=TEXT_PRIMARY)
        self.tree.tag_configure("even_row", background=ROW_EVEN, foreground=TEXT_PRIMARY)
        self.tree.tag_configure("group_header", background=GROUP_HEADER,
                                foreground=TEXT_PRIMARY, font=("Segoe UI", 10, "bold"))

        # Update status bar when selection changes
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._update_selection_status())

        self._create_status_bar(main_frame)

    def _create_control_panel(self, parent: tk.Frame) -> None:
        """Create control panel with buttons and progress display."""
        # Button row
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(
            btn_frame, text="▶ Scan", command=self._start_scan_dialog,
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Options", command=self._show_options
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Compare", command=self._compare_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Delete", command=self._delete_selected,
            style="Danger.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Move", command=self._move_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            btn_frame, text="Auto-Select",
            command=self._auto_select_duplicates
        ).pack(side=tk.LEFT, padx=5)

        self.cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_scan,
            state="disabled", style="Warning.TButton"
        )
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        self.rescan_btn = ttk.Button(
            btn_frame, text="\u27f3 Rescan", command=self._rescan,
            state="disabled"
        )
        self.rescan_btn.pack(side=tk.LEFT, padx=5)

        # Progress area
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, pady=(0, 5))

        # Stage label (bold, prominent)
        self.stage_label = ttk.Label(progress_frame, text="Ready",
                                      style="Stage.TLabel")
        self.stage_label.pack(anchor=tk.W)

        # Per-stage progress bar
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(
            progress_frame, variable=self.progress_var, maximum=100,
            mode="determinate", length=400
        ).pack(fill=tk.X, pady=(3, 2))

        # Bottom row: detail on left, overall on right
        detail_row = ttk.Frame(progress_frame)
        detail_row.pack(fill=tk.X)

        self.detail_label = ttk.Label(detail_row, text="",
                                       style="Detail.TLabel")
        self.detail_label.pack(side=tk.LEFT)

        self.overall_label = ttk.Label(detail_row, text="",
                                        style="Overall.TLabel")
        self.overall_label.pack(side=tk.RIGHT)

        # Keep progress_label as a hidden reference for compatibility
        self.progress_label = self.stage_label


    def _create_filter_bar(self, parent: tk.Frame) -> None:
        """Create filter bar for filtering scan results."""
        filter_frame = tk.Frame(parent, bg=BG_MEDIUM, bd=0)
        filter_frame.pack(fill=tk.X, pady=(5, 0))

        inner = tk.Frame(filter_frame, bg=BG_MEDIUM, bd=0)
        inner.pack(fill=tk.X, padx=8, pady=4)

        tk.Label(inner, text="🔍", bg=BG_MEDIUM, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 10)).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_search_var = tk.StringVar()
        self._filter_search_var.trace_add("write", lambda *_: self._apply_filters())
        search_entry = tk.Entry(
            inner, textvariable=self._filter_search_var, width=25,
            bg=BG_LIGHT, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY,
            relief="flat", font=("Segoe UI", 10), bd=0,
            highlightthickness=1, highlightcolor=ACCENT, highlightbackground=BORDER
        )
        search_entry.pack(side=tk.LEFT, padx=(0, 10), ipady=2)
        self._filter_search_entry = search_entry

        tk.Label(inner, text="Type:", bg=BG_MEDIUM, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_type_var = tk.StringVar(value="All")
        for label in ("All", "Exact", "Similar"):
            rb = tk.Radiobutton(
                inner, text=label, variable=self._filter_type_var, value=label,
                bg=BG_MEDIUM, fg=TEXT_PRIMARY, selectcolor=BG_LIGHT,
                activebackground=BG_MEDIUM, activeforeground=TEXT_PRIMARY,
                font=("Segoe UI", 9), bd=0, highlightthickness=0,
                command=self._apply_filters
            )
            rb.pack(side=tk.LEFT, padx=2)

        tk.Frame(inner, bg=BORDER, width=1).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=2)

        tk.Label(inner, text="Min size:", bg=BG_MEDIUM, fg=TEXT_SECONDARY,
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 4))

        self._filter_size_var = tk.StringVar(value="Any")
        size_options = ["Any", "1 KB", "100 KB", "1 MB", "10 MB", "100 MB", "1 GB"]
        size_menu = tk.OptionMenu(inner, self._filter_size_var, *size_options,
                                  command=lambda _: self._apply_filters())
        size_menu.config(bg=BG_LIGHT, fg=TEXT_PRIMARY, activebackground=ACCENT,
                        activeforeground="#ffffff", highlightthickness=0, bd=0,
                        font=("Segoe UI", 9), relief="flat")
        size_menu["menu"].config(bg=BG_LIGHT, fg=TEXT_PRIMARY, activebackground=ACCENT,
                                activeforeground="#ffffff", font=("Segoe UI", 9), bd=0)
        size_menu.pack(side=tk.LEFT, padx=(0, 10))

        clear_btn = tk.Label(inner, text="✕ Clear", bg=BG_MEDIUM, fg=TEXT_MUTED,
                            font=("Segoe UI", 9), cursor="hand2", padx=4)
        clear_btn.pack(side=tk.LEFT, padx=(0, 4))
        clear_btn.bind("<Button-1>", lambda e: self._clear_filters())
        clear_btn.bind("<Enter>", lambda e: clear_btn.config(fg=TEXT_PRIMARY))
        clear_btn.bind("<Leave>", lambda e: clear_btn.config(fg=TEXT_MUTED))

        self._filter_count_label = tk.Label(inner, text="", bg=BG_MEDIUM, fg=TEXT_MUTED,
                                            font=("Segoe UI", 9))
        self._filter_count_label.pack(side=tk.RIGHT)

    def _focus_filter_search(self) -> None:
        """Focus the filter search entry (Ctrl+F)."""
        try:
            self._filter_search_entry.focus_set()
            self._filter_search_entry.select_range(0, tk.END)
        except (tk.TclError, AttributeError):
            pass

    def _clear_filters(self) -> None:
        """Reset all filters to defaults."""
        self._filter_search_var.set("")
        self._filter_type_var.set("All")
        self._filter_size_var.set("Any")
        self._apply_filters()

    def _parse_min_size_bytes(self) -> int:
        """Parse the min size dropdown value to bytes."""
        SIZE_MAP = {"Any": 0, "1 KB": 1024, "100 KB": 102400,
                    "1 MB": 1048576, "10 MB": 10485760,
                    "100 MB": 104857600, "1 GB": 1073741824}
        return SIZE_MAP.get(self._filter_size_var.get(), 0)

    def _apply_filters(self) -> None:
        """Apply all active filters to the treeview using detach/reattach."""
        if self._is_scanning or self._populating:
            return

        search_text = self._filter_search_var.get().lower().strip()
        type_filter = self._filter_type_var.get()
        min_size = self._parse_min_size_bytes()
        SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

        for item_id, (parent, idx) in list(self._detached_items.items()):
            try:
                self.tree.reattach(item_id, parent, idx)
            except tk.TclError:
                pass
        self._detached_items.clear()

        visible_groups = 0
        total_groups = 0

        for group_id in list(self.tree.get_children()):
            total_groups += 1
            header = self.tree.item(group_id, "text")
            children = list(self.tree.get_children(group_id))

            if type_filter == "Exact" and "(similar)" in header:
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
                continue
            elif type_filter == "Similar" and "(similar)" not in header:
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
                continue

            visible_children = 0
            for child_id in children:
                values = self.tree.item(child_id, "values")
                if not values:
                    continue
                path = values[0].lower() if values[0] else ""
                filename = Path(path).name if path else ""
                size_bytes = 0
                try:
                    parts = values[1].split()
                    size_bytes = int(float(parts[0]) * SIZE_MULT.get(parts[1] if len(parts) > 1 else "B", 1))
                except (ValueError, IndexError):
                    pass
                match = True
                if search_text and search_text not in path and search_text not in filename:
                    match = False
                if min_size > 0 and size_bytes < min_size:
                    match = False
                if not match:
                    idx = self.tree.index(child_id)
                    self._detached_items[child_id] = (group_id, idx)
                    self.tree.detach(child_id)
                else:
                    visible_children += 1

            remaining = list(self.tree.get_children(group_id))
            if not remaining:
                idx = self.tree.index(group_id)
                self._detached_items[group_id] = ("", idx)
                self.tree.detach(group_id)
            else:
                visible_groups += 1

        is_filtered = bool(search_text or type_filter != "All" or min_size > 0)
        if is_filtered:
            self._filter_count_label.config(text=f"Showing {visible_groups} / {total_groups} groups")
        else:
            self._filter_count_label.config(text="")

    def _create_status_bar(self, parent: tk.Frame) -> None:
        """Create status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        trash_status = ""
        if HAS_SEND2TRASH and _config.use_trash:
            trash_status = " | 🗑️ Trash enabled"
        else:
            trash_status = " | ⚠️ Permanent delete (install send2trash for trash support)"

        self.status_label = ttk.Label(
            status_frame,
            text=f"Click Scan to begin.{trash_status}",
            style="Status.TLabel", anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)

    def _update_selection_status(self) -> None:
        """Update status bar to reflect current treeview selection."""
        if self._is_scanning or self._populating:
            return

        selected = self.tree.selection()
        paths = [self.tree.item(item, "values")[0]
                 for item in selected
                 if self.tree.item(item, "values")]
        count = len(paths)

        if count == 0:
            # No selection — show scan summary if we have results
            if self.duplicate_groups:
                total_recoverable = sum(g.recoverable_size() for g in self.duplicate_groups)
                total_files = sum(len(g.files) for g in self.duplicate_groups)
                self.status_label.config(
                    text=(
                        f"{len(self.duplicate_groups)} group(s), "
                        f"{total_files} files | "
                        f"Recoverable: {format_size(total_recoverable)}"
                    )
                )
            else:
                self.status_label.config(text="Click Scan to begin.")
        elif count == 1:
            self.status_label.config(text=f"Selected: {paths[0]}")
        else:
            total_size = 0
            for p in paths:
                try:
                    total_size += os.path.getsize(p)
                except OSError:
                    pass
            self.status_label.config(
                text=f"{count} files selected ({format_size(total_size)})"
            )

    def _cancel_scan(self) -> None:
        """Cancel the current scan operation."""
        if self.scanner:
            self.scanner.cancelled = True
            self.progress_label.config(text="Cancelling...")

    def _start_scan_dialog(self) -> None:
        """Open scan dialog."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Busy", "Please wait or cancel current scan.")
            return

        dialog = ScanDialog(self.root)
        self._center_dialog(dialog.top, 550, 420)
        self._apply_dark_titlebar(dialog.top)
        self.root.wait_window(dialog.top)

        if dialog.result:
            self._perform_scan(dialog.result)

    def _rescan(self) -> None:
        if self._last_scan_options is None:
            return
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Busy", "Please wait or cancel current scan.")
            return
        self._perform_scan(self._last_scan_options)

    def _perform_scan(self, options: ScanOptions) -> None:
        """Perform the actual scan operation."""
        self._last_scan_options = options
        self._stage_start_time = None
        self._current_stage_key = ""
        save_settings(scan_paths=options.paths, scan_exclusions=list(options.exclusions), scan_perceptual=options.perceptual)
        self.cancel_btn.config(state="normal")
        self.progress_var.set(0)
        self.progress_label.config(text="Scanning...")
        self._scan_start_time = time.monotonic()
        self._is_scanning = True
        self._dim_column_headers(True)

        # Queue-based progress: scan thread writes here, GUI polls it
        self._progress_queue: queue.Queue = queue.Queue()
        self._scan_finished = False
        self._live_group_count = 0  # Track groups added during scan

        # Clear tree for fresh scan
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scanner = DuplicateScanner(progress_callback=self._enqueue_progress)

        def group_callback(group: DuplicateGroup) -> None:
            """Called from scanner when a new duplicate group is found."""
            self._progress_queue.put(("_group", 0, group))

        def scan_task() -> None:
            try:
                files = self.scanner.collect_files(options.paths, options.exclusions)

                if not self.scanner.cancelled:
                    self.duplicate_groups = self.scanner.find_duplicates(
                        files, options.perceptual,
                        group_callback=group_callback
                    )

                    if not self.scanner.cancelled:
                        self._progress_queue.put(("_done", 0, ""))
                    else:
                        self._progress_queue.put(("_cancelled", 0, ""))
            except Exception as e:
                self._progress_queue.put(("_error", 0, str(e)))
            finally:
                self._scan_finished = True

        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()

        # Start the GUI poll loop
        self._poll_progress()

    def _enqueue_progress(self, percent: int, message: str) -> None:
        """Called from scan thread — puts progress onto the queue (never touches tkinter)."""
        try:
            self._progress_queue.put(("progress", int(percent), str(message)))
        except Exception:
            pass

    # Max groups to insert into the treeview per poll cycle.
    # Higher = more responsive results, but each insert does tree ops.
    # 5 keeps each poll under ~10ms even with large groups.
    _MAX_GROUPS_PER_POLL = 5

    def _poll_progress(self) -> None:
        """Main-thread poll loop: drains the queue and updates the GUI.

        Runs every 50ms via root.after(), giving tkinter plenty of time
        to process mouse clicks, window drags, and button presses between polls.
        Group insertions are capped per cycle to prevent "Not Responding".
        """
        try:
            # Drain all pending messages (but only apply the latest progress)
            latest_percent = None
            latest_message = None
            groups_added = 0

            while True:
                try:
                    msg_type, percent, message = self._progress_queue.get_nowait()
                except queue.Empty:
                    break

                if msg_type == "progress":
                    latest_percent = percent
                    latest_message = message
                elif msg_type == "_group":
                    if groups_added < self._MAX_GROUPS_PER_POLL:
                        group = message  # message is actually a DuplicateGroup
                        self._add_group_to_tree(group)
                        groups_added += 1
                    else:
                        # Put it back for the next poll cycle
                        self._progress_queue.put((msg_type, percent, message))
                        break  # Stop draining — let the event loop breathe
                elif msg_type == "_done":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    # Final re-sort and status update (groups already in tree)
                    self._finalize_tree()
                    self.cancel_btn.config(state="disabled")
                    self.rescan_btn.config(state="normal")
                    self.stage_label.config(text="Scan Complete")
                    self.detail_label.config(text="")
                    self.overall_label.config(text="")
                    return  # Stop polling
                elif msg_type == "_cancelled":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    self.stage_label.config(text="Cancelled")
                    self.detail_label.config(text="")
                    self.overall_label.config(text="")
                    self.cancel_btn.config(state="disabled")
                    self.root.after(2000, lambda: self.progress_var.set(0))
                    return  # Stop polling
                elif msg_type == "_error":
                    self._is_scanning = False
                    self._dim_column_headers(False)
                    messagebox.showerror("Error", message)
                    self.cancel_btn.config(state="disabled")
                    return  # Stop polling

            # Apply latest progress update (skip intermediate ones)
            if latest_message is not None:
                # Parse STAGE format: "STAGE:N/M:StageName|percent|detail"
                if latest_message.startswith("STAGE:"):
                    try:
                        header, stage_pct_str, detail = latest_message[6:].split("|", 2)
                        stage_num_str, stage_name = header.split(":", 1)
                        stage_pct = int(stage_pct_str)
                        # ETA computation
                        if stage_num_str != self._current_stage_key:
                            self._current_stage_key = stage_num_str
                            self._stage_start_time = time.monotonic()
                        if stage_pct > 5 and self._stage_start_time is not None:
                            elapsed = time.monotonic() - self._stage_start_time
                            if elapsed >= 2.0:
                                eta_seconds = elapsed / stage_pct * (100 - stage_pct)
                                if eta_seconds < 60:
                                    eta_str = f"{int(eta_seconds)}s"
                                elif eta_seconds < 3600:
                                    eta_str = f"{int(eta_seconds // 60)}m {int(eta_seconds % 60)}s"
                                else:
                                    eta_str = f"{int(eta_seconds // 3600)}h {int((eta_seconds % 3600) // 60)}m"
                                detail = f"{detail}  (ETA: ~{eta_str})"
                        self.stage_label.config(text=f"Stage {stage_num_str}: {stage_name}")
                        self.progress_var.set(stage_pct)
                        self.detail_label.config(text=detail)
                        self.overall_label.config(text=f"Stage {stage_num_str}")
                    except (ValueError, IndexError):
                        # Fallback if parsing fails
                        self.stage_label.config(text=latest_message)
                        if latest_percent is not None:
                            self.progress_var.set(latest_percent)
                else:
                    self.stage_label.config(text=latest_message)
                    self.detail_label.config(text="")
                    if latest_percent is not None:
                        self.progress_var.set(latest_percent)
            elif latest_percent is not None:
                self.progress_var.set(latest_percent)

        except Exception:
            pass

        # Schedule next poll in 50ms — keeps the GUI responsive
        self.root.after(50, self._poll_progress)

    def _add_group_to_tree(self, group: DuplicateGroup) -> None:
        """Add a single duplicate group to the treeview during scanning.

        Appends to the end for speed — sorting happens after the scan
        completes via _finalize_tree or user-triggered column sorts.
        """
        self._live_group_count += 1
        recoverable = group.recoverable_size()

        # Build header text
        header = (
            f"{len(group.files)} file(s) | "
            f"Recover: {format_size(recoverable)} | "
            f"{group.similarity:.1f}%"
        )
        if group.is_perceptual:
            header += " (similar)"
        elif group.verified:
            header += " ✓ verified"

        # Append at end (fast) — final sort happens after scan completes
        group_id = self.tree.insert("", "end", open=True,
                                     text=header, tags=("group_header", str(recoverable)))

        for idx, file_info in enumerate(group.files):
            mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                "%Y-%m-%d %H:%M"
            ) if file_info.mtime else ""
            row_tag = "odd_row" if idx % 2 else "even_row"
            self.tree.insert(
                group_id, "end",
                text=Path(file_info.path).name,
                values=(
                    file_info.path,
                    format_size(file_info.size),
                    mtime_str,
                    f"{group.similarity:.1f}%"
                ),
                tags=(row_tag,)
            )

        # Update status with running count
        self.status_label.config(
            text=f"Found {self._live_group_count} duplicate group(s) so far..."
        )

    def _finalize_tree(self) -> None:
        """Sort tree by recoverable size and update status after scan completes."""
        # Sort groups by recoverable size (largest first) using the tag we stored
        all_groups = list(self.tree.get_children())
        if all_groups:
            def recoverable_key(gid):
                tags = self.tree.item(gid, "tags")
                try:
                    return int(tags[1]) if len(tags) > 1 else 0
                except (ValueError, IndexError):
                    return 0

            sorted_groups = sorted(all_groups, key=recoverable_key, reverse=True)
            for i, gid in enumerate(sorted_groups):
                self.tree.move(gid, "", i)

        total_recoverable = 0
        total_files = 0
        for group in self.duplicate_groups:
            total_recoverable += group.recoverable_size()
            total_files += len(group.files)

        trash_note = ""
        if HAS_SEND2TRASH and _config.use_trash:
            trash_note = " | 🗑️ Trash"

        elapsed = ""
        if hasattr(self, "_scan_start_time"):
            secs = time.monotonic() - self._scan_start_time
            if secs >= 60:
                elapsed = f" | {int(secs // 60)}m {int(secs % 60)}s"
            else:
                elapsed = f" | {secs:.1f}s"

        self.status_label.config(
            text=(
                f"{len(self.duplicate_groups)} group(s), "
                f"{total_files} files | "
                f"Recoverable: {format_size(total_recoverable)}"
                f"{elapsed}{trash_note}"
            )
        )
        self.root.after(3000, lambda: self.progress_var.set(0))

    def _populate_tree(self) -> None:
        """Populate treeview with duplicate groups (used for refresh after delete/move)."""
        if self._populating:
            return
        self._populating = True

        try:
            for item in self.tree.get_children():
                self.tree.delete(item)

            self.duplicate_groups.sort(key=lambda g: -g.recoverable_size())

            total_recoverable = 0

            for group in self.duplicate_groups:
                group_id = self.tree.insert("", "end", open=True)
                recoverable = group.recoverable_size()
                total_recoverable += recoverable

                header = (
                    f"{len(group.files)} file(s) | "
                    f"Recover: {format_size(recoverable)} | "
                    f"{group.similarity:.1f}%"
                )

                if group.is_perceptual:
                    header += " (similar)"
                elif group.verified:
                    header += " ✓ verified"

                self.tree.item(group_id, text=header, tags=("group_header",))

                for idx, file_info in enumerate(group.files):
                    mtime_str = datetime.fromtimestamp(file_info.mtime).strftime(
                        "%Y-%m-%d %H:%M"
                    ) if file_info.mtime else ""
                    row_tag = "odd_row" if idx % 2 else "even_row"
                    self.tree.insert(
                        group_id,
                        "end",
                        text=Path(file_info.path).name,
                        values=(
                            file_info.path,
                            format_size(file_info.size),
                            mtime_str,
                            f"{group.similarity:.1f}%"
                        ),
                        tags=(row_tag,)
                    )

            trash_note = ""
            if HAS_SEND2TRASH and _config.use_trash:
                trash_note = " | 🗑️ Trash"

            elapsed = ""
            if hasattr(self, "_scan_start_time"):
                secs = time.monotonic() - self._scan_start_time
                if secs >= 60:
                    elapsed = f" | {int(secs // 60)}m {int(secs % 60)}s"
                else:
                    elapsed = f" | {secs:.1f}s"

            total_files = sum(len(g.files) for g in self.duplicate_groups)
            self.status_label.config(
                text=(
                    f"{len(self.duplicate_groups)} group(s), "
                    f"{total_files} files | "
                    f"Recoverable: {format_size(total_recoverable)}"
                    f"{elapsed}{trash_note}"
                )
            )

            self.root.after(2000, lambda: self.progress_var.set(0))

        finally:
            self._populating = False

    def _dim_column_headers(self, dimmed: bool) -> None:
        """Dim or restore column headers to indicate sorting availability."""
        col_names = {"path": "Path", "size": "Size", "modified": "Modified", "similarity": "Similarity"}
        if dimmed:
            # Grey out headers and show scanning note
            style = ttk.Style()
            style.configure("Treeview.Heading",
                            foreground=TEXT_MUTED,
                            background=BG_DARK)
            for c, name in col_names.items():
                self.tree.heading(c, text=f"{name}")
        else:
            # Restore normal header style
            style = ttk.Style()
            style.configure("Treeview.Heading",
                            foreground=TEXT_PRIMARY,
                            background=BG_MEDIUM)
            for c, name in col_names.items():
                self.tree.heading(c, text=name,
                                  command=lambda _c=c: self._sort_column(_c, False))

    def _get_group_paths(self, group_id: str) -> List[str]:
        """Get all file paths from a group's children."""
        paths = []
        for child in self.tree.get_children(group_id):
            values = self.tree.item(child, "values")
            if values:
                paths.append(values[0])
        return paths

    def _get_selected_paths(self) -> List[str]:
        """Get paths of selected items."""
        if self._populating:
            return []
        items = self.tree.selection()
        paths = []
        for item in items:
            values = self.tree.item(item, "values")
            if values:
                paths.append(values[0])
        return paths

    def _preview_item_or_group(self, item: str) -> None:
        """Preview all files in the group containing the clicked item.

        If a file item is clicked, finds its parent group and previews all siblings.
        If a group header is clicked, previews all children directly.
        """
        values = self.tree.item(item, "values")
        if values:
            # File item — find its parent group
            parent = self.tree.parent(item)
            if parent:
                paths = self._get_group_paths(parent)
            else:
                paths = [values[0]]
        else:
            # Group header — get all children
            paths = self._get_group_paths(item)

        if paths:
            pw = PreviewWindow(self.root, paths, on_delete=self._on_preview_delete)
            self._center_dialog(pw.top, 700, 500)
            self._apply_dark_titlebar(pw.top)

    def _show_preview(self) -> None:
        """Show preview of selected files, expanding to full group if single item selected."""
        selected = self.tree.selection()
        if not selected:
            return

        # If only one item selected, preview its whole group
        if len(selected) == 1:
            self._preview_item_or_group(selected[0])
            return

        # Multiple items selected — preview just those
        paths = self._get_selected_paths()
        if paths:
            pw = PreviewWindow(self.root, paths, on_delete=self._on_preview_delete)
            self._center_dialog(pw.top, 700, 500)
            self._apply_dark_titlebar(pw.top)

    def _compare_selected(self) -> None:
        """Compare selected files side by side."""
        paths = self._get_selected_paths()
        if len(paths) >= 2:
            cw = ComparisonWindow(self.root, paths[:2], on_delete=self._on_preview_delete)
            self._center_dialog(cw.top, 900, 600)
            self._apply_dark_titlebar(cw.top)

    def _delete_selected(self) -> None:
        """Delete selected files (via trash if available)."""
        paths = self._get_selected_paths()
        if not paths:
            return

        file_list = "\n".join(f"  {Path(p).name}" for p in paths[:10])
        if len(paths) > 10:
            file_list += f"\n  ... and {len(paths) - 10} more"

        method = "move to trash" if (HAS_SEND2TRASH and _config.use_trash) else "PERMANENTLY delete"
        if not messagebox.askyesno(
            "Confirm Delete",
            f"{method.capitalize()} these files?\n\n{file_list}"
        ):
            return

        deleted = 0
        errors: List[str] = []

        for path in paths:
            if not os.path.exists(path):
                errors.append(f"Not found: {path}")
                continue

            try:
                safe_delete(path)
                deleted += 1
            except PermissionError:
                errors.append(f"Permission denied: {path}")
            except OSError as e:
                errors.append(f"Error: {path} - {e}")

        # Remove deleted files from duplicate_groups so tree stays in sync
        self._purge_missing_files()

        msg = f"{'Trashed' if HAS_SEND2TRASH and _config.use_trash else 'Deleted'} {deleted} file(s)."
        if errors:
            msg += "\n\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n... and {len(errors) - 5} more"

        messagebox.showinfo("Done", msg)
        self._populate_tree()

    def _move_selected(self) -> None:
        """Move selected files to another location."""
        paths = self._get_selected_paths()
        if not paths:
            return

        dest = filedialog.askdirectory(title="Destination Folder")
        if not dest:
            return

        moved = 0
        errors: List[str] = []

        for path in paths:
            if not os.path.exists(path):
                errors.append(f"Not found: {path}")
                continue

            dest_path = os.path.join(dest, os.path.basename(path))
            if os.path.exists(dest_path):
                errors.append(f"Already exists at destination: {os.path.basename(path)}")
                continue

            try:
                shutil.move(path, dest)
                moved += 1
            except PermissionError:
                errors.append(f"Permission denied: {path}")
            except OSError as e:
                errors.append(f"Error: {path} - {e}")

        # Remove moved files from duplicate_groups so tree stays in sync
        self._purge_missing_files()

        msg = f"Moved {moved} file(s)."
        if errors:
            msg += "\n\nErrors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                msg += f"\n... and {len(errors) - 5} more"

        messagebox.showinfo("Done", msg)
        self._populate_tree()

    def _show_context_menu(self, event) -> None:
        """Show right-click context menu at cursor position using custom dark popup."""
        # Select the item under cursor if not already selected
        item = self.tree.identify_row(event.y)
        if not item:
            return
        if item not in self.tree.selection():
            self.tree.selection_set(item)

        # Close any existing context popup
        self._close_dropdown()

        # Reuse the same Toplevel dropdown system as the menu bar
        # Create a temporary "button" reference for the dropdown tracker
        dummy_btn = tk.Label(self.root)  # won't be displayed

        x = event.x_root
        y = event.y_root

        dropdown = tk.Toplevel(self.root)
        dropdown.overrideredirect(True)
        dropdown.configure(bg=BORDER)
        dropdown.attributes("-topmost", True)

        inner = tk.Frame(dropdown, bg=BG_DARK, bd=0)
        inner.pack(padx=1, pady=1, fill=tk.BOTH, expand=True)

        for ctx_item in self._context_items:
            if ctx_item is None:
                tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=8, pady=3)
                continue

            label_text, command, shortcut = ctx_item
            row = tk.Frame(inner, bg=BG_DARK, cursor="hand2")
            row.pack(fill=tk.X)

            lbl = tk.Label(
                row, text=f"  {label_text}", anchor=tk.W,
                bg=BG_DARK, fg=TEXT_PRIMARY,
                font=("Segoe UI", 10), padx=8, pady=5
            )
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)

            for widget in (row, lbl):
                widget.bind("<Enter>", lambda e, r=row, l=lbl: (
                    r.config(bg=ACCENT), l.config(bg=ACCENT, fg="#ffffff")
                ))
                widget.bind("<Leave>", lambda e, r=row, l=lbl: (
                    r.config(bg=BG_DARK), l.config(bg=BG_DARK, fg=TEXT_PRIMARY)
                ))
                widget.bind("<Button-1>", lambda e, cmd=command: self._dropdown_click(cmd))

        dropdown.geometry(f"+{x}+{y}")
        self._active_dropdown = (dummy_btn, dropdown)

    def _open_file_location(self) -> None:
        """Open the containing folder of the selected file in the system file manager."""
        paths = self._get_selected_paths()
        if not paths:
            return

        path = paths[0]
        folder = os.path.dirname(path)

        if not os.path.exists(folder):
            messagebox.showwarning("Not Found", f"Folder no longer exists:\n{folder}")
            return

        try:
            if sys.platform == "win32":
                # Select the file in Explorer
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                # Linux: open the containing folder
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file location:\n{e}")

    def _auto_select_duplicates(self) -> None:
        """Select all files except the first (oldest) in each duplicate group.
        
        Keeps the oldest file in each group unselected as the 'original'.
        Warns if any groups have less than 100% similarity (perceptual matches).
        """
        if not self.duplicate_groups:
            return

        # Check for non-100% similarity groups and warn
        has_similar = any(
            g.similarity < 100.0 or g.is_perceptual
            for g in self.duplicate_groups
        )

        if has_similar and not _config.suppress_similarity_warning:
            warn_win = tk.Toplevel(self.root)
            warn_win.title("⚠ Auto-Select Warning")
            warn_win.transient(self.root)
            warn_win.grab_set()
            warn_win.configure(bg=BG_DARK)
            self._center_dialog(warn_win, 480, 250)
            self._apply_dark_titlebar(warn_win)
            self._set_app_icon(warn_win)

            ttk.Label(
                warn_win,
                text="⚠  Some groups are similar but NOT identical",
                style="Stage.TLabel"
            ).pack(pady=(15, 5), padx=15)

            ttk.Label(
                warn_win,
                text=(
                    "Auto-Select will also select files from perceptual\n"
                    "match groups (less than 100% similarity).\n\n"
                    "These files look alike but may not be exact duplicates.\n"
                    "Review them carefully before deleting."
                ),
                style="Detail.TLabel", justify=tk.LEFT
            ).pack(padx=15, pady=(0, 10))

            dont_show_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                warn_win,
                text="Don't show this warning again",
                variable=dont_show_var
            ).pack(pady=(0, 5))

            # "select_all" = select from all groups, "exact_only" = skip similar groups
            user_choice = {"action": "cancel"}

            def on_select_all():
                user_choice["action"] = "select_all"
                if dont_show_var.get():
                    _config.suppress_similarity_warning = True
                warn_win.destroy()

            def on_exact_only():
                user_choice["action"] = "exact_only"
                warn_win.destroy()

            def on_cancel():
                warn_win.destroy()

            btn_frame = ttk.Frame(warn_win)
            btn_frame.pack(pady=10, padx=15, fill=tk.X)
            ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(btn_frame, text="Select All", command=on_select_all,
                       style="Warning.TButton").pack(side=tk.RIGHT, padx=(5, 0))
            ttk.Button(btn_frame, text="Exact Only", command=on_exact_only,
                       style="Accent.TButton").pack(side=tk.RIGHT)

            warn_win.bind("<Return>", lambda e: on_exact_only())
            warn_win.bind("<Escape>", lambda e: on_cancel())
            self.root.wait_window(warn_win)

            if user_choice["action"] == "cancel":
                return
            exact_only = (user_choice["action"] == "exact_only")
        else:
            exact_only = False

        # Perform the auto-selection
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(*sel)
        selected_count = 0

        skipped_groups = 0
        for group_id in self.tree.get_children():
            children = self.tree.get_children(group_id)
            if len(children) < 2:
                continue

            # If exact_only, skip groups that aren't 100% exact matches
            if exact_only:
                header = self.tree.item(group_id, "text")
                if "(similar)" in header or "100.0%" not in header:
                    skipped_groups += 1
                    continue

            # Determine which file to KEEP (don't select it for deletion)
            keep_idx = self._pick_best_file(children)

            # Select all except the best
            for i, child in enumerate(children):
                if i != keep_idx:
                    self.tree.selection_add(child)
                    selected_count += 1

        if exact_only:
            similar_note = f" (skipped {skipped_groups} similar group(s))"
        elif has_similar:
            similar_note = " (includes similar matches)"
        else:
            similar_note = ""
        self.status_label.config(
            text=f"Auto-selected {selected_count} duplicate(s) (keeping best quality in each group){similar_note}"
        )

    def _pick_best_file(self, children) -> int:
        """Determine which file in a group to KEEP (index to not select).

        For image groups: keeps the highest resolution file, using file size
        as tiebreaker (larger = less compression = better quality).
        For non-image groups: keeps the oldest file (likely the original).

        Returns the index of the file to keep.
        """
        SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

        # Gather info about each child
        file_info = []  # [(index, path, size_bytes, mtime_timestamp)]
        for i, child in enumerate(children):
            values = self.tree.item(child, "values")
            if not values:
                file_info.append((i, "", 0, float("inf")))
                continue

            path = values[0]

            # Parse size back to bytes
            size_bytes = 0
            try:
                parts = values[1].split()
                size_bytes = int(float(parts[0]) * SIZE_MULT.get(parts[1] if len(parts) > 1 else "B", 1))
            except (ValueError, IndexError):
                pass

            # Parse mtime
            mtime = float("inf")
            if values[2]:
                try:
                    mtime = datetime.strptime(values[2], "%Y-%m-%d %H:%M").timestamp()
                except ValueError:
                    pass

            file_info.append((i, path, size_bytes, mtime))

        if not file_info:
            return 0

        # Check if this is an image group (any file has an image extension)
        is_image_group = any(
            Path(path).suffix.lower() in IMAGE_EXTENSIONS
            for _, path, _, _ in file_info if path
        )

        if is_image_group:
            # For images: pick the highest resolution, then largest file size
            best_idx = 0
            best_pixels = -1
            best_size = -1

            for i, path, size_bytes, _ in file_info:
                if not path:
                    continue
                pixels = 0
                try:
                    with Image.open(path) as img:
                        pixels = img.width * img.height
                except Exception:
                    pass

                # Higher resolution wins; if tied, larger file wins (less compression)
                if (pixels, size_bytes) > (best_pixels, best_size):
                    best_pixels = pixels
                    best_size = size_bytes
                    best_idx = i

            return best_idx
        else:
            # For non-images: keep the oldest file (smallest mtime = earliest)
            oldest_idx = 0
            oldest_mtime = float("inf")
            for i, _, _, mtime in file_info:
                if mtime < oldest_mtime:
                    oldest_mtime = mtime
                    oldest_idx = i
            return oldest_idx

    def _select_all(self) -> None:
        """Select all file items (not group headers) in the tree."""
        all_items = []
        for group_id in self.tree.get_children():
            all_items.extend(self.tree.get_children(group_id))
        if all_items:
            self.tree.selection_set(*all_items)

    def _deselect_all(self) -> None:
        """Clear all selections in the tree."""
        sel = self.tree.selection()
        if sel:
            self.tree.selection_remove(*sel)

    def _make_sort_key(self, col: str, col_idx: int):
        """Create a sort key function for the given column.

        Returned as a standalone function (not a closure inside a loop)
        to avoid Python closure-over-loop-variable issues.
        """
        SIZE_MULT = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

        def sort_key(item_id):
            values = self.tree.item(item_id, "values")
            if not values or col_idx >= len(values):
                return ""
            val = values[col_idx]
            if col == "size":
                try:
                    parts = val.split()
                    return float(parts[0]) * SIZE_MULT.get(parts[1] if len(parts) > 1 else "B", 1)
                except (ValueError, IndexError):
                    return 0
            if col == "similarity":
                try:
                    return float(val.rstrip("%"))
                except (ValueError, TypeError):
                    return 0.0
            return val

        return sort_key

    def _sort_column(self, col: str, reverse: bool) -> None:
        """Sort treeview at both levels: groups by representative value, files within groups.

        Disabled during active scans to prevent freezes from concurrent
        tree modifications. Uses detach/reattach pattern to batch all
        tree moves into a single redraw.
        """
        if self._is_scanning:
            return  # Don't sort while scan is actively adding groups

        col_names = {"path": "Path", "size": "Size", "modified": "Modified", "similarity": "Similarity"}
        col_idx_map = {"path": 0, "size": 1, "modified": 2, "similarity": 3}

        # Update arrow indicators on column headers
        for c, name in col_names.items():
            if c == col:
                arrow = " ▼" if reverse else " ▲"
                self.tree.heading(c, text=name + arrow)
            else:
                self.tree.heading(c, text=name)

        sort_key = self._make_sort_key(col, col_idx_map.get(col, 0))
        all_groups = list(self.tree.get_children())

        # --- Pre-compute group representative values and child sort orders ---
        # Do all reads first, then batch all moves, to minimize redraws.
        group_data = []  # [(group_id, representative_value, sorted_child_ids)]
        for group_id in all_groups:
            children = list(self.tree.get_children(group_id))
            if children:
                child_key_pairs = [(c, sort_key(c)) for c in children]
                child_key_pairs.sort(key=lambda p: p[1], reverse=reverse)
                sorted_child_ids = [p[0] for p in child_key_pairs]
                values = [p[1] for p in child_key_pairs if p[1] != ""]
                rep = (max(values) if reverse else min(values)) if values else ""
            else:
                sorted_child_ids = []
                rep = ""
            group_data.append((group_id, rep, sorted_child_ids))

        # Sort groups by representative value
        group_data.sort(key=lambda g: g[1], reverse=reverse)

        # --- Batch apply: detach all, reattach in order ---
        # Detaching prevents incremental redraws during reordering
        for group_id, _, _ in group_data:
            self.tree.detach(group_id)

        for i, (group_id, _, sorted_children) in enumerate(group_data):
            self.tree.reattach(group_id, "", i)
            # Reorder children within the group
            for j, child_id in enumerate(sorted_children):
                self.tree.move(child_id, group_id, j)

        # Update ALL column heading commands (toggle direction for the active one)
        for c in col_names:
            if c == col:
                self.tree.heading(c, command=lambda _c=c: self._sort_column(_c, not reverse))
            else:
                self.tree.heading(c, command=lambda _c=c: self._sort_column(_c, False))

    def _on_preview_delete(self, path: str) -> None:
        """Called when a file is deleted from a preview/comparison window."""
        self._purge_missing_files()
        self._populate_tree()

    def _purge_missing_files(self) -> None:
        """Remove files that no longer exist from duplicate_groups."""
        for group in self.duplicate_groups:
            group.files = [f for f in group.files if os.path.exists(f.path)]
        # Drop groups that no longer have 2+ files
        self.duplicate_groups = [g for g in self.duplicate_groups if len(g.files) >= 2]

    def _export_report(self) -> None:
        """Export duplicate report to file."""
        if not self.duplicate_groups:
            messagebox.showinfo("No Data", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")],
            title="Save Report As"
        )

        if path:
            try:
                if path.lower().endswith(".csv"):
                    self._export_csv(path)
                else:
                    self._export_txt(path)
                messagebox.showinfo("Done", f"Report saved to:\n{path}")
            except (PermissionError, OSError) as e:
                messagebox.showerror("Error", f"Could not write file: {e}")

    def _export_txt(self, path: str) -> None:
        """Export report as formatted text."""
        export_txt(path, self.duplicate_groups)

    def _export_csv(self, path: str) -> None:
        """Export report as CSV for spreadsheet use."""
        export_csv(path, self.duplicate_groups)

    def _show_options(self) -> None:
        """Show options dialog."""
        od = OptionsDialog(self.root)
        self._center_dialog(od.top, 380, 420)
        self._apply_dark_titlebar(od.top)

    def _show_about(self) -> None:
        """Show about dialog."""
        trash_info = "Trash: enabled (send2trash)" if HAS_SEND2TRASH else "Trash: not available (pip install send2trash)"
        workers = _config.workers
        cpu = os.cpu_count() or "?"
        messagebox.showinfo(
            "About",
            f"VKScan v{VERSION}\n\n"
            "A comprehensive duplicate file detection tool.\n\n"
            "Features:\n"
            "• Exact duplicate detection (SHA-256 + byte verify)\n"
            "• Similar image detection (perceptual hashing)\n"
            "• Parallel scanning with live results\n"
            "• Preview, compare, and manage duplicates\n"
            f"\n{trash_info}\n"
            f"Workers: {workers} threads (CPU: {cpu} cores)\n"
            "\n─────────────────────────────────\n\n"
            "Copyright © 2026 Hygaard.\n\n"
            "Licensed under the GNU General Public License v3.0\n"
            "See LICENSE file for details.\n\n"
            "DISCLAIMER: This software is provided \"as is\", without\n"
            "warranty of any kind, express or implied. In no event\n"
            "shall the authors be liable for any claim, damages, or\n"
            "other liability arising from the use of this software.\n"
            "Use at your own risk. Always maintain backups before\n"
            "deleting or moving files."
        )


