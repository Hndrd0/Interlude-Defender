"""
Hermes Antivirus — Real-time File System Monitor.

Uses the *watchdog* library to observe file-system changes on configured
paths (or all fixed drives).  When an executable file is created, modified,
or moved into a monitored directory the file is enqueued for scanning.

A dedicated worker thread drains the queue and invokes the
:class:`Scanner <hermes.core.scanner.Scanner>` so the watchdog observer is
never blocked by I/O-heavy analysis.

This module is a pure back-end component — it does **not** import PySide6.
"""

from __future__ import annotations

import os
import queue
import string
import threading
import time
from typing import Any, Dict, List, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from hermes.utils.constants import (
    EXECUTABLE_EXTENSIONS,
    FILE_MONITOR_DEBOUNCE_SEC,
)
from hermes.utils.config import Config
from hermes.utils.logger import get_logger

logger = get_logger("file_monitor")

# Sentinel value pushed onto the queue to signal the worker to exit.
_STOP_SENTINEL = None


# ─── Watchdog Handler ────────────────────────────────────────────────────────


class HermesFileHandler(FileSystemEventHandler):
    """Filters and debounces file-system events before forwarding to the monitor.

    Only executable file types (from ``EXECUTABLE_EXTENSIONS``) trigger a
    scan.  Events on the same path that arrive within
    ``FILE_MONITOR_DEBOUNCE_SEC`` seconds of each other are collapsed into
    one.

    Args:
        monitor: Parent :class:`FileMonitor` that owns this handler.
    """

    def __init__(self, monitor: FileMonitor) -> None:
        super().__init__()
        self._monitor = monitor
        self._last_event: Dict[str, float] = {}
        self._debounce_lock = threading.Lock()

    # ── Overrides ────────────────────────────────────────────────────

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle newly created files."""
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle modified files."""
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle moved/renamed files (scan the destination)."""
        if not event.is_directory:
            self._handle(event.dest_path)

    # ── Internal ─────────────────────────────────────────────────────

    def _handle(self, file_path: str) -> None:
        """Filter by extension and debounce, then forward to the monitor."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in EXECUTABLE_EXTENSIONS:
            return

        now = time.time()
        with self._debounce_lock:
            last = self._last_event.get(file_path, 0.0)
            if now - last < FILE_MONITOR_DEBOUNCE_SEC:
                return  # Skip duplicate event
            self._last_event[file_path] = now

        self._monitor._on_file_event(file_path)  # noqa: SLF001


# ─── File Monitor ────────────────────────────────────────────────────────────


class FileMonitor:
    """Monitors configured paths for new or changed executable files.

    Discovered files are handed to the :class:`Scanner` for analysis.

    Args:
        scanner: Fully initialised :class:`Scanner` instance.
        config:  Application :class:`Config` singleton (or compatible).
    """

    def __init__(self, scanner: Any, config: Optional[Config] = None) -> None:
        self._scanner = scanner
        self._config: Config = config or Config()
        self._observer: Observer = Observer()
        self._observer.daemon = True

        self._scan_queue: queue.Queue[Optional[str]] = queue.Queue()
        self._worker_thread: Optional[threading.Thread] = None

        self._paused = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    # ── Properties ───────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """``True`` when the observer and worker thread are active."""
        return self._running

    # ── Public API ───────────────────────────────────────────────────

    def start(self) -> None:
        """Begin monitoring all configured (or discovered) paths.

        Paths are read from ``config["monitor_paths"]``.  When the list is
        empty every fixed drive root on the system is monitored.
        """
        with self._lock:
            if self._running:
                logger.warning("FileMonitor is already running")
                return

            paths = self._resolve_monitor_paths()
            if not paths:
                logger.error("No valid monitor paths found — aborting start")
                return

            handler = HermesFileHandler(self)

            for path in paths:
                try:
                    self._observer.schedule(handler, path, recursive=True)
                    logger.info("Watching: %s", path)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Cannot watch %s: %s", path, exc)

            # Start the background scan worker
            self._worker_thread = threading.Thread(
                target=self._scan_worker, name="FileMonitor-Worker", daemon=True,
            )
            self._worker_thread.start()

            try:
                self._observer.start()
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to start observer: %s", exc)
                self._scan_queue.put(_STOP_SENTINEL)
                return

            self._running = True
            logger.info("Real-time file monitor started (%d paths)", len(paths))

    def stop(self) -> None:
        """Gracefully stop the observer and drain the scan queue."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        logger.info("Stopping real-time file monitor …")

        # Signal the worker to exit
        self._scan_queue.put(_STOP_SENTINEL)

        try:
            self._observer.stop()
            self._observer.join(timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Observer shutdown error: %s", exc)

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)

        logger.info("Real-time file monitor stopped")

    def pause(self) -> None:
        """Temporarily suppress scanning without stopping the observer."""
        self._paused.set()
        logger.info("Real-time scanning paused")

    def resume(self) -> None:
        """Resume scanning after a call to :meth:`pause`."""
        self._paused.clear()
        logger.info("Real-time scanning resumed")

    # ── Internal ─────────────────────────────────────────────────────

    def _on_file_event(self, file_path: str) -> None:
        """Enqueue a file path for scanning (called from the handler)."""
        if self._paused.is_set():
            return
        self._scan_queue.put(file_path)

    def _scan_worker(self) -> None:
        """Background thread that continuously drains the scan queue."""
        logger.debug("Scan worker started")
        while True:
            try:
                file_path = self._scan_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if file_path is _STOP_SENTINEL:
                break

            if self._paused.is_set():
                continue

            try:
                if not os.path.isfile(file_path):
                    continue

                result = self._scanner.scan_file(file_path)

                if result.is_threat:
                    logger.warning(
                        "🛡️  THREAT DETECTED — %s — %s [%s / %s]",
                        result.threat_name,
                        file_path,
                        result.category.value,
                        result.severity.name,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("Error scanning %s: %s", file_path, exc)

        logger.debug("Scan worker exiting")

    def _resolve_monitor_paths(self) -> List[str]:
        """Determine which paths to monitor.

        Uses ``config["monitor_paths"]`` when configured, otherwise
        falls back to high-risk user directories (Downloads, Desktop).
        """
        configured: List[str] = self._config.get("monitor_paths", [])
        if configured:
            valid = [p for p in configured if os.path.isdir(p)]
            if valid:
                return valid
            logger.warning(
                "Configured monitor_paths are all invalid — falling back to user directories",
            )

        user_dir = os.path.expanduser("~")
        fallbacks = [
            os.path.join(user_dir, "Downloads"),
            os.path.join(user_dir, "Desktop"),
        ]
        valid_fallbacks = [p for p in fallbacks if os.path.isdir(p)]
        if valid_fallbacks:
            return valid_fallbacks

        return [user_dir]

    @staticmethod
    def _discover_drives() -> List[str]:
        """Return fixed drive roots present on this Windows system."""
        try:
            import win32api  # type: ignore[import-untyped]

            raw = win32api.GetLogicalDriveStrings()
            drives = [d for d in raw.split("\x00") if d]
            if drives:
                return drives
        except ImportError:
            pass

        drives: List[str] = []
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                drives.append(root)

        return drives if drives else ["C:\\"]
