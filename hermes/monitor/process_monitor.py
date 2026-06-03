"""
Hermes Antivirus — Process Activity Monitor.

Periodically inspects new processes via *psutil*.  When a newly spawned
process originates from a suspicious file-system location its executable
is scanned by the :class:`Scanner <hermes.core.scanner.Scanner>`.

The monitor **never** terminates processes — it only scans and logs or
raises alerts through the scanner's normal threat pipeline.

This module is a pure back-end component — it does **not** import PySide6.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, List, Optional, Set

import psutil

from hermes.utils.constants import (
    EXECUTABLE_EXTENSIONS,
    SUSPICIOUS_LOCATIONS,
)
from hermes.utils.logger import get_logger

logger = get_logger("proc_monitor")

# How often (seconds) the monitor polls for new processes.
_POLL_INTERVAL: float = 3.0


class ProcessMonitor:
    """Monitors the process table for new executables from risky locations.

    Args:
        scanner: Fully initialised :class:`Scanner` instance.
    """

    def __init__(self, scanner: Any) -> None:
        self._scanner = scanner
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._seen_pids: Set[int] = set()
        self._lock = threading.Lock()

    # ── Properties ───────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        """``True`` when the monitoring loop is active."""
        return self._thread is not None and self._thread.is_alive()

    # ── Public API ───────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background monitoring loop.

        If the monitor is already running the call is silently ignored.
        """
        with self._lock:
            if self.is_running:
                logger.warning("ProcessMonitor is already running")
                return

            # Snapshot current processes so we don't scan everything at startup
            self._seen_pids = self._snapshot_pids()
            self._stop_event.clear()

            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="ProcessMonitor-Loop",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Process monitor started (tracking %d existing PIDs)",
                len(self._seen_pids),
            )

    def stop(self) -> None:
        """Signal the monitoring loop to exit and wait for the thread."""
        with self._lock:
            if not self.is_running:
                return

            self._stop_event.set()

        if self._thread is not None:
            self._thread.join(timeout=_POLL_INTERVAL + 2.0)
            logger.info("Process monitor stopped")

    # ── Internal ─────────────────────────────────────────────────────

    def _monitor_loop(self) -> None:
        """Continuously poll for new processes until stopped."""
        logger.debug("Process monitor loop started")

        while not self._stop_event.is_set():
            try:
                new_procs = self._get_new_processes()
                for proc in new_procs:
                    if self._stop_event.is_set():
                        break
                    self._check_process(proc)
            except Exception as exc:  # noqa: BLE001
                logger.error("Error in process monitor loop: %s", exc)

            # Sleep in small increments so we can honour stop requests quickly
            self._stop_event.wait(timeout=_POLL_INTERVAL)

        logger.debug("Process monitor loop exiting")

    def _get_new_processes(self) -> List[psutil.Process]:
        """Return a list of :class:`psutil.Process` objects not yet seen.

        Updates the internal ``_seen_pids`` set as a side-effect.
        """
        current_pids = self._snapshot_pids()
        new_pids = current_pids - self._seen_pids
        self._seen_pids = current_pids  # refresh to track terminated PIDs too

        new_procs: List[psutil.Process] = []
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                new_procs.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process already exited or we can't access it — skip
                continue

        return new_procs

    def _check_process(self, proc: psutil.Process) -> None:
        """If *proc*'s executable lives in a suspicious location, scan it.

        Access errors and race conditions (the process may exit between
        detection and inspection) are handled gracefully.
        """
        try:
            exe_path: Optional[str] = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not get exe for PID %d: %s", proc.pid, exc)
            return

        if not exe_path or not os.path.isfile(exe_path):
            return

        # Only scan executables with recognised extensions
        ext = os.path.splitext(exe_path)[1].lower()
        if ext not in EXECUTABLE_EXTENSIONS:
            return

        if not self._is_suspicious_location(exe_path):
            return

        logger.info(
            "New process from suspicious location — PID %d, exe: %s",
            proc.pid,
            exe_path,
        )

        try:
            result = self._scanner.scan_file(exe_path)
            if result.is_threat:
                try:
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "<unknown>"

                logger.warning(
                    "🛡️  THREAT IN RUNNING PROCESS — %s — PID %d (%s) — %s [%s / %s]",
                    result.threat_name,
                    proc.pid,
                    proc_name,
                    exe_path,
                    result.category.value,
                    result.severity.name,
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("Error scanning process exe %s: %s", exe_path, exc)

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _snapshot_pids() -> Set[int]:
        """Return the set of currently running PIDs."""
        try:
            return set(psutil.pids())
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to snapshot PIDs: %s", exc)
            return set()

    @staticmethod
    def _is_suspicious_location(file_path: str) -> bool:
        """Return ``True`` when *file_path* is under a suspicious directory."""
        normalised = os.path.normcase(os.path.abspath(file_path))
        for loc in SUSPICIOUS_LOCATIONS:
            if not loc:
                continue
            loc_norm = os.path.normcase(os.path.abspath(loc))
            if normalised.startswith(loc_norm):
                return True
        return False
