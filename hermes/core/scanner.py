"""
Hermes Antivirus — Scan Orchestrator.

Coordinates signature matching and heuristic analysis across files and
directories.  Supports quick, full, and custom scan modes with concurrent
execution, progress callbacks, and cancellation via threading.Event.

This module is a pure back-end component — it does **not** import PySide6.
"""

from __future__ import annotations

import os
import string
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Generator,
    List,
    Optional,
    Protocol,
    runtime_checkable,
)

from hermes.utils.constants import (
    ALL_SCANNABLE_EXTENSIONS,
    DEFAULT_SCAN_THREADS,
    MAX_SCAN_FILE_SIZE,
    QUICK_SCAN_PATHS,
    ScanMode,
    ScanStatus,
    ThreatCategory,
    ThreatSeverity,
)
from hermes.utils.config import Config
from hermes.utils.logger import get_logger

logger = get_logger("scanner")


# ─── Data Structures ─────────────────────────────────────────────────────────


@dataclass
class ScanResult:
    """Result of scanning a single file.

    Attributes:
        file_path:    Absolute path to the scanned file.
        threat_name:  Human-readable threat identifier (empty when clean).
        category:     Classification of the detected threat.
        severity:     Numeric severity level.
        engine:       Name of the engine that flagged the file
                      (``"signature"`` or ``"heuristic"``).
        details:      Free-form detail dict (API hits, entropy, etc.).
        timestamp:    Unix timestamp of the scan.
    """

    file_path: str = ""
    threat_name: str = ""
    category: ThreatCategory = ThreatCategory.CLEAN
    severity: ThreatSeverity = ThreatSeverity.NONE
    engine: str = ""
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def is_threat(self) -> bool:
        """Return ``True`` when the result is anything other than clean."""
        return self.category != ThreatCategory.CLEAN


# ─── Engine Protocols ────────────────────────────────────────────────────────

@runtime_checkable
class SignatureEngine(Protocol):
    """Duck-type protocol that any signature engine must satisfy."""

    def scan_file(self, file_path: str) -> ScanResult: ...


@runtime_checkable
class HeuristicEngine(Protocol):
    """Duck-type protocol that any heuristic engine must satisfy."""

    def analyze_file(self, file_path: str) -> ScanResult: ...


@runtime_checkable
class QuarantineManager(Protocol):
    """Duck-type protocol for the quarantine sub-system."""

    def quarantine_file(self, file_path: str, threat_name: str) -> bool: ...


# ─── Progress Callback Signature ─────────────────────────────────────────────
# callback(progress_pct: float, current_file: str, threats_found: int) -> None

ProgressCallback = Optional[Callable[[float, str, int], None]]


# ─── Scanner ─────────────────────────────────────────────────────────────────


class Scanner:
    """Orchestrates file scanning across signature and heuristic engines.

    The scanner is thread-safe.  All mutable statistics are protected by a
    lock so that ``get_scan_stats()`` can be called from the UI thread while a
    scan is in progress.

    Args:
        db:                 Database handle (reserved for future use).
        signature_engine:   Object exposing ``scan_file(path) -> ScanResult``.
        heuristic_engine:   Object exposing ``analyze_file(path) -> ScanResult``.
        quarantine_manager: Object exposing ``quarantine_file(path, name)``.
    """

    def __init__(
        self,
        db: Any,
        signature_engine: SignatureEngine,
        heuristic_engine: HeuristicEngine,
        quarantine_manager: QuarantineManager,
    ) -> None:
        self._db = db
        self._sig_engine = signature_engine
        self._heuristic_engine = heuristic_engine
        self._quarantine = quarantine_manager
        self._config = Config()

        # ── Mutable scan stats (lock-protected) ──
        self._stats_lock = threading.Lock()
        self._files_scanned: int = 0
        self._threats_found: int = 0
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0
        self._status: ScanStatus = ScanStatus.IDLE
        self._current_threat_callback: Optional[Callable[[dict], None]] = None

    # ── Public API ───────────────────────────────────────────────────────

    def scan(
        self,
        mode: str,
        paths: List[str] | None = None,
        progress_callback: ProgressCallback = None,
        threat_callback: Optional[Callable[[dict], None]] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> dict:
        """Unified scan entry point used by UI ScanWorker.

        Coordinates quick, full, or custom scanning modes.
        """
        self._current_threat_callback = threat_callback
        try:
            if mode == "quick":
                self.quick_scan(progress_callback, cancel_event)
            elif mode == "full":
                self.full_scan(progress_callback, cancel_event)
            elif mode == "custom":
                self.custom_scan(paths or [], progress_callback, cancel_event)
            else:
                logger.error("Unknown scan mode: %s", mode)
        finally:
            self._current_threat_callback = None

        return self.get_scan_stats()

    def _trigger_threat_callback(self, result: Any) -> None:
        """Helper to invoke threat callback with dict format if configured."""
        if not self._current_threat_callback:
            return

        sev = getattr(result, "severity", None)
        if sev is None:
            sev = getattr(result, "threat_severity", None)

        cat = getattr(result, "category", None)
        if cat is None:
            cat = getattr(result, "threat_category", None)

        threat_dict = {
            "file_path": getattr(result, "file_path", ""),
            "threat_name": getattr(result, "threat_name", ""),
            "severity": sev.name if hasattr(sev, "name") else str(sev),
            "category": cat.name if hasattr(cat, "name") else str(cat),
        }
        try:
            self._current_threat_callback(threat_dict)
        except Exception as e:
            logger.error("Error invoking threat callback: %s", e)

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file through signature then heuristic engines.

        Returns the *worst* result (highest severity) across engines.
        If the file does not exist or exceeds the size limit a CLEAN
        result is returned so callers never receive ``None``.
        """
        if not os.path.isfile(file_path):
            logger.warning("File not found, skipping: %s", file_path)
            return ScanResult(file_path=file_path)

        try:
            file_size = os.path.getsize(file_path)
        except OSError as exc:
            logger.warning("Cannot stat file %s: %s", file_path, exc)
            return ScanResult(file_path=file_path)

        if file_size > MAX_SCAN_FILE_SIZE:
            logger.debug("Skipping oversized file (%d bytes): %s", file_size, file_path)
            return ScanResult(file_path=file_path)

        # 1) Signature scan
        try:
            sig_result = self._sig_engine.scan_file(file_path)
        except Exception as exc:  # noqa: BLE001
            logger.error("Signature engine error on %s: %s", file_path, exc)
            sig_result = ScanResult(file_path=file_path)

        if sig_result.is_threat:
            with self._stats_lock:
                self._files_scanned += 1
                self._threats_found += 1
            self._trigger_threat_callback(sig_result)
            return sig_result

        # 2) Heuristic analysis (only when no signature match)
        try:
            heur_result = self._heuristic_engine.analyze_file(file_path)
        except Exception as exc:  # noqa: BLE001
            logger.error("Heuristic engine error on %s: %s", file_path, exc)
            heur_result = ScanResult(file_path=file_path)

        with self._stats_lock:
            self._files_scanned += 1
            if heur_result.is_threat:
                self._threats_found += 1
                self._trigger_threat_callback(heur_result)

        return heur_result if heur_result.is_threat else sig_result

    def scan_directory(
        self,
        root_path: str,
        recursive: bool = True,
        callback: ProgressCallback = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> List[ScanResult]:
        """Walk *root_path*, scan eligible files, and return threat results.

        Args:
            root_path:    Directory to scan.
            recursive:    Descend into sub-directories.
            callback:     ``(progress_pct, current_file, threats)`` progress fn.
            cancel_event: When set, the scan aborts gracefully.

        Returns:
            List of :class:`ScanResult` instances that are **threats only**.
        """
        threats: List[ScanResult] = []
        file_list = list(self._discover_files(root_path, recursive))
        total = len(file_list)
        if total == 0:
            return threats

        scan_threads = self._config.get("scan_threads", DEFAULT_SCAN_THREADS)
        completed = 0
        threats_lock = threading.Lock()

        def _scan_one(path: str) -> Optional[ScanResult]:
            """Scan a single file inside the thread-pool."""
            if cancel_event and cancel_event.is_set():
                return None
            try:
                return self.scan_file(path)
            except Exception as exc:  # noqa: BLE001
                logger.error("Unexpected error scanning %s: %s", path, exc)
                return None

        with ThreadPoolExecutor(max_workers=scan_threads) as pool:
            futures = {pool.submit(_scan_one, fp): fp for fp in file_list}

            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    # Cancel remaining futures as best-effort
                    for f in futures:
                        f.cancel()
                    break

                result = future.result()
                completed += 1

                if result and result.is_threat:
                    with threats_lock:
                        threats.append(result)

                if callback and completed % max(1, total // 200) == 0:
                    pct = (completed / total) * 100.0
                    current = futures[future]
                    with threats_lock:
                        t_count = len(threats)
                    try:
                        callback(pct, current, t_count)
                    except Exception:  # noqa: BLE001
                        pass  # Never let a bad callback crash the scan

        # Final 100 % callback
        if callback:
            try:
                with threats_lock:
                    t_count = len(threats)
                callback(100.0, "", t_count)
            except Exception:  # noqa: BLE001
                pass

        return threats

    def quick_scan(
        self,
        callback: ProgressCallback = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> List[ScanResult]:
        """Scan high-risk locations defined in ``QUICK_SCAN_PATHS``.

        Returns a merged list of all threat results across scan paths.
        """
        self._reset_stats()
        self._status = ScanStatus.RUNNING
        logger.info("Quick scan started")

        all_threats: List[ScanResult] = []
        valid_paths = [p for p in QUICK_SCAN_PATHS if p and os.path.isdir(p)]

        for path in valid_paths:
            if cancel_event and cancel_event.is_set():
                break
            logger.info("Quick scan: scanning %s", path)
            results = self.scan_directory(
                path, recursive=True, callback=callback, cancel_event=cancel_event,
            )
            all_threats.extend(results)

        self._finalise_scan(cancel_event)
        return all_threats

    def full_scan(
        self,
        callback: ProgressCallback = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> List[ScanResult]:
        """Scan every fixed drive letter found on the system.

        On Windows, drives A–Z are probed with ``os.path.exists``.
        Falls back to scanning ``C:\\`` if nothing is detected.
        """
        self._reset_stats()
        self._status = ScanStatus.RUNNING
        logger.info("Full scan started")

        drives = self._discover_drives()
        all_threats: List[ScanResult] = []

        for drive in drives:
            if cancel_event and cancel_event.is_set():
                break
            logger.info("Full scan: scanning drive %s", drive)
            results = self.scan_directory(
                drive, recursive=True, callback=callback, cancel_event=cancel_event,
            )
            all_threats.extend(results)

        self._finalise_scan(cancel_event)
        return all_threats

    def custom_scan(
        self,
        paths: List[str],
        callback: ProgressCallback = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> List[ScanResult]:
        """Scan an arbitrary list of user-specified files and directories.

        Each entry in *paths* may be a file or a directory.
        """
        self._reset_stats()
        self._status = ScanStatus.RUNNING
        logger.info("Custom scan started (%d paths)", len(paths))

        all_threats: List[ScanResult] = []

        for path in paths:
            if cancel_event and cancel_event.is_set():
                break

            if os.path.isfile(path):
                result = self.scan_file(path)
                if result.is_threat:
                    all_threats.append(result)
            elif os.path.isdir(path):
                results = self.scan_directory(
                    path, recursive=True, callback=callback, cancel_event=cancel_event,
                )
                all_threats.extend(results)
            else:
                logger.warning("Path not found, skipping: %s", path)

        self._finalise_scan(cancel_event)
        return all_threats

    def get_scan_stats(self) -> dict:
        """Return a snapshot of current scan statistics.

        Returns:
            Dictionary with keys ``files_scanned``, ``threats_found``,
            ``scan_speed`` (files/sec), ``elapsed_time`` (seconds), and
            ``status``.
        """
        with self._stats_lock:
            end = self._scan_end if self._scan_end else time.time()
            elapsed = max(end - self._scan_start, 0.001) if self._scan_start else 0.0
            speed = self._files_scanned / elapsed if elapsed > 0 else 0.0
            return {
                "files_scanned": self._files_scanned,
                "threats_found": self._threats_found,
                "scan_speed": round(speed, 1),
                "elapsed_time": round(elapsed, 2),
                "status": self._status.value,
            }

    # ── Private Helpers ──────────────────────────────────────────────────

    def _should_scan(self, file_path: str) -> bool:
        """Decide whether *file_path* is eligible for scanning.

        Checks:
        * Extension is in ``ALL_SCANNABLE_EXTENSIONS``.
        * File size is within the configured limit.
        * Path is not in the user's exclusion list.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ALL_SCANNABLE_EXTENSIONS:
            return False

        # Honour user-excluded extensions
        excluded_exts = self._config.get("excluded_extensions", [])
        if ext in excluded_exts:
            return False

        # Honour user-excluded paths (case-insensitive on Windows)
        excluded_paths = self._config.get("excluded_paths", [])
        normalised = os.path.normcase(os.path.abspath(file_path))
        for ep in excluded_paths:
            if normalised.startswith(os.path.normcase(os.path.abspath(ep))):
                return False

        # Size gate
        try:
            if os.path.getsize(file_path) > MAX_SCAN_FILE_SIZE:
                return False
        except OSError:
            return False

        return True

    def _discover_files(
        self, root_path: str, recursive: bool,
    ) -> Generator[str, None, None]:
        """Yield absolute paths of scannable files under *root_path*.

        When *recursive* is ``False`` only the immediate children of
        *root_path* are considered.
        """
        if not os.path.isdir(root_path):
            logger.warning("Not a directory, skipping: %s", root_path)
            return

        if recursive:
            for dirpath, _dirnames, filenames in os.walk(root_path, topdown=True):
                for fname in filenames:
                    full_path = os.path.join(dirpath, fname)
                    if self._should_scan(full_path):
                        yield full_path
        else:
            try:
                entries = os.listdir(root_path)
            except PermissionError:
                logger.debug("Permission denied: %s", root_path)
                return
            for fname in entries:
                full_path = os.path.join(root_path, fname)
                if os.path.isfile(full_path) and self._should_scan(full_path):
                    yield full_path

    @staticmethod
    def _discover_drives() -> List[str]:
        """Return a list of fixed drive roots present on this system.

        Tries ``win32api.GetLogicalDriveStrings`` first; falls back to
        probing ``A:\\`` through ``Z:\\`` with ``os.path.exists``.
        """
        try:
            import win32api  # type: ignore[import-untyped]

            raw = win32api.GetLogicalDriveStrings()
            drives = [d for d in raw.split("\x00") if d]
            if drives:
                return drives
        except ImportError:
            pass

        # Fallback: brute-force drive letter probing
        drives: List[str] = []
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            if os.path.exists(root):
                drives.append(root)

        return drives if drives else ["C:\\"]

    def _reset_stats(self) -> None:
        """Zero out statistics before a new scan run."""
        with self._stats_lock:
            self._files_scanned = 0
            self._threats_found = 0
            self._scan_start = time.time()
            self._scan_end = 0.0
            self._status = ScanStatus.IDLE

    def _finalise_scan(self, cancel_event: Optional[threading.Event]) -> None:
        """Mark the scan as completed or cancelled and log a summary."""
        with self._stats_lock:
            self._scan_end = time.time()
            if cancel_event and cancel_event.is_set():
                self._status = ScanStatus.CANCELLED
                logger.info(
                    "Scan cancelled — %d files scanned, %d threats found",
                    self._files_scanned,
                    self._threats_found,
                )
            else:
                self._status = ScanStatus.COMPLETED
                logger.info(
                    "Scan completed — %d files scanned, %d threats found in %.1fs",
                    self._files_scanned,
                    self._threats_found,
                    self._scan_end - self._scan_start,
                )
