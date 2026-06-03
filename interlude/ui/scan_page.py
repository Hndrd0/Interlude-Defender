"""
Hermes Antivirus — Scan Page.

Manages scan lifecycle (idle → scanning → complete) with a background
``ScanWorker`` running in a ``QThread`` via the Worker-Object pattern.
"""

from __future__ import annotations

import os
import time
import threading
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QSizePolicy, QFileDialog, QStackedWidget,
)
from PySide6.QtCore import Qt, Signal, QObject, QThread, QTimer
from PySide6.QtGui import QFont

from hermes.ui.widgets.scan_progress import ScanProgressRing
from hermes.ui.widgets.threat_card import ThreatCard


# ═══════════════════════════════════════════════════════════════════════════════
#  ScanWorker — runs the scan engine on a background thread
# ═══════════════════════════════════════════════════════════════════════════════

class ScanWorker(QObject):
    """Background worker that drives a ``Scanner`` instance.

    Signals:
        progress(int, str, int): ``(percentage, current_file, threats_found)``
        threat_found(dict):       Details of a single detected threat.
        finished(dict):           Summary dict when the scan completes.
        error(str):               Error message if the scan fails.
    """

    progress = Signal(int, str, int)
    threat_found = Signal(dict)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self,
        scanner,
        mode: str,
        paths: list[str] | None = None,
    ) -> None:
        super().__init__()
        self._scanner = scanner
        self._mode = mode
        self._paths = paths or []
        self._cancel_event = threading.Event()

    # ── Main entry point (called on worker thread) ────────────────────────

    def run(self) -> None:
        """Execute the scan and emit progress signals."""
        try:
            self._scanner.cancel_event = self._cancel_event

            # Callback bridge: scanner calls this on each file
            def _progress_cb(pct: int, current_file: str, threats: int) -> None:
                if self._cancel_event.is_set():
                    return
                self.progress.emit(pct, current_file, threats)

            def _threat_cb(threat_info: dict) -> None:
                self.threat_found.emit(threat_info)

            results = self._scanner.scan(
                mode=self._mode,
                paths=self._paths,
                progress_callback=_progress_cb,
                threat_callback=_threat_cb,
                cancel_event=self._cancel_event,
            )

            if self._cancel_event.is_set():
                self.finished.emit({"cancelled": True})
            else:
                self.finished.emit(results if isinstance(results, dict) else {})

        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))

    def stop(self) -> None:
        """Request graceful cancellation."""
        self._cancel_event.set()


# ═══════════════════════════════════════════════════════════════════════════════
#  ScanPage
# ═══════════════════════════════════════════════════════════════════════════════

_STATE_IDLE = 0
_STATE_SCANNING = 1
_STATE_COMPLETE = 2


class ScanPage(QWidget):
    """Scan management page with three visual states: idle, scanning, complete."""

    def __init__(self, scanner, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("scanPage")
        self._scanner = scanner
        self._worker: ScanWorker | None = None
        self._thread: QThread | None = None
        self._threats_found: list[dict] = []
        self._files_scanned = 0
        self._elapsed_seconds = 0

        self._build_ui()

        # Elapsed-time timer
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1000)
        self._tick_timer.timeout.connect(self._tick_elapsed)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 20, 28, 20)
        root.setSpacing(0)

        self._stack = QStackedWidget()
        root.addWidget(self._stack)

        self._stack.addWidget(self._build_idle_page())     # index 0
        self._stack.addWidget(self._build_scanning_page()) # index 1
        self._stack.addWidget(self._build_complete_page())  # index 2

        self._stack.setCurrentIndex(_STATE_IDLE)

    # ── Idle state ────────────────────────────────────────────────────────

    def _build_idle_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(18)

        self._idle_ring = ScanProgressRing(value=0, size=180)
        layout.addWidget(self._idle_ring, 0, Qt.AlignCenter)

        lbl = QLabel("Ready to Scan")
        lbl.setFont(QFont("Segoe UI", 20, QFont.Bold))
        lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl)

        sub = QLabel("Choose a scan mode to start protecting your system")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setStyleSheet("color: #9aa0a6; background: transparent;")
        sub.setAlignment(Qt.AlignCenter)
        layout.addWidget(sub)

        layout.addSpacing(12)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)

        quick_btn = self._scan_button("⚡  Quick Scan", primary=True)
        quick_btn.clicked.connect(lambda: self.start_scan("quick"))

        full_btn = self._scan_button("🖥️  Full Scan")
        full_btn.clicked.connect(lambda: self.start_scan("full"))

        custom_btn = self._scan_button("📁  Custom Scan")
        custom_btn.clicked.connect(self._custom_scan_dialog)

        btn_row.addStretch()
        btn_row.addWidget(quick_btn)
        btn_row.addWidget(full_btn)
        btn_row.addWidget(custom_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addStretch()
        return page

    # ── Scanning state ────────────────────────────────────────────────────

    def _build_scanning_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(14)

        self._scan_ring = ScanProgressRing(value=0, size=200)
        layout.addWidget(self._scan_ring, 0, Qt.AlignCenter)

        self._scan_title = QLabel("Scanning…")
        self._scan_title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self._scan_title.setStyleSheet("color: #e8eaed; background: transparent;")
        self._scan_title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._scan_title)

        self._scan_file_label = QLabel("")
        self._scan_file_label.setFont(QFont("Consolas", 10))
        self._scan_file_label.setStyleSheet("color: #9aa0a6; background: transparent;")
        self._scan_file_label.setAlignment(Qt.AlignCenter)
        self._scan_file_label.setWordWrap(True)
        layout.addWidget(self._scan_file_label)

        layout.addSpacing(6)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(30)
        stats_row.setAlignment(Qt.AlignCenter)

        self._stat_files = self._stat_label("Files", "0")
        self._stat_threats = self._stat_label("Threats", "0")
        self._stat_elapsed = self._stat_label("Elapsed", "00:00")

        for w in (self._stat_files, self._stat_threats, self._stat_elapsed):
            stats_row.addWidget(w["widget"])
        layout.addLayout(stats_row)

        layout.addSpacing(12)

        cancel_btn = QPushButton("✕  Cancel Scan")
        cancel_btn.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.setMinimumHeight(44)
        cancel_btn.setFixedWidth(200)
        cancel_btn.setStyleSheet(
            """
            QPushButton {
                background: rgba(255,71,87,0.15);
                color: #ff4757;
                border: 1px solid rgba(255,71,87,0.3);
                border-radius: 12px;
            }
            QPushButton:hover {
                background: rgba(255,71,87,0.25);
            }
            """
        )
        cancel_btn.clicked.connect(self.cancel_scan)
        layout.addWidget(cancel_btn, 0, Qt.AlignCenter)

        layout.addStretch()
        return page

    # ── Complete state ────────────────────────────────────────────────────

    def _build_complete_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        # Top summary
        top = QVBoxLayout()
        top.setAlignment(Qt.AlignCenter)
        top.setSpacing(10)

        self._done_ring = ScanProgressRing(value=100, size=150)
        top.addWidget(self._done_ring, 0, Qt.AlignCenter)

        self._done_title = QLabel("Scan Complete")
        self._done_title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self._done_title.setStyleSheet("color: #2ed573; background: transparent;")
        self._done_title.setAlignment(Qt.AlignCenter)
        top.addWidget(self._done_title)

        self._done_summary = QLabel("")
        self._done_summary.setFont(QFont("Segoe UI", 12))
        self._done_summary.setStyleSheet("color: #9aa0a6; background: transparent;")
        self._done_summary.setAlignment(Qt.AlignCenter)
        top.addWidget(self._done_summary)

        layout.addLayout(top)
        layout.addSpacing(6)

        # Threat list (scrollable)
        self._threat_scroll = QScrollArea()
        self._threat_scroll.setWidgetResizable(True)
        self._threat_scroll.setFrameShape(QFrame.NoFrame)
        self._threat_scroll.setStyleSheet("background: transparent; border: none;")

        self._threat_container = QWidget()
        self._threat_list_layout = QVBoxLayout(self._threat_container)
        self._threat_list_layout.setContentsMargins(0, 0, 0, 0)
        self._threat_list_layout.setSpacing(8)
        self._threat_list_layout.addStretch()
        self._threat_scroll.setWidget(self._threat_container)

        layout.addWidget(self._threat_scroll, 1)

        # Scan Again button
        again_btn = QPushButton("🔄  Scan Again")
        again_btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        again_btn.setMinimumHeight(48)
        again_btn.setCursor(Qt.PointingHandCursor)
        again_btn.setStyleSheet(
            """
            QPushButton {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #00d4aa, stop:1 #00b894);
                color: #0a0e17;
                border: none; border-radius: 14px;
                padding: 12px 32px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #00e6bb, stop:1 #00d4aa);
            }
            """
        )
        again_btn.clicked.connect(self._go_idle)
        layout.addWidget(again_btn, 0, Qt.AlignCenter)

        return page

    # ── Widget factories ──────────────────────────────────────────────────

    def _scan_button(self, text: str, primary: bool = False) -> QPushButton:
        btn = QPushButton(text)
        btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        btn.setMinimumHeight(52)
        btn.setMinimumWidth(170)
        btn.setCursor(Qt.PointingHandCursor)
        if primary:
            btn.setStyleSheet(
                """
                QPushButton {
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                        stop:0 #00d4aa, stop:1 #00b894);
                    color: #0a0e17; border: none; border-radius: 14px;
                    padding: 12px 24px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                        stop:0 #00e6bb, stop:1 #00d4aa);
                }
                QPushButton:pressed { background: #00b894; }
                """
            )
        else:
            btn.setStyleSheet(
                """
                QPushButton {
                    background: rgba(255,255,255,0.06);
                    color: #e8eaed;
                    border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 14px; padding: 12px 24px;
                }
                QPushButton:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: rgba(255,255,255,0.15);
                }
                QPushButton:pressed { background: rgba(255,255,255,0.04); }
                """
            )
        return btn

    @staticmethod
    def _stat_label(title: str, value: str) -> dict:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        col = QVBoxLayout(w)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(2)
        col.setAlignment(Qt.AlignCenter)

        val_lbl = QLabel(value)
        val_lbl.setFont(QFont("Segoe UI", 22, QFont.Bold))
        val_lbl.setStyleSheet("color: #e8eaed; background: transparent;")
        val_lbl.setAlignment(Qt.AlignCenter)
        col.addWidget(val_lbl)

        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Segoe UI", 10))
        title_lbl.setStyleSheet("color: #9aa0a6; background: transparent;")
        title_lbl.setAlignment(Qt.AlignCenter)
        col.addWidget(title_lbl)

        return {"widget": w, "value_label": val_lbl}

    # ── Scan lifecycle ────────────────────────────────────────────────────

    def start_scan(self, mode: str, paths: list[str] | None = None) -> None:
        """Begin a scan in the background thread."""
        if self._thread is not None and self._thread.isRunning():
            return  # already scanning

        self._threats_found.clear()
        self._files_scanned = 0
        self._elapsed_seconds = 0

        # Reset scanning UI
        self._scan_ring.set_value(0)
        self._scan_file_label.setText("")
        self._stat_files["value_label"].setText("0")
        self._stat_threats["value_label"].setText("0")
        self._stat_elapsed["value_label"].setText("00:00")
        self._scan_title.setText("Scanning…")

        self._stack.setCurrentIndex(_STATE_SCANNING)

        # Worker-Object pattern
        self._thread = QThread()
        self._worker = ScanWorker(self._scanner, mode, paths)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.threat_found.connect(self._on_threat_found)
        self._worker.finished.connect(self._on_scan_finished)
        self._worker.error.connect(self._on_scan_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)

        self._thread.start()
        self._tick_timer.start()

    def cancel_scan(self) -> None:
        """Request the running scan to stop."""
        if self._worker is not None:
            self._worker.stop()
        self._scan_title.setText("Cancelling…")

    # ── Slots ─────────────────────────────────────────────────────────────

    def _on_progress(self, pct: int, current_file: str, threats: int) -> None:
        self._scan_ring.set_value(pct)
        # Truncate long paths
        display = current_file
        if len(display) > 80:
            display = "…" + display[-77:]
        self._scan_file_label.setText(display)
        self._files_scanned = max(self._files_scanned, pct)  # approximate
        self._stat_files["value_label"].setText(str(self._files_scanned))
        self._stat_threats["value_label"].setText(str(threats))

    def _on_threat_found(self, threat_dict: dict) -> None:
        self._threats_found.append(threat_dict)

    def _on_scan_finished(self, results: dict) -> None:
        self._tick_timer.stop()

        cancelled = results.get("cancelled", False)
        files = results.get("files_scanned", self._files_scanned)
        threats = results.get("threats_found", len(self._threats_found))

        # Populate complete page
        self._done_ring.set_value(100)

        if cancelled:
            self._done_title.setText("Scan Cancelled")
            self._done_title.setStyleSheet("color: #ffa502; background: transparent;")
        elif threats > 0:
            self._done_title.setText("Threats Found!")
            self._done_title.setStyleSheet("color: #ff4757; background: transparent;")
        else:
            self._done_title.setText("Scan Complete")
            self._done_title.setStyleSheet("color: #2ed573; background: transparent;")

        elapsed_str = self._format_elapsed(self._elapsed_seconds)
        self._done_summary.setText(
            f"{files:,} files scanned  •  {threats} threat{'s' if threats != 1 else ''} found  •  {elapsed_str}"
        )

        # Populate threat cards
        self._clear_threat_list()
        for t in self._threats_found:
            card = ThreatCard(
                file_path=t.get("file_path", "Unknown"),
                threat_name=t.get("threat_name", "Unknown Threat"),
                severity=str(t.get("severity", "LOW")),
            )
            card.quarantine_clicked.connect(self._quarantine_threat)
            card.remove_clicked.connect(self._remove_threat)
            card.ignore_clicked.connect(self._ignore_threat)
            self._threat_list_layout.insertWidget(
                self._threat_list_layout.count() - 1, card
            )

        self._stack.setCurrentIndex(_STATE_COMPLETE)

    def _on_scan_error(self, error_str: str) -> None:
        self._tick_timer.stop()
        self._done_title.setText("Scan Error")
        self._done_title.setStyleSheet("color: #ff4757; background: transparent;")
        self._done_summary.setText(error_str)
        self._done_ring.set_value(0)
        self._clear_threat_list()
        self._stack.setCurrentIndex(_STATE_COMPLETE)

    def _tick_elapsed(self) -> None:
        self._elapsed_seconds += 1
        self._stat_elapsed["value_label"].setText(
            self._format_elapsed(self._elapsed_seconds)
        )

    def _cleanup_thread(self) -> None:
        """Clean up thread and worker objects after the thread finishes."""
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        if self._thread is not None:
            self._thread.deleteLater()
            self._thread = None

    # ── Helpers ───────────────────────────────────────────────────────────

    def _go_idle(self) -> None:
        self._idle_ring.set_value(0)
        self._stack.setCurrentIndex(_STATE_IDLE)

    def _clear_threat_list(self) -> None:
        while self._threat_list_layout.count() > 1:
            item = self._threat_list_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _custom_scan_dialog(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            self.start_scan("custom", [folder])

    @staticmethod
    def _format_elapsed(seconds: int) -> str:
        m, s = divmod(seconds, 60)
        if m >= 60:
            h, m = divmod(m, 60)
            return f"{h}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    def _quarantine_threat(self, file_path: str) -> None:
        """Isolate a threat and move it to quarantine."""
        threat = None
        for t in self._threats_found:
            if t.get("file_path") == file_path:
                threat = t
                break

        if not threat:
            return

        try:
            qm = getattr(self._scanner, "_quarantine", None)
            if qm:
                qm.quarantine_file(
                    file_path=file_path,
                    threat_name=threat.get("threat_name", "Unknown Threat"),
                    severity=threat.get("severity", "LOW"),
                    detection_method=threat.get("detection_method", "manual"),
                )
                QMessageBox.information(self, "Quarantined", f"File isolated successfully:\n{file_path}")
                self._remove_card_by_path(file_path)
            else:
                QMessageBox.warning(self, "Error", "Quarantine manager not available.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to quarantine file:\n{e}")

    def _remove_threat(self, file_path: str) -> None:
        """Permanently delete a threat file from the host system."""
        reply = QMessageBox.question(
            self,
            "Delete File",
            f"Are you sure you want to permanently delete this threat?\n{file_path}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                QMessageBox.information(self, "Deleted", "File deleted successfully.")
                self._remove_card_by_path(file_path)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to delete file:\n{e}")

    def _ignore_threat(self, file_path: str) -> None:
        """Dismiss the threat display card without modifying the file."""
        self._remove_card_by_path(file_path)

    def _remove_card_by_path(self, file_path: str) -> None:
        """Remove a threat card widget and entry from tracked scans list."""
        for i in range(self._threat_list_layout.count()):
            item = self._threat_list_layout.itemAt(i)
            if item and item.widget():
                card = item.widget()
                if isinstance(card, ThreatCard) and card._file_path == file_path:
                    card.deleteLater()
                    break

        self._threats_found = [t for t in self._threats_found if t.get("file_path") != file_path]
